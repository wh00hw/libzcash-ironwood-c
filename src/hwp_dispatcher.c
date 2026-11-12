/*
 * hwp_dispatcher — device-side HWP protocol driver implementation.
 *
 * See hwp_dispatcher.h for the API contract. The bulk of the work is in
 * one big switch inside the main loop. The protocol-level invariants
 * lived in `FlipZcash/views/flipz_scene_1.c::sign_worker_thread` until
 * 2026-05; they're now here so every device target (FlipZcash, ESP32,
 * future BOLOS port, virtual-device test fixture) gets the same
 * behaviour for free, including the post-2026-05-13 fixes:
 *
 *   - IDLE-only IDLE_RESET: don't fire periodic PINGs while the signer
 *     is mid-transaction. Sinsemilla cmx can keep the worker out of
 *     this loop for 100+ s; PINGing in that window provoked a host
 *     PONG storm that overflowed the device's CDC RX buffer and
 *     dropped the next legitimate action frame.
 *
 *   - Bounded carryover for multi-frame drains: when the parser
 *     produces FRAME_READY mid-chunk, the remainder of the chunk is
 *     stashed in a per-loop carryover (max one CDC packet) and
 *     replayed on the next iteration; subsequent chunks stay queued
 *     in the CDC RX buffer (the drain callback only pulls one packet
 *     at a time now). No frames are lost.
 *
 *   - Transparent outputs (shielded → t-addr): begin_transparent is
 *     invoked from the output handler with num_inputs=0. Transparent
 *     INPUTS and transparent signing are refused: see README,
 *     "Transparent inputs are not supported".
 *
 * ERROR RULE. Every Error frame this file sends ends the session: the
 * signer is reset (viewing keys, hashes, approvals wiped) before the frame
 * goes out, whatever the cause — a signer rejection, a malformed or
 * unknown frame, a CRC or version error, a refusal by the user. There is
 * one place that sends Error frames, send_error(), and it does the reset.
 */
#include "hwp_dispatcher.h"

#include <string.h>

#include "hwp.h"
#include "memzero.h"
#include "orchard.h"
#include "redpallas.h"
#include "zip244.h"
#include "base58.h"

/* The dispatcher is documented single-threaded (one device, one host —
 * see hwp_dispatcher.h). Its two big pieces of scratch state — the TX
 * frame buffer and the RX parser (which embeds a full HwpFrame) — live
 * INSIDE the HwpDispatcher struct: on the caller's stack they would blow
 * the 512-byte per-function budget (scripts/check_stack.sh), and as
 * static module storage they inflated the FAP image past the Flipper
 * loader's free-heap budget. Embedding them lets each target choose the
 * placement (the Flipper heap-allocates the dispatcher for the session).
 *
 * hwp_dispatcher_run() re-initialises the parser at entry, so leftover
 * state from a previous run cannot bleed into the next.
 *
 * Per-message handlers below are also marked noinline: at -O2 GCC was
 * folding their locals (sign-req scratch, per-output review buffers,
 * fvk payload) into hwp_dispatcher_run's frame, and the
 * sum tripped the per-function limit even though no single handler
 * does. Forcing separate frames keeps each one comfortably under 512. */

#define HWP_NOINLINE __attribute__((noinline))

/* ── Local helpers ──────────────────────────────────────────────────── */

static HWP_NOINLINE void send_frame(HwpDispatcher* d, uint8_t seq,
                                     uint8_t msg_type,
                                     const uint8_t* payload, uint16_t len) {
    if(len > HWP_DISPATCHER_MAX_TX_PAYLOAD) {
        /* Structurally impossible for the frames this dispatcher emits
         * (see tx_buf sizing note in hwp_dispatcher.h); refuse rather
         * than overflow if a future message type outgrows the cap. */
        return;
    }
    size_t frame_len = hwp_encode(d->tx_buf, seq, msg_type, payload, len);
    d->io.serial_send(d->tx_buf, frame_len, d->user_ctx);
}

/* The ONLY place an Error frame is produced — and it ends the session.
 * Whatever state the signer was in, after an error it is IDLE with nothing
 * retained: a host cannot provoke an error and then carry on with the
 * approvals it had. (The device's network survives, see
 * orchard_signer_reset.) */
static HWP_NOINLINE void send_error(HwpDispatcher* d, uint8_t seq,
                                     HwpErrorCode code, const char* msg) {
    orchard_signer_reset(d->signer);
    size_t frame_len = hwp_encode_error(d->tx_buf, seq, code, msg);
    d->io.serial_send(d->tx_buf, frame_len, d->user_ctx);
    /* Make the error visible in the persistent UI footer. The actual
     * error code/message already went over the wire to the host. */
    if(d->ui.phase_update) {
        d->ui.phase_update(HWP_PHASE_ERROR, 0, 0, d->user_ctx);
    }
}

static void phase(HwpDispatcher* d, HwpPhase p, uint16_t idx, uint16_t total) {
    if(d->ui.phase_update) {
        d->ui.phase_update(p, idx, total, d->user_ctx);
    }
}

/* Block on the network-mismatch screen until the user dismisses it OR
 * io.should_exit fires. The UI callback is itself blocking, so we just
 * delegate; if the app doesn't supply one (e.g. headless test fixture)
 * skip it. */
static void show_network_error(HwpDispatcher* d, const char* msg) {
    phase(d, HWP_PHASE_ERROR, 0, 0);
    if(d->ui.network_error) {
        d->ui.network_error(msg, d->testnet, d->user_ctx);
    }
}

/* ── Per-message handlers ───────────────────────────────────────────── */

static HWP_NOINLINE void handle_ping(HwpDispatcher* d, HwpFrame* f,
                                      bool* user_confirmed,
                                      uint16_t* sign_req_seen) {
    send_frame(d, f->seq, HWP_MSG_PONG, NULL, 0);
    /* PING = canonical new-session signal. Wipe per-session state
     * defensively so a previous client's signer context doesn't bleed
     * into the next interaction. Keys are NOT touched (caller owns
     * them and rederiving on every reconnect is too slow). */
    *user_confirmed = false;
    *sign_req_seen = 0;
    orchard_signer_reset(d->signer);
    phase(d, HWP_PHASE_CONNECTED, 0, 0);
}

static HWP_NOINLINE void handle_fvk_req(HwpDispatcher* d, HwpFrame* f) {
    /* The device's network is the firmware's (d->testnet, and the coin type
     * given to orchard_signer_init): the host can ask which one it expects,
     * it cannot set it. A request that names the other network is refused;
     * one that names none (empty payload, or coin type 0) is answered — the
     * FVK is not a secret from the host, and the network check that
     * matters is the one on every TxMeta. */
    if(f->payload_len >= HWP_FVK_REQ_SIZE) {
        uint32_t req_coin = (uint32_t)f->payload[0] |
                            ((uint32_t)f->payload[1] << 8) |
                            ((uint32_t)f->payload[2] << 16) |
                            ((uint32_t)f->payload[3] << 24);
        if(req_coin != 0 && req_coin != d->signer->coin_type) {
            send_error(d, f->seq, HWP_ERR_NETWORK_MISMATCH,
                       d->testnet ? "Device is on testnet"
                                  : "Device is on mainnet");
            show_network_error(d,
                               d->testnet ? "Companion requested MAINNET"
                                          : "Companion requested TESTNET");
            return;
        }
    }
    uint8_t payload[96];
    memcpy(payload, d->keys.ak, 32);
    memcpy(payload + 32, d->keys.nk, 32);
    memcpy(payload + 64, d->keys.rivk, 32);
    send_frame(d, f->seq, HWP_MSG_FVK_RSP, payload, 96);
    memzero(payload, sizeof(payload));
}

/* Report a signer error to the host and abort the session. One mapping
 * for every handler, so each failure has one code and one message. */
static HWP_NOINLINE void fail_signer(HwpDispatcher* d, uint8_t seq,
                                      OrchardSignerError serr) {
    HwpErrorCode code = HWP_ERR_BAD_FRAME;
    const char* msg = "Bad transaction data";
    switch(serr) {
    case SIGNER_ERR_SAPLING_NOT_EMPTY:
        code = HWP_ERR_SAPLING_NOT_EMPTY;
        msg = "Sapling components not allowed (Orchard-only)";
        break;
    case SIGNER_ERR_BRANCH_NOT_ALLOWED:
        code = HWP_ERR_BRANCH_NOT_ALLOWED;
        msg = "Consensus branch not supported by this firmware";
        break;
    case SIGNER_ERR_BAD_FVK:
        code = HWP_ERR_INVALID_STATE;
        msg = "Device viewing key unavailable";
        break;
    case SIGNER_ERR_TOO_MANY_ACTIONS:
        /* actions or transparent outputs */
        code = HWP_ERR_LIMIT_EXCEEDED;
        msg = "More outputs than the device can review";
        break;
    case SIGNER_ERR_TOO_MANY_MEMOS:
        code = HWP_ERR_LIMIT_EXCEEDED;
        msg = "More memos than the device can review";
        break;
    case SIGNER_ERR_NOTE_COMMITMENT_MISMATCH:
        code = HWP_ERR_NOTE_COMMITMENT_MISMATCH;
        msg = "Action cmx does not commit to claimed note";
        break;
    case SIGNER_ERR_MEMO_MISMATCH:
        code = HWP_ERR_MEMO_MISMATCH;
        msg = "enc_ciphertext does not match recomputed note/memo";
        break;
    case SIGNER_ERR_NETWORK_MISMATCH:
        code = HWP_ERR_NETWORK_MISMATCH;
        msg = "TxMeta coin_type is not the device's network";
        break;
    case SIGNER_ERR_NO_ACTIONS:
        msg = "Transaction has no shielded actions";
        break;
    case SIGNER_ERR_EMPTY_POOL_BALANCE:
        code = HWP_ERR_EMPTY_POOL_BALANCE;
        msg = "Non-zero value balance for a pool without actions";
        break;
    case SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED:
        code = HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED;
        msg = "Transparent inputs are not supported";
        break;
    case SIGNER_ERR_TRANSPARENT_MISMATCH:
        code = HWP_ERR_TRANSPARENT_DIGEST_MISMATCH;
        msg = "Transparent digest mismatch";
        break;
    case SIGNER_ERR_TRANSPARENT_BAD_OUTPUT:
        msg = "Bad transparent output (P2PKH / P2SH only)";
        break;
    case SIGNER_ERR_BAD_PK_D:
        code = HWP_ERR_BAD_PK_D;
        msg = "pk_d does not decode to a valid Pallas point";
        break;
    case SIGNER_ERR_FEE_OVERFLOW:
        code = HWP_ERR_FEE_OVERFLOW;
        msg = "Fee arithmetic overflow";
        break;
    case SIGNER_ERR_FEE_NEGATIVE:
        code = HWP_ERR_FEE_NEGATIVE;
        msg = "Negative fee (unbalanced transaction)";
        break;
    case SIGNER_ERR_VALUE_OVERFLOW:
        code = HWP_ERR_VALUE_OVERFLOW;
        msg = "Output values overflow";
        break;
    case SIGNER_ERR_SIGHASH_MISMATCH:
        code = HWP_ERR_SIGHASH_MISMATCH;
        msg = "Device sighash != companion sighash";
        break;
    case SIGNER_ERR_BAD_STATE:
    case SIGNER_ERR_ACTION_NOT_CONFIRMED:
    case SIGNER_ERR_FEE_NOT_CONFIRMED:
    case SIGNER_ERR_TRANSPARENT_NOT_EMPTY:
        code = HWP_ERR_INVALID_STATE;
        msg = "Unexpected message for the current signing state";
        break;
    case SIGNER_ERR_BAD_META:
        msg = "Bad TX metadata";
        break;
    default:
        break;
    }
    send_error(d, seq, code, msg);   /* resets the signer */
    if(serr == SIGNER_ERR_NETWORK_MISMATCH) {
        show_network_error(d, "TX metadata network mismatch");
    }
}

/* Outcome of the review driven by the sighash sentinel. */
typedef enum {
    REVIEW_OK = 0,
    REVIEW_CANCELLED,     /* user said no, or the app is exiting */
    REVIEW_SIGNER_ERROR,  /* *serr holds the signer's error */
    REVIEW_NO_MEMO_UI,    /* a memo to read and no review_memo callback */
    REVIEW_UNRENDERABLE,  /* an output could not be turned into an address */
} ReviewResult;

/* Step 1 of the review: transparent outputs, rendered as base58check
 * t-addresses. These are typically the "real" recipient of a shielded →
 * t-addr sweep. Always presented (and counted) as leaving the wallet. */
static HWP_NOINLINE ReviewResult review_transparent_outputs(HwpDispatcher* d,
                                                             uint16_t total_t,
                                                             uint16_t total) {
    uint16_t n_t = total_t;
    char addr_buf[64];
    for(uint16_t i = 0; i < n_t; i++) {
        uint8_t script[25];
        size_t script_len = 0;
        uint64_t value = 0;
        if(orchard_signer_get_transparent_output_display(
               d->signer, i, &value, script, sizeof(script), &script_len) != SIGNER_OK) {
            return REVIEW_UNRENDERABLE;
        }
        if(script_to_taddr(script, script_len, d->testnet,
                           addr_buf, sizeof(addr_buf)) == 0) {
            /* Non-standard script: the lib already refused at feed time,
             * but without a renderable address there is nothing to show. */
            return REVIEW_UNRENDERABLE;
        }
        HwpOutputReview rv = {
            .kind = HWP_OUTPUT_TRANSPARENT,
            .index = (uint16_t)(i + 1),
            .total = total,
            .address = addr_buf,
            .value = value,
            .memo = HWP_MEMO_NOT_APPLICABLE,
            .has_memo = false,
        };
        phase(d, HWP_PHASE_REVIEW, rv.index, total);
        if(d->ui.review_output(&rv, d->user_ctx) != HWP_UI_OK) return REVIEW_CANCELLED;
    }
    return REVIEW_OK;
}

/* Step 2 of the review: shielded outputs. The kind shown to the user is
 * the signer's own classification; address, value and memo are the ones
 * the note commitment and ciphertext checks tied to the action. Outputs
 * verified to carry neither value nor a memo are padding: they are not
 * shown (the signer has already confirmed them and counts them in the
 * totals). Every other output is sent to the UI and is confirmed only if
 * the callback returns HWP_UI_OK. */
static HWP_NOINLINE ReviewResult review_shielded_outputs(HwpDispatcher* d,
                                                          uint16_t first_index,
                                                          uint16_t total) {
    /* orchard_encode_ua_raw requires ua_out_len >= 200; the encoded
     * Orchard-only UA itself is ~106 chars (mainnet) / ~110 (testnet). */
    char addr_buf[200];
    const char* hrp = d->testnet ? "utest" : "u";
    uint16_t n_o = d->signer->actions_received;
    uint16_t shown = first_index;

    for(uint16_t i = 0; i < n_o; i++) {
        OrchardOutputInfo info;
        if(orchard_signer_get_output(d->signer, i, &info) != SIGNER_OK) {
            return REVIEW_UNRENDERABLE;
        }
        if(!info.review_required) continue;

        if(orchard_encode_ua_raw(info.recipient, info.recipient + 11, hrp,
                                  addr_buf, sizeof(addr_buf)) <= 0) {
            return REVIEW_UNRENDERABLE;
        }
        /* A memo the user cannot be shown is a reason to stop, before the
         * user is asked to approve the output it belongs to. */
        if(info.has_memo && d->ui.review_memo == NULL) return REVIEW_NO_MEMO_UI;

        HwpOutputReview rv = {
            .kind = HWP_OUTPUT_EXTERNAL,
            .index = shown,
            .total = total,
            .address = addr_buf,
            .value = info.value,
            .memo = info.has_memo ? HWP_MEMO_PRESENT : HWP_MEMO_NONE,
            .has_memo = info.has_memo,
        };
        if(info.ownership == ORCHARD_OUTPUT_OWN_INTERNAL) {
            rv.kind = HWP_OUTPUT_OWN_CHANGE;
        } else if(info.ownership == ORCHARD_OUTPUT_OWN_EXTERNAL) {
            rv.kind = HWP_OUTPUT_OWN_ADDRESS;
        }

        phase(d, HWP_PHASE_REVIEW, shown, total);
        if(d->ui.review_output(&rv, d->user_ctx) != HWP_UI_OK) return REVIEW_CANCELLED;

        if(info.has_memo) {
            /* The bytes shown are the ones the device verified against the
             * on-chain enc_ciphertext. `memo_buf` is static to keep this
             * frame under the 512 B per-function stack budget; it is wiped
             * as soon as the screen returns. */
            static uint8_t memo_buf[512];
            bool present = false;
            HwpUiResult rm = HWP_UI_CANCELLED;
            if(orchard_signer_get_action_memo(d->signer, i, memo_buf, &present) ==
                   SIGNER_OK && present) {
                rm = d->ui.review_memo(shown, total, addr_buf, memo_buf, d->user_ctx);
            }
            memzero(memo_buf, sizeof(memo_buf));
            if(rm != HWP_UI_OK) return REVIEW_CANCELLED;
        }

        if(orchard_signer_confirm_action(d->signer, i) != SIGNER_OK) {
            return REVIEW_UNRENDERABLE;
        }
        shown++;
    }
    return REVIEW_OK;
}

/* Drive the review after the host's sighash sentinel:
 *   0. totals computed first — this also proves the transaction is
 *      complete and its sums are in range before the user is asked
 *      anything;
 *   1. transparent outputs;
 *   2. shielded outputs (own change / own address / external);
 *   3. the totals: what leaves the wallet, and the fee.
 * The signer refuses verify() unless 2 and 3 were confirmed. */
static HWP_NOINLINE ReviewResult run_per_output_review(HwpDispatcher* d,
                                                        OrchardSignerError* serr) {
    OrchardSignerTotals totals;
    *serr = orchard_signer_get_totals(d->signer, &totals);
    if(*serr != SIGNER_OK) return REVIEW_SIGNER_ERROR;

    uint16_t n_t = totals.n_transparent_out;
    uint16_t n_shown = n_t;
    for(uint16_t i = 0; i < d->signer->actions_received; i++) {
        OrchardOutputInfo info;
        if(orchard_signer_get_output(d->signer, i, &info) != SIGNER_OK) {
            return REVIEW_UNRENDERABLE;
        }
        if(info.review_required) n_shown++;
    }

    ReviewResult r = review_transparent_outputs(d, n_t, n_shown);
    if(r != REVIEW_OK) return r;
    r = review_shielded_outputs(d, (uint16_t)(n_t + 1), n_shown);
    if(r != REVIEW_OK) return r;

    phase(d, HWP_PHASE_REVIEW, (uint16_t)(n_shown + 1), (uint16_t)(n_shown + 1));
    if(d->ui.review_totals(&totals, d->user_ctx) != HWP_UI_OK) return REVIEW_CANCELLED;

    *serr = orchard_signer_confirm_totals(d->signer);
    if(*serr != SIGNER_OK) return REVIEW_SIGNER_ERROR;
    return REVIEW_OK;
}

/* TX_OUTPUT handler. The host packs three different things into this
 * message type, discriminated by output_index:
 *   - 0xFFFF             → TxMeta (one-shot, state IDLE → RECEIVING_ACTIONS)
 *   - 0..total-1         → action data (cmx recompute + capture)
 *   - == total           → sighash sentinel (per-action review then verify)
 * Returns true if the dispatcher should send the ACK. False means the
 * handler already emitted an error / state was reset and the caller
 * should `continue`. */
static HWP_NOINLINE bool handle_tx_output(HwpDispatcher* d, HwpFrame* f) {
    HwpTxOutput txo;
    if(!hwp_parse_tx_output(f->payload, f->payload_len, &txo)) {
        send_error(d, f->seq, HWP_ERR_BAD_FRAME, "Invalid TX_OUTPUT payload");
        return false;
    }

    OrchardSignerError serr;
    if(txo.output_index == HWP_TX_META_INDEX) {
        /* A TxMeta always starts a new transaction from nothing. Whatever
         * was in progress — a half-streamed transaction, or a verified one
         * the host asked fewer signatures for than it has actions — is
         * dropped with all its approvals. Nothing carries over. */
        orchard_signer_reset(d->signer);
        /* The session's incoming viewing keys are derived here, from the
         * device's own full viewing key (two Commit^ivk). */
        if(d->ui.progress) d->ui.progress(0, "Preparing...", d->user_ctx);
        OrchardSignerFvk fvk = {
            .ak = d->keys.ak, .nk = d->keys.nk, .rivk = d->keys.rivk};
        serr = orchard_signer_feed_meta(d->signer, &fvk, txo.output_data,
                                         txo.output_data_len, txo.total_outputs);
        if(serr != SIGNER_OK) {
            fail_signer(d, f->seq, serr);
            return false;
        }
        phase(d, HWP_PHASE_META, 0, txo.total_outputs);
    } else if(txo.output_index == txo.total_outputs) {
        /* Sighash sentinel. */
        if(txo.output_data_len != 32) {
            send_error(d, f->seq, HWP_ERR_BAD_SIGHASH, "Bad sighash length");
            return false;
        }
        /* The review runs once, for the transaction TxMeta announced: no
         * screen is shown for a sentinel that arrives early, twice, or
         * with another action count. */
        if(d->signer->state != SIGNER_RECEIVING_ACTIONS ||
           txo.total_outputs != d->signer->actions_expected ||
           d->signer->actions_received != d->signer->actions_expected) {
            send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                       "Sighash sentinel out of sequence");
            return false;
        }
        ReviewResult rr = run_per_output_review(d, &serr);
        if(rr == REVIEW_SIGNER_ERROR) {
            fail_signer(d, f->seq, serr);
            return false;
        } else if(rr != REVIEW_OK) {
            if(rr == REVIEW_NO_MEMO_UI) {
                send_error(d, f->seq, HWP_ERR_LIMIT_EXCEEDED,
                           "Output carries a memo this device cannot display");
            } else if(rr == REVIEW_UNRENDERABLE) {
                send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                           "Output cannot be displayed");
            } else {
                send_error(d, f->seq, HWP_ERR_USER_CANCELLED,
                           "User cancelled the review");
            }
            return false;
        }
        if(d->ui.progress) d->ui.progress(0, "Verifying ZIP-244 sighash...", d->user_ctx);
        serr = orchard_signer_verify(d->signer, txo.output_data);
        if(serr != SIGNER_OK) {
            fail_signer(d, f->seq, serr);
            return false;
        }
    } else {
        /* Action data 0..N-1. Every action payload is the 1-byte pool tag
         * (0x00 = sealed Orchard, 0x01 = Ironwood) followed by the
         * memo-carrying body: 1416 bytes on the wire. The compact
         * (no-memo, 904 B) body is refused for every output — the device
         * recomputes every ciphertext — and so is anything else, the
         * untagged pre-v6 layouts included. */
        phase(d, HWP_PHASE_VERIFY,
              (uint16_t)(txo.output_index + 1), txo.total_outputs);
        if(d->ui.progress) {
            d->ui.progress(0, "Verifying output...", d->user_ctx);
        }

        if(txo.output_data_len == HWP_ACTION_DATA_SIZE_V6_COMPACT) {
            send_error(d, f->seq, HWP_ERR_MEMO_REQUIRED,
                       "Compact action body refused: send the memo-carrying body");
            return false;
        }
        if(txo.output_data_len != HWP_ACTION_DATA_SIZE_V6) {
            send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                       "Action payload must be v6 pool-tagged with memo (1416 B)");
            return false;
        }
        if(txo.output_data[0] > ZIP244_POOL_IRONWOOD) {
            send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                       "Bad v6 action pool tag");
            return false;
        }
        /* The index must be the next one: an action cannot be replayed,
         * skipped or re-ordered into a different slot. */
        if(txo.output_index != d->signer->actions_received ||
           txo.total_outputs != d->signer->actions_expected) {
            send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                       "Action out of sequence");
            orchard_signer_reset(d->signer);
            return false;
        }
        Zip244Pool pool = (Zip244Pool)txo.output_data[0];
        const uint8_t* adata = txo.output_data + HWP_POOL_TAG_SIZE;
        size_t alen = (size_t)txo.output_data_len - HWP_POOL_TAG_SIZE;

        HwpActionV5 av5;
        if(!hwp_parse_action_v5(adata, (uint16_t)alen, &av5)) {
            send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                       "Action memo-body size mismatch");
            return false;
        }
        serr = orchard_signer_feed_action_with_note_and_memo(
            d->signer, pool, av5.action, HWP_ACTION_DATA_SIZE,
            av5.recipient, av5.value, av5.rseed,
            av5.memo);
        if(serr != SIGNER_OK) {
            fail_signer(d, f->seq, serr);
            return false;
        }
    }
    return true;
}

/* TX_TRANSPARENT_INPUT. Transparent inputs are not supported, so the only
 * frame of this type the device accepts is the one that carries no input:
 * index == total == 0 with the 32-byte transparent digest — the sentinel
 * that closes the transparent-output stream. Anything announcing an input
 * ends the session with TRANSPARENT_INPUTS_UNSUPPORTED. */
static HWP_NOINLINE void handle_tx_transparent_input(HwpDispatcher* d,
                                                       HwpFrame* f) {
    if(f->payload_len < HWP_TX_OUTPUT_HEADER) {
        send_error(d, f->seq, HWP_ERR_BAD_FRAME, "Transparent input too short");
        return;
    }
    uint16_t input_index =
        (uint16_t)f->payload[0] | ((uint16_t)f->payload[1] << 8);
    uint16_t total_inputs =
        (uint16_t)f->payload[2] | ((uint16_t)f->payload[3] << 8);
    const uint8_t* t_data = f->payload + HWP_TX_OUTPUT_HEADER;
    uint16_t t_data_len = (uint16_t)(f->payload_len - HWP_TX_OUTPUT_HEADER);

    phase(d, HWP_PHASE_TRANSPARENT, 0, 0);

    if(total_inputs != 0 || input_index != 0) {
        fail_signer(d, f->seq, SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
        return;
    }
    if(t_data_len != 32) {
        send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                   "Transparent sentinel must be 32 bytes");
        return;
    }
    /* A host may close an empty transparent stream too (no outputs): the
     * digest is then the empty-bundle constant. */
    if(d->signer->state == SIGNER_RECEIVING_ACTIONS &&
       !d->signer->transparent_begun) {
        OrchardSignerError berr = orchard_signer_begin_transparent(d->signer, 0, 0);
        if(berr != SIGNER_OK) {
            fail_signer(d, f->seq, berr);
            return;
        }
    }
    OrchardSignerError serr = orchard_signer_verify_transparent(d->signer, t_data);
    if(serr != SIGNER_OK) {
        fail_signer(d, f->seq, serr);
        return;
    }
    send_frame(d, f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
}

static HWP_NOINLINE void handle_tx_transparent_output(HwpDispatcher* d,
                                                        HwpFrame* f) {
    if(f->payload_len < HWP_TX_OUTPUT_HEADER) {
        send_error(d, f->seq, HWP_ERR_BAD_FRAME, "Transparent output too short");
        return;
    }
    uint16_t output_index =
        (uint16_t)f->payload[0] | ((uint16_t)f->payload[1] << 8);
    uint16_t total_outputs =
        (uint16_t)f->payload[2] | ((uint16_t)f->payload[3] << 8);
    const uint8_t* t_data = f->payload + HWP_TX_OUTPUT_HEADER;
    uint16_t t_data_len = (uint16_t)(f->payload_len - HWP_TX_OUTPUT_HEADER);

    phase(d, HWP_PHASE_TRANSPARENT, 0, 0);

    /* The first output opens the transparent pass (no inputs: shielded →
     * t-address). More outputs than the device can show are refused here,
     * with LIMIT_EXCEEDED, before any is hashed. */
    if(output_index == 0 && d->signer->state == SIGNER_RECEIVING_ACTIONS) {
        OrchardSignerError berr =
            orchard_signer_begin_transparent(d->signer, 0, total_outputs);
        if(berr != SIGNER_OK) {
            fail_signer(d, f->seq, berr);
            return;
        }
    }
    /* Like actions: the index must be the next one and the announced total
     * must not change. */
    if(d->signer->state != SIGNER_RECEIVING_TRANSPARENT ||
       output_index != d->signer->transparent_state.outputs_received ||
       total_outputs != d->signer->transparent_outputs_expected) {
        send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                   "Transparent output out of sequence");
        return;
    }

    OrchardSignerError serr =
        orchard_signer_feed_transparent_output(d->signer, t_data, t_data_len);
    if(serr != SIGNER_OK) {
        fail_signer(d, f->seq, serr);
        return;
    }
    send_frame(d, f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
}

/* TRANSPARENT_SIGN_REQ: refused, always. The message ID stays reserved.
 * The dispatcher holds no transparent key (HwpDispatcherKeys has no field
 * for one) and the library compiles no ECDSA signing by default. */
static HWP_NOINLINE void handle_transparent_sign_req(HwpDispatcher* d,
                                                       HwpFrame* f) {
    send_error(d, f->seq, HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED,
               "Transparent signing is not supported");
}

/* SIGN_REQ. Only two fields are used: the sighash, which must be the one
 * the device computed and verified, and alpha. amount, fee and recipient
 * are the host's words about a transaction the device has already examined
 * itself: they are parsed for framing and otherwise IGNORED — not checked,
 * not shown. (An earlier revision showed the recipient string on the final
 * screen after matching it against "any action"; a host could name there an
 * address no screen had shown.)
 *
 * Signatures per approved transaction: at most one per action, each over
 * the verified sighash. The count is reached -> the session ends. A host
 * that needs fewer (it signs dummy spends itself) simply stops; the next
 * TxMeta, PING or ABORT ends the transaction. */
static HWP_NOINLINE void handle_sign_req(HwpDispatcher* d, HwpFrame* f,
                                          bool* user_confirmed,
                                          uint16_t* sign_req_seen) {
    /* Parse into the dispatcher-embedded scratch (the struct does not fit
     * the per-function stack budget). */
    HwpSignReq* req = &d->sign_req;
    if(!hwp_parse_sign_req(f->payload, f->payload_len, req)) {
        send_error(d, f->seq, HWP_ERR_BAD_SIGHASH, "Invalid SIGN_REQ payload");
        return;
    }

    OrchardSignerError chk = orchard_signer_check(d->signer, req->sighash);
    if(chk == SIGNER_ERR_NOT_VERIFIED) {
        send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                   "ZIP-244 verification not completed");
        return;
    } else if(chk != SIGNER_OK) {
        /* A request for any other sighash ends the session: the approvals
         * were for one transaction. */
        send_error(d, f->seq, HWP_ERR_SIGHASH_MISMATCH,
                   "SIGN_REQ sighash != verified sighash");
        return;
    }
    if(*sign_req_seen >= d->signer->actions_received) {
        /* Unreachable (the session is reset when the count is reached);
         * kept as the bound's last line. */
        send_error(d, f->seq, HWP_ERR_INVALID_STATE, "Signature limit reached");
        return;
    }

    if(!*user_confirmed) {
        /* The final prompt shows the device's own numbers and nothing
         * else. */
        OrchardSignerTotals totals;
        OrchardSignerError terr = orchard_signer_get_totals(d->signer, &totals);
        if(terr != SIGNER_OK) {
            fail_signer(d, f->seq, terr);
            return;
        }

        phase(d, HWP_PHASE_AWAIT_CONFIRM, 0, d->signer->actions_received);
        HwpUiResult uir = d->ui.confirm_tx(&totals, d->user_ctx);
        if(uir != HWP_UI_OK) {
            /* A refusal ends the session: the host cannot simply ask again. */
            send_error(d, f->seq, HWP_ERR_USER_CANCELLED, "User cancelled");
            return;
        }
        *user_confirmed = true;
    }

    (*sign_req_seen)++;
    phase(d, HWP_PHASE_SIGNING, *sign_req_seen, d->signer->actions_received);
    if(d->ui.progress) {
        d->ui.progress(0, "Signing (RedPallas)...", d->user_ctx);
    }

    uint8_t sig[64], rk[32];
    OrchardSignerError serr = orchard_signer_sign(
        d->signer, req->sighash, d->keys.ask, req->alpha, sig, rk);
    if(serr != SIGNER_OK) {
        memzero(sig, sizeof(sig));
        send_error(d, f->seq, HWP_ERR_SIGN_FAILED, "RedPallas sign failed");
        return;
    }

    uint8_t rsp[96];
    memcpy(rsp, sig, 64);
    memcpy(rsp + 64, rk, 32);
    send_frame(d, f->seq, HWP_MSG_SIGN_RSP, rsp, 96);
    memzero(sig, sizeof(sig));
    memzero(rsp, sizeof(rsp));

    if(*sign_req_seen >= d->signer->actions_received) {
        /* One signature per action has been given: the transaction is
         * done. Show "Signature sent!" briefly, then reset everything so a
         * follow-up tx from the same companion session starts clean. */
        phase(d, HWP_PHASE_DONE, *sign_req_seen, d->signer->actions_received);
        d->io.sleep_ms(2500, d->user_ctx);
        orchard_signer_reset(d->signer);
        *user_confirmed = false;
        *sign_req_seen = 0;
        phase(d, HWP_PHASE_CONNECTED, 0, 0);
    } else {
        phase(d, HWP_PHASE_CONNECTED, *sign_req_seen,
              d->signer->actions_received);
    }
}

/* ── Main loop ──────────────────────────────────────────────────────── */

/* A handled frame may have carried a memo or a note plaintext; do not keep
 * it in the RX buffer (or the SIGN_REQ scratch) until the next one happens
 * to overwrite it. */
static void wipe_frame(HwpDispatcher* d) {
    memzero(&d->parser.frame, sizeof(d->parser.frame));
    memzero(&d->sign_req, sizeof(d->sign_req));
}

/* CDC packet size; one drain call pulls at most this many bytes so that
 * after a complete frame the unread bytes of subsequent frames stay
 * queued for the next iteration instead of being silently dropped. */
#define HWP_DRAIN_CHUNK 64

typedef struct {
    HwpParser* parser;
    HwpFeedResult last_result;
    /* Carryover: bytes from the same chunk that came AFTER FRAME_READY.
     * Bounded by HWP_DRAIN_CHUNK because we only pull one chunk per
     * inner iteration. */
    uint8_t carryover[HWP_DRAIN_CHUNK];
    size_t carryover_count;
} ParseCtx;

static void feed_byte(ParseCtx* pc, uint8_t b) {
    if(pc->last_result == HWP_FEED_FRAME_READY ||
       pc->last_result == HWP_FEED_CRC_ERROR) {
        if(pc->carryover_count < sizeof(pc->carryover)) {
            pc->carryover[pc->carryover_count++] = b;
        }
        return;
    }
    HwpFeedResult r = hwp_parser_feed(pc->parser, b);
    if(r != HWP_FEED_INCOMPLETE) pc->last_result = r;
}

HwpDispatchResult hwp_dispatcher_run(HwpDispatcher* d) {
    /* Everything the loop will dereference or call, checked once: a
     * missing mandatory callback or key is a configuration error to report
     * here, not a NULL dereference in the middle of a session. */
    if(!d || !d->signer || !d->io.serial_drain || !d->io.serial_send ||
       !d->io.get_tick_ms || !d->io.sleep_ms || !d->io.should_exit ||
       !d->ui.review_output || !d->ui.review_totals || !d->ui.confirm_tx ||
       !d->keys.ak || !d->keys.nk || !d->keys.rivk || !d->keys.ask) {
        return HWP_DISP_FATAL;
    }
    /* The network is the firmware's choice, made in orchard_signer_init();
     * `testnet` (address prefixes on the screens) must say the same. */
    if(d->signer->coin_type !=
       (d->testnet ? ORCHARD_SIGNER_COIN_TESTNET : ORCHARD_SIGNER_COIN_MAINNET)) {
        return HWP_DISP_FATAL;
    }
    /* Start from nothing, whatever the caller left in the context. */
    orchard_signer_reset(d->signer);

    hwp_parser_init(&d->parser);
    ParseCtx pc = {.parser = &d->parser, .last_result = HWP_FEED_INCOMPLETE,
                   .carryover_count = 0};

    uint8_t seq = 0;
    bool connected = false;
    bool user_confirmed = false;
    uint16_t sign_req_seen = 0;

    const uint32_t IDLE_RESET_MS = 1500;
    const uint32_t PING_PERIOD_MS = 400;
    uint32_t last_rx_tick = d->io.get_tick_ms(d->user_ctx);
    uint32_t last_ping_tick = 0;

    /* Initial PING — signals to the host "I'm alive, send your first
     * frame". */
    send_frame(d, seq++, HWP_MSG_PING, NULL, 0);
    last_ping_tick = d->io.get_tick_ms(d->user_ctx);
    phase(d, HWP_PHASE_IDLE, 0, 0);

    while(!d->io.should_exit(d->user_ctx)) {
        d->io.sleep_ms(connected ? 50 : 200, d->user_ctx);
        if(d->io.should_exit(d->user_ctx)) break;

        /* Replay any carryover from the previous iteration before
         * pulling fresh bytes. Use a snapshot copy to avoid feeding
         * back into the same buffer while iterating it. */
        if(pc.carryover_count > 0) {
            uint8_t snap[HWP_DRAIN_CHUNK];
            size_t n = pc.carryover_count;
            memcpy(snap, pc.carryover, n);
            pc.carryover_count = 0;
            pc.last_result = HWP_FEED_INCOMPLETE;
            for(size_t i = 0; i < n; i++) feed_byte(&pc, snap[i]);
        } else {
            pc.last_result = HWP_FEED_INCOMPLETE;
        }

        /* Drain at most one CDC chunk per iteration. The host's chunks
         * are paced at 64 bytes / 5 ms; pulling one chunk per iteration
         * preserves the parser's ability to back-pressure (subsequent
         * chunks stay queued in the CDC RX buffer until we ask for
         * them again next iteration). */
        uint8_t buf[HWP_DRAIN_CHUNK];
        size_t got = 0;
        if(pc.last_result != HWP_FEED_FRAME_READY) {
            got = d->io.serial_drain(buf, HWP_DRAIN_CHUNK, d->user_ctx);
            for(size_t i = 0; i < got; i++) feed_byte(&pc, buf[i]);
        }
        size_t bytes_rx = got + (pc.carryover_count > 0 ? 0 : 0);
        /* If we still don't have a frame, but got SOME bytes (partial
         * frame), keep looping. A short retry-with-sleep helps assemble
         * a multi-chunk frame inside one outer iteration without giving
         * the IDLE_RESET logic a chance to fire spuriously. */
        if(bytes_rx > 0 && pc.last_result == HWP_FEED_INCOMPLETE) {
            for(int retry = 0; retry < 5 &&
                                pc.last_result == HWP_FEED_INCOMPLETE; retry++) {
                d->io.sleep_ms(5, d->user_ctx);
                size_t more = d->io.serial_drain(buf, HWP_DRAIN_CHUNK,
                                                  d->user_ctx);
                if(more == 0) break;
                for(size_t i = 0; i < more; i++) feed_byte(&pc, buf[i]);
            }
        }

        uint32_t now = d->io.get_tick_ms(d->user_ctx);

        /* IDLE detection. ONLY fire when the signer is fully IDLE — a
         * busy mid-transaction state means the host is blocked waiting
         * for our response and the silence is OUR doing (Sinsemilla cmx
         * can keep the worker out of this loop for >>1.5 s). Firing
         * IDLE_RESET in that window flipped us to !connected, resumed
         * periodic PINGs, and the host PONGed every one of them; with
         * ~hundreds of PONGs queued in the CDC RX, the parser drain
         * dropped subsequent frames. */
        if(connected && got == 0 &&
           (now - last_rx_tick) > IDLE_RESET_MS &&
           d->signer->state == SIGNER_IDLE) {
            connected = false;
            hwp_parser_init(&d->parser);
            pc.last_result = HWP_FEED_INCOMPLETE;
            pc.carryover_count = 0;
            phase(d, HWP_PHASE_IDLE, 0, 0);
        }

        /* Periodic keepalive PING when truly idle (no host yet). */
        if(!connected && got == 0 &&
           (now - last_ping_tick) >= PING_PERIOD_MS) {
            send_frame(d, seq++, HWP_MSG_PING, NULL, 0);
            last_ping_tick = now;
        }

        if(pc.last_result == HWP_FEED_CRC_ERROR) {
            send_error(d, 0, HWP_ERR_BAD_FRAME, "CRC mismatch");
            hwp_parser_init(&d->parser);
            pc.last_result = HWP_FEED_INCOMPLETE;
            pc.carryover_count = 0;
            continue;
        }
        if(pc.last_result != HWP_FEED_FRAME_READY) continue;

        HwpFrame* f = &d->parser.frame;
        connected = true;
        last_rx_tick = now;

        /* Version check: v1 and v2 accepted. */
        if(f->version != HWP_VERSION && f->version != 0x01) {
            send_error(d, f->seq, HWP_ERR_UNSUPPORTED_VER,
                       "Unsupported protocol version");
            hwp_parser_init(&d->parser);
            pc.last_result = HWP_FEED_INCOMPLETE;
            continue;
        }

        switch(f->type) {
        case HWP_MSG_PONG:
            break;
        case HWP_MSG_PING:
            handle_ping(d, f, &user_confirmed, &sign_req_seen);
            break;
        case HWP_MSG_FVK_REQ:
            handle_fvk_req(d, f);
            break;
        case HWP_MSG_TX_OUTPUT:
            if(handle_tx_output(d, f)) {
                send_frame(d, f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
            }
            break;
        case HWP_MSG_TX_TRANSPARENT_INPUT:
            handle_tx_transparent_input(d, f);
            break;
        case HWP_MSG_TX_TRANSPARENT_OUTPUT:
            handle_tx_transparent_output(d, f);
            break;
        case HWP_MSG_TRANSPARENT_SIGN_REQ:
            handle_transparent_sign_req(d, f);
            break;
        case HWP_MSG_SIGN_REQ:
            handle_sign_req(d, f, &user_confirmed, &sign_req_seen);
            break;
        case HWP_MSG_ABORT:
            user_confirmed = false;
            orchard_signer_reset(d->signer);
            phase(d, HWP_PHASE_CONNECTED, 0, 0);
            break;
        default:
            send_error(d, f->seq, HWP_ERR_UNKNOWN, "Unknown message type");
            break;
        }

        /* The final confirmation belongs to one verified transaction. If
         * the signer is no longer VERIFIED (the session was reset, or a new
         * one has begun), it has to be asked again. */
        if(d->signer->state != SIGNER_VERIFIED) {
            user_confirmed = false;
            sign_req_seen = 0;
        }
        wipe_frame(d);

        /* After handling a frame, the parser is "done" with it — reset
         * state so the next byte starts the next frame. */
        hwp_parser_init(&d->parser);
        pc.last_result = HWP_FEED_INCOMPLETE;
    }

    /* Session over: the signer holds the incoming viewing keys of the
     * transaction in flight — do not leave them behind. The same goes for
     * the dispatcher's own buffers: the last frame sent (an FVK_RSP is the
     * viewing key) and the last one received. */
    orchard_signer_reset(d->signer);
    memzero(d->tx_buf, sizeof(d->tx_buf));
    memzero(&d->parser, sizeof(d->parser));
    memzero(&d->sign_req, sizeof(d->sign_req));
    memzero(&pc, sizeof(pc));
    return HWP_DISP_EXIT_REQUESTED;
}
