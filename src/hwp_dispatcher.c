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
 *   - Transparent-output-only bootstrap: if the host sends a
 *     transparent-output stream with zero inputs (shielded → t-addr
 *     sweep), begin_transparent is invoked from the output handler
 *     with num_inputs=0; previously the state machine remained in
 *     RECEIVING_ACTIONS and rejected the first output.
 */
#include "hwp_dispatcher.h"

#include <string.h>

#include "hwp.h"
#include "memzero.h"
#include "orchard.h"
#include "redpallas.h"
#include "secp256k1.h"
#include "segwit_addr.h"
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
 * fvk payload, ECDSA scratch) into hwp_dispatcher_run's frame, and the
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

static HWP_NOINLINE void send_error(HwpDispatcher* d, uint8_t seq,
                                     HwpErrorCode code, const char* msg) {
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
    if(f->payload_len >= HWP_FVK_REQ_SIZE) {
        uint32_t req_coin = (uint32_t)f->payload[0] |
                            ((uint32_t)f->payload[1] << 8) |
                            ((uint32_t)f->payload[2] << 16) |
                            ((uint32_t)f->payload[3] << 24);
        uint32_t device_coin = d->testnet ? 1u : 133u;
        if(req_coin != 0 && req_coin != device_coin) {
            send_error(d, f->seq, HWP_ERR_NETWORK_MISMATCH,
                       d->testnet ? "Device is on testnet"
                                  : "Device is on mainnet");
            show_network_error(d,
                               d->testnet ? "Companion requested MAINNET"
                                          : "Companion requested TESTNET");
            return;
        }
        d->signer->coin_type = req_coin;
    }
    uint8_t payload[96];
    memcpy(payload, d->keys.ak, 32);
    memcpy(payload + 32, d->keys.nk, 32);
    memcpy(payload + 64, d->keys.rivk, 32);
    send_frame(d, f->seq, HWP_MSG_FVK_RSP, payload, 96);
}

/* Drive the per-output review loop after the host's sighash sentinel.
 * The loop iterates BOTH classes of recipients the transaction touches:
 *
 *   1. Transparent outputs (count = signer->transparent_state.outputs_received)
 *      rendered as base58check t-addresses. These are typically the
 *      "real" recipient for shielded → t-addr sweeps; without showing
 *      them the user would sign blindly while only confirming the
 *      change Orchard outputs.
 *
 *   2. Orchard actions (count = signer->actions_received). Per the
 *      library invariant, orchard_signer_confirm_action() must be
 *      called for every action before verify() will advance to
 *      VERIFIED — without that, sign() refuses with NOT_VERIFIED.
 *
 * Returns true if every recipient was confirmed; false on cancel/exit. */
static HWP_NOINLINE bool run_per_output_review(HwpDispatcher* d) {
    uint16_t n_t = d->signer->transparent_state.outputs_received;
    uint16_t n_o = d->signer->actions_received;
    uint16_t total = (uint16_t)(n_t + n_o);
    /* orchard_encode_ua_raw requires `ua_out_len >= 200` for its
     * internal scratch (raw UA + padding + F4Jumble buffer). The
     * encoded mainnet Orchard-only UA itself is ~106 chars; the
     * 200-byte floor is defensive against future receiver types and
     * the Bech32m max-length cap. */
    char addr_buf[256];

    /* Step 1: transparent outputs. */
    for(uint16_t i = 0; i < n_t; i++) {
        uint8_t script[25];
        size_t script_len = 0;
        uint64_t value = 0;
        OrchardSignerError gerr =
            orchard_signer_get_transparent_output_display(
                d->signer, i, &value, script, sizeof(script), &script_len);
        if(gerr != SIGNER_OK) return false;
        size_t enc = script_to_taddr(script, script_len, d->testnet,
                                      addr_buf, sizeof(addr_buf));
        if(enc == 0) {
            /* Non-standard script: the lib already refused at feed
             * time, but if we somehow got here without a renderable
             * address we cannot satisfy no-blind-signing. */
            return false;
        }
        phase(d, HWP_PHASE_REVIEW, (uint16_t)(i + 1), total);
        HwpUiResult r = d->ui.review_output((uint16_t)(i + 1), total,
                                              addr_buf, value, d->user_ctx);
        if(r != HWP_UI_OK) return false;
    }

    /* Step 2: Orchard actions. */
    const char* hrp = d->testnet ? "utest" : "u";
    for(uint16_t i = 0; i < n_o; i++) {
        uint8_t recipient[43];
        uint64_t value;
        OrchardSignerError gerr =
            orchard_signer_get_action_display(d->signer, i, recipient, &value);
        if(gerr != SIGNER_OK) return false;
        int enc = orchard_encode_ua_raw(recipient, recipient + 11, hrp,
                                         addr_buf, sizeof(addr_buf));
        if(enc <= 0) return false;

        phase(d, HWP_PHASE_REVIEW, (uint16_t)(n_t + i + 1), total);
        HwpUiResult r = d->ui.review_output((uint16_t)(n_t + i + 1), total,
                                              addr_buf, value, d->user_ctx);
        if(r != HWP_UI_OK) return false;

        /* Memo review — only when (a) the firmware opted into the memo UI
         * callback, AND (b) the action was fed via the v5 (memo-aware)
         * path, AND (c) the memo is not the ZIP-302 empty-memo sentinel
         * (lead byte 0xF6). The cryptographic binding from
         * feed_action_with_note_and_memo() ensures the bytes the user
         * sees here are byte-for-byte what ends up in the on-chain
         * enc_ciphertext, closing the "memo bound but not user-visible"
         * gap that AEAD recomputation alone leaves open.
         *
         * `memo_buf` is static to keep run_per_output_review under the
         * 512 B per-function stack budget — same pattern used elsewhere
         * for the larger Pallas / AEAD scratchpads. Single-threaded
         * signer => no re-entrancy. */
        if(d->ui.review_memo != NULL) {
            static uint8_t memo_buf[512];
            bool memo_present = false;
            if(orchard_signer_get_action_memo(d->signer, i, memo_buf, &memo_present)
               == SIGNER_OK && memo_present && memo_buf[0] != 0xF6) {
                HwpUiResult rm = d->ui.review_memo(
                    (uint16_t)(n_t + i + 1), total,
                    addr_buf, memo_buf, d->user_ctx);
                if(rm != HWP_UI_OK) return false;
            }
        }

        if(orchard_signer_confirm_action(d->signer, i) != SIGNER_OK) {
            return false;
        }
    }

    /* Step 3: miner fee. The library refuses to advance verify() past
     * SIGNER_VERIFIED unless the user has approved the on-device-computed
     * fee value (no-blind-signing-for-fee invariant). Compute it from
     * already-collected meta + transparent state, show it on the trusted
     * screen, and propagate the user's decision to confirm_fee(). */
    uint64_t fee_zats = 0;
    OrchardSignerError ferr = orchard_signer_get_fee(d->signer, &fee_zats);
    if(ferr != SIGNER_OK) {
        /* FEE_OVERFLOW or FEE_NEGATIVE: the lib has already reset ctx. */
        return false;
    }
    phase(d, HWP_PHASE_REVIEW, (uint16_t)(total + 1), (uint16_t)(total + 1));
    HwpUiResult fee_r;
    if(d->ui.review_fee != NULL) {
        fee_r = d->ui.review_fee(fee_zats, d->user_ctx);
    } else {
        /* Backward-compat fallback: render the fee as a synthetic
         * extra output entry. UI sees idx = total+1 with addr_str =
         * "Network fee", value = fee_zats. */
        fee_r = d->ui.review_output(
            (uint16_t)(total + 1), (uint16_t)(total + 1),
            "Network fee", fee_zats, d->user_ctx);
    }
    if(fee_r != HWP_UI_OK) return false;

    if(orchard_signer_confirm_fee(d->signer) != SIGNER_OK) {
        return false;
    }
    return true;
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
        serr = orchard_signer_feed_meta(d->signer, txo.output_data,
                                         txo.output_data_len, txo.total_outputs);
        phase(d, HWP_PHASE_META, 0, txo.total_outputs);
        if(serr == SIGNER_ERR_NETWORK_MISMATCH) {
            send_error(d, f->seq, HWP_ERR_NETWORK_MISMATCH,
                       "TxMeta coin_type != session coin_type");
            show_network_error(d, "TX metadata network mismatch");
            orchard_signer_reset(d->signer);
            return false;
        } else if(serr == SIGNER_ERR_SAPLING_NOT_EMPTY) {
            send_error(d, f->seq, HWP_ERR_SAPLING_NOT_EMPTY,
                       "Sapling components not allowed (Orchard-only)");
            orchard_signer_reset(d->signer);
            return false;
        } else if(serr == SIGNER_ERR_TOO_MANY_ACTIONS) {
            send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                       "Transaction has more outputs than the device can display");
            orchard_signer_reset(d->signer);
            return false;
        } else if(serr != SIGNER_OK) {
            send_error(d, f->seq, HWP_ERR_BAD_FRAME, "Bad TX metadata");
            orchard_signer_reset(d->signer);
            return false;
        }
    } else if(txo.output_index == txo.total_outputs) {
        /* Sighash sentinel. */
        if(txo.output_data_len != 32) {
            send_error(d, f->seq, HWP_ERR_BAD_SIGHASH, "Bad sighash length");
            orchard_signer_reset(d->signer);
            return false;
        }
        if(!run_per_output_review(d)) {
            send_error(d, f->seq, HWP_ERR_USER_CANCELLED,
                       "User cancelled per-output review");
            orchard_signer_reset(d->signer);
            return false;
        }
        /* The lib's verify() runs Sinsemilla over Pallas — multi-second
         * on STM32. The progress callback will fire from inside pallas
         * if the app wired pallas_set_progress_cb. */
        if(d->ui.progress) d->ui.progress(0, "Verifying ZIP-244 sighash...", d->user_ctx);
        serr = orchard_signer_verify(d->signer, txo.output_data);
        if(serr == SIGNER_ERR_SIGHASH_MISMATCH) {
            send_error(d, f->seq, HWP_ERR_SIGHASH_MISMATCH,
                       "Device sighash != companion sighash");
            orchard_signer_reset(d->signer);
            return false;
        } else if(serr != SIGNER_OK) {
            send_error(d, f->seq, HWP_ERR_INVALID_STATE, "Verify failed");
            orchard_signer_reset(d->signer);
            return false;
        }
    } else {
        /* Action data 0..N-1. Discriminate v4 vs v5 by payload size:
         *   v4 (903 B)  = action(820) + recipient(43) + value(8) + rseed(32)
         *   v5 (1415 B) = v4 + memo(512)
         * The v5 path additionally verifies enc_ciphertext + epk on-device,
         * closing the memo-substitution attack that v4 cmx-only leaves open.
         *
         * v6 (NU6.3 / Ironwood) sessions — recognized by the v6 TxMeta
         * layout received at feed_meta — prefix every action payload with
         * a 1-byte pool tag (0x00 = sealed Orchard, 0x01 = Ironwood).
         * Strip and validate it, then reuse the v4/v5 size discrimination
         * on the remainder; the tag routes the action into the matching
         * ZIP-244 pool digest tree. */
        phase(d, HWP_PHASE_VERIFY,
              (uint16_t)(txo.output_index + 1), txo.total_outputs);
        if(d->ui.progress) {
            d->ui.progress(0, "Verifying output...", d->user_ctx);
        }

        const uint8_t* adata = txo.output_data;
        size_t alen = txo.output_data_len;
        Zip244Pool pool = ZIP244_POOL_ORCHARD;
        if(d->signer->tx_meta.is_v6) {
            if(alen < HWP_POOL_TAG_SIZE || adata[0] > ZIP244_POOL_IRONWOOD) {
                send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                           "Bad v6 action pool tag");
                orchard_signer_reset(d->signer);
                return false;
            }
            pool = (Zip244Pool)adata[0];
            adata += HWP_POOL_TAG_SIZE;
            alen -= HWP_POOL_TAG_SIZE;
        }

        if(alen == HWP_ACTION_DATA_SIZE_V5) {
            HwpActionV5 av5;
            if(!hwp_parse_action_v5(adata, alen, &av5)) {
                send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                           "Action v5 payload size mismatch");
                orchard_signer_reset(d->signer);
                return false;
            }
            serr = orchard_signer_feed_action_with_note_and_memo(
                d->signer, pool, av5.action, HWP_ACTION_DATA_SIZE,
                av5.recipient, av5.value, av5.rseed,
                av5.memo);
            if(serr == SIGNER_ERR_NOTE_COMMITMENT_MISMATCH) {
                send_error(d, f->seq, HWP_ERR_NOTE_COMMITMENT_MISMATCH,
                           "Action cmx does not commit to claimed note");
                orchard_signer_reset(d->signer);
                return false;
            } else if(serr == SIGNER_ERR_MEMO_MISMATCH) {
                send_error(d, f->seq, HWP_ERR_MEMO_MISMATCH,
                           "enc_ciphertext does not match recomputed memo/esk");
                orchard_signer_reset(d->signer);
                return false;
            } else if(serr == SIGNER_ERR_BAD_PK_D) {
                send_error(d, f->seq, HWP_ERR_BAD_PK_D,
                           "pk_d does not decode to a valid Pallas point");
                orchard_signer_reset(d->signer);
                return false;
            } else if(serr == SIGNER_ERR_TOO_MANY_ACTIONS) {
                send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                           "Transaction has more outputs than the device can display");
                orchard_signer_reset(d->signer);
                return false;
            } else if(serr != SIGNER_OK) {
                send_error(d, f->seq, HWP_ERR_BAD_FRAME, "Bad action v5 data");
                orchard_signer_reset(d->signer);
                return false;
            }
        } else {
            /* Backward-compat v4 path. */
            HwpActionV4 av4;
            if(!hwp_parse_action_v4(adata, alen, &av4)) {
                send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                           "Action payload size mismatch");
                orchard_signer_reset(d->signer);
                return false;
            }
            serr = orchard_signer_feed_action_with_note(
                d->signer, pool, av4.action, HWP_ACTION_DATA_SIZE,
                av4.recipient, av4.value, av4.rseed);
            if(serr == SIGNER_ERR_NOTE_COMMITMENT_MISMATCH) {
                send_error(d, f->seq, HWP_ERR_NOTE_COMMITMENT_MISMATCH,
                           "Action cmx does not commit to claimed recipient/value/rseed");
                orchard_signer_reset(d->signer);
                return false;
            } else if(serr == SIGNER_ERR_TOO_MANY_ACTIONS) {
                send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                           "Transaction has more outputs than the device can display");
                orchard_signer_reset(d->signer);
                return false;
            } else if(serr != SIGNER_OK) {
                send_error(d, f->seq, HWP_ERR_BAD_FRAME, "Bad action data");
                orchard_signer_reset(d->signer);
                return false;
            }
        }
    }
    return true;
}

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

    /* First input → begin transparent session. */
    if(input_index == 0 && d->signer->state == SIGNER_RECEIVING_ACTIONS) {
        OrchardSignerError berr =
            orchard_signer_begin_transparent(d->signer, total_inputs, 0);
        if(berr != SIGNER_OK) {
            send_error(d, f->seq, HWP_ERR_INVALID_STATE, "Cannot begin transparent");
            orchard_signer_reset(d->signer);
            return;
        }
    }

    /* Sentinel: index == total → verify digest. */
    if(input_index == total_inputs) {
        if(t_data_len != 32) {
            send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                       "Transparent sentinel must be 32 bytes");
            orchard_signer_reset(d->signer);
            return;
        }
        OrchardSignerError serr =
            orchard_signer_verify_transparent(d->signer, t_data);
        if(serr == SIGNER_ERR_TRANSPARENT_MISMATCH) {
            send_error(d, f->seq, HWP_ERR_TRANSPARENT_DIGEST_MISMATCH,
                       "Transparent digest mismatch");
            return;
        } else if(serr != SIGNER_OK) {
            send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                       "Transparent verify failed");
            orchard_signer_reset(d->signer);
            return;
        }
        send_frame(d, f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
        return;
    }

    /* Normal input data. */
    OrchardSignerError serr =
        orchard_signer_feed_transparent_input(d->signer, t_data, t_data_len);
    if(serr != SIGNER_OK) {
        HwpErrorCode code = (serr == SIGNER_ERR_BAD_STATE)
                                ? HWP_ERR_INVALID_STATE
                                : HWP_ERR_BAD_FRAME;
        send_error(d, f->seq, code, "Bad transparent input");
        orchard_signer_reset(d->signer);
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

    /* Output-only transparent flow (shielded → t-addr sweep, zero
     * transparent inputs): the state machine starts in
     * RECEIVING_ACTIONS until begin_transparent runs; without this
     * bootstrap, feed_transparent_output would return BAD_STATE and
     * the session would deadlock. */
    if(output_index == 0 && d->signer->state == SIGNER_RECEIVING_ACTIONS) {
        OrchardSignerError berr =
            orchard_signer_begin_transparent(d->signer, 0, total_outputs);
        if(berr != SIGNER_OK) {
            send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                       "Cannot begin transparent (output-only)");
            orchard_signer_reset(d->signer);
            return;
        }
    }

    /* Inputs-then-outputs: begin already ran with outputs_expected=0;
     * fill it from the first output's total. */
    if(output_index == 0 && d->signer->transparent_outputs_expected == 0) {
        d->signer->transparent_outputs_expected = total_outputs;
    }

    OrchardSignerError serr =
        orchard_signer_feed_transparent_output(d->signer, t_data, t_data_len);
    if(serr != SIGNER_OK) {
        HwpErrorCode code = (serr == SIGNER_ERR_BAD_STATE)
                                ? HWP_ERR_INVALID_STATE
                                : HWP_ERR_BAD_FRAME;
        send_error(d, f->seq, code, "Bad transparent output");
        orchard_signer_reset(d->signer);
        return;
    }
    send_frame(d, f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
}

static HWP_NOINLINE void handle_transparent_sign_req(HwpDispatcher* d,
                                                       HwpFrame* f) {
    if(f->payload_len < HWP_TX_OUTPUT_HEADER) {
        send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                   "Transparent sign req too short");
        return;
    }
    uint16_t input_index =
        (uint16_t)f->payload[0] | ((uint16_t)f->payload[1] << 8);
    const uint8_t* input_data = f->payload + HWP_TX_OUTPUT_HEADER;
    uint16_t input_data_len = (uint16_t)(f->payload_len - HWP_TX_OUTPUT_HEADER);

    if(!d->signer->transparent_verified) {
        send_error(d, f->seq, HWP_ERR_INVALID_STATE,
                   "Transparent not verified");
        return;
    }

    uint8_t per_input_sighash[32];
    zip244_transparent_per_input_sighash(
        &d->signer->transparent_state, input_index,
        input_data, input_data_len, 0x01, per_input_sighash);

    uint8_t compact_sig[64];
    if(secp256k1_ecdsa_sign_digest(d->keys.t_sk, per_input_sighash,
                                    compact_sig) != 0) {
        memzero(per_input_sighash, sizeof(per_input_sighash));
        send_error(d, f->seq, HWP_ERR_SIGN_FAILED, "ECDSA sign failed");
        return;
    }
    uint8_t der_sig[72];
    size_t der_len = secp256k1_sig_to_der(compact_sig, der_sig);
    memzero(compact_sig, sizeof(compact_sig));

    uint8_t rsp[HWP_TRANSPARENT_SIGN_RSP_MAX];
    rsp[0] = (uint8_t)der_len;
    memcpy(rsp + 1, der_sig, der_len);
    rsp[1 + der_len] = 0x01;  /* SIGHASH_ALL */
    memcpy(rsp + 1 + der_len + 1, d->keys.t_pubkey, 33);

    size_t rsp_len = 1 + der_len + 1 + 33;
    send_frame(d, f->seq, HWP_MSG_TRANSPARENT_SIGN_RSP, rsp, (uint16_t)rsp_len);
    memzero(per_input_sighash, sizeof(per_input_sighash));
}

static HWP_NOINLINE void handle_sign_req(HwpDispatcher* d, HwpFrame* f,
                                          bool* user_confirmed,
                                          uint16_t* sign_req_seen) {
    /* Parse into the dispatcher-embedded scratch: with the 255-byte
     * recipient the struct no longer fits the per-function stack budget
     * (see the field's note in hwp_dispatcher.h). */
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
    } else if(chk == SIGNER_ERR_WRONG_SIGHASH) {
        send_error(d, f->seq, HWP_ERR_SIGHASH_MISMATCH,
                   "SIGN_REQ sighash != verified sighash");
        return;
    } else if(chk != SIGNER_OK) {
        send_error(d, f->seq, HWP_ERR_INVALID_STATE, "Signer check failed");
        return;
    }

    if(!*user_confirmed) {
        /* Decide address type + network from the recipient string.
         *   "u"      → Orchard/shielded mainnet UA
         *   "utest"  → Orchard/shielded testnet UA
         *   "t1","t3"→ transparent P2PKH/P2SH mainnet (Zcash main params)
         *   "tm","t2"→ transparent P2PKH/P2SH testnet
         * Required for shielded → t-addr sweeps: the SIGN_REQ.recipient
         * is the destination t-addr, not a UA, and the previous code
         * (strncmp(... "utest", 5)) only recognized shielded testnet
         * and rejected every transparent recipient as a network
         * mismatch. The transparent digest the device already verified
         * is what binds SIGN_REQ.recipient to the actual sent funds. */
        const char* r = req->recipient;
        bool is_shielded;
        bool addr_is_testnet;
        if(r[0] == 'u') {
            is_shielded = true;
            addr_is_testnet = (strncmp(r, "utest", 5) == 0);
        } else if(r[0] == 't' &&
                  (r[1] == '1' || r[1] == '3' || r[1] == 'm' || r[1] == '2')) {
            is_shielded = false;
            addr_is_testnet = (r[1] == 'm' || r[1] == '2');
        } else {
            send_error(d, f->seq, HWP_ERR_BAD_FRAME,
                       "Unknown recipient address type");
            return;
        }
        if(addr_is_testnet != d->testnet) {
            send_error(d, f->seq, HWP_ERR_NETWORK_MISMATCH,
                       d->testnet ? "Mainnet addr on testnet signer"
                                  : "Testnet addr on mainnet signer");
            show_network_error(d, addr_is_testnet ? "Received TESTNET address"
                                                  : "Received MAINNET address");
            return;
        }

        /* Constant-time recipient binding: for shielded recipients the
         * SIGN_REQ.recipient UA must encode an Orchard receiver that
         * appears in one of the actions the user already confirmed in
         * the per-output review loop. Closes the post-confirmation
         * recipient-substitution attack. For transparent recipients
         * there is no equivalent on-device check at this layer — the
         * safety property is delegated to the transparent digest, which
         * the device cross-verifies twice (against TxMeta and against
         * the sentinel) before flipping `transparent_verified = true`.
         * TODO: surface the transparent outputs in the per-output
         * review so the user actually sees the destination t-addr
         * before signing (requires preserving script_pubkey + a small
         * base58check encoder on-device). */
        if(is_shielded) {
            uint8_t intended_recipient[43];
            const char* hrp = d->testnet ? "utest" : "u";
            int dec = orchard_decode_ua_orchard_receiver(
                r, hrp, intended_recipient);
            if(dec != 0 ||
               !orchard_signer_recipient_matches_any(d->signer,
                                                      intended_recipient)) {
                send_error(d, f->seq, HWP_ERR_RECIPIENT_MISMATCH,
                           "SIGN_REQ recipient does not match any confirmed action");
                memzero(intended_recipient, sizeof(intended_recipient));
                orchard_signer_reset(d->signer);
                return;
            }
            memzero(intended_recipient, sizeof(intended_recipient));
        }

        phase(d, HWP_PHASE_AWAIT_CONFIRM, 0, d->signer->actions_received);
        HwpUiResult uir = d->ui.confirm_tx(req->amount, req->fee, req->recipient,
                                            d->user_ctx);
        if(uir != HWP_UI_OK) {
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
        send_error(d, f->seq, HWP_ERR_SIGN_FAILED, "RedPallas sign failed");
        return;
    }

    uint8_t rsp[96];
    memcpy(rsp, sig, 64);
    memcpy(rsp + 64, rk, 32);
    send_frame(d, f->seq, HWP_MSG_SIGN_RSP, rsp, 96);

    if(*sign_req_seen >= d->signer->actions_received) {
        /* Last sig for this transaction. Show "Signature sent!" briefly
         * so the user sees the confirmation, then reset everything so a
         * follow-up tx from the SAME companion session starts clean
         * (the signer state machine refuses feed_meta unless we're back
         * in IDLE). The 2.5 s linger is long enough to read the
         * confirmation but short enough that a user pressing the back
         * button to start another tx isn't kept waiting. */
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
    if(!d || !d->signer || !d->io.serial_drain || !d->io.serial_send ||
       !d->io.get_tick_ms || !d->io.sleep_ms || !d->io.should_exit ||
       !d->ui.review_output || !d->ui.confirm_tx) {
        return HWP_DISP_FATAL;
    }

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

        /* After handling a frame, the parser is "done" with it — reset
         * state so the next byte starts the next frame. */
        hwp_parser_init(&d->parser);
        pc.last_result = HWP_FEED_INCOMPLETE;
    }

    return HWP_DISP_EXIT_REQUESTED;
}
