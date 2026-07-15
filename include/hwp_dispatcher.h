/*
 * hwp_dispatcher — device-side HWP protocol driver.
 *
 * Owns the dispatch loop, PING/PONG keepalive, IDLE detection,
 * multi-frame drain handling, and the per-message-type handlers
 * (FVK / TX_OUTPUT / TX_TRANSPARENT_* / SIGN_REQ / ...).
 *
 * Target-specific concerns — USB CDC primitives, UI scenes, sealed-storage
 * key loading — are injected via callbacks in HwpDispatcher.io / .ui.
 *
 * Usage (pseudocode):
 *
 *   OrchardSignerCtx signer;
 *   orchard_signer_init(&signer);
 *
 *   HwpDispatcher d = {
 *       .io = { .serial_drain = my_cdc_drain, ... },
 *       .ui = { .review_action = my_review_screen, ... },
 *       .keys = { .ak = ak, .nk = nk, .rivk = rivk, .ask = ask, ... },
 *       .signer = &signer,
 *       .testnet = is_testnet,
 *       .user_ctx = my_app_context,
 *   };
 *
 *   hwp_dispatcher_run(&d);
 *
 * The dispatcher returns when io.should_exit() returns true or on a
 * fatal protocol error. The signer state is left where it was so the
 * caller can inspect it for diagnostics; the caller owns its lifetime.
 */
#ifndef HWP_DISPATCHER_H
#define HWP_DISPATCHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hwp.h"
#include "orchard_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* High-level phase reported via ui.phase_update. The application uses
 * this to drive a persistent status footer ("zipher: verify  3/7") so
 * the user can see what the device is doing relative to the host. */
typedef enum {
    HWP_PHASE_IDLE,         /* no host yet (or host disconnected) */
    HWP_PHASE_CONNECTED,    /* host has handshaken */
    HWP_PHASE_META,         /* TxMeta accepted, awaiting actions */
    HWP_PHASE_VERIFY,       /* cmx/sighash crunching on this action */
    HWP_PHASE_REVIEW,       /* per-action review screen waiting for user */
    HWP_PHASE_TRANSPARENT,  /* transparent inputs/outputs flow */
    HWP_PHASE_AWAIT_CONFIRM,/* final amount/fee confirmation prompt */
    HWP_PHASE_SIGNING,      /* RedPallas signing this action */
    HWP_PHASE_DONE,         /* SIGN_RSP just sent for the last action */
    HWP_PHASE_ERROR,        /* device sent an Error frame */
} HwpPhase;

typedef enum {
    HWP_UI_OK = 0,
    HWP_UI_CANCELLED = 1,
    HWP_UI_EXIT = 2,        /* app shutting down — abort dispatcher */
} HwpUiResult;

typedef enum {
    HWP_DISP_OK = 0,
    HWP_DISP_EXIT_REQUESTED,
    HWP_DISP_FATAL,
} HwpDispatchResult;

typedef struct HwpDispatcherIo {
    /* Pull up to `out_cap` bytes from the CDC RX buffer (non-blocking).
     * Return count actually pulled (0..out_cap). The dispatcher calls
     * this repeatedly within an inner loop and STOPS as soon as the
     * parser has produced a complete frame — the unread bytes stay
     * queued for the next iteration. */
    size_t (*serial_drain)(uint8_t* out, size_t out_cap, void* ctx);
    /* Send `len` bytes; blocks until queued/sent. */
    void (*serial_send)(const uint8_t* data, size_t len, void* ctx);
    /* Get monotonic ms timestamp. */
    uint32_t (*get_tick_ms)(void* ctx);
    /* Cooperative sleep up to `ms` (may return early on event). */
    void (*sleep_ms)(uint32_t ms, void* ctx);
    /* True when the dispatcher should exit (e.g. user pressed Back). */
    bool (*should_exit)(void* ctx);
} HwpDispatcherIo;

typedef struct HwpDispatcherUi {
    /* Per-output review. Called for every transparent output (rendered
     * as a base58check t-address) and every Orchard action (rendered
     * as a bech32m UA) in the transaction, before signing. The
     * dispatcher does the encoding so the UI only sees a NUL-terminated
     * address string. Blocks until the user confirms, cancels, or the
     * app exits. */
    HwpUiResult (*review_output)(uint16_t idx_1_based, uint16_t total,
                                  const char* addr_str, uint64_t value,
                                  void* ctx);
    /* Per-tx fee review. Called once, AFTER every output has been
     * confirmed, with the on-device-computed miner fee
     * (= t_in - t_out + value_balance, evaluated by the library — NOT
     * a number supplied by the companion). The user must approve this
     * value or the signer refuses to advance past verify(), so a
     * hostile companion that inflates value_balance to siphon ZEC into
     * the miner fee cannot extract a signature.
     *
     * Optional: if a firmware leaves this NULL, the dispatcher falls
     * back to calling review_output() with addr_str = "Network fee"
     * so existing UIs still satisfy the no-blind-signing-for-fee
     * invariant — at a degraded UX cost (the fee appears as another
     * "output" row). */
    HwpUiResult (*review_fee)(uint64_t fee_zats, void* ctx);
    /* Per-Orchard-output memo review. Called once per Orchard action,
     * AFTER its recipient/value has been confirmed via review_output,
     * with the 512-byte memo plaintext that was captured by
     * orchard_signer_feed_action_with_note_and_memo() and verified
     * (cryptographically bound to enc_ciphertext on chain).
     *
     * The firmware is responsible for parsing the ZIP-302 lead byte and
     * rendering the memo accordingly:
     *   memo[0] == 0xF6                  -> empty memo; the dispatcher
     *                                       SKIPS the callback entirely
     *                                       (no prompt)
     *   memo[0] in 0x00..0xF4            -> UTF-8 text (trim trailing
     *                                       0x00 padding)
     *   memo[0] == 0xF5 or 0xF7..0xFF    -> opaque / non-text (firmware
     *                                       renders as hex or refuses)
     *
     * Optional: if NULL the dispatcher emits no memo prompt, leaving
     * memo verification to its cryptographic binding only. Existing
     * firmwares that have not been updated for HWP v5 keep working
     * without code changes at the cost of leaving the
     * "memo bound but not user-visible" gap open (a hostile companion
     * could show the user a different memo from the one declared to the
     * device — the binding catches divergence between declared-memo
     * and on-chain enc_ciphertext, but NOT divergence between
     * UI-displayed memo and declared-memo). */
    HwpUiResult (*review_memo)(uint16_t action_idx_1_based,
                                uint16_t total_actions,
                                const char* recipient_addr_str,
                                const uint8_t memo[512],
                                void* ctx);
    /* Final tx confirmation. `recipient_str` is the NUL-terminated UA
     * string the host advertised in SIGN_REQ. */
    HwpUiResult (*confirm_tx)(uint64_t amount, uint64_t fee,
                               const char* recipient_str, void* ctx);
    /* Network mismatch (companion expected the other network). Blocks
     * until user dismisses. */
    void (*network_error)(const char* msg, bool device_testnet, void* ctx);
    /* Non-blocking. Called whenever the dispatcher phase changes. */
    void (*phase_update)(HwpPhase phase, uint16_t idx_1_based, uint16_t total,
                          void* ctx);
    /* Non-blocking. Mid-crypto progress (0..100 + free-form label). */
    void (*progress)(uint8_t pct, const char* label, void* ctx);
} HwpDispatcherUi;

typedef struct HwpDispatcherKeys {
    const uint8_t* ak;        /* 32 */
    const uint8_t* nk;        /* 32 */
    const uint8_t* rivk;      /* 32 */
    const uint8_t* ask;       /* 32 — used by RedPallas signing */
    const uint8_t* t_sk;      /* 32 — secp256k1 spending key */
    const uint8_t* t_pubkey;  /* 33 — compressed secp256k1 pubkey */
} HwpDispatcherKeys;

typedef struct HwpDispatcher {
    HwpDispatcherIo io;
    HwpDispatcherUi ui;
    HwpDispatcherKeys keys;
    OrchardSignerCtx* signer;   /* caller-allocated, lifetime > dispatcher */
    bool testnet;
    void* user_ctx;             /* passed verbatim to every callback */
    /* Frame TX scratch + RX parser. Embedded in the dispatcher rather than
     * in static module storage so the TARGET decides where the memory
     * lives: constrained targets (Flipper Zero) heap-allocate the whole
     * HwpDispatcher for the session — keeping these buffers out of both
     * the FAP image (loader budget) and the worker thread stack.
     * hwp_dispatcher_run() (re)initialises the parser at entry; neither
     * field needs caller setup.
     *
     * The TX buffer is deliberately small: the device only ever SENDS
     * short frames (largest payload: FVK_RSP = 96 bytes, transparent
     * SIGN_RSP ≈ 106; error strings are capped well below the limit).
     * Only the RX parser needs a full HWP_MAX_PAYLOAD frame (the host
     * streams 1.4 KB action payloads). send_frame() refuses payloads
     * exceeding the TX cap instead of overflowing. */
#ifndef HWP_DISPATCHER_MAX_TX_PAYLOAD
#define HWP_DISPATCHER_MAX_TX_PAYLOAD 192
#endif
    uint8_t tx_buf[HWP_HEADER_SIZE + HWP_DISPATCHER_MAX_TX_PAYLOAD + HWP_CRC_SIZE];
    HwpParser parser;
    /* SIGN_REQ parse scratch. Lives here for the same reason as tx_buf:
     * with HWP_MAX_RECIPIENT = 255 the struct is ~300 bytes, which blew
     * handle_sign_req past the 512-byte per-function stack budget. Only
     * valid while a SIGN_REQ frame is being handled. */
    HwpSignReq sign_req;
} HwpDispatcher;

/* Run the dispatcher loop until io.should_exit() returns true or a
 * fatal transport error is encountered. */
HwpDispatchResult hwp_dispatcher_run(HwpDispatcher* d);

#ifdef __cplusplus
}
#endif

#endif /* HWP_DISPATCHER_H */
