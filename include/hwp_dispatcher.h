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
 *   orchard_signer_init(&signer, is_testnet ? ORCHARD_SIGNER_COIN_TESTNET
 *                                           : ORCHARD_SIGNER_COIN_MAINNET);
 *
 *   HwpDispatcher d = {
 *       .io = { .serial_drain = my_cdc_drain, ... },
 *       .ui = { .review_output = my_review_screen, ... },
 *       .keys = { .ak = ak, .nk = nk, .rivk = rivk, .ask = ask },
 *       .signer = &signer,
 *       .testnet = is_testnet,
 *       .user_ctx = my_app_context,
 *   };
 *
 *   hwp_dispatcher_run(&d);
 *
 * The dispatcher returns HWP_DISP_FATAL at once — before any I/O — if a
 * mandatory callback or key is NULL, or if `testnet` disagrees with the
 * network the signer was initialised for. Otherwise it returns when
 * io.should_exit() returns true. On return the signer has been reset
 * (orchard_signer_reset): the session's incoming viewing keys do not
 * outlive the dispatcher. The caller owns the signer's lifetime.
 *
 * What the host is trusted for: see README, "On-Device Verification".
 * In particular the dispatcher never takes ownership information from the
 * host — whether an output is the wallet's change is decided by the signer
 * from keys.ak / keys.nk / keys.rivk, which MUST be the device's own.
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

/* What kind of output review_output is being asked to show. Decided by
 * the device (see OrchardOutputOwnership); 0 is not a member so that a
 * zero-initialised struct is recognisably invalid. */
typedef enum {
    HWP_OUTPUT_TRANSPARENT = 1, /* t-address. Always counted as leaving the
                                   wallet (own t-addresses are not recognised). */
    HWP_OUTPUT_EXTERNAL    = 2, /* shielded, NOT this wallet's: a payment.    */
    HWP_OUTPUT_OWN_CHANGE  = 3, /* shielded, this wallet's internal (change)
                                   key.                                        */
    HWP_OUTPUT_OWN_ADDRESS = 4, /* shielded, one of this wallet's own
                                   receiving addresses.                        */
} HwpOutputKind;

/* What the device established about an output's memo. 0 is not a member. */
typedef enum {
    HWP_MEMO_NONE           = 1, /* shielded output VERIFIED to carry no memo */
    HWP_MEMO_PRESENT        = 2, /* verified memo; review_memo() follows       */
    HWP_MEMO_NOT_APPLICABLE = 3, /* transparent output: there is no memo field */
} HwpMemoStatus;

/* One output for the user to review. REQUIRED UI BEHAVIOUR per `kind`:
 *
 *   HWP_OUTPUT_TRANSPARENT / HWP_OUTPUT_EXTERNAL
 *       Show `address` and `value` as a payment leaving the wallet. The
 *       user has to read the address: the device cannot know who it is.
 *       For HWP_OUTPUT_EXTERNAL also show whether there is a memo: say
 *       "Memo: none" when `memo == HWP_MEMO_NONE`. A memo the user expected
 *       (an exchange deposit tag) and that is missing is otherwise visible
 *       only as a screen that does not come.
 *   HWP_OUTPUT_OWN_CHANGE
 *       Show "Change (your wallet)" and `value`. Do not present `address`
 *       as a recipient (it may be shown as detail).
 *   HWP_OUTPUT_OWN_ADDRESS
 *       Show "Your address" and `value`; `address` may be shown.
 *
 * A firmware must never label an output as the wallet's unless `kind` says
 * so, and must not derive the label from anything the host sent.
 *
 * `value == 0` only occurs together with HWP_MEMO_PRESENT (an output
 * verified to carry neither value nor a memo is padding: it is not sent to
 * this callback at all, only counted in OrchardSignerTotals.n_zero_value).
 * Present it as a message that carries no funds, not as a payment.
 *
 * `index` / `total` number the outputs that are shown (1-based), not the
 * transaction's actions. */
typedef struct {
    HwpOutputKind kind;
    uint16_t index;
    uint16_t total;
    const char* address;   /* NUL-terminated t-address or Orchard UA */
    uint64_t value;        /* zatoshis */
    HwpMemoStatus memo;
    bool has_memo;         /* == (memo == HWP_MEMO_PRESENT) */
} HwpOutputReview;

typedef struct HwpDispatcherUi {
    /* Per-output review (mandatory). Called for every transparent output
     * and for every shielded output that carries value or a memo, before
     * signing. Blocks until the user confirms, cancels, or the app exits.
     * Only HWP_UI_OK counts as approval; any other return value ends the
     * session. */
    HwpUiResult (*review_output)(const HwpOutputReview* out, void* ctx);
    /* Totals review (mandatory). Called once, after every output has been
     * confirmed, with numbers computed on the device from data the signed
     * sighash binds. The UI MUST show at least totals->total_leaving
     * ("Leaving your wallet") and totals->fee; showing own_internal as
     * "Change" and n_zero_value as padding is recommended. */
    HwpUiResult (*review_totals)(const OrchardSignerTotals* totals, void* ctx);
    /* Memo review. Called right after review_output for an output with
     * HWP_MEMO_PRESENT, with the 512-byte memo plaintext the device
     * verified against enc_ciphertext. Never called for an empty memo
     * (0xF6 + zeros, or all zeros).
     *
     * The firmware parses the ZIP-302 lead byte:
     *   memo[0] in 0x00..0xF4   -> UTF-8 text (trim trailing 0x00 padding)
     *   anything else           -> opaque / non-text (render as hex)
     *
     * May be NULL on a device with no way to show a memo — but then a
     * transaction that carries one is REFUSED (Error LIMIT_EXCEEDED), not
     * signed with the memo unseen. */
    HwpUiResult (*review_memo)(uint16_t index,
                                uint16_t total,
                                const char* recipient_addr_str,
                                const uint8_t memo[512],
                                void* ctx);
    /* Final confirmation before the first signature (mandatory). `totals`
     * are the same device-computed numbers review_totals showed
     * (n_external and n_transparent_out say how many payments there are).
     * NOTHING from the host reaches this screen: the recipient, amount and
     * fee fields of SIGN_REQ are ignored.
     *
     * (The previous signature also passed `host_recipient`, the SIGN_REQ
     * string. It could name an address no review screen had shown — a
     * zero-value output, or the wallet's own change.) */
    HwpUiResult (*confirm_tx)(const OrchardSignerTotals* totals, void* ctx);
    /* Network mismatch (companion expected the other network). Blocks
     * until user dismisses. */
    void (*network_error)(const char* msg, bool device_testnet, void* ctx);
    /* Non-blocking. Called whenever the dispatcher phase changes. */
    void (*phase_update)(HwpPhase phase, uint16_t idx_1_based, uint16_t total,
                          void* ctx);
    /* Non-blocking. Mid-crypto progress (0..100 + free-form label). */
    void (*progress)(uint8_t pct, const char* label, void* ctx);
} HwpDispatcherUi;

/* The device's own keys — all four mandatory (hwp_dispatcher_run returns
 * HWP_DISP_FATAL if one is NULL). ak / nk / rivk are both what FVK_RSP
 * sends and what every output is classified against (own change / own
 * address / external), so they must come from the device's storage, never
 * from the host, and must be the keys of the network the signer was
 * initialised for.
 *
 * There is deliberately NO transparent key here (the former t_sk /
 * t_pubkey fields were removed): the dispatcher does not sign transparent
 * inputs, and a firmware must not load that key for it. */
typedef struct HwpDispatcherKeys {
    const uint8_t* ak;        /* 32 */
    const uint8_t* nk;        /* 32 */
    const uint8_t* rivk;      /* 32 */
    const uint8_t* ask;       /* 32 — used by RedPallas signing */
} HwpDispatcherKeys;

typedef struct HwpDispatcher {
    HwpDispatcherIo io;
    HwpDispatcherUi ui;
    HwpDispatcherKeys keys;
    OrchardSignerCtx* signer;   /* caller-allocated, lifetime > dispatcher */
    bool testnet;               /* must match the signer's coin type (init) */
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
     * short frames (largest payload: FVK_RSP / SIGN_RSP = 96 bytes;
     * error strings are capped well below the limit).
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
