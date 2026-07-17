/**
 * Orchard Signing Context — enforces ZIP-244 verification before signing.
 *
 * This module wraps the signing state machine so that:
 *   1. The caller feeds TX metadata + action data (TX_OUTPUT messages)
 *   2. The context computes the ZIP-244 sighash incrementally
 *   3. The caller provides the expected sighash for comparison
 *   4. Only after successful verification can sign() be called
 *
 * Attempting to sign without completing ZIP-244 verification returns an error.
 * This is a library-level invariant that firmware cannot bypass.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "zip244.h"

/**
 * Maximum number of Orchard actions the signer will track for per-action
 * user confirmation. A transaction with more actions is rejected at
 * feed_meta() time. This bounds the per-context display storage at
 * MAX_ACTIONS * sizeof(OrchardActionDisplay) ≈ 16 * 52 = 832 bytes.
 *
 * Practically every Zcash wallet today produces 2..4 Orchard actions
 * per transaction; the default of 16 is a generous ceiling for targets
 * with room to spare (ESP32-class and hosts).
 *
 * RAM-constrained targets override this (and the other capacity
 * tunables below) with compile definitions rather than by editing the
 * library — the library stays generic and each consumer picks its own
 * memory/capability trade-off. E.g. FlipZcash (application.fam):
 *   cdefines=["ORCHARD_SIGNER_MAX_ACTIONS=8", "ORCHARD_SIGNER_MAX_MEMOS=4", ...]
 * IMPORTANT: an override must be applied uniformly to every translation
 * unit that includes this header (library AND application sources) —
 * these constants shape struct layouts, so mixed values are an ABI
 * mismatch. Overriding targets should also add a
 * _Static_assert(sizeof(OrchardSignerCtx) <= <budget>, ...) next to
 * their allocation so a future capacity bump fails the build instead of
 * the device.
 */
#ifndef ORCHARD_SIGNER_MAX_ACTIONS
#define ORCHARD_SIGNER_MAX_ACTIONS 16
#endif

/**
 * Maximum number of transparent outputs the signer will capture for
 * per-output display. Bounded so the captured script + value array
 * costs at most MAX_T_OUTPUTS * 34 ≈ 272 bytes of RAM. Eight is
 * generous for any realistic Zcash transaction (a typical shielded →
 * t-addr sweep produces exactly one transparent output).
 */
#ifndef ORCHARD_SIGNER_MAX_T_OUTPUTS
#define ORCHARD_SIGNER_MAX_T_OUTPUTS 8
#endif

/* Sanity bound: the action/output counters are uint16_t. Bounds for the
 * memo-pool tunable are asserted next to its definition below. */
_Static_assert(ORCHARD_SIGNER_MAX_ACTIONS >= 2 && ORCHARD_SIGNER_MAX_ACTIONS <= 65535,
               "ORCHARD_SIGNER_MAX_ACTIONS must fit the uint16_t action counters");

typedef enum {
    SIGNER_IDLE,                     /* Waiting for metadata */
    SIGNER_RECEIVING_TRANSPARENT,    /* Collecting transparent inputs/outputs (v3) */
    SIGNER_RECEIVING_ACTIONS,        /* Metadata received, collecting actions */
    SIGNER_VERIFIED,                 /* ZIP-244 sighash verified, signing allowed */
} OrchardSignerState;

typedef enum {
    SIGNER_OK = 0,
    SIGNER_ERR_BAD_META,          /* Invalid metadata payload — including
                                     legacy pre-v6 TxMeta layouts (125/129
                                     bytes): the library is v6-only and
                                     rejects them outright */
    SIGNER_ERR_BAD_ACTION,        /* Invalid action data */
    SIGNER_ERR_BAD_STATE,         /* Unexpected call for current state */
    SIGNER_ERR_SIGHASH_MISMATCH,  /* Device-computed sighash != companion sighash */
    SIGNER_ERR_NOT_VERIFIED,      /* sign() called without verification */
    SIGNER_ERR_WRONG_SIGHASH,     /* SIGN_REQ sighash doesn't match verified one */
    SIGNER_ERR_SIGN_FAILED,       /* redpallas_sign returned error */
    SIGNER_ERR_NETWORK_MISMATCH,         /* TxMeta coin_type != session coin_type */
    SIGNER_ERR_TRANSPARENT_BAD_INPUT,    /* Invalid transparent input data */
    SIGNER_ERR_TRANSPARENT_BAD_OUTPUT,   /* Invalid transparent output data */
    SIGNER_ERR_TRANSPARENT_MISMATCH,     /* Transparent digest mismatch (v3) */
    SIGNER_ERR_SAPLING_NOT_EMPTY,        /* sapling_digest != empty-bundle constant
                                            (Orchard-only invariant violation) */
    SIGNER_ERR_TRANSPARENT_NOT_EMPTY,    /* transparent_sig_digest != empty-bundle
                                            constant when no transparent flow was
                                            attempted. A host that omits the
                                            transparent stream but supplies a
                                            non-empty digest is trying to bind
                                            an unverified transparent bundle to
                                            the Orchard signature. */
    SIGNER_ERR_RECIPIENT_MISMATCH,       /* SIGN_REQ.recipient (UA) decodes to an
                                            Orchard receiver that does not appear
                                            among the actions the user confirmed.
                                            A hostile companion is claiming to
                                            send to one address while the device
                                            is actually signing transfers to
                                            different addresses. */
    SIGNER_ERR_NOTE_COMMITMENT_MISMATCH, /* device-recomputed cmx != action.cmx
                                            (companion-claimed recipient does not
                                            match the recipient committed in the
                                            output note — siphoning attempt) */
    SIGNER_ERR_TOO_MANY_ACTIONS,         /* tx exceeds ORCHARD_SIGNER_MAX_ACTIONS */
    SIGNER_ERR_INVALID_ACTION_INDEX,     /* confirm/get on out-of-range index */
    SIGNER_ERR_ACTION_NOT_CONFIRMED,     /* verify() called before user confirmed
                                            every output's recipient/value */
    SIGNER_ERR_FEE_NOT_CONFIRMED,        /* verify() called before user confirmed
                                            the computed miner fee. Mirrors the
                                            no-blind-signing invariant for the
                                            fee — a hostile companion that
                                            shows "fee 0.0001 ZEC" on its own UI
                                            but sets value_balance much higher
                                            would silently pay the surplus to
                                            miners. */
    SIGNER_ERR_FEE_OVERFLOW,             /* arithmetic overflow when summing
                                            transparent values or computing
                                            t_in - t_out + value_balance. The
                                            companion has supplied values that
                                            overflow the 21M-ZEC monetary cap
                                            or arranged them so the signed fee
                                            is outside i64 range. Treated as a
                                            hostile input — the session is
                                            reset. */
    SIGNER_ERR_FEE_NEGATIVE,             /* computed fee is negative
                                            (t_in + value_balance < t_out).
                                            Negative fees are not valid in
                                            Zcash consensus; a negative result
                                            means the companion assembled an
                                            unbalanced bundle. The session is
                                            reset. */
    SIGNER_ERR_MEMO_MISMATCH,            /* device-recomputed enc_ciphertext
                                            (from companion-supplied memo +
                                            esk + note plaintext) does not
                                            match the action's on-chain
                                            enc_ciphertext field. A hostile
                                            companion is showing one memo to
                                            the user while embedding another
                                            in the action — closes the gap
                                            the cmx recomputation leaves open
                                            (cmx binds value/recipient but
                                            not memo bytes). The session is
                                            reset. */
    SIGNER_ERR_BAD_PK_D,                 /* companion-supplied pk_d does not
                                            decode to a valid Pallas point
                                            (x^3 + 5 is a non-square mod p).
                                            Structurally invalid input. */
    SIGNER_ERR_BAD_POOL,                 /* unknown pool byte on an action
                                            payload (only 0x00 sealed Orchard
                                            and 0x01 Ironwood are valid). */
} OrchardSignerError;

/**
 * Per-action display info captured from feed_action_with_note().
 * The firmware reads these via orchard_signer_get_action_display() and is
 * required to call orchard_signer_confirm_action() once the user has
 * approved each output's recipient/value on the device's UI. Without all
 * actions confirmed, orchard_signer_verify() refuses to advance to
 * SIGNER_VERIFIED, which in turn prevents orchard_signer_sign() from
 * producing a signature — the "no blind signing" invariant.
 */
/** No memo captured for this action (cmx-only feed path, or ZIP-302
 *  empty memo). */
#define ORCHARD_SIGNER_MEMO_NONE 0xFF

/**
 * Maximum number of NON-EMPTY memos captured per transaction. Memos are
 * kept in a shared pool of 512-byte slots (rather than one buffer per
 * action): ZIP-302 empty memos (0xF6 lead) are verified but occupy no
 * slot, and a realistic transaction carries at most one or two
 * memo-bearing outputs. A transaction with more memo-carrying outputs
 * than slots is rejected at feed time with SIGNER_ERR_TOO_MANY_ACTIONS —
 * never reviewed with a silently missing memo.
 *
 * The default (one slot per action) makes the pool semantically
 * equivalent to per-action buffers. RAM-constrained targets override it
 * downwards (see the override note on ORCHARD_SIGNER_MAX_ACTIONS);
 * FlipZcash uses 4.
 */
#ifndef ORCHARD_SIGNER_MAX_MEMOS
#define ORCHARD_SIGNER_MAX_MEMOS ORCHARD_SIGNER_MAX_ACTIONS
#endif

/* memo_slot is a uint8_t with 0xFF reserved as the "no memo" sentinel;
 * a pool larger than the action ceiling is meaningless. */
_Static_assert(ORCHARD_SIGNER_MAX_MEMOS >= 1 && ORCHARD_SIGNER_MAX_MEMOS <= 254,
               "ORCHARD_SIGNER_MAX_MEMOS must be in 1..254 (uint8_t slot, 0xFF sentinel)");
_Static_assert(ORCHARD_SIGNER_MAX_MEMOS <= ORCHARD_SIGNER_MAX_ACTIONS,
               "memo pool larger than the action ceiling is meaningless");

typedef struct {
    uint8_t recipient[43];   /* d[11] || pk_d[32] */
    uint64_t value;          /* output note value in zatoshis */
    bool confirmed;          /* set by orchard_signer_confirm_action() */
    /* Index into OrchardSignerCtx.memo_pool of the 512-byte memo plaintext
     * captured from feed_action_with_note_and_memo() after the on-device
     * enc_ciphertext recomputation verified it matches the action bytes —
     * surfaced to the firmware UI via orchard_signer_get_action_memo() so
     * the user can verify the memo on the trusted screen (without this, a
     * hostile companion could show one memo on its untrusted UI and
     * declare a different but cryptographically consistent one to the
     * device). ORCHARD_SIGNER_MEMO_NONE when the action carried no
     * displayable memo (cmx-only feed path, or ZIP-302 empty memo
     * 0xF6-lead — nothing to show).
     *
     * Memo content interpretation follows ZIP-302:
     *   bytes[0] == 0xF6                 -> empty memo
     *   bytes[0] in 0x00..0xF4           -> UTF-8 text (trim trailing 0x00)
     *   bytes[0] == 0xF5 or 0xF7..0xFF   -> opaque / non-text
     */
    uint8_t memo_slot;
} OrchardActionDisplay;

/**
 * Per-transparent-output display info captured from
 * orchard_signer_feed_transparent_output(). The firmware reads these
 * via orchard_signer_get_transparent_output_display() and renders the
 * destination t-address (decoded from script_pubkey via base58.h) on
 * its trusted screen so the user sees where transparent funds are
 * actually going — without this, shielded → t-addr sweeps would sign
 * with the user only seeing the change Orchard outputs (which point
 * back to their own wallet), masking the real recipient.
 */
typedef struct {
    uint8_t script[25];      /* Standard P2PKH = 25 B; P2SH = 23 B */
    uint8_t script_len;
    uint64_t value;          /* output value in zatoshis */
} TransparentOutputDisplay;

typedef struct {
    OrchardSignerState state;
    Zip244TxMeta tx_meta;
    Zip244ActionsState actions_state;
    /** Ironwood pool digest state (NU6.3). `actions_state` hashes the
     *  (sealed) Orchard pool's actions; this one hashes the Ironwood
     *  pool's. Wire actions are routed by their pool tag. A pool with
     *  zero streamed actions contributes its empty-bundle leaf. */
    Zip244ActionsState ironwood_actions_state;
    Zip244TransparentState transparent_state;   /* v3: transparent digest */
    uint16_t actions_expected;
    uint16_t actions_received;
    uint16_t transparent_inputs_expected;
    uint16_t transparent_outputs_expected;
    bool has_meta;
    bool transparent_verified;                  /* v3: transparent digest matched */
    uint8_t verified_sighash[32];
    /** Session coin_type set by FvkReq. 0 = unset (backward compat). */
    uint32_t coin_type;
    /** Per-action recipient/value/confirmation captured by feed_action_with_note(),
     *  consumed by the firmware UI via get_action_display() / confirm_action().
     *  orchard_signer_verify() refuses to transition to VERIFIED unless every
     *  entry [0 .. actions_expected) has confirmed == true. */
    OrchardActionDisplay actions_display[ORCHARD_SIGNER_MAX_ACTIONS];
    /** Shared pool of verified memo plaintexts referenced by
     *  actions_display[].memo_slot. Only non-empty (non-0xF6-lead) memos
     *  occupy a slot; see ORCHARD_SIGNER_MAX_MEMOS. */
    uint8_t memo_pool[ORCHARD_SIGNER_MAX_MEMOS][512];
    uint8_t memos_used;
    /** Per-transparent-output captured by feed_transparent_output(),
     *  consumed by the firmware UI via
     *  get_transparent_output_display(). Bounded; if a transaction
     *  has more transparent outputs than fit here, the OVERFLOW ones
     *  are still hashed into the digest (so the signature commits to
     *  them) but cannot be displayed — feed_transparent_output()
     *  returns SIGNER_ERR_TOO_MANY_ACTIONS to surface the limit. */
    TransparentOutputDisplay t_outputs_display[ORCHARD_SIGNER_MAX_T_OUTPUTS];
    /** Computed miner fee (zatoshis) cached after orchard_signer_get_fee()
     *  was first called, and the flag set when the user has confirmed it via
     *  orchard_signer_confirm_fee(). orchard_signer_verify() refuses to
     *  advance to SIGNER_VERIFIED unless fee_confirmed == true — the
     *  no-blind-signing invariant extended to the fee number itself, so a
     *  hostile companion that inflates value_balance behind a misleading
     *  fee on its own UI cannot extract a signature. */
    uint64_t fee_zatoshis;
    bool fee_computed;
    bool fee_confirmed;
} OrchardSignerCtx;

/**
 * Initialize the signing context. Must be called before any operation.
 */
void orchard_signer_init(OrchardSignerCtx *ctx);

/**
 * Reset the context (abort any in-progress session).
 */
void orchard_signer_reset(OrchardSignerCtx *ctx);

/**
 * Feed transaction metadata (called with HWP_TX_META_INDEX sentinel).
 * Transitions: IDLE → RECEIVING_ACTIONS.
 *
 * v6-only (post-NU6.3): meta_len must be ZIP244_TX_META_V6_SIZE (166) or
 * ZIP244_TX_META_V6_EXT_SIZE (170). Legacy 125/129-byte v5 metas — and any
 * other length — return SIGNER_ERR_BAD_META. Also enforces the v6 header
 * constants (tx_version 0x80000006, version_group_id 0xD884B698) and the
 * pool flag policy (sealed-Orchard enableCrossAddress bit clear, no
 * reserved bits) with the same error.
 *
 * @param meta_data   Raw metadata bytes (v6 TxMeta wire layout)
 * @param meta_len    Length of meta_data (166 or 170)
 * @param total_actions  Number of actions to expect
 */
OrchardSignerError orchard_signer_feed_meta(OrchardSignerCtx *ctx,
                                             const uint8_t *meta_data, size_t meta_len,
                                             uint16_t total_actions);

/**
 * Feed one action's data (820 bytes).
 * Must be called in order: index 0, 1, ..., N-1.
 *
 * @param pool         The shielded pool the action belongs to
 *                     (ZIP244_POOL_ORCHARD or ZIP244_POOL_IRONWOOD; any
 *                     other value → SIGNER_ERR_BAD_POOL).
 * @param action_data  Raw action bytes (HWP_ACTION_DATA_SIZE)
 * @param action_len   Length of action_data
 */
OrchardSignerError orchard_signer_feed_action(OrchardSignerCtx *ctx,
                                               Zip244Pool pool,
                                               const uint8_t *action_data, size_t action_len);

/**
 * Feed one action together with the unencrypted output-note plaintext, and
 * verify that the action's cmx field commits to the claimed recipient.
 *
 * Without this verification, a hostile companion can put a cmx that commits
 * to an attacker recipient inside an action while telling the device's UI
 * "send to <Mario>" — the device would hash the action bytes correctly,
 * produce a valid sighash, and sign a transaction whose actual on-chain
 * effect is to pay the attacker. The defence is to recompute cmx on-device
 * from the (recipient, value, rseed) the companion claims, and require it
 * to match the cmx field at offset 96 of the action data byte-for-byte.
 *
 * Per Orchard's split-action design, the rho input to the output note's
 * NoteCommit is the action's nullifier (offset 32 of action_data); this
 * function uses that automatically — the caller does not pass rho.
 *
 * On mismatch: returns SIGNER_ERR_NOTE_COMMITMENT_MISMATCH and resets the
 * context so the partial action stream is discarded.
 *
 * @param ctx          Signing context (must be in RECEIVING_ACTIONS)
 * @param action_data  Raw action bytes (820)
 * @param action_len   Length of action_data
 * @param recipient    43 bytes = d[11] || pk_d[32] (raw Orchard address)
 * @param value        Output note value in zatoshis
 * @param rseed        32-byte note rseed
 */
OrchardSignerError orchard_signer_feed_action_with_note(
    OrchardSignerCtx *ctx,
    Zip244Pool pool,
    const uint8_t *action_data, size_t action_len,
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32]);

/**
 * Feed one action together with the FULL note plaintext (including the
 * 512-byte memo), and verify both the cmx and the enc_ciphertext
 * on-device. The ephemeral secret `esk` is derived on-chip (see below).
 *
 * This is the stronger variant of feed_action_with_note(). The cmx check
 * binds (d, pk_d, value, rho, rseed) but is silent about the memo bytes:
 * a hostile companion that has been forced through cmx-recomputation can
 * still display "invoice #123" on its untrusted UI while putting an
 * arbitrary attacker-chosen memo inside enc_ciphertext (the memo is
 * inside the encrypted note plaintext that goes to the recipient).
 *
 * On-device defence:
 *   1. Recompute the note commitment cmx as in feed_action_with_note();
 *      mismatch → SIGNER_ERR_NOTE_COMMITMENT_MISMATCH, session reset.
 *   2. Recompute the 580-byte enc_ciphertext via:
 *        epk          = [esk]·g_d
 *        SharedSecret = [esk]·pk_d
 *        K_enc        = BLAKE2b("Zcash_OrchardKDF", repr_P(ss)||repr_P(epk))
 *        np           = leadByte||d||value_LE||rseed||memo  (564 B)
 *                       (leadByte 0x02 = Orchard V2, 0x03 = Ironwood V3)
 *        enc_ciphertext = ChaCha20-Poly1305_Encrypt(K_enc, IV=0, np)
 *      and constant-time compare against the action's enc_ciphertext
 *      field (offset 160, 580 B). Mismatch → SIGNER_ERR_MEMO_MISMATCH,
 *      session reset.
 *   3. Verify the action's `ephemeral_key` field (offset 128, 32 B)
 *      matches the recomputed epk. Mismatch → SIGNER_ERR_MEMO_MISMATCH
 *      (same code, since both are companion-claimed values that bind to
 *      the on-chain action and don't pass the recompute check).
 *   4. On success, hash the action into the sighash state and capture
 *      (recipient, value) for the per-action display loop.
 *
 * Behavioural compatibility: callers that only need cmx-binding can keep
 * using feed_action_with_note(); this stronger variant is the one a
 * companion-treats-as-untrusted-period device should use.
 *
 * Returns SIGNER_OK on success, or one of:
 *   SIGNER_ERR_BAD_ACTION                action_data invalid / wrong size
 *   SIGNER_ERR_BAD_PK_D                  pk_d does not decode to a valid
 *                                        Pallas point
 *   SIGNER_ERR_NOTE_COMMITMENT_MISMATCH  cmx does not commit to the
 *                                        claimed (d, pk_d, value, rseed)
 *   SIGNER_ERR_MEMO_MISMATCH             enc_ciphertext (and/or epk) does
 *                                        not match what the device
 *                                        recomputed from the supplied
 *                                        memo (esk derived on-chip)
 *
 * On any mismatch error the context is reset to IDLE so a partial
 * session cannot be reused.
 *
 * @param ctx          Signing context (must be in RECEIVING_ACTIONS)
 * @param action_data  Raw action bytes (820)
 * @param action_len   Length of action_data (must equal 820)
 * @param recipient    43 bytes = d[11] || pk_d[32]
 * @param value        Output note value in zatoshis
 * @param rseed        32-byte note rseed
 * @param memo         512-byte memo plaintext (ZIP-302 conventions; the
 *                     leading byte signals memo type, but on-device the
 *                     bytes are opaque — the user-visible rendering is
 *                     the firmware's responsibility)
 *
 * The ephemeral secret `esk` is NOT taken as input: per ZIP-212 it is a
 * deterministic function of `rseed` and the action's nullifier
 * (= rho), so the device derives it on-chip from the same inputs the
 * companion already supplies. This keeps esk off the wire (32 bytes
 * less per action) and removes one trust-from-companion vector.
 */
OrchardSignerError orchard_signer_feed_action_with_note_and_memo(
    OrchardSignerCtx *ctx,
    Zip244Pool pool,
    const uint8_t *action_data, size_t action_len,
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32],
    const uint8_t memo[512]);

/**
 * Read out the (recipient, value) the firmware needs to display for a
 * given action index, captured during feed_action_with_note().
 *
 * @param ctx           Signing context (any state after feed_action_with_note)
 * @param idx           Action index, 0 .. actions_received - 1
 * @param recipient_out 43-byte buffer (d || pk_d)
 * @param value_out     output note value in zatoshis
 *
 * @return SIGNER_OK, or SIGNER_ERR_INVALID_ACTION_INDEX if idx is out of range.
 */
OrchardSignerError orchard_signer_get_action_display(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    uint8_t recipient_out[43],
    uint64_t *value_out);

/**
 * Read out the 512-byte memo plaintext captured for the given action
 * index. Returned only when the action was fed via the memo-verifying path
 * (feed_action_with_note_and_memo); the cmx-only path captures no
 * memo and `*present_out` is set to false.
 *
 * The firmware uses this to render the memo on the trusted screen so
 * the user can verify the memo content end-to-end (cryptographic
 * binding is necessary but not sufficient — a hostile companion can
 * show one memo to the user on its untrusted UI while declaring a
 * different one to the device; without on-device rendering the user
 * cannot detect the divergence).
 *
 * Memo bytes follow ZIP-302:
 *   bytes[0] == 0xF6                 -> empty memo (firmware may skip the prompt)
 *   bytes[0] in 0x00..0xF4           -> UTF-8 text (trim trailing 0x00)
 *   bytes[0] == 0xF5 or 0xF7..0xFF   -> opaque / non-text (render hex)
 *
 * @param ctx           Signing context
 * @param idx           Action index, 0 .. actions_received - 1
 * @param memo_out      512-byte output buffer (written only on success)
 * @param present_out   Set to true iff a memo was captured for this action
 *
 * @return SIGNER_OK, or SIGNER_ERR_INVALID_ACTION_INDEX if idx is out of range.
 */
OrchardSignerError orchard_signer_get_action_memo(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    uint8_t memo_out[512],
    bool *present_out);

/**
 * Constant-time check whether a 43-byte raw Orchard recipient (d || pk_d)
 * matches at least one action's display recipient.
 *
 * Used by the firmware to validate a companion-supplied "intended recipient"
 * UA against what the device is actually about to sign for. A mismatch means
 * the host's UI is showing the user a different recipient than the device
 * just confirmed via per-output review — the user may have been led to
 * believe they were paying someone else.
 *
 * The comparison runs ct_memequal across every confirmed action in turn so
 * that the timing reveals only "matched / didn't match", not which action
 * matched. Returns true if any actions_display[i].recipient equals
 * `recipient_43` byte-for-byte.
 *
 * If no actions have been received yet (actions_received == 0), returns
 * false.
 *
 * @param ctx           Signing context
 * @param recipient_43  43 bytes = d[11] || pk_d[32]
 */
bool orchard_signer_recipient_matches_any(
    const OrchardSignerCtx *ctx,
    const uint8_t recipient_43[43]);

/**
 * Mark action `idx` as confirmed by the user.
 *
 * The firmware MUST call this for every action [0 .. actions_received - 1]
 * after the user has approved the corresponding recipient and value on
 * the device UI. Without all actions confirmed, orchard_signer_verify()
 * returns SIGNER_ERR_ACTION_NOT_CONFIRMED and refuses to transition to
 * SIGNER_VERIFIED, so orchard_signer_sign() will fail with NOT_VERIFIED.
 *
 * Confirmation is monotonic: re-calling confirm on an already-confirmed
 * index is a no-op (returns OK). To revoke, call orchard_signer_reset().
 *
 * @param ctx  Signing context
 * @param idx  Action index, 0 .. actions_received - 1
 *
 * @return SIGNER_OK, or SIGNER_ERR_INVALID_ACTION_INDEX if idx is out of range.
 */
OrchardSignerError orchard_signer_confirm_action(
    OrchardSignerCtx *ctx,
    uint16_t idx);

/**
 * Begin transparent digest verification (v3).
 * Call after feed_meta() when the transaction has transparent inputs.
 * Transitions: RECEIVING_ACTIONS → RECEIVING_TRANSPARENT.
 *
 * @param num_inputs   Expected number of transparent inputs
 * @param num_outputs  Expected number of transparent outputs
 */
OrchardSignerError orchard_signer_begin_transparent(OrchardSignerCtx *ctx,
                                                     uint16_t num_inputs,
                                                     uint16_t num_outputs);

/**
 * Feed one transparent input's data (v3).
 * Must be in RECEIVING_TRANSPARENT state.
 */
OrchardSignerError orchard_signer_feed_transparent_input(OrchardSignerCtx *ctx,
                                                          const uint8_t *data, size_t data_len);

/**
 * Feed one transparent output's data (v3).
 * Must be in RECEIVING_TRANSPARENT state.
 *
 * Also parses (value, script_pubkey) out of the input bytes and
 * captures them for the per-output display loop, bounded by
 * ORCHARD_SIGNER_MAX_T_OUTPUTS. A transaction with more transparent
 * outputs than that is rejected with SIGNER_ERR_TOO_MANY_ACTIONS to
 * preserve the no-blind-signing invariant (every output the user
 * signs must be displayable on the trusted screen).
 *
 * Wire format (matches HwpDispatcher / signer.rs serialise):
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 */
OrchardSignerError orchard_signer_feed_transparent_output(OrchardSignerCtx *ctx,
                                                           const uint8_t *data, size_t data_len);

/**
 * Read out the (value, script_pubkey) captured for transparent output
 * `idx`. Use base58.h::script_to_taddr() to render the destination
 * t-address from the returned script_pubkey.
 *
 * @param ctx              Signing context
 * @param idx              Output index, 0 .. transparent_state.outputs_received - 1
 * @param value_out        Output value in zatoshis
 * @param script_out       Caller-provided buffer ≥ 25 bytes
 * @param script_out_cap   Capacity of script_out
 * @param script_len_out   Actual script length written
 *
 * @return SIGNER_OK, or SIGNER_ERR_INVALID_ACTION_INDEX (out of range),
 *         or SIGNER_ERR_BAD_STATE (capture buffer too small for this entry).
 */
OrchardSignerError orchard_signer_get_transparent_output_display(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    uint64_t *value_out,
    uint8_t *script_out,
    size_t script_out_cap,
    size_t *script_len_out);

/**
 * Verify the transparent digest against TxMeta's transparent_sig_digest (v3).
 * Transitions: RECEIVING_TRANSPARENT → RECEIVING_ACTIONS (on match).
 *
 * @param expected_digest  32-byte expected transparent digest from companion
 */
OrchardSignerError orchard_signer_verify_transparent(OrchardSignerCtx *ctx,
                                                      const uint8_t expected_digest[32]);

/**
 * Compute (or retrieve cached) the miner fee in zatoshis that this
 * transaction will pay, derived from already-collected data:
 *
 *   fee = transparent_in_total - transparent_out_total + value_balance
 *
 * For an Orchard-only transaction with no transparent flow, this reduces
 * to `fee = value_balance` (value flowing out of the Orchard pool == fee
 * paid to miners, since there is no transparent pool to absorb it).
 *
 * Prerequisites (caller MUST satisfy):
 *   - feed_meta() has been called (value_balance available)
 *   - if the tx has transparent components, every transparent input AND
 *     output has been streamed via feed_transparent_input/output(), so
 *     t_in_total / t_out_total reflect the full bundle.
 *
 * Errors:
 *   - SIGNER_ERR_BAD_STATE     prerequisites not met
 *   - SIGNER_ERR_FEE_OVERFLOW  unsigned add overflow on t_in / t_out,
 *                              or i64 overflow combining the three terms
 *   - SIGNER_ERR_FEE_NEGATIVE  fee < 0 (companion built an unbalanced bundle)
 *
 * On success the fee is cached in ctx->fee_zatoshis and ctx->fee_computed
 * is set; subsequent calls return the same value without recomputation.
 *
 * @param ctx       Signing context
 * @param fee_out   Output: miner fee in zatoshis (uint64)
 */
OrchardSignerError orchard_signer_get_fee(OrchardSignerCtx *ctx,
                                           uint64_t *fee_out);

/**
 * Mark the computed fee as confirmed by the user.
 *
 * The firmware MUST display the value returned by orchard_signer_get_fee()
 * on the trusted device screen and call this only after the user explicitly
 * approves it. Without confirmation, orchard_signer_verify() refuses to
 * transition to SIGNER_VERIFIED (SIGNER_ERR_FEE_NOT_CONFIRMED).
 *
 * Confirmation is monotonic: re-calling on an already-confirmed context is
 * a no-op. To revoke, call orchard_signer_reset().
 *
 * @param ctx  Signing context (must have fee_computed == true)
 */
OrchardSignerError orchard_signer_confirm_fee(OrchardSignerCtx *ctx);

/**
 * Feed the expected sighash (sentinel message) and verify.
 * Transitions: RECEIVING_ACTIONS → VERIFIED (on match) or resets (on mismatch).
 *
 * @param expected_sighash  32-byte sighash from companion
 */
OrchardSignerError orchard_signer_verify(OrchardSignerCtx *ctx,
                                          const uint8_t expected_sighash[32]);

/**
 * Check if the context is in VERIFIED state and the sighash matches.
 * Call this before signing to enforce the invariant.
 *
 * @param sighash  32-byte sighash from SIGN_REQ
 */
OrchardSignerError orchard_signer_check(const OrchardSignerCtx *ctx,
                                         const uint8_t sighash[32]);

/**
 * Sign a transaction action. Enforces that ZIP-244 verification passed
 * and that the SIGN_REQ sighash matches the verified one.
 *
 * @param ctx       Signing context (must be VERIFIED)
 * @param sighash   32-byte sighash (must match verified sighash)
 * @param ask       32-byte spend authorization key
 * @param alpha     32-byte randomizer
 * @param sig_out   64-byte signature output
 * @param rk_out    32-byte randomized key output
 */
OrchardSignerError orchard_signer_sign(const OrchardSignerCtx *ctx,
                                        const uint8_t sighash[32],
                                        const uint8_t ask[32],
                                        const uint8_t alpha[32],
                                        uint8_t sig_out[64],
                                        uint8_t rk_out[32]);
