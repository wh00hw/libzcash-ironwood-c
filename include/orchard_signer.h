/**
 * Orchard Signing Context — the review-then-sign state machine.
 *
 *   1. The caller feeds TX metadata (with the wallet's full viewing key),
 *      the transparent OUTPUTS if any, and one full note plaintext per action
 *   2. The context recomputes each note commitment and each ciphertext,
 *      decides FROM ITS OWN KEYS whether each output returns to the wallet,
 *      and computes the ZIP-244 sighash incrementally
 *   3. The firmware shows the outputs and the totals; the user approves
 *   4. The caller provides the expected sighash for comparison
 *   5. Only after successful verification does orchard_signer_sign() sign,
 *      and only the sighash the context computed
 *
 * WHAT THIS IS, AND IS NOT. It is an API-ordering guard: used through this
 * header, a signature cannot be obtained before the confirm_* calls were
 * made, which makes the safe path the default one. It is NOT a barrier
 * against the firmware itself: the firmware holds the spending key and can
 * call confirm_action() / confirm_totals() without showing anything, or
 * call redpallas_sign() directly. Whether the user really saw the screens
 * is the firmware's responsibility; the library cannot check it.
 *
 * Nothing the host says about ownership is used: there is no "is change"
 * input anywhere in this API. Which host-supplied fields are bound by the
 * signature, recomputed, forced or unbound is tabulated in SECURITY.md,
 * "What binds each host-supplied field".
 *
 * NOT SUPPORTED: transparent inputs (spending from a t-address). A
 * transaction that has any is refused (SIGNER_ERR_TRANSPARENT_INPUTS_
 * UNSUPPORTED). Transparent outputs (paying to a t-address from shielded
 * funds) are supported.
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

/**
 * Consensus branch IDs the signer accepts in TxMeta, as a brace-enclosed
 * initializer list of uint32_t. The branch ID is bound into the sighash, so
 * a signature made for one network upgrade is not valid under another; the
 * device nevertheless refuses to sign for a branch it was not built for
 * (SIGNER_ERR_BRANCH_NOT_ALLOWED) rather than bind whatever the host sends.
 *
 * Default: NU6.3 (0x37A5165B) and NU7 (0x77190AD9), both with the v6
 * transaction format (header 0x80000006, version group 0xD884B698 — those
 * two constants are enforced separately and are not configurable).
 *
 * BY DESIGN a later network upgrade needs a firmware update: its rules are
 * not known to this code. Override at build time (uniformly for every
 * translation unit of the library), e.g.
 *   -D'ORCHARD_SIGNER_ALLOWED_BRANCH_IDS={0x37A5165Bu}'
 */
#ifndef ORCHARD_SIGNER_ALLOWED_BRANCH_IDS
#define ORCHARD_SIGNER_ALLOWED_BRANCH_IDS { 0x37A5165Bu, 0x77190AD9u }
#endif

typedef enum {
    SIGNER_IDLE,                     /* Waiting for metadata */
    SIGNER_RECEIVING_TRANSPARENT,    /* Collecting transparent outputs */
    SIGNER_RECEIVING_ACTIONS,        /* Metadata received, collecting actions */
    SIGNER_VERIFIED,                 /* ZIP-244 sighash verified, signing allowed */
} OrchardSignerState;

typedef enum {
    SIGNER_OK = 0,
    SIGNER_ERR_BAD_META,          /* Invalid metadata payload — including
                                     legacy pre-v6 TxMeta layouts (125/129
                                     bytes), a non-v6 header, or flag bits
                                     outside the pool policy */
    SIGNER_ERR_BAD_ACTION,        /* Invalid action data */
    SIGNER_ERR_BAD_STATE,         /* Unexpected call for current state */
    SIGNER_ERR_SIGHASH_MISMATCH,  /* Device-computed sighash != companion sighash */
    SIGNER_ERR_NOT_VERIFIED,      /* sign() called without verification */
    SIGNER_ERR_WRONG_SIGHASH,     /* SIGN_REQ sighash doesn't match verified one */
    SIGNER_ERR_SIGN_FAILED,       /* redpallas_sign returned error */
    SIGNER_ERR_NETWORK_MISMATCH,         /* TxMeta coin_type != the device's
                                            network (orchard_signer_init), or
                                            TxMeta carries no coin_type at all
                                            (166-byte layout) */
    SIGNER_ERR_NETWORK_UNSET,            /* the context was initialised with a
                                            coin type other than 133 / 1: the
                                            signer does not run without knowing
                                            the device's network */
    SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED,
                                         /* the transaction has transparent
                                            inputs: begin_transparent() with
                                            num_inputs > 0, or any call to
                                            feed_transparent_input(). Spending
                                            from a t-address is not implemented
                                            (see README). Session reset. */
    SIGNER_ERR_TRANSPARENT_BAD_OUTPUT,   /* Malformed transparent output, or a
                                            script that is not standard P2PKH /
                                            P2SH (it could not be shown as an
                                            address). Session reset. */
    SIGNER_ERR_TRANSPARENT_MISMATCH,     /* Recomputed transparent digest !=
                                            TxMeta / the host's sentinel */
    SIGNER_ERR_SAPLING_NOT_EMPTY,        /* sapling_digest != empty-bundle constant
                                            (Orchard-only invariant violation) */
    SIGNER_ERR_TRANSPARENT_NOT_EMPTY,    /* transparent_sig_digest != empty-bundle
                                            constant when no transparent output
                                            was streamed. A host that omits the
                                            transparent stream but supplies a
                                            non-empty digest is trying to bind
                                            an unreviewed transparent bundle to
                                            the signature. */
    SIGNER_ERR_NOTE_COMMITMENT_MISMATCH, /* device-recomputed cmx != action.cmx
                                            (the declared recipient / value is
                                            not the one committed in the output
                                            note) */
    SIGNER_ERR_TOO_MANY_ACTIONS,         /* more actions than
                                            ORCHARD_SIGNER_MAX_ACTIONS, or more
                                            transparent outputs than
                                            ORCHARD_SIGNER_MAX_T_OUTPUTS */
    SIGNER_ERR_NO_ACTIONS,               /* TxMeta announces zero actions. With
                                            no shielded spend there is nothing
                                            for this device to authorise. */
    SIGNER_ERR_INVALID_ACTION_INDEX,     /* confirm/get on out-of-range index */
    SIGNER_ERR_ACTION_NOT_CONFIRMED,     /* verify() called before
                                            confirm_action() for every output
                                            that requires review */
    SIGNER_ERR_FEE_NOT_CONFIRMED,        /* verify() called before
                                            confirm_totals() */
    SIGNER_ERR_FEE_OVERFLOW,             /* overflow summing the transparent
                                            output values or the value
                                            balances. Session reset. */
    SIGNER_ERR_FEE_NEGATIVE,             /* computed fee is negative. Session
                                            reset. */
    SIGNER_ERR_EMPTY_POOL_BALANCE,       /* TxMeta declares a non-zero value
                                            balance for a pool (Orchard or
                                            Ironwood) for which no action was
                                            streamed. Such a pool has no bundle
                                            on chain, so its value balance is
                                            not covered by the sighash: a host
                                            could use it to make the device
                                            display any fee it likes. Session
                                            reset. */
    SIGNER_ERR_MEMO_MISMATCH,            /* device-recomputed enc_ciphertext or
                                            ephemeral_key (from the declared
                                            note + memo; esk derived on-chip)
                                            does not match the action. Session
                                            reset. */
    SIGNER_ERR_BAD_PK_D,                 /* declared pk_d does not decode to a
                                            valid Pallas point */
    SIGNER_ERR_BAD_POOL,                 /* unknown pool byte on an action
                                            (only 0x00 sealed Orchard and 0x01
                                            Ironwood are valid). */
    SIGNER_ERR_BAD_FVK,                  /* feed_meta() was given no full
                                            viewing key, or one whose
                                            Commit^ivk is invalid. */
    SIGNER_ERR_BRANCH_NOT_ALLOWED,       /* TxMeta consensus_branch_id is not
                                            in ORCHARD_SIGNER_ALLOWED_BRANCH_IDS */
    SIGNER_ERR_TOO_MANY_MEMOS,           /* more outputs carry a memo the user
                                            has to read than
                                            ORCHARD_SIGNER_MAX_MEMOS. Nothing
                                            is skipped: the session is reset. */
    SIGNER_ERR_VALUE_OVERFLOW,           /* a sum of output values, or the
                                            total leaving the wallet, does not
                                            fit in 64 bits. Session reset. */
} OrchardSignerError;

/* Removed in November 2026 (code that names them no longer compiles):
 *   SIGNER_ERR_MEMO_REQUIRED          the compact (no-memo) entry point is gone
 *   SIGNER_ERR_RECIPIENT_MISMATCH     orchard_signer_recipient_matches_any() is gone
 *   SIGNER_ERR_TRANSPARENT_BAD_INPUT  transparent inputs are refused outright */

/** The device's network, as the ZIP 32 / BIP 44 coin type. */
#define ORCHARD_SIGNER_COIN_MAINNET 133u
#define ORCHARD_SIGNER_COIN_TESTNET 1u   /* testnet and regtest */

/**
 * Who an output note belongs to — decided on-device, from the wallet's own
 * incoming viewing keys, right after the note commitment of the output has
 * been verified:
 *
 *   pk_d == [ivk_internal] * DiversifyHash(d)  ->  OWN_INTERNAL  (change)
 *   pk_d == [ivk_external] * DiversifyHash(d)  ->  OWN_EXTERNAL  (one of the
 *                                   wallet's receiving addresses, any
 *                                   diversifier)
 *   neither                                    ->  EXTERNAL      (leaves the
 *                                   wallet)
 *
 * 0 is deliberately not a member: a zero-initialised record is
 * "unclassified" and orchard_signer_verify() refuses it.
 */
typedef enum {
    ORCHARD_OUTPUT_EXTERNAL     = 1,
    ORCHARD_OUTPUT_OWN_INTERNAL = 2,
    ORCHARD_OUTPUT_OWN_EXTERNAL = 3,
} OrchardOutputOwnership;

/**
 * The wallet's Orchard full viewing key, as three 32-byte encodings (the
 * same bytes FVK_RSP carries). Named fields rather than three positional
 * pointers so they cannot be swapped silently.
 */
typedef struct {
    const uint8_t *ak;    /* spend validating key (sign bit ignored) */
    const uint8_t *nk;    /* nullifier deriving key */
    const uint8_t *rivk;  /* Commit^ivk randomness (external) */
} OrchardSignerFvk;

/** Internal memo_slot value: the (verified) memo of this output is empty,
 *  nothing is kept — see orchard_signer_memo_is_empty(). */
#define ORCHARD_SIGNER_MEMO_NONE 0xFF

/**
 * Maximum number of NON-EMPTY memos captured per transaction. Memos are
 * kept in a shared pool of 512-byte slots (rather than one buffer per
 * action): empty memos are verified like any other but occupy no slot, and
 * a realistic transaction carries at most one or two memo-bearing outputs.
 * The pool therefore bounds the memos the user has to READ, not the outputs
 * whose ciphertext is VERIFIED (that is every output with a value). A
 * transaction with more memo-carrying outputs than slots is rejected at
 * feed time with SIGNER_ERR_TOO_MANY_MEMOS — never reviewed with a silently
 * missing memo.
 *
 * "Empty" is exactly one of two 512-byte strings: the ZIP-302 "no memo"
 * encoding (0xF6 followed by 511 zero bytes) or 512 zero bytes (the empty
 * text memo the orchard builder gives its padding outputs). Anything else
 * — including 0xF6 followed by non-zero bytes — is a memo the user must
 * see.
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

/* Internal per-action record. Firmware reads it through
 * orchard_signer_get_output(), never directly. */
typedef struct {
    uint8_t recipient[43];   /* d[11] || pk_d[32] */
    uint64_t value;          /* output note value in zatoshis */
    bool confirmed;          /* set by orchard_signer_confirm_action(), or at
                                feed time for an output that needs no review */
    /* Index into OrchardSignerCtx.memo_pool of the verified 512-byte memo
     * plaintext, or ORCHARD_SIGNER_MEMO_NONE. */
    uint8_t memo_slot;
    uint8_t ownership;       /* OrchardOutputOwnership; 0 = unclassified */
    uint8_t enc_verified;    /* 1: enc_ciphertext + epk recomputed and
                                matched. 2: the sealed-pool spend-paired
                                dummy (zero value, own address, real epk,
                                randomized enc_ciphertext) — see
                                orchard_signer.c. verify() refuses 0. */
} OrchardActionDisplay;

/**
 * What the device established about the memo of an output. There is no
 * "unknown": every output's ciphertext is recomputed, so the memo is always
 * known. 0 is not a member.
 */
typedef enum {
    ORCHARD_MEMO_NONE    = 1,  /* verified to carry NO memo: the 512 bytes are
                                  0xF6 + zeros, or all zeros */
    ORCHARD_MEMO_PRESENT = 2,  /* verified, not empty: available through
                                  orchard_signer_get_action_memo() */
} OrchardMemoStatus;

/**
 * What the firmware needs to show one shielded output, read with
 * orchard_signer_get_output().
 *
 * REQUIRED UI BEHAVIOUR, per `ownership`:
 *   ORCHARD_OUTPUT_EXTERNAL      a payment leaving the wallet: show the
 *                                address and the value; the user must check
 *                                the address against what they intend.
 *   ORCHARD_OUTPUT_OWN_INTERNAL  "Change (your wallet)": show the value. The
 *                                address may be shown but must not be
 *                                presented as a recipient.
 *   ORCHARD_OUTPUT_OWN_EXTERNAL  "Your address": the value returns to one of
 *                                the wallet's own receiving addresses.
 * An output that the device did not classify as OWN_* must never be
 * labelled as the wallet's, whatever the host claims.
 *
 * MEMO. `memo` says whether the output carries one. For an EXTERNAL output
 * the screen should say so either way — "Memo: none" for ORCHARD_MEMO_NONE —
 * because a memo the user expected and does not see (an exchange deposit
 * tag) is otherwise only noticeable as a screen that never came.
 *
 * Zero-value outputs (`value == 0`) exist in most transactions as padding
 * to random addresses. Rule: they are never presented as payments.
 *   - `review_required == false` (value 0 and ORCHARD_MEMO_NONE): do not
 *     show a screen for it; it is counted in OrchardSignerTotals.n_zero_value
 *     and is already confirmed. The device has verified that it carries
 *     neither value nor a memo; its address is NOT shown to anyone.
 *   - value 0 with a memo: it is a message, not a payment; show the
 *     address and the memo, say that it carries no funds.
 * `review_required` is true for every output with a non-zero value.
 */
typedef struct {
    uint8_t recipient[43];             /* d[11] || pk_d[32] */
    uint64_t value;                    /* zatoshis */
    OrchardOutputOwnership ownership;  /* decided on-device */
    OrchardMemoStatus memo;            /* decided on-device */
    bool has_memo;                     /* == (memo == ORCHARD_MEMO_PRESENT) */
    bool ciphertext_verified;          /* false only for the sealed-Orchard
                                          spend-paired dummy output: zero
                                          value, one of this wallet's own
                                          addresses, expected epk, and an
                                          enc_ciphertext the builder
                                          randomized on purpose. Never shown
                                          (review_required is false). */
    bool review_required;              /* false only for value == 0 and
                                          ORCHARD_MEMO_NONE */
    bool confirmed;
} OrchardOutputInfo;

/**
 * The numbers of the transaction, all computed on-device, read with
 * orchard_signer_get_totals(). The one the user has to check is
 * `total_leaving`:
 *
 *   total_leaving = external_shielded + transparent_out + fee
 *
 *   external_shielded  sum of the values of the outputs classified
 *                      ORCHARD_OUTPUT_EXTERNAL (both pools)
 *   transparent_out    sum of all transparent output values. Transparent
 *                      outputs are ALWAYS counted as leaving: the device
 *                      does not recognise its own t-address.
 *   fee                value_balance(Orchard) + value_balance(Ironwood)
 *                      - transparent_out
 *                      (there are no transparent inputs: unsupported). A
 *                      pool's value balance is used only if the pool has
 *                      actions — then it is bound by the sighash; for a pool
 *                      without actions it must be zero
 *                      (SIGNER_ERR_EMPTY_POOL_BALANCE).
 *
 * WHAT total_leaving MEANS. Every term is bound by the sighash the device
 * signs, so the numbers describe the transaction that the signature is
 * valid for. total_leaving is an UPPER BOUND on what this wallet loses. It
 * is exact when every spent note is the wallet's. The device does not see
 * the spend side (which notes are spent, their values, whose they are): if
 * the host adds somebody else's notes as inputs, the wallet loses less than
 * total_leaving, never more.
 *
 * The wallet's own outputs (own_internal, own_external) are not part of
 * total_leaving and are not subtracted from anything either: they only
 * enter through value_balance, so change is never counted twice. A host
 * that redirects the "change" to an address of its own turns it into an
 * EXTERNAL output, and total_leaving grows by exactly that amount.
 *
 * NOT IN HERE: the expiry height and the lock time. Both are bound by the
 * sighash (header digest) but the device does not show them; a host can
 * make a signed transaction valid for longer than the wallet app says.
 *
 * Every addition is checked: a sum that does not fit in uint64_t makes
 * get_totals() fail with SIGNER_ERR_VALUE_OVERFLOW (fee arithmetic:
 * SIGNER_ERR_FEE_OVERFLOW / SIGNER_ERR_FEE_NEGATIVE) and resets the session.
 */
typedef struct {
    uint64_t total_leaving;
    uint64_t fee;
    uint64_t external_shielded;
    uint64_t transparent_out;
    uint64_t own_internal;       /* change returning to the wallet */
    uint64_t own_external;       /* to the wallet's own receiving addresses */
    uint16_t n_external;         /* non-zero EXTERNAL outputs */
    uint16_t n_own_internal;     /* non-zero OWN_INTERNAL outputs */
    uint16_t n_own_external;     /* non-zero OWN_EXTERNAL outputs */
    uint16_t n_zero_value;       /* zero-value outputs (padding), any owner */
    uint16_t n_transparent_out;
} OrchardSignerTotals;

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
     *  zero streamed actions contributes its empty-bundle leaf — and must
     *  have a zero value balance (SIGNER_ERR_EMPTY_POOL_BALANCE). */
    Zip244ActionsState ironwood_actions_state;
    Zip244TransparentState transparent_state;   /* transparent OUTPUTS digest */
    uint16_t actions_expected;
    uint16_t actions_received;
    uint16_t transparent_outputs_expected;
    bool has_meta;
    bool transparent_begun;                     /* begin_transparent() ran (once per session) */
    bool transparent_verified;                  /* transparent digest matched */
    uint8_t verified_sighash[32];
    /** The device's network: ORCHARD_SIGNER_COIN_MAINNET (133) or
     *  ORCHARD_SIGNER_COIN_TESTNET (1), set by orchard_signer_init() and the
     *  one field that orchard_signer_reset() keeps. 0 = unset: feed_meta()
     *  refuses. */
    uint32_t coin_type;
    /** Per-action recipient/value/confirmation captured when the action is
     *  fed, consumed by the firmware UI via get_output() / confirm_action().
     *  orchard_signer_verify() refuses to transition to VERIFIED unless every
     *  entry [0 .. actions_expected) has confirmed == true. */
    OrchardActionDisplay actions_display[ORCHARD_SIGNER_MAX_ACTIONS];
    /** Shared pool of verified memo plaintexts referenced by
     *  actions_display[].memo_slot. Only non-empty memos occupy a slot; see
     *  ORCHARD_SIGNER_MAX_MEMOS. */
    uint8_t memo_pool[ORCHARD_SIGNER_MAX_MEMOS][512];
    uint8_t memos_used;
    /** Transparent outputs captured by feed_transparent_output(), consumed
     *  by the firmware UI via get_transparent_output_display(). A
     *  transaction with more than ORCHARD_SIGNER_MAX_T_OUTPUTS of them is
     *  refused at begin_transparent(): nothing is hashed that cannot be
     *  shown. */
    TransparentOutputDisplay t_outputs_display[ORCHARD_SIGNER_MAX_T_OUTPUTS];
    /** Fee (zatoshis) cached by the first successful
     *  orchard_signer_get_totals(), and the flag set by
     *  orchard_signer_confirm_totals(). orchard_signer_verify() refuses to
     *  advance to SIGNER_VERIFIED unless fee_confirmed == true. */
    uint64_t fee_zatoshis;
    bool fee_computed;
    bool fee_confirmed;        /* totals (fee + total leaving) approved */
    /** The wallet's incoming viewing keys for this session, derived by
     *  feed_meta() from the full viewing key: ivk_external owns the
     *  receiving addresses, ivk_internal the change addresses. Viewing-key
     *  material: wiped by orchard_signer_reset(), i.e. at session end and
     *  on every abort path. Valid only while has_meta is true. */
    uint8_t ivk_external[32];
    uint8_t ivk_internal[32];
} OrchardSignerCtx;

/**
 * Initialize the signing context and fix the device's network. Must be
 * called once before any operation.
 *
 * `coin_type` is ORCHARD_SIGNER_COIN_MAINNET (133) or
 * ORCHARD_SIGNER_COIN_TESTNET (1) — the SAME value the firmware used to
 * derive the keys it will sign with (ZIP 32 path m/32'/coin_type'/account').
 * It survives orchard_signer_reset(). Any other value leaves the network
 * unset and every feed_meta() fails with SIGNER_ERR_NETWORK_UNSET.
 *
 * WHAT "NETWORK" MEANS FOR A SIGNATURE — read this before relying on it.
 * Nothing in a Zcash transaction or in its sighash names the network:
 * mainnet and testnet use the same consensus branch IDs, and an Orchard
 * receiver (d, pk_d) is the same bytes on both. What separates the networks
 * is (1) the keys — a wallet derives different keys per coin type, so a
 * testnet key authorises nothing that a mainnet key owns — and (2) the
 * address prefix on the screen. The signer enforces what can be enforced:
 * TxMeta must declare the device's coin type, in every session, or the
 * transaction is refused (SIGNER_ERR_NETWORK_MISMATCH). That catches a
 * wallet application talking to a device set up for the other network. It
 * does not bind a hostile host, which can declare whatever it likes: if
 * coins of one network were ever sent to this wallet's receivers of the
 * other, the host can have them spent while the device shows the prefix of
 * its own network.
 *
 * (The previous signature took no coin type; the session's network came
 * from FVK_REQ and was lost on every reset.)
 */
void orchard_signer_init(OrchardSignerCtx *ctx, uint32_t coin_type);

/**
 * Reset the context (abort any in-progress session). Wipes the whole
 * context, including the session's incoming viewing keys and any captured
 * memo, and keeps only the device's network (coin_type).
 */
void orchard_signer_reset(OrchardSignerCtx *ctx);

/**
 * Feed transaction metadata (called with HWP_TX_META_INDEX sentinel).
 * Transitions: IDLE → RECEIVING_ACTIONS.
 *
 * Checks, in this order (first failure wins; the context stays IDLE with
 * nothing retained):
 *   - `fvk` present                                    SIGNER_ERR_BAD_FVK
 *   - the device's network is set                      SIGNER_ERR_NETWORK_UNSET
 *   - meta_len is ZIP244_TX_META_V6_SIZE (166) or
 *     ZIP244_TX_META_V6_EXT_SIZE (170)                 SIGNER_ERR_BAD_META
 *   - TxMeta.coin_type == the device's network; the
 *     166-byte layout carries none and is refused      SIGNER_ERR_NETWORK_MISMATCH
 *   - sapling_digest is the empty-bundle constant      SIGNER_ERR_SAPLING_NOT_EMPTY
 *   - 1 <= total_actions <= ORCHARD_SIGNER_MAX_ACTIONS SIGNER_ERR_NO_ACTIONS /
 *                                                      SIGNER_ERR_TOO_MANY_ACTIONS
 *   - v6 header constants (0x80000006 / 0xD884B698)
 *     and pool flag policy (sealed-Orchard
 *     enableCrossAddress clear, no reserved bits)      SIGNER_ERR_BAD_META
 *   - consensus branch in
 *     ORCHARD_SIGNER_ALLOWED_BRANCH_IDS                SIGNER_ERR_BRANCH_NOT_ALLOWED
 *   - the two incoming viewing keys derive             SIGNER_ERR_BAD_FVK
 *
 * `fvk` is the wallet's own full viewing key. feed_meta() derives the
 * external and internal incoming viewing keys from it (two Commit^ivk, once
 * per session) and keeps them in the context until reset; every output is
 * later classified against them. The key MUST come from the device's own
 * storage: a key supplied by the host would let the host decide what "own"
 * means.
 *
 * The two anchors in TxMeta are discarded here: under the v6 format they
 * are not part of what the device signs, and nothing in the library reads
 * them. The value balances are used only for pools that turn out to have
 * actions (see SIGNER_ERR_EMPTY_POOL_BALANCE).
 *
 * @param fvk         The device's own Orchard full viewing key
 * @param meta_data   Raw metadata bytes (v6 TxMeta wire layout)
 * @param meta_len    Length of meta_data (170)
 * @param total_actions  Number of actions to expect (>= 1)
 */
OrchardSignerError orchard_signer_feed_meta(OrchardSignerCtx *ctx,
                                             const OrchardSignerFvk *fvk,
                                             const uint8_t *meta_data, size_t meta_len,
                                             uint16_t total_actions);

/* Removed entry points (code that calls them no longer compiles):
 *   orchard_signer_feed_action()            hashed an action with no note:
 *                                           no commitment check, no
 *                                           classification.
 *   orchard_signer_feed_action_with_note()  the compact (no-memo) body. It
 *                                           did not recompute enc_ciphertext,
 *                                           so even restricted to zero-value
 *                                           outputs it let the host attach an
 *                                           arbitrary 512-byte message, to an
 *                                           address of its choosing, that no
 *                                           screen showed.
 * Every action now enters through the one function below, with its memo. */

/**
 * Feed one action together with the FULL note plaintext of its output
 * (including the 512-byte memo), and verify both the cmx and the
 * enc_ciphertext on-device. The ephemeral secret `esk` is derived on-chip
 * (see below).
 *
 * THE ONLY WAY AN ACTION REACHES THE SIGHASH — for payments, for the
 * wallet's own change and for zero-value padding alike. The cmx check binds
 * (d, pk_d, value, rho, rseed) but is silent about the memo bytes and about
 * whether the recipient can decrypt the note; the ciphertext check closes
 * both.
 *
 * What an honest host needs for it: the note of every output (recipient,
 * value, rseed) — which the cmx check needs anyway — and its memo. For the
 * padding outputs of the `orchard` crate's builder the memo is 512 zero
 * bytes; for an output whose memo the host did not keep, it can be
 * recovered by decrypting enc_ciphertext with esk = ToScalar(PRF^expand(
 * rseed, [0x04] || rho)) and pk_d (zcash_note_encryption::
 * try_output_recovery_with_pkd_esk). An output whose ciphertext is not the
 * ZIP 212 encryption of its note cannot be signed for.
 *
 * On-device:
 *   1. Recompute the note commitment cmx from (d, pk_d, value, rseed) with
 *      rho = the action's nullifier (offset 32) and compare it with the
 *      action's cmx (offset 96);
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
 *   4. Classify the output against the session's incoming viewing keys
 *      (OrchardOutputOwnership): internal first, external only if the
 *      internal key did not match.
 *   5. Keep the memo for review if it is not empty (see
 *      ORCHARD_SIGNER_MAX_MEMOS; SIGNER_ERR_TOO_MANY_MEMOS if the pool is
 *      full).
 *   6. Hash the action into the sighash state and record
 *      (recipient, value, ownership) for the review loop.
 *   7. When this was the last action: require a zero value balance for a
 *      pool that received none (SIGNER_ERR_EMPTY_POOL_BALANCE).
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
 *   SIGNER_ERR_TOO_MANY_MEMOS            memo pool full
 *   SIGNER_ERR_EMPTY_POOL_BALANCE        see step 7
 *   SIGNER_ERR_TOO_MANY_ACTIONS / SIGNER_ERR_BAD_STATE / SIGNER_ERR_BAD_POOL
 *
 * On ANY error the context is reset to IDLE so a partial session cannot be
 * reused.
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
 * Read what the firmware has to show for output `idx`: address, value and
 * the on-device ownership decision. See OrchardOutputInfo for the required
 * UI behaviour.
 *
 *
 * @return SIGNER_OK, or SIGNER_ERR_INVALID_ACTION_INDEX if idx is out of
 *         range or `out` is NULL.
 */
OrchardSignerError orchard_signer_get_output(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    OrchardOutputInfo *out);

/**
 * True iff `memo` is one of the two "nothing to read" encodings: 0xF6
 * followed by 511 zero bytes (ZIP-302 no-memo), or 512 zero bytes (empty
 * text). The signer uses this to decide whether a memo takes a review slot.
 */
bool orchard_signer_memo_is_empty(const uint8_t memo[512]);

/**
 * Read out the 512-byte memo plaintext captured for the given action
 * index. `*present_out` is true only for a non-empty memo that was verified
 * against the action's enc_ciphertext (OrchardOutputInfo.memo ==
 * ORCHARD_MEMO_PRESENT); for a verified-empty memo it is false.
 *
 * The firmware uses this to render the memo on the trusted screen so
 * the user can verify the memo content end-to-end (cryptographic
 * binding is necessary but not sufficient — a hostile companion can
 * show one memo to the user on its untrusted UI while declaring a
 * different one to the device; without on-device rendering the user
 * cannot detect the divergence).
 *
 * Memo bytes follow ZIP-302:
 *   bytes[0] in 0x00..0xF4           -> UTF-8 text (trim trailing 0x00)
 *   anything else                    -> opaque / non-text (render hex). This
 *                                       includes 0xF6 followed by non-zero
 *                                       bytes, which is NOT an empty memo.
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

/* orchard_signer_recipient_matches_any() was removed. It matched a
 * host-named address against EVERY action — including zero-value outputs no
 * screen had shown and the wallet's own change — and so let a host put an
 * address the user never reviewed on the final confirmation screen. The
 * final confirmation now shows device-computed totals only. */

/**
 * Mark action `idx` as confirmed by the user.
 *
 * The firmware MUST call this for every action whose
 * OrchardOutputInfo.review_required is true, after the user has approved
 * what the device showed for it (address, value, ownership, memo or its
 * absence). Outputs that need no review are confirmed by the library when
 * they are fed. Without all actions confirmed, orchard_signer_verify()
 * returns SIGNER_ERR_ACTION_NOT_CONFIRMED and refuses to transition to
 * SIGNER_VERIFIED, so orchard_signer_sign() will fail with NOT_VERIFIED.
 *
 * The library records the call; it cannot know whether a screen was shown.
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
 * Begin the transparent pass: the transaction pays to `num_outputs`
 * transparent addresses.
 * Transitions: RECEIVING_ACTIONS → RECEIVING_TRANSPARENT.
 *
 * TRANSPARENT INPUTS ARE NOT SUPPORTED. `num_inputs` exists so that a
 * caller has to say how many the transaction has: anything but 0 resets the
 * session and returns SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED.
 *
 * Allowed once per session, and not after the totals have been computed
 * (SIGNER_ERR_BAD_STATE, session left as it is): the transparent outputs
 * the user reviewed and the sums behind the fee cannot be replaced by a
 * second pass. More outputs than ORCHARD_SIGNER_MAX_T_OUTPUTS:
 * SIGNER_ERR_TOO_MANY_ACTIONS, session reset.
 *
 * @param num_inputs   Number of transparent inputs — must be 0
 * @param num_outputs  Expected number of transparent outputs
 */
OrchardSignerError orchard_signer_begin_transparent(OrchardSignerCtx *ctx,
                                                     uint16_t num_inputs,
                                                     uint16_t num_outputs);

/**
 * Always fails: transparent inputs are not supported. Resets the session
 * and returns SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED, whatever the state
 * and the data. Kept so that a firmware forwarding the host's message gets
 * the named error instead of a generic one.
 */
OrchardSignerError orchard_signer_feed_transparent_input(OrchardSignerCtx *ctx,
                                                          const uint8_t *data, size_t data_len);

/**
 * Feed one transparent output.
 * Must be in RECEIVING_TRANSPARENT state.
 *
 * Wire format, exact length:
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 *
 * The script must be standard pay-to-public-key-hash (25 bytes:
 * 76 A9 14 <20> 88 AC) or pay-to-script-hash (23 bytes: A9 14 <20> 87) —
 * the two shapes that have an address the device can show. Anything else:
 * SIGNER_ERR_TRANSPARENT_BAD_OUTPUT. The output is hashed into the
 * transparent digest and captured for display. Every error resets the
 * session, except SIGNER_ERR_BAD_STATE for a call outside the pass.
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
 * End the transparent pass: recompute the transparent digest from the
 * outputs that were fed and require it to equal both TxMeta's
 * transparent_sig_digest and `expected_digest`.
 * Transitions: RECEIVING_TRANSPARENT → RECEIVING_ACTIONS (on match).
 * Mismatch: SIGNER_ERR_TRANSPARENT_MISMATCH, session reset.
 *
 * The digest is the ZIP 244 transparent leaf for a transaction with no
 * transparent inputs (see Zip244TransparentState).
 *
 * @param expected_digest  32-byte expected transparent digest from companion
 */
OrchardSignerError orchard_signer_verify_transparent(OrchardSignerCtx *ctx,
                                                      const uint8_t expected_digest[32]);

/**
 * Compute the transaction's totals — fee, value leaving the wallet, value
 * returning to it — from what the device itself verified. See
 * OrchardSignerTotals for the arithmetic.
 *
 * Prerequisites:
 *   - every action has been fed (actions_received == actions_expected);
 *   - the transparent flow, if one was started, has been verified;
 *   - state is RECEIVING_ACTIONS or VERIFIED.
 * After the first successful call nothing that enters the totals can
 * change: no further action is accepted and begin_transparent() refuses.
 *
 * Errors (all but BAD_STATE reset the session):
 *   SIGNER_ERR_BAD_STATE       prerequisites not met
 *   SIGNER_ERR_EMPTY_POOL_BALANCE  non-zero value balance for a pool
 *                              without actions
 *   SIGNER_ERR_FEE_OVERFLOW    overflow in t_out / value balances
 *   SIGNER_ERR_FEE_NEGATIVE    fee < 0 (unbalanced bundle)
 *   SIGNER_ERR_VALUE_OVERFLOW  a sum of output values, or total_leaving,
 *                              exceeds uint64_t
 */
OrchardSignerError orchard_signer_get_totals(OrchardSignerCtx *ctx,
                                              OrchardSignerTotals *out);

/**
 * Mark the totals as confirmed by the user.
 *
 * The firmware MUST display at least `total_leaving` and `fee` from
 * orchard_signer_get_totals() on the trusted screen and call this only
 * after the user explicitly approves them. Without it,
 * orchard_signer_verify() refuses (SIGNER_ERR_FEE_NOT_CONFIRMED).
 *
 * @return SIGNER_ERR_BAD_STATE if get_totals() has not succeeded yet.
 */
OrchardSignerError orchard_signer_confirm_totals(OrchardSignerCtx *ctx);

/**
 * Compute the sighash, compare it with the host's, and move to VERIFIED.
 * Transitions: RECEIVING_ACTIONS → VERIFIED (on match) or resets (on mismatch).
 *
 * Requires every action fed, every output confirmed, the totals confirmed,
 * and the transparent digest either verified from streamed outputs or equal
 * to the empty-bundle constant. The sighash kept for signing is the one the
 * device computed; the host's copy only has to agree with it.
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
 * `alpha` is the host's: the device does not check that the resulting
 * rk = ak + [alpha]G is the rk of any action it hashed. A wrong alpha gives
 * a signature that verifies under no action of the transaction — an invalid
 * transaction, not a loss. The context does not count signatures; the
 * dispatcher gives one per action and then ends the session.
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
