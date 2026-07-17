/**
 * ZIP-244 Transaction Sighash Computation for Zcash v6 Transactions.
 *
 * Implements the shielded sighash algorithm as specified in ZIP-244:
 * https://zips.z.cash/zip-0244
 *
 * v6-only (post-NU6.3): the legacy v5 four-leaf sighash entry point and the
 * 125/129-byte v5 TxMeta wire layout have been removed — the parser rejects
 * pre-v6 metadata outright. The pool/format-parameterized helpers
 * (zip244_actions_init_pool, zip244_bundle_digest, zip244_pool_empty_digest)
 * retain their v5-capable parameterization because the v6 digest tree
 * domain-separates at the bundle level, but no top-level v5 path remains.
 *
 * v6 digest tree (NU6.3 / Ironwood, ZIP 258): adds the Ironwood pool leaf
 * and moves the shielded-pool anchors out of the effects digest (they are
 * committed by the authorizing-data digest instead, which the device never
 * computes):
 *   sighash = BLAKE2b-256("ZcashTxHash_" || branch_id_le,
 *       header_digest || transparent_digest || sapling_digest ||
 *       orchard_digest || ironwood_digest)
 *
 * Where orchard_digest  = BLAKE2b-256("ZTxIdOrchardH_v6",
 *       compact_digest || memos_digest || noncompact_digest ||
 *       flags[1] || value_balance[8 LE])          (no anchor)
 * and   ironwood_digest = BLAKE2b-256("ZTxIdIronwd_H_v6",
 *       compact_digest || memos_digest || noncompact_digest ||
 *       flags[1] || value_balance[8 LE])          (no anchor)
 * with the Ironwood action-level digests personalized
 * "ZTxIdIrnActCH_v6" / "ZTxIdIrnActMH_v6" / "ZTxIdIrnActNH_v6" (the Orchard
 * ones keep the v5 strings — the parent digest domain-separates them).
 * An absent pool contributes BLAKE2b-256(pool bundle personalization, "").
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "blake2b.h"

/**
 * The shielded value pool an Orchard-protocol bundle belongs to.
 * Matches the pool byte prefixed to v6 action payloads on the wire.
 */
typedef enum {
    ZIP244_POOL_ORCHARD  = 0x00,
    ZIP244_POOL_IRONWOOD = 0x01,
} Zip244Pool;

/**
 * Transaction header metadata needed for sighash computation.
 * Sent from companion to device before action data.
 *
 * Wire format (v6, 166 bytes — the ONLY layout this library accepts;
 * legacy 125/129-byte v5 metas are rejected by zip244_parse_tx_meta):
 *   version[4 LE] || version_group_id[4 LE] || consensus_branch_id[4 LE] ||
 *   lock_time[4 LE] || expiry_height[4 LE] ||
 *   orchard_flags[1] || value_balance[8 LE signed] || anchor[32] ||
 *   ironwood_flags[1] || ironwood_value_balance[8 LE signed] ||
 *   ironwood_anchor[32] ||
 *   transparent_sig_digest[32] || sapling_digest[32]
 *
 * The transparent_sig_digest and sapling_digest are pre-computed by the
 * companion from the full transaction data, since the device only has
 * access to the Orchard-protocol bundles.
 *
 * Orchard-only invariant: this signer enforces sapling_digest equal to
 * the ZIP-244 empty-bundle constant (zip244_sapling_empty_digest) at
 * orchard_signer_feed_meta() time. Any non-empty value aborts the
 * session with SIGNER_ERR_SAPLING_NOT_EMPTY before action streaming.
 */
/** Wire size of the core v6 TxMeta fields. */
#define ZIP244_TX_META_V6_SIZE     166
/** v6 wire size with the coin_type extension (network discrimination). */
#define ZIP244_TX_META_V6_EXT_SIZE 170

/** NU6.3 consensus constants (v6 transaction format). */
#define ZIP244_V6_TX_VERSION       0x80000006u
#define ZIP244_V6_VERSION_GROUP_ID 0xD884B698u

typedef struct {
    uint32_t version;
    uint32_t version_group_id;
    uint32_t consensus_branch_id;
    uint32_t lock_time;
    uint32_t expiry_height;
    uint8_t  orchard_flags;
    int64_t  value_balance;
    uint8_t  anchor[32];
    /** Always true after a successful zip244_parse_tx_meta() — the library
     *  is v6-only and the parser rejects pre-v6 layouts. Retained for
     *  struct/firmware compatibility. */
    bool     is_v6;
    /** Ironwood bundle flag byte (bit 2 = enableCrossAddress under NU6.3). */
    uint8_t  ironwood_flags;
    /** Ironwood bundle net value balance (zatoshis, signed). */
    int64_t  ironwood_value_balance;
    /** Ironwood bundle anchor. Carried for display/consistency only — under
     *  the v6 format anchors are NOT part of the effects digest. */
    uint8_t  ironwood_anchor[32];
    uint8_t  transparent_sig_digest[32];
    uint8_t  sapling_digest[32];
    /** ZIP-32 coin type: 133 = mainnet, 1 = testnet, 0 = unspecified. */
    uint32_t coin_type;
} Zip244TxMeta;

/**
 * Incremental state for computing the ZIP-244 orchard actions digest.
 *
 * Three parallel BLAKE2b contexts hash different portions of each action:
 * - compact:    nullifier || cmx || epk || enc_ciphertext[0..52]
 * - memos:      enc_ciphertext[52..564]
 * - noncompact: cv_net || rk || enc_ciphertext[564..580] || out_ciphertext
 */
typedef struct {
    /* Three parallel BLAKE2b-256 hashers with ZIP-244 personalizations */
    blake2b_state compact_ctx;
    blake2b_state memos_ctx;
    blake2b_state noncompact_ctx;
    uint16_t actions_hashed;
    /** The pool this state hashes for; selects the bundle-digest
     *  personalization at finalize time. */
    Zip244Pool pool;
    /** True for the v6 commitment format (no anchor in the effects digest,
     *  v6 bundle personalization). */
    bool v6;
    bool initialized;
} Zip244ActionsState;

/* ------------------------------------------------------------------ */
/*  Transparent digest (incremental, for on-device verification)      */
/* ------------------------------------------------------------------ */

/**
 * Incremental state for computing the ZIP-244 transparent txid digest.
 *
 * Three parallel BLAKE2b contexts hash different portions of each input/output:
 * - prevouts:  prevout_hash[32] || prevout_index[4 LE] per input
 * - sequences: sequence[4 LE] per input
 * - outputs:   value[8 LE] || CompactSize(script_len) || script_pubkey per output
 *
 * The combined digest is:
 *   BLAKE2b-256("ZTxIdTranspaHash",
 *       prevouts_digest || sequence_digest || outputs_digest)
 */
typedef struct {
    blake2b_state prevouts_ctx;    /* "ZTxIdPrevoutHash" */
    blake2b_state sequence_ctx;    /* "ZTxIdSequencHash" */
    blake2b_state outputs_ctx;     /* "ZTxIdOutputsHash" */
    blake2b_state amounts_ctx;     /* "ZTxTrAmountsHash" (per-input sighash) */
    blake2b_state scripts_ctx;     /* "ZTxTrScriptsHash" (per-input sighash) */
    uint16_t inputs_received;
    uint16_t outputs_received;
    /* Per-input/output value running totals (zatoshis), independent of the
     * BLAKE2b digests. Used by the orchard signer to compute the on-device
     * fee = t_in_total - t_out_total + value_balance, so the user can be
     * asked to confirm the fee value itself (closes the "companion-claimed
     * fee != real fee" gap — a hostile companion could inflate value_balance
     * and pay extra to miners while showing a small fee in its own UI). */
    uint64_t t_in_total;
    uint64_t t_out_total;
    bool t_in_overflow;            /* set if any add overflowed */
    bool t_out_overflow;
    bool initialized;
} Zip244TransparentState;

/**
 * Initialize the incremental transparent digest state.
 * Must be called before any zip244_hash_transparent_input/output() calls.
 */
void zip244_transparent_init(Zip244TransparentState *state);

/**
 * Hash one transparent input incrementally.
 *
 * Wire format (from companion SDK):
 *   prevout_hash[32] || prevout_index[4 LE] || sequence[4 LE] ||
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 *
 * Extracts prevout + sequence and feeds them into the respective hashers.
 * Returns true on success, false if data_len < 48 (minimum: 32+4+4+8).
 */
bool zip244_hash_transparent_input(Zip244TransparentState *state,
                                   const uint8_t *data, size_t data_len);

/**
 * Hash one transparent output incrementally.
 *
 * Wire format (from companion SDK):
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 *
 * Re-encodes with CompactSize for the script length before hashing,
 * matching the serialization used by zcash_primitives::TxOut::write().
 * Returns true on success, false if data_len < 10.
 */
bool zip244_hash_transparent_output(Zip244TransparentState *state,
                                    const uint8_t *data, size_t data_len);

/**
 * Finalize and compute the transparent txid digest.
 *
 * transparent_digest = BLAKE2b-256("ZTxIdTranspaHash",
 *     prevouts_digest || sequence_digest || outputs_digest)
 *
 * digest_out must be 32 bytes.
 */
void zip244_transparent_digest(Zip244TransparentState *state,
                               uint8_t digest_out[32]);

/**
 * Compute the per-input transparent signature digest (ZIP-244 S.2).
 *
 * For SIGHASH_ALL (the standard case):
 *   BLAKE2b-256("ZTxIdTranspaHash",
 *       hash_type[1] || prevouts_digest || amounts_digest || scripts_digest ||
 *       sequence_digest || outputs_digest || txin_sig_digest)
 *
 * Where txin_sig_digest = BLAKE2b-256("Zcash___TxInHash",
 *       prevout_hash[32] || prevout_index[4 LE] || value[8 LE signed] ||
 *       CompactSize(script_len) || script_pubkey || sequence[4 LE])
 *
 * @param state         Transparent state (must have all inputs/outputs hashed)
 * @param input_index   Index of the input being signed
 * @param inputs        Array of all transparent inputs (for txin_sig_digest)
 * @param num_inputs    Number of inputs
 * @param hash_type     Sighash type (usually 0x01 = SIGHASH_ALL)
 * @param sighash_out   32-byte output
 */
void zip244_transparent_per_input_sighash(
    Zip244TransparentState *state,
    uint16_t input_index,
    const uint8_t *input_data,  /* raw wire data of the specific input being signed */
    size_t input_data_len,
    uint8_t hash_type,
    uint8_t sighash_out[32]);

/* ------------------------------------------------------------------ */

/**
 * Parse transaction metadata from wire format.
 *
 * v6-only: accepts exactly ZIP244_TX_META_V6_SIZE (166) or
 * ZIP244_TX_META_V6_EXT_SIZE (170) bytes; any other length — including the
 * legacy 125/129-byte v5 layouts — returns false.
 * Returns true on success.
 */
bool zip244_parse_tx_meta(const uint8_t* data, size_t len, Zip244TxMeta* out);

/**
 * Serialize transaction metadata to the v6 wire format (with the coin_type
 * extension). buf must be at least ZIP244_TX_META_V6_EXT_SIZE bytes.
 * Returns ZIP244_TX_META_V6_EXT_SIZE.
 */
size_t zip244_encode_tx_meta(uint8_t* buf, const Zip244TxMeta* meta);

/**
 * Initialize the incremental actions digest state for a specific pool and
 * commitment format (NU6.3 / Ironwood).
 *
 * Orchard states use the v5 action-level personalizations regardless of
 * format (the parent bundle digest domain-separates v5 from v6); Ironwood
 * states use the "ZTxIdIrnAct{C,M,N}H_v6" personalizations. Ironwood
 * requires v6 == true.
 */
void zip244_actions_init_pool(Zip244ActionsState* state, Zip244Pool pool, bool v6);

/**
 * Hash one action's data incrementally into the three parallel digesters.
 *
 * action_data layout (820 bytes):
 *   cv_net[32] || nullifier[32] || rk[32] || cmx[32] ||
 *   ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80]
 *
 * Returns true on success, false if action_data_len != 820.
 */
bool zip244_hash_action(Zip244ActionsState* state,
                        const uint8_t* action_data, size_t action_data_len);

/**
 * Finalize the three action digesters and compute the bundle effects digest
 * for the state's (pool, format):
 *
 *   BLAKE2b-256(bundle_personal,
 *       compact_digest || memos_digest || noncompact_digest ||
 *       flags[1] || value_balance[8 LE] [|| anchor[32] if v5])
 *
 * bundle_personal is "ZTxIdOrchardHash" (Orchard v5), "ZTxIdOrchardH_v6"
 * (Orchard v6) or "ZTxIdIronwd_H_v6" (Ironwood). The anchor is hashed only
 * in the v5 format; under v6 it lives in the authorizing-data digest.
 * Consumes the state's hash contexts. digest_out must be 32 bytes.
 */
void zip244_bundle_digest(Zip244ActionsState* state,
                          uint8_t flags,
                          int64_t value_balance,
                          const uint8_t anchor[32],
                          uint8_t digest_out[32]);

/**
 * Compute the empty-bundle effects digest for a shielded pool:
 * BLAKE2b-256 of no data with the pool's bundle personalization for the
 * given format. Used for the pool leaves a v6 transaction does not carry.
 */
void zip244_pool_empty_digest(Zip244Pool pool, bool v6, uint8_t digest_out[32]);

/**
 * Compute the empty-bundle digest for a protocol component.
 * Used when transparent or sapling bundles are absent.
 *
 * Returns BLAKE2b-256(personal, "") — hash with personalization but no data.
 * personal must be exactly 16 bytes. digest_out must be 32 bytes.
 */
void zip244_empty_digest(const char* personal, uint8_t digest_out[32]);

/**
 * Compute the empty-bundle Sapling sighash digest (ZIP-244).
 *
 * Equivalent to zip244_empty_digest("ZTxIdSaplingHash", out).
 *
 * The wallet is Orchard-only by design (no Sapling keys, no Sapling notes,
 * no Sapling-only recipients in scope), so any well-formed transaction it
 * signs must have an empty Sapling bundle. The signer enforces equality
 * between the companion-supplied sapling_digest and this constant on
 * TxMeta receipt; any non-empty Sapling component aborts the session
 * before action streaming begins.
 *
 * digest_out must be 32 bytes.
 */
void zip244_sapling_empty_digest(uint8_t digest_out[32]);

/**
 * Compute the header digest.
 *
 * header_digest = BLAKE2b-256("ZTxIdHeadersHash",
 *     version[4 LE] || version_group_id[4 LE] ||
 *     consensus_branch_id[4 LE] || lock_time[4 LE] || expiry_height[4 LE])
 */
void zip244_header_digest(const Zip244TxMeta* meta, uint8_t digest_out[32]);

/**
 * Compute the full v6 (NU6.3 / Ironwood) shielded sighash.
 *
 * sighash = BLAKE2b-256("ZcashTxHash_" || consensus_branch_id[4 LE],
 *     header_digest || transparent_digest || sapling_digest ||
 *     orchard_digest || ironwood_digest)
 *
 * A pool state with zero hashed actions (or a NULL state pointer)
 * contributes the pool's empty-bundle digest; otherwise the state must have
 * been initialized with zip244_actions_init_pool() for the matching pool
 * with v6 == true, and its bundle digest is computed from the pool's
 * flags/value_balance in `meta` (anchors are NOT hashed under v6).
 * Consumes the non-empty states' hash contexts.
 *
 * sighash_out must be 32 bytes.
 */
void zip244_shielded_sighash_v6(const Zip244TxMeta* meta,
                                Zip244ActionsState* orchard_state,
                                Zip244ActionsState* ironwood_state,
                                uint8_t sighash_out[32]);
