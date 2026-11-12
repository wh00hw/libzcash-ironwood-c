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
 * NOT every field here is bound by the sighash. SECURITY.md, "What binds
 * each host-supplied field", has the full table; in short:
 *   - flags and value_balance of a pool are hashed ONLY if that pool has at
 *     least one action. For a pool without actions the bundle does not
 *     exist on chain and zip244_shielded_sighash_v6() hashes the empty-
 *     bundle constant — it does not read the pool's fields. A caller that
 *     uses value_balance for anything (a fee) must therefore require it to
 *     be zero for such a pool; orchard_signer does.
 *   - anchors are not in the v6 effects digest at all.
 *   - coin_type is not part of the transaction.
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
    /** Ironwood bundle anchor. Like `anchor`, not read by this library:
     *  under the v6 format anchors are NOT part of the effects digest. */
    uint8_t  ironwood_anchor[32];
    uint8_t  transparent_sig_digest[32];
    uint8_t  sapling_digest[32];
    /** ZIP-32 coin type the host declares: 133 = mainnet, 1 = testnet,
     *  0 = not sent (166-byte layout). Not part of the transaction; the
     *  signer compares it with the device's own network. */
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
 * Incremental state for the ZIP-244 transparent digest of a transaction
 * with NO TRANSPARENT INPUTS (shielded -> transparent payments).
 *
 * TRANSPARENT INPUTS ARE NOT SUPPORTED. With an empty vin, ZIP 244 defines
 * the transparent leaf of the signature hash (S.2) to be the txid digest
 * (T.2):
 *
 *   BLAKE2b-256("ZTxIdTranspaHash",
 *       prevouts_digest || sequence_digest || outputs_digest)
 *
 * where prevouts_digest and sequence_digest are the hashes of nothing under
 * their personalizations, and the whole leaf is BLAKE2b-256(
 * "ZTxIdTranspaHash", "") when there are no outputs either. That is the only
 * case this state computes. With a non-empty vin the leaf is a different
 * construction (hash_type, amounts, scripts, per-input data) that this
 * library does not implement — earlier revisions hashed inputs into the T.2
 * form, which gives a sighash the network rejects; see README, "Transparent
 * inputs are not supported".
 */
typedef struct {
    blake2b_state outputs_ctx;     /* "ZTxIdOutputsHash" */
    uint16_t outputs_received;
    /* Running total of the output values (zatoshis), for the on-device fee
     * and "total leaving" computation. */
    uint64_t t_out_total;
    bool t_out_overflow;           /* set if the sum overflowed uint64 */
    bool initialized;
} Zip244TransparentState;

/**
 * Initialize the incremental transparent digest state.
 * Must be called before any zip244_hash_transparent_output() call.
 */
void zip244_transparent_init(Zip244TransparentState *state);

/* zip244_hash_transparent_input() was removed together with transparent-
 * input support (it also read two bytes past a 48-byte input). */

/**
 * Hash one transparent output incrementally.
 *
 * Wire format (from companion SDK), exact length required:
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 *
 * Re-encodes with CompactSize for the script length before hashing,
 * matching the serialization used by zcash_primitives::TxOut::write().
 * Returns true on success, false if data_len != 10 + script_pubkey_len.
 */
bool zip244_hash_transparent_output(Zip244TransparentState *state,
                                    const uint8_t *data, size_t data_len);

/**
 * Finalize and compute the transparent leaf for a transaction without
 * transparent inputs (see Zip244TransparentState): the empty-bundle
 * constant if no output was hashed, the T.2 digest otherwise.
 * Consumes the state's hash context. digest_out must be 32 bytes.
 */
void zip244_transparent_digest(Zip244TransparentState *state,
                               uint8_t digest_out[32]);

/* zip244_transparent_per_input_sighash() was removed: it returned the S.2
 * transparent node, not the transaction's signature hash, so an ECDSA
 * signature over it was not valid on chain. */

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
 * contributes the pool's empty-bundle digest, and that pool's flags and
 * value_balance in `meta` are then NOT hashed (the caller must not rely on
 * them: see Zip244TxMeta). Otherwise the state must have
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
