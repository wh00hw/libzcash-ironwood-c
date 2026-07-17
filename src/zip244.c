/**
 * ZIP-244 Transaction Sighash Computation.
 *
 * Implements the v6 (NU6.3 / Ironwood) five-leaf shielded sighash for
 * Zcash Orchard-protocol transactions as specified in
 * https://zips.z.cash/zip-0244. v6-only: the legacy v5 four-leaf sighash
 * entry point and the v5 TxMeta wire layout have been removed.
 */
#include "zip244.h"
#include "blake2b.h"
#include "memzero.h"
#include <string.h>

/* --- ZIP-244 BLAKE2b personalizations (all exactly 16 bytes) --- */

static const char PERSONAL_HEADERS[]    = "ZTxIdHeadersHash";
/* Transparent txid digest personalizations */
static const char PERSONAL_TRANSPARENT[] = "ZTxIdTranspaHash";
static const char PERSONAL_PREVOUTS[]    = "ZTxIdPrevoutHash";
static const char PERSONAL_SEQUENCES[]   = "ZTxIdSequencHash";
static const char PERSONAL_OUTPUTS[]     = "ZTxIdOutputsHash";
/* Per-input transparent sig digest personalizations (ZIP-244 S.2) */
static const char PERSONAL_AMOUNTS[]     = "ZTxTrAmountsHash";
static const char PERSONAL_SCRIPTS[]     = "ZTxTrScriptsHash";
static const char PERSONAL_TXIN_SIG[]    = "Zcash___TxInHash";

static const char PERSONAL_ORCHARD[]    = "ZTxIdOrchardHash";
static const char PERSONAL_COMPACT[]    = "ZTxIdOrcActCHash";
static const char PERSONAL_MEMOS[]      = "ZTxIdOrcActMHash";
static const char PERSONAL_NONCOMPACT[] = "ZTxIdOrcActNHash";
static const char PERSONAL_SAPLING[]    = "ZTxIdSaplingHash";
/* v6 (NU6.3) bundle personalizations. The Orchard v6 bundle digest reuses
 * the v5 action-level personalizations (domain separation happens at the
 * bundle level); Ironwood has its own action-level set. */
static const char PERSONAL_ORCHARD_V6[]     = "ZTxIdOrchardH_v6";
static const char PERSONAL_IRONWOOD[]       = "ZTxIdIronwd_H_v6";
static const char PERSONAL_IRN_COMPACT[]    = "ZTxIdIrnActCH_v6";
static const char PERSONAL_IRN_MEMOS[]      = "ZTxIdIrnActMH_v6";
static const char PERSONAL_IRN_NONCOMPACT[] = "ZTxIdIrnActNH_v6";
/* Root sighash: first 12 bytes are "ZcashTxHash_", last 4 = branch_id LE */

/* --- Action data field offsets --- */
/* Layout: cv_net[32] || nullifier[32] || rk[32] || cmx[32] ||
 *         ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80]
 * Total: 820 bytes
 */
#define OFF_CV_NET       0
#define OFF_NULLIFIER    32
#define OFF_RK           64
#define OFF_CMX          96
#define OFF_EPK          128
#define OFF_ENC          160
#define OFF_OUT          740
#define ACTION_DATA_SIZE 820
#define ENC_CIPHER_SIZE  580
#define OUT_CIPHER_SIZE  80

/* ------------------------------------------------------------------ */
/*  CompactSize encoding (Bitcoin-style variable-length integer)       */
/* ------------------------------------------------------------------ */

/**
 * Write a CompactSize-encoded length to buf.
 * Returns the number of bytes written (1, 3, or 5).
 */
static size_t write_compact_size(uint8_t* buf, uint64_t val) {
    if (val < 253) {
        buf[0] = (uint8_t)val;
        return 1;
    } else if (val <= 0xFFFF) {
        buf[0] = 0xFD;
        buf[1] = val & 0xFF;
        buf[2] = (val >> 8) & 0xFF;
        return 3;
    } else {
        buf[0] = 0xFE;
        buf[1] = val & 0xFF;
        buf[2] = (val >> 8) & 0xFF;
        buf[3] = (val >> 16) & 0xFF;
        buf[4] = (val >> 24) & 0xFF;
        return 5;
    }
}

/* ------------------------------------------------------------------ */
/*  Transparent txid digest (incremental)                             */
/* ------------------------------------------------------------------ */

void zip244_transparent_init(Zip244TransparentState *state) {
    memset(state, 0, sizeof(*state));
    blake2b_InitPersonal(&state->prevouts_ctx,  32, PERSONAL_PREVOUTS,  16);
    blake2b_InitPersonal(&state->sequence_ctx,  32, PERSONAL_SEQUENCES, 16);
    blake2b_InitPersonal(&state->outputs_ctx,   32, PERSONAL_OUTPUTS,   16);
    blake2b_InitPersonal(&state->amounts_ctx,   32, PERSONAL_AMOUNTS,   16);
    blake2b_InitPersonal(&state->scripts_ctx,   32, PERSONAL_SCRIPTS,   16);
    state->inputs_received = 0;
    state->outputs_received = 0;
    state->initialized = true;
}

bool zip244_hash_transparent_input(Zip244TransparentState *state,
                                   const uint8_t *data, size_t data_len) {
    if (!state->initialized) return false;

    /* Wire format: prevout_hash[32] || prevout_index[4 LE] || sequence[4 LE] ||
     *              value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
     * Minimum size: 32 + 4 + 4 + 8 = 48 (+ optional script fields) */
    if (data_len < 48) return false;

    /* prevouts_digest: prevout_hash[32] || prevout_index[4 LE] */
    blake2b_Update(&state->prevouts_ctx, data, 36);

    /* sequence_digest: sequence[4 LE] */
    blake2b_Update(&state->sequence_ctx, data + 36, 4);

    /* amounts_digest: value[8 LE] (as i64, same bytes for non-negative) */
    blake2b_Update(&state->amounts_ctx, data + 40, 8);

    /* Accumulate the per-input value into the running total used for
     * on-device fee computation. Negative values are nonsensical for a
     * Bitcoin/Zcash UTXO input; treat the wire bytes as unsigned and
     * flag overflow so the signer surfaces an error rather than wrapping. */
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | data[40 + i];
    uint64_t new_total = state->t_in_total + v;
    if (new_total < state->t_in_total) state->t_in_overflow = true;
    state->t_in_total = new_total;

    /* scripts_digest: CompactSize(script_len) || script_pubkey
     * Wire format has script_pubkey_len as 2-byte LE at offset 48 */
    uint16_t script_len = (uint16_t)data[48] | ((uint16_t)data[49] << 8);
    const uint8_t *script = data + 50;
    uint8_t cs_buf[5];
    size_t cs_len = write_compact_size(cs_buf, script_len);
    blake2b_Update(&state->scripts_ctx, cs_buf, cs_len);
    if (script_len > 0 && data_len >= (size_t)(50 + script_len)) {
        blake2b_Update(&state->scripts_ctx, script, script_len);
    }

    state->inputs_received++;
    return true;
}

bool zip244_hash_transparent_output(Zip244TransparentState *state,
                                    const uint8_t *data, size_t data_len) {
    if (!state->initialized) return false;

    /* Wire format: value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
     * Minimum size: 8 + 2 = 10 */
    if (data_len < 10) return false;

    const uint8_t *value = data;
    uint16_t script_len = (uint16_t)data[8] | ((uint16_t)data[9] << 8);
    const uint8_t *script = data + 10;

    if (data_len < (size_t)(10 + script_len)) return false;

    /* outputs_digest matches TxOut::write():
     *   value[8 LE] || CompactSize(script_len) || script_pubkey */
    blake2b_Update(&state->outputs_ctx, value, 8);

    uint8_t cs_buf[5];
    size_t cs_len = write_compact_size(cs_buf, script_len);
    blake2b_Update(&state->outputs_ctx, cs_buf, cs_len);
    blake2b_Update(&state->outputs_ctx, script, script_len);

    /* Accumulate output value for on-device fee computation (see notes
     * on zip244_hash_transparent_input). */
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | value[i];
    uint64_t new_total = state->t_out_total + v;
    if (new_total < state->t_out_total) state->t_out_overflow = true;
    state->t_out_total = new_total;

    state->outputs_received++;
    return true;
}

void zip244_transparent_digest(Zip244TransparentState *state,
                               uint8_t digest_out[32]) {
    /* Finalize sub-digests */
    uint8_t prevouts_digest[32], sequence_digest[32], outputs_digest[32];

    blake2b_Final(&state->prevouts_ctx,  prevouts_digest,  32);
    blake2b_Final(&state->sequence_ctx,  sequence_digest,  32);
    blake2b_Final(&state->outputs_ctx,   outputs_digest,   32);

    /* Combine: BLAKE2b-256("ZTxIdTranspaHash",
     *     prevouts_digest || sequence_digest || outputs_digest) */
    blake2b_state root;
    blake2b_InitPersonal(&root, 32, PERSONAL_TRANSPARENT, 16);
    blake2b_Update(&root, prevouts_digest, 32);
    blake2b_Update(&root, sequence_digest, 32);
    blake2b_Update(&root, outputs_digest,  32);
    blake2b_Final(&root, digest_out, 32);
}

void zip244_transparent_per_input_sighash(
    Zip244TransparentState *state,
    uint16_t input_index,
    const uint8_t *input_data,
    size_t input_data_len,
    uint8_t hash_type,
    uint8_t sighash_out[32])
{
    (void)input_index; /* reserved for future per-input disambiguation */

    /* Static storage to stay within embedded stack budget.
     * Same pattern as pallas_point_mul / pallas_jac_double. */
    static blake2b_state s_ctx;
    static uint8_t s_digests[7][32]; /* prevouts, sequence, outputs, amounts, scripts, txin_sig, (spare) */

    /* Finalize sub-digests (copy contexts to avoid consuming them) */
    s_ctx = state->prevouts_ctx;  blake2b_Final(&s_ctx, s_digests[0], 32);
    s_ctx = state->sequence_ctx;  blake2b_Final(&s_ctx, s_digests[1], 32);
    s_ctx = state->outputs_ctx;   blake2b_Final(&s_ctx, s_digests[2], 32);
    s_ctx = state->amounts_ctx;   blake2b_Final(&s_ctx, s_digests[3], 32);
    s_ctx = state->scripts_ctx;   blake2b_Final(&s_ctx, s_digests[4], 32);

    /* txin_sig_digest = BLAKE2b-256("Zcash___TxInHash",
     *     prevout_hash[32] || prevout_index[4 LE] || value[8 LE signed] ||
     *     CompactSize(script_len) || script_pubkey || sequence[4 LE])
     *
     * Wire format of input_data:
     *   prevout_hash[32] || prevout_index[4] || sequence[4] ||
     *   value[8] || script_pubkey_len[2 LE] || script_pubkey[N]
     */
    blake2b_InitPersonal(&s_ctx, 32, PERSONAL_TXIN_SIG, 16);

    if (input_data_len >= 50) {
        blake2b_Update(&s_ctx, input_data, 36);           /* prevout */
        blake2b_Update(&s_ctx, input_data + 40, 8);       /* value */

        uint16_t script_len = (uint16_t)input_data[48] | ((uint16_t)input_data[49] << 8);
        uint8_t cs_buf[5];
        size_t cs_len = write_compact_size(cs_buf, script_len);
        blake2b_Update(&s_ctx, cs_buf, cs_len);
        if (script_len > 0 && input_data_len >= (size_t)(50 + script_len)) {
            blake2b_Update(&s_ctx, input_data + 50, script_len);
        }

        blake2b_Update(&s_ctx, input_data + 36, 4);       /* sequence */
    }

    blake2b_Final(&s_ctx, s_digests[5], 32);               /* txin_sig_digest */

    /* transparent_sig_digest = BLAKE2b-256("ZTxIdTranspaHash",
     *     hash_type[1] || prevouts || amounts || scripts ||
     *     sequence || outputs || txin_sig) */
    blake2b_InitPersonal(&s_ctx, 32, PERSONAL_TRANSPARENT, 16);
    blake2b_Update(&s_ctx, &hash_type, 1);
    blake2b_Update(&s_ctx, s_digests[0], 32);  /* prevouts */
    blake2b_Update(&s_ctx, s_digests[3], 32);  /* amounts */
    blake2b_Update(&s_ctx, s_digests[4], 32);  /* scripts */
    blake2b_Update(&s_ctx, s_digests[1], 32);  /* sequence */
    blake2b_Update(&s_ctx, s_digests[2], 32);  /* outputs */
    blake2b_Update(&s_ctx, s_digests[5], 32);  /* txin_sig */
    blake2b_Final(&s_ctx, sighash_out, 32);

    memzero(s_digests, sizeof(s_digests));
}

/* ------------------------------------------------------------------ */
/*  Metadata serialization                                            */
/* ------------------------------------------------------------------ */

static void write_u32_le(uint8_t* buf, uint32_t v) {
    buf[0] = v & 0xFF;
    buf[1] = (v >> 8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF;
    buf[3] = (v >> 24) & 0xFF;
}

static uint32_t read_u32_le(const uint8_t* buf) {
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

static void write_i64_le(uint8_t* buf, int64_t v) {
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++) {
        buf[i] = u & 0xFF;
        u >>= 8;
    }
}

static int64_t read_i64_le(const uint8_t* buf) {
    uint64_t u = 0;
    for (int i = 7; i >= 0; i--) {
        u = (u << 8) | buf[i];
    }
    return (int64_t)u;
}

bool zip244_parse_tx_meta(const uint8_t* data, size_t len, Zip244TxMeta* out) {
    /* v6-only: exactly 166 (core) or 170 (with coin_type extension) bytes.
     * Everything else — notably the legacy 125/129-byte v5 layouts — is
     * rejected outright; the signer surfaces this as SIGNER_ERR_BAD_META. */
    if (len != ZIP244_TX_META_V6_SIZE && len != ZIP244_TX_META_V6_EXT_SIZE) {
        return false;
    }

    out->version              = read_u32_le(data + 0);
    out->version_group_id     = read_u32_le(data + 4);
    out->consensus_branch_id  = read_u32_le(data + 8);
    out->lock_time            = read_u32_le(data + 12);
    out->expiry_height        = read_u32_le(data + 16);
    out->orchard_flags        = data[20];
    out->value_balance        = read_i64_le(data + 21);
    memcpy(out->anchor, data + 29, 32);
    out->is_v6 = true;

    out->ironwood_flags         = data[61];
    out->ironwood_value_balance = read_i64_le(data + 62);
    memcpy(out->ironwood_anchor, data + 70, 32);
    memcpy(out->transparent_sig_digest, data + 102, 32);
    memcpy(out->sapling_digest, data + 134, 32);

    /* Extended format: coin_type appended after the core fields */
    if (len >= ZIP244_TX_META_V6_EXT_SIZE) {
        out->coin_type = read_u32_le(data + ZIP244_TX_META_V6_SIZE);
    } else {
        out->coin_type = 0; /* unspecified (backward compat with old SDK) */
    }
    return true;
}

size_t zip244_encode_tx_meta(uint8_t* buf, const Zip244TxMeta* meta) {
    /* v6-only: always emits the extended v6 layout (meta->is_v6 is
     * ignored — this library has no pre-v6 wire format). */
    write_u32_le(buf + 0,  meta->version);
    write_u32_le(buf + 4,  meta->version_group_id);
    write_u32_le(buf + 8,  meta->consensus_branch_id);
    write_u32_le(buf + 12, meta->lock_time);
    write_u32_le(buf + 16, meta->expiry_height);
    buf[20] = meta->orchard_flags;
    write_i64_le(buf + 21, meta->value_balance);
    memcpy(buf + 29, meta->anchor, 32);
    buf[61] = meta->ironwood_flags;
    write_i64_le(buf + 62, meta->ironwood_value_balance);
    memcpy(buf + 70, meta->ironwood_anchor, 32);
    memcpy(buf + 102, meta->transparent_sig_digest, 32);
    memcpy(buf + 134, meta->sapling_digest, 32);
    /* Extended: coin_type (not part of ZIP-244 sighash, used for network validation) */
    write_u32_le(buf + ZIP244_TX_META_V6_SIZE, meta->coin_type);
    return ZIP244_TX_META_V6_EXT_SIZE;
}

/* ------------------------------------------------------------------ */
/*  Incremental actions digest                                        */
/* ------------------------------------------------------------------ */

void zip244_actions_init_pool(Zip244ActionsState* state, Zip244Pool pool, bool v6) {
    memset(state, 0, sizeof(*state));

    if (pool == ZIP244_POOL_IRONWOOD) {
        blake2b_InitPersonal(&state->compact_ctx,    32, PERSONAL_IRN_COMPACT,    16);
        blake2b_InitPersonal(&state->memos_ctx,      32, PERSONAL_IRN_MEMOS,      16);
        blake2b_InitPersonal(&state->noncompact_ctx, 32, PERSONAL_IRN_NONCOMPACT, 16);
    } else {
        /* Orchard keeps the v5 action-level personalizations in both
         * formats; the parent bundle digest domain-separates v5 from v6. */
        blake2b_InitPersonal(&state->compact_ctx,    32, PERSONAL_COMPACT,    16);
        blake2b_InitPersonal(&state->memos_ctx,      32, PERSONAL_MEMOS,      16);
        blake2b_InitPersonal(&state->noncompact_ctx, 32, PERSONAL_NONCOMPACT, 16);
    }

    state->pool = pool;
    state->v6 = v6;
    state->actions_hashed = 0;
    state->initialized = true;
}

bool zip244_hash_action(Zip244ActionsState* state,
                        const uint8_t* action_data, size_t action_data_len) {
    if (!state->initialized || action_data_len != ACTION_DATA_SIZE)
        return false;

    blake2b_state* compact = &state->compact_ctx;
    blake2b_state* memos   = &state->memos_ctx;
    blake2b_state* noncomp = &state->noncompact_ctx;

    const uint8_t* cv_net = action_data + OFF_CV_NET;
    const uint8_t* nullifier = action_data + OFF_NULLIFIER;
    const uint8_t* rk = action_data + OFF_RK;
    const uint8_t* cmx = action_data + OFF_CMX;
    const uint8_t* epk = action_data + OFF_EPK;
    const uint8_t* enc = action_data + OFF_ENC;
    const uint8_t* out = action_data + OFF_OUT;

    /* Compact digest: nullifier(32) || cmx(32) || epk(32) || enc[0..52] */
    blake2b_Update(compact, nullifier, 32);
    blake2b_Update(compact, cmx, 32);
    blake2b_Update(compact, epk, 32);
    blake2b_Update(compact, enc, 52);

    /* Memos digest: enc[52..564] (512 bytes) */
    blake2b_Update(memos, enc + 52, 512);

    /* Non-compact digest: cv_net(32) || rk(32) || enc[564..580](16) || out(80) */
    blake2b_Update(noncomp, cv_net, 32);
    blake2b_Update(noncomp, rk, 32);
    blake2b_Update(noncomp, enc + 564, 16);
    blake2b_Update(noncomp, out, OUT_CIPHER_SIZE);

    state->actions_hashed++;
    return true;
}

/** Select the bundle-digest personalization for a (pool, format) pair. */
static const char* bundle_personal(Zip244Pool pool, bool v6) {
    if (pool == ZIP244_POOL_IRONWOOD) return PERSONAL_IRONWOOD;
    return v6 ? PERSONAL_ORCHARD_V6 : PERSONAL_ORCHARD;
}

void zip244_bundle_digest(Zip244ActionsState* state,
                          uint8_t flags,
                          int64_t value_balance,
                          const uint8_t anchor[32],
                          uint8_t digest_out[32]) {
    /* Finalize the three sub-digests */
    uint8_t compact_digest[32], memos_digest[32], noncompact_digest[32];

    blake2b_Final(&state->compact_ctx,    compact_digest,    32);
    blake2b_Final(&state->memos_ctx,      memos_digest,      32);
    blake2b_Final(&state->noncompact_ctx, noncompact_digest, 32);

    /* Combine into the bundle effects digest:
     * BLAKE2b-256(bundle_personal,
     *     compact || memos || noncompact || flags[1] || value_balance[8]
     *     [|| anchor[32] — v5 format only; under v6 the anchor is committed
     *      by the authorizing-data digest instead])
     */
    blake2b_state bundle;
    blake2b_InitPersonal(&bundle, 32, bundle_personal(state->pool, state->v6), 16);
    blake2b_Update(&bundle, compact_digest, 32);
    blake2b_Update(&bundle, memos_digest, 32);
    blake2b_Update(&bundle, noncompact_digest, 32);

    /* Flags: 1 byte */
    blake2b_Update(&bundle, &flags, 1);

    /* Value balance: 8 bytes LE signed */
    uint8_t vb[8];
    write_i64_le(vb, value_balance);
    blake2b_Update(&bundle, vb, 8);

    /* Anchor: 32 bytes, v5 format only */
    if (!state->v6) {
        blake2b_Update(&bundle, anchor, 32);
    }

    blake2b_Final(&bundle, digest_out, 32);
}

void zip244_pool_empty_digest(Zip244Pool pool, bool v6, uint8_t digest_out[32]) {
    zip244_empty_digest(bundle_personal(pool, v6), digest_out);
}

/* ------------------------------------------------------------------ */
/*  Header and empty-bundle digests                                   */
/* ------------------------------------------------------------------ */

void zip244_empty_digest(const char* personal, uint8_t digest_out[32]) {
    blake2b_state s;
    blake2b_InitPersonal(&s, 32, personal, 16);
    blake2b_Final(&s, digest_out, 32);
}

void zip244_sapling_empty_digest(uint8_t digest_out[32]) {
    zip244_empty_digest(PERSONAL_SAPLING, digest_out);
}

void zip244_header_digest(const Zip244TxMeta* meta, uint8_t digest_out[32]) {
    blake2b_state s;
    blake2b_InitPersonal(&s, 32, PERSONAL_HEADERS, 16);

    uint8_t buf[4];
    write_u32_le(buf, meta->version);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->version_group_id);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->consensus_branch_id);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->lock_time);
    blake2b_Update(&s, buf, 4);
    write_u32_le(buf, meta->expiry_height);
    blake2b_Update(&s, buf, 4);

    blake2b_Final(&s, digest_out, 32);
}

/* ------------------------------------------------------------------ */
/*  Full shielded sighash (v6 five-leaf tree)                         */
/* ------------------------------------------------------------------ */

void zip244_shielded_sighash_v6(const Zip244TxMeta* meta,
                                Zip244ActionsState* orchard_state,
                                Zip244ActionsState* ironwood_state,
                                uint8_t sighash_out[32]) {
    /* 1. Header digest (same construction as v5; the v6 version and
     *    version-group-id values feed through the meta fields). */
    uint8_t hdr_digest[32];
    zip244_header_digest(meta, hdr_digest);

    /* 2./3. Transparent + Sapling digests (pre-computed by companion;
     *    Sapling emptiness is enforced by the signer at feed_meta). */
    const uint8_t *transparent_digest = meta->transparent_sig_digest;
    const uint8_t *sapling_digest = meta->sapling_digest;

    /* 4. Orchard (sealed pool) digest — empty-bundle constant when the
     *    transaction carries no Orchard actions. No anchor under v6. */
    uint8_t orchard_digest_val[32];
    if (orchard_state != NULL && orchard_state->actions_hashed > 0) {
        zip244_bundle_digest(orchard_state, meta->orchard_flags,
                             meta->value_balance, meta->anchor,
                             orchard_digest_val);
    } else {
        zip244_pool_empty_digest(ZIP244_POOL_ORCHARD, true, orchard_digest_val);
    }

    /* 5. Ironwood digest — empty-bundle constant when absent. */
    uint8_t ironwood_digest_val[32];
    if (ironwood_state != NULL && ironwood_state->actions_hashed > 0) {
        zip244_bundle_digest(ironwood_state, meta->ironwood_flags,
                             meta->ironwood_value_balance, meta->ironwood_anchor,
                             ironwood_digest_val);
    } else {
        zip244_pool_empty_digest(ZIP244_POOL_IRONWOOD, true, ironwood_digest_val);
    }

    /* 6. Root sighash:
     * BLAKE2b-256("ZcashTxHash_" || consensus_branch_id[4 LE],
     *     header || transparent || sapling || orchard || ironwood)
     */
    uint8_t root_personal[16];
    memcpy(root_personal, "ZcashTxHash_", 12);
    write_u32_le(root_personal + 12, meta->consensus_branch_id);

    blake2b_state root;
    blake2b_InitPersonal(&root, 32, (const char*)root_personal, 16);
    blake2b_Update(&root, hdr_digest, 32);
    blake2b_Update(&root, transparent_digest, 32);
    blake2b_Update(&root, sapling_digest, 32);
    blake2b_Update(&root, orchard_digest_val, 32);
    blake2b_Update(&root, ironwood_digest_val, 32);
    blake2b_Final(&root, sighash_out, 32);
}
