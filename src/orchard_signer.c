/**
 * Orchard Signing Context — enforces ZIP-244 verification before signing.
 */
#include "orchard_signer.h"
#include "redpallas.h"
#include "orchard.h"
#include "memzero.h"
#include <stdint.h>
#include <string.h>

void orchard_signer_init(OrchardSignerCtx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = SIGNER_IDLE;
}

void orchard_signer_reset(OrchardSignerCtx *ctx)
{
    memzero(ctx->verified_sighash, sizeof(ctx->verified_sighash));
    orchard_signer_init(ctx);
}

OrchardSignerError orchard_signer_feed_meta(OrchardSignerCtx *ctx,
                                             const uint8_t *meta_data, size_t meta_len,
                                             uint16_t total_actions)
{
    if (ctx->state != SIGNER_IDLE) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!zip244_parse_tx_meta(meta_data, meta_len, &ctx->tx_meta)) {
        return SIGNER_ERR_BAD_META;
    }

    /* Validate coin_type consistency: if both session and TxMeta specify
     * a coin_type (non-zero), they must match. */
    if (ctx->coin_type != 0 && ctx->tx_meta.coin_type != 0 &&
        ctx->coin_type != ctx->tx_meta.coin_type) {
        return SIGNER_ERR_NETWORK_MISMATCH;
    }

    /* Orchard-only invariant: the wallet derives no Sapling keys, holds no
     * Sapling notes, and does not send to Sapling-only recipients. The
     * companion-supplied sapling_digest must therefore equal the ZIP-244
     * empty-bundle constant. Enforcing this on-device closes the last
     * sighash component that was previously trusted from the companion
     * and prevents a hostile companion from siphoning value via a hidden
     * Sapling output. Aborts the session before any action is hashed. */
    uint8_t sapling_empty[32];
    zip244_sapling_empty_digest(sapling_empty);
    if (!ct_memequal(ctx->tx_meta.sapling_digest, sapling_empty, 32)) {
        memzero(sapling_empty, sizeof(sapling_empty));
        memzero(&ctx->tx_meta, sizeof(ctx->tx_meta));
        return SIGNER_ERR_SAPLING_NOT_EMPTY;
    }
    memzero(sapling_empty, sizeof(sapling_empty));

    /* Per-action display storage is bounded; reject early if the tx claims
     * more outputs than we can display, rather than failing partway through
     * the action stream. */
    if (total_actions > ORCHARD_SIGNER_MAX_ACTIONS) {
        memzero(&ctx->tx_meta, sizeof(ctx->tx_meta));
        return SIGNER_ERR_TOO_MANY_ACTIONS;
    }

    if (ctx->tx_meta.is_v6) {
        /* v6 (NU6.3 / Ironwood) consistency + policy checks:
         *  - the header version/version-group-id must be the v6 constants
         *    (a v6-layout TxMeta with a v5 header would let a companion
         *    pick personalizations that don't match the encoded tx);
         *  - the sealed Orchard pool's flag byte must have bit 2 clear —
         *    consensus mandates the cross-address restriction post-NU6.3 —
         *    and no reserved bits set;
         *  - the Ironwood flag byte may use bits 0..2 only
         *    (enableSpends / enableOutputs / enableCrossAddress). */
        if (ctx->tx_meta.version != ZIP244_V6_TX_VERSION ||
            ctx->tx_meta.version_group_id != ZIP244_V6_VERSION_GROUP_ID ||
            (ctx->tx_meta.orchard_flags & ~0x03u) != 0 ||
            (ctx->tx_meta.ironwood_flags & ~0x07u) != 0) {
            memzero(&ctx->tx_meta, sizeof(ctx->tx_meta));
            return SIGNER_ERR_BAD_META;
        }
    }

    zip244_actions_init_pool(&ctx->actions_state, ZIP244_POOL_ORCHARD,
                             ctx->tx_meta.is_v6);
    zip244_actions_init_pool(&ctx->ironwood_actions_state, ZIP244_POOL_IRONWOOD,
                             true);
    ctx->has_meta = true;
    ctx->actions_expected = total_actions;
    ctx->actions_received = 0;
    ctx->state = SIGNER_RECEIVING_ACTIONS;

    return SIGNER_OK;
}

/* ------------------------------------------------------------------ */
/*  Transparent digest verification (v3)                              */
/* ------------------------------------------------------------------ */

OrchardSignerError orchard_signer_begin_transparent(OrchardSignerCtx *ctx,
                                                     uint16_t num_inputs,
                                                     uint16_t num_outputs)
{
    /* Can begin transparent verification after metadata is received
     * but before (or instead of) starting actions. Accept from
     * RECEIVING_ACTIONS state (after feed_meta). */
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }

    zip244_transparent_init(&ctx->transparent_state);
    ctx->transparent_inputs_expected = num_inputs;
    ctx->transparent_outputs_expected = num_outputs;
    ctx->transparent_verified = false;
    ctx->state = SIGNER_RECEIVING_TRANSPARENT;

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_feed_transparent_input(OrchardSignerCtx *ctx,
                                                          const uint8_t *data, size_t data_len)
{
    if (ctx->state != SIGNER_RECEIVING_TRANSPARENT) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.inputs_received >= ctx->transparent_inputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!zip244_hash_transparent_input(&ctx->transparent_state, data, data_len)) {
        return SIGNER_ERR_TRANSPARENT_BAD_INPUT;
    }

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_feed_transparent_output(OrchardSignerCtx *ctx,
                                                           const uint8_t *data, size_t data_len)
{
    if (ctx->state != SIGNER_RECEIVING_TRANSPARENT) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.outputs_received >= ctx->transparent_outputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    /* Capture (value, script_pubkey) for the per-output display BEFORE
     * the hash so we own a clean copy. Wire format:
     *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
     * If the bounded display array is full we refuse the tx — the
     * no-blind-signing invariant requires every output we sign to be
     * displayable on the trusted screen. */
    if (data_len < 10) return SIGNER_ERR_TRANSPARENT_BAD_OUTPUT;
    uint16_t idx = ctx->transparent_state.outputs_received;
    if (idx >= ORCHARD_SIGNER_MAX_T_OUTPUTS) {
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TOO_MANY_ACTIONS;
    }
    uint64_t value = 0;
    for (int b = 0; b < 8; b++) value |= ((uint64_t)data[b]) << (8 * b);
    uint16_t script_len = (uint16_t)data[8] | ((uint16_t)data[9] << 8);
    if ((size_t)10 + script_len != data_len) {
        return SIGNER_ERR_TRANSPARENT_BAD_OUTPUT;
    }
    TransparentOutputDisplay *disp = &ctx->t_outputs_display[idx];
    disp->value = value;
    if (script_len > sizeof(disp->script)) {
        /* Non-standard / oversized script — refuse rather than sign
         * something we can't display. P2PKH (25 B) and P2SH (23 B) are
         * the only standardised Zcash transparent output shapes. */
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TRANSPARENT_BAD_OUTPUT;
    }
    memcpy(disp->script, data + 10, script_len);
    disp->script_len = (uint8_t)script_len;

    if (!zip244_hash_transparent_output(&ctx->transparent_state, data, data_len)) {
        return SIGNER_ERR_TRANSPARENT_BAD_OUTPUT;
    }

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_get_transparent_output_display(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    uint64_t *value_out,
    uint8_t *script_out,
    size_t script_out_cap,
    size_t *script_len_out)
{
    if (idx >= ctx->transparent_state.outputs_received ||
        idx >= ORCHARD_SIGNER_MAX_T_OUTPUTS) {
        return SIGNER_ERR_INVALID_ACTION_INDEX;
    }
    const TransparentOutputDisplay *disp = &ctx->t_outputs_display[idx];
    if (script_out_cap < disp->script_len) return SIGNER_ERR_BAD_STATE;
    if (value_out) *value_out = disp->value;
    if (script_out && disp->script_len > 0) {
        memcpy(script_out, disp->script, disp->script_len);
    }
    if (script_len_out) *script_len_out = disp->script_len;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_verify_transparent(OrchardSignerCtx *ctx,
                                                      const uint8_t expected_digest[32])
{
    if (ctx->state != SIGNER_RECEIVING_TRANSPARENT) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.inputs_received != ctx->transparent_inputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->transparent_state.outputs_received != ctx->transparent_outputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    /* Compute transparent digest from received inputs/outputs */
    uint8_t computed[32];
    zip244_transparent_digest(&ctx->transparent_state, computed);

    /* Verify against TxMeta's transparent_sig_digest */
    if (!ct_memequal(computed, ctx->tx_meta.transparent_sig_digest, 32)) {
        memzero(computed, sizeof(computed));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TRANSPARENT_MISMATCH;
    }

    /* Also verify against the expected_digest from the companion */
    if (!ct_memequal(computed, expected_digest, 32)) {
        memzero(computed, sizeof(computed));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TRANSPARENT_MISMATCH;
    }

    memzero(computed, sizeof(computed));
    ctx->transparent_verified = true;
    ctx->state = SIGNER_RECEIVING_ACTIONS;

    return SIGNER_OK;
}

/* ------------------------------------------------------------------ */
/*  Orchard action feed                                               */
/* ------------------------------------------------------------------ */

/* Route an action to the digest state of its pool. Ironwood actions are
 * only valid inside v6 transactions; unknown pool bytes are rejected. */
static Zip244ActionsState* signer_pool_state(OrchardSignerCtx *ctx, Zip244Pool pool)
{
    switch (pool) {
        case ZIP244_POOL_ORCHARD:
            return &ctx->actions_state;
        case ZIP244_POOL_IRONWOOD:
            return ctx->tx_meta.is_v6 ? &ctx->ironwood_actions_state : NULL;
        default:
            return NULL;
    }
}

/* The note plaintext version implied by an action's pool: the sealed
 * Orchard pool carries ZIP-212 V2 notes, Ironwood carries ZIP-2005 V3. */
static uint8_t signer_pool_note_version(Zip244Pool pool)
{
    return (pool == ZIP244_POOL_IRONWOOD) ? ORCHARD_NOTE_V3 : ORCHARD_NOTE_V2;
}

OrchardSignerError orchard_signer_feed_action(OrchardSignerCtx *ctx,
                                               Zip244Pool pool,
                                               const uint8_t *action_data, size_t action_len)
{
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->actions_received >= ctx->actions_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    Zip244ActionsState *pool_state = signer_pool_state(ctx, pool);
    if (pool_state == NULL) {
        return SIGNER_ERR_BAD_POOL;
    }

    if (!zip244_hash_action(pool_state, action_data, action_len)) {
        return SIGNER_ERR_BAD_ACTION;
    }

    ctx->actions_received++;
    return SIGNER_OK;
}

/* Action data layout (matches zip244.c OFF_* constants):
 *   cv_net[32] || nullifier[32] || rk[32] || cmx[32] || ephemeral_key[32] ||
 *   enc_ciphertext[580] || out_ciphertext[80]   (total 820 bytes)
 * The nullifier is at offset 32 (used as rho for the output note's NoteCommit
 * per Orchard's split-action construction); cmx is at offset 96.
 */
#define ORCHARD_ACTION_OFFSET_NULLIFIER 32
#define ORCHARD_ACTION_OFFSET_CMX       96
#define ORCHARD_ACTION_OFFSET_EPK       128
#define ORCHARD_ACTION_OFFSET_ENC       160
#define ORCHARD_ACTION_ENC_SIZE         580
#define ORCHARD_ACTION_TOTAL_SIZE       820

OrchardSignerError orchard_signer_feed_action_with_note(
    OrchardSignerCtx *ctx,
    Zip244Pool pool,
    const uint8_t *action_data, size_t action_len,
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32])
{
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }
    if (ctx->actions_received >= ctx->actions_expected) {
        return SIGNER_ERR_BAD_STATE;
    }
    if (ctx->actions_received >= ORCHARD_SIGNER_MAX_ACTIONS) {
        /* Per-action display storage is bounded; a tx with more outputs
         * than ORCHARD_SIGNER_MAX_ACTIONS cannot be safely displayed. */
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TOO_MANY_ACTIONS;
    }
    if (action_len != ORCHARD_ACTION_TOTAL_SIZE) {
        return SIGNER_ERR_BAD_ACTION;
    }

    Zip244ActionsState *pool_state = signer_pool_state(ctx, pool);
    if (pool_state == NULL) {
        return SIGNER_ERR_BAD_POOL;
    }

    /* Recompute cmx from the claimed (d, pk_d, value, rseed) using the
     * action's nullifier as rho, and compare it constant-time against the
     * cmx field embedded in the action bytes. A hostile companion that
     * substituted the recipient must produce a colliding cmx, which is
     * computationally infeasible against Sinsemilla. The note version
     * (and thus the rcm derivation) follows the action's pool. */
    const uint8_t *d         = recipient;          /* 11 bytes */
    const uint8_t *pk_d      = recipient + 11;     /* 32 bytes */
    const uint8_t *rho       = action_data + ORCHARD_ACTION_OFFSET_NULLIFIER;
    const uint8_t *action_cmx = action_data + ORCHARD_ACTION_OFFSET_CMX;

    uint8_t computed_cmx[32];
    orchard_compute_cmx(d, pk_d, value, rho, rseed,
                        signer_pool_note_version(pool), computed_cmx);

    if (!ct_memequal(computed_cmx, action_cmx, 32)) {
        memzero(computed_cmx, sizeof(computed_cmx));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_NOTE_COMMITMENT_MISMATCH;
    }
    memzero(computed_cmx, sizeof(computed_cmx));

    /* cmx verified: feed the action through the normal hash path. */
    if (!zip244_hash_action(pool_state, action_data, action_len)) {
        return SIGNER_ERR_BAD_ACTION;
    }

    /* Capture the display info so the firmware UI can render this output
     * to the user, and so verify() can later refuse to advance to VERIFIED
     * unless every captured action has been explicitly confirmed. */
    OrchardActionDisplay *disp = &ctx->actions_display[ctx->actions_received];
    memcpy(disp->recipient, recipient, 43);
    disp->value = value;
    disp->confirmed = false;

    ctx->actions_received++;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_feed_action_with_note_and_memo(
    OrchardSignerCtx *ctx,
    Zip244Pool pool,
    const uint8_t *action_data, size_t action_len,
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32],
    const uint8_t memo[512])
{
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }
    if (ctx->actions_received >= ctx->actions_expected) {
        return SIGNER_ERR_BAD_STATE;
    }
    if (ctx->actions_received >= ORCHARD_SIGNER_MAX_ACTIONS) {
        orchard_signer_reset(ctx);
        return SIGNER_ERR_TOO_MANY_ACTIONS;
    }
    if (action_len != ORCHARD_ACTION_TOTAL_SIZE) {
        return SIGNER_ERR_BAD_ACTION;
    }

    Zip244ActionsState *pool_state = signer_pool_state(ctx, pool);
    if (pool_state == NULL) {
        return SIGNER_ERR_BAD_POOL;
    }
    uint8_t note_version = signer_pool_note_version(pool);

    const uint8_t *d         = recipient;          /* 11 bytes */
    const uint8_t *pk_d      = recipient + 11;     /* 32 bytes */
    const uint8_t *rho       = action_data + ORCHARD_ACTION_OFFSET_NULLIFIER;
    const uint8_t *action_cmx = action_data + ORCHARD_ACTION_OFFSET_CMX;
    const uint8_t *action_epk = action_data + ORCHARD_ACTION_OFFSET_EPK;
    const uint8_t *action_enc = action_data + ORCHARD_ACTION_OFFSET_ENC;

    /* Static-storage for the 580 B recomputed-ciphertext buffer so the
     * function frame stays within the 512 B per-function stack budget.
     * Same pattern as orchard_compute_enc_ciphertext() and the other
     * Pallas heavyweights. Single-threaded signer => no re-entrancy. */
    static uint8_t computed_enc[ORCHARD_ACTION_ENC_SIZE];

    /* Step 1: cmx recomputation — same as feed_action_with_note(). */
    uint8_t computed_cmx[32];
    orchard_compute_cmx(d, pk_d, value, rho, rseed, note_version, computed_cmx);
    if (!ct_memequal(computed_cmx, action_cmx, 32)) {
        memzero(computed_cmx, sizeof(computed_cmx));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_NOTE_COMMITMENT_MISMATCH;
    }
    memzero(computed_cmx, sizeof(computed_cmx));

    /* Step 2: recompute enc_ciphertext from (recipient, value, rseed, memo)
     * and cross-check both ciphertext + epk against the action bytes. esk
     * is derived internally from rseed + rho (shared by ZIP-212 V2 and
     * ZIP-2005 V3 notes); the plaintext lead byte follows the pool's note
     * version. Closes the memo-substitution gap that cmx alone leaves open. */
    uint8_t computed_epk[32];
    int rc = orchard_compute_enc_ciphertext_from_rseed(
        d, pk_d, value, rseed, rho, memo, note_version,
        computed_enc, computed_epk);
    if (rc != 0) {
        /* pk_d is not a valid Pallas point. */
        memzero(computed_enc, sizeof(computed_enc));
        memzero(computed_epk, sizeof(computed_epk));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_BAD_PK_D;
    }

    /* Both checks must pass before we commit anything to the action stream.
     * OR-accumulate the two equality results so the timing profile reveals
     * only "both matched" vs "at least one didn't" — a sender that knows
     * which of the two diverged could infer something about device state. */
    int enc_ok = (int)ct_memequal(computed_enc, action_enc, ORCHARD_ACTION_ENC_SIZE);
    int epk_ok = (int)ct_memequal(computed_epk, action_epk, 32);
    memzero(computed_enc, sizeof(computed_enc));
    memzero(computed_epk, sizeof(computed_epk));
    if (!(enc_ok & epk_ok)) {
        orchard_signer_reset(ctx);
        return SIGNER_ERR_MEMO_MISMATCH;
    }

    /* All recomputations verified: feed the action through the normal hash path. */
    if (!zip244_hash_action(pool_state, action_data, action_len)) {
        return SIGNER_ERR_BAD_ACTION;
    }

    /* Capture display info — identical to feed_action_with_note, PLUS the
     * memo plaintext so the firmware UI can render it on the trusted
     * screen (closes the "memo bound but not user-visible" gap that the
     * AEAD recomputation alone leaves open). */
    OrchardActionDisplay *disp = &ctx->actions_display[ctx->actions_received];
    memcpy(disp->recipient, recipient, 43);
    disp->value = value;
    disp->confirmed = false;
    memcpy(disp->memo, memo, 512);
    disp->memo_present = true;

    ctx->actions_received++;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_get_action_display(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    uint8_t recipient_out[43],
    uint64_t *value_out)
{
    if (idx >= ctx->actions_received) {
        return SIGNER_ERR_INVALID_ACTION_INDEX;
    }
    const OrchardActionDisplay *disp = &ctx->actions_display[idx];
    if (recipient_out) memcpy(recipient_out, disp->recipient, 43);
    if (value_out)     *value_out = disp->value;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_get_action_memo(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    uint8_t memo_out[512],
    bool *present_out)
{
    if (idx >= ctx->actions_received) {
        return SIGNER_ERR_INVALID_ACTION_INDEX;
    }
    const OrchardActionDisplay *disp = &ctx->actions_display[idx];
    if (memo_out)    memcpy(memo_out, disp->memo, 512);
    if (present_out) *present_out = disp->memo_present;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_confirm_action(
    OrchardSignerCtx *ctx,
    uint16_t idx)
{
    if (idx >= ctx->actions_received) {
        return SIGNER_ERR_INVALID_ACTION_INDEX;
    }
    ctx->actions_display[idx].confirmed = true;
    return SIGNER_OK;
}

bool orchard_signer_recipient_matches_any(
    const OrchardSignerCtx *ctx,
    const uint8_t recipient_43[43])
{
    /* OR-accumulate the constant-time equality result across every action.
     * We do NOT short-circuit on first match — running the full loop
     * preserves a constant timing profile across "matched at action 0",
     * "matched at action 4", and "did not match" — preventing a host from
     * inferring which action was the matching one. */
    int any_match = 0;
    for (uint16_t i = 0; i < ctx->actions_received; i++) {
        any_match |= (int)ct_memequal(
            ctx->actions_display[i].recipient, recipient_43, 43);
    }
    return any_match != 0;
}

OrchardSignerError orchard_signer_get_fee(OrchardSignerCtx *ctx,
                                           uint64_t *fee_out)
{
    if (!ctx->has_meta) {
        return SIGNER_ERR_BAD_STATE;
    }

    /* If the transaction declared transparent components, the caller must
     * have streamed all of them before we can compute the fee — otherwise
     * t_in_total / t_out_total are partial sums. */
    if (ctx->transparent_inputs_expected > 0 || ctx->transparent_outputs_expected > 0) {
        if (ctx->transparent_state.inputs_received != ctx->transparent_inputs_expected ||
            ctx->transparent_state.outputs_received != ctx->transparent_outputs_expected) {
            return SIGNER_ERR_BAD_STATE;
        }
        if (ctx->transparent_state.t_in_overflow || ctx->transparent_state.t_out_overflow) {
            orchard_signer_reset(ctx);
            return SIGNER_ERR_FEE_OVERFLOW;
        }
    }

    if (ctx->fee_computed) {
        if (fee_out) *fee_out = ctx->fee_zatoshis;
        return SIGNER_OK;
    }

    /* fee = t_in - t_out + value_balance(Orchard) [+ value_balance(Ironwood)]
     * (all in zatoshis)
     *
     * Each term has a 21M·10^8 = 2.1·10^15 cap on a valid Zcash tx, well
     * inside i64. We still cross-check at each step because the companion
     * controls these inputs and a deliberately malformed bundle could try
     * to produce wraparound. */
    uint64_t t_in  = ctx->transparent_state.t_in_total;
    uint64_t t_out = ctx->transparent_state.t_out_total;
    int64_t  vb    = ctx->tx_meta.value_balance;

    /* v6: both shielded pools contribute their net value balance to the
     * transaction's transparent value pool. Guard the sum against
     * companion-crafted wraparound before folding into the fee. */
    if (ctx->tx_meta.is_v6) {
        int64_t ivb = ctx->tx_meta.ironwood_value_balance;
        if (ivb > 0 && vb > INT64_MAX - ivb) {
            orchard_signer_reset(ctx);
            return SIGNER_ERR_FEE_OVERFLOW;
        }
        if (ivb < 0 && vb < INT64_MIN - ivb) {
            orchard_signer_reset(ctx);
            return SIGNER_ERR_FEE_OVERFLOW;
        }
        vb += ivb;
    }

    if (t_in  > (uint64_t)INT64_MAX) { orchard_signer_reset(ctx); return SIGNER_ERR_FEE_OVERFLOW; }
    if (t_out > (uint64_t)INT64_MAX) { orchard_signer_reset(ctx); return SIGNER_ERR_FEE_OVERFLOW; }

    int64_t t_in_i  = (int64_t)t_in;
    int64_t t_out_i = (int64_t)t_out;
    int64_t net_transparent = t_in_i - t_out_i;  /* both non-negative i64 */

    int64_t fee_signed;
    if (vb > 0) {
        if (net_transparent > INT64_MAX - vb) {
            orchard_signer_reset(ctx);
            return SIGNER_ERR_FEE_OVERFLOW;
        }
    } else if (vb < 0) {
        if (net_transparent < INT64_MIN - vb) {
            orchard_signer_reset(ctx);
            return SIGNER_ERR_FEE_OVERFLOW;
        }
    }
    fee_signed = net_transparent + vb;

    if (fee_signed < 0) {
        orchard_signer_reset(ctx);
        return SIGNER_ERR_FEE_NEGATIVE;
    }

    ctx->fee_zatoshis = (uint64_t)fee_signed;
    ctx->fee_computed = true;
    if (fee_out) *fee_out = ctx->fee_zatoshis;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_confirm_fee(OrchardSignerCtx *ctx)
{
    if (!ctx->fee_computed) {
        /* Firmware must call get_fee() first, then display the value, then
         * confirm. Confirming without computing would be confirming a stale
         * zero — refuse so a buggy UI can't silently approve nothing. */
        return SIGNER_ERR_BAD_STATE;
    }
    ctx->fee_confirmed = true;
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_verify(OrchardSignerCtx *ctx,
                                          const uint8_t expected_sighash[32])
{
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (!ctx->has_meta) {
        return SIGNER_ERR_BAD_STATE;
    }

    if (ctx->actions_received != ctx->actions_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    /* No-blind-signing invariant: every action's (recipient, value) must
     * have been displayed to the user via orchard_signer_get_action_display()
     * AND explicitly confirmed via orchard_signer_confirm_action(). The
     * library refuses to advance to SIGNER_VERIFIED until that is true.
     * orchard_signer_sign() in turn refuses to produce a signature unless
     * the context is in SIGNER_VERIFIED — so a hostile firmware that skips
     * the UI step cannot extract a signature. */
    for (uint16_t i = 0; i < ctx->actions_received; i++) {
        if (!ctx->actions_display[i].confirmed) {
            return SIGNER_ERR_ACTION_NOT_CONFIRMED;
        }
    }

    /* Same invariant extended to the miner fee: even if every output
     * recipient and value was confirmed, a hostile companion can inflate
     * value_balance (and lie about the fee on its own UI) to pay the
     * surplus to miners. The fee number must be computed on-device and
     * explicitly approved by the user before signing can proceed. */
    if (!ctx->fee_confirmed) {
        return SIGNER_ERR_FEE_NOT_CONFIRMED;
    }

    /* Orchard-only-with-no-transparent invariant. The sighash mixes in
     * tx_meta.transparent_sig_digest verbatim. If the host did NOT walk us
     * through the transparent input/output stream (transparent_verified is
     * false), then transparent_sig_digest must be the empty-bundle constant
     * BLAKE2b("ZTxIdTranspaHash", ""). A host that supplies an arbitrary
     * non-empty digest while skipping the transparent flow is trying to bind
     * an unverified transparent bundle to the Orchard signature — see
     * docs/security-audit/02-orchard-protocol-signing.md C2/M1.
     * Mirrors the sapling_digest enforcement at feed_meta(). */
    if (!ctx->transparent_verified) {
        uint8_t transparent_empty[32];
        zip244_empty_digest("ZTxIdTranspaHash", transparent_empty);
        if (!ct_memequal(ctx->tx_meta.transparent_sig_digest, transparent_empty, 32)) {
            memzero(transparent_empty, sizeof(transparent_empty));
            orchard_signer_reset(ctx);
            return SIGNER_ERR_TRANSPARENT_NOT_EMPTY;
        }
        memzero(transparent_empty, sizeof(transparent_empty));
    }

    /* Compute the full ZIP-244 sighash from metadata + actions. v6
     * transactions use the five-leaf tree with the Ironwood pool digest;
     * a pool with zero streamed actions contributes its empty-bundle
     * constant. */
    uint8_t computed[32];
    if (ctx->tx_meta.is_v6) {
        zip244_shielded_sighash_v6(&ctx->tx_meta, &ctx->actions_state,
                                   &ctx->ironwood_actions_state, computed);
    } else {
        zip244_shielded_sighash(&ctx->tx_meta, &ctx->actions_state, computed);
    }

    if (!ct_memequal(computed, expected_sighash, 32)) {
        memzero(computed, sizeof(computed));
        orchard_signer_reset(ctx);
        return SIGNER_ERR_SIGHASH_MISMATCH;
    }

    /* Store verified sighash and transition to VERIFIED */
    memcpy(ctx->verified_sighash, computed, 32);
    memzero(computed, sizeof(computed));
    ctx->state = SIGNER_VERIFIED;

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_check(const OrchardSignerCtx *ctx,
                                         const uint8_t sighash[32])
{
    if (ctx->state != SIGNER_VERIFIED) {
        return SIGNER_ERR_NOT_VERIFIED;
    }

    if (!ct_memequal(sighash, ctx->verified_sighash, 32)) {
        return SIGNER_ERR_WRONG_SIGHASH;
    }

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_sign(const OrchardSignerCtx *ctx,
                                        const uint8_t sighash[32],
                                        const uint8_t ask[32],
                                        const uint8_t alpha[32],
                                        uint8_t sig_out[64],
                                        uint8_t rk_out[32])
{
    /* Enforce verification invariant */
    if (ctx->state != SIGNER_VERIFIED) {
        return SIGNER_ERR_NOT_VERIFIED;
    }

    if (!ct_memequal(sighash, ctx->verified_sighash, 32)) {
        return SIGNER_ERR_WRONG_SIGHASH;
    }

    /* Delegate to RedPallas */
    int ret = redpallas_sign(ask, alpha, sighash, sig_out, rk_out);
    return (ret == 0) ? SIGNER_OK : SIGNER_ERR_SIGN_FAILED;
}
