/**
 * Orchard Signing Context — enforces ZIP-244 verification before signing.
 */
#include "orchard_signer.h"
#include "redpallas.h"
#include "orchard.h"
#include "memzero.h"
#include <stdint.h>
#include <string.h>

static bool signer_network_valid(uint32_t coin_type)
{
    return coin_type == ORCHARD_SIGNER_COIN_MAINNET ||
           coin_type == ORCHARD_SIGNER_COIN_TESTNET;
}

void orchard_signer_init(OrchardSignerCtx *ctx, uint32_t coin_type)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = SIGNER_IDLE;
    /* Anything but the two known networks stays 0 = unset, and feed_meta()
     * refuses to start a session. */
    ctx->coin_type = signer_network_valid(coin_type) ? coin_type : 0;
}

void orchard_signer_reset(OrchardSignerCtx *ctx)
{
    /* The context holds the session's incoming viewing keys, the verified
     * sighash and any captured memo: wipe all of it with the
     * elision-resistant primitive, then re-establish the IDLE state. The
     * device's network is not session state and is the one thing kept. */
    uint32_t coin_type = ctx->coin_type;
    memzero(ctx, sizeof(*ctx));
    ctx->state = SIGNER_IDLE;
    ctx->coin_type = coin_type;
}

/* Consensus branch allow-list (see ORCHARD_SIGNER_ALLOWED_BRANCH_IDS). */
static const uint32_t SIGNER_ALLOWED_BRANCH_IDS[] = ORCHARD_SIGNER_ALLOWED_BRANCH_IDS;

static bool signer_branch_allowed(uint32_t branch_id)
{
    bool ok = false;
    for (size_t i = 0;
         i < sizeof(SIGNER_ALLOWED_BRANCH_IDS) / sizeof(SIGNER_ALLOWED_BRANCH_IDS[0]);
         i++) {
        ok |= (SIGNER_ALLOWED_BRANCH_IDS[i] == branch_id);
    }
    return ok;
}

/* feed_meta() failed: keep nothing of the rejected metadata. */
static OrchardSignerError signer_meta_reject(OrchardSignerCtx *ctx, OrchardSignerError err)
{
    orchard_signer_reset(ctx);
    return err;
}

OrchardSignerError orchard_signer_feed_meta(OrchardSignerCtx *ctx,
                                             const OrchardSignerFvk *fvk,
                                             const uint8_t *meta_data, size_t meta_len,
                                             uint16_t total_actions)
{
    if (ctx->state != SIGNER_IDLE) {
        return SIGNER_ERR_BAD_STATE;
    }
    if (fvk == NULL || fvk->ak == NULL || fvk->nk == NULL || fvk->rivk == NULL) {
        return SIGNER_ERR_BAD_FVK;
    }
    /* The device's network is fixed by orchard_signer_init() and survives
     * every reset; without it nothing is signed. */
    if (!signer_network_valid(ctx->coin_type)) {
        return SIGNER_ERR_NETWORK_UNSET;
    }

    /* v6-only (post-NU6.3): zip244_parse_tx_meta accepts exactly the
     * 166/170-byte v6 layouts. Legacy 125/129-byte v5 metas (and any
     * other length) fail the parse and are rejected here. */
    if (!zip244_parse_tx_meta(meta_data, meta_len, &ctx->tx_meta)) {
        return signer_meta_reject(ctx, SIGNER_ERR_BAD_META);
    }

    /* Network: the host must declare the device's coin type, every time.
     * The 166-byte layout has no coin type (parsed as 0) and is refused by
     * the same comparison. This is a consistency check against a wallet
     * application on the other network, not a binding: the coin type is not
     * part of the transaction (see orchard_signer_init). */
    if (ctx->tx_meta.coin_type != ctx->coin_type) {
        return signer_meta_reject(ctx, SIGNER_ERR_NETWORK_MISMATCH);
    }

    /* Orchard-only invariant: the wallet derives no Sapling keys, holds no
     * Sapling notes, and does not send to Sapling-only recipients. The
     * companion-supplied sapling_digest must therefore equal the ZIP-244
     * empty-bundle constant, which is then what the sighash binds. */
    uint8_t sapling_empty[32];
    zip244_sapling_empty_digest(sapling_empty);
    int sapling_ok = ct_memequal(ctx->tx_meta.sapling_digest, sapling_empty, 32);
    memzero(sapling_empty, sizeof(sapling_empty));
    if (!sapling_ok) {
        return signer_meta_reject(ctx, SIGNER_ERR_SAPLING_NOT_EMPTY);
    }

    /* A transaction without actions has no shielded spend, hence nothing
     * this device could authorise (transparent inputs are not supported).
     * It is also the one case where "which pools are empty" is known
     * already: both, so neither value balance would be bound. */
    if (total_actions == 0) {
        return signer_meta_reject(ctx, SIGNER_ERR_NO_ACTIONS);
    }
    /* Per-action display storage is bounded; reject early if the tx claims
     * more outputs than we can display. */
    if (total_actions > ORCHARD_SIGNER_MAX_ACTIONS) {
        return signer_meta_reject(ctx, SIGNER_ERR_TOO_MANY_ACTIONS);
    }

    /* v6 (NU6.3 / Ironwood) consistency + policy checks:
     *  - the header version/version-group-id must be the v6 constants;
     *  - the sealed Orchard pool's flag byte must have bit 2 clear —
     *    consensus mandates the cross-address restriction post-NU6.3 —
     *    and no reserved bits set;
     *  - the Ironwood flag byte may use bits 0..2 only
     *    (enableSpends / enableOutputs / enableCrossAddress). */
    if (ctx->tx_meta.version != ZIP244_V6_TX_VERSION ||
        ctx->tx_meta.version_group_id != ZIP244_V6_VERSION_GROUP_ID ||
        (ctx->tx_meta.orchard_flags & ~0x03u) != 0 ||
        (ctx->tx_meta.ironwood_flags & ~0x07u) != 0) {
        return signer_meta_reject(ctx, SIGNER_ERR_BAD_META);
    }

    /* Consensus branch gate: the branch ID goes into the sighash
     * personalization, so whatever is accepted here is what gets signed
     * for. Only the upgrades this build knows are accepted. */
    if (!signer_branch_allowed(ctx->tx_meta.consensus_branch_id)) {
        return signer_meta_reject(ctx, SIGNER_ERR_BRANCH_NOT_ALLOWED);
    }

    /* The anchors are not part of the v6 effects digest and nothing here
     * reads them: do not keep host bytes that nothing binds. */
    memzero(ctx->tx_meta.anchor, sizeof(ctx->tx_meta.anchor));
    memzero(ctx->tx_meta.ironwood_anchor, sizeof(ctx->tx_meta.ironwood_anchor));

    /* Session viewing keys, from the device's own full viewing key. Done
     * last so that a rejected TxMeta costs no curve arithmetic and leaves
     * no key material behind. */
    if (orchard_derive_ivks(fvk->ak, fvk->nk, fvk->rivk,
                            ctx->ivk_external, ctx->ivk_internal) != 0) {
        return signer_meta_reject(ctx, SIGNER_ERR_BAD_FVK);
    }

    zip244_actions_init_pool(&ctx->actions_state, ZIP244_POOL_ORCHARD, true);
    zip244_actions_init_pool(&ctx->ironwood_actions_state, ZIP244_POOL_IRONWOOD,
                             true);
    ctx->has_meta = true;
    ctx->actions_expected = total_actions;
    ctx->actions_received = 0;
    ctx->state = SIGNER_RECEIVING_ACTIONS;

    return SIGNER_OK;
}

/* Reset and return: a rejected input aborts the session, so no error path
 * leaves the viewing keys or a half-fed stream behind. */
static OrchardSignerError signer_abort(OrchardSignerCtx *ctx, OrchardSignerError err)
{
    orchard_signer_reset(ctx);
    return err;
}

/* ------------------------------------------------------------------ */
/*  Transparent OUTPUTS (transparent inputs are not supported)        */
/* ------------------------------------------------------------------ */

OrchardSignerError orchard_signer_begin_transparent(OrchardSignerCtx *ctx,
                                                     uint16_t num_inputs,
                                                     uint16_t num_outputs)
{
    /* Spending from a t-address is not implemented: the sighash this
     * library computes is only correct for an empty vin, and there is no
     * transparent signature to give. Refuse the whole transaction. */
    if (num_inputs != 0) {
        return signer_abort(ctx, SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    }
    if (ctx->state != SIGNER_RECEIVING_ACTIONS) {
        return SIGNER_ERR_BAD_STATE;
    }
    /* One transparent pass per session, and none once the totals exist:
     * a second begin would re-initialise the sums behind the fee and the
     * outputs the user reviewed. */
    if (ctx->transparent_begun || ctx->fee_computed) {
        return SIGNER_ERR_BAD_STATE;
    }
    /* Every output has to be shown: more than can be captured is refused
     * before anything is hashed. */
    if (num_outputs > ORCHARD_SIGNER_MAX_T_OUTPUTS) {
        return signer_abort(ctx, SIGNER_ERR_TOO_MANY_ACTIONS);
    }
    ctx->transparent_begun = true;

    zip244_transparent_init(&ctx->transparent_state);
    ctx->transparent_outputs_expected = num_outputs;
    ctx->transparent_verified = false;
    ctx->state = SIGNER_RECEIVING_TRANSPARENT;

    return SIGNER_OK;
}

OrchardSignerError orchard_signer_feed_transparent_input(OrchardSignerCtx *ctx,
                                                          const uint8_t *data, size_t data_len)
{
    (void)data;
    (void)data_len;
    return signer_abort(ctx, SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
}

/* Standard P2PKH (76 A9 14 <20> 88 AC) or P2SH (A9 14 <20> 87): the two
 * script shapes with a t-address. Public data, plain comparisons. */
static bool signer_script_is_standard(const uint8_t *script, size_t len)
{
    if (len == 25) {
        return script[0] == 0x76 && script[1] == 0xA9 && script[2] == 0x14 &&
               script[23] == 0x88 && script[24] == 0xAC;
    }
    if (len == 23) {
        return script[0] == 0xA9 && script[1] == 0x14 && script[22] == 0x87;
    }
    return false;
}

OrchardSignerError orchard_signer_feed_transparent_output(OrchardSignerCtx *ctx,
                                                           const uint8_t *data, size_t data_len)
{
    if (ctx->state != SIGNER_RECEIVING_TRANSPARENT) {
        return SIGNER_ERR_BAD_STATE;
    }
    uint16_t idx = ctx->transparent_state.outputs_received;
    if (idx >= ctx->transparent_outputs_expected) {
        return signer_abort(ctx, SIGNER_ERR_BAD_STATE);
    }
    if (idx >= ORCHARD_SIGNER_MAX_T_OUTPUTS) {
        /* Unreachable: begin_transparent() bounds outputs_expected. */
        return signer_abort(ctx, SIGNER_ERR_TOO_MANY_ACTIONS);
    }

    /* Wire format: value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N],
     * exact length. Only scripts that have an address are accepted: every
     * output the device signs for must be displayable. */
    if (data == NULL || data_len < 10) {
        return signer_abort(ctx, SIGNER_ERR_TRANSPARENT_BAD_OUTPUT);
    }
    uint64_t value = 0;
    for (int b = 0; b < 8; b++) value |= ((uint64_t)data[b]) << (8 * b);
    uint16_t script_len = (uint16_t)data[8] | ((uint16_t)data[9] << 8);
    if ((size_t)10 + script_len != data_len ||
        !signer_script_is_standard(data + 10, script_len)) {
        return signer_abort(ctx, SIGNER_ERR_TRANSPARENT_BAD_OUTPUT);
    }
    if (!zip244_hash_transparent_output(&ctx->transparent_state, data, data_len)) {
        return signer_abort(ctx, SIGNER_ERR_TRANSPARENT_BAD_OUTPUT);
    }

    TransparentOutputDisplay *disp = &ctx->t_outputs_display[idx];
    disp->value = value;
    memcpy(disp->script, data + 10, script_len);
    disp->script_len = (uint8_t)script_len;

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
    if (!ctx->transparent_begun ||
        idx >= ctx->transparent_state.outputs_received ||
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
    if (ctx->transparent_state.outputs_received != ctx->transparent_outputs_expected) {
        return SIGNER_ERR_BAD_STATE;
    }

    /* The transparent leaf of a transaction with no transparent inputs,
     * from the outputs that were fed (and shown). The stream is complete,
     * so finalising the hasher here loses nothing. */
    uint8_t computed[32];
    zip244_transparent_digest(&ctx->transparent_state, computed);

    /* It must be what TxMeta carries — that is the value the sighash
     * mixes in — and what the host's sentinel says. */
    int ok = ct_memequal(computed, ctx->tx_meta.transparent_sig_digest, 32) &
             ct_memequal(computed, expected_digest, 32);
    memzero(computed, sizeof(computed));
    if (!ok) {
        return signer_abort(ctx, SIGNER_ERR_TRANSPARENT_MISMATCH);
    }

    ctx->transparent_verified = true;
    ctx->state = SIGNER_RECEIVING_ACTIONS;

    return SIGNER_OK;
}

/* ------------------------------------------------------------------ */
/*  Orchard action feed                                               */
/* ------------------------------------------------------------------ */

/* Route an action to the digest state of its pool. Every session is v6
 * (feed_meta rejects anything else), so both pools are always valid;
 * unknown pool bytes are rejected. */
static Zip244ActionsState* signer_pool_state(OrchardSignerCtx *ctx, Zip244Pool pool)
{
    switch (pool) {
        case ZIP244_POOL_ORCHARD:
            return &ctx->actions_state;
        case ZIP244_POOL_IRONWOOD:
            return &ctx->ironwood_actions_state;
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

bool orchard_signer_memo_is_empty(const uint8_t memo[512])
{
    /* Exactly 0xF6 || 0^511 (ZIP-302 "no memo") or 0^512 (empty text).
     * The memo is the host's data, nothing secret steers this scan. */
    if (memo[0] != 0xF6 && memo[0] != 0x00) return false;
    uint8_t acc = 0;
    for (size_t i = 1; i < 512; i++) acc |= memo[i];
    return acc == 0;
}

/* A pool for which no action was streamed has no bundle in the transaction:
 * the sighash then holds that pool's empty-bundle constant and does NOT
 * cover the value balance TxMeta declares for it. Such a value balance must
 * be zero, or the fee shown to the user would be whatever the host wants
 * (declare -(real fee - 0.0001) for the absent pool and a 5 ZEC fee reads
 * 0.0001). Only meaningful once every action is in. */
static bool signer_empty_pools_neutral(const OrchardSignerCtx *ctx)
{
    bool ok = true;
    if (ctx->actions_state.actions_hashed == 0) {
        ok &= (ctx->tx_meta.value_balance == 0);
    }
    if (ctx->ironwood_actions_state.actions_hashed == 0) {
        ok &= (ctx->tx_meta.ironwood_value_balance == 0);
    }
    return ok;
}

/* Who does (d, pk_d) belong to? Decided from the session's own incoming
 * viewing keys only. The internal key is tried first and the external one
 * only if it did not match, so the running time depends on the outcome —
 * which is the classification the device is about to display, and which
 * the host can compute itself from the full viewing key it was given.
 * Each individual check is constant-time in the key. */
static uint8_t signer_classify(const OrchardSignerCtx *ctx, const uint8_t recipient[43])
{
    if (orchard_ivk_owns_address(ctx->ivk_internal, recipient, recipient + 11)) {
        return (uint8_t)ORCHARD_OUTPUT_OWN_INTERNAL;
    }
    if (orchard_ivk_owns_address(ctx->ivk_external, recipient, recipient + 11)) {
        return (uint8_t)ORCHARD_OUTPUT_OWN_EXTERNAL;
    }
    return (uint8_t)ORCHARD_OUTPUT_EXTERNAL;
}

/* The single entry point through which an action reaches the sighash.
 * Order:
 *   state/limits -> cmx -> ciphertext -> classification -> memo slot
 *   -> hash -> record -> (last action) empty-pool rule.
 * Nothing is recorded, and nothing is hashed, unless every step passed;
 * any failure resets the context. */
OrchardSignerError orchard_signer_feed_action_with_note_and_memo(
    OrchardSignerCtx *ctx,
    Zip244Pool pool,
    const uint8_t *action_data, size_t action_len,
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32],
    const uint8_t memo[512])
{
    if (action_data == NULL || recipient == NULL || rseed == NULL || memo == NULL) {
        return signer_abort(ctx, SIGNER_ERR_BAD_ACTION);
    }
    if (ctx->state != SIGNER_RECEIVING_ACTIONS || !ctx->has_meta) {
        return signer_abort(ctx, SIGNER_ERR_BAD_STATE);
    }
    /* A repeated or surplus action, or one arriving after the totals were
     * computed, ends the session. */
    if (ctx->actions_received >= ctx->actions_expected || ctx->fee_computed) {
        return signer_abort(ctx, SIGNER_ERR_BAD_STATE);
    }
    if (ctx->actions_received >= ORCHARD_SIGNER_MAX_ACTIONS) {
        /* Per-action display storage is bounded; a tx with more outputs
         * than ORCHARD_SIGNER_MAX_ACTIONS cannot be safely displayed. */
        return signer_abort(ctx, SIGNER_ERR_TOO_MANY_ACTIONS);
    }
    if (action_len != ORCHARD_ACTION_TOTAL_SIZE) {
        return signer_abort(ctx, SIGNER_ERR_BAD_ACTION);
    }

    Zip244ActionsState *pool_state = signer_pool_state(ctx, pool);
    if (pool_state == NULL) {
        return signer_abort(ctx, SIGNER_ERR_BAD_POOL);
    }
    uint8_t note_version = signer_pool_note_version(pool);

    const uint8_t *d          = recipient;          /* 11 bytes */
    const uint8_t *pk_d       = recipient + 11;     /* 32 bytes */
    const uint8_t *rho        = action_data + ORCHARD_ACTION_OFFSET_NULLIFIER;
    const uint8_t *action_cmx = action_data + ORCHARD_ACTION_OFFSET_CMX;
    const uint8_t *action_epk = action_data + ORCHARD_ACTION_OFFSET_EPK;
    const uint8_t *action_enc = action_data + ORCHARD_ACTION_OFFSET_ENC;

    /* Step 1: recompute cmx from the claimed (d, pk_d, value, rseed) using
     * the action's nullifier as rho, and compare it constant-time against
     * the cmx field embedded in the action bytes. From here on recipient
     * and value are facts about the note, not claims. The note version
     * (and thus the rcm derivation) follows the action's pool. */
    uint8_t computed_cmx[32];
    orchard_compute_cmx(d, pk_d, value, rho, rseed, note_version, computed_cmx);
    int cmx_ok = ct_memequal(computed_cmx, action_cmx, 32);
    memzero(computed_cmx, sizeof(computed_cmx));
    if (!cmx_ok) {
        return signer_abort(ctx, SIGNER_ERR_NOTE_COMMITMENT_MISMATCH);
    }

    /* Step 2: the ciphertext, for every output — payment, own change or
     * zero-value padding. It binds the memo and proves the note can be
     * decrypted by whoever holds the recipient's key.
     *
     * Static storage for the 580 B recomputed ciphertext keeps the frame
     * within the 512 B per-function stack budget. Single-threaded signer =>
     * no re-entrancy. esk is derived internally from rseed + rho (shared by
     * ZIP-212 V2 and ZIP-2005 V3 notes); the plaintext lead byte follows
     * the pool's note version. */
    {
        static uint8_t computed_enc[ORCHARD_ACTION_ENC_SIZE];
        uint8_t computed_epk[32];
        int rc = orchard_compute_enc_ciphertext_from_rseed(
            d, pk_d, value, rseed, rho, memo, note_version,
            computed_enc, computed_epk);
        /* Both checks must pass before anything is committed to the action
         * stream; AND-accumulate so the timing shows only "both matched". */
        int enc_ok = ct_memequal(computed_enc, action_enc, ORCHARD_ACTION_ENC_SIZE);
        int epk_ok = ct_memequal(computed_epk, action_epk, 32);
        memzero(computed_enc, sizeof(computed_enc));
        memzero(computed_epk, sizeof(computed_epk));
        if (rc != 0) {
            /* pk_d is not a valid Pallas point. */
            return signer_abort(ctx, SIGNER_ERR_BAD_PK_D);
        }
        if (!(enc_ok & epk_ok)) {
            return signer_abort(ctx, SIGNER_ERR_MEMO_MISMATCH);
        }
    }

    /* Step 3: ownership, from the device's own keys. g_d is served from the
     * diversifier cache filled by the cmx recomputation above. */
    uint8_t ownership = signer_classify(ctx, recipient);

    /* Step 4: a memo the user has to read needs a slot. Empty memos were
     * verified above like any other but have nothing to show. A transaction
     * with more memos than slots cannot be fully reviewed and is rejected —
     * silently dropping one from review would reopen the gap step 2 closes. */
    uint8_t memo_slot = ORCHARD_SIGNER_MEMO_NONE;
    if (!orchard_signer_memo_is_empty(memo)) {
        if (ctx->memos_used >= ORCHARD_SIGNER_MAX_MEMOS) {
            return signer_abort(ctx, SIGNER_ERR_TOO_MANY_MEMOS);
        }
        memo_slot = ctx->memos_used;
    }

    /* Step 5: everything verified — hash the action. */
    if (!zip244_hash_action(pool_state, action_data, action_len)) {
        return signer_abort(ctx, SIGNER_ERR_BAD_ACTION);
    }

    /* Step 6: record it for the review loop. verify() later refuses to
     * advance unless every record is classified and confirmed. A zero-value
     * output with nothing to read needs no user decision and is confirmed
     * here; every output with a value waits for confirm_action(). */
    OrchardActionDisplay *disp = &ctx->actions_display[ctx->actions_received];
    memcpy(disp->recipient, recipient, 43);
    disp->value = value;
    disp->ownership = ownership;
    disp->enc_verified = 1;
    disp->memo_slot = memo_slot;
    disp->confirmed = (value == 0 && memo_slot == ORCHARD_SIGNER_MEMO_NONE);
    if (memo_slot != ORCHARD_SIGNER_MEMO_NONE) {
        memcpy(ctx->memo_pool[memo_slot], memo, 512);
        ctx->memos_used++;
    }

    ctx->actions_received++;

    /* Step 7: with the last action in, it is known which pools the
     * transaction really has. */
    if (ctx->actions_received == ctx->actions_expected &&
        !signer_empty_pools_neutral(ctx)) {
        return signer_abort(ctx, SIGNER_ERR_EMPTY_POOL_BALANCE);
    }
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_get_output(
    const OrchardSignerCtx *ctx,
    uint16_t idx,
    OrchardOutputInfo *out)
{
    if (out == NULL || idx >= ctx->actions_received ||
        idx >= ORCHARD_SIGNER_MAX_ACTIONS) {
        return SIGNER_ERR_INVALID_ACTION_INDEX;
    }
    const OrchardActionDisplay *disp = &ctx->actions_display[idx];
    memcpy(out->recipient, disp->recipient, 43);
    out->value = disp->value;
    out->ownership = (OrchardOutputOwnership)disp->ownership;
    out->has_memo = disp->memo_slot != ORCHARD_SIGNER_MEMO_NONE;
    out->memo = out->has_memo ? ORCHARD_MEMO_PRESENT : ORCHARD_MEMO_NONE;
    out->ciphertext_verified = disp->enc_verified != 0;
    out->review_required = (disp->value != 0) || out->has_memo;
    out->confirmed = disp->confirmed;
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
    bool present = disp->memo_slot != ORCHARD_SIGNER_MEMO_NONE;
    if (memo_out) {
        if (present) {
            memcpy(memo_out, ctx->memo_pool[disp->memo_slot], 512);
        } else {
            /* Nothing captured for this action: return the ZIP-302 empty
             * memo so callers that ignore present_out still see a
             * well-formed "no memo" plaintext. */
            memset(memo_out, 0, 512);
            memo_out[0] = 0xF6;
        }
    }
    if (present_out) *present_out = present;
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

/* fee = value_balance(Orchard) + value_balance(Ironwood) - t_out, computed
 * once and cached. There are no transparent inputs. A pool's value balance
 * enters only if the pool has actions — i.e. only if the sighash binds it —
 * and must be zero otherwise. Every step is range-checked: the companion
 * controls these inputs. On error the context has been reset. */
static OrchardSignerError signer_compute_fee(OrchardSignerCtx *ctx)
{
    if (ctx->fee_computed) {
        return SIGNER_OK;
    }
    if (!signer_empty_pools_neutral(ctx)) {
        return signer_abort(ctx, SIGNER_ERR_EMPTY_POOL_BALANCE);
    }
    if (ctx->transparent_state.t_out_overflow) {
        return signer_abort(ctx, SIGNER_ERR_FEE_OVERFLOW);
    }

    uint64_t t_out = ctx->transparent_begun ? ctx->transparent_state.t_out_total : 0;
    int64_t vb  = (ctx->actions_state.actions_hashed != 0)
                      ? ctx->tx_meta.value_balance : 0;
    int64_t ivb = (ctx->ironwood_actions_state.actions_hashed != 0)
                      ? ctx->tx_meta.ironwood_value_balance : 0;

    /* Both shielded pools contribute their net value balance to the
     * transparent value pool. Guard the sum against wraparound. */
    if ((ivb > 0 && vb > INT64_MAX - ivb) ||
        (ivb < 0 && vb < INT64_MIN - ivb)) {
        return signer_abort(ctx, SIGNER_ERR_FEE_OVERFLOW);
    }
    vb += ivb;

    if (t_out > (uint64_t)INT64_MAX) {
        return signer_abort(ctx, SIGNER_ERR_FEE_OVERFLOW);
    }
    /* vb - t_out with t_out in [0, INT64_MAX]: underflows only below
     * INT64_MIN. */
    if (vb < INT64_MIN + (int64_t)t_out) {
        return signer_abort(ctx, SIGNER_ERR_FEE_OVERFLOW);
    }
    int64_t fee_signed = vb - (int64_t)t_out;

    if (fee_signed < 0) {
        return signer_abort(ctx, SIGNER_ERR_FEE_NEGATIVE);
    }

    ctx->fee_zatoshis = (uint64_t)fee_signed;
    ctx->fee_computed = true;
    return SIGNER_OK;
}

/* *acc += v; false on uint64 overflow. */
static bool add_u64_checked(uint64_t *acc, uint64_t v)
{
    if (v > UINT64_MAX - *acc) return false;
    *acc += v;
    return true;
}

OrchardSignerError orchard_signer_get_totals(OrchardSignerCtx *ctx,
                                              OrchardSignerTotals *out)
{
    if (out == NULL || !ctx->has_meta ||
        (ctx->state != SIGNER_RECEIVING_ACTIONS && ctx->state != SIGNER_VERIFIED)) {
        return SIGNER_ERR_BAD_STATE;
    }
    /* The totals describe the whole transaction or nothing: every action
     * fed, and a transparent pass — if one was started — verified against
     * TxMeta. (State RECEIVING_ACTIONS already excludes "mid-pass".) */
    if (ctx->actions_received != ctx->actions_expected ||
        (ctx->transparent_begun && !ctx->transparent_verified)) {
        return SIGNER_ERR_BAD_STATE;
    }

    OrchardSignerError ferr = signer_compute_fee(ctx);
    if (ferr != SIGNER_OK) {
        return ferr;
    }

    memset(out, 0, sizeof(*out));
    out->fee = ctx->fee_zatoshis;
    if (ctx->transparent_begun) {
        out->transparent_out = ctx->transparent_state.t_out_total;
        out->n_transparent_out = ctx->transparent_state.outputs_received;
    }

    bool ok = true;
    for (uint16_t i = 0; i < ctx->actions_received; i++) {
        const OrchardActionDisplay *disp = &ctx->actions_display[i];
        if (disp->value == 0) {
            out->n_zero_value++;
            continue;
        }
        switch (disp->ownership) {
            case ORCHARD_OUTPUT_OWN_INTERNAL:
                ok &= add_u64_checked(&out->own_internal, disp->value);
                out->n_own_internal++;
                break;
            case ORCHARD_OUTPUT_OWN_EXTERNAL:
                ok &= add_u64_checked(&out->own_external, disp->value);
                out->n_own_external++;
                break;
            default:
                /* EXTERNAL — and anything unexpected counts as leaving. */
                ok &= add_u64_checked(&out->external_shielded, disp->value);
                out->n_external++;
                break;
        }
    }

    /* total leaving = external shielded + transparent out + fee */
    out->total_leaving = out->external_shielded;
    ok &= add_u64_checked(&out->total_leaving, out->transparent_out);
    ok &= add_u64_checked(&out->total_leaving, out->fee);

    if (!ok) {
        memset(out, 0, sizeof(*out));
        return signer_abort(ctx, SIGNER_ERR_VALUE_OVERFLOW);
    }
    return SIGNER_OK;
}

OrchardSignerError orchard_signer_confirm_totals(OrchardSignerCtx *ctx)
{
    if (!ctx->fee_computed || ctx->state != SIGNER_RECEIVING_ACTIONS ||
        ctx->actions_received != ctx->actions_expected) {
        /* Firmware must call get_totals() first, show them, then confirm.
         * Confirming without computing would be confirming nothing. */
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

    /* Ordering guard: every output that requires review must have been
     * confirmed through orchard_signer_confirm_action(), and sign() only
     * works in SIGNER_VERIFIED. This makes "review, then sign" the only
     * order this API offers; whether a screen was really shown before the
     * firmware called confirm_action() is outside the library's knowledge. */
    for (uint16_t i = 0; i < ctx->actions_received; i++) {
        /* Unreachable through this API (every record is written by the
         * feed function), kept as the invariant's last line: an
         * unclassified or unverified output never reaches VERIFIED. */
        if (ctx->actions_display[i].ownership == 0 ||
            ctx->actions_display[i].enc_verified != 1) {
            return SIGNER_ERR_BAD_STATE;
        }
        if (!ctx->actions_display[i].confirmed) {
            return SIGNER_ERR_ACTION_NOT_CONFIRMED;
        }
    }

    /* Same guard for the totals (fee and total leaving). */
    if (!ctx->fee_confirmed) {
        return SIGNER_ERR_FEE_NOT_CONFIRMED;
    }

    /* Everything the totals were computed from must be covered by the
     * sighash computed below. confirm_totals() implies get_totals(), which
     * already enforced this; checked again where the sighash is made. */
    if (!signer_empty_pools_neutral(ctx)) {
        return signer_abort(ctx, SIGNER_ERR_EMPTY_POOL_BALANCE);
    }

    /* The sighash mixes in tx_meta.transparent_sig_digest. Either the
     * transparent outputs were streamed and the digest recomputed from them
     * (transparent_verified), or there must be none: the digest has to be
     * the empty-bundle constant BLAKE2b("ZTxIdTranspaHash", ""). A host that
     * supplies anything else while skipping the transparent stream is
     * trying to bind an unreviewed transparent bundle to the signature. */
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

    /* Compute the full ZIP-244 v6 sighash from metadata + actions: the
     * five-leaf tree with the Ironwood pool digest; a pool with zero
     * streamed actions contributes its empty-bundle constant. */
    uint8_t computed[32];
    zip244_shielded_sighash_v6(&ctx->tx_meta, &ctx->actions_state,
                               &ctx->ironwood_actions_state, computed);

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
