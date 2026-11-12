/**
 * test_ownership — the signer against a host that lies.
 *
 * Every test drives the real state machine (orchard_signer.c) with real
 * actions (tests/test_tx_fixture.h) for a wallet whose keys and addresses
 * are orchard-crate vectors. What is checked:
 *
 *   H1  the device decides, from its own keys, whether an output is the
 *       wallet's change, one of its own addresses, or somebody else's —
 *       and the totals it reports follow from that decision;
 *   H2  an output that carries value cannot avoid the enc_ciphertext check
 *       by the host's choice of body, own or not;
 *   L4  the consensus branch ID is gated;
 *   and that no ordering of calls reaches SIGNER_VERIFIED around them.
 *
 * Built twice: with the library defaults and with FlipZcash's RAM tuning
 * (ORCHARD_SIGNER_MAX_ACTIONS=8, ORCHARD_SIGNER_MAX_MEMOS=4), where the
 * memo pool is smaller than the action table.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "hwp_dispatcher.h"
#include "test_tx_fixture.h"

#ifdef FLIPZ_TUNING
/* The budgets FlipZcash asserts next to its allocations
 * (views/flipz_scene_1.c). Checked here so a size regression fails in this
 * repository's test suite, not in the firmware build. */
_Static_assert(ORCHARD_SIGNER_MAX_ACTIONS == 8 && ORCHARD_SIGNER_MAX_MEMOS == 4 &&
                   HWP_MAX_PAYLOAD == 1536,
               "FLIPZ_TUNING build must carry FlipZcash's cdefines");
_Static_assert(sizeof(OrchardSignerCtx) <= 6 * 1024, "signer ctx over FlipZcash's 6 KB");
_Static_assert(sizeof(HwpDispatcher) <= 3 * 1024, "dispatcher over FlipZcash's 3 KB");
#endif

static int n_pass = 0;
#define PASS(msg)                  \
    do {                           \
        n_pass++;                  \
        printf("  PASS: %s\n", msg); \
    } while(0)

/* ── helpers ───────────────────────────────────────────────────────── */

static OrchardSignerCtx g_ctx; /* static: 5.8-11 KB, keep it off the stack */

static void open_session(OrchardSignerCtx* ctx, uint16_t n_actions, int64_t ironwood_vb) {
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, ironwood_vb);
    OrchardSignerFvk fvk = fx_wallet_fvk();
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), n_actions) == SIGNER_OK);
    assert(ctx->state == SIGNER_RECEIVING_ACTIONS);
    assert(!fx_ivks_wiped(ctx));
    /* The session keys are the crate's ivks for this wallet. */
    assert(memcmp(ctx->ivk_external, fx_wallet()->ivk_external, 32) == 0);
    assert(memcmp(ctx->ivk_internal, fx_wallet()->ivk_internal, 32) == 0);
}

/* Feed `note` truthfully, with its memo. */
static OrchardSignerError feed_full(OrchardSignerCtx* ctx, const FxNote* note, uint8_t tag) {
    uint8_t action[820];
    fx_build_action(action, note, tag);
    return orchard_signer_feed_action_with_note_and_memo(
        ctx, note->pool, action, sizeof(action), note->recipient, note->value,
        note->rseed, note->memo);
}

static OrchardOutputInfo output(const OrchardSignerCtx* ctx, uint16_t idx) {
    OrchardOutputInfo info;
    assert(orchard_signer_get_output(ctx, idx, &info) == SIGNER_OK);
    return info;
}

/* What a correct firmware does after the last action: show what needs
 * showing, confirm it, show and confirm the totals, verify. */
static OrchardSignerError review_all_and_verify(OrchardSignerCtx* ctx, OrchardSignerTotals* totals) {
    OrchardSignerError e = orchard_signer_get_totals(ctx, totals);
    if(e != SIGNER_OK) return e;
    for(uint16_t i = 0; i < ctx->actions_received; i++) {
        OrchardOutputInfo info = output(ctx, i);
        if(!info.review_required) {
            assert(info.confirmed); /* nothing to ask the user */
            continue;
        }
        assert(!info.confirmed);
        assert(orchard_signer_confirm_action(ctx, i) == SIGNER_OK);
    }
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_OK);
    uint8_t sighash[32];
    fx_sighash(ctx, sighash);
    return orchard_signer_verify(ctx, sighash);
}

static void assert_aborted(const OrchardSignerCtx* ctx) {
    assert(ctx->state == SIGNER_IDLE);
    assert(!ctx->has_meta);
    assert(ctx->actions_received == 0);
    assert(fx_ivks_wiped(ctx));
}

/* ── H1: ownership ─────────────────────────────────────────────────── */

static void test_send_with_change(void) {
    /* Spend 10 ZEC: 3 to a stranger (with a memo), 6.9999 back as change,
     * fee 0.0001. */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], change[43];
    fx_addr_foreign(to);
    fx_addr_change(change);
    FxNote pay = fx_note(to, 3 * FX_ZEC, "invoice 42", 1);
    FxNote chg = fx_note(change, 7 * FX_ZEC - 10000, NULL, 2);

    open_session(ctx, 2, 10000);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(feed_full(ctx, &chg, 2) == SIGNER_OK);

    OrchardOutputInfo o0 = output(ctx, 0), o1 = output(ctx, 1);
    assert(o0.ownership == ORCHARD_OUTPUT_EXTERNAL);
    assert(o0.value == 3 * FX_ZEC && o0.has_memo && o0.ciphertext_verified && o0.review_required);
    assert(memcmp(o0.recipient, to, 43) == 0);
    assert(o1.ownership == ORCHARD_OUTPUT_OWN_INTERNAL);
    assert(o1.value == 7 * FX_ZEC - 10000 && !o1.has_memo && o1.ciphertext_verified);
    assert(o1.review_required && !o1.confirmed); /* change has a value: never auto-approved */

    OrchardSignerTotals t;
    assert(review_all_and_verify(ctx, &t) == SIGNER_OK);
    assert(ctx->state == SIGNER_VERIFIED);
    assert(t.fee == 10000);
    assert(t.external_shielded == 3 * FX_ZEC);
    assert(t.own_internal == 7 * FX_ZEC - 10000 && t.own_external == 0);
    assert(t.total_leaving == 3 * FX_ZEC + 10000); /* change is not counted, in or out */
    assert(t.n_external == 1 && t.n_own_internal == 1 && t.n_own_external == 0 &&
           t.n_zero_value == 0 && t.n_transparent_out == 0);

    /* And it signs. */
    uint8_t sk[32], ask[32], nk[32], rivk[32], alpha[32] = {7}, sighash[32], sig[64], rk[32];
    orchard_derive_account_sk(fx_wallet()->seed, fx_wallet()->coin_type, 0, sk);
    orchard_derive_keys(sk, ask, nk, rivk);
    memcpy(sighash, ctx->verified_sighash, 32);
    assert(orchard_signer_sign(ctx, sighash, ask, alpha, sig, rk) == SIGNER_OK);

    /* The totals stay readable in VERIFIED (final confirmation screen). */
    OrchardSignerTotals t2;
    assert(orchard_signer_get_totals(ctx, &t2) == SIGNER_OK);
    assert(memcmp(&t, &t2, sizeof(t)) == 0);

    orchard_signer_reset(ctx);
    assert_aborted(ctx);
    PASS("send with change: payment EXTERNAL, change OWN_INTERNAL, leaving = payment + fee");
}

static void test_change_redirected(void) {
    /* The same transaction as far as the host's story goes — but the
     * "change" is addressed to the attacker. The device has no way to be
     * told otherwise: it is EXTERNAL and it is counted as leaving. */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], attacker[43];
    fx_addr_foreign(to);
    for(int variant = 0; variant < 2; variant++) {
        /* variant 0: attacker's receiving address; variant 1: the
         * attacker's own CHANGE address (internal scope of another key). */
        if(variant == 0) {
            fx_addr(attacker, ADDRESS_VECTORS[5].d, ADDRESS_VECTORS[5].pk_d);
        } else {
            fx_addr_foreign_change(attacker);
        }
        FxNote pay = fx_note(to, 3 * FX_ZEC, NULL, 1);
        FxNote chg = fx_note(attacker, 7 * FX_ZEC - 10000, NULL, 2);

        open_session(ctx, 2, 10000);
        assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
        assert(feed_full(ctx, &chg, 2) == SIGNER_OK);
        assert(output(ctx, 0).ownership == ORCHARD_OUTPUT_EXTERNAL);
        assert(output(ctx, 1).ownership == ORCHARD_OUTPUT_EXTERNAL);
        assert(output(ctx, 1).review_required);

        OrchardSignerTotals t;
        assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
        assert(t.n_external == 2 && t.n_own_internal == 0);
        assert(t.own_internal == 0);
        assert(t.external_shielded == 10 * FX_ZEC - 10000);
        assert(t.total_leaving == 10 * FX_ZEC); /* the whole note */
        orchard_signer_reset(ctx);
    }
    PASS("change redirected to a foreign address: EXTERNAL, whole amount shown as leaving");
}

static void test_own_external_addresses(void) {
    /* Paying one's own receiving addresses: the default one, one at a
     * non-default diversifier, and the pre-fix ("legacy") default. All are
     * the wallet's; none leaves it. */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t a0[43], a1[43], a2[43];
    fx_addr_own_default(a0);
    fx_addr_own_other(a1);
    fx_addr(a2, fx_wallet()->legacy_d, fx_wallet()->legacy_pk_d);
    assert(memcmp(a0, a1, 43) != 0 && memcmp(a0, a2, 43) != 0); /* odd-y wallet */
    FxNote n0 = fx_note(a0, 1 * FX_ZEC, NULL, 1);
    FxNote n1 = fx_note(a1, 2 * FX_ZEC, "to myself", 2);
    FxNote n2 = fx_note(a2, 3 * FX_ZEC, NULL, 3);

    open_session(ctx, 3, 15000);
    assert(feed_full(ctx, &n0, 1) == SIGNER_OK);
    assert(feed_full(ctx, &n1, 2) == SIGNER_OK);
    assert(feed_full(ctx, &n2, 3) == SIGNER_OK);
    for(uint16_t i = 0; i < 3; i++) {
        assert(output(ctx, i).ownership == ORCHARD_OUTPUT_OWN_EXTERNAL);
        assert(output(ctx, i).review_required);
    }
    OrchardSignerTotals t;
    assert(review_all_and_verify(ctx, &t) == SIGNER_OK);
    assert(t.n_own_external == 3 && t.n_external == 0 && t.n_own_internal == 0);
    assert(t.own_external == 6 * FX_ZEC);
    assert(t.external_shielded == 0);
    assert(t.total_leaving == 15000); /* only the fee leaves */
    orchard_signer_reset(ctx);
    PASS("own receiving addresses (default, non-default diversifier, legacy): OWN_EXTERNAL");
}

static void test_wrong_fvk_fails_safe(void) {
    /* A firmware that passes the wrong viewing key (here: nk and rivk
     * swapped) does not get its change mislabelled as its own... it gets
     * it labelled EXTERNAL. Misuse errs on the alarming side. */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE], change[43];
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, 10000);
    OrchardSignerFvk bad = {.ak = fx_wallet()->ak, .nk = fx_wallet()->rivk, .rivk = fx_wallet()->nk};
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &bad, meta, sizeof(meta), 1) == SIGNER_OK);
    fx_addr_change(change);
    FxNote chg = fx_note(change, FX_ZEC, NULL, 1);
    assert(feed_full(ctx, &chg, 1) == SIGNER_OK);
    assert(output(ctx, 0).ownership == ORCHARD_OUTPUT_EXTERNAL);
    orchard_signer_reset(ctx);

    /* No key at all: no session. */
    OrchardSignerFvk none = {.ak = fx_wallet()->ak, .nk = NULL, .rivk = fx_wallet()->rivk};
    assert(orchard_signer_feed_meta(ctx, NULL, meta, sizeof(meta), 1) == SIGNER_ERR_BAD_FVK);
    assert(orchard_signer_feed_meta(ctx, &none, meta, sizeof(meta), 1) == SIGNER_ERR_BAD_FVK);
    assert_aborted(ctx);
    PASS("wrong FVK -> outputs EXTERNAL (fail-safe); missing FVK -> BAD_FVK, no session");
}

/* ── zero-value outputs ────────────────────────────────────────────── */

static void test_zero_value_outputs(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], random_addr[43], change[43];
    fx_addr_foreign(to);
    fx_addr(random_addr, ADDRESS_VECTORS[7].d, ADDRESS_VECTORS[7].pk_d);
    fx_addr_change(change);

    FxNote pay = fx_note(to, 5 * FX_ZEC, NULL, 1);
    /* 1: padding with the ZIP-302 "no memo" encoding. */
    FxNote dummy_compact = fx_note(random_addr, 0, NULL, 2);
    /* 2: padding sent with its memo; the orchard builder's dummy memo is
     *    512 zero bytes, which is "empty" too. */
    FxNote dummy_full = fx_note(random_addr, 0, NULL, 3);
    memset(dummy_full.memo, 0, 512);
    /* 3: a zero-value output that carries a text: a message. */
    FxNote message = fx_note(to, 0, "hello", 4);
    /* 4: 0xF6 followed by data is NOT an empty memo. */
    FxNote sneaky = fx_note(to, 0, NULL, 5);
    sneaky.memo[200] = 0x41;
    /* 5: zero-value output to the wallet itself. */
    FxNote own_zero = fx_note(change, 0, NULL, 6);

    open_session(ctx, 6, 10000);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(feed_full(ctx, &dummy_compact, 2) == SIGNER_OK);
    assert(feed_full(ctx, &dummy_full, 3) == SIGNER_OK);
    assert(feed_full(ctx, &message, 4) == SIGNER_OK);
    assert(feed_full(ctx, &sneaky, 5) == SIGNER_OK);
    assert(feed_full(ctx, &own_zero, 6) == SIGNER_OK);

    OrchardOutputInfo o;
    o = output(ctx, 1); /* padding, 0xF6 memo */
    assert(o.value == 0 && o.ownership == ORCHARD_OUTPUT_EXTERNAL);
    assert(!o.review_required && o.confirmed && !o.has_memo && o.ciphertext_verified);
    assert(o.memo == ORCHARD_MEMO_NONE);
    o = output(ctx, 2); /* padding with all-zero memo */
    assert(!o.review_required && o.confirmed && !o.has_memo && o.ciphertext_verified);
    o = output(ctx, 3); /* message */
    assert(o.value == 0 && o.review_required && !o.confirmed && o.has_memo);
    assert(o.memo == ORCHARD_MEMO_PRESENT);
    o = output(ctx, 4); /* 0xF6 + data */
    assert(o.review_required && !o.confirmed && o.has_memo);
    o = output(ctx, 5); /* own zero */
    assert(o.ownership == ORCHARD_OUTPUT_OWN_INTERNAL && !o.review_required && o.confirmed);
    assert(ctx->memos_used == 2);

    /* The memo the user will be shown is the one that was verified. */
    uint8_t memo[512];
    bool present = false;
    assert(orchard_signer_get_action_memo(ctx, 3, memo, &present) == SIGNER_OK && present);
    assert(memcmp(memo, message.memo, 512) == 0);
    assert(orchard_signer_get_action_memo(ctx, 1, memo, &present) == SIGNER_OK && !present);

    /* Not confirming the message blocks the signature: a zero value does
     * not make an output with something to read auto-approved. */
    OrchardSignerTotals t;
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(orchard_signer_confirm_action(ctx, 0) == SIGNER_OK);
    assert(orchard_signer_confirm_action(ctx, 4) == SIGNER_OK);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_OK);
    uint8_t sighash[32];
    fx_sighash(ctx, sighash);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_ERR_ACTION_NOT_CONFIRMED);
    assert(orchard_signer_confirm_action(ctx, 3) == SIGNER_OK);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_OK);

    assert(t.n_zero_value == 5 && t.n_external == 1 && t.n_own_internal == 0);
    assert(t.external_shielded == 5 * FX_ZEC && t.total_leaving == 5 * FX_ZEC + 10000);
    orchard_signer_reset(ctx);

    assert(orchard_signer_memo_is_empty(dummy_full.memo));
    assert(orchard_signer_memo_is_empty(pay.memo));
    assert(!orchard_signer_memo_is_empty(sneaky.memo));
    assert(!orchard_signer_memo_is_empty(message.memo));
    PASS("zero-value outputs: padding needs no review and is counted; a memo always does");
}

static void test_value_never_auto_approved(void) {
    /* The smallest value there is, to the wallet's own change address,
     * with no memo: still waits for the user. */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t change[43];
    fx_addr_change(change);
    FxNote one = fx_note(change, 1, NULL, 1);
    open_session(ctx, 1, 0);
    assert(feed_full(ctx, &one, 1) == SIGNER_OK);
    assert(output(ctx, 0).review_required && !output(ctx, 0).confirmed);
    OrchardSignerTotals t;
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_OK);
    uint8_t sighash[32];
    fx_sighash(ctx, sighash);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_ERR_ACTION_NOT_CONFIRMED);
    orchard_signer_reset(ctx);
    PASS("1 zatoshi of own change still requires confirmation");
}

/* ── H2: the ciphertext is not optional ────────────────────────────── */

static void test_no_hidden_memo_on_padding(void) {
    /* Reviewer item: "zero-value compact outputs can carry an unverified
     * memo to any address with no screen". There is no compact entry point
     * any more; what is left to try is to DECLARE an empty memo for a
     * zero-value output whose ciphertext carries a message. */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], change[43];
    fx_addr_foreign(to);
    fx_addr_change(change);

    FxNote hidden = fx_note(to, 0, "wire the rest to ...", 1);
    uint8_t action[820], empty[512];
    fx_build_action(action, &hidden, 1);
    fx_memo_none(empty);
    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, hidden.pool, action, sizeof(action), hidden.recipient, 0,
               hidden.rseed, empty) == SIGNER_ERR_MEMO_MISMATCH);
    assert_aborted(ctx);
    memset(empty, 0, 512);
    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, hidden.pool, action, sizeof(action), hidden.recipient, 0,
               hidden.rseed, empty) == SIGNER_ERR_MEMO_MISMATCH);
    assert_aborted(ctx);

    /* A zero-value output with random bytes for a ciphertext (not an
     * encryption of its note) is refused as well, to the wallet or not. */
    FxNote pad = fx_note(change, 0, NULL, 2);
    fx_build_action(action, &pad, 2);
    action[160 + 300] ^= 0x01;
    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, pad.pool, action, sizeof(action), pad.recipient, 0, pad.rseed,
               pad.memo) == SIGNER_ERR_MEMO_MISMATCH);
    assert_aborted(ctx);

    /* NULL arguments end the session instead of crashing. */
    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, pad.pool, action, sizeof(action), pad.recipient, 0, pad.rseed,
               NULL) == SIGNER_ERR_BAD_ACTION);
    assert_aborted(ctx);
    PASS("zero-value output: a memo cannot be hidden, the ciphertext is always verified");
}

static void test_memo_substitution(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43];
    fx_addr_foreign(to);
    /* On chain: the attacker's deposit tag. Declared to the device: the
     * user's. */
    FxNote onchain = fx_note(to, 3 * FX_ZEC, "tag: ATTACKER", 1);
    FxNote declared = onchain;
    fx_memo_text(declared.memo, "tag: USER");
    uint8_t action[820];
    fx_build_action(action, &onchain, 1);

    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, onchain.pool, action, sizeof(action), declared.recipient,
               declared.value, declared.rseed, declared.memo) == SIGNER_ERR_MEMO_MISMATCH);
    assert_aborted(ctx);

    /* Declared as "no memo" instead: same answer. */
    fx_memo_none(declared.memo);
    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, onchain.pool, action, sizeof(action), declared.recipient,
               declared.value, declared.rseed, declared.memo) == SIGNER_ERR_MEMO_MISMATCH);
    assert_aborted(ctx);

    /* A substituted ephemeral key (the recipient could not decrypt). */
    fx_build_action(action, &onchain, 1);
    action[128] ^= 0x01;
    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, onchain.pool, action, sizeof(action), onchain.recipient, onchain.value,
               onchain.rseed, onchain.memo) == SIGNER_ERR_MEMO_MISMATCH);
    assert_aborted(ctx);
    PASS("memo / epk substituted on a payment -> MEMO_MISMATCH");
}

static void test_wrong_ciphertext_on_own_change(void) {
    /* The change note is real (cmx commits to the wallet's own address),
     * but its ciphertext is garbage: on chain the wallet would never find
     * it. With the memo-carrying body the device notices; without it the
     * device refuses (test_compact_body_rules). */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t change[43];
    fx_addr_change(change);
    FxNote chg = fx_note(change, 7 * FX_ZEC, NULL, 1);
    uint8_t action[820];
    for(int where = 0; where < 3; where++) {
        fx_build_action(action, &chg, 1);
        /* 0: first byte of the note plaintext part; 1: memo part; 2: tag */
        action[160 + (where == 0 ? 0 : where == 1 ? 300 : 579)] ^= 0x80;
        open_session(ctx, 1, 0);
        assert(orchard_signer_feed_action_with_note_and_memo(
                   ctx, chg.pool, action, sizeof(action), chg.recipient, chg.value, chg.rseed,
                   chg.memo) == SIGNER_ERR_MEMO_MISMATCH);
        assert_aborted(ctx);
    }
    PASS("corrupted ciphertext on own change -> MEMO_MISMATCH (note stays recoverable or no signature)");
}

/* ── limits ────────────────────────────────────────────────────────── */

static void test_limits_fail_closed(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], change[43];
    fx_addr_foreign(to);
    fx_addr_change(change);
    OrchardSignerFvk fvk = fx_wallet_fvk();
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, 0);

    /* More actions than the device can show: refused before any work. */
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta),
                                    ORCHARD_SIGNER_MAX_ACTIONS + 1) == SIGNER_ERR_TOO_MANY_ACTIONS);
    assert_aborted(ctx);

    /* One action more than announced. */
    FxNote n = fx_note(change, FX_ZEC, NULL, 1);
    open_session(ctx, 1, 0);
    assert(feed_full(ctx, &n, 1) == SIGNER_OK);
    assert(feed_full(ctx, &n, 2) == SIGNER_ERR_BAD_STATE);
    assert_aborted(ctx);

    /* A full table of verified outputs, of which exactly MAX_MEMOS carry a
     * memo: fine — the pool bounds what must be READ, not what is
     * verified. */
    open_session(ctx, ORCHARD_SIGNER_MAX_ACTIONS, 0);
    for(int i = 0; i < ORCHARD_SIGNER_MAX_ACTIONS; i++) {
        FxNote o = fx_note(to, 1000 + (uint64_t)i,
                           i < ORCHARD_SIGNER_MAX_MEMOS ? "memo" : NULL, (uint8_t)(i + 1));
        assert(feed_full(ctx, &o, (uint8_t)(i + 1)) == SIGNER_OK);
        assert(output(ctx, (uint16_t)i).ciphertext_verified);
    }
    assert(ctx->memos_used == ORCHARD_SIGNER_MAX_MEMOS);
    assert(ctx->actions_received == ORCHARD_SIGNER_MAX_ACTIONS);
    OrchardSignerTotals t;
    assert(review_all_and_verify(ctx, &t) == SIGNER_OK);
    assert(t.n_external == ORCHARD_SIGNER_MAX_ACTIONS);
    orchard_signer_reset(ctx);
    PASS("limits: too many actions / surplus action rejected; full table verifies");

#if ORCHARD_SIGNER_MAX_MEMOS < ORCHARD_SIGNER_MAX_ACTIONS
    /* One memo more than the pool holds: the session ends, with its own
     * error — the extra memo is not dropped from review. */
    open_session(ctx, ORCHARD_SIGNER_MAX_MEMOS + 1, 0);
    for(int i = 0; i < ORCHARD_SIGNER_MAX_MEMOS; i++) {
        FxNote o = fx_note(to, 1000, "memo", (uint8_t)(i + 1));
        assert(feed_full(ctx, &o, (uint8_t)(i + 1)) == SIGNER_OK);
    }
    FxNote extra = fx_note(to, 1000, "one too many", 99);
    assert(feed_full(ctx, &extra, 99) == SIGNER_ERR_TOO_MANY_MEMOS);
    assert_aborted(ctx);
    PASS("limits: memo pool exhausted -> TOO_MANY_MEMOS (distinct), session reset");
#else
    printf("  SKIP: memo pool == action table in this build (covered by the FlipZcash-tuned build)\n");
#endif
}

/* ── ordering ──────────────────────────────────────────────────────── */

static void test_ordering(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], change[43];
    fx_addr_foreign(to);
    fx_addr_change(change);
    FxNote pay = fx_note(to, 3 * FX_ZEC, NULL, 1);
    FxNote chg = fx_note(change, 7 * FX_ZEC, NULL, 2);
    OrchardSignerFvk fvk = fx_wallet_fvk();
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE], sighash[32];
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, 0);
    OrchardSignerTotals t;

    /* Nothing before the metadata. */
    orchard_signer_init(ctx, 1);
    assert(feed_full(ctx, &pay, 1) == SIGNER_ERR_BAD_STATE);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_BAD_STATE);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_ERR_BAD_STATE);
    assert(orchard_signer_verify(ctx, meta) == SIGNER_ERR_BAD_STATE);

    /* Metadata twice. */
    open_session(ctx, 2, 0);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_ERR_BAD_STATE);

    /* Totals / verify with an action still missing. */
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_BAD_STATE);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_ERR_BAD_STATE);
    fx_sighash(ctx, sighash);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_ERR_BAD_STATE);
    assert(ctx->state == SIGNER_RECEIVING_ACTIONS);

    /* Complete; confirm before anything was computed. */
    assert(feed_full(ctx, &chg, 2) == SIGNER_OK);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_ERR_BAD_STATE);
    fx_sighash(ctx, sighash);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_ERR_ACTION_NOT_CONFIRMED);
    assert(orchard_signer_confirm_action(ctx, 0) == SIGNER_OK);
    assert(orchard_signer_confirm_action(ctx, 1) == SIGNER_OK);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_ERR_FEE_NOT_CONFIRMED);
    assert(ctx->state == SIGNER_RECEIVING_ACTIONS);

    /* Once the totals exist, the transparent side cannot be (re)opened. */
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(orchard_signer_begin_transparent(ctx, 0, 1) == SIGNER_ERR_BAD_STATE);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_OK);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_OK);

    /* In VERIFIED: a stray action ends the session; so nothing can be
     * appended to what the user approved. */
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_ERR_BAD_STATE);
    assert(feed_full(ctx, &pay, 3) == SIGNER_ERR_BAD_STATE);
    assert_aborted(ctx);

    /* The same action twice in a row is two outputs to review, not one
     * approval covering both. */
    open_session(ctx, 2, 0);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(t.n_external == 2 && t.external_shielded == 6 * FX_ZEC);
    assert(orchard_signer_confirm_action(ctx, 0) == SIGNER_OK);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_OK);
    fx_sighash(ctx, sighash);
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_ERR_ACTION_NOT_CONFIRMED);
    orchard_signer_reset(ctx);

    /* An action arriving after the totals were computed. */
    open_session(ctx, 2, 0);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(feed_full(ctx, &chg, 2) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(feed_full(ctx, &pay, 3) == SIGNER_ERR_BAD_STATE);
    assert_aborted(ctx);

    /* Transparent pass: once only. */
    open_session(ctx, 1, 0);
    assert(orchard_signer_begin_transparent(ctx, 0, 1) == SIGNER_OK);
    assert(orchard_signer_begin_transparent(ctx, 0, 1) == SIGNER_ERR_BAD_STATE);
    /* Mid-pass: no action, no totals. */
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_BAD_STATE);
    assert(feed_full(ctx, &pay, 1) == SIGNER_ERR_BAD_STATE);
    assert_aborted(ctx);
    PASS("ordering: no path to VERIFIED around review, totals or a complete action set");
}

/* ── L4: consensus branch allow-list ───────────────────────────────── */

static void test_branch_allow_list(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    OrchardSignerFvk fvk = fx_wallet_fvk();
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    static const uint32_t refused[] = {FX_BRANCH_NU6, 0x4DEC4DF0u /* NU6.1 */, 0, 0xFFFFFFFFu,
                                       FX_BRANCH_NU6_3 ^ 1u};
    for(size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        fx_build_meta(meta, refused[i], 0, 0);
        orchard_signer_init(ctx, 1);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) ==
               SIGNER_ERR_BRANCH_NOT_ALLOWED);
        assert_aborted(ctx);
    }
    static const uint32_t accepted[] = {FX_BRANCH_NU6_3, FX_BRANCH_NU7};
    for(size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        fx_build_meta(meta, accepted[i], 0, 0);
        orchard_signer_init(ctx, 1);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
        assert(ctx->tx_meta.consensus_branch_id == accepted[i]);
        orchard_signer_reset(ctx);
    }
    /* The v6 header constants stay mandatory under either branch. */
    fx_build_meta(meta, FX_BRANCH_NU7, 0, 0);
    meta[0] = 0x05; /* v5 header */
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) == SIGNER_ERR_BAD_META);
    PASS("branch allow-list: NU6.3 and NU7 accepted, everything else BRANCH_NOT_ALLOWED");
}

/* ── totals arithmetic ─────────────────────────────────────────────── */

/* The sealed-pool spend-paired dummy: the only output whose ciphertext
 * may differ from the recomputed one. */
static OrchardSignerError feed_tampered(OrchardSignerCtx* ctx, const FxNote* note, uint8_t tag,
                                        int enc_off, int epk_off) {
    uint8_t action[820];
    fx_build_action(action, note, tag);
    /* action layout: cv[32] nf[32] rk[32] cmx[32] epk[32] enc[580] out[80] */
    if(enc_off >= 0) action[160 + enc_off] ^= 0x5A;
    if(epk_off >= 0) action[128 + epk_off] ^= 0x01;
    return orchard_signer_feed_action_with_note_and_memo(
        ctx, note->pool, action, sizeof(action), note->recipient, note->value,
        note->rseed, note->memo);
}

static void test_sealed_pool_spend_dummy(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], change[43], own[43];
    fx_addr_foreign(to);
    fx_addr_change(change);
    fx_addr_own_default(own);

    /* Accepted: sealed Orchard pool, value 0, own address (external or
     * internal), expected epk, no memo, ciphertext not the recomputed one. */
    const uint8_t* mine[2] = {own, change};
    for(int w = 0; w < 2; w++) {
        FxNote dmy = fx_note(mine[w], 0, NULL, (uint8_t)(60 + w));
        dmy.pool = ZIP244_POOL_ORCHARD;
        open_session(ctx, 1, 0);
        assert(feed_tampered(ctx, &dmy, (uint8_t)(60 + w), 17, -1) == SIGNER_OK);
        OrchardOutputInfo info = output(ctx, 0);
        assert(info.value == 0 && !info.review_required && !info.ciphertext_verified);
        assert(info.ownership != ORCHARD_OUTPUT_EXTERNAL && info.memo == ORCHARD_MEMO_NONE);
        orchard_signer_reset(ctx);
    }

    /* Refused, one condition removed at a time. */
    {
        /* a foreign recipient */
        FxNote x = fx_note(to, 0, NULL, 70);
        x.pool = ZIP244_POOL_ORCHARD;
        open_session(ctx, 1, 0);
        assert(feed_tampered(ctx, &x, 70, 17, -1) == SIGNER_ERR_MEMO_MISMATCH);
        assert_aborted(ctx);
        /* the Ironwood pool */
        FxNote y = fx_note(own, 0, NULL, 71);
        open_session(ctx, 1, 0);
        assert(feed_tampered(ctx, &y, 71, 17, -1) == SIGNER_ERR_MEMO_MISMATCH);
        assert_aborted(ctx);
        /* a value */
        FxNote z = fx_note(own, 1, NULL, 72);
        z.pool = ZIP244_POOL_ORCHARD;
        open_session(ctx, 1, 0);
        assert(feed_tampered(ctx, &z, 72, 17, -1) == SIGNER_ERR_MEMO_MISMATCH);
        assert_aborted(ctx);
        /* a different epk */
        FxNote e = fx_note(own, 0, NULL, 73);
        e.pool = ZIP244_POOL_ORCHARD;
        open_session(ctx, 1, 0);
        assert(feed_tampered(ctx, &e, 73, 17, 3) == SIGNER_ERR_MEMO_MISMATCH);
        assert_aborted(ctx);
        open_session(ctx, 1, 0);
        assert(feed_tampered(ctx, &e, 73, -1, 3) == SIGNER_ERR_MEMO_MISMATCH);
        assert_aborted(ctx);
        /* a declared memo */
        FxNote m = fx_note(own, 0, "hello", 74);
        m.pool = ZIP244_POOL_ORCHARD;
        open_session(ctx, 1, 0);
        assert(feed_tampered(ctx, &m, 74, 17, -1) == SIGNER_ERR_MEMO_MISMATCH);
        assert_aborted(ctx);
    }

    /* An untampered zero-value own output in the sealed pool is still an
     * ordinary verified output. */
    FxNote ok = fx_note(own, 0, NULL, 75);
    ok.pool = ZIP244_POOL_ORCHARD;
    open_session(ctx, 1, 0);
    assert(feed_full(ctx, &ok, 75) == SIGNER_OK);
    assert(output(ctx, 0).ciphertext_verified);
    orchard_signer_reset(ctx);
    PASS("sealed-pool spend dummy: randomized ciphertext tolerated only for zero value, own address, real epk, no memo");
}

static void test_totals_overflow(void) {
    /* 21,000,000 coins in zatoshi: nothing larger can exist on chain, and
     * nothing larger may reach a UI callback. */
    const uint64_t MAXM = 2100000000000000ull;
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43], change[43], own[43];
    fx_addr_foreign(to);
    fx_addr_change(change);
    fx_addr_own_default(own);
    OrchardSignerTotals t;

    /* A single output above the supply is refused when it is fed, whoever
     * it pays: external, change, own address. */
    {
        const uint8_t* who[3] = {to, change, own};
        const uint64_t vals[3] = {MAXM + 1, 5000000000000000000ull, UINT64_MAX};
        uint8_t seed = 40;
        for(int w = 0; w < 3; w++) {
            for(int v = 0; v < 3; v++) {
                FxNote x = fx_note(who[w], vals[v], NULL, seed);
                open_session(ctx, 1, 0);
                assert(feed_full(ctx, &x, seed) == SIGNER_ERR_VALUE_OVERFLOW);
                assert_aborted(ctx);
                seed++;
            }
        }
    }

    /* The boundary itself is fine. */
    FxNote e = fx_note(to, MAXM, NULL, 4);
    open_session(ctx, 1, 0);
    assert(feed_full(ctx, &e, 4) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(t.total_leaving == MAXM && t.fee == 0);
    orchard_signer_reset(ctx);

    /* Two external outputs, each legal, whose sum is not. */
    FxNote a = fx_note(to, MAXM - 5, NULL, 1);
    FxNote b = fx_note(to, 6, NULL, 2);
    open_session(ctx, 2, 0);
    assert(feed_full(ctx, &a, 1) == SIGNER_OK);
    assert(feed_full(ctx, &b, 2) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_VALUE_OVERFLOW);
    assert(t.total_leaving == 0);
    assert_aborted(ctx);

    /* External sum fits, external + fee does not. */
    FxNote c = fx_note(to, MAXM - 9999, NULL, 3);
    open_session(ctx, 1, 10000);
    assert(feed_full(ctx, &c, 3) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_VALUE_OVERFLOW);
    assert_aborted(ctx);
    FxNote c2 = fx_note(to, MAXM - 10000, NULL, 13);
    open_session(ctx, 1, 10000);
    assert(feed_full(ctx, &c2, 13) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(t.total_leaving == MAXM && t.fee == 10000);
    orchard_signer_reset(ctx);

    /* Own outputs are reported, so their sums are checked too. */
    FxNote f = fx_note(change, MAXM, NULL, 5);
    FxNote g = fx_note(change, 1, NULL, 6);
    open_session(ctx, 2, 0);
    assert(feed_full(ctx, &f, 5) == SIGNER_OK);
    assert(feed_full(ctx, &g, 6) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_VALUE_OVERFLOW);
    assert_aborted(ctx);
    FxNote h = fx_note(own, MAXM, NULL, 7);
    FxNote k = fx_note(own, 1, NULL, 8);
    open_session(ctx, 2, 0);
    assert(feed_full(ctx, &h, 7) == SIGNER_OK);
    assert(feed_full(ctx, &k, 8) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_VALUE_OVERFLOW);
    assert_aborted(ctx);

    /* A large own output next to a large external one is NOT an overflow:
     * the two are never added together. */
    FxNote m = fx_note(change, MAXM, NULL, 9);
    FxNote n = fx_note(to, MAXM - 1, NULL, 10);
    open_session(ctx, 2, 1);
    assert(feed_full(ctx, &m, 9) == SIGNER_OK);
    assert(feed_full(ctx, &n, 10) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(t.own_internal == MAXM && t.total_leaving == MAXM);
    orchard_signer_reset(ctx);

    {
        uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
        OrchardSignerFvk fvk = fx_wallet_fvk();
        FxNote z = fx_note(change, 1, NULL, 11);
        FxNote zo = fx_note(change, 2, NULL, 12);
        zo.pool = ZIP244_POOL_ORCHARD;

        /* A value balance beyond the supply, in either direction and in
         * either pool, is refused with the TxMeta. */
        const int64_t bad[4] = {INT64_MAX, INT64_MIN, (int64_t)MAXM + 1, -(int64_t)MAXM - 1};
        for(int i = 0; i < 4; i++) {
            fx_build_meta(meta, FX_BRANCH_NU6_3, bad[i], 1);
            orchard_signer_init(ctx, 1);
            assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) ==
                   SIGNER_ERR_VALUE_OVERFLOW);
            fx_build_meta(meta, FX_BRANCH_NU6_3, 1, bad[i]);
            orchard_signer_init(ctx, 1);
            assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) ==
                   SIGNER_ERR_VALUE_OVERFLOW);
        }

        /* Two legal balances whose sum is a fee above the supply. */
        fx_build_meta(meta, FX_BRANCH_NU6_3, (int64_t)MAXM, 1);
        orchard_signer_init(ctx, 1);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_OK);
        assert(feed_full(ctx, &z, 11) == SIGNER_OK);
        assert(feed_full(ctx, &zo, 12) == SIGNER_OK);
        assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_VALUE_OVERFLOW);
        assert_aborted(ctx);

        /* Both pools contribute to the fee. */
        fx_build_meta(meta, FX_BRANCH_NU6_3, 7000, 3000);
        orchard_signer_init(ctx, 1);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_OK);
        assert(feed_full(ctx, &z, 11) == SIGNER_OK);
        assert(feed_full(ctx, &zo, 12) == SIGNER_OK);
        assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
        assert(t.fee == 10000 && t.total_leaving == 10000 && t.own_internal == 3);
        orchard_signer_reset(ctx);

        /* Negative fee. */
        fx_build_meta(meta, FX_BRANCH_NU6_3, 0, -1);
        orchard_signer_init(ctx, 1);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
        assert(feed_full(ctx, &z, 11) == SIGNER_OK);
        assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_FEE_NEGATIVE);
        assert_aborted(ctx);
    }
    PASS("totals: nothing above MAX_MONEY is accepted or reported; sums checked; boundary exact");
}

static void test_totals_with_transparent(void) {
    /* Shielded -> transparent: 4 ZEC to a t-address, 2 ZEC shielded to a
     * stranger, 3.9999 change, fee 0.0001. The transparent output always
     * counts as leaving. */
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t t_out[8 + 2 + 25];
    uint64_t t_value = 4 * FX_ZEC;
    for(int i = 0; i < 8; i++) t_out[i] = (uint8_t)(t_value >> (8 * i));
    t_out[8] = 25; t_out[9] = 0;
    static const uint8_t p2pkh_head[3] = {0x76, 0xA9, 0x14};
    memcpy(t_out + 10, p2pkh_head, 3);
    for(int i = 0; i < 20; i++) t_out[13 + i] = (uint8_t)(0x30 + i);
    t_out[33] = 0x88; t_out[34] = 0xAC;

    /* The transparent digest the TxMeta must carry. */
    Zip244TransparentState ts;
    uint8_t t_digest[32];
    zip244_transparent_init(&ts);
    assert(zip244_hash_transparent_output(&ts, t_out, sizeof(t_out)));
    zip244_transparent_digest(&ts, t_digest);

    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, (int64_t)(4 * FX_ZEC + 10000));
    memcpy(meta + 102, t_digest, 32);
    OrchardSignerFvk fvk = fx_wallet_fvk();
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_OK);

    assert(orchard_signer_begin_transparent(ctx, 0, 1) == SIGNER_OK);
    assert(orchard_signer_feed_transparent_output(ctx, t_out, sizeof(t_out)) == SIGNER_OK);
    assert(orchard_signer_verify_transparent(ctx, t_digest) == SIGNER_OK);

    uint8_t to[43], change[43];
    fx_addr_foreign(to);
    fx_addr_change(change);
    FxNote pay = fx_note(to, 2 * FX_ZEC, NULL, 1);
    FxNote chg = fx_note(change, 4 * FX_ZEC - 10000, NULL, 2);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(feed_full(ctx, &chg, 2) == SIGNER_OK);

    OrchardSignerTotals t;
    assert(review_all_and_verify(ctx, &t) == SIGNER_OK);
    assert(t.fee == 10000);
    assert(t.transparent_out == 4 * FX_ZEC && t.n_transparent_out == 1);
    assert(t.external_shielded == 2 * FX_ZEC);
    assert(t.own_internal == 4 * FX_ZEC - 10000);
    assert(t.total_leaving == 6 * FX_ZEC + 10000);
    orchard_signer_reset(ctx);

    /* A non-empty transparent digest with the transparent pass skipped is
     * caught at verify(): the user's approval of totals without those
     * outputs does not produce a signature. */
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_OK);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(feed_full(ctx, &chg, 2) == SIGNER_OK);
    /* (fee = vb here, there is no t_out to subtract; the totals are wrong
     * and the transaction cannot be signed) */
    assert(review_all_and_verify(ctx, &t) == SIGNER_ERR_TRANSPARENT_NOT_EMPTY);
    assert_aborted(ctx);
    PASS("transparent outputs always counted as leaving; skipped transparent pass cannot be signed");
}

/* ── November 2026 review: fields the sighash does not bind ─────────── */

static void test_unbound_value_balance(void) {
    /* F1. The value balance of a pool with no action is not covered by the
     * sighash (the pool's leaf is the empty-bundle constant). It must be
     * zero, or the fee on the screen would be the host's choice. */
    OrchardSignerCtx* ctx = &g_ctx;
    OrchardSignerFvk fvk = fx_wallet_fvk();
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE], to[43], change[43];
    fx_addr_foreign(to);
    fx_addr_change(change);
    FxNote pay = fx_note(to, 3 * FX_ZEC, NULL, 1);       /* Ironwood */
    FxNote chg = fx_note(change, 2 * FX_ZEC, NULL, 2);   /* Ironwood */
    const int64_t real = 5 * (int64_t)FX_ZEC;

    /* The sighash really is blind to it. */
    uint8_t h0[32], h1[32];
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, real);
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_OK);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK && feed_full(ctx, &chg, 2) == SIGNER_OK);
    fx_sighash(ctx, h0);
    ctx->tx_meta.value_balance = -(real - 10000);  /* poke the context directly */
    ctx->tx_meta.orchard_flags = 0;
    fx_sighash(ctx, h1);
    assert(memcmp(h0, h1, 32) == 0);
    /* ... which is why every later stage refuses the poked context too:
     * totals, and verify() even with the confirmations forced. */
    OrchardSignerTotals t;
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_ERR_EMPTY_POOL_BALANCE);
    assert_aborted(ctx);
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_OK);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK && feed_full(ctx, &chg, 2) == SIGNER_OK);
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK && t.fee == (uint64_t)real);
    assert(orchard_signer_confirm_action(ctx, 0) == SIGNER_OK);
    assert(orchard_signer_confirm_action(ctx, 1) == SIGNER_OK);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_OK);
    ctx->tx_meta.value_balance = 1;
    assert(orchard_signer_verify(ctx, h0) == SIGNER_ERR_EMPTY_POOL_BALANCE);
    assert_aborted(ctx);

    /* Through the API: refused as soon as the last action is in. */
    fx_build_meta(meta, FX_BRANCH_NU6_3, -(real - 10000), real);
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 2) == SIGNER_OK);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    assert(feed_full(ctx, &chg, 2) == SIGNER_ERR_EMPTY_POOL_BALANCE);
    assert_aborted(ctx);
    /* Even the smallest lie, in either direction, in either pool. */
    /* (bounded by the supply: larger balances are refused with the TxMeta) */
    static const int64_t lies[] = {1, -1, 2100000000000000ll, -2100000000000000ll};
    for(size_t i = 0; i < 4; i++) {
        fx_build_meta(meta, FX_BRANCH_NU6_3, lies[i], real);
        orchard_signer_init(ctx, 1);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
        assert(feed_full(ctx, &pay, 1) == SIGNER_ERR_EMPTY_POOL_BALANCE);
        FxNote op = pay;
        op.pool = ZIP244_POOL_ORCHARD;
        fx_build_meta(meta, FX_BRANCH_NU6_3, real, lies[i]);
        orchard_signer_init(ctx, 1);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
        assert(feed_full(ctx, &op, 1) == SIGNER_ERR_EMPTY_POOL_BALANCE);
        assert_aborted(ctx);
    }

    /* No actions at all: nothing to authorise, and neither value balance
     * could be bound. */
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, 0);
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 0) == SIGNER_ERR_NO_ACTIONS);
    assert_aborted(ctx);

    /* The anchors are not kept: nothing binds them and nothing reads them. */
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, 0);
    memset(meta + 29, 0xAA, 32);
    memset(meta + 70, 0xBB, 32);
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
    for(int i = 0; i < 32; i++) {
        assert(ctx->tx_meta.anchor[i] == 0 && ctx->tx_meta.ironwood_anchor[i] == 0);
    }
    orchard_signer_reset(ctx);
    PASS("value balance of a pool without actions must be zero (feed, totals, verify); no-action tx refused");
}

static void test_transparent_inputs_unsupported(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t in[75] = {0};
    open_session(ctx, 1, 0);
    assert(orchard_signer_begin_transparent(ctx, 1, 0) ==
           SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    assert_aborted(ctx);
    open_session(ctx, 1, 0);
    assert(orchard_signer_begin_transparent(ctx, 0, 1) == SIGNER_OK);
    assert(orchard_signer_feed_transparent_input(ctx, in, sizeof(in)) ==
           SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    assert_aborted(ctx);
    /* in any state, with anything */
    assert(orchard_signer_feed_transparent_input(ctx, NULL, 0) ==
           SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_transparent_input(ctx, in, 48) ==
           SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    assert_aborted(ctx);

    /* Outputs: only scripts that have an address; exact length. */
    uint8_t out[40] = {0};
    out[8] = 25;
    out[10] = 0x76; out[11] = 0xA9; out[12] = 0x14; out[33] = 0x88; out[34] = 0xAC;
    open_session(ctx, 1, 0);
    assert(orchard_signer_begin_transparent(ctx, 0, 2) == SIGNER_OK);
    assert(orchard_signer_feed_transparent_output(ctx, out, 35) == SIGNER_OK);
    assert(orchard_signer_feed_transparent_output(ctx, out, 36) ==
           SIGNER_ERR_TRANSPARENT_BAD_OUTPUT);              /* trailing byte */
    assert_aborted(ctx);
    out[10] = 0x51;                                          /* not P2PKH */
    open_session(ctx, 1, 0);
    assert(orchard_signer_begin_transparent(ctx, 0, 1) == SIGNER_OK);
    assert(orchard_signer_feed_transparent_output(ctx, out, 35) ==
           SIGNER_ERR_TRANSPARENT_BAD_OUTPUT);
    assert_aborted(ctx);
    uint8_t p2sh[33] = {0};
    p2sh[8] = 23; p2sh[10] = 0xA9; p2sh[11] = 0x14; p2sh[32] = 0x87;
    open_session(ctx, 1, 0);
    assert(orchard_signer_begin_transparent(ctx, 0, 1) == SIGNER_OK);
    assert(orchard_signer_feed_transparent_output(ctx, p2sh, 33) == SIGNER_OK);
    orchard_signer_reset(ctx);

    /* No outputs: the transparent leaf is the empty-bundle constant. */
    uint8_t empty[32], got[32];
    Zip244TransparentState ts;
    zip244_empty_digest("ZTxIdTranspaHash", empty);
    zip244_transparent_init(&ts);
    zip244_transparent_digest(&ts, got);
    assert(memcmp(empty, got, 32) == 0);
    open_session(ctx, 1, 0);
    assert(orchard_signer_begin_transparent(ctx, 0, 0) == SIGNER_OK);
    assert(orchard_signer_verify_transparent(ctx, empty) == SIGNER_OK);
    orchard_signer_reset(ctx);
    PASS("transparent inputs refused by name; outputs P2PKH/P2SH only, exact length; empty stream = empty digest");
}

static void test_network(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    OrchardSignerFvk fvk = fx_wallet_fvk();
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    fx_build_meta(meta, FX_BRANCH_NU6_3, 0, 0);    /* declares coin type 1 */

    /* No network, no session. */
    static const uint32_t bad[] = {0, 2, 132, 134, 0x80000085u};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        orchard_signer_init(ctx, bad[i]);
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) ==
               SIGNER_ERR_NETWORK_UNSET);
        assert_aborted(ctx);
    }
    /* A mainnet device refuses the testnet transaction — also after every
     * kind of reset (the check used to live in session state). */
    orchard_signer_init(ctx, ORCHARD_SIGNER_COIN_MAINNET);
    for(int round = 0; round < 3; round++) {
        assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) ==
               SIGNER_ERR_NETWORK_MISMATCH);
        assert_aborted(ctx);
        orchard_signer_reset(ctx);
        assert(ctx->coin_type == ORCHARD_SIGNER_COIN_MAINNET);
    }
    /* A testnet device refuses mainnet, and a TxMeta that does not say. */
    orchard_signer_init(ctx, ORCHARD_SIGNER_COIN_TESTNET);
    meta[ZIP244_TX_META_V6_SIZE] = 133;
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) ==
           SIGNER_ERR_NETWORK_MISMATCH);
    meta[ZIP244_TX_META_V6_SIZE] = 0;
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) ==
           SIGNER_ERR_NETWORK_MISMATCH);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, ZIP244_TX_META_V6_SIZE, 1) ==
           SIGNER_ERR_NETWORK_MISMATCH);
    meta[ZIP244_TX_META_V6_SIZE] = 1;
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
    /* an aborted session keeps the network and nothing else */
    uint8_t junk[820] = {0}, r43[43] = {0}, rs[32] = {0}, memo[512] = {0};
    assert(orchard_signer_feed_action_with_note_and_memo(ctx, ZIP244_POOL_IRONWOOD, junk, 820,
                                                         r43, 0, rs, memo) != SIGNER_OK);
    assert_aborted(ctx);
    assert(ctx->coin_type == ORCHARD_SIGNER_COIN_TESTNET);

    /* The coin type is NOT in the sighash (documented limit): the same
     * transaction has the same sighash whatever network is declared. */
    uint8_t to[43], h1[32], h2[32];
    fx_addr_foreign(to);
    FxNote pay = fx_note(to, 1, NULL, 1);
    open_session(ctx, 1, 1);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    fx_sighash(ctx, h1);
    ctx->tx_meta.coin_type = 133;
    fx_sighash(ctx, h2);
    assert(memcmp(h1, h2, 32) == 0);
    orchard_signer_reset(ctx);
    PASS("network: fixed at init, survives resets, TxMeta must declare it; unset -> no session");
}

/* ── session key lifecycle ─────────────────────────────────────────── */

static void test_ivks_wiped_on_every_exit(void) {
    OrchardSignerCtx* ctx = &g_ctx;
    uint8_t to[43];
    fx_addr_foreign(to);
    FxNote pay = fx_note(to, FX_ZEC, NULL, 1);
    uint8_t action[820];

    /* Keys absent before a session and after an explicit reset. */
    orchard_signer_init(ctx, 1);
    assert(fx_ivks_wiped(ctx));
    open_session(ctx, 1, 0);
    orchard_signer_reset(ctx);
    assert_aborted(ctx);

    /* Every rejection of an action. */
    open_session(ctx, 1, 0);
    fx_build_action(action, &pay, 1);
    action[96] ^= 1; /* cmx */
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, pay.pool, action, sizeof(action), pay.recipient, pay.value, pay.rseed,
               pay.memo) == SIGNER_ERR_NOTE_COMMITMENT_MISMATCH);
    assert_aborted(ctx);

    open_session(ctx, 1, 0);
    fx_build_action(action, &pay, 1);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, (Zip244Pool)7, action, sizeof(action), pay.recipient, pay.value, pay.rseed,
               pay.memo) == SIGNER_ERR_BAD_POOL);
    assert_aborted(ctx);

    open_session(ctx, 1, 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
               ctx, pay.pool, action, 819, pay.recipient, pay.value, pay.rseed, pay.memo) ==
           SIGNER_ERR_BAD_ACTION);
    assert_aborted(ctx);

    /* A sighash mismatch at the very end. */
    open_session(ctx, 1, 0);
    assert(feed_full(ctx, &pay, 1) == SIGNER_OK);
    OrchardSignerTotals t;
    assert(orchard_signer_get_totals(ctx, &t) == SIGNER_OK);
    assert(orchard_signer_confirm_action(ctx, 0) == SIGNER_OK);
    assert(orchard_signer_confirm_totals(ctx) == SIGNER_OK);
    uint8_t sighash[32];
    fx_sighash(ctx, sighash);
    sighash[5] ^= 1;
    assert(orchard_signer_verify(ctx, sighash) == SIGNER_ERR_SIGHASH_MISMATCH);
    assert_aborted(ctx);

    /* A TxMeta that is rejected leaves no keys behind either. */
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    OrchardSignerFvk fvk = fx_wallet_fvk();
    fx_build_meta(meta, FX_BRANCH_NU6, 0, 0);
    orchard_signer_init(ctx, 1);
    assert(orchard_signer_feed_meta(ctx, &fvk, meta, sizeof(meta), 1) ==
           SIGNER_ERR_BRANCH_NOT_ALLOWED);
    assert(fx_ivks_wiped(ctx));
    PASS("session viewing keys wiped on reset and on every abort path");
}

int main(void) {
    printf("Ownership / ciphertext / branch tests (MAX_ACTIONS=%d, MAX_MEMOS=%d, "
           "sizeof ctx=%zu, sizeof dispatcher=%zu):\n",
           ORCHARD_SIGNER_MAX_ACTIONS, ORCHARD_SIGNER_MAX_MEMOS, sizeof(OrchardSignerCtx),
           sizeof(HwpDispatcher));
    test_send_with_change();
    test_change_redirected();
    test_own_external_addresses();
    test_wrong_fvk_fails_safe();
    test_zero_value_outputs();
    test_value_never_auto_approved();
    test_no_hidden_memo_on_padding();
    test_memo_substitution();
    test_wrong_ciphertext_on_own_change();
    test_limits_fail_closed();
    test_ordering();
    test_branch_allow_list();
    test_totals_overflow();
    test_totals_with_transparent();
    test_unbound_value_balance();
    test_sealed_pool_spend_dummy();
    test_transparent_inputs_unsupported();
    test_network();
    test_ivks_wiped_on_every_exit();
    printf("All ownership tests passed (%d groups).\n", n_pass);
    return 0;
}
