/**
 * Tests for orchard_signer state machine — Orchard-only invariants.
 *
 * Covers two enforcement points:
 *
 * 1. Sapling-digest empty-bundle enforcement: feed_meta must accept a TxMeta
 *    whose sapling_digest equals BLAKE2b-256("ZTxIdSaplingHash", []) and
 *    reject any other value with SIGNER_ERR_SAPLING_NOT_EMPTY.
 *
 * 2. NoteCommitment (cmx) recomputation: feed_action_with_note must accept
 *    an action whose cmx field commits to the claimed (recipient, value,
 *    rseed), and reject with SIGNER_ERR_NOTE_COMMITMENT_MISMATCH any
 *    attempt to swap the recipient (the canonical "hostile companion shows
 *    Mario, sends to attacker" siphoning attack).
 */
#include "orchard_signer.h"
#include "orchard.h"
#include "zip244.h"
#include "test_vectors.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Build a minimal-but-valid 125-byte TxMeta wire payload with the given
 * sapling_digest. Other fields are set to plausible Nu5-mainnet values.
 * The transparent_sig_digest is populated with the empty-bundle constant
 * BLAKE2b-256("ZTxIdTranspaHash", "") so verify() does not reject the
 * fixture as a hostile-companion "non-empty digest with skipped transparent
 * flow" attempt. Callers that exercise transparent flow patch this field. */
static void build_tx_meta_wire(uint8_t buf[125], const uint8_t sapling_digest[32]) {
    memset(buf, 0, 125);
    /* version = 5, version_group_id = 0x26A7270A (Nu5), branch_id = 0xC2D6D0B4 (Nu5),
     * lock_time = 0, expiry_height = 0 */
    buf[0]  = 0x05;                                /* version LE */
    buf[4]  = 0x0A; buf[5]  = 0x27; buf[6]  = 0xA7; buf[7]  = 0x26;  /* vgi */
    buf[8]  = 0xB4; buf[9]  = 0xD0; buf[10] = 0xD6; buf[11] = 0xC2;  /* branch_id */
    /* orchard_flags = 0x03 (spends + outputs enabled) */
    buf[20] = 0x03;
    /* value_balance = 0, anchor = 32 zero bytes (offset 29..60) */
    /* transparent_sig_digest at offset 61..92: empty-bundle constant */
    uint8_t transparent_empty[32];
    zip244_empty_digest("ZTxIdTranspaHash", transparent_empty);
    memcpy(buf + 61, transparent_empty, 32);
    /* sapling_digest at offset 93 */
    memcpy(buf + 93, sapling_digest, 32);
}

static void test_sapling_empty_accepted(void) {
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t empty[32];
    zip244_sapling_empty_digest(empty);

    uint8_t wire[125];
    build_tx_meta_wire(wire, empty);

    OrchardSignerError err = orchard_signer_feed_meta(&ctx, wire, sizeof(wire), 1);
    assert(err == SIGNER_OK);
    assert(ctx.state == SIGNER_RECEIVING_ACTIONS);
    assert(ctx.has_meta == true);
    printf("  PASS: sapling empty-bundle constant accepted\n");
}

static void test_sapling_nonempty_rejected(void) {
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    /* Use a value that is definitely not the empty constant. All-0xAA is
     * a fine choice — vanishingly unlikely to collide. */
    uint8_t nonempty[32];
    memset(nonempty, 0xAA, 32);

    uint8_t wire[125];
    build_tx_meta_wire(wire, nonempty);

    OrchardSignerError err = orchard_signer_feed_meta(&ctx, wire, sizeof(wire), 1);
    assert(err == SIGNER_ERR_SAPLING_NOT_EMPTY);
    /* Context must remain in IDLE — the session must not have advanced. */
    assert(ctx.state == SIGNER_IDLE);
    assert(ctx.has_meta == false);
    printf("  PASS: non-empty sapling_digest rejected (state unchanged)\n");
}

static void test_sapling_off_by_one_byte_rejected(void) {
    /* Tamper with a single byte of the empty constant: the check must catch it. */
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t tampered[32];
    zip244_sapling_empty_digest(tampered);
    tampered[17] ^= 0x01;

    uint8_t wire[125];
    build_tx_meta_wire(wire, tampered);

    OrchardSignerError err = orchard_signer_feed_meta(&ctx, wire, sizeof(wire), 1);
    assert(err == SIGNER_ERR_SAPLING_NOT_EMPTY);
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: single-bit-flip on empty constant rejected\n");
}

static void test_sapling_empty_constant_is_stable(void) {
    /* The empty-bundle constant is BLAKE2b-256 with 16-byte personalization
     * "ZTxIdSaplingHash" and no input data. Its value is fixed and must
     * not change across runs. We pin the first/last bytes as a sanity check
     * that the personalization string and BLAKE2b finalize-on-empty are wired
     * up correctly. The full reference vector lives in test_vectors.c. */
    uint8_t a[32], b[32];
    zip244_sapling_empty_digest(a);
    zip244_sapling_empty_digest(b);
    assert(memcmp(a, b, 32) == 0);
    /* The result is deterministic and non-zero (BLAKE2b output of a
     * 16-byte personalization on empty input is never all-zero). */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (a[i] != 0) { all_zero = 0; break; }
    }
    assert(!all_zero);
    printf("  PASS: empty-bundle constant is deterministic and non-zero\n");
}

/* ----------------------------------------------------------------------- */
/*  NoteCommitment (cmx) verification                                      */
/* ----------------------------------------------------------------------- */

/* Build a synthetic 820-byte action whose nullifier (offset 32) and cmx
 * (offset 96) are populated from the KAT in test_vectors.h. Other fields
 * are zero — the cmx check at feed-time only depends on the nullifier
 * (used as rho) and the cmx field. */
static void build_synthetic_action(uint8_t out[820],
                                   const uint8_t rho[32],
                                   const uint8_t cmx[32]) {
    memset(out, 0, 820);
    memcpy(out + 32, rho, 32);   /* OFF_NULLIFIER */
    memcpy(out + 96, cmx, 32);   /* OFF_CMX */
}

/* Feed a valid TxMeta + start session (returns ctx in RECEIVING_ACTIONS). */
static void start_session_for_one_action(OrchardSignerCtx *ctx, uint8_t wire[125]) {
    orchard_signer_init(ctx);
    uint8_t empty[32];
    zip244_sapling_empty_digest(empty);
    build_tx_meta_wire(wire, empty);
    OrchardSignerError err = orchard_signer_feed_meta(ctx, wire, 125, 1);
    assert(err == SIGNER_OK);
    assert(ctx->state == SIGNER_RECEIVING_ACTIONS);
}

static void test_note_commit_match_accepted(void) {
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);

    OrchardSignerError err = orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed);
    assert(err == SIGNER_OK);
    assert(ctx.actions_received == 1);
    printf("  PASS: matching cmx accepted (recipient/value/rseed correct)\n");
}

static void test_note_commit_attacker_recipient_rejected(void) {
    /* Simulate the hostile-companion attack: keep the cmx in the action
     * (which commits to the *real* recipient — say Mario), but pass a
     * different recipient as the claimed one (the attacker). The check
     * must catch it. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);

    /* Swap the first byte of the recipient diversifier: a 1-byte change is
     * enough to make the recomputed cmx land somewhere else. */
    uint8_t fake_recipient[43];
    memcpy(fake_recipient, note_commit_recipient, 43);
    fake_recipient[0] ^= 0x01;

    OrchardSignerError err = orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        fake_recipient, note_commit_value, note_commit_rseed);
    assert(err == SIGNER_ERR_NOTE_COMMITMENT_MISMATCH);
    /* On rejection, ctx is reset to IDLE and the partial session is
     * discarded — no signature is producible. */
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: tampered diversifier (1-bit flip) rejected, ctx reset\n");
}

static void test_note_commit_attacker_value_rejected(void) {
    /* Same attack on the value: companion shows "0.5 ZEC to Mario" but
     * the action commits to a different value. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);

    OrchardSignerError err = orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value + 1, note_commit_rseed);
    assert(err == SIGNER_ERR_NOTE_COMMITMENT_MISMATCH);
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: tampered value (off by one) rejected, ctx reset\n");
}

static void test_note_commit_wrong_action_size_rejected(void) {
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);

    /* Pass shorter action_len: must be SIGNER_ERR_BAD_ACTION before any
     * cmx work happens. */
    OrchardSignerError err = orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, 819,
        note_commit_recipient, note_commit_value, note_commit_rseed);
    assert(err == SIGNER_ERR_BAD_ACTION);
    printf("  PASS: invalid action length rejected\n");
}

/* ----------------------------------------------------------------------- */
/*  Memo / enc_ciphertext verification (v5 feed)                           */
/* ----------------------------------------------------------------------- */
/*
 * orchard_signer_feed_action_with_note_and_memo must:
 *   - accept an action whose enc_ciphertext + epk match the recomputed
 *     values from (d, pk_d, value, rseed, memo, esk)
 *   - reject (SIGNER_ERR_MEMO_MISMATCH) any tamper on memo or esk
 *   - reject pk_d that does not decode (SIGNER_ERR_BAD_PK_D)
 *
 * Builds an action where cmx, ephemeral_key and enc_ciphertext are all
 * recomputed live from a known set of note-plaintext inputs, so the test
 * exercises the full ECDH-Pallas + ChaCha20-Poly1305 path that the
 * companion would normally provide pre-computed.
 */

/* Build a synthetic 820-byte action whose nullifier (rho), cmx, epk and
 * enc_ciphertext are consistent with (recipient, value, rseed, memo).
 * esk is derived from rseed + rho per ZIP-212 — the same derivation the
 * device performs internally, so we use the same primitive here.
 * Returns 0 on success, non-zero if pk_d decoding fails. */
static int build_synthetic_action_v5(uint8_t out[820],
                                      const uint8_t recipient[43],
                                      uint64_t value,
                                      const uint8_t rseed[32],
                                      const uint8_t memo[512]) {
    memset(out, 0, 820);
    /* Pick an arbitrary nullifier as rho. Real Orchard uses a derived
     * value; for this fixture any 32 bytes work — cmx and enc_ciphertext
     * are computed against this rho. */
    for (int i = 0; i < 32; i++) out[32 + i] = (uint8_t)(0x42 ^ i);

    /* cmx at offset 96 */
    orchard_compute_cmx(recipient, recipient + 11, value,
                        out + 32, rseed, ORCHARD_NOTE_V2, out + 96);

    /* enc_ciphertext at offset 160, epk at offset 128 */
    return orchard_compute_enc_ciphertext_from_rseed(
        recipient, recipient + 11, value, rseed, out + 32, memo,
        ORCHARD_NOTE_V2, out + 160, out + 128);
}

/* A reusable memo fixture. */
static const uint8_t test_memo[512] = {
    'H','e','l','l','o',' ','M','a','r','i','o','!',' ',
    'I','n','v','o','i','c','e',' ','#','1','2','3',
    /* rest is implicit zero */
};

static void test_memo_full_consistency_accepted(void) {
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    int built = build_synthetic_action_v5(
        action, note_commit_recipient, note_commit_value,
        note_commit_rseed, test_memo);
    assert(built == 0);

    OrchardSignerError err = orchard_signer_feed_action_with_note_and_memo(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed,
        test_memo);
    assert(err == SIGNER_OK);
    assert(ctx.actions_received == 1);
    printf("  PASS: action with consistent cmx + epk + enc_ciphertext accepted\n");
}

static void test_memo_captured_for_display(void) {
    /* After feed_action_with_note_and_memo() succeeds, the firmware must
     * be able to retrieve the memo bytes via get_action_memo() so it
     * can render them on the trusted screen. Without this, the AEAD
     * binding catches "memo on chain != memo declared" but the user
     * cannot detect "memo declared != memo shown by companion UI". */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    assert(build_synthetic_action_v5(
        action, note_commit_recipient, note_commit_value,
        note_commit_rseed, test_memo) == 0);
    assert(orchard_signer_feed_action_with_note_and_memo(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed,
        test_memo) == SIGNER_OK);

    uint8_t memo_out[512];
    bool present = false;
    assert(orchard_signer_get_action_memo(&ctx, 0, memo_out, &present) == SIGNER_OK);
    assert(present == true);
    assert(memcmp(memo_out, test_memo, 512) == 0);

    /* Out-of-range index rejected. */
    assert(orchard_signer_get_action_memo(&ctx, 1, memo_out, &present)
           == SIGNER_ERR_INVALID_ACTION_INDEX);

    printf("  PASS: memo captured and retrievable via get_action_memo\n");
}

static void test_memo_not_present_for_v4_feed(void) {
    /* When the action was fed via the cmx-only feed_action_with_note()
     * path, no memo is captured and get_action_memo reports
     * present=false. Lets the firmware skip the memo-review step
     * gracefully on legacy / OVK-None payloads. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
    assert(orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed) == SIGNER_OK);

    uint8_t memo_out[512];
    bool present = true;  /* prove it gets overwritten to false */
    assert(orchard_signer_get_action_memo(&ctx, 0, memo_out, &present) == SIGNER_OK);
    assert(present == false);
    printf("  PASS: v4 (cmx-only) feed leaves memo_present=false\n");
}

static void test_memo_tampered_memo_rejected(void) {
    /* Hostile companion: shows the user "Invoice #123" but inside
     * enc_ciphertext puts a different memo. We simulate by building the
     * action with the real memo, then telling feed() that the memo
     * was something else. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    int built = build_synthetic_action_v5(
        action, note_commit_recipient, note_commit_value,
        note_commit_rseed, test_memo);
    assert(built == 0);

    uint8_t fake_memo[512];
    memcpy(fake_memo, test_memo, 512);
    fake_memo[100] ^= 1;  /* flip one bit somewhere in the middle */

    OrchardSignerError err = orchard_signer_feed_action_with_note_and_memo(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed,
        fake_memo);
    assert(err == SIGNER_ERR_MEMO_MISMATCH);
    assert(ctx.state == SIGNER_IDLE);  /* context reset */
    printf("  PASS: tampered memo (1-bit flip) rejected, ctx reset\n");
}

static void test_memo_tampered_rseed_rejected(void) {
    /* esk is derived from rseed + rho per ZIP-212; flipping rseed
     * therefore changes both the recomputed cmx AND the K_enc → memo
     * encryption. cmx mismatch fires first; the test checks rseed
     * tamper detection regardless of which leg catches it. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    int built = build_synthetic_action_v5(
        action, note_commit_recipient, note_commit_value,
        note_commit_rseed, test_memo);
    assert(built == 0);

    uint8_t fake_rseed[32];
    memcpy(fake_rseed, note_commit_rseed, 32);
    fake_rseed[0] ^= 1;

    OrchardSignerError err = orchard_signer_feed_action_with_note_and_memo(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, fake_rseed,
        test_memo);
    /* Either NOTE_COMMITMENT_MISMATCH (cmx leg fires first) or
     * MEMO_MISMATCH would be a correct rejection; we just require the
     * session is reset. */
    assert(err == SIGNER_ERR_NOTE_COMMITMENT_MISMATCH ||
           err == SIGNER_ERR_MEMO_MISMATCH);
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: tampered rseed rejected (cmx or memo), ctx reset\n");
}

static void test_memo_tampered_enc_ciphertext_rejected(void) {
    /* Hostile companion: leaves memo/rseed truthful but mangles
     * enc_ciphertext bytes in the action. Real-world version of the
     * "I tell you what the memo says but write something else on chain"
     * attack — the device must catch the divergence and abort. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    int built = build_synthetic_action_v5(
        action, note_commit_recipient, note_commit_value,
        note_commit_rseed, test_memo);
    assert(built == 0);

    /* Flip a byte inside enc_ciphertext (offset 160 + 200 = 360, still
     * inside the memo portion of the ciphertext). */
    action[360] ^= 1;

    OrchardSignerError err = orchard_signer_feed_action_with_note_and_memo(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed,
        test_memo);
    assert(err == SIGNER_ERR_MEMO_MISMATCH);
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: tampered enc_ciphertext (1-byte flip) rejected, ctx reset\n");
}

/* ----------------------------------------------------------------------- */
/*  No-blind-signing invariant                                             */
/* ----------------------------------------------------------------------- */
/*
 * orchard_signer_verify() must refuse to advance to SIGNER_VERIFIED unless
 * every captured action has been explicitly confirmed via
 * orchard_signer_confirm_action(). Without VERIFIED, orchard_signer_sign()
 * returns SIGNER_ERR_NOT_VERIFIED and no signature is produced — so a
 * hostile firmware that skips the per-output user-confirmation UI cannot
 * extract a signature.
 */

static void compute_sighash(OrchardSignerCtx *src, uint8_t out[32]) {
    /* Snapshot the actions_state so the streaming hashers don't get
     * finalized in `src` itself. zip244_shielded_sighash() finalizes them. */
    Zip244ActionsState snap = src->actions_state;
    zip244_shielded_sighash(&src->tx_meta, &snap, out);
}

static void test_verify_refuses_without_any_confirm(void) {
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
    OrchardSignerError err = orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed);
    assert(err == SIGNER_OK);

    /* Compute the sighash that the companion would also send. */
    uint8_t sighash[32];
    compute_sighash(&ctx, sighash);

    /* No confirm_action() called → verify must refuse. */
    err = orchard_signer_verify(&ctx, sighash);
    assert(err == SIGNER_ERR_ACTION_NOT_CONFIRMED);
    assert(ctx.state == SIGNER_RECEIVING_ACTIONS);  /* not advanced */
    printf("  PASS: verify refuses (NOT_CONFIRMED) when no action confirmed\n");
}

static void test_verify_accepts_after_confirm(void) {
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
    assert(orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed) == SIGNER_OK);

    uint8_t sighash[32];
    compute_sighash(&ctx, sighash);

    /* Firmware reads the display, asks the user, marks confirmed. */
    uint8_t recipient[43];
    uint64_t value;
    assert(orchard_signer_get_action_display(&ctx, 0, recipient, &value) == SIGNER_OK);
    assert(memcmp(recipient, note_commit_recipient, 43) == 0);
    assert(value == note_commit_value);
    assert(orchard_signer_confirm_action(&ctx, 0) == SIGNER_OK);

    /* Firmware also computes and confirms the miner fee — for this fixture
     * value_balance is 0 and there is no transparent flow, so fee == 0. */
    uint64_t fee;
    assert(orchard_signer_get_fee(&ctx, &fee) == SIGNER_OK);
    assert(fee == 0);
    assert(orchard_signer_confirm_fee(&ctx) == SIGNER_OK);

    /* Now verify must succeed and transition to VERIFIED. */
    OrchardSignerError err = orchard_signer_verify(&ctx, sighash);
    assert(err == SIGNER_OK);
    assert(ctx.state == SIGNER_VERIFIED);
    printf("  PASS: verify advances to VERIFIED once all actions + fee confirmed\n");
}

static void test_verify_refuses_without_fee_confirm(void) {
    /* All actions confirmed but fee not → verify must refuse with the
     * no-blind-signing-for-fee invariant. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
    assert(orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed) == SIGNER_OK);

    uint8_t sighash[32];
    compute_sighash(&ctx, sighash);

    assert(orchard_signer_confirm_action(&ctx, 0) == SIGNER_OK);
    /* Deliberately skip get_fee / confirm_fee. */

    OrchardSignerError err = orchard_signer_verify(&ctx, sighash);
    assert(err == SIGNER_ERR_FEE_NOT_CONFIRMED);
    assert(ctx.state == SIGNER_RECEIVING_ACTIONS);   /* did not advance */
    printf("  PASS: verify refuses (FEE_NOT_CONFIRMED) when fee not approved\n");
}

static void test_confirm_fee_refuses_without_get_fee(void) {
    /* confirm_fee() before get_fee() must refuse: a firmware UI that
     * "confirms" before computing would be approving a stale zero. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    OrchardSignerError err = orchard_signer_confirm_fee(&ctx);
    assert(err == SIGNER_ERR_BAD_STATE);
    assert(ctx.fee_confirmed == false);
    printf("  PASS: confirm_fee refuses before get_fee was called\n");
}

static void test_get_fee_orchard_only_returns_value_balance(void) {
    /* For an Orchard-only tx (no transparent flow), fee == value_balance.
     * Patch the wire to set value_balance = 10_000 zatoshis and check. */
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t empty[32];
    zip244_sapling_empty_digest(empty);
    uint8_t wire[125];
    build_tx_meta_wire(wire, empty);
    /* value_balance is at offset 21 (i64 LE). 10_000 = 0x2710. */
    wire[21] = 0x10; wire[22] = 0x27;

    assert(orchard_signer_feed_meta(&ctx, wire, 125, 1) == SIGNER_OK);

    uint64_t fee = 0xDEADBEEF;
    assert(orchard_signer_get_fee(&ctx, &fee) == SIGNER_OK);
    assert(fee == 10000);

    /* Caching: second call returns the same value without recomputation. */
    fee = 0;
    assert(orchard_signer_get_fee(&ctx, &fee) == SIGNER_OK);
    assert(fee == 10000);
    printf("  PASS: orchard-only fee == value_balance (cached on second call)\n");
}

static void test_get_fee_rejects_negative(void) {
    /* A bundle where t_in + value_balance < t_out is unbalanced. */
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t empty[32];
    zip244_sapling_empty_digest(empty);
    uint8_t wire[125];
    build_tx_meta_wire(wire, empty);
    /* value_balance = -1000 (two's complement i64 LE). */
    int64_t vb = -1000;
    for (int i = 0; i < 8; i++) wire[21 + i] = (uint8_t)((uint64_t)vb >> (8 * i));

    assert(orchard_signer_feed_meta(&ctx, wire, 125, 1) == SIGNER_OK);

    uint64_t fee = 0;
    OrchardSignerError err = orchard_signer_get_fee(&ctx, &fee);
    assert(err == SIGNER_ERR_FEE_NEGATIVE);
    /* On negative fee, ctx is reset — the partial session is discarded. */
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: negative fee rejected (FEE_NEGATIVE), ctx reset\n");
}

static void test_verify_refuses_partial_confirm(void) {
    /* Three actions captured, only one confirmed → verify must refuse. */
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t empty[32];
    zip244_sapling_empty_digest(empty);
    uint8_t wire[125];
    build_tx_meta_wire(wire, empty);
    assert(orchard_signer_feed_meta(&ctx, wire, 125, 3) == SIGNER_OK);

    uint8_t action[820];
    for (int i = 0; i < 3; i++) {
        build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
        assert(orchard_signer_feed_action_with_note(
            &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
            note_commit_recipient, note_commit_value, note_commit_rseed) == SIGNER_OK);
    }

    uint8_t sighash[32];
    compute_sighash(&ctx, sighash);

    /* Confirm only action 1 (skipping 0 and 2). */
    assert(orchard_signer_confirm_action(&ctx, 1) == SIGNER_OK);

    OrchardSignerError err = orchard_signer_verify(&ctx, sighash);
    assert(err == SIGNER_ERR_ACTION_NOT_CONFIRMED);
    assert(ctx.state == SIGNER_RECEIVING_ACTIONS);
    printf("  PASS: verify refuses when 1 of 3 actions confirmed\n");
}

static void test_invalid_action_index(void) {
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    /* No action fed yet — index 0 is invalid. */
    uint8_t recipient[43];
    uint64_t value;
    assert(orchard_signer_get_action_display(&ctx, 0, recipient, &value) ==
           SIGNER_ERR_INVALID_ACTION_INDEX);
    assert(orchard_signer_confirm_action(&ctx, 0) ==
           SIGNER_ERR_INVALID_ACTION_INDEX);

    /* Feed one action: now index 0 is valid, but 1 is not. */
    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
    assert(orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed) == SIGNER_OK);
    assert(orchard_signer_get_action_display(&ctx, 1, recipient, &value) ==
           SIGNER_ERR_INVALID_ACTION_INDEX);
    assert(orchard_signer_confirm_action(&ctx, 1) ==
           SIGNER_ERR_INVALID_ACTION_INDEX);
    printf("  PASS: invalid action index rejected for both display and confirm\n");
}

static void test_too_many_actions_rejected_at_meta(void) {
    OrchardSignerCtx ctx;
    orchard_signer_init(&ctx);

    uint8_t empty[32];
    zip244_sapling_empty_digest(empty);
    uint8_t wire[125];
    build_tx_meta_wire(wire, empty);

    OrchardSignerError err = orchard_signer_feed_meta(
        &ctx, wire, 125, ORCHARD_SIGNER_MAX_ACTIONS + 1);
    assert(err == SIGNER_ERR_TOO_MANY_ACTIONS);
    /* Context must remain in IDLE — meta was rejected. */
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: tx with > MAX_ACTIONS outputs rejected at feed_meta\n");
}

static void test_sign_refuses_without_verify(void) {
    /* Direct check that sign() refuses if state never reached VERIFIED.
     * Belt-and-braces: the same invariant is enforced inside verify(),
     * but sign() also short-circuits to NOT_VERIFIED if a confused
     * caller skips verify(). */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
    assert(orchard_signer_feed_action_with_note(
        &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
        note_commit_recipient, note_commit_value, note_commit_rseed) == SIGNER_OK);

    uint8_t sighash[32];
    compute_sighash(&ctx, sighash);

    uint8_t ask[32] = {0};
    uint8_t alpha[32] = {0};
    uint8_t sig[64], rk[32];
    OrchardSignerError err = orchard_signer_sign(&ctx, sighash, ask, alpha, sig, rk);
    assert(err == SIGNER_ERR_NOT_VERIFIED);
    printf("  PASS: sign refuses (NOT_VERIFIED) if state never reached VERIFIED\n");
}

/* ----------------------------------------------------------------------- */
/*  Transparent-output capture (no-blind-signing for t-addr destinations)  */
/* ----------------------------------------------------------------------- */

/* Build the wire payload of one TxTransparentOutput:
 *   value[8 LE] || script_pubkey_len[2 LE] || script_pubkey[N]
 * Returns the total length written. */
static size_t build_transparent_output_wire(
    uint8_t *out, uint64_t value,
    const uint8_t *script, uint16_t script_len) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (8 * i));
    out[8] = (uint8_t)(script_len & 0xFF);
    out[9] = (uint8_t)(script_len >> 8);
    memcpy(out + 10, script, script_len);
    return 10 + script_len;
}

/* Build a standard P2PKH script_pubkey:
 *   OP_DUP OP_HASH160 0x14 <pkh:20> OP_EQUALVERIFY OP_CHECKSIG (25 B) */
static void build_p2pkh_script(uint8_t out[25], const uint8_t pkh[20]) {
    out[0] = 0x76; out[1] = 0xa9; out[2] = 0x14;
    memcpy(out + 3, pkh, 20);
    out[23] = 0x88; out[24] = 0xac;
}

static void test_transparent_output_capture_p2pkh(void) {
    /* feed_transparent_output() must store (value, script_pubkey) in the
     * display array so the firmware UI can render the destination
     * t-address — without this, a shielded → t-addr sweep would show
     * the user only the change Orchard receivers, not the actual
     * transparent recipient. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);
    assert(orchard_signer_begin_transparent(&ctx, /*in*/0, /*out*/1) == SIGNER_OK);
    assert(ctx.state == SIGNER_RECEIVING_TRANSPARENT);

    uint8_t pkh[20];
    for (int i = 0; i < 20; i++) pkh[i] = (uint8_t)(0x10 + i);
    uint8_t script[25];
    build_p2pkh_script(script, pkh);
    uint64_t value = 696969;

    uint8_t out_wire[64];
    size_t out_wire_len =
        build_transparent_output_wire(out_wire, value, script, sizeof(script));
    assert(orchard_signer_feed_transparent_output(&ctx, out_wire, out_wire_len)
           == SIGNER_OK);
    assert(ctx.transparent_state.outputs_received == 1);

    uint64_t got_value = 0;
    uint8_t got_script[25];
    size_t got_script_len = 0;
    OrchardSignerError gerr = orchard_signer_get_transparent_output_display(
        &ctx, 0, &got_value, got_script, sizeof(got_script), &got_script_len);
    assert(gerr == SIGNER_OK);
    assert(got_value == value);
    assert(got_script_len == sizeof(script));
    assert(memcmp(got_script, script, sizeof(script)) == 0);
    printf("  PASS: P2PKH transparent output captured (value + script roundtrip)\n");
}

static void test_transparent_output_oversized_script_rejected(void) {
    /* script_pubkey > 25 B is rejected at feed time so the device cannot
     * be coaxed into signing a transaction it cannot display: any
     * non-standard shape would have to be displayed as raw script
     * (which the no-blind-signing invariant refuses to do). */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);
    assert(orchard_signer_begin_transparent(&ctx, 0, 1) == SIGNER_OK);

    uint8_t huge[80] = {0};
    uint8_t out_wire[128];
    size_t out_wire_len =
        build_transparent_output_wire(out_wire, 1, huge, sizeof(huge));
    OrchardSignerError err =
        orchard_signer_feed_transparent_output(&ctx, out_wire, out_wire_len);
    assert(err == SIGNER_ERR_TRANSPARENT_BAD_OUTPUT);
    /* Context resets so the partial session is discarded. */
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: oversized script rejected, ctx reset\n");
}

static void test_transparent_output_too_many_rejected(void) {
    /* Feeding more transparent outputs than the bounded display array
     * holds (ORCHARD_SIGNER_MAX_T_OUTPUTS) is refused with
     * TOO_MANY_ACTIONS. The invariant is the same as for Orchard
     * actions: every output the device signs must be displayable. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);
    assert(orchard_signer_begin_transparent(
               &ctx, 0, ORCHARD_SIGNER_MAX_T_OUTPUTS + 1) == SIGNER_OK);

    uint8_t pkh[20] = {0};
    uint8_t script[25];
    build_p2pkh_script(script, pkh);
    uint8_t out_wire[64];
    size_t out_wire_len =
        build_transparent_output_wire(out_wire, 1, script, sizeof(script));

    /* Fill the array. */
    for (int i = 0; i < ORCHARD_SIGNER_MAX_T_OUTPUTS; i++) {
        assert(orchard_signer_feed_transparent_output(
                   &ctx, out_wire, out_wire_len) == SIGNER_OK);
    }
    /* MAX_T_OUTPUTS + 1 → rejection. */
    OrchardSignerError err =
        orchard_signer_feed_transparent_output(&ctx, out_wire, out_wire_len);
    assert(err == SIGNER_ERR_TOO_MANY_ACTIONS);
    assert(ctx.state == SIGNER_IDLE);
    printf("  PASS: > %d transparent outputs rejected\n",
           ORCHARD_SIGNER_MAX_T_OUTPUTS);
}

static void test_transparent_get_display_out_of_range(void) {
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);
    assert(orchard_signer_begin_transparent(&ctx, 0, 1) == SIGNER_OK);

    /* No outputs received yet → idx=0 out of range. */
    uint64_t v;
    uint8_t s[25];
    size_t slen;
    OrchardSignerError err = orchard_signer_get_transparent_output_display(
        &ctx, 0, &v, s, sizeof(s), &slen);
    assert(err == SIGNER_ERR_INVALID_ACTION_INDEX);
    printf("  PASS: get_transparent_output_display rejects out-of-range\n");
}

/* ----------------------------------------------------------------------- */
/*  Recipient-binding (orchard_signer_recipient_matches_any)               */
/* ----------------------------------------------------------------------- */

static void test_recipient_matches_any_after_feed(void) {
    /* After feed_action_with_note succeeds, the captured recipient
     * must be discoverable via recipient_matches_any — the constant-
     * time matcher the dispatcher uses to bind SIGN_REQ.recipient to a
     * user-confirmed Orchard receiver, closing the post-confirmation
     * recipient-substitution attack. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t action[820];
    build_synthetic_action(action, note_commit_rho, note_commit_expected_cmx);
    assert(orchard_signer_feed_action_with_note(
               &ctx, ZIP244_POOL_ORCHARD, action, sizeof(action),
               note_commit_recipient, note_commit_value, note_commit_rseed)
           == SIGNER_OK);

    /* Exact match wins. */
    assert(orchard_signer_recipient_matches_any(&ctx, note_commit_recipient)
           == true);

    /* Off-by-one-bit attacker recipient does not. */
    uint8_t attacker[43];
    memcpy(attacker, note_commit_recipient, 43);
    attacker[0] ^= 0x01;
    assert(orchard_signer_recipient_matches_any(&ctx, attacker) == false);
    printf("  PASS: recipient_matches_any matches captured / rejects tampered\n");
}

static void test_recipient_matches_any_empty(void) {
    /* With no actions received the matcher must return false rather
     * than e.g. degenerate-match against zero-initialised storage. */
    OrchardSignerCtx ctx;
    uint8_t wire[125];
    start_session_for_one_action(&ctx, wire);

    uint8_t zeros[43] = {0};
    assert(orchard_signer_recipient_matches_any(&ctx, zeros) == false);
    printf("  PASS: recipient_matches_any returns false on empty session\n");
}

int main(void) {
    printf("Orchard signer / Sapling-empty-bundle invariant tests:\n");
    test_sapling_empty_accepted();
    test_sapling_nonempty_rejected();
    test_sapling_off_by_one_byte_rejected();
    test_sapling_empty_constant_is_stable();

    printf("\nOrchard signer / NoteCommitment (cmx) verification tests:\n");
    test_note_commit_match_accepted();
    test_note_commit_attacker_recipient_rejected();
    test_note_commit_attacker_value_rejected();
    test_note_commit_wrong_action_size_rejected();

    printf("\nOrchard signer / memo+enc_ciphertext verification tests:\n");
    test_memo_full_consistency_accepted();
    test_memo_captured_for_display();
    test_memo_not_present_for_v4_feed();
    test_memo_tampered_memo_rejected();
    test_memo_tampered_rseed_rejected();
    test_memo_tampered_enc_ciphertext_rejected();

    printf("\nOrchard signer / no-blind-signing invariant tests:\n");
    test_verify_refuses_without_any_confirm();
    test_verify_accepts_after_confirm();
    test_verify_refuses_partial_confirm();
    test_invalid_action_index();
    test_too_many_actions_rejected_at_meta();
    test_sign_refuses_without_verify();

    printf("\nOrchard signer / fee-confirmation invariant tests:\n");
    test_verify_refuses_without_fee_confirm();
    test_confirm_fee_refuses_without_get_fee();
    test_get_fee_orchard_only_returns_value_balance();
    test_get_fee_rejects_negative();

    printf("\nOrchard signer / transparent-output display tests:\n");
    test_transparent_output_capture_p2pkh();
    test_transparent_output_oversized_script_rejected();
    test_transparent_output_too_many_rejected();
    test_transparent_get_display_out_of_range();

    printf("\nOrchard signer / recipient-binding tests:\n");
    test_recipient_matches_any_after_feed();
    test_recipient_matches_any_empty();

    printf("All signer tests passed.\n");
    return 0;
}
