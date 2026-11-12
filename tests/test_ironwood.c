/**
 * Ironwood (NU6.3) cross-validation tests.
 *
 * Expected values generated from the reference Rust implementation
 * (orchard 0.15.0-pre.2, zcash_note_encryption 0.4.1) using the same
 * note inputs as the existing V2 note-commit vector:
 *   - V3 (ZIP-2005) note commitment: validates the quantum-recoverable
 *     rcm derivation (PRF^expand domain 0x0B over all note fields);
 *   - V3 note encryption: validates the 0x03 lead byte and that the
 *     esk/KDF/AEAD pipeline is unchanged;
 *   - v6 empty-bundle effects digests: validate the "ZTxIdOrchardH_v6"
 *     and "ZTxIdIronwd_H_v6" personalizations and, together with the
 *     existing v5 sighash tests, the five-leaf v6 digest tree wiring.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "orchard.h"
#include "orchard_signer.h"
#include "zip244.h"

/* Same inputs as note_commit_* in test_vectors.h */
static const uint8_t k_recipient[43] = {
    0x3c, 0x15, 0x0e, 0x60, 0x98, 0xb8, 0x61, 0x71, 0x6c, 0xc7, 0xf6,
    0x28, 0x35, 0xf6, 0x9f, 0xeb, 0x30, 0x21, 0x93, 0xc9, 0x26, 0x60,
    0x44, 0x4f, 0x26, 0x62, 0x4f, 0xd1, 0x3e, 0x00, 0xea, 0x7a, 0xc7,
    0x74, 0xcd, 0x55, 0x07, 0x4d, 0x63, 0x67, 0xef, 0xef, 0x37,
};
static const uint64_t k_value = 12345678;
static const uint8_t k_rho[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
};
static const uint8_t k_rseed[32] = {
    0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
};

/* orchard 0.15.0-pre.2: Note::from_parts(..., NoteVersion::V3).commitment() */
static const uint8_t k_expected_cmx_v3[32] = {
    0x89, 0x6e, 0xe3, 0x45, 0xd8, 0xb0, 0x40, 0x98, 0x72, 0x17, 0x25,
    0x37, 0x66, 0x6a, 0x48, 0x24, 0x09, 0x66, 0x1a, 0x22, 0xad, 0x77,
    0xc0, 0x98, 0x96, 0xa3, 0xe7, 0x17, 0x65, 0xf1, 0x86, 0x33,
};

/* IronwoodNoteEncryption::new(None, note_v3, memo=0xF6||zeros) */
static const uint8_t k_expected_epk_v3[32] = {
    0xd6, 0x9d, 0xa2, 0x8e, 0x9c, 0x9a, 0x59, 0x67, 0xfa, 0xb1, 0x15,
    0x5d, 0x7f, 0x34, 0xd8, 0xa6, 0x6a, 0x33, 0x2f, 0x0f, 0x63, 0xee,
    0x41, 0xde, 0x3c, 0x50, 0x50, 0x91, 0x7b, 0xa7, 0x94, 0x3c,
};
static const uint8_t k_expected_enc_v3_first64[64] = {
    0xd4, 0xc6, 0x5c, 0x6e, 0xe4, 0x44, 0x11, 0xd2, 0x3e, 0x50, 0x6e,
    0x15, 0xc0, 0x83, 0x42, 0x26, 0x71, 0x10, 0x6b, 0xe1, 0x8e, 0xd2,
    0x54, 0x90, 0x40, 0x58, 0x35, 0xb6, 0xbc, 0x17, 0x4c, 0x80, 0xd6,
    0x09, 0x90, 0x39, 0x81, 0xcc, 0x6a, 0x8a, 0x59, 0xdc, 0x96, 0xbf,
    0xdc, 0x2b, 0xa2, 0x27, 0x3a, 0x9b, 0xc6, 0xfa, 0xd0, 0x06, 0x80,
    0xf2, 0x5f, 0xea, 0x6f, 0xa3, 0x73, 0xd0, 0xfc, 0x59,
};
static const uint8_t k_expected_enc_v3_last16[16] = {
    0xa4, 0x53, 0x7e, 0x96, 0x80, 0x65, 0xea, 0x40, 0x16, 0x5c, 0x16,
    0xa5, 0x18, 0xdc, 0x5c, 0xd0,
};
/* OrchardNoteEncryption (V2) with the same inputs: identical keystream, so
 * the ciphertext differs from V3 only in byte 0 (lead byte 0x02 vs 0x03)
 * and the AEAD tag. Cross-validates the legacy V2 path and, crucially,
 * the KDF input order (sharedSecret || ephemeralKey per spec §5.4.5.6). */
static const uint8_t k_expected_enc_v2_byte0 = 0xd5;
static const uint8_t k_expected_enc_v2_last16[16] = {
    0x43, 0x8d, 0xcc, 0x76, 0x0c, 0x86, 0xd3, 0xff, 0x86, 0x8f, 0x8c,
    0x1a, 0x46, 0x39, 0x4c, 0x45,
};

/* hash_bundle_txid_empty(pool, TxVersion::V6) */
static const uint8_t k_empty_orchard_v6[32] = {
    0xa3, 0x36, 0x7d, 0x2f, 0xde, 0xa2, 0x91, 0x01, 0x59, 0xfc, 0x50,
    0x26, 0xe9, 0xbf, 0x1f, 0xcc, 0xd3, 0xe2, 0x8c, 0xe5, 0xe6, 0xde,
    0x46, 0xbf, 0xb7, 0x15, 0x87, 0x23, 0x0e, 0xea, 0x95, 0x15,
};
static const uint8_t k_empty_ironwood_v6[32] = {
    0xb9, 0xcf, 0xe6, 0x43, 0xce, 0x45, 0xb2, 0x8c, 0x33, 0x19, 0x0f,
    0x0d, 0x52, 0x23, 0xe4, 0x75, 0x97, 0x2f, 0x2a, 0x14, 0x9d, 0xc5,
    0x44, 0x04, 0xfd, 0x83, 0x65, 0x52, 0x1f, 0x84, 0x16, 0xc5,
};
/* hash_bundle_txid_empty(Orchard, TxVersion::V5) — matches the historical
 * "ZTxIdOrchardHash" empty constant. */
static const uint8_t k_empty_orchard_v5[32] = {
    0x9f, 0xbe, 0x4e, 0xd1, 0x3b, 0x0c, 0x08, 0xe6, 0x71, 0xc1, 0x1a,
    0x34, 0x07, 0xd8, 0x4e, 0x11, 0x17, 0xcd, 0x45, 0x02, 0x8a, 0x2e,
    0xee, 0x1b, 0x9f, 0xea, 0xe7, 0x8b, 0x48, 0xa6, 0xe2, 0xc1,
};

static void check(const char *name, const uint8_t *expected,
                  const uint8_t *got, size_t len) {
    if (memcmp(expected, got, len) != 0) {
        printf("FAIL: %s\n  expected: ", name);
        for (size_t i = 0; i < len; i++) printf("%02x", expected[i]);
        printf("\n  got:      ");
        for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
        printf("\n");
        assert(0 && "vector mismatch");
    }
    printf("PASS: %s\n", name);
}

static void test_cmx_v3(void) {
    uint8_t cmx[32];
    orchard_compute_cmx(k_recipient, k_recipient + 11, k_value, k_rho,
                        k_rseed, ORCHARD_NOTE_V3, cmx);
    check("cmx V3 (ZIP-2005 rcm)", k_expected_cmx_v3, cmx, 32);

    /* And V2 must NOT change under the refactor (covered in test_vectors
     * too, but cheap to re-assert next to its V3 sibling). */
    uint8_t cmx_v2[32];
    orchard_compute_cmx(k_recipient, k_recipient + 11, k_value, k_rho,
                        k_rseed, ORCHARD_NOTE_V2, cmx_v2);
    assert(memcmp(cmx, cmx_v2, 32) != 0);
}

static void test_enc_v3(void) {
    uint8_t memo[512] = {0};
    memo[0] = 0xF6; /* ZIP-302 empty memo */

    uint8_t enc[580];
    uint8_t epk[32];
    int rc = orchard_compute_enc_ciphertext_from_rseed(
        k_recipient, k_recipient + 11, k_value, k_rseed, k_rho, memo,
        ORCHARD_NOTE_V3, enc, epk);
    assert(rc == 0);
    check("enc V3 epk", k_expected_epk_v3, epk, 32);
    check("enc V3 ciphertext[0..64]", k_expected_enc_v3_first64, enc, 64);
    check("enc V3 tag", k_expected_enc_v3_last16, enc + 564, 16);

    /* Legacy V2 path with the same inputs. */
    uint8_t enc2[580];
    uint8_t epk2[32];
    rc = orchard_compute_enc_ciphertext_from_rseed(
        k_recipient, k_recipient + 11, k_value, k_rseed, k_rho, memo,
        ORCHARD_NOTE_V2, enc2, epk2);
    assert(rc == 0);
    check("enc V2 epk (== V3)", k_expected_epk_v3, epk2, 32);
    check("enc V2 lead-byte ct", &k_expected_enc_v2_byte0, enc2, 1);
    check("enc V2 ciphertext[1..64]", k_expected_enc_v3_first64 + 1, enc2 + 1, 63);
    check("enc V2 tag", k_expected_enc_v2_last16, enc2 + 564, 16);
}

static void test_empty_digests(void) {
    uint8_t d[32];
    zip244_pool_empty_digest(ZIP244_POOL_ORCHARD, true, d);
    check("empty Orchard v6 digest (ZTxIdOrchardH_v6)", k_empty_orchard_v6, d, 32);
    zip244_pool_empty_digest(ZIP244_POOL_IRONWOOD, true, d);
    check("empty Ironwood v6 digest (ZTxIdIronwd_H_v6)", k_empty_ironwood_v6, d, 32);
    zip244_pool_empty_digest(ZIP244_POOL_ORCHARD, false, d);
    check("empty Orchard v5 digest (ZTxIdOrchardHash)", k_empty_orchard_v5, d, 32);
}

/* TxMeta v6 wire round-trip: parse(encode(meta)) == meta. */
static void test_tx_meta_v6_roundtrip(void) {
    Zip244TxMeta meta;
    memset(&meta, 0, sizeof(meta));
    meta.version = ZIP244_V6_TX_VERSION;
    meta.version_group_id = ZIP244_V6_VERSION_GROUP_ID;
    meta.consensus_branch_id = 0x37a5165b; /* NU6.3 */
    meta.lock_time = 7;
    meta.expiry_height = 4200000;
    meta.orchard_flags = 0x03;
    meta.value_balance = -123456789;
    memset(meta.anchor, 0xA1, 32);
    meta.is_v6 = true;
    meta.ironwood_flags = 0x07;
    meta.ironwood_value_balance = 123456789;
    memset(meta.ironwood_anchor, 0xB2, 32);
    memset(meta.transparent_sig_digest, 0xC3, 32);
    memset(meta.sapling_digest, 0xD4, 32);
    meta.coin_type = 133;

    uint8_t buf[ZIP244_TX_META_V6_EXT_SIZE];
    size_t n = zip244_encode_tx_meta(buf, &meta);
    assert(n == ZIP244_TX_META_V6_EXT_SIZE);

    Zip244TxMeta parsed;
    assert(zip244_parse_tx_meta(buf, n, &parsed));
    assert(parsed.is_v6);
    assert(parsed.version == meta.version);
    assert(parsed.version_group_id == meta.version_group_id);
    assert(parsed.consensus_branch_id == meta.consensus_branch_id);
    assert(parsed.lock_time == meta.lock_time);
    assert(parsed.expiry_height == meta.expiry_height);
    assert(parsed.orchard_flags == meta.orchard_flags);
    assert(parsed.value_balance == meta.value_balance);
    assert(memcmp(parsed.anchor, meta.anchor, 32) == 0);
    assert(parsed.ironwood_flags == meta.ironwood_flags);
    assert(parsed.ironwood_value_balance == meta.ironwood_value_balance);
    assert(memcmp(parsed.ironwood_anchor, meta.ironwood_anchor, 32) == 0);
    assert(memcmp(parsed.transparent_sig_digest, meta.transparent_sig_digest, 32) == 0);
    assert(memcmp(parsed.sapling_digest, meta.sapling_digest, 32) == 0);
    assert(parsed.coin_type == meta.coin_type);
    printf("PASS: TxMeta v6 wire round-trip\n");
}

/* ------------------------------------------------------------------ */
/* Full v6 shielded sighash, end-to-end against zcash_primitives.
 *
 * Reference transaction (tools/gen_ironwood_vectors, zcash_primitives
 * 0.29.0-pre.0 TxIdDigester + v6_signature_hash):
 *   v6, branch NU6.3 (0x37a5165b), lock_time 7, expiry 4_200_000,
 *   no transparent, no Sapling, EMPTY Orchard pool, and one Ironwood
 *   action built from the same V3 note as the vectors above with:
 *     rk       = ab8f01a0... (from ask = [0x07; 32])
 *     cv_net   = 177da8b4... (commit(12345678, trapdoor=1))
 *     out_ct   = [0x55; 80]
 *     flags    = 0x07, value_balance = +10000, anchor = empty tree
 *
 * The device reconstructs the full 820-byte action from primitives it
 * computes itself (cmx via rcm_v3, enc_ciphertext + epk via the V3
 * encryption path), drives the COMPLETE signer state machine (feed_meta →
 * feed_action_with_note_and_memo → per-action confirm → fee confirm →
 * verify), and must land on the exact sighash the Rust stack produced.
 */
static const uint8_t k_v6tx_rk[32] = {
    0xab, 0x8f, 0x01, 0xa0, 0x84, 0x5e, 0x54, 0xf6, 0x46, 0xda, 0xfb,
    0x87, 0x8c, 0xd6, 0x7f, 0x16, 0x63, 0x34, 0xc3, 0x22, 0xd0, 0x32,
    0x7b, 0x62, 0x43, 0x3e, 0xe7, 0xcc, 0x0f, 0x0a, 0x60, 0x87,
};
static const uint8_t k_v6tx_cv_net[32] = {
    0x17, 0x7d, 0xa8, 0xb4, 0xa7, 0xe4, 0x30, 0xe9, 0x35, 0xe6, 0xb4,
    0x35, 0x41, 0xe5, 0x6e, 0xea, 0xb9, 0x8a, 0x01, 0x0f, 0x82, 0xf7,
    0x93, 0x49, 0x19, 0xd4, 0x78, 0xc8, 0xa9, 0x4f, 0x82, 0x2e,
};
static const uint8_t k_v6tx_anchor[32] = {
    0xae, 0x29, 0x35, 0xf1, 0xdf, 0xd8, 0xa2, 0x4a, 0xed, 0x7c, 0x70,
    0xdf, 0x7d, 0xe3, 0xa6, 0x68, 0xeb, 0x7a, 0x49, 0xb1, 0x31, 0x98,
    0x80, 0xdd, 0xe2, 0xbb, 0xd9, 0x03, 0x1a, 0xe5, 0xd8, 0x2f,
};
static const uint8_t k_v6tx_expected_sighash[32] = {
    0x09, 0x7b, 0x59, 0x13, 0x61, 0xc3, 0xf6, 0xb5, 0x41, 0x24, 0xbf,
    0xa1, 0x37, 0xd6, 0x65, 0x90, 0x9b, 0x2e, 0xab, 0xb2, 0x84, 0xe4,
    0x33, 0x38, 0xec, 0xcf, 0x56, 0x99, 0x4b, 0xcc, 0xea, 0xd2,
};

static void build_v6_action(uint8_t action[820], uint8_t memo[512]) {
    memset(memo, 0, 512);
    memo[0] = 0xF6; /* ZIP-302 empty memo */

    uint8_t enc[580];
    uint8_t epk[32];
    int rc = orchard_compute_enc_ciphertext_from_rseed(
        k_recipient, k_recipient + 11, k_value, k_rseed, k_rho, memo,
        ORCHARD_NOTE_V3, enc, epk);
    assert(rc == 0);

    uint8_t cmx[32];
    orchard_compute_cmx(k_recipient, k_recipient + 11, k_value, k_rho,
                        k_rseed, ORCHARD_NOTE_V3, cmx);

    /* cv_net[32] || nullifier[32] || rk[32] || cmx[32] || epk[32] ||
     * enc_ciphertext[580] || out_ciphertext[80] */
    memcpy(action + 0, k_v6tx_cv_net, 32);
    memcpy(action + 32, k_rho, 32);
    memcpy(action + 64, k_v6tx_rk, 32);
    memcpy(action + 96, cmx, 32);
    memcpy(action + 128, epk, 32);
    memcpy(action + 160, enc, 580);
    memset(action + 740, 0x55, 80);
}

static void make_v6_meta(Zip244TxMeta *meta) {
    memset(meta, 0, sizeof(*meta));
    meta->version = ZIP244_V6_TX_VERSION;
    meta->version_group_id = ZIP244_V6_VERSION_GROUP_ID;
    meta->consensus_branch_id = 0x37a5165b; /* NU6.3 */
    meta->lock_time = 7;
    meta->expiry_height = 4200000;
    meta->orchard_flags = 0x03;      /* unused: Orchard pool absent */
    meta->value_balance = 0;
    meta->is_v6 = true;
    meta->ironwood_flags = 0x07;
    meta->ironwood_value_balance = 10000;
    memcpy(meta->ironwood_anchor, k_v6tx_anchor, 32);
    zip244_empty_digest("ZTxIdTranspaHash", meta->transparent_sig_digest);
    zip244_sapling_empty_digest(meta->sapling_digest);
    meta->coin_type = 133;
}

/* zip244 layer: digest tree only. */
static void test_v6_sighash_zip244(void) {
    uint8_t action[820];
    uint8_t memo[512];
    build_v6_action(action, memo);

    Zip244TxMeta meta;
    make_v6_meta(&meta);

    Zip244ActionsState ironwood;
    zip244_actions_init_pool(&ironwood, ZIP244_POOL_IRONWOOD, true);
    assert(zip244_hash_action(&ironwood, action, sizeof(action)));

    uint8_t sighash[32];
    zip244_shielded_sighash_v6(&meta, NULL, &ironwood, sighash);
    check("v6 shielded sighash (zip244 vs zcash_primitives)",
          k_v6tx_expected_sighash, sighash, 32);
}

/* Signer layer: the full on-device verification state machine. */
static void test_v6_sighash_full_signer(void) {
    uint8_t action[820];
    uint8_t memo[512];
    build_v6_action(action, memo);

    Zip244TxMeta meta;
    make_v6_meta(&meta);
    uint8_t meta_wire[ZIP244_TX_META_V6_EXT_SIZE];
    size_t meta_len = zip244_encode_tx_meta(meta_wire, &meta);
    assert(meta_len == ZIP244_TX_META_V6_EXT_SIZE);

    /* Any full viewing key will do here: this test is about the sighash,
     * and k_recipient belongs to nobody in particular (EXTERNAL). */
    static const uint8_t fvk_ak[32] = {[0 ... 31] = 0x10};
    static const uint8_t fvk_nk[32] = {[0 ... 31] = 0x20};
    static const uint8_t fvk_rivk[32] = {[0 ... 31] = 0x30};
    const OrchardSignerFvk fvk = {.ak = fvk_ak, .nk = fvk_nk, .rivk = fvk_rivk};

    static OrchardSignerCtx ctx;
    orchard_signer_init(&ctx, 133);

    assert(orchard_signer_feed_meta(&ctx, &fvk, meta_wire, meta_len, 1) == SIGNER_OK);
    assert(ctx.tx_meta.is_v6);

    assert(orchard_signer_feed_action_with_note_and_memo(
               &ctx, ZIP244_POOL_IRONWOOD, action, sizeof(action),
               k_recipient, k_value, k_rseed, memo) == SIGNER_OK);

    /* No-blind-signing invariants: confirm the output and the fee. */
    assert(orchard_signer_confirm_action(&ctx, 0) == SIGNER_OK);
    OrchardSignerTotals totals;
    assert(orchard_signer_get_totals(&ctx, &totals) == SIGNER_OK);
    uint64_t fee = totals.fee;
    assert(fee == 10000);
    assert(totals.total_leaving == k_value + 10000);
    assert(orchard_signer_confirm_totals(&ctx) == SIGNER_OK);

    /* verify() recomputes the whole v6 sighash and must accept the
     * zcash_primitives-produced value... */
    assert(orchard_signer_verify(&ctx, k_v6tx_expected_sighash) == SIGNER_OK);
    printf("PASS: full signer path on v6 Ironwood tx (fee=%llu)\n",
           (unsigned long long)fee);

    /* ...and a flipped-bit sighash must be rejected. */
    orchard_signer_init(&ctx, 133);
    assert(orchard_signer_feed_meta(&ctx, &fvk, meta_wire, meta_len, 1) == SIGNER_OK);
    assert(orchard_signer_feed_action_with_note_and_memo(
               &ctx, ZIP244_POOL_IRONWOOD, action, sizeof(action),
               k_recipient, k_value, k_rseed, memo) == SIGNER_OK);
    assert(orchard_signer_confirm_action(&ctx, 0) == SIGNER_OK);
    assert(orchard_signer_get_totals(&ctx, &totals) == SIGNER_OK);
    assert(orchard_signer_confirm_totals(&ctx) == SIGNER_OK);
    uint8_t bad[32];
    memcpy(bad, k_v6tx_expected_sighash, 32);
    bad[0] ^= 0x01;
    assert(orchard_signer_verify(&ctx, bad) == SIGNER_ERR_SIGHASH_MISMATCH);
    printf("PASS: v6 sighash mismatch rejected\n");
}

/* ── Shielded -> transparent, against the crates ─────────────────────
 * tests/test_ztot_vector.h is a transaction built by zcash_primitives'
 * Builder (tools/gen_ztot_vector): an Ironwood spend, a transparent P2PKH
 * output, Ironwood change and the builder's dummy output. The sighash is the
 * pczt Signer role's. The device must arrive at the same value from the
 * streamed data — which checks the transparent leaf for "outputs, no
 * inputs" — and must accept the dummy output with its 512 zero bytes of
 * memo through the mandatory ciphertext check. */
#include "test_ztot_vector.h"

static void test_ztot_crate_vector(void) {
    Zip244TxMeta meta;
    memset(&meta, 0, sizeof(meta));
    meta.version = ZTOT_VERSION;
    meta.version_group_id = ZTOT_VERSION_GROUP_ID;
    meta.consensus_branch_id = ZTOT_BRANCH_ID;
    meta.lock_time = ZTOT_LOCK_TIME;
    meta.expiry_height = ZTOT_EXPIRY_HEIGHT;
    meta.orchard_flags = ZTOT_ORCHARD_FLAGS;   /* absent bundle: as the PCZT has it */
    meta.value_balance = 0;
    meta.ironwood_flags = ZTOT_IRONWOOD_FLAGS;
    meta.ironwood_value_balance = ZTOT_IRONWOOD_VALUE_BALANCE;
    meta.coin_type = ZTOT_COIN_TYPE;
    zip244_sapling_empty_digest(meta.sapling_digest);
    assert(ZTOT_ORCHARD_ACTIONS == 0);

    /* transparent output: value[8] || len[2] || script */
    uint8_t t_out[10 + sizeof(ZTOT_T_OUT_SCRIPT)];
    for(int i = 0; i < 8; i++) t_out[i] = (uint8_t)(ZTOT_T_OUT_VALUE >> (8 * i));
    t_out[8] = (uint8_t)sizeof(ZTOT_T_OUT_SCRIPT);
    t_out[9] = 0;
    memcpy(t_out + 10, ZTOT_T_OUT_SCRIPT, sizeof(ZTOT_T_OUT_SCRIPT));
    Zip244TransparentState ts;
    uint8_t t_digest[32];
    zip244_transparent_init(&ts);
    assert(zip244_hash_transparent_output(&ts, t_out, sizeof(t_out)));
    zip244_transparent_digest(&ts, t_digest);
    memcpy(meta.transparent_sig_digest, t_digest, 32);

    uint8_t wire[ZIP244_TX_META_V6_EXT_SIZE];
    assert(zip244_encode_tx_meta(wire, &meta) == sizeof(wire));

    static OrchardSignerCtx ctx;
    OrchardSignerFvk fvk = {.ak = ZTOT_AK, .nk = ZTOT_NK, .rivk = ZTOT_RIVK};
    orchard_signer_init(&ctx, ZTOT_COIN_TYPE);
    assert(orchard_signer_feed_meta(&ctx, &fvk, wire, sizeof(wire), ZTOT_N_ACTIONS) == SIGNER_OK);
    assert(orchard_signer_begin_transparent(&ctx, 0, 1) == SIGNER_OK);
    assert(orchard_signer_feed_transparent_output(&ctx, t_out, sizeof(t_out)) == SIGNER_OK);
    assert(orchard_signer_verify_transparent(&ctx, t_digest) == SIGNER_OK);

    int n_change = 0, n_dummy = 0;
    for(int i = 0; i < ZTOT_N_ACTIONS; i++) {
        const uint8_t* a = ZTOT_ACTIONS[i];
        uint64_t value = 0;
        for(int b = 7; b >= 0; b--) value = (value << 8) | a[820 + 43 + b];
        /* What an honest host knows: the change it built has the ZIP 302
         * "no memo"; the builder's dummy has 512 zero bytes. */
        uint8_t memo[512];
        memset(memo, 0, sizeof(memo));
        if(value != 0) memo[0] = 0xF6;
        assert(orchard_signer_feed_action_with_note_and_memo(
                   &ctx, ZIP244_POOL_IRONWOOD, a, 820, a + 820, value, a + 820 + 43 + 8,
                   memo) == SIGNER_OK);
        OrchardOutputInfo info;
        assert(orchard_signer_get_output(&ctx, (uint16_t)i, &info) == SIGNER_OK);
        assert(info.memo == ORCHARD_MEMO_NONE && info.ciphertext_verified);
        if(value != 0) {
            assert(value == ZTOT_CHANGE_VALUE);
            assert(info.ownership == ORCHARD_OUTPUT_OWN_INTERNAL && info.review_required);
            assert(orchard_signer_confirm_action(&ctx, (uint16_t)i) == SIGNER_OK);
            n_change++;
        } else {
            assert(info.ownership == ORCHARD_OUTPUT_EXTERNAL && !info.review_required);
            n_dummy++;
        }
    }
    assert(n_change == 1 && n_dummy == 1);

    OrchardSignerTotals t;
    assert(orchard_signer_get_totals(&ctx, &t) == SIGNER_OK);
    assert(t.fee == ZTOT_FEE && t.transparent_out == ZTOT_T_OUT_VALUE);
    assert(t.total_leaving == ZTOT_T_OUT_VALUE + ZTOT_FEE && t.own_internal == ZTOT_CHANGE_VALUE);
    assert(orchard_signer_confirm_totals(&ctx) == SIGNER_OK);

    /* The crate's sighash, and nothing else, is accepted. */
    uint8_t wrong[32];
    memcpy(wrong, ZTOT_SIGHASH, 32);
    wrong[31] ^= 1;
    OrchardSignerCtx saved = ctx;
    assert(orchard_signer_verify(&ctx, wrong) == SIGNER_ERR_SIGHASH_MISMATCH);
    ctx = saved;
    assert(orchard_signer_verify(&ctx, ZTOT_SIGHASH) == SIGNER_OK);
    assert(ctx.state == SIGNER_VERIFIED);
    orchard_signer_reset(&ctx);
    printf("  PASS: z->t transaction built by zcash_primitives 0.31: device sighash == crate sighash\n");
}

int main(void) {
    test_empty_digests();
    test_tx_meta_v6_roundtrip();
    test_cmx_v3();
    test_enc_v3();
    test_v6_sighash_zip244();
    test_v6_sighash_full_signer();
    printf("All Ironwood cross-validation tests passed.\n");
    test_ztot_crate_vector();
    return 0;
}
