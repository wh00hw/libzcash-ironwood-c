/**
 * Known-Answer Tests (KAT) for libzcash-orchard-c
 *
 * All expected values generated from librustzcash reference implementation.
 * See tools/gen_test_vectors/ for the generator.
 */

#include "blake2b.h"
#include "pallas.h"
#include "bignum.h"
#include "orchard.h"
#include "redpallas.h"
#include "bip39.h"
#include "memzero.h"
#include "test_vectors.h"
#include "test_address_vectors.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* ── Helpers ── */

static int total_tests = 0;
static int passed_tests = 0;

static void assert_eq_bytes(const char* name, const uint8_t* expected,
                            const uint8_t* actual, size_t len) {
    total_tests++;
    if (memcmp(expected, actual, len) == 0) {
        passed_tests++;
        printf("  PASS: %s\n", name);
    } else {
        printf("  FAIL: %s\n", name);
        printf("    expected: ");
        for (size_t i = 0; i < len && i < 16; i++) printf("%02x", expected[i]);
        if (len > 16) printf("...");
        printf("\n    actual:   ");
        for (size_t i = 0; i < len && i < 16; i++) printf("%02x", actual[i]);
        if (len > 16) printf("...");
        printf("\n");
    }
}

static void compress_point(const pallas_point* p, uint8_t out[32]) {
    bn_write_le(&p->x, out);
    if (p->y.val[0] & 1) out[31] |= 0x80;
}

/* ── BLAKE2b Personalized Tests ── */

static void test_blake2b_personalized(const char* name,
                                       const uint8_t* personal, size_t personal_len,
                                       const uint8_t* input, size_t input_len,
                                       const uint8_t* expected, size_t output_len) {
    uint8_t out[64];
    blake2b_state S;
    blake2b_InitPersonal(&S, output_len, personal, personal_len);
    blake2b_Update(&S, input, input_len);
    blake2b_Final(&S, out, output_len);
    assert_eq_bytes(name, expected, out, output_len);
}

static void test_all_blake2b(void) {
    printf("\nBLAKE2b Personalized Hashing:\n");

    test_blake2b_personalized("BLAKE2b ZcashIP32Orchard",
        (const uint8_t*)"ZcashIP32Orchard", 16,
        blake2b_zip32_orchard_input, blake2b_zip32_orchard_input_len,
        blake2b_zip32_orchard_expected, blake2b_zip32_orchard_output_len);

    test_blake2b_personalized("BLAKE2b Zcash_ExpandSeed",
        (const uint8_t*)"Zcash_ExpandSeed", 16,
        blake2b_expand_seed_input, blake2b_expand_seed_input_len,
        blake2b_expand_seed_expected, blake2b_expand_seed_output_len);

    test_blake2b_personalized("BLAKE2b Zcash_RedPallasN",
        (const uint8_t*)"Zcash_RedPallasN", 16,
        blake2b_redpallas_nonce_input, blake2b_redpallas_nonce_input_len,
        blake2b_redpallas_nonce_expected, blake2b_redpallas_nonce_output_len);

    test_blake2b_personalized("BLAKE2b Zcash_RedPallasH",
        (const uint8_t*)"Zcash_RedPallasH", 16,
        blake2b_redpallas_challenge_input, blake2b_redpallas_challenge_input_len,
        blake2b_redpallas_challenge_expected, blake2b_redpallas_challenge_output_len);

    test_blake2b_personalized("BLAKE2b ZTxIdOrchardHash",
        (const uint8_t*)"ZTxIdOrchardHash", 16,
        blake2b_tx_hash_input, blake2b_tx_hash_input_len,
        blake2b_tx_hash_expected, blake2b_tx_hash_output_len);
}

/* ── Pallas Hash-to-Curve Tests ── */

static void test_hash_to_curve(const char* name,
                                const char* domain,
                                const uint8_t* msg, size_t msg_len,
                                const uint8_t expected[32]) {
    pallas_point p;
    pallas_group_hash(&p, domain, msg, msg_len);
    uint8_t actual[32];
    compress_point(&p, actual);
    assert_eq_bytes(name, expected, actual, 32);
}

static void test_all_hash_to_curve(void) {
    printf("\nPallas Hash-to-Curve (Group Hash):\n");
    pallas_init();

    test_hash_to_curve("GroupHash z.cash:Orchard G",
        "z.cash:Orchard",
        htc_orchard_g_msg, htc_orchard_g_msg_len,
        htc_orchard_g_expected);

    test_hash_to_curve("GroupHash z.cash:Orchard-gd (d=0)",
        "z.cash:Orchard-gd",
        htc_orchard_gd_msg, htc_orchard_gd_msg_len,
        htc_orchard_gd_expected);

    /* SinsemillaQ test uses hash_to_curve, not group_hash */
    {
        pallas_point p;
        pallas_hash_to_curve(&p, "z.cash:SinsemillaQ",
            htc_sinsemilla_q_msg, htc_sinsemilla_q_msg_len);
        uint8_t actual[32];
        compress_point(&p, actual);
        assert_eq_bytes("HashToCurve SinsemillaQ",
            htc_sinsemilla_q_expected, actual, 32);
    }
}

/* ── Sinsemilla S-Table Tests ── */

static void test_sinsemilla_s_table(void) {
    printf("\nSinsemilla S-Table Samples:\n");
    pallas_init();

    static const uint8_t* expected_points[] = {
        sinsemilla_s_0_expected,
        sinsemilla_s_1_expected,
        sinsemilla_s_2_expected,
        sinsemilla_s_512_expected,
        sinsemilla_s_1023_expected,
    };

    for (size_t i = 0; i < sinsemilla_s_num_samples; i++) {
        uint32_t idx = sinsemilla_s_indices[i];
        uint8_t idx_le[4];
        idx_le[0] = idx & 0xff;
        idx_le[1] = (idx >> 8) & 0xff;
        idx_le[2] = (idx >> 16) & 0xff;
        idx_le[3] = (idx >> 24) & 0xff;

        pallas_point p;
        pallas_group_hash(&p, "z.cash:SinsemillaS", idx_le, 4);
        uint8_t actual[32];
        compress_point(&p, actual);

        char label[64];
        snprintf(label, sizeof(label), "SinsemillaS[%u]", idx);
        assert_eq_bytes(label, expected_points[i], actual, 32);
    }
}

/* ── ZIP-32 Key Derivation Tests ── */

static void test_zip32_derivation(void) {
    printf("\nZIP-32 Orchard Key Derivation:\n");
    pallas_init();

    /* Master key from seed */
    {
        uint8_t master[64];
        blake2b_state S;
        blake2b_InitPersonal(&S, 64, "ZcashIP32Orchard", 16);
        blake2b_Update(&S, zip32_seed, 64);
        blake2b_Final(&S, master, 64);
        assert_eq_bytes("ZIP-32 master sk", zip32_master_sk, master, 32);
        assert_eq_bytes("ZIP-32 master chain", zip32_master_chain, master + 32, 32);
    }

    /* Full derivation: seed -> sk -> keys -> ak */
    {
        uint8_t sk[32];
        orchard_derive_account_sk(zip32_seed, zip32_coin_type, zip32_account, sk);
        assert_eq_bytes("ZIP-32 spending key (account 0)", zip32_sk, sk, 32);

        uint8_t ask[32], nk[32], rivk[32];
        orchard_derive_keys(sk, ask, nk, rivk);

        uint8_t ak[32];
        redpallas_derive_ak(ask, ak);
        assert_eq_bytes("ZIP-32 ak", zip32_ak, ak, 32);
        assert_eq_bytes("ZIP-32 nk", zip32_nk, nk, 32);
        assert_eq_bytes("ZIP-32 rivk", zip32_rivk, rivk, 32);
    }

    /* Full address derivation */
    {
        uint8_t d[11], pk_d[32];
        char ua[256] = {0};
        int len = orchard_derive_unified_address(
            zip32_seed, zip32_coin_type, zip32_account,
            "u", ua, sizeof(ua), d, pk_d);
        assert(len > 0);
        assert_eq_bytes("ZIP-32 diversifier", zip32_diversifier, d, 11);
        assert_eq_bytes("ZIP-32 pk_d", zip32_pk_d, pk_d, 32);
    }
}

/* ── FF1-AES-256 Tests ── */

static void test_ff1_case(const char* name,
                           const uint8_t key[32],
                           const uint8_t input[11],
                           const uint8_t expected[11]) {
    uint8_t actual[11];
    ff1_aes256_encrypt(key, input, actual);
    assert_eq_bytes(name, expected, actual, 11);
}

static void test_all_ff1(void) {
    printf("\nFF1-AES-256 (Diversifier Derivation):\n");

    test_ff1_case("FF1 all-zero key + input",
        ff1_key_1, ff1_input_1, ff1_expected_1);
    test_ff1_case("FF1 patterned key + zero input",
        ff1_key_2, ff1_input_2, ff1_expected_2);
    test_ff1_case("FF1 0xAB key + non-zero input",
        ff1_key_3, ff1_input_3, ff1_expected_3);
}

/* ── RedPallas Deterministic Signing Tests ── */

static void test_redpallas_sign(void) {
    printf("\nRedPallas Signing (deterministic nonce):\n");
    pallas_init();

    uint8_t sig[64], rk[32];
    int ret = redpallas_sign(rp_ask, rp_alpha, rp_sighash, sig, rk);
    assert(ret == 0);

    assert_eq_bytes("RedPallas rk", rp_rk_expected, rk, 32);
    assert_eq_bytes("RedPallas sig (R || S)", rp_sig_expected, sig, 64);
}

/* ── Sinsemilla End-to-End Tests ── */

static void test_sinsemilla_end_to_end(void) {
    printf("\nSinsemilla End-to-End:\n");
    pallas_init();

    /* Test 1: HashToPoint with 10-bit message (single chunk) */
    {
        pallas_point result;
        sinsemilla_hash_to_point(&result,
            (const char*)sinse_htp_domain,
            sinse_htp_msg, sinse_htp_num_bits);
        uint8_t actual[32];
        compress_point(&result, actual);
        assert_eq_bytes("SinsemillaHashToPoint (10 bits, 1 chunk)",
            sinse_htp_expected, actual, 32);
    }

    /* Test 2: HashToPoint with 20-bit message (two chunks) */
    {
        pallas_point result;
        sinsemilla_hash_to_point(&result,
            (const char*)sinse_htp_domain,
            sinse_htp2_msg, sinse_htp2_num_bits);
        uint8_t actual[32];
        compress_point(&result, actual);
        assert_eq_bytes("SinsemillaHashToPoint (20 bits, 2 chunks)",
            sinse_htp2_expected, actual, 32);
    }

    /* Test 3: ShortCommit (IVK-style, 510 zero bits) */
    {
        bignum256 rcm;
        bn_read_le(sinse_sc_rcm, &rcm);

        bignum256 result;
        sinsemilla_short_commit(&result,
            (const char*)sinse_sc_domain,
            sinse_sc_msg, sinse_sc_num_bits,
            &rcm);

        uint8_t actual[32];
        bn_write_le(&result, actual);
        if (result.val[0] & 1) { /* sign bit not needed for x-coordinate output */ }
        /* The expected value is the compressed point (x with sign bit).
         * ShortCommit returns x-coordinate as a field element, which we
         * compare to the compressed point's x (ignoring sign bit). */
        uint8_t expected_x[32];
        memcpy(expected_x, sinse_sc_expected, 32);
        expected_x[31] &= 0x7F; /* clear sign bit for comparison */
        actual[31] &= 0x7F;
        assert_eq_bytes("SinsemillaShortCommit (510 zero bits)",
            expected_x, actual, 32);
    }
}

/* ── F4Jumble Tests ── */

static void test_f4jumble_case(const char* name,
                                const uint8_t* input, size_t len,
                                const uint8_t* expected) {
    uint8_t buf[256];
    assert(len <= sizeof(buf));
    memcpy(buf, input, len);
    f4jumble(buf, len);
    assert_eq_bytes(name, expected, buf, len);
}

static void test_all_f4jumble(void) {
    printf("\nF4Jumble (ZIP-316):\n");

    test_f4jumble_case("F4Jumble 48 bytes (min)",
        f4j_input_1, f4j_len_1, f4j_expected_1);
    test_f4jumble_case("F4Jumble 83 bytes (typical UA)",
        f4j_input_2, f4j_len_2, f4j_expected_2);
    test_f4jumble_case("F4Jumble 128 bytes",
        f4j_input_3, f4j_len_3, f4j_expected_3);
}

/* ── ZIP-32 Child Key Intermediates ── */

static void test_zip32_intermediates(void) {
    printf("\nZIP-32 Child Key Intermediates (per-hop):\n");

    uint8_t sk[32], cc[32], sk_child[32], cc_child[32];

    /* Master */
    orchard_master_key(zip32_seed, sk, cc);
    assert_eq_bytes("ZIP-32 master sk (verify)", zip32_master_sk, sk, 32);

    /* Hop 1: m / 32' */
    orchard_child_key(sk, cc, 0x80000000 | 32, sk_child, cc_child);
    assert_eq_bytes("ZIP-32 hop1 sk (m/32')", zip32_hop1_sk, sk_child, 32);
    assert_eq_bytes("ZIP-32 hop1 cc (m/32')", zip32_hop1_cc, cc_child, 32);

    memcpy(sk, sk_child, 32);
    memcpy(cc, cc_child, 32);

    /* Hop 2: m / 32' / 133' */
    orchard_child_key(sk, cc, 0x80000000 | 133, sk_child, cc_child);
    assert_eq_bytes("ZIP-32 hop2 sk (m/32'/133')", zip32_hop2_sk, sk_child, 32);
    assert_eq_bytes("ZIP-32 hop2 cc (m/32'/133')", zip32_hop2_cc, cc_child, 32);

    memcpy(sk, sk_child, 32);
    memcpy(cc, cc_child, 32);

    /* Hop 3: m / 32' / 133' / 0' */
    orchard_child_key(sk, cc, 0x80000000 | 0, sk_child, cc_child);
    assert_eq_bytes("ZIP-32 hop3 sk (m/32'/133'/0')", zip32_hop3_sk, sk_child, 32);
    assert_eq_bytes("ZIP-32 hop3 cc (m/32'/133'/0')", zip32_hop3_cc, cc_child, 32);
}

/* ── Sinsemilla with Real IVK Data ── */

static void test_sinsemilla_real_ivk(void) {
    printf("\nSinsemilla ShortCommit with real ZIP-32 data:\n");
    pallas_init();

    bignum256 rcm;
    bn_read_le(sinse_real_ivk_rivk, &rcm);

    bignum256 result;
    sinsemilla_short_commit(&result,
        "z.cash:Orchard-CommitIvk",
        sinse_real_ivk_msg, sinse_real_ivk_num_bits,
        &rcm);

    uint8_t actual[32];
    bn_write_le(&result, actual);
    uint8_t expected_x[32];
    memcpy(expected_x, sinse_real_ivk_expected, 32);
    expected_x[31] &= 0x7F;
    actual[31] &= 0x7F;
    assert_eq_bytes("SinsemillaShortCommit (real ak||nk, rivk from ZIP-32)",
        expected_x, actual, 32);
}

/* ── FF1-AES with Real dk ── */

static void test_ff1_real_dk(void) {
    printf("\nFF1-AES-256 with real dk from ZIP-32:\n");

    uint8_t actual[11];
    ff1_aes256_encrypt(ff1_real_dk, ff1_real_input, actual);
    assert_eq_bytes("FF1 real dk -> diversifier", ff1_real_diversifier, actual, 11);
}

/* ── RedPallas Extra Cases ── */

static void test_redpallas_extra(void) {
    printf("\nRedPallas Extra Test Cases:\n");
    pallas_init();

    /* Case 2: alpha = 0 */
    {
        uint8_t sig[64], rk[32];
        int ret = redpallas_sign(rp2_ask, rp2_alpha, rp2_sighash, sig, rk);
        assert(ret == 0);
        assert_eq_bytes("RedPallas #2 rk (alpha=0)", rp2_rk_expected, rk, 32);
        assert_eq_bytes("RedPallas #2 sig (alpha=0)", rp2_sig_expected, sig, 64);
    }

    /* Case 3: sighash = 0 */
    {
        uint8_t sig[64], rk[32];
        int ret = redpallas_sign(rp3_ask, rp3_alpha, rp3_sighash, sig, rk);
        assert(ret == 0);
        assert_eq_bytes("RedPallas #3 rk (sighash=0)", rp3_rk_expected, rk, 32);
        assert_eq_bytes("RedPallas #3 sig (sighash=0)", rp3_sig_expected, sig, 64);
    }

    /* Case 4: large scalars */
    {
        uint8_t sig[64], rk[32];
        int ret = redpallas_sign(rp4_ask, rp4_alpha, rp4_sighash, sig, rk);
        assert(ret == 0);
        assert_eq_bytes("RedPallas #4 rk (large scalars)", rp4_rk_expected, rk, 32);
        assert_eq_bytes("RedPallas #4 sig (large scalars)", rp4_sig_expected, sig, 64);
    }
}

/* ── F4Jumble Inverse ── */

static void test_f4jumble_inverse(void) {
    printf("\nF4Jumble Inverse (Round-Trip):\n");

    /* Forward: input -> jumbled */
    uint8_t buf[256];
    memcpy(buf, f4j_inv_input, f4j_inv_len);
    f4jumble(buf, f4j_inv_len);
    assert_eq_bytes("F4Jumble forward", f4j_inv_jumbled, buf, f4j_inv_len);

    /* Inverse: jumbled -> input */
    memcpy(buf, f4j_inv_jumbled, f4j_inv_len);
    f4jumble_inv(buf, f4j_inv_len);
    assert_eq_bytes("F4Jumble inverse (round-trip)", f4j_inv_input, buf, f4j_inv_len);
}

/* ── Orchard NoteCommitment (cmx) ── */

static void test_orchard_note_commit(void) {
    printf("\nOrchard NoteCommitment (cmx, vs librustzcash Note::commitment):\n");

    /* note_commit_recipient = d[11] || pk_d[32] (43 bytes raw Orchard address) */
    const uint8_t* d    = note_commit_recipient;
    const uint8_t* pk_d = note_commit_recipient + 11;

    uint8_t cmx[32];
    orchard_compute_cmx(d, pk_d, note_commit_value,
                        note_commit_rho, note_commit_rseed, ORCHARD_NOTE_V2, cmx);

    assert_eq_bytes("orchard_compute_cmx", note_commit_expected_cmx, cmx, 32);
}

/* ── Orchard Unified Address encoding from raw (d, pk_d) ── */

static void test_orchard_encode_ua_raw(void) {
    printf("\nOrchard UA encoding from raw (d, pk_d) — vs librustzcash + ZIP-316:\n");

    const uint8_t* d    = note_commit_recipient;
    const uint8_t* pk_d = note_commit_recipient + 11;

    char ua[256] = {0};
    int n = orchard_encode_ua_raw(d, pk_d, "u", ua, sizeof(ua));

    /* String length matches reference. */
    if (n != (int)ua_encoded_mainnet_len) {
        fprintf(stderr, "  FAIL: orchard_encode_ua_raw length: expected %zu, got %d\n",
                ua_encoded_mainnet_len, n);
        total_tests++;
        return;
    }
    /* String content matches byte-for-byte. */
    if (memcmp(ua, ua_encoded_mainnet, ua_encoded_mainnet_len) != 0) {
        fprintf(stderr, "  FAIL: orchard_encode_ua_raw\n");
        fprintf(stderr, "    expected: %s\n", ua_encoded_mainnet);
        fprintf(stderr, "    got:      %s\n", ua);
        total_tests++;
        return;
    }
    printf("  PASS: orchard_encode_ua_raw (mainnet) → %s\n", ua);
    total_tests++;
    passed_tests++;
}

/* ── Default address vs the orchard crate (tests/test_address_vectors.h) ── */

static void check_true(const char* name, int cond) {
    total_tests++;
    if (cond) {
        passed_tests++;
        printf("  PASS: %s\n", name);
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/* Sixteen (seed, network) pairs, seven of them with an odd-y [ask]G — the
 * case in which releases up to a55d168 derived the diversifier key from the
 * un-normalised ak encoding and returned an address no FVK-based wallet
 * would show. For each: ak and the default (d, pk_d) must equal the crate's,
 * the legacy entry point must reproduce the pre-fix address, and the two
 * must differ exactly when [ask]G is odd. */
static void test_default_address_vectors(void) {
    printf("\nDefault address (orchard 0.16.0, even and odd [ask]G):\n");

    int odd_seen = 0;
    for (int i = 0; i < ADDRESS_VECTORS_COUNT; i++) {
        const address_vector* v = &ADDRESS_VECTORS[i];
        const char* hrp = (v->coin_type == 133) ? "u" : "utest";
        char label[96];

        uint8_t sk[32], ask[32], nk[32], rivk[32], ak[32];
        orchard_derive_account_sk(v->seed, v->coin_type, 0, sk);
        orchard_derive_keys(sk, ask, nk, rivk);
        redpallas_derive_ak(ask, ak);
        snprintf(label, sizeof(label), "%s: ak", v->name);
        assert_eq_bytes(label, v->ak, ak, 32);

        uint8_t d[11], pk_d[32];
        char ua[256] = {0}, ua_ref[256] = {0};
        int len = orchard_derive_unified_address(
            v->seed, v->coin_type, 0, hrp, ua, sizeof(ua), d, pk_d);
        snprintf(label, sizeof(label), "%s: d%s", v->name, v->ak_odd ? " (odd y)" : "");
        assert_eq_bytes(label, v->d, d, 11);
        snprintf(label, sizeof(label), "%s: pk_d", v->name);
        assert_eq_bytes(label, v->pk_d, pk_d, 32);
        int ref_len = orchard_encode_ua_raw(v->d, v->pk_d, hrp, ua_ref, sizeof(ua_ref));
        snprintf(label, sizeof(label), "%s: UA string", v->name);
        check_true(label, len > 0 && len == ref_len && strcmp(ua, ua_ref) == 0);

        uint8_t ld[11], lpk_d[32];
        char lua[256] = {0};
        int llen = orchard_derive_unified_address_legacy(
            v->seed, v->coin_type, 0, hrp, lua, sizeof(lua), ld, lpk_d);
        snprintf(label, sizeof(label), "%s: legacy d", v->name);
        assert_eq_bytes(label, v->legacy_d, ld, 11);
        snprintf(label, sizeof(label), "%s: legacy pk_d", v->name);
        assert_eq_bytes(label, v->legacy_pk_d, lpk_d, 32);
        int same = llen == len && strcmp(lua, ua) == 0 && memcmp(ld, d, 11) == 0 &&
                   memcmp(lpk_d, pk_d, 32) == 0;
        snprintf(label, sizeof(label), "%s: legacy %s current", v->name,
                 v->ak_odd ? "!=" : "==");
        check_true(label, llen > 0 && same == !v->ak_odd);
        odd_seen += v->ak_odd;
    }
    check_true("vector set covers both parities",
               odd_seen == ADDRESS_VECTORS_ODD_COUNT && odd_seen >= 4 &&
               ADDRESS_VECTORS_COUNT - odd_seen >= 4);
}

/* ── Main ── */

int main(void) {
    printf("Known-Answer Tests (cross-checked against librustzcash):\n");

    test_all_blake2b();
    test_all_hash_to_curve();
    test_sinsemilla_s_table();
    test_zip32_derivation();
    test_all_ff1();
    test_redpallas_sign();
    test_sinsemilla_end_to_end();
    test_all_f4jumble();
    test_zip32_intermediates();
    test_sinsemilla_real_ivk();
    test_ff1_real_dk();
    test_redpallas_extra();
    test_f4jumble_inverse();
    test_orchard_note_commit();
    test_orchard_encode_ua_raw();
    test_default_address_vectors();

    printf("\n=== Results: %d/%d tests passed ===\n", passed_tests, total_tests);

    return (passed_tests == total_tests) ? 0 : 1;
}
