/*
 * test_secp256k1.c — known-answer tests for the transparent key path:
 * secp256k1 scalar multiplication, BIP-32 derivation and the Zcash BIP-44
 * transparent key.
 *
 * WHY THIS FILE EXISTS. Until November 2026 the library had no secp256k1
 * known-answer test, and the arithmetic was wrong: sfp_mul(r, a, b) copied
 * `a` into `r` before reading `b`, so with r == b (the line
 * `sfp_mul(&y3, &rr, &y3)` of the mixed addition and its twin in the
 * doubling) it computed a*a. 1*G and the x-coordinate of 2*G came out
 * right; every other multiple was wrong — 3*G gave 03909038d6... instead of
 * 02f9308a01... — and with it every transparent public key, BIP-32
 * non-hardened child and ECDSA signature the library ever produced.
 *
 * References (independent of this library):
 *   - k*G: affine textbook arithmetic over the integers (Python), which
 *     reproduces the published small multiples of G (2G = c6047f94...,
 *     3G = f9308a01...).
 *   - BIP-32: test vector 2 of the BIP (its seed is 64 bytes, the size
 *     bip32_master_key() takes).
 *   - Zcash: m/44'/133'/0'/0/0 of the BIP-39 "abandon ... about" mnemonic,
 *     03db98d8..., as derived by zcash_transparent; m/44'/1'/0'/0/0 from the
 *     same reference arithmetic.
 *   - ECDSA (only with ZCASH_ENABLE_TRANSPARENT_SIGNING=1): the RFC 6979
 *     "Satoshi Nakamoto" vector for the key 1.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bip32.h"
#include "bip39.h"
#include "options.h"
#include "secp256k1.h"

static void hx(const char* s, uint8_t* out, size_t n) {
    for(size_t i = 0; i < n; i++) {
        unsigned v;
        assert(sscanf(s + 2 * i, "%2x", &v) == 1);
        out[i] = (uint8_t)v;
    }
}

static const struct { const char* k; const char* pub; } KG[] = {
    {"0000000000000000000000000000000000000000000000000000000000000001", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"},
    {"0000000000000000000000000000000000000000000000000000000000000008", "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"},
    /* n-1 = -G, n-2 = -2G */
    {"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
    {"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f", "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"},
    {"8000000000000000000000000000000000000000000000000000000000000000", "02b23790a42be63e1b251ad6c94fdef07271ec0aada31db6c3e8bd32043f8be384"},
    {"00000000000000000000000000000000ffffffffffffffffffffffffffffffff", "036c034fd8cc8bd548e12569b630710400e6c24a05d9d6b32f08522a241e936da8"},
    /* random scalars */
    {"e2d09110bbfaf9dad1a84e2161ebd21834991a7b815a2788ca2339e135f0b12d", "02ee6b1e0d8ee80033a99826c8a8f0e5fb579a73bcaa4aa162b5a84efe069c38ef"},
    {"3e546e43c2a572b8e2830ecb1da744c1fa4f03229aa36a67f50c37993ff3f089", "028c4ac222d14c5ea0806d3113215c2aa640f01c03919a91ae665a70c40e5abba9"},
    {"f71f2f1d351fca738afce2e9796a69d3cb30daab2d07e2ce5aa772736f744c64", "02e1f9c794eb6c74966d9bc33d218c82a9c555ee4ad5db9bc72ddfa118ba69c0d2"},
    {"f51a41634df4a9e18508de5f067cfdf86ffb2a5f6e524fd57e60f8f33b4140c6", "022e5689dff524cf912a4d3bd6d3995bd0ba49001b1689a8d93e7df0854539480a"},
    {"1e81de38ab9efcf13ff5eef9dc979a26dcec557eb0120afc8731f50f17745600", "02a6104009031349debeee621e835cb71a84e686c3fc575c48e7e528cfc571caf2"},
    {"1bf3c7fd04368aae8a796c12f0c6fe91e9127e5bd6e91ba7bac2f24a575c9837", "02aa40e03f53152528426371bf5097a433b601eb3327f3bfa3cb6892a5fa05e421"},
    {"605f1a1469ae708f30746a98d94efde3f751440c53c4aceffba21fac9f63e318", "02da1d9d9da7086a90ffc698fdc9b2df32e8cae6380df1da873a54d6643820b86c"},
    {"f5d83848a120bfb4e23d2117bfb0b910698ed2d80df45be30cdf6f924bb63999", "02036d78846909283bd31944c1f2cdb31901614ebd6220bb8b4fdddccefd4be2e1"},
};

static void test_scalar_mul(void) {
    for(size_t i = 0; i < sizeof(KG) / sizeof(KG[0]); i++) {
        uint8_t k[32], want[33], got[33];
        hx(KG[i].k, k, 32);
        hx(KG[i].pub, want, 33);
        assert(secp256k1_get_public_key33(k, got) == 0);
        if(memcmp(got, want, 33) != 0) {
            fprintf(stderr, "k*G mismatch for k = %s\n", KG[i].k);
            assert(0);
        }
    }
    /* 0 and n are not keys. */
    uint8_t z[32] = {0}, out[33];
    assert(secp256k1_get_public_key33(z, out) != 0);
    hx("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", z, 32);
    assert(secp256k1_get_public_key33(z, out) != 0);
    printf("  PASS: k*G for k = 1..10, n-1, n-2, 2^255, 2^128-1 and 8 random scalars\n");
}

static void check_node(const Bip32ExtKey* k, const char* priv, const char* chain,
                       const char* pub) {
    uint8_t b[33], got[33];
    hx(priv, b, 32);
    assert(memcmp(k->key, b, 32) == 0);
    if(chain) {
        hx(chain, b, 32);
        assert(memcmp(k->chaincode, b, 32) == 0);
    }
    hx(pub, b, 33);
    assert(secp256k1_get_public_key33(k->key, got) == 0);
    assert(memcmp(got, b, 33) == 0);
}

static void test_bip32_vector2(void) {
    uint8_t seed[64];
    hx("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
       "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", seed, 64);
    Bip32ExtKey m, a, b, c;
    bip32_master_key(seed, &m);
    check_node(&m, "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
               "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
               "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7");
    /* m/0 — a NON-hardened child: needs the parent public key, i.e. the
     * scalar multiplication that was wrong. */
    assert(bip32_derive_child(&m, 0, &a) == 0);
    check_node(&a, "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e", NULL,
               "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea");
    assert(bip32_derive_child(&a, 2147483647u | 0x80000000u, &b) == 0);
    check_node(&b, "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93", NULL,
               "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b");
    assert(bip32_derive_child(&b, 1, &c) == 0);
    check_node(&c, "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7", NULL,
               "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9");
    printf("  PASS: BIP-32 test vector 2: m, m/0, m/0/2147483647', m/0/2147483647'/1\n");
}

static void test_zcash_bip44(void) {
    uint8_t seed[64], sk[32], pub[33], want_sk[32], want_pub[33];
    mnemonic_to_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon about",
        "", seed, NULL);
    assert(bip32_derive_transparent_sk(seed, 133, sk, pub) == 0);
    hx("59eb13b2361c4fee7dcc028444052c64d28f40a89db24ead9e14ab48c260a0d7", want_sk, 32);
    hx("03db98d8f87716269ed31879aef19bdadbc869a9ea67729e36332d023b916cbcc9", want_pub, 33);
    assert(memcmp(sk, want_sk, 32) == 0 && memcmp(pub, want_pub, 33) == 0);
    assert(bip32_derive_transparent_sk(seed, 1, sk, pub) == 0);
    hx("e01fea8a48e2854fdd0255c12b1d704967d9401f11c3f4980006ced8977574dc", want_sk, 32);
    hx("02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6", want_pub, 33);
    assert(memcmp(sk, want_sk, 32) == 0 && memcmp(pub, want_pub, 33) == 0);
    printf("  PASS: Zcash m/44'/133'/0'/0/0 and m/44'/1'/0'/0/0 of 'abandon ... about'\n");
}

#if ZCASH_ENABLE_TRANSPARENT_SIGNING
static void test_ecdsa_rfc6979(void) {
    static const struct { const char* sk; const char* digest; const char* sig; } V[] = {
        /* sha256("Satoshi Nakamoto"), key 1 */
        {"0000000000000000000000000000000000000000000000000000000000000001",
         "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e",
         "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
         "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"},
        {"59eb13b2361c4fee7dcc028444052c64d28f40a89db24ead9e14ab48c260a0d7",
         "16189374079484bbe1cd6a748a977908c8bee685fd08aac143cef4fb8fa288e3",
         "459c2257eb66280eed325fd3189f8fae071e2798ab8d704cf4b8328d2587043d"
         "4116d6644c3c1037a351357ed40196e31416d0d273394664a36ba58c8b3195e0"},
    };
    for(size_t i = 0; i < 2; i++) {
        uint8_t sk[32], dg[32], want[64], got[64];
        hx(V[i].sk, sk, 32);
        hx(V[i].digest, dg, 32);
        hx(V[i].sig, want, 64);
        assert(secp256k1_ecdsa_sign_digest(sk, dg, got) == 0);
        assert(memcmp(got, want, 64) == 0);
    }
    printf("  PASS: ECDSA / RFC 6979 known answers (ZCASH_ENABLE_TRANSPARENT_SIGNING=1)\n");
}
#endif

int main(void) {
    printf("secp256k1 / BIP-32 known-answer tests:\n");
    test_scalar_mul();
    test_bip32_vector2();
    test_zcash_bip44();
#if ZCASH_ENABLE_TRANSPARENT_SIGNING
    test_ecdsa_rfc6979();
#else
    printf("  (ECDSA signing is compiled out: ZCASH_ENABLE_TRANSPARENT_SIGNING=0)\n");
#endif
    printf("All secp256k1 tests passed.\n");
    return 0;
}
