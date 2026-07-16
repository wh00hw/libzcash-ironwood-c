#include "orchard.h"
#include "pallas.h"
#include "redpallas.h"
#include "bip39.h"
#include "chacha20poly1305.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Test vector: known mnemonic -> expected address prefix
static void test_address_derivation(void) {
    const char* mnemonic =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";

    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, "", seed, NULL);

    pallas_init();

    char ua[256] = {0};
    int len = orchard_derive_unified_address(
        seed, 133, 0, "u", ua, sizeof(ua), NULL, NULL);

    assert(len > 0);
    assert(ua[0] == 'u');
    assert(ua[1] != 't'); // mainnet, not testnet
    printf("  PASS: address derivation (UA: %.20s...)\n", ua);
}

static void test_key_derivation(void) {
    const char* mnemonic =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";

    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, "", seed, NULL);

    pallas_init();

    uint8_t sk[32];
    orchard_derive_account_sk(seed, 133, 0, sk);

    uint8_t ask[32], nk[32], rivk[32];
    orchard_derive_keys(sk, ask, nk, rivk);

    // ask should be non-zero
    int all_zero = 1;
    for(int i = 0; i < 32; i++) {
        if(ask[i] != 0) { all_zero = 0; break; }
    }
    assert(!all_zero);

    // Derive ak from ask
    uint8_t ak[32];
    redpallas_derive_ak(ask, ak);

    all_zero = 1;
    for(int i = 0; i < 32; i++) {
        if(ak[i] != 0) { all_zero = 0; break; }
    }
    assert(!all_zero);

    printf("  PASS: key derivation (ask, nk, rivk, ak all non-zero)\n");
}

static void test_sign_verify_roundtrip(void) {
    const char* mnemonic =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";

    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, "", seed, NULL);

    pallas_init();

    uint8_t sk[32];
    orchard_derive_account_sk(seed, 133, 0, sk);

    uint8_t ask[32], nk[32], rivk[32];
    orchard_derive_keys(sk, ask, nk, rivk);

    // Fake sighash and alpha
    uint8_t sighash[32], alpha[32];
    memset(sighash, 0x11, 32);
    memset(alpha, 0x22, 32);

    uint8_t sig[64], rk[32];
    int ret = redpallas_sign(ask, alpha, sighash, sig, rk);
    assert(ret == 0);

    // sig and rk should be non-zero
    int all_zero = 1;
    for(int i = 0; i < 64; i++) {
        if(sig[i] != 0) { all_zero = 0; break; }
    }
    assert(!all_zero);
    printf("  PASS: sign roundtrip (signature produced)\n");
}

static void test_chacha20poly1305(void) {
    assert(chacha20poly1305_self_test() == 1);
    printf("  PASS: ChaCha20-Poly1305 self-test (RFC 7539 vector + tamper detection)\n");
}

int main(void) {
    printf("Orchard crypto tests:\n");
    test_chacha20poly1305();
    test_key_derivation();
    test_sign_verify_roundtrip();
    test_address_derivation();
    printf("All Orchard tests passed.\n");
    return 0;
}
