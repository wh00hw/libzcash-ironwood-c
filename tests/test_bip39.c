/*
 * BIP-39 wordlist and mnemonic encoding: official test vectors (entropy ->
 * mnemonic, from the BIP-39 reference vectors) and a round trip over every
 * word of the list.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bip39.h"

static void hex(const char* h, uint8_t* out, size_t n) {
    for(size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static const struct {
    const char* entropy;
    const char* mnemonic;
} V[] = {
    {"00000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
    {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank yellow"},
    {"80808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"},
    {"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon art"},
    {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
     "zoo vote"},
    {"9e885d952ad362caeb4efe34a8e91bd2",
     "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"},
    {"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
     "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing "
     "screen patrol group space point ten exist slush involve unfold"},
};

int main(void) {
    for(size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
        uint8_t ent[32];
        size_t n = strlen(V[i].entropy) / 2;
        hex(V[i].entropy, ent, n);
        const char* m = mnemonic_from_data(ent, (int)n);
        assert(m != NULL && strcmp(m, V[i].mnemonic) == 0);
        assert(mnemonic_check(V[i].mnemonic));
        mnemonic_clear();
    }
    printf("  PASS: %zu BIP-39 reference vectors (entropy -> mnemonic, checksum)\n",
           sizeof(V) / sizeof(V[0]));

    /* Every word: within the row width, NUL-terminated, sorted, and found
     * again at its own index. */
    for(int i = 0; i < BIP39_WORD_COUNT; i++) {
        const char* w = mnemonic_get_word(i);
        assert(w != NULL);
        size_t len = strlen(w);
        assert(len >= 3 && len <= BIP39_WORD_MAX_LEN);
        assert(mnemonic_find_word(w) == i);
        if(i > 0) assert(strcmp(mnemonic_get_word(i - 1), w) < 0);
    }
    assert(strcmp(mnemonic_get_word(0), "abandon") == 0);
    assert(strcmp(mnemonic_get_word(2047), "zoo") == 0);
    assert(mnemonic_find_word("notaword") < 0);
    /* A bad checksum is refused. */
    assert(!mnemonic_check(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"));
    printf("  PASS: all 2048 words round-trip, sorted, within %d characters\n", BIP39_WORD_MAX_LEN);
    printf("All BIP-39 tests passed.\n");
    return 0;
}
