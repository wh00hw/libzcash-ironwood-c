/* Secret-residue regression test.
 *
 * The library keeps its large intermediates in `static` storage (the stack
 * budget is 512 B per function), so "wipe after use" has to hold for
 * .data/.bss, not only for the stack — on Flipper Zero an external app's
 * .bss is heap, and whatever is left there outlives the app.
 *
 * Method: run the same wallet sequence twice with two unrelated sets of
 * secrets (PIN, mnemonic, passphrase, note randomness), snapshot the whole
 * .data/.bss of this process after each run, and compare. Public state the
 * library legitimately keeps (curve constants, init flags, callbacks) is
 * identical in both snapshots; any byte that differs depends on the secrets
 * and is residue. This catches derived state (hash schedules, field
 * temporaries, key pads), not just verbatim copies of a key.
 *
 * The sequence: PIN KDF, seal + unseal, mnemonic -> seed, ZIP-32 and BIP-32
 * key derivation, ak, default address (current and legacy), RedPallas
 * signing (direct and domain-separated), ECDSA signing, per-action
 * verification (cmx + enc_ciphertext), HMAC and SHA-2 one-shots.
 *
 * Not covered by the pass/fail verdict: the dead stack. The library wipes
 * its named stack buffers, but what a compiler spills is outside the reach
 * of C; a verbatim scan of the dead stack is printed for information.
 *
 * ELF/Linux only (needs the linker's __data_start/_end); elsewhere the
 * test reports SKIP and passes. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "bip32.h"
#include "bip39.h"
#include "hmac.h"
#include "memzero.h"
#include "orchard.h"
#include "pallas.h"
#include "pbkdf2.h"
#include "redpallas.h"
#include "secp256k1.h"
#include "sha2.h"

#if defined(__linux__) && defined(__ELF__) && !defined(__SANITIZE_ADDRESS__)

extern char __data_start, _end;

typedef struct {
    const char* mnemonic;
    const char* passphrase;
    uint8_t pin[6];
    uint8_t fill; /* seeds the note randomness / messages */
} secrets;

/* Verbatim secrets remembered (XOR-masked) for the scans. This is the one
 * object of the test itself that differs between the two runs; its range is
 * excluded from the snapshot comparison. */
typedef struct {
    const char* name;
    uint8_t masked[16];
} pattern;
static pattern s_patterns[64];
static int s_num_patterns;

static void remember(const char* name, const uint8_t* p) {
    pattern* q = &s_patterns[s_num_patterns++];
    q->name = name;
    for(int i = 0; i < 16; i++) q->masked[i] = p[i] ^ 0xA5;
}

/* Everything the caller owns lives in this frame and is wiped before
 * returning, as an application is expected to do. */
__attribute__((noinline)) static void wallet_sequence(const secrets* s) {
    struct {
        uint8_t salt[16], key[AEAD_KEY_SIZE], nonce[AEAD_NONCE_SIZE], tag[AEAD_TAG_SIZE];
        uint8_t seed[64], sealed[64], unsealed[64];
        uint8_t sk[32], ask[32], nk[32], rivk[32], ak[32], tsk[32], tpk[33];
        uint8_t d[11], pk_d[32], d2[11], pk_d2[32];
        char ua[256];
        uint8_t alpha[32], sighash[32], sig[64], rk[32], personal[16];
        uint8_t tsig[64];
        uint8_t rho[32], rseed[32], cmx[32], epk[32], memo[512], enc[580];
        uint8_t mac[64], dig[64];
    } w;
    memset(&w, 0, sizeof(w));
    memset(w.salt, 0x11, sizeof(w.salt));
    memset(w.nonce, 0x22, sizeof(w.nonce));

    /* PIN -> AEAD key, seal and unseal the seed */
    wallet_pin_kdf(s->pin, sizeof(s->pin), w.salt, sizeof(w.salt), 64, w.key);
    remember("pin_key", w.key);
    remember("pin_key_mac", w.key + 32);
    mnemonic_to_seed(s->mnemonic, s->passphrase, w.seed, NULL);
    remember("seed", w.seed);
    remember("seed_hi", w.seed + 32);
    assert(aead_aes256_ctr_hmac_seal(w.key, w.nonce, NULL, 0, w.seed, 64, w.sealed, w.tag) == 0);
    assert(aead_aes256_ctr_hmac_unseal(w.key, w.nonce, NULL, 0, w.sealed, 64, w.tag, w.unsealed) == 0);
    assert(memcmp(w.seed, w.unsealed, 64) == 0);

    /* key derivation */
    orchard_derive_account_sk(w.seed, 1, 0, w.sk);
    remember("sk", w.sk);
    orchard_derive_keys(w.sk, w.ask, w.nk, w.rivk);
    remember("ask", w.ask);
    remember("nk", w.nk);
    remember("rivk", w.rivk);
    redpallas_derive_ak(w.ask, w.ak);
    assert(bip32_derive_transparent_sk(w.seed, 1, w.tsk, w.tpk) == 0);
    remember("t_sk", w.tsk);
    assert(orchard_derive_unified_address(w.seed, 1, 0, "utest", w.ua, sizeof(w.ua), w.d, w.pk_d) > 0);
    assert(orchard_derive_unified_address_legacy(
               w.seed, 1, 0, "utest", w.ua, sizeof(w.ua), w.d2, w.pk_d2) > 0);

    /* signing */
    memset(w.alpha, s->fill, 31);
    memset(w.sighash, s->fill ^ 0x5a, 32);
    memcpy(w.personal, "residue_test_sig", 16);
    assert(redpallas_sign(w.ask, w.alpha, w.sighash, w.sig, w.rk) == 0);
    assert(orchard_sign_with_personal(w.ask, w.personal, w.sighash, w.sig, w.rk) == 0);
    assert(secp256k1_ecdsa_sign_digest(w.tsk, w.sighash, w.tsig) == 0);

    /* per-action verification of an output to our own address */
    memset(w.rho, s->fill ^ 0x33, 32);
    w.rho[31] = 0x1a;
    memset(w.rseed, s->fill ^ 0xc3, 32);
    remember("rseed", w.rseed);
    w.memo[0] = 0xf6;
    orchard_compute_cmx(w.d, w.pk_d, 12345, w.rho, w.rseed, ORCHARD_NOTE_V3, w.cmx);
    assert(orchard_compute_enc_ciphertext_from_rseed(
               w.d, w.pk_d, 12345, w.rseed, w.rho, w.memo, ORCHARD_NOTE_V3, w.enc, w.epk) == 0);

    /* keyed one-shots */
    hmac_sha256(w.sk, 32, w.sighash, 32, w.mac);
    hmac_sha512(w.sk, 32, w.sighash, 32, w.mac);
    sha256_Raw(w.sk, 32, w.dig);
    sha512_Raw(w.sk, 32, w.dig);

    /* The g_d cache keeps the last diversifier's DiversifyHash. That is a
     * public value (it is part of the address), deliberately not wiped;
     * leave it on a fixed diversifier so the snapshots compare equal. */
    {
        static const uint8_t fixed_d[11] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
        memset(w.rseed, 0x44, 32);
        orchard_compute_cmx(fixed_d, w.pk_d, 1, w.rho, w.rseed, ORCHARD_NOTE_V3, w.cmx);
    }

    memzero(&w, sizeof(w));
}

/* Dead-stack window: 48 KB below main's frame, skipping the 512 bytes
 * nearest to it (live frames of main and of the copy itself). */
#define DEAD_STACK_BYTES (48u * 1024u)
#define DEAD_STACK_SKIP 512u

static size_t image_size(void) {
    return (size_t)(&_end - &__data_start);
}

/* Offsets are relative to __data_start; `nm -n` on the test binary maps
 * them to the static object that holds the residue. */
static int scan_verbatim(const char* region, const uint8_t* lo, size_t len, int fatal) {
    int hits = 0;
    for(int r = 0; r < s_num_patterns; r++) {
        uint8_t pat[16];
        for(int i = 0; i < 16; i++) pat[i] = s_patterns[r].masked[i] ^ 0xA5;
        const uint8_t* p = memmem(lo, len, pat, sizeof(pat));
        if(p) {
            printf("  %s: verbatim %s in %s at +0x%zx\n", fatal ? "RESIDUE" : "note",
                   s_patterns[r].name, region, (size_t)(p - lo));
            hits++;
        }
        memzero(pat, sizeof(pat));
    }
    return hits;
}

int main(void) {
    static const secrets A = {
        "legal winner thank year wave sausage worth useful legal winner thank year wave "
        "sausage worth useful legal winner thank year wave sausage worth title",
        "", {3, 1, 4, 1, 5, 9}, 0x17};
    static const secrets B = {
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
        "amount doctor acoustic avoid letter advice cage above",
        "TREZOR", {2, 7, 1, 8, 2, 8}, 0xe2};

    const size_t n = image_size();
    uint8_t* snap_a = malloc(n);
    uint8_t* snap_b = malloc(n);
    assert(snap_a && snap_b);

    pallas_init();
    /* warm-up, so one-time initialisation is not mistaken for residue */
    wallet_sequence(&B);

    /* The dead stack is copied to the heap right after the sequence returns
     * and scanned there: scanning it in place would find the scanner's own
     * copies of the patterns. */
    volatile uint8_t marker = 0;
    /* through a volatile integer: the compiler must not reason about reads
     * below `marker` (it would, rightly, call them out of bounds) */
    volatile uintptr_t marker_addr = (uintptr_t)&marker;
    const uint8_t* sp_hi = (const uint8_t*)marker_addr;
    uint8_t* stack_copy = malloc(DEAD_STACK_BYTES);
    assert(stack_copy);

    s_num_patterns = 0;
    wallet_sequence(&A);
    memcpy(stack_copy, sp_hi - DEAD_STACK_BYTES - DEAD_STACK_SKIP, DEAD_STACK_BYTES);
    memcpy(snap_a, &__data_start, n);
    int verbatim = scan_verbatim(".data/.bss", snap_a, n, 1);
    int stack_notes = scan_verbatim("dead stack", stack_copy, DEAD_STACK_BYTES, 0);

    s_num_patterns = 0;
    wallet_sequence(&B);
    memcpy(stack_copy, sp_hi - DEAD_STACK_BYTES - DEAD_STACK_SKIP, DEAD_STACK_BYTES);
    memcpy(snap_b, &__data_start, n);
    verbatim += scan_verbatim(".data/.bss", snap_b, n, 1);
    stack_notes += scan_verbatim("dead stack", stack_copy, DEAD_STACK_BYTES, 0);
    free(stack_copy);

    const size_t own_lo = (size_t)((const char*)s_patterns - &__data_start);
    const size_t own_hi = own_lo + sizeof(s_patterns);
    size_t differing = 0, runs = 0;
    for(size_t i = 0; i < n; i++) {
        if(i >= own_lo && i < own_hi) continue;
        if(snap_a[i] != snap_b[i]) {
            if(i == 0 || snap_a[i - 1] == snap_b[i - 1]) {
                if(runs < 400) printf("  RESIDUE: secret-dependent bytes at +0x%zx\n", i);
                runs++;
            }
            differing++;
        }
    }

    printf("test_residue: %zu bytes of .data/.bss scanned, %zu secret-dependent "
           "(%zu ranges), %d verbatim; dead stack: %d verbatim (informational)\n",
           n, differing, runs, verbatim, stack_notes);

    fflush(stdout);

    free(snap_a);
    free(snap_b);
    assert(differing == 0);
    assert(verbatim == 0);
    printf("test_residue: OK\n");
    return 0;
}

#else

int main(void) {
    printf("test_residue: SKIP (needs ELF/Linux linker symbols, no ASan)\n");
    return 0;
}

#endif
