#include "redpallas.h"
#include "pallas.h"
#include "bignum.h"
#include "blake2b.h"
#include "rand.h"
#include "memzero.h"
#include <string.h>

// Constant-time modular reduction: r = r mod q.
// Performs a fixed number of conditional subtractions to avoid
// leaking the magnitude of r through loop iteration count.
// After bn_lshift or bn_add, r < 2*q, so 2 iterations suffice.
// We do 3 for safety margin with wider intermediates.
static void fq_full_reduce(bignum256* r) {
    const bignum256* q = pallas_q();
    bignum256 tmp;
    bn_normalize(r);
    for(int i = 0; i < 3; i++) {
        int ge = !bn_is_less(r, q); // 1 if r >= q
        bn_copy(r, &tmp);
        bn_subtract(&tmp, q, &tmp);
        bn_normalize(&tmp);
        bn_cmov(r, ge, &tmp, r);
    }
}

// Scalar addition mod q: r = (a + b) mod q
static void fq_add(bignum256* r, const bignum256* a, const bignum256* b) {
    bn_copy(a, r);
    bn_add(r, b);
    fq_full_reduce(r);
}

// Constant-time scalar multiplication mod q: r = (a * b) mod q
// Shift-and-add with conditional add via bn_cmov (no branching on secret bits).
static void fq_mul(bignum256* r, const bignum256* a, const bignum256* b) {
    bignum256 with_add;
    bn_zero(r);
    for(int i = 255; i >= 0; i--) {
        // r = r * 2
        bn_lshift(r);
        fq_full_reduce(r);
        // Constant-time conditional add: r += b if bit set, else r unchanged
        bn_copy(r, &with_add);
        bn_add(&with_add, b);
        fq_full_reduce(&with_add);
        uint32_t bit = bn_testbit(a, i);
        bn_cmov(r, bit, &with_add, r);
    }
    memzero(&with_add, sizeof(with_add));
}

// Wide reduction: convert 64-byte LE hash output to scalar mod q.
// This matches reddsa's from_bytes_wide / from_uniform_bytes.
// Method: interpret as 512-bit LE integer, reduce mod q.
// Split: low = bytes[0..32], high = bytes[32..64]
// result = (high * 2^256 + low) mod q
// Wide reduction: 64-byte LE → scalar mod q.
// Uses Horner's method with bn_lshift (safe x2), processing nibble by nibble.
// Each step: r = r*16 + nibble, then reduce. Safe because r < q < 2^255,
// after lshift r < 2^256 which fits in bignum256, and fq_full_reduce handles it.
static void fq_from_wide(bignum256* r, const uint8_t bytes[64]) {
    bn_zero(r);
    for(int i = 63; i >= 0; i--) {
        // r = r * 16 (via 4 left shifts with reduction)
        bn_lshift(r); fq_full_reduce(r);
        bn_lshift(r); fq_full_reduce(r);
        bn_lshift(r); fq_full_reduce(r);
        bn_lshift(r); fq_full_reduce(r);
        bn_addi(r, (bytes[i] >> 4) & 0xF);
        fq_full_reduce(r);

        bn_lshift(r); fq_full_reduce(r);
        bn_lshift(r); fq_full_reduce(r);
        bn_lshift(r); fq_full_reduce(r);
        bn_lshift(r); fq_full_reduce(r);
        bn_addi(r, bytes[i] & 0xF);
        fq_full_reduce(r);
    }
}

// Encode a Pallas point as 32 bytes (x-coordinate LE, sign bit in top bit)
// IMPORTANT: x and y must be fully reduced mod p before encoding.
static void pallas_point_encode(uint8_t out[32], const pallas_point* p) {
    // Reduce x mod p and write
    bignum256 x_reduced;
    bn_copy(&p->x, &x_reduced);
    bn_mod(&x_reduced, pallas_p());
    bn_write_le(&x_reduced, out);

    // Reduce y mod p and check parity
    bignum256 y_reduced;
    bn_copy(&p->y, &y_reduced);
    bn_mod(&y_reduced, pallas_p());
    if(y_reduced.val[0] & 1) {
        out[31] |= 0x80;
    }

    memzero(&x_reduced, sizeof(x_reduced));
    memzero(&y_reduced, sizeof(y_reduced));
}

// Deterministic nonce generation per ZIP 244 / RFC 8032 style
// T = BLAKE2b-512("Zcash_RedPallasN", rsk_bytes || sighash || random)
// nonce = T mod q
static void generate_nonce(bignum256* nonce, const uint8_t rsk_bytes[32], const uint8_t sighash[32]) {
    static uint8_t random_bytes[32];
#ifdef TEST_DETERMINISTIC_NONCE
    // For KAT testing: use fixed random bytes so signatures are reproducible.
    memset(random_bytes, 0x42, 32);
#else
    random_buffer(random_bytes, 32);
#endif

    static uint8_t personal[16];
    memset(personal, 0, 16);
    memcpy(personal, "Zcash_RedPallasN", 16);

    static blake2b_state S;
    blake2b_InitPersonal(&S, 64, personal, 16);
    blake2b_Update(&S, rsk_bytes, 32);
    blake2b_Update(&S, sighash, 32);
    blake2b_Update(&S, random_bytes, 32);

    static uint8_t hash[64];
    blake2b_Final(&S, hash, 64);

    // Wide reduction: all 64 bytes → scalar mod q
    fq_from_wide(nonce, hash);

    // Constant-time fix for zero nonce: set to 1 without branching.
    // bn_is_zero returns 1 if zero, 0 otherwise.
    static bignum256 one;
    bn_one(&one);
    int is_zero = bn_is_zero(nonce);
    bn_cmov(nonce, is_zero, &one, nonce);

    memzero(hash, 64);
    memzero(random_bytes, 32);
    memzero(&S, sizeof(S));
    memzero(&one, sizeof(one));
}

void redpallas_derive_ak(const uint8_t ask[32], uint8_t ak_out[32]) {
    pallas_init();

    // Static to reduce stack pressure on constrained devices
    static bignum256 ask_bn;
    static pallas_point ak;

    bn_read_le(ask, &ask_bn);
    fq_full_reduce(&ask_bn);

    /* G_SpendAuth = hash_to_curve("z.cash:Orchard")("G"), via its comb table */
    pallas_point_mul_fixed(&ak, &ask_bn, PALLAS_BASE_SPEND_AUTH_G);

    // Orchard protocol §4.2.3: SpendValidatingKey is normalized so that
    // the sign bit of the encoded ak is 0. If [ask]*G has sign bit 1,
    // we negate the point (which is equivalent to using -ask).
    // This matches the orchard crate's SpendAuthorizingKey::from().
    {
        static bignum256 y_reduced, neg_y;
        bn_copy(&ak.y, &y_reduced);
        bn_mod(&y_reduced, pallas_p());
        if(y_reduced.val[0] & 1) {
            bn_subtract(pallas_p(), &y_reduced, &neg_y);
            bn_copy(&neg_y, &ak.y);
            memzero(&neg_y, sizeof(neg_y));
        }
        memzero(&y_reduced, sizeof(y_reduced));
    }

    pallas_point_encode(ak_out, &ak);

    memzero(&ask_bn, sizeof(ask_bn));
    memzero(&ak, sizeof(ak));
}

int redpallas_sign(
    const uint8_t ask[32],
    const uint8_t alpha[32],
    const uint8_t sighash[32],
    uint8_t sig_out[64],
    uint8_t rk_out[32]) {

    pallas_init();

    // Large structures are static to avoid ~880 bytes of stack pressure.
    // Ledger Nano S+ has only ~6KB stack; without this, the nested call
    // chain (sample_main -> signer -> sign -> group_hash -> hash_to_curve)
    // overflows. All statics are explicitly zeroed after use.
    static bignum256 ask_bn, alpha_bn, rsk, nonce;
    static bignum256 challenge, c_times_rsk, S_scalar;
    static bignum256 q_minus_ask, ak_y_red;       /* H-2: ask normalization */
    static pallas_point ak_check, rk, R;          /* H-2: ak_check */
    static blake2b_state S_hash;
    static uint8_t challenge_raw[64];
    static uint8_t R_bytes[32];
    static uint8_t rsk_bytes[32];

    // Load scalars
    bn_read_le(ask, &ask_bn);
    fq_full_reduce(&ask_bn);
    bn_read_le(alpha, &alpha_bn);
    fq_full_reduce(&alpha_bn);

    // SpendAuth generator G = hash_to_curve("z.cash:Orchard")("G"): every
    // multiplication below goes through its constant-time comb table
    // (pallas_point_mul_fixed, PALLAS_BASE_SPEND_AUTH_G).

    /* ===== H-2 fix: ak normalization =====================================
     * Per Orchard spec §4.2.3 and librustzcash SpendAuthorizingKey::from(),
     * the on-chain SpendValidatingKey ak is the encoding of [ask]·G_SpendAuth
     * normalized to have y-bit 0. When [ask]·G has y-bit 1, the canonical
     * encoding flips the y-coordinate, which is equivalent to using -ask as
     * the spending scalar. redpallas_derive_ak() applies this normalization
     * at the point level (negating ak.y) before encoding ak.
     *
     * Without the matching normalization here, we compute
     *     rk = [ask + alpha]·G
     * but the verifier reconstructs
     *     ak_reconstructed = rk - [alpha]·G = [ask]·G  (un-normalized)
     * which differs from the on-chain ak by a sign flip half the time. Half
     * the seeds would silently produce signatures the network rejects.
     *
     * We apply the same conditional negation to ask itself, in constant time:
     *   1. compute ak_check = [ask]·G  (one extra fixed-base multiplication)
     *   2. test parity of ak_check.y mod p
     *   3. cmov ask ← q - ask   when y-bit is 1
     *
     * The check is constant-time because q_minus_ask is computed
     * unconditionally and bn_cmov selects in constant time. The point
     * multiplication itself runs through pallas_point_mul_fixed, whose constant-
     * time properties are tracked separately (audit C-1 / H-1).
     *
     * Audit: docs/security-audit/01-crypto-c-primitives.md H-2.
     */
    pallas_point_mul_fixed(&ak_check, &ask_bn, PALLAS_BASE_SPEND_AUTH_G);
    bn_subtract(pallas_q(), &ask_bn, &q_minus_ask);
    bn_copy(&ak_check.y, &ak_y_red);
    bn_mod(&ak_y_red, pallas_p());
    {
        int needs_neg = (int)(ak_y_red.val[0] & 1);
        bn_cmov(&ask_bn, needs_neg, &q_minus_ask, &ask_bn);
    }
    /* ===================================================================== */

    // rsk = ask + alpha (mod q) — using the normalized ask
    fq_add(&rsk, &ask_bn, &alpha_bn);

    pallas_report(10, "Computing rk...");

    // rk = [rsk] * G_SpendAuth
    pallas_point_mul_fixed(&rk, &rsk, PALLAS_BASE_SPEND_AUTH_G);
    pallas_point_encode(rk_out, &rk);

    pallas_report(40, "Computing nonce...");

    // Generate nonce
    bn_write_le(&rsk, rsk_bytes);
    generate_nonce(&nonce, rsk_bytes, sighash);

    pallas_report(50, "Computing R...");

    // R = [nonce] * G_SpendAuth
    pallas_point_mul_fixed(&R, &nonce, PALLAS_BASE_SPEND_AUTH_G);
    pallas_point_encode(R_bytes, &R);

    pallas_report(80, "Computing S...");

    // challenge = H("Zcash_RedPallasH", R || rk || sighash) mod q
    uint8_t personal[16];
    memset(personal, 0, 16);
    memcpy(personal, "Zcash_RedPallasH", 16);

    blake2b_InitPersonal(&S_hash, 64, personal, 16);
    blake2b_Update(&S_hash, R_bytes, 32);
    blake2b_Update(&S_hash, rk_out, 32);
    blake2b_Update(&S_hash, sighash, 32);

    blake2b_Final(&S_hash, challenge_raw, 64);

    fq_from_wide(&challenge, challenge_raw);

    // S = nonce + challenge * rsk (mod q)
    fq_mul(&c_times_rsk, &challenge, &rsk);
    fq_add(&S_scalar, &nonce, &c_times_rsk);

    // Output signature: R || S
    memcpy(sig_out, R_bytes, 32);
    bn_write_le(&S_scalar, sig_out + 32);

    pallas_report(100, "Done");

    // Cleanup ALL secrets and intermediates from BSS
    memzero(&ask_bn, sizeof(ask_bn));
    memzero(&alpha_bn, sizeof(alpha_bn));
    memzero(&rsk, sizeof(rsk));
    memzero(&nonce, sizeof(nonce));
    memzero(&S_scalar, sizeof(S_scalar));
    memzero(&challenge, sizeof(challenge));
    memzero(&c_times_rsk, sizeof(c_times_rsk));
    memzero(&q_minus_ask, sizeof(q_minus_ask));   /* H-2 */
    memzero(&ak_y_red, sizeof(ak_y_red));         /* H-2 */
    memzero(challenge_raw, sizeof(challenge_raw));
    memzero(R_bytes, sizeof(R_bytes));
    memzero(rsk_bytes, sizeof(rsk_bytes));
    memzero(&S_hash, sizeof(S_hash));
    memzero(&ak_check, sizeof(ak_check));         /* H-2 */
    memzero(&rk, sizeof(rk));
    memzero(&R, sizeof(R));

    return 0;
}
