#include "orchard.h"
#include "pallas.h"
#include "redpallas.h"
#include "blake2b.h"
#include "bignum.h"
#include "segwit_addr.h"
#include "memzero.h"
#include "chacha20poly1305.h"
#include <string.h>

#include "aes_ct.h"

// Pallas base field modulus (big-endian)
// p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
static const uint8_t PALLAS_P_BE[32] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b,
    0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01};

// Pallas scalar field (group order, big-endian)
// q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
static const uint8_t PALLAS_Q_BE[32] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd,
    0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01};

// Reduce a 64-byte little-endian value modulo a ~255-bit prime.
// Constant-time bit-by-bit Horner's method (audit M-3): every bit triggers
// the same operations regardless of value, and the conditional subtract is
// performed unconditionally with bn_cmov selecting the result.
//
// The previous implementation had two secret-dependent branches per bit:
//   1. `if (input_le[..] & (1 << ..)) bn_addi(&acc, 1)`  — leaks input bits
//   2. `if (!bn_is_less(&acc, &prime)) ... bn_subtract ... bn_copy ...`
//      — leaks structural bits of the secret-derived hash.
// Used by to_scalar/to_base on PRF^expand outputs of sk/rivk/rseed, so the
// timing leak applies to every key-derivation and address-derivation path.
//
// Works correctly for any prime (unlike bn_fast_mod which requires prime ~ 2^256).
static void reduce_512_mod(
    const uint8_t input_le[64],
    const uint8_t modulus_be[32],
    uint8_t output_le[32]) {
    bignum256 acc, prime, temp;

    bn_read_be(modulus_be, &prime);
    bn_zero(&acc);

    // Process 512 bits from MSB to LSB
    for(int bit = 511; bit >= 0; bit--) {
        // acc = 2 * acc
        bn_lshift(&acc);

        // Constant-time bit-add: bit_val is always added (0 or 1), no branch.
        int byte_idx = bit / 8;
        int bit_idx = bit % 8;
        uint32_t bit_val = ((uint32_t)input_le[byte_idx] >> bit_idx) & 1u;
        bn_addi(&acc, bit_val);

        // Normalize to propagate any carries from addi/lshift
        bn_normalize(&acc);

        // Constant-time conditional reduce: compute (acc - prime) UNCONDITIONALLY
        // and then bn_cmov selects whether to keep the original acc or the
        // subtracted result based on the (constant-time) comparison.
        // bn_subtract is well-defined when acc < prime (the result is garbage,
        // but we discard it via bn_cmov).
        bn_subtract(&acc, &prime, &temp);
        int needs_reduce = !bn_is_less(&acc, &prime);
        bn_cmov(&acc, needs_reduce, &temp, &acc);
    }

    bn_write_le(&acc, output_le);

    memzero(&acc, sizeof(acc));
    memzero(&temp, sizeof(temp));
}

// ToScalar: reduce 64-byte LE value modulo Pallas group order q
static void to_scalar(const uint8_t input_le[64], uint8_t output_le[32]) {
    reduce_512_mod(input_le, PALLAS_Q_BE, output_le);
}

// ToBase: reduce 64-byte LE value modulo Pallas base field p
static void to_base(const uint8_t input_le[64], uint8_t output_le[32]) {
    reduce_512_mod(input_le, PALLAS_P_BE, output_le);
}

// PRF^expand(sk, domain, parts...):
//   BLAKE2b-512(personal="Zcash_ExpandSeed", input = sk || domain || parts)
// NOTE: sk is part of the INPUT, NOT the BLAKE2b key parameter!
static void prf_expand(
    const uint8_t sk[32],
    const uint8_t* domain_and_parts,
    size_t parts_len,
    uint8_t output[64]) {
    blake2b_state S;
    blake2b_InitPersonal(&S, 64, "Zcash_ExpandSeed", 16);
    blake2b_Update(&S, sk, 32);
    blake2b_Update(&S, domain_and_parts, parts_len);
    blake2b_Final(&S, output, 64);
    memzero(&S, sizeof(S));
}

void orchard_master_key(
    const uint8_t seed[64],
    uint8_t sk_out[32],
    uint8_t chaincode_out[32]) {
    uint8_t I[64];
    blake2b_state S;

    // I = BLAKE2b-512(personalization="ZcashIP32Orchard", input=seed)
    blake2b_InitPersonal(&S, 64, "ZcashIP32Orchard", 16);
    blake2b_Update(&S, seed, 64);
    blake2b_Final(&S, I, 64);

    memcpy(sk_out, I, 32);
    memcpy(chaincode_out, I + 32, 32);

    memzero(I, sizeof(I));
    memzero(&S, sizeof(S));
}

void orchard_child_key(
    const uint8_t sk_parent[32],
    const uint8_t chaincode_parent[32],
    uint32_t index,
    uint8_t sk_out[32],
    uint8_t chaincode_out[32]) {
    // I = PRF^expand(c_parent, [0x81] || sk_parent || I2LEOSP32(index))
    uint8_t input[1 + 32 + 4];
    input[0] = 0x81;
    memcpy(input + 1, sk_parent, 32);
    // I2LEOSP32: 32-bit little-endian encoding
    input[33] = (uint8_t)(index & 0xFF);
    input[34] = (uint8_t)((index >> 8) & 0xFF);
    input[35] = (uint8_t)((index >> 16) & 0xFF);
    input[36] = (uint8_t)((index >> 24) & 0xFF);

    uint8_t I[64];
    prf_expand(chaincode_parent, input, sizeof(input), I);

    memcpy(sk_out, I, 32);
    memcpy(chaincode_out, I + 32, 32);

    memzero(I, sizeof(I));
    memzero(input, sizeof(input));
}

void orchard_derive_keys(
    const uint8_t sk[32],
    uint8_t ask_out[32],
    uint8_t nk_out[32],
    uint8_t rivk_out[32]) {
    uint8_t prf_out[64];
    uint8_t domain[1];

    // ask = ToScalar(PRF^expand(sk, [0x06]))
    domain[0] = 0x06;
    prf_expand(sk, domain, 1, prf_out);
    to_scalar(prf_out, ask_out);

    // nk = ToBase(PRF^expand(sk, [0x07]))
    domain[0] = 0x07;
    prf_expand(sk, domain, 1, prf_out);
    to_base(prf_out, nk_out);

    // rivk = ToScalar(PRF^expand(sk, [0x08]))
    domain[0] = 0x08;
    prf_expand(sk, domain, 1, prf_out);
    to_scalar(prf_out, rivk_out);

    memzero(prf_out, sizeof(prf_out));
}

void orchard_derive_account_sk(
    const uint8_t seed[64],
    uint32_t coin_type,
    uint32_t account,
    uint8_t sk_out[32]) {
    uint8_t sk[32], chaincode[32];
    uint8_t sk_child[32], cc_child[32];

    // Master key
    orchard_master_key(seed, sk, chaincode);

    // ZIP-32 Orchard path: m_Orchard / 32' / coin_type' / account'
    // Purpose = 32 (ZIP-32)
    orchard_child_key(sk, chaincode, 0x80000000 | 32, sk_child, cc_child);
    memcpy(sk, sk_child, 32);
    memcpy(chaincode, cc_child, 32);

    // Coin type
    orchard_child_key(sk, chaincode, 0x80000000 | coin_type, sk_child, cc_child);
    memcpy(sk, sk_child, 32);
    memcpy(chaincode, cc_child, 32);

    // Account: account'
    orchard_child_key(sk, chaincode, 0x80000000 | account, sk_child, cc_child);

    memcpy(sk_out, sk_child, 32);

    memzero(sk, sizeof(sk));
    memzero(chaincode, sizeof(chaincode));
    memzero(sk_child, sizeof(sk_child));
    memzero(cc_child, sizeof(cc_child));
}

// ============================================================
// FF1-AES-256 (NIST SP 800-38G) for diversifier derivation
// Radix 2, n=88 bits, empty tweak
// Matches the fpe crate's BinaryNumeralString behavior exactly.
// ============================================================

// BinaryNumeralString: bytes are LE, bits within bytes are LE.
// Numeral i = (byte[i/8] >> (i%8)) & 1
// NUM_2(X) treats numerals in big-endian order:
//   NUM_2(X[0..m]) = X[0]*2^(m-1) + X[1]*2^(m-2) + ... + X[m-1]*2^0
// So bit 0 of byte 0 is the MSB of the 44-bit integer.

// Extract 44-bit integer from the numeral string starting at bit offset
static uint64_t ff1_extract(const uint8_t* data, int bit_offset, int count) {
    uint64_t val = 0;
    for(int i = 0; i < count; i++) {
        int src = bit_offset + i;
        int byte_idx = src / 8;
        int bit_idx = src % 8;
        if(data[byte_idx] & (1 << bit_idx)) {
            val |= (1ULL << (count - 1 - i)); // numeral 0 = MSB
        }
    }
    return val;
}

// Write 44-bit integer back to numeral string at bit offset
static void ff1_inject(uint8_t* data, int bit_offset, int count, uint64_t val) {
    for(int i = 0; i < count; i++) {
        int dst = bit_offset + i;
        int byte_idx = dst / 8;
        int bit_idx = dst % 8;
        if(val & (1ULL << (count - 1 - i))) {
            data[byte_idx] |= (1 << bit_idx);
        } else {
            data[byte_idx] &= ~(1 << bit_idx);
        }
    }
}

// Convert uint64 to b-byte big-endian
static void ff1_to_be(uint64_t val, uint8_t* out, int b) {
    for(int i = b - 1; i >= 0; i--) {
        out[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

void ff1_aes256_encrypt(const uint8_t key[32], const uint8_t in[11], uint8_t out[11]) {
    /* Constant-time AES-256 (audit H-3): the previous Brian-Gladman T-table
     * implementation leaked the round-key bytes via cache timing. The
     * replacement scans the entire S-box on every byte substitution so
     * the access pattern is independent of the input. FF1 runs once per
     * account creation (then the address is cached in NVS), so the
     * software-AES overhead is irrelevant in practice. Firmware can
     * register a hardware-AES backend via aes_ct_256_set_override(); on
     * ESP32-S2 / S3 the hardware AES accelerator is constant-time. */
    aes_ct_256_ctx ctx;
    aes_ct_256_keysched(key, &ctx);

    const int n = 88; // bits
    const int u = 44, v = 44;
    (void)v; // used in comments, m alternates u/v
    const uint64_t mask44 = (1ULL << 44) - 1;

    // Split: A = NUM_2(numerals 0..43), B = NUM_2(numerals 44..87)
    uint64_t num_a = ff1_extract(in, 0, u);
    uint64_t num_b = ff1_extract(in, u, v);

    // P = [1,2,1] || [radix=2 as 3 BE bytes] || [10] || [u%256] || [n as 4 BE] || [t=0 as 4 BE]
    uint8_t P[16] = {1, 2, 1, 0, 0, 2, 10, (uint8_t)(u & 0xFF),
                     0, 0, 0, (uint8_t)((n >> 0) & 0xFF), 0, 0, 0, 0};
    // n=88: BE 4 bytes = 0,0,0,88
    P[8] = 0; P[9] = 0; P[10] = 0; P[11] = 88;

    // PRF base: AES-CBC-MAC of P with IV=0
    // For empty tweak and b=6: padding = ((-0-6-1) mod 16 + 16) mod 16 = 9 zeros
    // So Q = [0]*9 || [i] || [NUM_2(B) as 6 BE bytes] = 16 bytes
    // R = AES(key, AES(key, P) ^ Q)
    uint8_t prf_p[16];
    aes_ct_256_ecb_encrypt(&ctx, P, prf_p);

    for(int i = 0; i < 10; i++) {

        // Q: 9 zeros || round_byte || NUM_2(B) as 6 BE bytes
        uint8_t Q[16] = {0};
        Q[9] = (uint8_t)i;
        ff1_to_be(num_b, Q + 10, 6);

        // R = AES(key, prf_p ^ Q)
        uint8_t R[16];
        for(int j = 0; j < 16; j++) R[j] = prf_p[j] ^ Q[j];
        uint8_t S[16];
        aes_ct_256_ecb_encrypt(&ctx, R, S);

        // y = NUM(S[0..d]) where d=12, as big-endian integer
        // We need (num_a + y) mod 2^m where m=44
        // Only the low 44 bits of y matter
        uint64_t y_low = 0;
        for(int j = 6; j < 12; j++) y_low = (y_low << 8) | S[j];
        // Also include contribution from S[5] low nibble
        y_low |= ((uint64_t)(S[5] & 0x0F) << 48);
        y_low &= mask44;

        uint64_t c = (num_a + y_low) & mask44;

        // A = B, B = c
        num_a = num_b;
        num_b = c;
    }

    // Reconstruct output
    memcpy(out, in, 11); // start with input (preserves bit layout)
    ff1_inject(out, 0, u, num_a);
    ff1_inject(out, u, v, num_b);

    /* Wipe the AES round keys: rk[0]||rk[1] reconstitutes the master key,
     * which is dk and is part of the user's spending capability. */
    memzero(&ctx, sizeof(ctx));
    memzero(prf_p, sizeof(prf_p));
}

// ============================================================
// F4Jumble (ZIP-316)
// ============================================================

// F4Jumble (ZIP-316) - Reference: zcash-test-vectors/f4jumble.py
// H_i(u) -> l_L bytes (short, single BLAKE2b)
// G_i(u) -> l_R bytes (long, counter-mode BLAKE2b)
static void f4jumble_H(int i, const uint8_t* u, size_t u_len, uint8_t* out, size_t out_len) {
    uint8_t personal[16] = {'U','A','_','F','4','J','u','m','b','l','e','_','H',0,0,0};
    personal[13] = (uint8_t)i;
    blake2b_state S;
    blake2b_InitPersonal(&S, out_len, personal, 16);
    blake2b_Update(&S, u, u_len);
    blake2b_Final(&S, out, out_len);
}

static void f4jumble_G(int i, const uint8_t* u, size_t u_len, uint8_t* out, size_t out_len) {
    uint8_t personal[16] = {'U','A','_','F','4','J','u','m','b','l','e','_','G',0,0,0};
    personal[13] = (uint8_t)i;
    size_t done = 0;
    for(uint32_t j = 0; done < out_len; j++) {
        size_t chunk = out_len - done;
        if(chunk > 64) chunk = 64;
        personal[14] = (uint8_t)(j & 0xFF);
        personal[15] = (uint8_t)((j >> 8) & 0xFF);
        blake2b_state S;
        blake2b_InitPersonal(&S, 64, personal, 16);
        blake2b_Update(&S, u, u_len);
        uint8_t hash[64];
        blake2b_Final(&S, hash, 64);
        memcpy(out + done, hash, chunk);
        done += chunk;
    }
}

// F4Jumble (ZIP-316). For Unified Addresses the input is ~83 bytes.
// l_L is capped at 64, so buf needs max(l_R, l_L).
// We use a static buffer to avoid both malloc and stack pressure
// on constrained devices (Flipper Zero: 4 KB stack).
#ifndef F4JUMBLE_MAX_INPUT
#define F4JUMBLE_MAX_INPUT 256
#endif

void f4jumble(uint8_t* data, size_t len) {
    if(len < 48 || len > F4JUMBLE_MAX_INPUT) return;
    size_t l_L = len / 2;
    if(l_L > 64) l_L = 64;
    size_t l_R = len - l_L;

    // Static buffer: max(l_R, l_L) where l_L ≤ 64, l_R = len - l_L.
    // Worst case: len=256 → l_R=192. Lives in BSS, not stack.
    static uint8_t buf[F4JUMBLE_MAX_INPUT - 64];

    uint8_t* a = data;
    uint8_t* b = data + l_L;

    // x = b XOR G(0, a)
    f4jumble_G(0, a, l_L, buf, l_R);
    for(size_t i = 0; i < l_R; i++) b[i] ^= buf[i];
    // Now b = x

    // y = a XOR H(0, x)
    f4jumble_H(0, b, l_R, buf, l_L);
    for(size_t i = 0; i < l_L; i++) a[i] ^= buf[i];
    // Now a = y

    // d = x XOR G(1, y)
    f4jumble_G(1, a, l_L, buf, l_R);
    for(size_t i = 0; i < l_R; i++) b[i] ^= buf[i];
    // Now b = d

    // c = y XOR H(1, d)
    f4jumble_H(1, b, l_R, buf, l_L);
    for(size_t i = 0; i < l_L; i++) a[i] ^= buf[i];
    // Now a = c

    // Result: c || d = a || b (in-place)
}

void f4jumble_inv(uint8_t* data, size_t len) {
    if(len < 48 || len > F4JUMBLE_MAX_INPUT) return;
    size_t l_L = len / 2;
    if(l_L > 64) l_L = 64;
    size_t l_R = len - l_L;

    static uint8_t buf[F4JUMBLE_MAX_INPUT - 64];

    uint8_t* c = data;
    uint8_t* d = data + l_L;

    // y = c XOR H(1, d)
    f4jumble_H(1, d, l_R, buf, l_L);
    for(size_t i = 0; i < l_L; i++) c[i] ^= buf[i];
    // Now c = y

    // x = d XOR G(1, y)
    f4jumble_G(1, c, l_L, buf, l_R);
    for(size_t i = 0; i < l_R; i++) d[i] ^= buf[i];
    // Now d = x

    // a = y XOR H(0, x)
    f4jumble_H(0, d, l_R, buf, l_L);
    for(size_t i = 0; i < l_L; i++) c[i] ^= buf[i];
    // Now c = a

    // b = x XOR G(0, a)
    f4jumble_G(0, c, l_L, buf, l_R);
    for(size_t i = 0; i < l_R; i++) d[i] ^= buf[i];
    // Now d = b

    // Result: a || b = c || d (in-place)
}

// ============================================================
// Identity-attestation primitive (HWP-agnostic, audit M1)
// ============================================================

int orchard_sign_with_personal(
    const uint8_t scalar[32],
    const uint8_t personal_16[16],
    const uint8_t msg[32],
    uint8_t sig_out[64],
    uint8_t rk_out[32]) {
    /* Stage 1: domain-separated digest of the message.
     *
     * BLAKE2b is used (not the orchard-specific Sinsemilla) because the
     * verifier needs to recompute the same digest from the public
     * (personal, msg) pair without any Pallas curve work. */
    uint8_t digest[32];
    blake2b_state bs;
    blake2b_InitPersonal(&bs, 32, personal_16, 16);
    blake2b_Update(&bs, msg, 32);
    blake2b_Final(&bs, digest, 32);

    /* Stage 2: RedPallas Schnorr-style signature with no rerandomization.
     *
     * `alpha = 0` ⇒ rsk = scalar (post-normalization) and rk = [scalar]·G.
     * That binding lets the verifier check `rk == pinned_pubkey` AND
     * verify the signature in one round-trip. */
    static const uint8_t alpha_zero[32] = {0};
    int ret = redpallas_sign(scalar, alpha_zero, digest, sig_out, rk_out);

    memzero(digest, sizeof(digest));
    memzero(&bs, sizeof(bs));
    return ret;
}

// ============================================================
// Unified Address encoding
// ============================================================

// Convert 8-bit byte array to 5-bit array for Bech32
static size_t convert_bits_8to5(
    const uint8_t* in, size_t in_len,
    uint8_t* out, size_t out_max) {
    uint32_t val = 0;
    int bits = 0;
    size_t out_len = 0;
    for(size_t i = 0; i < in_len; i++) {
        val = (val << 8) | in[i];
        bits += 8;
        while(bits >= 5) {
            bits -= 5;
            if(out_len < out_max) out[out_len++] = (val >> bits) & 0x1F;
        }
    }
    if(bits > 0) {
        if(out_len < out_max) out[out_len++] = (val << (5 - bits)) & 0x1F;
    }
    return out_len;
}

// Address generation is done via orchard_derive_unified_address() below

int orchard_derive_unified_address(
    const uint8_t seed[64],
    uint32_t coin_type,
    uint32_t account,
    const char* hrp,
    char* ua_out,
    size_t ua_out_len,
    uint8_t* d_out,
    uint8_t* pk_d_out) {

    pallas_init();

    static uint8_t d[11];
    static uint8_t pk_d_bytes[32];

    // Cache is handled by caller

    // Large structures are static to avoid stack pressure
    // on constrained devices (e.g. Flipper Zero: 4 KB stack).
    // All are explicitly zeroed after use to prevent secret persistence.
    {
        // 1. Derive spending key and components
        pallas_report(2, "Deriving keys...");
        static uint8_t sk[32], ask_le[32], nk_le[32], rivk_le[32];
        orchard_derive_account_sk(seed, coin_type, account, sk);
        orchard_derive_keys(sk, ask_le, nk_le, rivk_le);

        // 2. ak = [ask] * G_spend
        pallas_report(5, "Computing ak...");
        static bignum256 ask_bn;
        bn_read_le(ask_le, &ask_bn);

        static pallas_point G_spend;
        pallas_group_hash(&G_spend, "z.cash:Orchard", (const uint8_t*)"G", 1);

        pallas_report(15, "Scalar mul [ask]*G");
        static pallas_point ak;
        pallas_point_mul(&ak, &ask_bn, &G_spend);

        // 3. IVK = SinsemillaShortCommit
        pallas_report(35, "Sinsemilla IVK...");
        static bignum256 nk_bn;
        bn_read_le(nk_le, &nk_bn);

        static uint8_t commit_msg[64];
        memzero(commit_msg, 64);
        static uint8_t nk_bytes_le[32], ak_x_bytes[32];
        bn_write_le(&nk_bn, nk_bytes_le);
        nk_bytes_le[31] &= 0x7F;
        bn_write_le(&ak.x, ak_x_bytes);
        ak_x_bytes[31] &= 0x7F;
        // Message = I2LEBSP_255(ak) || I2LEBSP_255(nk) — ak FIRST per spec
        memcpy(commit_msg, ak_x_bytes, 32);
        for(int i = 0; i < 255; i++) {
            int sb = i / 8, sbt = i % 8, db = (255 + i) / 8, dbt = (255 + i) % 8;
            if(nk_bytes_le[sb] & (1 << sbt)) commit_msg[db] |= (1 << dbt);
        }

        static bignum256 rivk_bn;
        bn_read_le(rivk_le, &rivk_bn);
        static bignum256 ivk_x;
        sinsemilla_short_commit(&ivk_x, "z.cash:Orchard-CommitIvk",
                                commit_msg, 510, &rivk_bn);
        fq_reduce(&ivk_x, &ivk_x);
        static bignum256 ivk;
        bn_copy(&ivk_x, &ivk);

        // 4. dk
        static uint8_t ak_compressed[32];
        bn_write_le(&ak.x, ak_compressed);
        if(ak.y.val[0] & 1) ak_compressed[31] |= 0x80;
        static uint8_t dk[32];
        {
            static uint8_t prf_dk_out[64];
            static blake2b_state S_dk;
            blake2b_InitPersonal(&S_dk, 64, "Zcash_ExpandSeed", 16);
            blake2b_Update(&S_dk, rivk_le, 32);
            uint8_t dk_d[1] = {0x82};
            blake2b_Update(&S_dk, dk_d, 1);
            blake2b_Update(&S_dk, ak_compressed, 32);
            blake2b_Update(&S_dk, nk_le, 32);
            blake2b_Final(&S_dk, prf_dk_out, 64);
            memcpy(dk, prf_dk_out, 32);
            memzero(prf_dk_out, sizeof(prf_dk_out));
            memzero(&S_dk, sizeof(S_dk));
        }

        // 5. diversifier
        pallas_report(70, "Diversifier...");
        static uint8_t d_in[11];
        memzero(d_in, sizeof(d_in));
        ff1_aes256_encrypt(dk, d_in, d);

        // 6. g_d = DiversifyHash(d)
        pallas_report(72, "DiversifyHash...");
        static pallas_point g_d;
        pallas_hash_to_curve(&g_d, "z.cash:Orchard-gd", d, 11);

        // 7. pk_d = [ivk] * g_d
        pallas_report(80, "Computing pk_d...");
        static pallas_point pk_d;
        pallas_point_mul(&pk_d, &ivk, &g_d);

        bn_write_le(&pk_d.x, pk_d_bytes);
        if(pk_d.y.val[0] & 1) pk_d_bytes[31] |= 0x80;

        pallas_report(95, "Encoding...");

        // Wipe ALL secret intermediates (static + stack)
        memzero(sk, sizeof(sk));
        memzero(ask_le, sizeof(ask_le));
        memzero(nk_le, sizeof(nk_le));
        memzero(rivk_le, sizeof(rivk_le));
        memzero(dk, sizeof(dk));
        memzero(ak_compressed, sizeof(ak_compressed));
        memzero(nk_bytes_le, sizeof(nk_bytes_le));
        memzero(ak_x_bytes, sizeof(ak_x_bytes));
        memzero(commit_msg, sizeof(commit_msg));
        memzero(&ask_bn, sizeof(ask_bn));
        memzero(&nk_bn, sizeof(nk_bn));
        memzero(&rivk_bn, sizeof(rivk_bn));
        memzero(&ivk_x, sizeof(ivk_x));
        memzero(&ivk, sizeof(ivk));
        memzero(&ak, sizeof(ak));
        memzero(&g_d, sizeof(g_d));
        memzero(&pk_d, sizeof(pk_d));
        memzero(&G_spend, sizeof(G_spend));
    }


    pallas_report(98, "Encoding UA...");

    // Export d and pk_d for caching
    if(d_out) memcpy(d_out, d, 11);
    if(pk_d_out) memcpy(pk_d_out, pk_d_bytes, 32);

    // 8. Build raw UA per ZIP-316: Orchard-only
    //    receivers (ascending typecode) || HRP padded to 16 bytes
    static uint8_t raw_ua[80]; // Orchard(45) + padding(16) = 61
    size_t raw_len = 0;

    // Orchard receiver (typecode 0x03)
    raw_ua[raw_len++] = 0x03;
    raw_ua[raw_len++] = 43;
    memcpy(raw_ua + raw_len, d, 11);
    raw_len += 11;
    memcpy(raw_ua + raw_len, pk_d_bytes, 32);
    raw_len += 32;
    // raw_len = 45 (Orchard only)

    // ZIP-316 padding: HRP padded to 16 bytes with zeros
    {
        uint8_t hrp_padded[16] = {0};
        size_t hlen = strlen(hrp);
        if(hlen > 16) hlen = 16;
        memcpy(hrp_padded, hrp, hlen);
        memcpy(raw_ua + raw_len, hrp_padded, 16);
        raw_len += 16;
    }
    // raw_len = 83 (67 receivers + 16 padding)

    // 9. F4Jumble
    f4jumble(raw_ua, raw_len);

    // 11. Bech32m encode (ignoring length restrictions per ZIP-316)
    static uint8_t data5[160];
    size_t data5_len = convert_bits_8to5(raw_ua, raw_len, data5, sizeof(data5));

    // Use bech32_encode directly (not segwit_addr_encode which has length limits)
    if(ua_out_len < 200) return 0;
    int ok = bech32_encode(ua_out, hrp, data5, data5_len, BECH32_ENCODING_BECH32M);
    if(!ok) return 0;

    // Sensitive data was cleared in the computation block above

    return (int)strlen(ua_out);
}

/* ---------------------------------------------------------------------- */
/*  Orchard-only Unified Address encoding from a raw (d, pk_d) pair       */
/* ---------------------------------------------------------------------- */
/*
 * Used by the on-device signer to render an arbitrary recipient (extracted
 * from a PCZT, NOT necessarily belonging to the device's own key) so the
 * user can verify it on screen before authorizing a signature. ZIP-316:
 *
 *   raw_ua = 0x03 || 43 || d || pk_d || hrp_padded_to_16
 *   ua     = bech32m(hrp, F4Jumble(raw_ua))
 *
 * No key derivation runs here — this function only encodes.
 */
int orchard_encode_ua_raw(
    const uint8_t d[11],
    const uint8_t pk_d[32],
    const char* hrp,
    char* ua_out,
    size_t ua_out_len)
{
    if (!d || !pk_d || !hrp || !ua_out || ua_out_len < 200) return 0;

    uint8_t raw_ua[80];
    memzero(raw_ua, sizeof(raw_ua));
    size_t raw_len = 0;

    /* Orchard receiver (typecode 0x03), length 43 */
    raw_ua[raw_len++] = 0x03;
    raw_ua[raw_len++] = 43;
    memcpy(raw_ua + raw_len, d, 11);
    raw_len += 11;
    memcpy(raw_ua + raw_len, pk_d, 32);
    raw_len += 32;
    /* raw_len = 45 (Orchard-only) */

    /* ZIP-316 padding: HRP padded to 16 bytes with zeros */
    {
        uint8_t hrp_padded[16] = {0};
        size_t hlen = strlen(hrp);
        if (hlen > 16) hlen = 16;
        memcpy(hrp_padded, hrp, hlen);
        memcpy(raw_ua + raw_len, hrp_padded, 16);
        raw_len += 16;
    }
    /* raw_len = 61 */

    f4jumble(raw_ua, raw_len);

    uint8_t data5[160];
    size_t data5_len = convert_bits_8to5(raw_ua, raw_len, data5, sizeof(data5));

    int ok = bech32_encode(ua_out, hrp, data5, data5_len, BECH32_ENCODING_BECH32M);
    memzero(raw_ua, sizeof(raw_ua));
    memzero(data5, sizeof(data5));
    if (!ok) return 0;

    return (int)strlen(ua_out);
}

/* ---------------------------------------------------------------------- */
/*  Unified Address decoding                                              */
/* ---------------------------------------------------------------------- */
/*
 * Inverse of orchard_encode_ua_raw, used to validate companion-supplied
 * "intended recipient" UAs against the on-device signer's actions_display[].
 * Tracked in docs/security-audit/02-orchard-protocol-signing.md C1.
 *
 * ZIP-316 §3 receiver-encoding constraints relevant here:
 *   - typecode is compactSize-encoded; for currently defined receivers
 *     (transparent P2PKH=0x00, P2SH=0x01, Sapling=0x02, Orchard=0x03)
 *     the typecode fits in a single byte;
 *   - length is compactSize-encoded; for currently defined receivers
 *     (P2PKH=20, P2SH=20, Sapling=43, Orchard=43) the length fits in a
 *     single byte;
 *   - the trailing 16 bytes of the F4Jumble preimage are the ASCII HRP
 *     padded with zeros, providing a self-consistent HRP check.
 *
 * For forward compatibility the parser skips unknown receivers (typecode
 * != 0x03) without rejecting them; only a malformed structure (truncated
 * header, bad length) returns -5.
 */
static size_t convert_bits_5to8(
    const uint8_t* in, size_t in_len,
    uint8_t* out, size_t out_max)
{
    uint32_t val = 0;
    int bits = 0;
    size_t out_len = 0;
    for (size_t i = 0; i < in_len; i++) {
        val = (val << 5) | (in[i] & 0x1F);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (out_len < out_max) out[out_len++] = (val >> bits) & 0xFF;
        }
    }
    /* Trailing fewer-than-8 bits are zero-padding from the encoder; per
     * ZIP-316 we ignore them, matching the Bitcoin segwit decode behaviour. */
    return out_len;
}

int orchard_decode_ua_orchard_receiver(
    const char* ua_str,
    const char* expected_hrp,
    uint8_t orchard_recipient_out[43])
{
    if (!ua_str || !expected_hrp || !orchard_recipient_out) return -1;

    /* bech32m has a 90-char limit for segwit; ZIP-316 explicitly waives
     * that so UAs can be much longer. The buffers below are `static` to
     * keep the stack frame within the 512-byte embedded budget — the rest
     * of the library follows the same single-threaded-use convention. */
    static char hrp_decoded[84];
    static uint8_t data5[512];
    memset(hrp_decoded, 0, sizeof(hrp_decoded));
    size_t data5_len = 0;

    /* bech32_decode returns BECH32_ENCODING_BECH32M (=2), BECH32_ENCODING_BECH32
     * (=1), or BECH32_ENCODING_NONE (=0). UAs MUST be bech32m. */
    bech32_encoding enc = bech32_decode(hrp_decoded, data5, &data5_len, ua_str);
    if (enc != BECH32_ENCODING_BECH32M) return -1;

    /* HRP plausibility: must match the wallet's network exactly. */
    if (strcmp(hrp_decoded, expected_hrp) != 0) return -2;

    /* 5→8 bit repacking. `raw` is `static` for the same stack-budget reason
     * as `data5`/`hrp_decoded` above. */
    static uint8_t raw[400];
    size_t raw_len = convert_bits_5to8(data5, data5_len, raw, sizeof(raw));

    /* F4Jumble length bounds: ZIP-316 §4.2 restricts to 48..4194368 bytes;
     * any well-formed UA on a Zcash network is comfortably within. We bound
     * by the max receivers we anticipate (raw + 16 hrp pad). */
    if (raw_len < 48 || raw_len > sizeof(raw)) return -3;

    /* F4Jumble is its own inverse partner — apply f4jumble_inv to recover
     * the receivers blob || padded_hrp. */
    f4jumble_inv(raw, raw_len);

    /* Verify the trailing 16-byte HRP padding matches expected_hrp. This is
     * a self-consistent integrity check that detects truncation/corruption
     * of the receivers section as well as an HRP swap. */
    {
        uint8_t hrp_pad_expected[16] = {0};
        size_t hlen = strlen(expected_hrp);
        if (hlen > 16) hlen = 16;
        memcpy(hrp_pad_expected, expected_hrp, hlen);

        const uint8_t* tail = raw + (raw_len - 16);
        if (memcmp(tail, hrp_pad_expected, 16) != 0) return -2;
    }

    /* Walk receivers in the leading (raw_len - 16) bytes. We only handle
     * single-byte compactSize typecode and length, which covers every
     * currently defined receiver (typecodes 0..3, lengths 20 and 43). */
    size_t receivers_len = raw_len - 16;
    size_t i = 0;
    int found_orchard = 0;

    while (i < receivers_len) {
        if (i + 2 > receivers_len) return -5;          /* truncated header */
        uint8_t typecode = raw[i++];
        uint8_t length   = raw[i++];

        /* compactSize escape values are not handled — every defined
         * receiver fits in single bytes. Reject anything that tries to
         * use the escape, both for safety and to flag spec evolution. */
        if (typecode == 0xFD || typecode == 0xFE || typecode == 0xFF) return -5;
        if (length == 0xFD || length == 0xFE || length == 0xFF) return -5;

        if (i + length > receivers_len) return -5;     /* truncated data */

        if (typecode == 0x03 && length == 43) {
            memcpy(orchard_recipient_out, raw + i, 43);
            found_orchard = 1;
            /* Don't break: completing the walk validates the structure. */
        }

        i += length;
    }

    if (i != receivers_len) return -5;                 /* trailing garbage */
    if (!found_orchard) return -4;
    return 0;
}

/* ---------------------------------------------------------------------- */
/*  Orchard NoteCommitment (cmx) recomputation                            */
/* ---------------------------------------------------------------------- */
/*
 *   cmx = Extract_P( NoteCommit_rcm^Orchard(g_d, pk_d, v, rho, psi) )
 *
 * with
 *   g_d = DiversifyHash(d)
 *   rcm = ToScalar( PRF^expand(rseed, [0x05] || rho) )
 *   psi = ToBase  ( PRF^expand(rseed, [0x09] || rho) )
 *
 * The Sinsemilla input is the bit string (LSB-first per byte):
 *   repr_P(g_d) (256 bits)
 *   || repr_P(pk_d) (256 bits)
 *   || I2LEBSP_64(v) (64 bits)
 *   || I2LEBSP_255(rho) (255 bits)
 *   || I2LEBSP_255(psi) (255 bits)
 * Total 1086 bits, packed into 136 bytes.
 *
 * Used by the on-device signer to verify the cmx field of each streamed
 * Orchard action against the recipient/value/rseed the companion claims it
 * commits to. A hostile companion that swaps the recipient must also produce
 * a matching cmx; this is computationally infeasible.
 */
void orchard_compute_cmx(
    const uint8_t d[11],
    const uint8_t pk_d[32],
    uint64_t value,
    const uint8_t rho[32],
    const uint8_t rseed[32],
    uint8_t note_version,
    uint8_t cmx_out[32])
{
    /* The 1086-bit Sinsemilla input doubles as our scratchpad: every
     * intermediate is written directly into it, so we avoid keeping
     * separate repr/psi buffers alive on the stack. */
    uint8_t msg[136];
    memzero(msg, sizeof(msg));

    /* bits 0..255 (bytes 0..31): repr_P(g_d) — written in place. */
    {
        pallas_point g_d;
        pallas_hash_to_curve(&g_d, "z.cash:Orchard-gd", d, 11);
        bn_write_le(&g_d.x, msg + 0);
        if (g_d.y.val[0] & 1) msg[31] |= 0x80;
        memzero(&g_d, sizeof(g_d));
    }

    /* bits 256..511 (bytes 32..63): pk_d (already in repr_P form) */
    memcpy(msg + 32, pk_d, 32);
    /* bits 512..575 (bytes 64..71): value, little-endian */
    for (int i = 0; i < 8; i++) {
        msg[64 + i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
    /* bits 576..830 (bytes 72..103, top bit of byte 103 unused for rho):
     *   first 255 bits of rho */
    memcpy(msg + 72, rho, 31);
    msg[103] = rho[31] & 0x7F;

    /* Compute psi first (needed for the Sinsemilla message in both note
     * versions, and as an rcm input for V3), then rcm per note version.
     *
     * `pre` is the ZIP-2005 rcm preimage laid out as
     *   [0x0B] || repr_P(g_d)(32) || repr_P(pk_d)(32) || v_LE(8) ||
     *   rho(32) || psi(32)
     * and doubles as the psi scratch buffer (psi is written straight into
     * its final slot at pre+105) so no separate psi buffer stays live on
     * the stack — the frame must fit the embedded 512-byte per-function
     * budget (scripts/check_stack.sh). Static storage, single-threaded
     * signer, memzero'd before return — same pattern as the other Pallas
     * heavyweights. */
    bignum256 rcm_bn;
    {
        static uint8_t pre[1 + 32 + 32 + 8 + 32 + 32];
        uint8_t prf_in[1 + 32];
        uint8_t prf_out[64];
        uint8_t *psi_le = pre + 105;
        memcpy(prf_in + 1, rho, 32);

        /* psi = ToBase(PRF^expand(rseed, [0x09] || rho)). The 255 valid
         * bits are packed into msg[103..135] starting at bit 7 of byte 103
         * — equivalent to (psi & ~bit255) shifted left by 7 bits and OR'd
         * into msg starting at byte 103. */
        prf_in[0] = 0x09;
        prf_expand(rseed, prf_in, sizeof(prf_in), prf_out);
        to_base(prf_out, psi_le);
        psi_le[31] &= 0x7F;
        for (int k = 0; k < 32; k++) {
            uint8_t b = psi_le[k];
            msg[103 + k] |= (uint8_t)(b << 7);
            msg[104 + k] |= (uint8_t)(b >> 1);
        }

        {
            uint8_t rcm_le[32];
            if (note_version == ORCHARD_NOTE_V3) {
                /* ZIP-2005 quantum-recoverable rcm (Ironwood V3 notes):
                 * binds rcm to all note fields for post-quantum commitment
                 * binding.
                 *   rcm = ToScalar(PRF^expand(rseed,
                 *       [0x0B] || repr_P(g_d)(32) || repr_P(pk_d)(32) ||
                 *       v_LE(8) || rho(32) || psi(32)))
                 * repr_P(g_d) and v_LE are already serialized in the
                 * Sinsemilla message scratchpad (msg[0..32] / msg[64..72]);
                 * psi already sits at pre+105. */
                pre[0] = 0x0B;
                memcpy(pre + 1, msg, 32);        /* repr_P(g_d) */
                memcpy(pre + 33, pk_d, 32);      /* repr_P(pk_d) */
                memcpy(pre + 65, msg + 64, 8);   /* value LE */
                memcpy(pre + 73, rho, 32);
                prf_expand(rseed, pre, sizeof(pre), prf_out);
                to_scalar(prf_out, rcm_le);
            } else {
                /* ZIP-212 V2: rcm = ToScalar(PRF^expand(rseed, [0x05] || rho)) */
                prf_in[0] = 0x05;
                prf_expand(rseed, prf_in, sizeof(prf_in), prf_out);
                to_scalar(prf_out, rcm_le);
            }
            bn_read_le(rcm_le, &rcm_bn);
            memzero(rcm_le, sizeof(rcm_le));
        }

        memzero(pre, sizeof(pre));
        memzero(prf_out, sizeof(prf_out));
        memzero(prf_in, sizeof(prf_in));
    }

    /* Sinsemilla commit + Extract_P (returns x-coordinate as bignum) */
    bignum256 cmx_bn;
    sinsemilla_short_commit(&cmx_bn, "z.cash:Orchard-NoteCommit", msg, 1086, &rcm_bn);
    bn_write_le(&cmx_bn, cmx_out);

    memzero(msg, sizeof(msg));
    memzero(&rcm_bn, sizeof(rcm_bn));
    memzero(&cmx_bn, sizeof(cmx_bn));
}

/* ------------------------------------------------------------------ */
/*  Orchard note encryption verification helpers                       */
/* ------------------------------------------------------------------ */

/* Decode a Pallas point from its 32-byte repr_P encoding:
 *   bytes[0..30]              = x_LE
 *   bytes[31] bits 0..6       = top 7 bits of x_LE
 *   bytes[31] bit  7          = sign(y) (LSB of y as integer)
 *
 * Recovers y by solving y^2 = x^3 + 5 (the Pallas curve equation with
 * a=0, b=5), then picks the root whose LSB matches the encoded sign bit.
 *
 * Returns 0 on success, -1 if no point lies above x (the encoded x has
 * no square root for x^3 + 5, which means the companion supplied an
 * invalid pk_d/epk — treated as a hostile or corrupt input).
 */
static int pallas_decode_repr_p(pallas_point* out, const uint8_t repr[32]) {
    uint8_t x_le[32];
    memcpy(x_le, repr, 32);
    uint8_t y_sign = (x_le[31] >> 7) & 1u;
    x_le[31] &= 0x7Fu;

    bignum256 x_bn;
    bn_read_le(x_le, &x_bn);
    memzero(x_le, sizeof(x_le));

    /* y^2 = x^3 + 5 */
    bignum256 y2, t;
    fp_sqr(&t, &x_bn);                /* x^2 */
    fp_mul(&y2, &t, &x_bn);           /* x^3 */
    bignum256 five;
    bn_read_uint32(5, &five);
    fp_add(&y2, &y2, &five);          /* y^2 = x^3 + 5 */

    bignum256 y_bn;
    if (!fp_sqrt(&y_bn, &y2)) {
        memzero(&x_bn, sizeof(x_bn));
        memzero(&y2, sizeof(y2));
        return -1;
    }

    /* Pick the root matching the encoded sign. */
    if ((y_bn.val[0] & 1u) != y_sign) {
        fp_neg(&y_bn, &y_bn);
    }

    bn_copy(&x_bn, &out->x);
    bn_copy(&y_bn, &out->y);
    out->infinity = 0;

    memzero(&x_bn, sizeof(x_bn));
    memzero(&y_bn, sizeof(y_bn));
    memzero(&y2, sizeof(y2));
    memzero(&t, sizeof(t));
    return 0;
}

/* Encode a Pallas point to repr_P. */
static void pallas_encode_repr_p(uint8_t out[32], const pallas_point* p) {
    bn_write_le(&p->x, out);
    out[31] &= 0x7Fu;
    if (p->y.val[0] & 1u) out[31] |= 0x80u;
}

/* Derive the per-output ephemeral secret key esk from rseed + rho, per
 * ZIP-212 / Orchard protocol spec §4.7.3:
 *   esk = ToScalar(PRF^expand(rseed, [0x04] || rho))
 *
 * Exposed as a static helper so both the public esk-aware API and the
 * derive-internally API share one implementation.
 */
static void orchard_derive_esk_from_rseed(
    const uint8_t rseed[32],
    const uint8_t rho[32],
    uint8_t esk_out[32])
{
    uint8_t prf_in[1 + 32];
    uint8_t prf_out[64];
    prf_in[0] = 0x04;
    memcpy(prf_in + 1, rho, 32);
    prf_expand(rseed, prf_in, sizeof(prf_in), prf_out);
    to_scalar(prf_out, esk_out);
    memzero(prf_in, sizeof(prf_in));
    memzero(prf_out, sizeof(prf_out));
}

int orchard_compute_enc_ciphertext_from_rseed(
    const uint8_t d[11],
    const uint8_t pk_d[32],
    uint64_t value,
    const uint8_t rseed[32],
    const uint8_t rho[32],
    const uint8_t memo[512],
    uint8_t note_version,
    uint8_t enc_ciphertext_out[580],
    uint8_t epk_out[32])
{
    uint8_t esk[32];
    /* esk derivation is shared between V2 (ZIP-212) and V3 (ZIP-2005)
     * note plaintexts; only the plaintext lead byte and rcm differ. */
    orchard_derive_esk_from_rseed(rseed, rho, esk);
    int rc = orchard_compute_enc_ciphertext(d, pk_d, value, rseed, memo, esk,
                                             note_version,
                                             enc_ciphertext_out, epk_out);
    memzero(esk, sizeof(esk));
    return rc;
}

int orchard_compute_enc_ciphertext(
    const uint8_t d[11],
    const uint8_t pk_d[32],
    uint64_t value,
    const uint8_t rseed[32],
    const uint8_t memo[512],
    const uint8_t esk[32],
    uint8_t note_version,
    uint8_t enc_ciphertext_out[580],
    uint8_t epk_out[32])
{
    /* Static-storage locals to stay within the embedded 512 B per-function
     * stack budget (audit: scripts/check_stack.sh). Same pattern as
     * orchard_compute_cmx() and zip244_transparent_per_input_sighash().
     * The signer state machine is single-threaded per call so re-entrancy
     * is a non-issue; every secret byte is memzero'd before return. */
    static pallas_point g_d;
    static pallas_point epk;
    static pallas_point pk_d_pt;
    static pallas_point ss;
    static bignum256 esk_bn;
    static uint8_t epk_bytes[32];
    static uint8_t ss_bytes[32];
    static uint8_t k_enc[32];
    static uint8_t np[564];
    static blake2b_state h;
    static const uint8_t zero_nonce[12] = {0};

    /* 1. g_d = DiversifyHash(d). Same hash-to-curve used by cmx. */
    pallas_hash_to_curve(&g_d, "z.cash:Orchard-gd", d, 11);

    /* 2. esk as Pallas scalar (the companion-supplied 32 bytes are
     *    treated verbatim, mod q; pallas_point_mul handles reduction). */
    bn_read_le(esk, &esk_bn);

    /* 3. epk = [esk]·g_d, encoded as repr_P. */
    pallas_point_mul(&epk, &esk_bn, &g_d);
    pallas_encode_repr_p(epk_bytes, &epk);
    if (epk_out) memcpy(epk_out, epk_bytes, 32);

    /* 4. SharedSecret = [esk]·pk_d. */
    if (pallas_decode_repr_p(&pk_d_pt, pk_d) != 0) {
        memzero(&g_d, sizeof(g_d));
        memzero(&epk, sizeof(epk));
        memzero(&esk_bn, sizeof(esk_bn));
        memzero(epk_bytes, sizeof(epk_bytes));
        return -1;
    }
    pallas_point_mul(&ss, &esk_bn, &pk_d_pt);
    pallas_encode_repr_p(ss_bytes, &ss);

    /* 5. K_enc = BLAKE2b-256("Zcash_OrchardKDF", ss_bytes || epk_bytes).
     *    Matches Zcash protocol spec §5.4.5.6: the shared secret is hashed
     *    FIRST, then the ephemeral key (cross-validated against the orchard
     *    crate's kdf_orchard in tests/test_ironwood.c — an earlier revision
     *    hashed the two in the opposite order). */
    blake2b_InitPersonal(&h, 32, "Zcash_OrchardKDF", 16);
    blake2b_Update(&h, ss_bytes, 32);
    blake2b_Update(&h, epk_bytes, 32);
    blake2b_Final(&h, k_enc, 32);

    /* 6. Note plaintext (564 bytes):
     *   leadByte || d(11) || value_LE(8) || rseed(32) || memo(512)
     * leadByte = 0x02 for ZIP-212 (Orchard) notes, 0x03 for ZIP-2005
     * (Ironwood V3) notes. The layout is otherwise identical. */
    np[0] = (note_version == ORCHARD_NOTE_V3) ? 0x03 : 0x02;
    memcpy(np + 1, d, 11);
    for (int i = 0; i < 8; i++) {
        np[12 + i] = (uint8_t)((value >> (8 * i)) & 0xFFu);
    }
    memcpy(np + 20, rseed, 32);
    memcpy(np + 52, memo, 512);

    /* 7. enc_ciphertext = ChaCha20-Poly1305_Encrypt(K_enc, nonce=0, np)
     *    The 16-byte tag is appended after the 564-byte ciphertext for a
     *    total of 580 bytes, matching the layout the on-chain action uses. */
    chacha20poly1305_encrypt(
        k_enc, zero_nonce,
        NULL, 0,
        np, 564,
        enc_ciphertext_out,
        enc_ciphertext_out + 564);

    memzero(np, sizeof(np));
    memzero(k_enc, sizeof(k_enc));
    memzero(epk_bytes, sizeof(epk_bytes));
    memzero(ss_bytes, sizeof(ss_bytes));
    memzero(&epk, sizeof(epk));
    memzero(&ss, sizeof(ss));
    memzero(&g_d, sizeof(g_d));
    memzero(&pk_d_pt, sizeof(pk_d_pt));
    memzero(&esk_bn, sizeof(esk_bn));
    memzero(&h, sizeof(h));
    return 0;
}
