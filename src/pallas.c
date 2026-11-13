#include "pallas.h"
#include "blake2b.h"
#include "pallas_consts.h"
/* PALLAS_FIXED_BASE_COMB: 1 (default) multiplies the three fixed bases with a
 * precomputed comb table (src/pallas_fixed_base_table.h, 6.5 KB of rodata);
 * 0 drops the table and routes pallas_point_mul_fixed() through the generic
 * constant-time pallas_point_mul(), about half the speed for these
 * multiplications. Same results either way. 0 is for targets where the
 * table does not fit, e.g. a Flipper Zero .fap, which is loaded into RAM. */
#ifndef PALLAS_FIXED_BASE_COMB
#define PALLAS_FIXED_BASE_COMB 1
#endif
#if PALLAS_FIXED_BASE_COMB
#include "pallas_fixed_base_table.h"
#endif
#include "pallas_sqrt_table.h"
#include "memzero.h"
#include <stdio.h>
#include <string.h>

// Progress callback
static pallas_progress_cb s_progress_cb = NULL;
static void* s_progress_ctx = NULL;

void pallas_set_progress_cb(pallas_progress_cb cb, void* ctx) {
    s_progress_cb = cb;
    s_progress_ctx = ctx;
}

void pallas_report(uint8_t pct, const char* label) {
    if(s_progress_cb) s_progress_cb(pct, label, s_progress_ctx);
}

// Yield callback — platform sets this to prevent watchdog reset on
// constrained devices (e.g. furi_delay_tick on Flipper Zero).
// Default: no-op.
static void (*s_yield_fn)(void* ctx) = NULL;
static void* s_yield_ctx = NULL;
static uint32_t s_yield_counter = 0;

void pallas_set_yield_cb(void (*cb)(void* ctx), void* ctx) {
    s_yield_fn = cb;
    s_yield_ctx = ctx;
}

static inline void pallas_yield(void) {
    /* Period sized for the folded fp_mul: 256 field multiplications are
     * roughly the wall-clock the former period of 5 covered when each
     * multiplication ran a 522-step reduction loop. */
    if(s_yield_fn && ++s_yield_counter >= 256) {
        s_yield_counter = 0;
        s_yield_fn(s_yield_ctx);
    }
}

// ============================================================
// Constants
// ============================================================

static const uint8_t PALLAS_P_BE[32] = {
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xed,0x00,0x00,0x00,0x01};
static const uint8_t PALLAS_Q_BE[32] = {
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x46,0x98,0xfc,0x09,0x94,0xa8,0xdd,0x8c,0x46,0xeb,0x21,0x00,0x00,0x00,0x01};
static const uint8_t P_MINUS_1_HALF_BE[32] = {
    0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x11,0x23,0x4c,0x7e,0x04,0xa6,0x7c,0x8d,0xcc,0x96,0x98,0x76,0x80,0x00,0x00,0x00};

// iso-Pallas: y^2 = x^3 + ISO_A*x + ISO_B
static const uint8_t ISO_A_BE[32] = {
    0x18,0x35,0x4a,0x2e,0xb0,0xea,0x8c,0x9c,0x49,0xbe,0x2d,0x72,0x58,0x37,0x07,0x42,
    0xb7,0x41,0x34,0x58,0x1a,0x27,0xa5,0x9f,0x92,0xbb,0x4b,0x0b,0x65,0x7a,0x01,0x4b};
static const uint8_t ISO_B_BE[32] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0xf1};
static const uint8_t SWU_Z_BE[32] = { // -13 mod p
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xec,0xff,0xff,0xff,0xf4};

// 3-isogeny map coefficients (iso-Pallas -> Pallas)
static const uint8_t ISO_C_BE[13][32] = {
    {0x0e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x38,0xe3,0x8e,0x40,0x81,0x77,0x54,0x73,0xd8,0x37,0x5b,0x77,0x5f,0x60,0x34,0xaa,0xaa,0xaa,0xab},
    {0x35,0x09,0xaf,0xd5,0x18,0x72,0xd8,0x8e,0x26,0x7c,0x7f,0xfa,0x51,0xcf,0x41,0x2a,0x0f,0x93,0xb8,0x2e,0xe4,0xb9,0x94,0x95,0x8c,0xf8,0x63,0xb0,0x28,0x14,0xfb,0x76},
    {0x17,0x32,0x9b,0x9e,0xc5,0x25,0x37,0x53,0x98,0xc7,0xd7,0xac,0x3d,0x98,0xfd,0x13,0x38,0x0a,0xf0,0x66,0xcf,0xeb,0x6d,0x69,0x0e,0xb6,0x4f,0xae,0xf3,0x7e,0xa4,0xf7},
    {0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x71,0xc7,0x1c,0x81,0x02,0xee,0xa8,0xe7,0xb0,0x6e,0xb6,0xee,0xbe,0xc0,0x69,0x55,0x55,0x55,0x80},
    {0x1d,0x57,0x2e,0x7d,0xdc,0x09,0x9c,0xff,0x5a,0x60,0x7f,0xcc,0xe0,0x49,0x4a,0x79,0x9c,0x43,0x4a,0xc1,0xc9,0x6b,0x69,0x80,0xc4,0x7f,0x2a,0xb6,0x68,0xbc,0xd7,0x1f},
    {0x32,0x56,0x69,0xbe,0xca,0xec,0xd5,0xd1,0x1d,0x13,0xbf,0x2a,0x7f,0x22,0xb1,0x05,0xb4,0xab,0xf9,0xfb,0x9a,0x1f,0xc8,0x1c,0x2a,0xa3,0xaf,0x1e,0xae,0x5b,0x66,0x04},
    {0x1a,0x12,0xf6,0x84,0xbd,0xa1,0x2f,0x68,0x4b,0xda,0x12,0xf6,0x84,0xbd,0xa1,0x2f,0x76,0x42,0xb0,0x1a,0xd4,0x61,0xba,0xd2,0x5a,0xd9,0x85,0xb5,0xe3,0x8e,0x38,0xe4},
    {0x1a,0x84,0xd7,0xea,0x8c,0x39,0x6c,0x47,0x13,0x3e,0x3f,0xfd,0x28,0xe7,0xa0,0x95,0x07,0xc9,0xdc,0x17,0x72,0x5c,0xca,0x4a,0xc6,0x7c,0x31,0xd8,0x14,0x0a,0x7d,0xbb},
    {0x3f,0xb9,0x8f,0xf0,0xd2,0xdd,0xca,0xdd,0x30,0x32,0x16,0xcc,0xe1,0xdb,0x9f,0xf1,0x17,0x65,0xe9,0x24,0xf7,0x45,0x93,0x78,0x02,0xe2,0xbe,0x87,0xd2,0x25,0xb2,0x34},
    {0x02,0x5e,0xd0,0x97,0xb4,0x25,0xed,0x09,0x7b,0x42,0x5e,0xd0,0x97,0xb4,0x25,0xed,0x0a,0xc0,0x3e,0x8e,0x13,0x4e,0xb3,0xe4,0x93,0xe5,0x3a,0xb3,0x71,0xc7,0x1c,0x4f},
    {0x0c,0x02,0xc5,0xbc,0xca,0x0e,0x6b,0x7f,0x07,0x90,0xbf,0xb3,0x50,0x6d,0xef,0xb6,0x59,0x41,0xa3,0xa4,0xa9,0x7a,0xa1,0xb3,0x5a,0x28,0x27,0x9b,0x1d,0x1b,0x42,0xae},
    {0x17,0x03,0x3d,0x3c,0x60,0xc6,0x81,0x73,0x57,0x3b,0x3d,0x7f,0x7d,0x68,0x13,0x10,0xd9,0x76,0xbb,0xfa,0xbb,0xc5,0x66,0x1d,0x4d,0x90,0xab,0x82,0x0b,0x12,0x32,0x0a},
    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x22,0x46,0x98,0xfc,0x09,0x4c,0xf9,0x1b,0x99,0x2d,0x30,0xec,0xff,0xff,0xfd,0xe5},
};

// Loaded at runtime
static bignum256 s_p, s_q, s_pm1h;
static bignum256 s_iso_a, s_iso_b, s_swu_z;
static bignum256 s_iso_c[13];
static int s_initialized = 0;

void pallas_init(void) {
    if(s_initialized) return;
    bn_read_be(PALLAS_P_BE, &s_p);
    bn_read_be(PALLAS_Q_BE, &s_q);
    bn_read_be(P_MINUS_1_HALF_BE, &s_pm1h);
    bn_read_be(ISO_A_BE, &s_iso_a);
    bn_read_be(ISO_B_BE, &s_iso_b);
    bn_read_be(SWU_Z_BE, &s_swu_z);
    for(int i = 0; i < 13; i++)
        bn_read_be(ISO_C_BE[i], &s_iso_c[i]);
    s_initialized = 1;
}

const bignum256* pallas_p(void) { return &s_p; }
const bignum256* pallas_q(void) { return &s_q; }

// ============================================================
// Field arithmetic mod p
// ============================================================
//
// The Pallas base prime is p = 2^254 + c with a 126-bit c, so a product is
// reduced by folding its high half back with 2^254 ≡ -c (mod p) instead of
// dividing: three short multiplications by c replace the former 522-step
// shift-compare-subtract loop. Values stay in the canonical (non-Montgomery)
// representation, so every caller and every serialization is unchanged.
//
// All of it is straight-line code over limbs: no branch, loop count or
// memory access depends on the operands. (audit M-3)

/* c = p - 2^254, base-2^29 limbs. */
static const uint32_t FP_C[5] = {
    0x00000001, 0x09698768, 0x133e46e6, 0x0d31f812, 0x00000224};
/* c·2^7, i.e. -(2^261) mod p: folds whole limbs above limb 8. */
static const uint32_t FP_C7[5] = {
    0x00000080, 0x14c3b400, 0x1f237325, 0x18fc094c, 0x00011234};
/* 256·p written with every limb below the top one inflated above 2^29, so a
 * normalized 9-limb value can be subtracted limb by limb without a borrow
 * going negative. sum(FP_D[k]·2^(29k)) == 256·p. */
static const uint32_t FP_D[10] = {
    0x40000100, 0x498767fe, 0x5e46e649, 0x51f81297, 0x40022467,
    0x3ffffffe, 0x3ffffffe, 0x3ffffffe, 0x3ffffffe, 0x00000000};
/* p in the same inflated form (limbs 0..7 above 2^29). */
static const uint32_t FP_E[9] = {
    0x40000001, 0x49698766, 0x533e46e4, 0x4d31f810, 0x40000222,
    0x3ffffffe, 0x3ffffffe, 0x3ffffffe, 0x003ffffe};
/* RCB constant b3 = 3·b. For Pallas (y² = x³ + 5), b = 5 → b3 = 15. */
#define FP_B3 15u

static const uint32_t FP_P[9] = {
    0x00000001, 0x09698768, 0x133e46e6, 0x0d31f812, 0x00000224,
    0x00000000, 0x00000000, 0x00000000, 0x00400000};

/* Value barrier for select masks derived from secret data.
 *
 * A mask such as `0u - bit` used as `(a & ~mask) | (b & mask)` is something
 * an optimizer may recognise as `bit ? b : a` and turn back into a
 * conditional branch, or into a select between the two POINTERS followed by
 * a load (a secret-dependent address). clang does both at several -O levels;
 * GCC, as of 16.2, does not. Passing the mask through a volatile object
 * hides its 0 / all-ones structure, so the masked arithmetic is emitted as
 * written. */
static inline uint32_t ct_mask_barrier(uint32_t mask) {
    volatile uint32_t v = mask;
    return v;
}

/* x -= p if x >= p, in constant time. x must be normalized. */
static void fp_cond_sub_p(bignum256* x) {
    uint32_t t[BN_LIMBS];
    uint32_t borrow = 0;
    for(int k = 0; k < BN_LIMBS; k++) {
        uint32_t d = x->val[k] - FP_P[k] - borrow;
        t[k] = d & BN_LIMB_MASK;
        borrow = d >> 31;
    }
    /* borrow == 0  <=>  x >= p  <=>  keep the difference. */
    uint32_t mask = ct_mask_barrier(borrow - 1);
    for(int k = 0; k < BN_LIMBS; k++) {
        x->val[k] = (x->val[k] & ~mask) | (t[k] & mask);
    }
}

/* r = a + b mod p. Operands must be canonical (< p); any aliasing is fine. */
void fp_add(bignum256* r, const bignum256* a, const bignum256* b) {
    uint32_t acc = 0;
    for(int k = 0; k < BN_LIMBS; k++) {
        acc += a->val[k] + b->val[k];
        r->val[k] = acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }
    fp_cond_sub_p(r);
}

/* r = a - b mod p. Operands must be canonical (< p); any aliasing is fine. */
void fp_sub(bignum256* r, const bignum256* a, const bignum256* b) {
    uint32_t t[BN_LIMBS];
    uint32_t borrow = 0;
    for(int k = 0; k < BN_LIMBS; k++) {
        uint32_t d = a->val[k] - b->val[k] - borrow;
        t[k] = d & BN_LIMB_MASK;
        borrow = d >> 31;
    }
    /* On borrow t holds a - b + 2^261: add p, the carry out drops the 2^261. */
    uint32_t mask = 0u - borrow;
    uint32_t acc = 0;
    for(int k = 0; k < BN_LIMBS; k++) {
        acc += t[k] + (FP_P[k] & mask);
        r->val[k] = acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }
}

void fp_neg(bignum256* r, const bignum256* a) {
    static const bignum256 zero = {{0}};
    fp_sub(r, &zero, a);
}

extern void bn_multiply_long(const bignum256* k, const bignum256* x, uint32_t res[2 * BN_LIMBS]);

/* r = (v - q·c) mod p for v < 2^254 (normalized limbs) and q < 2^13: the
 * last step of every reduction, with q the part of the value above bit 254. */
static void fp_fold_254(bignum256* r, const uint32_t v[BN_LIMBS], uint32_t q) {
    uint32_t qc[6];
    uint64_t acc = 0;
    for(int k = 0; k < 5; k++) {
        acc += (uint64_t)q * FP_C[k];
        qc[k] = (uint32_t)acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }
    qc[5] = (uint32_t)acc;

    uint32_t a32 = 0;
    for(int k = 0; k < BN_LIMBS; k++) {
        a32 += v[k] + FP_E[k] - (k < 6 ? qc[k] : 0);
        r->val[k] = a32 & BN_LIMB_MASK;
        a32 >>= BN_BITS_PER_LIMB;
    }
    fp_cond_sub_p(r);
}

/* Reduce an 18-limb product (< 2^522, limbs normalized) to the canonical
 * residue mod p. Bounds, with hi = t[9..17] < 2^261:
 *   y = hi·c7           < 2^394   (14 limbs), t ≡ lo - y
 *   z = y[9..13]·c7     < 2^266   (10 limbs), y ≡ y[0..8] - z
 *   v = lo - y[0..8] + z + 256p   in (0, 2^267)
 *   w = (v mod 2^254) - (v >> 254)·c + p   in (0, 2^254 + p)
 * and one conditional subtraction of p lands in [0, p). */
static void fp_reduce_wide(bignum256* r, const uint32_t t[2 * BN_LIMBS]) {
    uint32_t y[14];
    uint32_t z[10];
    uint32_t v[10];
    uint64_t acc = 0;

    for(int k = 0; k < 14; k++) {
        /* at most 5 products of (29-bit)·(29-bit) plus a < 2^35 carry */
        int j0 = k > 8 ? k - 8 : 0;
        int j1 = k < 4 ? k : 4;
        for(int j = j0; j <= j1; j++) {
            acc += (uint64_t)t[9 + k - j] * FP_C7[j];
        }
        y[k] = (uint32_t)acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }

    acc = 0;
    for(int k = 0; k < 9; k++) {
        int j0 = k > 4 ? k - 4 : 0;
        int j1 = k < 4 ? k : 4;
        for(int j = j0; j <= j1; j++) {
            acc += (uint64_t)y[9 + k - j] * FP_C7[j];
        }
        z[k] = (uint32_t)acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }
    z[9] = (uint32_t)acc;

    acc = 0;
    for(int k = 0; k < 9; k++) {
        acc += (uint64_t)t[k] + z[k] + FP_D[k] - y[k];
        v[k] = (uint32_t)acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }
    v[9] = (uint32_t)acc + z[9] + FP_D[9];

    /* Fold at bit 254 (bit 22 of limb 8). q < 2^13. */
    uint32_t q = (v[8] >> 22) | (v[9] << 7);
    v[8] &= (1u << 22) - 1;
    fp_fold_254(r, v, q);
}

void fp_mul(bignum256* r, const bignum256* a, const bignum256* b) {
    uint32_t t[2 * BN_LIMBS];
    bn_multiply_long(a, b, t);
    fp_reduce_wide(r, t);
    pallas_yield();
}

/* Schoolbook squaring: each cross product a_i·a_j (i < j) is computed once
 * and doubled, 45 limb products instead of 81. */
static void fp_square_long(const bignum256* a, uint32_t res[2 * BN_LIMBS]) {
    uint64_t acc = 0;
    for(int k = 0; k < 2 * BN_LIMBS - 1; k++) {
        /* at most 4 cross products per column: 2·4·2^58 + 2^58 + carry < 2^64 */
        uint64_t cross = 0;
        for(int i = k > 8 ? k - 8 : 0; 2 * i < k; i++) {
            cross += (uint64_t)a->val[i] * a->val[k - i];
        }
        acc += 2 * cross;
        if((k & 1) == 0) acc += (uint64_t)a->val[k / 2] * a->val[k / 2];
        res[k] = (uint32_t)acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }
    res[2 * BN_LIMBS - 1] = (uint32_t)acc;
}

void fp_sqr(bignum256* r, const bignum256* a) {
    uint32_t t[2 * BN_LIMBS];
    fp_square_long(a, t);
    fp_reduce_wide(r, t);
    pallas_yield();
}

/* r = k·a mod p for a small constant k < 2^7 and canonical a. */
static void fp_mul_small(bignum256* r, const bignum256* a, uint32_t k) {
    uint32_t v[BN_LIMBS];
    uint64_t acc = 0;
    for(int i = 0; i < BN_LIMBS - 1; i++) {
        acc += (uint64_t)a->val[i] * k;
        v[i] = (uint32_t)acc & BN_LIMB_MASK;
        acc >>= BN_BITS_PER_LIMB;
    }
    /* a < 2^255 puts limb 8 below 2^23, so the top limb stays below 2^31 */
    v[8] = (uint32_t)acc + a->val[8] * k;
    uint32_t q = v[8] >> 22;
    v[8] &= (1u << 22) - 1;
    fp_fold_254(r, v, q);
}

// r = a^e mod p, left-to-right square-and-multiply. The exponent is a
// public constant at every call site, so only public bits steer the
// multiply branch. e must be non-zero.
static void fp_pow(bignum256* r, const bignum256* a, const bignum256* e) {
    static bignum256 acc;
    int top = 255;
    while(top > 0 && !bn_testbit(e, top)) top--;
    bn_copy(a, &acc);
    for(int i = top - 1; i >= 0; i--) {
        fp_sqr(&acc, &acc);
        if(bn_testbit(e, i)) fp_mul(&acc, &acc, a);
    }
    bn_copy(&acc, r);
    memzero(&acc, sizeof(acc));
}

/* ----------------------------------------------------------------------------
 * Modular inversion: constant-time safegcd (Bernstein-Yang divsteps).
 *
 * Adapted from libsecp256k1's src/modinv32_impl.h, constant-time variant:
 *   Copyright (c) 2020 Peter Dettman. Distributed under the MIT software
 *   license, see https://opensource.org/license/mit.
 *
 * The inverse is computed with 20 batches of 30 divsteps. Each batch is a
 * fixed sequence of masked operations on the low limbs of (f, g), folded
 * into a 2x2 transition matrix that is then applied to the full-width
 * (f, g) and (d, e). 600 divsteps cover every input below 2^256 (the bound
 * for this divstep variant is 590), so the iteration count, the memory
 * access pattern and the instruction trace are independent of the value
 * being inverted.
 *
 * This replaces Fermat exponentiation (254 squarings + 126 multiplications)
 * and keeps the property that motivated it over the earlier Stein binary
 * GCD: no timing dependence on the operand. (audit C-1)
 *
 * Signed right shifts are assumed arithmetic, as libsecp256k1 assumes.
 * ------------------------------------------------------------------------- */

typedef struct { int32_t v[9]; } fp_signed30;
typedef struct { int32_t u, v, q, r; } fp_trans2x2;

#define FP_M30 ((int32_t)(UINT32_MAX >> 2))

/* p in signed-30 limbs; p ≡ 1 (mod 2^30), so p^-1 mod 2^30 == 1. */
static const fp_signed30 FP_P30 = {{
    0x00000001, 0x24b4c3b4, 0x14cf91b9, 0x11a63f02, 0x00000022,
    0x00000000, 0x00000000, 0x00000000, 0x00004000}};
#define FP_P30_INV 1u

static int32_t fp_divsteps_30(int32_t zeta, uint32_t f0, uint32_t g0, fp_trans2x2* t) {
    uint32_t u = 1, v = 0, q = 0, r = 1;
    volatile uint32_t c1, c2;
    uint32_t mask1, mask2, f = f0, g = g0, x, y, z;

    for(int i = 0; i < 30; i++) {
        /* Masks for (zeta < 0) and for (g odd). */
        c1 = (uint32_t)(zeta >> 31);
        mask1 = c1;
        c2 = g & 1;
        mask2 = -c2;
        /* x, y, z: conditionally negated f, u, v. */
        x = (f ^ mask1) - mask1;
        y = (u ^ mask1) - mask1;
        z = (v ^ mask1) - mask1;
        /* Conditionally add them to g, q, r. */
        g += x & mask2;
        q += y & mask2;
        r += z & mask2;
        /* From here mask1 means (zeta < 0) and (g was odd). */
        mask1 &= mask2;
        /* zeta becomes -zeta-2 or zeta-1. */
        zeta = (int32_t)((uint32_t)zeta ^ mask1) - 1;
        /* Conditionally add g, q, r to f, u, v. */
        f += g & mask1;
        u += q & mask1;
        v += r & mask1;
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    t->u = (int32_t)u;
    t->v = (int32_t)v;
    t->q = (int32_t)q;
    t->r = (int32_t)r;
    return zeta;
}

/* (d, e) <- t·(d, e) / 2^30 mod p, keeping both in (-2p, p). */
static void fp_update_de_30(fp_signed30* d, fp_signed30* e, const fp_trans2x2* t) {
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
    int32_t di, ei, md, me, sd, se;
    int64_t cd, ce;

    /* md, me: multiples of p to add so the low 30 bits cancel. */
    sd = d->v[8] >> 31;
    se = e->v[8] >> 31;
    md = (u & sd) + (v & se);
    me = (q & sd) + (r & se);
    di = d->v[0];
    ei = e->v[0];
    cd = (int64_t)u * di + (int64_t)v * ei;
    ce = (int64_t)q * di + (int64_t)r * ei;
    md -= (int32_t)((FP_P30_INV * (uint32_t)cd + (uint32_t)md) & (uint32_t)FP_M30);
    me -= (int32_t)((FP_P30_INV * (uint32_t)ce + (uint32_t)me) & (uint32_t)FP_M30);
    cd += (int64_t)FP_P30.v[0] * md;
    ce += (int64_t)FP_P30.v[0] * me;
    cd >>= 30;
    ce >>= 30;
    for(int i = 1; i < 9; i++) {
        di = d->v[i];
        ei = e->v[i];
        cd += (int64_t)u * di + (int64_t)v * ei;
        ce += (int64_t)q * di + (int64_t)r * ei;
        cd += (int64_t)FP_P30.v[i] * md;
        ce += (int64_t)FP_P30.v[i] * me;
        d->v[i - 1] = (int32_t)cd & FP_M30;
        cd >>= 30;
        e->v[i - 1] = (int32_t)ce & FP_M30;
        ce >>= 30;
    }
    d->v[8] = (int32_t)cd;
    e->v[8] = (int32_t)ce;
}

/* (f, g) <- t·(f, g) / 2^30 (exact). */
static void fp_update_fg_30(fp_signed30* f, fp_signed30* g, const fp_trans2x2* t) {
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
    int32_t fi, gi;
    int64_t cf, cg;

    fi = f->v[0];
    gi = g->v[0];
    cf = (int64_t)u * fi + (int64_t)v * gi;
    cg = (int64_t)q * fi + (int64_t)r * gi;
    cf >>= 30;
    cg >>= 30;
    for(int i = 1; i < 9; i++) {
        fi = f->v[i];
        gi = g->v[i];
        cf += (int64_t)u * fi + (int64_t)v * gi;
        cg += (int64_t)q * fi + (int64_t)r * gi;
        f->v[i - 1] = (int32_t)cf & FP_M30;
        cf >>= 30;
        g->v[i - 1] = (int32_t)cg & FP_M30;
        cg >>= 30;
    }
    f->v[8] = (int32_t)cf;
    g->v[8] = (int32_t)cg;
}

/* Bring r from (-2p, p) to [0, p), negating first if sign < 0. */
static void fp_normalize_30(fp_signed30* r, int32_t sign) {
    volatile int32_t cond_add, cond_negate;

    cond_add = r->v[8] >> 31;
    for(int i = 0; i < 9; i++) r->v[i] += FP_P30.v[i] & cond_add;
    cond_negate = sign >> 31;
    for(int i = 0; i < 9; i++) r->v[i] = (r->v[i] ^ cond_negate) - cond_negate;
    for(int i = 0; i < 8; i++) {
        r->v[i + 1] += r->v[i] >> 30;
        r->v[i] &= FP_M30;
    }

    cond_add = r->v[8] >> 31;
    for(int i = 0; i < 9; i++) r->v[i] += FP_P30.v[i] & cond_add;
    for(int i = 0; i < 8; i++) {
        r->v[i + 1] += r->v[i] >> 30;
        r->v[i] &= FP_M30;
    }
}

/* r = a^-1 mod p (0 maps to 0, as a^(p-2) did). a must be canonical. */
void fp_inv(bignum256* r, const bignum256* a) {
    fp_signed30 d = {{0}}, e = {{1, 0, 0, 0, 0, 0, 0, 0, 0}};
    fp_signed30 f = FP_P30, g;
    fp_trans2x2 t;
    int32_t zeta = -1;

    /* 9x29-bit limbs -> 9x30-bit limbs */
    uint64_t acc = 0;
    int bits = 0, j = 0;
    for(int i = 0; i < BN_LIMBS; i++) {
        acc |= (uint64_t)a->val[i] << bits;
        bits += BN_BITS_PER_LIMB;
        if(bits >= 30 && j < 8) {
            g.v[j++] = (int32_t)(acc & (uint32_t)FP_M30);
            acc >>= 30;
            bits -= 30;
        }
    }
    g.v[8] = (int32_t)acc;

    for(int i = 0; i < 20; i++) {
        zeta = fp_divsteps_30(zeta, (uint32_t)f.v[0], (uint32_t)g.v[0], &t);
        fp_update_de_30(&d, &e, &t);
        fp_update_fg_30(&f, &g, &t);
    }
    /* g == 0 and f == ±1 (f == ±p when a == 0, where d == 0 anyway). */
    fp_normalize_30(&d, f.v[8]);

    /* 9x30-bit limbs -> 9x29-bit limbs */
    acc = 0;
    bits = 0;
    j = 0;
    for(int i = 0; i < 9; i++) {
        acc |= (uint64_t)(uint32_t)d.v[i] << bits;
        bits += 30;
        while(bits >= BN_BITS_PER_LIMB && j < BN_LIMBS) {
            r->val[j++] = (uint32_t)acc & BN_LIMB_MASK;
            acc >>= BN_BITS_PER_LIMB;
            bits -= BN_BITS_PER_LIMB;
        }
    }

    memzero(&d, sizeof(d));
    memzero(&e, sizeof(e));
    memzero(&f, sizeof(f));
    memzero(&g, sizeof(g));
    memzero(&t, sizeof(t));
    pallas_yield();
}

int fp_is_square(const bignum256* a) {
    if(bn_is_zero(a)) return 1;
    // Euler criterion: a^((p-1)/2) == 1
    static bignum256 r;
    fp_pow(&r, a, &s_pm1h);
    int ok = bn_is_one(&r);
    memzero(&r, sizeof(r));
    return ok;
}

/* Square root mod p; returns 1 and a root in r if a is a square, else 0.
 *
 * p - 1 = 2^32·T, so plain Tonelli-Shanks would spend ~S^2/2 squarings
 * resolving the 2-adic part. Instead the discrete log of t = a^T in the
 * order-2^31 subgroup <g^2> is recovered four bits at a time against a
 * small table (src/pallas_sqrt_table.h) — the same idea, with smaller
 * windows, as the Sarkar table square root used by pasta_curves:
 *
 *   w = a^((T-1)/2),  x = a·w = a^((T+1)/2),  t = x·w = a^T = (g^2)^e'
 *   sqrt(a) = x · g^(-e')
 *
 * Which of the two roots comes back is unspecified; callers pick the sign
 * they need. Every call site feeds public values (curve points received
 * from the host, hash-to-curve of public input), but the digit search is
 * written as a full masked scan regardless. */
int fp_sqrt(bignum256* r, const bignum256* a) {
    static bignum256 a_c, w, x, t, s, tmp;
    static const bignum256 one = {{1, 0, 0, 0, 0, 0, 0, 0, 0}};

    fp_mul(&a_c, a, &one); /* canonical a */
    if(bn_is_zero(&a_c)) {
        bn_zero(r);
        return 1;
    }

    fp_pow(&w, &a_c, &FP_SQRT_EXP);
    fp_mul(&x, &a_c, &w);
    fp_mul(&t, &x, &w);

    for(int j = 0; j < 8; j++) {
        /* s = t^(2^(27-4j)) is the 16th root of unity ROOT[digit]; the last
         * window has only three bits left, t itself being ROOT[2·digit]. */
        bn_copy(&t, &s);
        for(int k = 0; k < 27 - 4 * j; k++) fp_sqr(&s, &s);

        uint32_t digit = 0;
        const int step = (j < 7) ? 1 : 2;
        for(uint32_t i = 0; i < 16u / (uint32_t)step; i++) {
            uint32_t eq = (uint32_t)bn_is_equal(&s, &FP_SQRT_ROOT[i * (uint32_t)step]);
            digit |= i & (0u - eq);
        }

        const bignum256* gi = &FP_SQRT_GINV[j][digit];
        fp_mul(&x, &x, gi);
        fp_sqr(&tmp, gi);
        fp_mul(&t, &t, &tmp);
    }

    /* A non-square never matches the table and leaves x meaningless; the
     * final check is what decides. */
    fp_sqr(&tmp, &x);
    int ok = bn_is_equal(&tmp, &a_c);
    if(ok) bn_copy(&x, r);

    memzero(&a_c, sizeof(a_c)); memzero(&w, sizeof(w)); memzero(&x, sizeof(x));
    memzero(&t, sizeof(t)); memzero(&s, sizeof(s)); memzero(&tmp, sizeof(tmp));
    return ok;
}

void fq_reduce(bignum256* r, const bignum256* a) {
    bn_copy(a, r);
    if(!bn_is_less(r, &s_q)) {
        static bignum256 t;
        bn_subtract(r, &s_q, &t);
        bn_copy(&t, r);
        memzero(&t, sizeof(t));
    }
}

// ============================================================
// Point operations on Pallas (Jacobian coordinates)
// ============================================================

void pallas_point_set_infinity(pallas_point* p) {
    bn_zero(&p->x);
    bn_zero(&p->y);
    p->infinity = 1;
}

void pallas_to_jac(pallas_jac* j, const pallas_point* p) {
    /* Affine (X, Y) → projective (X:Y:1). Point at infinity is encoded
     * canonically as (0:1:0) so the RCB formulas have a non-degenerate
     * input: a (0:0:0) input would make every coordinate zero through
     * the formulas. */
    if(p->infinity) {
        bn_zero(&j->x);
        bn_one(&j->y);
        bn_zero(&j->z);
    } else {
        bn_copy(&p->x, &j->x);
        bn_copy(&p->y, &j->y);
        bn_one(&j->z);
    }
}

void pallas_from_jac(pallas_point* p, const pallas_jac* j) {
    /* Projective (X:Y:Z) → affine (X/Z, Y/Z). The Z=0 branch produces the
     * affine "point at infinity" sentinel; this is the FINAL conversion
     * called once on a public ladder output, so the branch does not leak
     * a secret-derived bit (the result coordinates themselves are public). */
    if(bn_is_zero(&j->z)) {
        pallas_point_set_infinity(p);
        return;
    }
    p->infinity = 0;
    static bignum256 zinv;
    fp_inv(&zinv, &j->z);
    fp_mul(&p->x, &j->x, &zinv);
    fp_mul(&p->y, &j->y, &zinv);
    memzero(&zinv, sizeof(zinv));
}

/* ============================================================================
 * Renes-Costello-Batina "Complete addition formulas for prime order elliptic
 * curves" (2016), specialised for short Weierstrass with a = 0 (Pallas).
 *
 * These formulas are EXCEPTION-FREE: they produce the correct result for
 * every input pair, including P = O, Q = O, P = Q (doubling), and P = -Q
 * (sum is infinity). No secret-dependent branch, no early return.
 *
 * The previous Jacobian implementation had three classes of secret-dependent
 * branches: `bn_is_zero(p->z)` early return, `p->infinity` shortcut, and
 * `bn_is_zero(h)` doubling/inversion fallback. Each one took a different
 * code path with measurably different timing, leaking bits of the secret
 * scalar over many ladder iterations. (audit C-1, H-1, H-4)
 *
 * Cost: 12 multiplications + ~14 add/sub per addition,
 *        8 multiplications +  ~6 add/sub per doubling.
 * ============================================================================ */

void pallas_jac_add(pallas_jac* r, const pallas_jac* p, const pallas_jac* q) {
    /* RCB Algorithm 7. Variables named after the paper (t0..t4, X3, Y3, Z3).
     * Operands are aliased through fp_sub's static `nb` intermediate buffer,
     * so r == p or r == q is safe. fp_add/fp_mul tolerate aliasing too. */
    static bignum256 t0, t1, t2, t3, t4;
    static bignum256 X3, Y3, Z3;

    fp_mul(&t0, &p->x, &q->x);          /* 01: t0 = X1·X2          */
    fp_mul(&t1, &p->y, &q->y);          /* 02: t1 = Y1·Y2          */
    fp_mul(&t2, &p->z, &q->z);          /* 03: t2 = Z1·Z2          */
    fp_add(&t3, &p->x, &p->y);          /* 04: t3 = X1+Y1          */
    fp_add(&t4, &q->x, &q->y);          /* 05: t4 = X2+Y2          */
    fp_mul(&t3, &t3, &t4);              /* 06: t3 = t3·t4          */
    fp_add(&t4, &t0, &t1);              /* 07: t4 = t0+t1          */
    fp_sub(&t3, &t3, &t4);              /* 08: t3 = t3-t4          */
    fp_add(&t4, &p->y, &p->z);          /* 09: t4 = Y1+Z1          */
    fp_add(&X3, &q->y, &q->z);          /* 10: X3 = Y2+Z2          */
    fp_mul(&t4, &t4, &X3);              /* 11: t4 = t4·X3          */
    fp_add(&X3, &t1, &t2);              /* 12: X3 = t1+t2          */
    fp_sub(&t4, &t4, &X3);              /* 13: t4 = t4-X3          */
    fp_add(&X3, &p->x, &p->z);          /* 14: X3 = X1+Z1          */
    fp_add(&Y3, &q->x, &q->z);          /* 15: Y3 = X2+Z2          */
    fp_mul(&X3, &X3, &Y3);              /* 16: X3 = X3·Y3          */
    fp_add(&Y3, &t0, &t2);              /* 17: Y3 = t0+t2          */
    fp_sub(&Y3, &X3, &Y3);              /* 18: Y3 = X3-Y3          */
    fp_add(&X3, &t0, &t0);              /* 19: X3 = t0+t0          */
    /* Step 20: t0 = X3+t0. Operands swapped to avoid the fp_add r==b
     * aliasing pitfall (bn_copy(a, r) would clobber b before bn_add reads
     * it). Addition is commutative; mathematically identical. */
    fp_add(&t0, &t0, &X3);              /* 20: t0 = t0+X3          */
    fp_mul_small(&t2, &t2, FP_B3);            /* 21: t2 = b3·t2          */
    fp_add(&Z3, &t1, &t2);              /* 22: Z3 = t1+t2          */
    fp_sub(&t1, &t1, &t2);              /* 23: t1 = t1-t2          */
    fp_mul_small(&Y3, &Y3, FP_B3);            /* 24: Y3 = b3·Y3          */
    fp_mul(&X3, &t4, &Y3);              /* 25: X3 = t4·Y3          */
    fp_mul(&t2, &t3, &t1);              /* 26: t2 = t3·t1          */
    fp_sub(&X3, &t2, &X3);              /* 27: X3 = t2-X3          */
    fp_mul(&Y3, &Y3, &t0);              /* 28: Y3 = Y3·t0          */
    fp_mul(&t1, &t1, &Z3);              /* 29: t1 = t1·Z3          */
    /* Step 30: Y3 = t1+Y3. Operands swapped (alias safety, see step 20). */
    fp_add(&Y3, &Y3, &t1);              /* 30: Y3 = Y3+t1          */
    fp_mul(&t0, &t0, &t3);              /* 31: t0 = t0·t3          */
    fp_mul(&Z3, &Z3, &t4);              /* 32: Z3 = Z3·t4          */
    fp_add(&Z3, &Z3, &t0);              /* 33: Z3 = Z3+t0          */

    bn_copy(&X3, &r->x);
    bn_copy(&Y3, &r->y);
    bn_copy(&Z3, &r->z);

    memzero(&t0, sizeof(t0)); memzero(&t1, sizeof(t1));
    memzero(&t2, sizeof(t2)); memzero(&t3, sizeof(t3)); memzero(&t4, sizeof(t4));
    memzero(&X3, sizeof(X3)); memzero(&Y3, sizeof(Y3)); memzero(&Z3, sizeof(Z3));
}

void pallas_jac_double(pallas_jac* r, const pallas_jac* p) {
    /* RCB Algorithm 9 (a = 0). Exception-free; in particular doubles the
     * point at infinity to itself without an early-return branch. */
    static bignum256 t0, t1, t2;
    static bignum256 X3, Y3, Z3;

    fp_sqr(&t0, &p->y);                 /* 01: t0 = Y·Y            */
    fp_add(&Z3, &t0, &t0);              /* 02: Z3 = t0+t0          */
    fp_add(&Z3, &Z3, &Z3);              /* 03: Z3 = Z3+Z3          */
    fp_add(&Z3, &Z3, &Z3);              /* 04: Z3 = Z3+Z3 (= 8·Y²) */
    fp_mul(&t1, &p->y, &p->z);          /* 05: t1 = Y·Z            */
    fp_sqr(&t2, &p->z);                 /* 06: t2 = Z·Z            */
    fp_mul_small(&t2, &t2, FP_B3);            /* 07: t2 = b3·t2          */
    fp_mul(&X3, &t2, &Z3);              /* 08: X3 = t2·Z3          */
    fp_add(&Y3, &t0, &t2);              /* 09: Y3 = t0+t2          */
    fp_mul(&Z3, &t1, &Z3);              /* 10: Z3 = t1·Z3          */
    fp_add(&t1, &t2, &t2);              /* 11: t1 = t2+t2          */
    /* Step 12: t2 = t1+t2. Operands swapped (alias safety: r==b would
     * clobber via bn_copy). Commutative; mathematically identical. */
    fp_add(&t2, &t2, &t1);              /* 12: t2 = t2+t1          */
    fp_sub(&t0, &t0, &t2);              /* 13: t0 = t0-t2          */
    fp_mul(&Y3, &t0, &Y3);              /* 14: Y3 = t0·Y3          */
    /* Step 15: Y3 = X3+Y3. Operands swapped (alias safety, as in step 12). */
    fp_add(&Y3, &Y3, &X3);              /* 15: Y3 = Y3+X3          */
    fp_mul(&t1, &p->x, &p->y);          /* 16: t1 = X·Y            */
    fp_mul(&X3, &t0, &t1);              /* 17: X3 = t0·t1          */
    fp_add(&X3, &X3, &X3);              /* 18: X3 = X3+X3          */

    bn_copy(&X3, &r->x);
    bn_copy(&Y3, &r->y);
    bn_copy(&Z3, &r->z);

    memzero(&t0, sizeof(t0)); memzero(&t1, sizeof(t1)); memzero(&t2, sizeof(t2));
    memzero(&X3, sizeof(X3)); memzero(&Y3, sizeof(Y3)); memzero(&Z3, sizeof(Z3));
}

void pallas_jac_add_mixed(pallas_jac* r, const pallas_jac* j, const pallas_point* p) {
    /* RCB Algorithm 8: complete mixed addition for a = 0 with Z2 = 1
     * (11 multiplications instead of 12, and two fewer field additions).
     * An affine point cannot encode the identity, so that one input falls
     * back to the fully projective formula; the flag is public at every
     * call site except a zero commitment randomness, where it reveals only
     * that the scalar was zero. */
    if(p->infinity) {
        static pallas_jac q;
        pallas_to_jac(&q, p);
        pallas_jac_add(r, j, &q);
        memzero(&q, sizeof(q));
        return;
    }

    static bignum256 t0, t1, t2, t3, t4;
    static bignum256 X3, Y3, Z3;

    fp_mul(&t0, &j->x, &p->x);          /* 01: t0 = X1·X2          */
    fp_mul(&t1, &j->y, &p->y);          /* 02: t1 = Y1·Y2          */
    fp_add(&t3, &p->x, &p->y);          /* 03: t3 = X2+Y2          */
    fp_add(&t4, &j->x, &j->y);          /* 04: t4 = X1+Y1          */
    fp_mul(&t3, &t3, &t4);              /* 05: t3 = t3·t4          */
    fp_add(&t4, &t0, &t1);              /* 06: t4 = t0+t1          */
    fp_sub(&t3, &t3, &t4);              /* 07: t3 = t3-t4          */
    fp_mul(&t4, &p->y, &j->z);          /* 08: t4 = Y2·Z1          */
    fp_add(&t4, &t4, &j->y);            /* 09: t4 = t4+Y1          */
    fp_mul(&Y3, &p->x, &j->z);          /* 10: Y3 = X2·Z1          */
    fp_add(&Y3, &Y3, &j->x);            /* 11: Y3 = Y3+X1          */
    fp_add(&X3, &t0, &t0);              /* 12: X3 = t0+t0          */
    fp_add(&t0, &X3, &t0);              /* 13: t0 = X3+t0          */
    fp_mul_small(&t2, &j->z, FP_B3);    /* 14: t2 = b3·Z1          */
    fp_add(&Z3, &t1, &t2);              /* 15: Z3 = t1+t2          */
    fp_sub(&t1, &t1, &t2);              /* 16: t1 = t1-t2          */
    fp_mul_small(&Y3, &Y3, FP_B3);      /* 17: Y3 = b3·Y3          */
    fp_mul(&X3, &t4, &Y3);              /* 18: X3 = t4·Y3          */
    fp_mul(&t2, &t3, &t1);              /* 19: t2 = t3·t1          */
    fp_sub(&X3, &t2, &X3);              /* 20: X3 = t2-X3          */
    fp_mul(&Y3, &Y3, &t0);              /* 21: Y3 = Y3·t0          */
    fp_mul(&t1, &t1, &Z3);              /* 22: t1 = t1·Z3          */
    fp_add(&Y3, &t1, &Y3);              /* 23: Y3 = t1+Y3          */
    fp_mul(&t0, &t0, &t3);              /* 24: t0 = t0·t3          */
    fp_mul(&Z3, &Z3, &t4);              /* 25: Z3 = Z3·t4          */
    fp_add(&Z3, &Z3, &t0);              /* 26: Z3 = Z3+t0          */

    bn_copy(&X3, &r->x);
    bn_copy(&Y3, &r->y);
    bn_copy(&Z3, &r->z);

    memzero(&t0, sizeof(t0)); memzero(&t1, sizeof(t1));
    memzero(&t2, sizeof(t2)); memzero(&t3, sizeof(t3)); memzero(&t4, sizeof(t4));
    memzero(&X3, sizeof(X3)); memzero(&Y3, sizeof(Y3)); memzero(&Z3, sizeof(Z3));
}

/* ----------------------------------------------------------------------------
 * GLV scalar decomposition.
 *
 * Pallas has j-invariant 0, hence the endomorphism φ(x, y) = (ζ·x, y) with
 * φ(P) = [λ]P, for cube roots of unity ζ in F_p and λ in F_q. A scalar is
 * split as k ≡ k1 + k2·λ (mod q) with |k1|, |k2| < 2^127, which halves the
 * number of doublings of a scalar multiplication.
 *
 * The split is Babai rounding against a short lattice basis
 * v1 = (V1A, -V1B_NEG), v2 = (V2A, V2B):
 *
 *   c1 = round(G1·k / 2^384)        k1 = k - c1·V1A - c2·V2A
 *   c2 = round(G2·k / 2^384)        k2 =     c1·V1B_NEG - c2·V2B
 *
 * Constants and method are those of zakura-pasta-curves (glv.rs,
 * `GlvParams for pallas::Point`, generated by its sage/glv_constants.sage);
 * unlike that implementation, everything here — the split and the ladder
 * that consumes it — runs in constant time, because the scalars on this
 * path include spend-authorization keys.
 * ------------------------------------------------------------------------- */

/* 32-bit little-endian words. */
static const uint32_t GLV_Q[8] = {
    0x00000001, 0x8c46eb21, 0x0994a8dd, 0x224698fc,
    0x00000000, 0x00000000, 0x00000000, 0x40000000};
static const uint32_t GLV_G1[9] = {
    0x11afc293, 0x111f6861, 0x086862e0, 0xc35fbd4d, 0x00000002,
    0x31f02568, 0x066389a4, 0x4f34e8b2, 0x00000002};
static const uint32_t GLV_G2[9] = {
    0x72171db4, 0x4a95a2d9, 0x8480fa55, 0x61afdea6, 0xffffffff,
    0x32c49e4b, 0x02a2654e, 0x279a7459, 0x00000001};
static const uint32_t GLV_V1A[4] = {0x00000001, 0x7fcae1c7, 0x40f04915, 0x49e69d16};
static const uint32_t GLV_V1B_NEG[4] = {0x00000000, 0x8cb12793, 0x40a89953, 0x49e69d16};
static const uint32_t GLV_V2A[4] = {0x00000000, 0x8cb12793, 0x40a89953, 0x49e69d16};
static const uint32_t GLV_V2B[4] = {0x00000001, 0x0c7c095a, 0x8198e269, 0x93cd3a2c};
/* ζ in F_p with (ζ·x, y) = [λ](x, y); base-2^29 limbs. */
static const bignum256 FP_ZETA = {{
    0x1dfe4ab9, 0x0d6af5ef, 0x0b4c5247, 0x1f17a46f, 0x0b1b01d1,
    0x0aee2bd5, 0x09c4b2ab, 0x106959b7, 0x0012ccca}};

/* out[0..na+nb) = a·b, schoolbook over 32-bit words. */
static void glv_mul_words(uint32_t* out, const uint32_t* a, int na, const uint32_t* b, int nb) {
    for(int i = 0; i < na + nb; i++) out[i] = 0;
    for(int i = 0; i < na; i++) {
        uint64_t carry = 0;
        for(int j = 0; j < nb; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + out[i + j] + carry;
            out[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        out[i + nb] = (uint32_t)carry;
    }
}

/* c = round(g·k / 2^384), a value below 2^128. */
static void glv_round_mul_shift(uint32_t c[4], const uint32_t g[9], const uint32_t k[8]) {
    uint32_t prod[17];
    glv_mul_words(prod, g, 9, k, 8);
    uint64_t carry = prod[11] >> 31; /* rounding bit: bit 383 */
    for(int i = 0; i < 4; i++) {
        carry += prod[12 + i];
        c[i] = (uint32_t)carry;
        carry >>= 32;
    }
    memzero(prod, sizeof(prod));
}

/* x -= y over 8 words, wrapping (two's complement). */
static void glv_sub256(uint32_t x[8], const uint32_t y[8]) {
    uint64_t borrow = 0;
    for(int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)x[i] - y[i] - borrow;
        x[i] = (uint32_t)d;
        borrow = (d >> 32) & 1;
    }
}

/* Split a signed 256-bit two's-complement value known to fit 128 bits into
 * a sign mask (all-ones if negative) and its magnitude. */
static uint32_t glv_signed_half(uint32_t mag[4], const uint32_t x[8]) {
    uint32_t mask = 0u - (x[7] >> 31);
    uint64_t carry = mask & 1;
    for(int i = 0; i < 4; i++) {
        carry += x[i] ^ mask;
        mag[i] = (uint32_t)carry;
        carry >>= 32;
    }
    return mask;
}

/* k ≡ ±mag1 ± mag2·λ (mod q); the returned masks are all-ones for a minus. */
static void glv_decompose(
    const bignum256* k, uint32_t mag1[4], uint32_t* neg1, uint32_t mag2[4], uint32_t* neg2) {
    uint8_t bytes[32];
    uint32_t kw[8], c1[4], c2[4], t[8], k2[8];

    bn_write_le(k, bytes);
    for(int i = 0; i < 8; i++) kw[i] = read_le(bytes + 4 * i);

    /* k < 2^256 < 4q: three conditional subtractions bring it below q. */
    for(int round = 0; round < 3; round++) {
        uint64_t borrow = 0;
        for(int i = 0; i < 8; i++) {
            uint64_t d = (uint64_t)kw[i] - GLV_Q[i] - borrow;
            t[i] = (uint32_t)d;
            borrow = (d >> 32) & 1;
        }
        uint32_t keep = ct_mask_barrier(0u - (uint32_t)borrow); /* borrow: k < q, keep k */
        for(int i = 0; i < 8; i++) kw[i] = (kw[i] & keep) | (t[i] & ~keep);
    }

    glv_round_mul_shift(c1, GLV_G1, kw);
    glv_round_mul_shift(c2, GLV_G2, kw);

    /* k1 = k - c1·V1A - c2·V2A */
    glv_mul_words(t, c1, 4, GLV_V1A, 4);
    glv_sub256(kw, t);
    glv_mul_words(t, c2, 4, GLV_V2A, 4);
    glv_sub256(kw, t);
    /* k2 = c1·V1B_NEG - c2·V2B */
    glv_mul_words(k2, c1, 4, GLV_V1B_NEG, 4);
    glv_mul_words(t, c2, 4, GLV_V2B, 4);
    glv_sub256(k2, t);

    *neg1 = glv_signed_half(mag1, kw);
    *neg2 = glv_signed_half(mag2, k2);

    memzero(bytes, sizeof(bytes));
    memzero(kw, sizeof(kw));
    memzero(k2, sizeof(k2));
    memzero(c1, sizeof(c1));
    memzero(c2, sizeof(c2));
    memzero(t, sizeof(t));
}

// Constant-time scalar multiplication: GLV split + fixed windows.
//
// With k ≡ k1 + k2·λ, [k]P = [k1]P + [k2]φ(P) is evaluated as one
// interleaved ladder over the two 128-bit halves, most significant window
// first: w doublings, then one addition per half of the multiple
// [digit]P read from a single table of 2^w entries. The φ half reuses that
// table — φ acts on a projective point by multiplying X by ζ — and a
// negative half adds the negated point.
//
// Every window runs the same instruction sequence whatever the scalar:
//
//   - a table entry is selected by scanning all 2^w entries under a mask,
//     never by indexing with the digit;
//   - the sign of each half is applied by a masked select between Y and -Y;
//   - digit 0 adds the identity through the same exception-free RCB
//     addition as any other digit, and so does the first window, which
//     doubles and adds onto the identity.
//
// So, as with the Montgomery ladder this replaces, neither the branch
// trace nor the memory access pattern depends on the scalar (audit C-1),
// at 128 doublings + 2·128/w additions instead of 256 + 256.
//
// The table costs 2^w projective points of static RAM (1728 B at w = 4,
// 864 B at w = 3, 432 B at w = 2) and is wiped before returning.
#ifndef PALLAS_POINT_MUL_WINDOW
#define PALLAS_POINT_MUL_WINDOW 4
#endif
#define PALLAS_MUL_TABLE_LEN (1u << PALLAS_POINT_MUL_WINDOW)

/* sel = table[digit], then Y negated iff neg is all-ones. */
static void pallas_mul_select(
    pallas_jac* sel, const pallas_jac* table, const uint32_t mag[4], int win, uint32_t neg) {
    uint32_t digit = 0;
    for(int b = PALLAS_POINT_MUL_WINDOW - 1; b >= 0; b--) {
        int bit = win * PALLAS_POINT_MUL_WINDOW + b;
        digit = (digit << 1) | (bit < 128 ? (mag[bit / 32] >> (bit % 32)) & 1u : 0u);
    }

    memzero(sel, sizeof(*sel));
    for(uint32_t i = 0; i < PALLAS_MUL_TABLE_LEN; i++) {
        /* mask = all-ones iff i == digit */
        uint32_t mask = 0u - (((i ^ digit) - 1u) >> 31);
        for(int l = 0; l < BN_LIMBS; l++) {
            sel->x.val[l] |= table[i].x.val[l] & mask;
            sel->y.val[l] |= table[i].y.val[l] & mask;
            sel->z.val[l] |= table[i].z.val[l] & mask;
        }
    }

    bignum256 ny;
    fp_neg(&ny, &sel->y);
    for(int l = 0; l < BN_LIMBS; l++) {
        sel->y.val[l] = (sel->y.val[l] & ~neg) | (ny.val[l] & neg);
    }
    memzero(&ny, sizeof(ny));
}

/* Scratch shared by pallas_point_mul, pallas_point_mul_fixed and the
 * fixed-base table self-check (single-threaded, never nested); each user
 * wipes what it touched before returning. */
static pallas_jac s_mul_table[PALLAS_MUL_TABLE_LEN];
static pallas_jac s_mul_acc, s_mul_sel;

void pallas_point_mul(pallas_point* r, const bignum256* k, const pallas_point* p) {
    pallas_jac* const table = s_mul_table;
    pallas_jac* const acc = &s_mul_acc;
    pallas_jac* const sel = &s_mul_sel;
    uint32_t mag1[4], mag2[4], neg1, neg2;

    glv_decompose(k, mag1, &neg1, mag2, &neg2);

    /* table[i] = [i]P, with table[0] the identity (0:1:0). */
    bn_zero(&table[0].x);
    bn_one(&table[0].y);
    bn_zero(&table[0].z);
    pallas_to_jac(&table[1], p);
    for(uint32_t i = 2; i < PALLAS_MUL_TABLE_LEN; i++) {
        pallas_jac_add(&table[i], &table[i - 1], &table[1]);
    }

    *acc = table[0];

    const int windows = (128 + PALLAS_POINT_MUL_WINDOW - 1) / PALLAS_POINT_MUL_WINDOW;
    for(int win = windows - 1; win >= 0; win--) {
        for(int d = 0; d < PALLAS_POINT_MUL_WINDOW; d++) {
            pallas_jac_double(acc, acc);
        }

        pallas_mul_select(sel, table, mag1, win, neg1);
        pallas_jac_add(acc, acc, sel);

        pallas_mul_select(sel, table, mag2, win, neg2);
        fp_mul(&sel->x, &sel->x, &FP_ZETA); /* φ */
        pallas_jac_add(acc, acc, sel);

        pallas_yield();
    }
    pallas_from_jac(r, acc);

    // Wipe table, accumulators and the split scalar (statics live in BSS)
    memzero(s_mul_table, sizeof(s_mul_table));
    memzero(acc, sizeof(*acc));
    memzero(sel, sizeof(*sel));
    memzero(mag1, sizeof(mag1));
    memzero(mag2, sizeof(mag2));
    neg1 = neg2 = 0;
}

// Constant-time fixed-base scalar multiplication: Lim-Lee comb.
//
// For the bases that never change — the spend-authorization base G and the
// commitment blinding bases R — the multiples a ladder would compute by
// doubling are precomputed (src/pallas_fixed_base_table.h). The 256-bit
// scalar is cut into TEETH·BLOCKS pieces of SPACING bits; column j of block
// u gathers bit j of that block's TEETH pieces into one 4-bit digit, and
//
//   [k]B = sum_j 2^j · sum_u TABLE[u][digit(u, j)]
//
// is evaluated most significant column first: SPACING doublings and
// 256 / TEETH mixed additions in all (32 + 64 at BLOCKS = 2, against
// 128 doublings + 64 additions + the 14 that build the table in
// pallas_point_mul). No GLV split, and no table built at run time.
//
// The idea of trading a table for the doublings of a fixed base is the one
// behind zakura-pasta-curves' `PreparedFixedBaseSum` (glv/fixed_base.rs,
// zakura-core/common commit 9c9e9e02: doubling-free signed 7-bit windows,
// "about 76 KiB per base", variable-time, public scalars). Only the idea is
// shared. This is a different construction, sized for a microcontroller
// image (2160 B per base) and constant-time, because its scalars are ask,
// rsk, the RedPallas nonce, rivk and rcm:
//
//   - which scalar bits form a digit depends only on the loop counters;
//   - the table entry is picked by scanning all 15 entries under a mask,
//     never by indexing with the digit;
//   - digit 0 runs the same mixed addition as any other digit (on table
//     entry 1, as a dummy) and its result is discarded by a masked select;
//   - the RCB formulas are complete, so the identity accumulator of the
//     first columns and any doubling case take the same path.
//
// The scalar may be any value below 2^256; it is not reduced mod q, the
// comb simply multiplies by the integer.
#if PALLAS_FIXED_BASE_COMB
_Static_assert(PALLAS_COMB_TEETH * PALLAS_COMB_BLOCKS * PALLAS_COMB_SPACING == 256,
               "comb must cover 256 scalar bits");
_Static_assert(PALLAS_COMB_BASES == PALLAS_FIXED_BASE_COUNT, "one comb table per fixed base");
_Static_assert(PALLAS_MUL_TABLE_LEN >= PALLAS_COMB_TEETH, "scratch reused by the table self-check");

void pallas_point_mul_fixed(pallas_point* r, const bignum256* k, pallas_fixed_base base) {
    pallas_jac* const acc = &s_mul_acc;
    pallas_jac* const sum = &s_mul_sel;
    pallas_point sel;
    uint8_t kb[32];
    /* The current digit lives only in these two objects (and in registers
     * between calls); being volatile they are real stack slots that the
     * stores before returning are guaranteed to clear. */
    volatile uint32_t want_v = 0, keep_v = 0;

    /* The base is a public compile-time constant at every call site. An
     * unknown one fails closed: the identity, never another generator. */
    if((unsigned)base >= PALLAS_COMB_BASES) {
        pallas_point_set_infinity(r);
        return;
    }
    const pallas_comb_point (*table)[PALLAS_COMB_ENTRIES] = PALLAS_COMB_TABLE[(unsigned)base];

    bn_write_le(k, kb);

    bn_zero(&acc->x);
    bn_one(&acc->y);
    bn_zero(&acc->z);
    sel.infinity = 0;

    for(int j = PALLAS_COMB_SPACING - 1; j >= 0; j--) {
        pallas_jac_double(acc, acc);

        for(int u = 0; u < PALLAS_COMB_BLOCKS; u++) {
            uint32_t digit = 0;
            for(int t = 0; t < PALLAS_COMB_TEETH; t++) {
                int bit = (t * PALLAS_COMB_BLOCKS + u) * PALLAS_COMB_SPACING + j;
                digit |= (((uint32_t)kb[bit >> 3] >> (bit & 7)) & 1u) << t;
            }

            /* sel = table[u][digit - 1]; digit 0 has no entry (an affine
             * point cannot be the identity) and reads entry 1 as a dummy. */
            {
                const uint32_t is_zero = (digit - 1u) >> 31; /* 1 iff digit == 0 */
                want_v = digit | is_zero;
                keep_v = 0u - is_zero;
            }
            memzero(&sel.x, sizeof(sel.x));
            memzero(&sel.y, sizeof(sel.y));
            for(uint32_t i = 0; i < PALLAS_COMB_ENTRIES; i++) {
                /* mask = all-ones iff i + 1 == want */
                uint32_t mask = 0u - ((((i + 1u) ^ want_v) - 1u) >> 31);
                for(int l = 0; l < BN_LIMBS; l++) {
                    sel.x.val[l] |= table[u][i].x.val[l] & mask;
                    sel.y.val[l] |= table[u][i].y.val[l] & mask;
                }
            }

            pallas_jac_add_mixed(sum, acc, &sel);

            /* acc = digit != 0 ? sum : acc. Reading the mask back from the
             * volatile slot is also the value barrier (ct_mask_barrier):
             * without it clang folds this into a select of the two pointers
             * followed by a load. */
            const uint32_t keep = keep_v;
            for(int l = 0; l < BN_LIMBS; l++) {
                acc->x.val[l] = (acc->x.val[l] & keep) | (sum->x.val[l] & ~keep);
                acc->y.val[l] = (acc->y.val[l] & keep) | (sum->y.val[l] & ~keep);
                acc->z.val[l] = (acc->z.val[l] & keep) | (sum->z.val[l] & ~keep);
            }
        }
        pallas_yield();
    }
    pallas_from_jac(r, acc);

    memzero(acc, sizeof(*acc));
    memzero(sum, sizeof(*sum));
    memzero(&sel, sizeof(sel));
    memzero(kb, sizeof(kb));
    want_v = 0;
    keep_v = 0;
}
#else /* !PALLAS_FIXED_BASE_COMB */

/* No table: the generic constant-time multiplication by the base point
 * (pallas_consts.h, checked by pallas_verify_fixed_points()). Same result
 * as the comb for every k below 2^256. */
void pallas_point_mul_fixed(pallas_point* r, const bignum256* k, pallas_fixed_base base) {
    static const uint8_t idx[PALLAS_FIXED_BASE_COUNT] = {
        [PALLAS_BASE_SPEND_AUTH_G] = 4,  /* "z.cash:Orchard", "G" */
        [PALLAS_BASE_NOTE_COMMIT_R] = 1, /* "z.cash:Orchard-NoteCommit-r" */
        [PALLAS_BASE_COMMIT_IVK_R] = 3,  /* "z.cash:Orchard-CommitIvk-r" */
    };
    if((unsigned)base >= PALLAS_FIXED_BASE_COUNT) {
        pallas_point_set_infinity(r);
        return;
    }
    const pallas_fixed_point* fp = &PALLAS_FIXED_POINTS[idx[(unsigned)base]];
    pallas_point b;
    bn_read_le(fp->xy, &b.x);
    bn_read_le(fp->xy + 32, &b.y);
    b.infinity = 0;
    pallas_point_mul(r, k, &b);
}
#endif /* PALLAS_FIXED_BASE_COMB */

// ============================================================
// Hash-to-curve: simplified SWU + 3-isogeny
// ============================================================

// (expand_message_xmd and hash_to_field are now inlined in pallas_hash_to_curve)

// Simplified SWU map for iso-Pallas (returns projective X, Y)
static void map_to_curve_swu(const bignum256* u, bignum256* out_x, bignum256* out_y) {
    static bignum256 u2, tv1, tv2, y, tmp;

    // tv1 = Z * u^2
    fp_sqr(&u2, u);
    fp_mul(&tv1, &s_swu_z, &u2);

    // tv2 = tv1^2 + tv1
    fp_sqr(&tv2, &tv1);
    fp_add(&tv2, &tv2, &tv1);

    // x1 = (-B/A) * (1 + 1/(tv2))  if tv2 != 0, else x1 = B/(Z*A)
    static bignum256 x1_num, x1_den;
    if(bn_is_zero(&tv2)) {
        // x1 = B/(Z*A) = -B/(A * (-Z))
        fp_mul(&x1_den, &s_iso_a, &s_swu_z); // A*Z
        bn_copy(&s_iso_b, &x1_num);
    } else {
        // x1_num = -B * (tv2 + 1)
        static bignum256 tv2p1;
        bn_one(&tmp);
        fp_add(&tv2p1, &tv2, &tmp);
        fp_mul(&x1_num, &s_iso_b, &tv2p1);
        fp_neg(&x1_num, &x1_num);
        memzero(&tv2p1, sizeof(tv2p1));
        // x1_den = A * tv2
        fp_mul(&x1_den, &s_iso_a, &tv2);
    }

    // gx1 = x1^3 + A*x1 + B (using x1 = x1_num/x1_den)
    // gx1 = (x1_num^3 + A*x1_num*x1_den^2 + B*x1_den^3) / x1_den^3
    static bignum256 xn2, xn3, xd2, xd3, gx1_num;
    fp_sqr(&xn2, &x1_num);
    fp_mul(&xn3, &xn2, &x1_num);
    fp_sqr(&xd2, &x1_den);
    fp_mul(&xd3, &xd2, &x1_den);

    fp_mul(&tmp, &s_iso_a, &x1_num);
    fp_mul(&tmp, &tmp, &xd2);
    fp_add(&gx1_num, &xn3, &tmp);
    fp_mul(&tmp, &s_iso_b, &xd3);
    fp_add(&gx1_num, &gx1_num, &tmp);

    // gx1 = gx1_num / xd3 is a square iff gx1_num * xd3 is, and then
    // sqrt(gx1) = sqrt(gx1_num * xd3) / xd3. Attempting the root directly
    // doubles as the squareness test.
    static bignum256 x_num;
    fp_mul(&tmp, &gx1_num, &xd3);
    if(fp_sqrt(&y, &tmp)) {
        bn_copy(&x1_num, &x_num);
    } else {
        // x2 = Z * u^2 * x1 = tv1 * x1_num / x1_den; gx2 is then a square.
        static bignum256 x2n2, x2n3, gx2_num;
        fp_mul(&x_num, &tv1, &x1_num);
        fp_sqr(&x2n2, &x_num);
        fp_mul(&x2n3, &x2n2, &x_num);
        fp_mul(&tmp, &s_iso_a, &x_num);
        fp_mul(&tmp, &tmp, &xd2);
        fp_add(&gx2_num, &x2n3, &tmp);
        fp_mul(&tmp, &s_iso_b, &xd3);
        fp_add(&gx2_num, &gx2_num, &tmp);

        fp_mul(&tmp, &gx2_num, &xd3);
        fp_sqrt(&y, &tmp);
        memzero(&x2n2, sizeof(x2n2)); memzero(&x2n3, sizeof(x2n3));
        memzero(&gx2_num, sizeof(gx2_num));
    }

    // Affine output: x = x_num / x1_den, y = y / x1_den^3 (one inversion).
    static bignum256 inv;
    fp_inv(&inv, &x1_den);
    fp_mul(out_x, &x_num, &inv);
    fp_sqr(&tmp, &inv);
    fp_mul(&tmp, &tmp, &inv);
    fp_mul(out_y, &y, &tmp);

    // Ensure sgn0(y) == sgn0(u)
    int u_sign = u->val[0] & 1;
    int y_sign = out_y->val[0] & 1;
    if(u_sign != y_sign) {
        fp_neg(out_y, out_y);
    }

    /* Statics (stack budget): the map's input is public at most call sites
     * but not at all of them (Sinsemilla without the S table hashes message
     * chunks), so nothing is left behind. */
    memzero(&u2, sizeof(u2)); memzero(&tv1, sizeof(tv1)); memzero(&tv2, sizeof(tv2));
    memzero(&y, sizeof(y)); memzero(&tmp, sizeof(tmp));
    memzero(&x1_num, sizeof(x1_num)); memzero(&x1_den, sizeof(x1_den));
    memzero(&xn2, sizeof(xn2)); memzero(&xn3, sizeof(xn3));
    memzero(&xd2, sizeof(xd2)); memzero(&xd3, sizeof(xd3));
    memzero(&gx1_num, sizeof(gx1_num)); memzero(&x_num, sizeof(x_num));
    memzero(&inv, sizeof(inv));
}

// 3-isogeny map from iso-Pallas to Pallas
static void iso_map(const bignum256* ix, const bignum256* iy, bignum256* ox, bignum256* oy) {
    // x_num = c[0]*x^3 + c[1]*x^2 + c[2]*x + c[3]
    // x_den = x^2 + c[4]*x + c[5]
    // y_num = c[6]*x^3 + c[7]*x^2 + c[8]*x + c[9]
    // y_den = x^3 + c[10]*x^2 + c[11]*x + c[12]
    static bignum256 x2, x3, tmp;
    fp_sqr(&x2, ix);
    fp_mul(&x3, &x2, ix);

    // x_num
    static bignum256 xn;
    fp_mul(&xn, &s_iso_c[0], &x3);
    fp_mul(&tmp, &s_iso_c[1], &x2);
    fp_add(&xn, &xn, &tmp);
    fp_mul(&tmp, &s_iso_c[2], ix);
    fp_add(&xn, &xn, &tmp);
    fp_add(&xn, &xn, &s_iso_c[3]);

    // x_den
    static bignum256 xd;
    fp_add(&xd, &x2, &tmp); // tmp is c[2]*x, recompute
    bn_copy(&x2, &xd);
    fp_mul(&tmp, &s_iso_c[4], ix);
    fp_add(&xd, &xd, &tmp);
    fp_add(&xd, &xd, &s_iso_c[5]);

    // y_num
    static bignum256 yn;
    fp_mul(&yn, &s_iso_c[6], &x3);
    fp_mul(&tmp, &s_iso_c[7], &x2);
    fp_add(&yn, &yn, &tmp);
    fp_mul(&tmp, &s_iso_c[8], ix);
    fp_add(&yn, &yn, &tmp);
    fp_add(&yn, &yn, &s_iso_c[9]);

    // y_den
    static bignum256 yd;
    bn_copy(&x3, &yd);
    fp_mul(&tmp, &s_iso_c[10], &x2);
    fp_add(&yd, &yd, &tmp);
    fp_mul(&tmp, &s_iso_c[11], ix);
    fp_add(&yd, &yd, &tmp);
    fp_add(&yd, &yd, &s_iso_c[12]);

    // ox = xn / xd
    static bignum256 inv;
    fp_inv(&inv, &xd);
    fp_mul(ox, &xn, &inv);

    // oy = iy * yn / yd
    fp_inv(&inv, &yd);
    fp_mul(oy, &yn, &inv);
    fp_mul(oy, oy, iy);

    memzero(&x2, sizeof(x2)); memzero(&x3, sizeof(x3)); memzero(&tmp, sizeof(tmp));
    memzero(&xn, sizeof(xn)); memzero(&xd, sizeof(xd));
    memzero(&yn, sizeof(yn)); memzero(&yd, sizeof(yd)); memzero(&inv, sizeof(inv));
}

// Full hash-to-curve for Pallas
// Matches pasta_curves::hashtocurve::hash_to_field exactly
static void hash_to_curve_compute(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len) {
    pallas_init();

    // pasta_curves uses CHUNKLEN=64, builds DST inline in BLAKE2b input (not personalization)
    // DST = domain_prefix + "-pallas_XMD:BLAKE2b_SSWU_RO_" + len_byte
    // BLAKE2b personalization = 16 zero bytes
    const char* curve_suffix = "-pallas_XMD:BLAKE2b_SSWU_RO_";
    size_t dom_len = strlen(domain);
    size_t suf_len = strlen(curve_suffix);
    size_t dst_total = dom_len + suf_len;
    uint8_t dst_len_byte = (uint8_t)dst_total;

    const uint8_t personal[16] = {0};
    const int CHUNKLEN = 64;
    static uint8_t b0[64], b1[64], b2[64];

    // b_0 = BLAKE2b-64(personal=zeros, Z_pad(128) || msg || I2OSP(128,2) || I2OSP(0,1) || DST || len)
    {
        static blake2b_state S;
        blake2b_InitPersonal(&S, CHUNKLEN, personal, 16);
        static uint8_t zeros[128];
        memset(zeros, 0, 128);
        blake2b_Update(&S, zeros, 128);
        blake2b_Update(&S, msg, msg_len);
        uint8_t len_buf[3] = {0, (uint8_t)(CHUNKLEN * 2), 0}; // I2OSP(128,2) || I2OSP(0,1)
        blake2b_Update(&S, len_buf, 3);
        blake2b_Update(&S, (const uint8_t*)domain, dom_len);
        blake2b_Update(&S, (const uint8_t*)curve_suffix, suf_len);
        blake2b_Update(&S, &dst_len_byte, 1);
        blake2b_Final(&S, b0, CHUNKLEN);
        memzero(&S, sizeof(S));
    }

    // b_1 = BLAKE2b-64(personal=zeros, b_0 || I2OSP(1,1) || DST || len)
    {
        static blake2b_state S;
        blake2b_InitPersonal(&S, CHUNKLEN, personal, 16);
        blake2b_Update(&S, b0, CHUNKLEN);
        uint8_t one = 1;
        blake2b_Update(&S, &one, 1);
        blake2b_Update(&S, (const uint8_t*)domain, dom_len);
        blake2b_Update(&S, (const uint8_t*)curve_suffix, suf_len);
        blake2b_Update(&S, &dst_len_byte, 1);
        blake2b_Final(&S, b1, CHUNKLEN);
        memzero(&S, sizeof(S));
    }

    // b_2 = BLAKE2b-64(personal=zeros, (b_0 XOR b_1) || I2OSP(2,1) || DST || len)
    {
        static blake2b_state S;
        blake2b_InitPersonal(&S, CHUNKLEN, personal, 16);
        static uint8_t xored[64];
        for(int j = 0; j < 64; j++) xored[j] = b0[j] ^ b1[j];
        blake2b_Update(&S, xored, CHUNKLEN);
        uint8_t two = 2;
        blake2b_Update(&S, &two, 1);
        blake2b_Update(&S, (const uint8_t*)domain, dom_len);
        blake2b_Update(&S, (const uint8_t*)curve_suffix, suf_len);
        blake2b_Update(&S, &dst_len_byte, 1);
        blake2b_Final(&S, b2, CHUNKLEN);
        memzero(&S, sizeof(S));
        memzero(xored, sizeof(xored));
    }

    // Hash to field: reverse each 64-byte block, then reduce mod p
    // u0 = from_uniform_bytes(reverse(b1))
    // u1 = from_uniform_bytes(reverse(b2))
    // u = (lo + hi·2^256) mod p, with lo/hi the two 256-bit halves.
    static bignum256 u0, u1;
    {
        static const bignum256 one = {{1, 0, 0, 0, 0, 0, 0, 0, 0}};
        static const bignum256 two_256 = {{ /* 2^256 mod p */
            0x1ffffffd, 0x03c369c7, 0x06452b4d, 0x186a17c8, 0x1ffff992,
            0x1fffffff, 0x1fffffff, 0x1fffffff, 0x003fffff}};
        static uint8_t rev[64];
        static bignum256 lo, hi;

        for(int i = 0; i < 64; i++) rev[i] = b1[63 - i];
        bn_read_le(rev, &lo);
        bn_read_le(rev + 32, &hi);
        fp_mul(&lo, &lo, &one);
        fp_mul(&hi, &hi, &two_256);
        fp_add(&u0, &lo, &hi);

        for(int i = 0; i < 64; i++) rev[i] = b2[63 - i];
        bn_read_le(rev, &lo);
        bn_read_le(rev + 32, &hi);
        fp_mul(&lo, &lo, &one);
        fp_mul(&hi, &hi, &two_256);
        fp_add(&u1, &lo, &hi);

        memzero(rev, sizeof(rev));
        memzero(&lo, sizeof(lo));
        memzero(&hi, sizeof(hi));
    }
    memzero(b0, sizeof(b0));
    memzero(b1, sizeof(b1));
    memzero(b2, sizeof(b2));

    // Map to iso-Pallas via SWU, apply isogeny, and add.
    // All large intermediates are static to avoid ~700 bytes stack pressure.
    {
        static bignum256 ix0, iy0, ix1, iy1;
        map_to_curve_swu(&u0, &ix0, &iy0);
        map_to_curve_swu(&u1, &ix1, &iy1);

        static bignum256 px0, py0, px1, py1;
        iso_map(&ix0, &iy0, &px0, &py0);
        iso_map(&ix1, &iy1, &px1, &py1);

        static pallas_point p0, p1;
        bn_copy(&px0, &p0.x); bn_copy(&py0, &p0.y); p0.infinity = 0;
        bn_copy(&px1, &p1.x); bn_copy(&py1, &p1.y); p1.infinity = 0;

        static pallas_jac j0, jtmp;
        pallas_to_jac(&j0, &p0);
        pallas_jac_add_mixed(&jtmp, &j0, &p1);
        pallas_from_jac(r, &jtmp);

        memzero(&ix0, sizeof(ix0)); memzero(&iy0, sizeof(iy0));
        memzero(&ix1, sizeof(ix1)); memzero(&iy1, sizeof(iy1));
        memzero(&px0, sizeof(px0)); memzero(&py0, sizeof(py0));
        memzero(&px1, sizeof(px1)); memzero(&py1, sizeof(py1));
        memzero(&p0, sizeof(p0)); memzero(&p1, sizeof(p1));
        memzero(&j0, sizeof(j0)); memzero(&jtmp, sizeof(jtmp));
    }
    memzero(&u0, sizeof(u0));
    memzero(&u1, sizeof(u1));
}

static const pallas_fixed_point* fixed_point_find(const char* domain, const uint8_t* msg, size_t msg_len) {
    for(size_t i = 0; i < PALLAS_FIXED_POINTS_COUNT; i++) {
        const pallas_fixed_point* fp = &PALLAS_FIXED_POINTS[i];
        if(strcmp(fp->domain, domain) == 0 && strlen(fp->msg) == msg_len &&
           memcmp(fp->msg, msg, msg_len) == 0) {
            return fp;
        }
    }
    return NULL;
}

void pallas_hash_to_curve(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len) {
    /* Domains and messages are public protocol constants or public inputs,
     * so the table scan may be data-dependent. */
    const pallas_fixed_point* fp = fixed_point_find(domain, msg, msg_len);
    if(fp) {
        bn_read_le(fp->xy, &r->x);
        bn_read_le(fp->xy + 32, &r->y);
        r->infinity = 0;
        return;
    }
    hash_to_curve_compute(r, domain, msg, msg_len);
}

#if PALLAS_FIXED_BASE_COMB
/* Which hash-to-curve output each comb table belongs to, in
 * pallas_fixed_base order. */
static const struct {
    const char* domain;
    const char* msg;
} PALLAS_FIXED_BASES[PALLAS_FIXED_BASE_COUNT] = {
    [PALLAS_BASE_SPEND_AUTH_G] = {"z.cash:Orchard", "G"},
    [PALLAS_BASE_NOTE_COMMIT_R] = {"z.cash:Orchard-NoteCommit-r", ""},
    [PALLAS_BASE_COMMIT_IVK_R] = {"z.cash:Orchard-CommitIvk-r", ""},
};

/* Rebuild the comb table of one base from the base point itself (taken
 * from a fresh hash-to-curve, not from pallas_consts.h) and compare every
 * entry. Returns 0 iff all match. Public data throughout. */
static int fixed_base_table_diff(unsigned base) {
    pallas_jac* const tooth = s_mul_table; /* [2^((t·BLOCKS + u)·SPACING)]B */
    pallas_jac* const run = &s_mul_acc;
    pallas_jac* const sum = &s_mul_sel;
    pallas_point pt;
    int diff = 0;

    for(int u = 0; u < PALLAS_COMB_BLOCKS; u++) {
        hash_to_curve_compute(
            &pt, PALLAS_FIXED_BASES[base].domain,
            (const uint8_t*)PALLAS_FIXED_BASES[base].msg,
            strlen(PALLAS_FIXED_BASES[base].msg));
        pallas_to_jac(run, &pt);
        for(int m = 0; m < PALLAS_COMB_TEETH * PALLAS_COMB_BLOCKS; m++) {
            if(m % PALLAS_COMB_BLOCKS == u) tooth[m / PALLAS_COMB_BLOCKS] = *run;
            for(int i = 0; i < PALLAS_COMB_SPACING; i++) pallas_jac_double(run, run);
        }

        for(uint32_t d = 1; d <= PALLAS_COMB_ENTRIES; d++) {
            bn_zero(&sum->x);
            bn_one(&sum->y);
            bn_zero(&sum->z);
            for(int t = 0; t < PALLAS_COMB_TEETH; t++) {
                if((d >> t) & 1u) pallas_jac_add(sum, sum, &tooth[t]);
            }
            pallas_from_jac(&pt, sum);
            const pallas_comb_point* e = &PALLAS_COMB_TABLE[base][u][d - 1];
            diff |= pt.infinity;
            diff |= !bn_is_equal(&pt.x, &e->x);
            diff |= !bn_is_equal(&pt.y, &e->y);
        }
    }

    memzero(s_mul_table, sizeof(s_mul_table));
    memzero(run, sizeof(*run));
    memzero(sum, sizeof(*sum));
    return diff;
}
#endif /* PALLAS_FIXED_BASE_COMB */

bool pallas_verify_fixed_points(void) {
    int diff = 0;
    for(size_t i = 0; i < PALLAS_FIXED_POINTS_COUNT; i++) {
        const pallas_fixed_point* fp = &PALLAS_FIXED_POINTS[i];
        pallas_point p;
        uint8_t xy[64];
        hash_to_curve_compute(&p, fp->domain, (const uint8_t*)fp->msg, strlen(fp->msg));
        bn_write_le(&p.x, xy);
        bn_write_le(&p.y, xy + 32);
        for(int j = 0; j < 64; j++) diff |= xy[j] ^ fp->xy[j];
    }
#if PALLAS_FIXED_BASE_COMB
    for(unsigned b = 0; b < PALLAS_FIXED_BASE_COUNT; b++) {
        diff |= fixed_base_table_diff(b);
    }
#endif
    return diff == 0;
}

void pallas_group_hash(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len) {
    pallas_hash_to_curve(r, domain, msg, msg_len);
}

// ============================================================
// Sinsemilla hash
// ============================================================

// Sinsemilla S lookup: 1024 precomputed points (64 KB binary)
// S_i = hash_to_curve("z.cash:SinsemillaS")(i.to_le_bytes()), i in 0..1024
// Each entry: 64 bytes (x_le 32 || y_le 32)
//
// Platform integrators can register a lookup callback to load points from
// storage (SD card, flash, etc.) instead of computing them on-the-fly.
// See pallas_set_sinsemilla_lookup() in pallas.h.

static pallas_sinsemilla_lookup_fn s_sinsemilla_lookup = NULL;
static void* s_sinsemilla_lookup_ctx = NULL;

void pallas_set_sinsemilla_lookup(pallas_sinsemilla_lookup_fn fn, void* ctx) {
    s_sinsemilla_lookup = fn;
    s_sinsemilla_lookup_ctx = ctx;
}

/* Canonical BLAKE2b-256 (unpersonalized, 32-byte output) of the 64 KB
 * Sinsemilla S-table, in the byte order produced by the lookup callback
 * `(x_le[32] || y_le[32])` for indices 0..1023.
 *
 * Recompute on a clean source tree:
 *   b2sum -l 256 src/sinsemilla_s.bin
 *
 * Audit: docs/security-audit/01-crypto-c-primitives.md M-5. */
static const uint8_t SINSEMILLA_S_DIGEST_EXPECTED[32] = {
    0xf5,0x3e,0x52,0x90,0xdd,0xa0,0xd2,0x25,
    0x7b,0x1f,0x2c,0xf6,0x4f,0x0b,0x16,0xe9,
    0xdf,0xdf,0xe9,0xcc,0x9a,0x9b,0x24,0x9c,
    0x91,0x37,0xcc,0x6a,0xab,0x45,0x25,0x97,
};

bool pallas_verify_sinsemilla_table(void) {
    /* No table = on-the-fly computation; nothing to verify. */
    if (s_sinsemilla_lookup == NULL) return true;

    blake2b_state s;
    blake2b_Init(&s, 32);

    uint8_t entry[64];
    for (uint32_t i = 0; i < 1024; i++) {
        if (!s_sinsemilla_lookup(i, entry, s_sinsemilla_lookup_ctx)) {
            memzero(entry, sizeof(entry));
            return false;
        }
        blake2b_Update(&s, entry, 64);
        pallas_yield(); /* avoid watchdog reset on slow callbacks */
    }
    memzero(entry, sizeof(entry));

    uint8_t computed[32];
    blake2b_Final(&s, computed, 32);

    /* Constant-time compare so timing does not reveal which prefix matched
     * (would only matter if an attacker could supply a partially-tampered
     * table, but uniform timing is a no-cost defensive habit). */
    int diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (int)(computed[i] ^ SINSEMILLA_S_DIGEST_EXPECTED[i]);
    }
    memzero(computed, sizeof(computed));
    memzero(&s, sizeof(s));
    return diff == 0;
}

void sinsemilla_hash_to_point(
    pallas_point* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits) {
    pallas_init();

    // Q = GroupHash("z.cash:SinsemillaQ", domain)
    pallas_point Q;
    pallas_group_hash(&Q, "z.cash:SinsemillaQ", (const uint8_t*)domain, strlen(domain));

    static pallas_jac acc;
    pallas_to_jac(&acc, &Q);

    bool has_table = (s_sinsemilla_lookup != NULL);

    /* Per the Sinsemilla specification, a partial final chunk is zero-padded
     * to K=10 bits and processed like a full chunk. */
    size_t num_full_chunks = num_bits / 10;
    size_t remainder_bits  = num_bits % 10;
    size_t num_chunks      = num_full_chunks + (remainder_bits > 0 ? 1 : 0);
    for(size_t i = 0; i < num_chunks; i++) {
        pallas_report(35 + (uint8_t)(i * 35 / num_chunks),
            has_table ? "Sinsemilla (fast)..." : "Sinsemilla (slow)...");

        uint32_t chunk = 0;
        int chunk_bits = (i < num_full_chunks) ? 10 : (int)remainder_bits;
        for(int b = 0; b < chunk_bits; b++) {
            size_t bit_idx = i * 10 + b;
            if(msg_bits[bit_idx / 8] & (1 << (bit_idx % 8))) {
                chunk |= (1 << b);
            }
        }

        pallas_point S;
        bool got = false;
        if(s_sinsemilla_lookup) {
            uint8_t buf[64];
            got = s_sinsemilla_lookup(chunk, buf, s_sinsemilla_lookup_ctx);
            if(got) {
                bn_read_le(buf, &S.x);
                bn_read_le(buf + 32, &S.y);
                S.infinity = 0;
            }
            memzero(buf, sizeof(buf));
        }
        if(!got) {
            // Slow fallback: compute on-the-fly
            uint8_t chunk_le[4] = {(uint8_t)(chunk & 0xff), (uint8_t)((chunk >> 8) & 0xff), 0, 0};
            pallas_group_hash(&S, "z.cash:SinsemillaS", chunk_le, 4);
        }

        /* Sinsemilla step: acc <- (acc + S) + acc = [2]acc + S.
         *
         * `acc` stays projective for the whole message (one inversion at
         * the very end, not one per chunk). With the complete RCB formulas
         * the incomplete-addition exceptions of the specification cannot
         * arise, so the step is evaluated as one doubling plus one mixed
         * addition with the affine table point — 18 field multiplications
         * against 24 for two general additions. */
        static pallas_jac tmp;
        pallas_jac_double(&tmp, &acc);
        pallas_jac_add_mixed(&acc, &tmp, &S);

        /* The table point is selected by the message chunk: not kept. */
        memzero(&tmp, sizeof(tmp));
        memzero(&S, sizeof(S));
        chunk = 0;
    }

    pallas_from_jac(r, &acc);
    memzero(&acc, sizeof(acc));
}

void sinsemilla_short_commit(
    bignum256* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits,
    const bignum256* rcm) {
    pallas_init();

    // S = SinsemillaHashToPoint(domain + "-M", M)
    char m_domain[128] = {0};
    snprintf(m_domain, sizeof(m_domain), "%s-M", domain);
    static pallas_point S;
    sinsemilla_hash_to_point(&S, m_domain, msg_bits, num_bits);

    // commit = S + [rcm] * R, with R = hash_to_curve(domain + "-r")(&[]).
    // The two protocol domains have a comb table for R; the domain string
    // is a public constant, so choosing the path by it leaks nothing.
    static pallas_point rcm_R;
    if(strcmp(domain, "z.cash:Orchard-NoteCommit") == 0) {
        pallas_point_mul_fixed(&rcm_R, rcm, PALLAS_BASE_NOTE_COMMIT_R);
    } else if(strcmp(domain, "z.cash:Orchard-CommitIvk") == 0) {
        pallas_point_mul_fixed(&rcm_R, rcm, PALLAS_BASE_COMMIT_IVK_R);
    } else {
        char r_domain[128] = {0};
        snprintf(r_domain, sizeof(r_domain), "%s-r", domain);
        static pallas_point R;
        pallas_hash_to_curve(&R, r_domain, (const uint8_t*)"", 0);
        pallas_point_mul(&rcm_R, rcm, &R);
        memzero(&R, sizeof(R));
    }

    static pallas_jac j;
    pallas_to_jac(&j, &S);
    static pallas_jac tmp;
    pallas_jac_add_mixed(&tmp, &j, &rcm_R);

    static pallas_point commit;
    pallas_from_jac(&commit, &tmp);

    // Extract x-coordinate
    bn_copy(&commit.x, r);

    /* S is the un-blinded commitment and rcm_R the blinding term: either
     * one next to the public commitment gives the other away. */
    memzero(&S, sizeof(S));
    memzero(&rcm_R, sizeof(rcm_R));
    memzero(&j, sizeof(j));
    memzero(&tmp, sizeof(tmp));
    memzero(&commit, sizeof(commit));
}
