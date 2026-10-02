/* Differential tests for the Pallas base-field arithmetic.
 *
 * fp_mul/fp_add/fp_sub are checked against a deliberately naive reference
 * (shift-and-subtract reduction, the algorithm the library used before the
 * special-form folding) on edge values and a pseudo-random sweep. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "pallas.h"

extern void bn_multiply_long(const bignum256* k, const bignum256* x, uint32_t res[2 * BN_LIMBS]);

static void ref_reduce_bits(bignum256* r, const uint32_t* limbs, int nlimbs) {
    const bignum256* p = pallas_p();
    bignum256 tmp;
    bn_zero(r);
    for(int limb = nlimbs - 1; limb >= 0; limb--) {
        for(int bit = BN_BITS_PER_LIMB - 1; bit >= 0; bit--) {
            bn_lshift(r);
            if(limbs[limb] & (1u << bit)) r->val[0] |= 1;
            if(!bn_is_less(r, p)) {
                bn_subtract(r, p, &tmp);
                bn_copy(&tmp, r);
            }
        }
    }
}

static void ref_mul(bignum256* r, const bignum256* a, const bignum256* b) {
    uint32_t res[2 * BN_LIMBS];
    bn_multiply_long(a, b, res);
    ref_reduce_bits(r, res, 2 * BN_LIMBS);
}

static void ref_mod(bignum256* r, const bignum256* a) {
    ref_reduce_bits(r, a->val, BN_LIMBS);
}

static uint64_t s_rng = 0x9e3779b97f4a7c15ULL;
static uint64_t next_u64(void) {
    uint64_t z = (s_rng += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* Any 256-bit value: fp_* must accept non-canonical inputs read straight
 * from untrusted bytes. */
static void random_bn(bignum256* x) {
    uint8_t b[32];
    for(int i = 0; i < 4; i++) {
        uint64_t v = next_u64();
        memcpy(b + 8 * i, &v, 8);
    }
    switch(next_u64() & 7) {
    case 0: memset(b + 16, 0xff, 16); break; /* near 2^256 */
    case 1: memset(b + 8, 0, 24); break;     /* small */
    case 2: b[31] &= 0x3f; break;            /* < 2^254 */
    default: break;
    }
    bn_read_le(b, x);
}

static void check_mul(const bignum256* a, const bignum256* b) {
    bignum256 want, got;
    ref_mul(&want, a, b);
    fp_mul(&got, a, b);
    assert(bn_is_equal(&want, &got));
    assert(bn_is_less(&got, pallas_p()));

    /* aliasing: r == a, r == b, a == b */
    bignum256 t;
    bn_copy(a, &t);
    fp_mul(&t, &t, b);
    assert(bn_is_equal(&want, &t));
    bn_copy(b, &t);
    fp_mul(&t, a, &t);
    assert(bn_is_equal(&want, &t));

    ref_mul(&want, a, a);
    fp_sqr(&got, a);
    assert(bn_is_equal(&want, &got));
}

static void check_add_sub(const bignum256* a, const bignum256* b) {
    /* fp_add/fp_sub are specified on canonical inputs. */
    bignum256 ca, cb, want, got, sum;
    ref_mod(&ca, a);
    ref_mod(&cb, b);

    bn_copy(&ca, &sum);
    bn_add(&sum, &cb);
    ref_mod(&want, &sum);
    fp_add(&got, &ca, &cb);
    assert(bn_is_equal(&want, &got));

    /* (a - b) + b == a */
    fp_sub(&got, &ca, &cb);
    assert(bn_is_less(&got, pallas_p()));
    fp_add(&got, &got, &cb);
    assert(bn_is_equal(&ca, &got));
}

int main(void) {
    pallas_init();

    bignum256 edge[8];
    bn_zero(&edge[0]);
    bn_one(&edge[1]);
    bn_copy(pallas_p(), &edge[2]);                 /* p     */
    bn_copy(pallas_p(), &edge[3]);
    edge[3].val[0] -= 1;                           /* p - 1 */
    bn_copy(pallas_p(), &edge[4]);
    edge[4].val[0] += 1;                           /* p + 1 */
    for(int i = 0; i < BN_LIMBS - 1; i++) edge[5].val[i] = BN_LIMB_MASK;
    edge[5].val[BN_LIMBS - 1] = (1u << BN_BITS_LAST_LIMB) - 1; /* 2^256 - 1 */
    bn_zero(&edge[6]);
    edge[6].val[BN_LIMBS - 1] = 1u << 22;          /* 2^254 */
    bn_zero(&edge[7]);
    edge[7].val[4] = 0x00000224;                   /* top limb of c */

    for(int i = 0; i < 8; i++) {
        for(int j = 0; j < 8; j++) {
            check_mul(&edge[i], &edge[j]);
            check_add_sub(&edge[i], &edge[j]);
        }
    }

    for(int i = 0; i < 20000; i++) {
        bignum256 a, b;
        random_bn(&a);
        random_bn(&b);
        check_mul(&a, &b);
        check_add_sub(&a, &b);
    }

    /* inverse: a·a^-1 == 1 on edge values and a random sweep; 0 -> 0 */
    {
        bignum256 inv, prod;
        fp_inv(&inv, &edge[0]);
        assert(bn_is_zero(&inv));
        fp_inv(&inv, &edge[1]);
        assert(bn_is_one(&inv));
        fp_inv(&inv, &edge[3]); /* (p-1)^-1 == p-1 */
        assert(bn_is_equal(&inv, &edge[3]));
        for(int i = 0; i < 5000; i++) {
            bignum256 raw, a;
            random_bn(&raw);
            ref_mod(&a, &raw);
            if(bn_is_zero(&a)) continue;
            fp_inv(&inv, &a);
            assert(bn_is_less(&inv, pallas_p()));
            fp_mul(&prod, &a, &inv);
            assert(bn_is_one(&prod));
            /* aliasing r == a */
            fp_inv(&a, &a);
            assert(bn_is_equal(&a, &inv));
        }
    }

    /* square root: every square has a root that squares back; squareness
     * agrees with Euler's criterion; 5 generates the non-squares. */
    {
        bignum256 root, back, five, sq, ns;
        int squares = 0, nonsquares = 0;
        bn_read_uint32(5, &five);
        assert(!fp_is_square(&five));
        assert(!fp_sqrt(&root, &five));
        assert(fp_sqrt(&root, &edge[0]) && bn_is_zero(&root));
        assert(fp_sqrt(&root, &edge[1]));
        for(int i = 0; i < 3000; i++) {
            bignum256 raw, a;
            random_bn(&raw);
            ref_mod(&a, &raw);
            if(bn_is_zero(&a)) continue;

            int is_sq = fp_is_square(&a);
            int got = fp_sqrt(&root, &a);
            assert(is_sq == got);
            if(got) {
                fp_sqr(&back, &root);
                assert(bn_is_equal(&back, &a));
                squares++;
            } else {
                nonsquares++;
            }

            /* a^2 is a square, 5·a^2 is not */
            fp_sqr(&sq, &a);
            assert(fp_sqrt(&root, &sq));
            fp_sqr(&back, &root);
            assert(bn_is_equal(&back, &sq));
            fp_mul(&ns, &sq, &five);
            assert(!fp_sqrt(&root, &ns));
        }
        assert(squares > 1000 && nonsquares > 1000);
    }

    /* baked-in Sinsemilla Q / commitment R / spend-auth G points */
    assert(pallas_verify_fixed_points());

    printf("test_field: OK\n");
    return 0;
}
