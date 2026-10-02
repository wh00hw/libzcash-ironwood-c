/* Differential tests for the Pallas group operations.
 *
 * pallas_point_mul (fixed-window, table based) and pallas_jac_add_mixed
 * (RCB mixed addition) are checked against the plainest possible reference:
 * bit-by-bit double-and-add built on the fully projective addition. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "pallas.h"

static uint64_t s_rng = 0x243f6a8885a308d3ULL;
static uint64_t next_u64(void) {
    uint64_t z = (s_rng += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void random_scalar(bignum256* k) {
    uint8_t b[32];
    for(int i = 0; i < 4; i++) {
        uint64_t v = next_u64();
        memcpy(b + 8 * i, &v, 8);
    }
    switch(next_u64() & 7) {
    case 0: memset(b + 4, 0, 28); break;  /* short */
    case 1: memset(b, 0xff, 16); break;   /* long runs of ones */
    case 2: memset(b + 16, 0, 16); break; /* half width */
    default: break;                       /* full 256 bits, may exceed q */
    }
    bn_read_le(b, k);
}

static void ref_mul(pallas_point* r, const bignum256* k, const pallas_point* p) {
    pallas_jac acc, base, t;
    pallas_point inf;
    pallas_point_set_infinity(&inf);
    pallas_to_jac(&acc, &inf);
    pallas_to_jac(&base, p);
    for(int i = 255; i >= 0; i--) {
        pallas_jac_double(&t, &acc);
        acc = t;
        if(bn_testbit(k, (uint16_t)i)) {
            pallas_jac_add(&t, &acc, &base);
            acc = t;
        }
    }
    pallas_from_jac(r, &acc);
}

static int point_eq(const pallas_point* a, const pallas_point* b) {
    if(a->infinity || b->infinity) return a->infinity && b->infinity;
    return bn_is_equal(&a->x, &b->x) && bn_is_equal(&a->y, &b->y);
}

static void check_mul(const bignum256* k, const pallas_point* p) {
    pallas_point want, got;
    ref_mul(&want, k, p);
    pallas_point_mul(&got, k, p);
    assert(point_eq(&want, &got));
}

int main(void) {
    pallas_init();

    pallas_point G, H;
    pallas_group_hash(&G, "z.cash:Orchard", (const uint8_t*)"G", 1);
    pallas_hash_to_curve(&H, "z.cash:Orchard-gd", (const uint8_t*)"test_curve!", 11);

    /* edge scalars: 0, 1, 2, q-1, q, q+1, 2^256-1 */
    bignum256 k;
    pallas_point r;
    bn_zero(&k);
    pallas_point_mul(&r, &k, &G);
    assert(r.infinity);
    bn_one(&k);
    pallas_point_mul(&r, &k, &G);
    assert(point_eq(&r, &G));
    bn_read_uint32(2, &k);
    check_mul(&k, &G);
    bn_copy(pallas_q(), &k);
    pallas_point_mul(&r, &k, &G);
    assert(r.infinity);
    k.val[0] -= 1; /* q - 1: -G */
    pallas_point_mul(&r, &k, &G);
    assert(!r.infinity && bn_is_equal(&r.x, &G.x) && !bn_is_equal(&r.y, &G.y));
    k.val[0] += 2; /* q + 1: G */
    pallas_point_mul(&r, &k, &G);
    assert(point_eq(&r, &G));
    for(int i = 0; i < BN_LIMBS - 1; i++) k.val[i] = BN_LIMB_MASK;
    k.val[BN_LIMBS - 1] = (1u << BN_BITS_LAST_LIMB) - 1;
    check_mul(&k, &G);

    /* identity base */
    pallas_point inf;
    pallas_point_set_infinity(&inf);
    random_scalar(&k);
    pallas_point_mul(&r, &k, &inf);
    assert(r.infinity);

    /* random scalars on two bases, chaining the result as the next base */
    pallas_point base = H;
    for(int i = 0; i < 1500; i++) {
        random_scalar(&k);
        check_mul(&k, &G);
        check_mul(&k, &base);
        pallas_point next;
        pallas_point_mul(&next, &k, &base);
        if(!next.infinity) base = next;
    }

    /* mixed addition == projective addition, including P + P, P + (-P),
     * O + P and P + O */
    for(int i = 0; i < 300; i++) {
        pallas_point a, b, want, got;
        pallas_jac ja, jb, jw, jg;
        random_scalar(&k);
        pallas_point_mul(&a, &k, &G);
        random_scalar(&k);
        pallas_point_mul(&b, &k, &H);
        if(i == 0) b = a;                                   /* doubling */
        if(i == 1) { b = a; bn_subtract(pallas_p(), &a.y, &b.y); } /* inverse */
        if(i == 2) pallas_point_set_infinity(&a);           /* O + P */
        if(i == 3) pallas_point_set_infinity(&b);           /* P + O */

        /* randomize the projective representation of a: (X·z : Y·z : z) */
        pallas_to_jac(&ja, &a);
        if(!a.infinity) {
            bignum256 z;
            random_scalar(&z);
            z.val[BN_LIMBS - 1] &= (1u << 21) - 1; /* < p */
            z.val[0] |= 1;
            fp_mul(&ja.x, &ja.x, &z);
            fp_mul(&ja.y, &ja.y, &z);
            bn_copy(&z, &ja.z);
        }
        pallas_to_jac(&jb, &b);
        pallas_jac_add(&jw, &ja, &jb);
        pallas_jac_add_mixed(&jg, &ja, &b);
        pallas_from_jac(&want, &jw);
        pallas_from_jac(&got, &jg);
        assert(point_eq(&want, &got));

        /* aliasing r == j */
        pallas_jac_add_mixed(&ja, &ja, &b);
        pallas_from_jac(&got, &ja);
        assert(point_eq(&want, &got));
    }

    printf("test_curve: OK\n");
    return 0;
}
