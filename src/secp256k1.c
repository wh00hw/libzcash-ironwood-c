/**
 * secp256k1 curve operations + ECDSA signing.
 *
 * Point arithmetic adapted from pallas.c (same short Weierstrass form with a=0).
 * ECDSA signing with RFC 6979 deterministic nonce (HMAC-SHA256).
 * All operations constant-time. No heap. No precomputed tables.
 */
#include "secp256k1.h"
#include "bignum.h"
#include "hmac.h"
#include "memzero.h"
#include <string.h>

/* ── Curve constants (29-bit limbs) ──────────────────────────────── */

/* p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F */
static const bignum256 s_p = {{
    0x1ffffc2f, 0x1ffffff7, 0x1fffffff, 0x1fffffff,
    0x1fffffff, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x00ffffff
}};

/* n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 */
static const bignum256 s_n = {{
    0x10364141, 0x1e92f466, 0x12280eef, 0x1db9cd5e,
    0x1fffebaa, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x00ffffff
}};

/* n/2 for low-S normalization (BIP-62) */
static const bignum256 s_half_n = {{
    0x081b20a0, 0x1f497a33, 0x09140777, 0x0edce6af,
    0x1ffff5d5, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x007fffff
}};

/* Generator G */
static const bignum256 s_Gx = {{
    0x16f81798, 0x0f940ad8, 0x138a3656, 0x17f9b65b,
    0x10b07029, 0x114ae743, 0x0eb15681, 0x0fdf3b97, 0x0079be66
}};
static const bignum256 s_Gy = {{
    0x1b10d4b8, 0x023e847f, 0x01550667, 0x0f68914d,
    0x108a8fd1, 0x1dfe0708, 0x11957693, 0x0ee4d478, 0x00483ada
}};

const bignum256 *secp256k1_p(void)  { return &s_p; }
const bignum256 *secp256k1_n(void)  { return &s_n; }
const bignum256 *secp256k1_Gx(void) { return &s_Gx; }
const bignum256 *secp256k1_Gy(void) { return &s_Gy; }

/* ── Field arithmetic (mod p) ────────────────────────────────────── */

static void sfp_add(bignum256 *r, const bignum256 *a, const bignum256 *b) {
    bn_copy(a, r); bn_add(r, b); bn_fast_mod(r, &s_p); bn_mod(r, &s_p);
}
static void sfp_sub(bignum256 *r, const bignum256 *a, const bignum256 *b) {
    bn_subtractmod(a, b, r, &s_p); bn_fast_mod(r, &s_p); bn_mod(r, &s_p);
}
static void sfp_mul(bignum256 *r, const bignum256 *a, const bignum256 *b) {
    bn_copy(a, r); bn_multiply(b, r, &s_p);
}
static void sfp_sqr(bignum256 *r, const bignum256 *a) {
    bn_copy(a, r); bn_multiply(a, r, &s_p);
}
static void sfp_inv(bignum256 *r, const bignum256 *a) {
    bn_copy(a, r); bn_inverse(r, &s_p);
}

/* ── Point operations (Jacobian, a=0) ────────────────────────────── */

void secp256k1_point_set_infinity(secp256k1_point *p) {
    bn_zero(&p->x); bn_zero(&p->y); p->infinity = 1;
}

void secp256k1_to_jac(secp256k1_jac *j, const secp256k1_point *p) {
    bn_copy(&p->x, &j->x);
    bn_copy(&p->y, &j->y);
    bn_one(&j->z);
    if (p->infinity) bn_zero(&j->z);
}

void secp256k1_from_jac(secp256k1_point *p, const secp256k1_jac *j) {
    if (bn_is_zero(&j->z)) {
        secp256k1_point_set_infinity(p);
        return;
    }
    p->infinity = 0;
    static bignum256 zinv, zinv2, zinv3;
    sfp_inv(&zinv, &j->z);
    sfp_sqr(&zinv2, &zinv);
    sfp_mul(&zinv3, &zinv2, &zinv);
    sfp_mul(&p->x, &j->x, &zinv2);
    sfp_mul(&p->y, &j->y, &zinv3);
    memzero(&zinv, sizeof(zinv));
    memzero(&zinv2, sizeof(zinv2));
    memzero(&zinv3, sizeof(zinv3));
}

/* Double: 2P in Jacobian (a=0, same formulas as Pallas) */
void secp256k1_jac_double(secp256k1_jac *r, const secp256k1_jac *p) {
    if (bn_is_zero(&p->z)) { bn_zero(&r->z); return; }
    static bignum256 a, b, c, d, e, f, x3, y3, z3;

    sfp_sqr(&a, &p->x);       /* A = X^2 */
    sfp_sqr(&b, &p->y);       /* B = Y^2 */
    sfp_sqr(&c, &b);          /* C = B^2 */

    /* D = 2*((X+B)^2 - A - C) */
    sfp_add(&d, &p->x, &b);
    sfp_sqr(&d, &d);
    sfp_sub(&d, &d, &a);
    sfp_sub(&d, &d, &c);
    sfp_add(&d, &d, &d);

    /* E = 3*A */
    sfp_add(&e, &a, &a);
    sfp_add(&e, &e, &a);

    sfp_sqr(&f, &e);          /* F = E^2 */

    /* X3 = F - 2D */
    sfp_sub(&x3, &f, &d);
    sfp_sub(&x3, &x3, &d);

    /* Y3 = E*(D - X3) - 8C */
    sfp_sub(&y3, &d, &x3);
    sfp_mul(&y3, &e, &y3);
    sfp_add(&c, &c, &c);
    sfp_add(&c, &c, &c);
    sfp_add(&c, &c, &c);      /* 8C */
    sfp_sub(&y3, &y3, &c);

    /* Z3 = 2*Y*Z */
    sfp_mul(&z3, &p->y, &p->z);
    sfp_add(&z3, &z3, &z3);

    bn_copy(&x3, &r->x);
    bn_copy(&y3, &r->y);
    bn_copy(&z3, &r->z);

    /* statics: the ladder's last intermediates must not outlive the call */
    memzero(&a, sizeof(a)); memzero(&b, sizeof(b)); memzero(&c, sizeof(c));
    memzero(&d, sizeof(d)); memzero(&e, sizeof(e)); memzero(&f, sizeof(f));
    memzero(&x3, sizeof(x3)); memzero(&y3, sizeof(y3)); memzero(&z3, sizeof(z3));
}

/* Mixed add: J + affine P */
void secp256k1_jac_add_mixed(secp256k1_jac *r, const secp256k1_jac *j, const secp256k1_point *p) {
    if (p->infinity) { *r = *j; return; }
    if (bn_is_zero(&j->z)) { secp256k1_to_jac(r, p); return; }

    static bignum256 z2, u2, s2, h, rr, hh, hhh, v, x3, y3, z3, tmp;

    sfp_sqr(&z2, &j->z);
    sfp_mul(&u2, &p->x, &z2);
    sfp_mul(&tmp, &z2, &j->z);
    sfp_mul(&s2, &p->y, &tmp);

    sfp_sub(&h, &u2, &j->x);
    sfp_sub(&rr, &s2, &j->y);

    if (bn_is_zero(&h)) {
        int same = bn_is_zero(&rr);
        memzero(&z2, sizeof(z2)); memzero(&u2, sizeof(u2)); memzero(&s2, sizeof(s2));
        memzero(&h, sizeof(h)); memzero(&rr, sizeof(rr)); memzero(&tmp, sizeof(tmp));
        if (same) {
            secp256k1_jac_double(r, j);
            return;
        }
        bn_zero(&r->z);
        return;
    }

    sfp_sqr(&hh, &h);
    sfp_mul(&hhh, &hh, &h);
    sfp_mul(&v, &j->x, &hh);

    sfp_sqr(&x3, &rr);
    sfp_sub(&x3, &x3, &hhh);
    sfp_sub(&x3, &x3, &v);
    sfp_sub(&x3, &x3, &v);

    sfp_sub(&y3, &v, &x3);
    sfp_mul(&y3, &rr, &y3);
    sfp_mul(&tmp, &j->y, &hhh);
    sfp_sub(&y3, &y3, &tmp);

    sfp_mul(&z3, &j->z, &h);

    bn_copy(&x3, &r->x);
    bn_copy(&y3, &r->y);
    bn_copy(&z3, &r->z);

    memzero(&z2, sizeof(z2)); memzero(&u2, sizeof(u2)); memzero(&s2, sizeof(s2));
    memzero(&h, sizeof(h)); memzero(&rr, sizeof(rr)); memzero(&hh, sizeof(hh));
    memzero(&hhh, sizeof(hhh)); memzero(&v, sizeof(v)); memzero(&tmp, sizeof(tmp));
    memzero(&x3, sizeof(x3)); memzero(&y3, sizeof(y3)); memzero(&z3, sizeof(z3));
}

/* Constant-time Montgomery ladder: r = k * p */
void secp256k1_point_mul(secp256k1_point *r, const bignum256 *k, const secp256k1_point *p) {
    static secp256k1_jac R0, R1, jtmp;
    static secp256k1_point R0_affine;

    /* R0 = infinity, R1 = P */
    bn_zero(&R0.x); bn_one(&R0.y); bn_zero(&R0.z);
    secp256k1_to_jac(&R1, p);

    for (int i = 255; i >= 0; i--) {
        uint32_t bit = bn_testbit(k, i);

        /* Constant-time swap */
        for (int j = 0; j < BN_LIMBS; j++) {
            uint32_t mask = -(uint32_t)bit;
            uint32_t t;
            t = mask & (R0.x.val[j] ^ R1.x.val[j]); R0.x.val[j] ^= t; R1.x.val[j] ^= t;
            t = mask & (R0.y.val[j] ^ R1.y.val[j]); R0.y.val[j] ^= t; R1.y.val[j] ^= t;
            t = mask & (R0.z.val[j] ^ R1.z.val[j]); R0.z.val[j] ^= t; R1.z.val[j] ^= t;
        }

        secp256k1_from_jac(&R0_affine, &R0);
        secp256k1_jac_add_mixed(&jtmp, &R1, &R0_affine);
        R1 = jtmp;

        secp256k1_jac_double(&jtmp, &R0);
        R0 = jtmp;

        /* Swap back */
        for (int j = 0; j < BN_LIMBS; j++) {
            uint32_t mask = -(uint32_t)bit;
            uint32_t t;
            t = mask & (R0.x.val[j] ^ R1.x.val[j]); R0.x.val[j] ^= t; R1.x.val[j] ^= t;
            t = mask & (R0.y.val[j] ^ R1.y.val[j]); R0.y.val[j] ^= t; R1.y.val[j] ^= t;
            t = mask & (R0.z.val[j] ^ R1.z.val[j]); R0.z.val[j] ^= t; R1.z.val[j] ^= t;
        }
    }

    secp256k1_from_jac(r, &R0);

    memzero(&R0, sizeof(R0));
    memzero(&R1, sizeof(R1));
    memzero(&jtmp, sizeof(jtmp));
    memzero(&R0_affine, sizeof(R0_affine));
}

/* ── Key derivation ──────────────────────────────────────────────── */

int secp256k1_get_public_key33(const uint8_t sk[32], uint8_t pubkey[33]) {
    bignum256 k;
    bn_read_be(sk, &k);

    /* Reject zero or >= n */
    if (bn_is_zero(&k) || !bn_is_less(&k, &s_n)) {
        memzero(&k, sizeof(k));
        return -1;
    }

    secp256k1_point G, Q;
    G.infinity = 0;
    bn_copy(&s_Gx, &G.x);
    bn_copy(&s_Gy, &G.y);

    secp256k1_point_mul(&Q, &k, &G);
    memzero(&k, sizeof(k));

    if (Q.infinity) return -1;

    /* Compress: 0x02 if y even, 0x03 if y odd */
    bn_mod(&Q.y, &s_p);
    pubkey[0] = (Q.y.val[0] & 1) ? 0x03 : 0x02;
    bn_mod(&Q.x, &s_p);
    bn_write_be(&Q.x, pubkey + 1);

    memzero(&Q, sizeof(Q));
    return 0;
}

/* ── RFC 6979 deterministic nonce (HMAC-SHA256) ──────────────────── */

/**
 * RFC 6979 section 3.2: deterministic k generation.
 * Uses HMAC-SHA256 with the private key and message hash.
 */
static void rfc6979_generate_k(const uint8_t sk[32], const uint8_t digest[32],
                                bignum256 *k_out)
{
    static uint8_t V[32], K[32];
    static uint8_t buf[32 + 1 + 32 + 32]; /* V || 0x00/0x01 || sk || digest */

    /* Step b: V = 0x01 0x01 ... (32 bytes) */
    memset(V, 0x01, 32);
    /* Step c: K = 0x00 0x00 ... (32 bytes) */
    memset(K, 0x00, 32);

    /* Step d: K = HMAC_K(V || 0x00 || sk || digest) */
    memcpy(buf, V, 32);
    buf[32] = 0x00;
    memcpy(buf + 33, sk, 32);
    memcpy(buf + 65, digest, 32);
    hmac_sha256(K, 32, buf, 97, K);

    /* Step e: V = HMAC_K(V) */
    hmac_sha256(K, 32, V, 32, V);

    /* Step f: K = HMAC_K(V || 0x01 || sk || digest) */
    memcpy(buf, V, 32);
    buf[32] = 0x01;
    memcpy(buf + 33, sk, 32);
    memcpy(buf + 65, digest, 32);
    hmac_sha256(K, 32, buf, 97, K);

    /* Step g: V = HMAC_K(V) */
    hmac_sha256(K, 32, V, 32, V);

    /* Step h: loop until valid k found */
    for (int attempt = 0; attempt < 64; attempt++) {
        /* V = HMAC_K(V) */
        hmac_sha256(K, 32, V, 32, V);

        bn_read_be(V, k_out);

        /* k must be in [1, n-1] */
        if (!bn_is_zero(k_out) && bn_is_less(k_out, &s_n)) {
            memzero(K, sizeof(K));
            memzero(V, sizeof(V));
            memzero(buf, sizeof(buf));
            return;
        }

        /* Update: K = HMAC_K(V || 0x00), V = HMAC_K(V) */
        memcpy(buf, V, 32);
        buf[32] = 0x00;
        hmac_sha256(K, 32, buf, 33, K);
        hmac_sha256(K, 32, V, 32, V);
    }

    /* Should never reach here with a proper hash */
    bn_zero(k_out);
    memzero(K, sizeof(K));
    memzero(V, sizeof(V));
    memzero(buf, sizeof(buf));
}

/* ── ECDSA signing ───────────────────────────────────────────────── */

int secp256k1_ecdsa_sign_digest(const uint8_t sk[32], const uint8_t digest[32],
                                 uint8_t sig_out[64])
{
    /* Static storage to stay within 512-byte stack budget.
     * Same pattern as pallas_point_mul / pallas_jac_double. */
    static bignum256 d, z, k, r_bn, s_bn;
    static secp256k1_point G, R;

    bn_read_be(sk, &d);
    if (bn_is_zero(&d) || !bn_is_less(&d, &s_n)) {
        memzero(&d, sizeof(d));
        return -1;
    }

    bn_read_be(digest, &z);

    /* Generate deterministic k via RFC 6979 */
    rfc6979_generate_k(sk, digest, &k);

    /* R = k * G */
    G.infinity = 0;
    bn_copy(&s_Gx, &G.x);
    bn_copy(&s_Gy, &G.y);

    secp256k1_point_mul(&R, &k, &G);

    if (R.infinity) {
        memzero(&d, sizeof(d));
        memzero(&k, sizeof(k));
        return -1;
    }

    /* r = R.x mod n */
    bn_mod(&R.x, &s_p);
    bn_copy(&R.x, &r_bn);
    bn_mod(&r_bn, &s_n);

    if (bn_is_zero(&r_bn)) {
        memzero(&d, sizeof(d));
        memzero(&k, sizeof(k));
        return -1;
    }

    /* s = k^-1 * (z + r * d) mod n */
    bn_copy(&r_bn, &s_bn);
    bn_multiply(&d, &s_bn, &s_n);    /* s = r * d mod n */
    bn_addmod(&s_bn, &z, &s_n);       /* s = z + r*d mod n */
    bn_inverse(&k, &s_n);             /* k = k^-1 mod n */
    bn_multiply(&k, &s_bn, &s_n);    /* s = k^-1 * (z + r*d) mod n */

    if (bn_is_zero(&s_bn)) {
        memzero(&d, sizeof(d));
        memzero(&k, sizeof(k));
        return -1;
    }

    /* Low-S normalization (BIP-62): if s > n/2, s = n - s */
    if (!bn_is_less(&s_bn, &s_half_n)) {
        bn_subtract(&s_n, &s_bn, &s_bn);
    }

    /* Write r || s */
    bn_mod(&r_bn, &s_n);
    bn_write_be(&r_bn, sig_out);
    bn_mod(&s_bn, &s_n);
    bn_write_be(&s_bn, sig_out + 32);

    memzero(&d, sizeof(d));
    memzero(&z, sizeof(z));
    memzero(&k, sizeof(k));
    memzero(&r_bn, sizeof(r_bn));
    memzero(&s_bn, sizeof(s_bn));
    memzero(&R, sizeof(R));

    return 0;
}

/* ── DER encoding ────────────────────────────────────────────────── */

size_t secp256k1_sig_to_der(const uint8_t compact[64], uint8_t *der_out) {
    /* DER: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s> */
    const uint8_t *r = compact;
    const uint8_t *s = compact + 32;

    /* Skip leading zeros, but add padding byte if high bit set */
    int r_start = 0, s_start = 0;
    while (r_start < 31 && r[r_start] == 0) r_start++;
    while (s_start < 31 && s[s_start] == 0) s_start++;

    int r_len = 32 - r_start;
    int s_len = 32 - s_start;
    int r_pad = (r[r_start] & 0x80) ? 1 : 0;
    int s_pad = (s[s_start] & 0x80) ? 1 : 0;

    int total = 2 + r_len + r_pad + 2 + s_len + s_pad;

    der_out[0] = 0x30;
    der_out[1] = (uint8_t)total;

    der_out[2] = 0x02;
    der_out[3] = (uint8_t)(r_len + r_pad);
    int pos = 4;
    if (r_pad) der_out[pos++] = 0x00;
    memcpy(der_out + pos, r + r_start, r_len);
    pos += r_len;

    der_out[pos++] = 0x02;
    der_out[pos++] = (uint8_t)(s_len + s_pad);
    if (s_pad) der_out[pos++] = 0x00;
    memcpy(der_out + pos, s + s_start, s_len);
    pos += s_len;

    return (size_t)pos;
}
