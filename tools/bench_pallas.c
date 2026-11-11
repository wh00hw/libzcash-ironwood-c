/* bench_pallas — host micro-benchmark for the Pallas hot path.
 *
 * Times the primitives that dominate per-action verification on the device
 * (field mul/inv/sqrt, hash-to-curve, scalar multiplication, Sinsemilla,
 * cmx and enc_ciphertext recomputation) and the signing side (RedPallas
 * spend authorization, ak and address derivation). Host numbers are only meaningful
 * as ratios between two builds of the library; absolute device timings
 * need the same loop driven from the target's tick source.
 *
 * Usage: bench_pallas [path/to/sinsemilla_s.bin]
 */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "orchard.h"
#include "pallas.h"
#include "redpallas.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

static uint8_t s_table[65536];

static bool table_lookup(uint32_t index, uint8_t buf_out[64], void* ctx) {
    (void)ctx;
    if(index >= 1024) return false;
    memcpy(buf_out, s_table + (size_t)index * 64, 64);
    return true;
}

#define BENCH(label, iters, stmt)                                  \
    do {                                                           \
        double t0 = now_ms();                                      \
        for(int it_ = 0; it_ < (iters); it_++) { stmt; }           \
        double dt = now_ms() - t0;                                 \
        printf("%-34s %12.2f us/op  (%d iters)\n", (label),        \
               dt * 1e3 / (iters), (iters));                             \
    } while(0)

int main(int argc, char** argv) {
    pallas_init();

    bignum256 a, b, r;
    static const uint8_t a_le[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,
        0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x9a,0xab,0xbc,0xcd,0xde,0xef,0xf0,0x1f};
    static const uint8_t b_le[32] = {
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,
        0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0x2f};
    bn_read_le(a_le, &a);
    bn_read_le(b_le, &b);

    BENCH("fp_mul", 2000000, (fp_mul(&r, &a, &b), bn_copy(&r, &a)));
    BENCH("fp_sqr", 2000000, (fp_sqr(&r, &a), bn_copy(&r, &a)));
    BENCH("fp_add", 5000000, (fp_add(&r, &a, &b), bn_copy(&r, &a)));
    BENCH("fp_inv", 20000, (fp_inv(&r, &a), bn_copy(&r, &a)));
    BENCH("fp_sqrt (of a square)", 5000, (fp_sqr(&r, &a), fp_sqrt(&a, &r)));

    pallas_point P, Q;
    uint8_t d[11] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    BENCH("pallas_hash_to_curve", 2000,
          (d[0]++, pallas_hash_to_curve(&P, "z.cash:Orchard-gd", d, 11)));
    BENCH("pallas_point_mul", 2000, (pallas_point_mul(&Q, &b, &P), P = Q));

    /* Note fields: pk_d must be a valid point encoding, so derive one. */
    uint8_t pk_d[32], rho[32], rseed[32], cmx[32], epk[32];
    static uint8_t memo[512], enc[580];
    bn_write_le(&P.x, pk_d);
    if(P.y.val[0] & 1) pk_d[31] |= 0x80;
    memset(rho, 0x5a, 32);
    rho[31] = 0x1a;
    memset(rseed, 0xc3, 32);
    memset(memo, 0xf6, 1);

    BENCH("sinsemilla 1086 bit (no table)", 20, {
        static uint8_t msg[136];
        msg[0]++;
        sinsemilla_hash_to_point(&Q, "z.cash:Orchard-NoteCommit-M", msg, 1086);
    });
    BENCH("orchard_compute_cmx (no table)", 20,
          (rseed[0]++, orchard_compute_cmx(d, pk_d, 12345, rho, rseed, ORCHARD_NOTE_V3, cmx)));

    const char* path = argc > 1 ? argv[1] : "src/sinsemilla_s.bin";
    FILE* f = fopen(path, "rb");
    if(f && fread(s_table, 1, sizeof(s_table), f) == sizeof(s_table)) {
        pallas_set_sinsemilla_lookup(table_lookup, NULL);
        if(!pallas_verify_sinsemilla_table()) {
            printf("S-table digest mismatch\n");
            return 1;
        }
        BENCH("sinsemilla 1086 bit (S table)", 2000, {
            static uint8_t msg[136];
            msg[0]++;
            sinsemilla_hash_to_point(&Q, "z.cash:Orchard-NoteCommit-M", msg, 1086);
        });
        BENCH("orchard_compute_cmx (S table)", 2000,
              (rseed[0]++, orchard_compute_cmx(d, pk_d, 12345, rho, rseed, ORCHARD_NOTE_V3, cmx)));
    } else {
        printf("(S table not found at %s — skipping table-backed cases)\n", path);
    }
    if(f) fclose(f);

    BENCH("orchard_compute_enc_ciphertext", 2000,
          (rseed[0]++, orchard_compute_enc_ciphertext_from_rseed(
                           d, pk_d, 12345, rseed, rho, memo, ORCHARD_NOTE_V3, enc, epk)));
    BENCH("per-action verify (cmx + enc)", 2000, {
        rseed[0]++;
        orchard_compute_cmx(d, pk_d, 12345, rho, rseed, ORCHARD_NOTE_V3, cmx);
        orchard_compute_enc_ciphertext_from_rseed(
            d, pk_d, 12345, rseed, rho, memo, ORCHARD_NOTE_V3, enc, epk);
    });

    /* Signing side. ask/alpha are arbitrary scalars below q. */
    uint8_t ask[32], alpha[32], sighash[32], sig[64], rk[32], ak[32];
    memcpy(ask, a_le, 32);
    memcpy(alpha, b_le, 32);
    memset(sighash, 0x77, 32);
    BENCH("redpallas_sign", 2000,
          (sighash[0]++, alpha[0]++, redpallas_sign(ask, alpha, sighash, sig, rk)));
    BENCH("redpallas_derive_ak", 2000, (ask[0]++, redpallas_derive_ak(ask, ak)));
    {
        static uint8_t seed[64];
        static char ua[256];
        uint8_t d_out[11], pk_d_out[32];
        memset(seed, 0x31, sizeof(seed));
        BENCH("orchard_derive_unified_address", 500,
              (seed[0]++, orchard_derive_unified_address(
                              seed, 133, 0, "u", ua, sizeof(ua), d_out, pk_d_out)));
        cmx[0] ^= pk_d_out[0];
    }

    printf("checksum %02x%02x%02x%02x %02x%02x\n", cmx[0], enc[0], epk[0],
           (unsigned)(r.val[0] & 0xff), sig[0] ^ sig[63], rk[0] ^ ak[0]);
    return 0;
}
