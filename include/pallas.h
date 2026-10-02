#pragma once

#include <stdint.h>
#include <stddef.h>
#include "bignum.h"

// Pallas curve: y^2 = x^3 + 5
// Field modulus p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
// Group order  q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

typedef struct {
    /* Standard projective coordinates: affine = (X/Z, Y/Z). Z=0 represents
     * the point at infinity, encoded canonically as (0:1:0). The legacy
     * naming (`pallas_jac`, `pallas_to_jac`, `pallas_from_jac`) is kept for
     * source-compatibility — these used to be Jacobian (X/Z², Y/Z³), but
     * the implementation switched to projective in the security audit
     * follow-up so the Renes-Costello-Batina complete addition formulas
     * could be used (audit H-1). The struct layout is unchanged. */
    bignum256 x, y, z;
} pallas_jac;

typedef struct {
    bignum256 x, y;
    int infinity;
} pallas_point;

// Progress callback for long operations
typedef void (*pallas_progress_cb)(uint8_t percent, const char* label, void* ctx);
void pallas_set_progress_cb(pallas_progress_cb cb, void* ctx);

void pallas_report(uint8_t pct, const char* label);

// Yield callback — set this on constrained platforms to prevent watchdog reset.
// The callback is invoked periodically during long computations.
void pallas_set_yield_cb(void (*cb)(void* ctx), void* ctx);

// Sinsemilla S-table lookup callback (optional, for performance).
// If registered, called with index (0..1023). Must write 64 bytes
// (x_le[32] || y_le[32]) into buf_out. Return true on success.
// When not set (or returns false), points are computed on-the-fly.
typedef bool (*pallas_sinsemilla_lookup_fn)(uint32_t index, uint8_t buf_out[64], void* ctx);
void pallas_set_sinsemilla_lookup(pallas_sinsemilla_lookup_fn fn, void* ctx);

/**
 * Verify the integrity of the loaded Sinsemilla S-table against the
 * canonical BLAKE2b-256 fingerprint baked into the library.
 *
 * Walks the registered lookup callback for indices 0..1023, hashes the
 * 64 KB of returned point data, and compares constant-time against the
 * canonical digest. Returns true iff the loaded table matches the
 * canonical Zcash Orchard Sinsemilla S-table.
 *
 * If no lookup callback is registered, the device is using the on-the-
 * fly slow fallback (every S[i] is recomputed from a Pallas
 * group-hash); there is no flash blob whose integrity needs checking,
 * so the function returns true unconditionally.
 *
 * Every firmware (regardless of MCU or how the table is embedded —
 * objcopy on ESP-IDF, BOLOS resource on Ledger, raw flash region on
 * STM32) MUST call this function once at boot before invoking any
 * Sinsemilla operation. A false return means the on-flash table was
 * altered (supply-chain attack, fault injection during programming,
 * NVS corruption) and Sinsemilla outputs cannot be trusted: refuse
 * to operate. (audit M-5)
 *
 * Cost: 1024 callback invocations + ~64 KB of BLAKE2b. ~10 ms on a
 * 240 MHz Cortex-class core. One-time at boot.
 */
bool pallas_verify_sinsemilla_table(void);

/**
 * Verify the baked-in fixed hash-to-curve outputs (Sinsemilla Q, commitment
 * blinding bases R, spend-authorization base G — src/pallas_consts.h)
 * against a from-scratch recomputation. Returns true iff every entry
 * matches. Optional boot-time self-test, same role as
 * pallas_verify_sinsemilla_table(); costs one hash-to-curve per entry.
 */
bool pallas_verify_fixed_points(void);

// Must call before any Pallas operations
void pallas_init(void);

// Field arithmetic mod p (Pallas base field)
void fp_add(bignum256* r, const bignum256* a, const bignum256* b);
void fp_sub(bignum256* r, const bignum256* a, const bignum256* b);
void fp_mul(bignum256* r, const bignum256* a, const bignum256* b);
void fp_sqr(bignum256* r, const bignum256* a);
void fp_neg(bignum256* r, const bignum256* a);
void fp_inv(bignum256* r, const bignum256* a);
int fp_sqrt(bignum256* r, const bignum256* a);
int fp_is_square(const bignum256* a);

// Scalar field arithmetic (mod q)
void fq_reduce(bignum256* r, const bignum256* a);

// Point operations on Pallas
void pallas_point_set_infinity(pallas_point* p);
void pallas_to_jac(pallas_jac* j, const pallas_point* p);
void pallas_from_jac(pallas_point* p, const pallas_jac* j);
void pallas_jac_double(pallas_jac* r, const pallas_jac* p);
void pallas_jac_add(pallas_jac* r, const pallas_jac* a, const pallas_jac* b);
void pallas_jac_add_mixed(pallas_jac* r, const pallas_jac* p, const pallas_point* q);
void pallas_point_mul(pallas_point* r, const bignum256* k, const pallas_point* p);

// Hash to curve
void pallas_hash_to_curve(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len);
void pallas_group_hash(pallas_point* r, const char* domain, const uint8_t* msg, size_t msg_len);

// Sinsemilla
void sinsemilla_hash_to_point(
    pallas_point* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits);

void sinsemilla_short_commit(
    bignum256* r,
    const char* domain,
    const uint8_t* msg_bits,
    size_t num_bits,
    const bignum256* rcm);

// Access to the Pallas prime for external use
const bignum256* pallas_p(void);
const bignum256* pallas_q(void);

