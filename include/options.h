/**
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __OPTIONS_H__
#define __OPTIONS_H__

// use precomputed Curve Points (some scalar multiples of curve base point G)
#ifndef USE_PRECOMPUTED_CP
#define USE_PRECOMPUTED_CP 0
#endif

// use fast inverse method
#ifndef USE_INVERSE_FAST
#define USE_INVERSE_FAST 1
#endif

// support for printing bignum256 structures via printf
#ifndef USE_BN_PRINT
#define USE_BN_PRINT 0
#endif

// use deterministic signatures
#ifndef USE_RFC6979
#define USE_RFC6979 1
#endif

// implement BIP32 caching
#ifndef USE_BIP32_CACHE
#define USE_BIP32_CACHE 0
#define BIP32_CACHE_SIZE 10
#define BIP32_CACHE_MAXDEPTH 8
#endif

// support constructing BIP32 nodes from ed25519 and curve25519 curves.
#ifndef USE_BIP32_25519_CURVES
#define USE_BIP32_25519_CURVES 0
#endif

// implement BIP39 caching
#ifndef USE_BIP39_CACHE
#define USE_BIP39_CACHE 0
#define BIP39_CACHE_SIZE 4
#endif

// support Ethereum operations
#ifndef USE_ETHEREUM
#define USE_ETHEREUM 0
#endif

// support NEM operations
#ifndef USE_NEM
#define USE_NEM 0
#endif

// support MONERO operations
#ifndef USE_MONERO
#define USE_MONERO 0
#endif

// support CARDANO operations
#ifndef USE_CARDANO
#define USE_CARDANO 0
#endif

// support Keccak hashing
#ifndef USE_KECCAK
#define USE_KECCAK 1
#endif

// add a way to mark confidential data
#ifndef CONFIDENTIAL
#define CONFIDENTIAL
#endif

// Platform-specific hardware RNG. Default ON for safety: every integration
// MUST provide random32()/random_buffer() backed by a CSPRNG (audit C-2).
//
// If you really want the unseeded LCG fallback (e.g. for deterministic
// unit tests), set ZORCHARD_INSECURE_LCG=1 explicitly. The library refuses
// to compile silently against the LCG so a careless integrator can't ship
// a build whose RedPallas nonces and BIP-39 entropy come from a
// predictable PRNG.
#ifndef USE_PLATFORM_RNG
#define USE_PLATFORM_RNG 1
#endif

#if !USE_PLATFORM_RNG
#  ifndef ZORCHARD_INSECURE_LCG
#    error "USE_PLATFORM_RNG=0 requires ZORCHARD_INSECURE_LCG=1 (DO NOT use in production)."
#  endif
#endif

// Transparent (secp256k1 ECDSA) SIGNING. OFF by default, and nothing in
// this library calls it: transparent inputs are not supported (README,
// "Transparent inputs are not supported"). The code is kept behind this
// switch — rather than deleted — only as the starting point for a future
// implementation, because it is NOT fit for a device key as it stands:
//   - secp256k1_point_mul() is variable-time in the ECDSA nonce (and in the
//     secret key); a host that can request signatures and time the replies
//     can recover the key with a lattice attack;
//   - there is no correct ZIP 244 transparent signature hash to sign.
// Defining this to 1 compiles secp256k1_ecdsa_sign_digest() and
// secp256k1_sig_to_der() for experiments and known-answer tests. Do not
// ship a firmware that signs with a wallet key through it.
#ifndef ZCASH_ENABLE_TRANSPARENT_SIGNING
#define ZCASH_ENABLE_TRANSPARENT_SIGNING 0
#endif

// backward compat: old Flipper flag maps to the generic one
#ifdef USE_FLIPPER_HAL_RANDOM
#  if USE_FLIPPER_HAL_RANDOM && !USE_PLATFORM_RNG
#    undef  USE_PLATFORM_RNG
#    define USE_PLATFORM_RNG 1
#  endif
#endif

#endif
