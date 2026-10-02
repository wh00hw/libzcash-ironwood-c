# Security Properties

This document maps every secret-dependent operation to the constant-time technique used, for audit reviewers.

## Threat model

The library runs on single-core embedded MCUs (Cortex-M4, ESP32, Flipper Zero) with 4 KB stack budgets. The attacker model is:

- **Timing side-channels**: observable via USB/UART latency or EM emanation.
- **Stack overflow**: an oversized frame can corrupt control flow or leak secrets.
- **Compiler optimization**: dead-store elimination can skip secret cleanup.

The library does **not** defend against power analysis (DPA/SPA), fault injection, or cache-timing attacks. Those require hardware countermeasures beyond the scope of a pure-C library.

## Constant-time operation map

| Operation | Technique | File | Notes |
|-----------|-----------|------|-------|
| Scalar multiplication `[k]*P` | GLV split (`k = k1 + k2·λ`, constant-time Babai rounding) + interleaved fixed-window ladder; table entries selected by a masked scan of all `2^w` entries, signs by masked select | `src/pallas.c` pallas_point_mul() | Fixed iteration count; no branch or memory index depends on the scalar. The zero digit and the initial identity go through the same exception-free RCB addition (audit C-1) |
| Base-field multiplication / squaring `a * b mod p` | Schoolbook product + folding with `2^254 ≡ -c (mod p)`, masked final subtraction | `src/pallas.c` fp_mul(), fp_sqr(), fp_reduce_wide() | Straight-line limb arithmetic; replaces the data-dependent shift-compare-subtract loop (audit M-3) |
| Base-field add / sub / negate | Limb chain + masked conditional correction by `p` | `src/pallas.c` fp_add(), fp_sub(), fp_neg() | No branch on the operands |
| Base-field inversion | Constant-time safegcd: 20 batches of 30 masked divsteps (adapted from libsecp256k1 `modinv32`) | `src/pallas.c` fp_inv() | Fixed 600 divsteps regardless of the value; replaces Fermat exponentiation, which had replaced the variable-time Stein GCD (audit C-1) |
| Modular reduction `x mod q` | Fixed-iteration conditional subtraction via `bn_cmov()` | `src/redpallas.c` fq_full_reduce() | No variable-length while loops |
| Field multiplication `a * b mod p` | Shift-and-add with `bn_cmov()` conditional add | `src/redpallas.c` fq_mul() | No branching on secret bits |
| Nonce-is-zero check | `bn_cmov()` replaces zero with 1 | `src/redpallas.c` generate_nonce() | No `if` branch on nonce value |
| Wide-to-scalar reduction (64B -> 32B) | Horner's method with nibble processing | `src/redpallas.c` fq_from_wide() | Deterministic iteration count |
| Sighash / cmx / enc_ciphertext / epk comparison | `ct_memequal()` (volatile XOR accumulator) | `src/orchard_signer.c` | Sighash is public data, but ct-comparing also memo-bound ciphertexts on the same code path keeps the timing profile uniform across all on-device verification checks |
| ChaCha20 stream cipher | Pure 32-bit `+`, `^`, rotates; no table lookups | `src/chacha20poly1305.c` | RFC 7539 §2.3 — inherently constant-time |
| Poly1305 MAC | 26-bit-limb representation (poly1305-donna); branch-free field arithmetic | `src/chacha20poly1305.c` | RFC 7539 §2.5 |
| ChaCha20-Poly1305 tag check | `ct_memequal_local()` (volatile XOR accumulator, no early-out) | `src/chacha20poly1305.c::chacha20poly1305_decrypt` | Tag verified before any plaintext is written |
| AES-256 (FF1 diversifier + AEAD sealed storage) | Masked full-scan S-box: every S-box byte touched on every lookup | `src/aes/aes_ct.c` | Replaces the cache-timing-leaky T-table AES (audit H-3); optional constant-time HW-AES backend via `orchard_set_aes256_encrypt()` |
| Memory comparison | `ct_memequal()` | `src/memzero.c` | Volatile accumulator prevents short-circuit |
| Secret cleanup | `memzero()` via platform-specific secure zeroing | `src/memzero.c` | Resists dead-store elimination; covers the per-output K_enc / esk / np buffer in `orchard_compute_enc_ciphertext` |

## Non-constant-time operations (justified)

| Operation | Technique | File | Why it's safe |
|-----------|-----------|------|---------------|
| `fp_sqrt()` table square root | Early return on zero; result validity reported to the caller (the digit search itself is a full masked scan) | `src/pallas.c` | Input is a public curve coordinate or a hash-to-curve intermediate of public input, not a secret |
| `pallas_hash_to_curve()` fixed-point lookup | `strcmp`/`memcmp` scan of `PALLAS_FIXED_POINTS` | `src/pallas.c` | Domain strings and messages are public protocol constants |
| `g_d` cache | `memcmp` on the diversifier, cached point not wiped | `src/orchard.c` orchard_diversify_hash() | The diversifier and `g_d` are the recipient address — public |
| `pallas_jac_add_mixed()` identity fallback | Branch on the affine operand's `infinity` flag | `src/pallas.c` | The affine operand is a public table point, or `[rcm]·R`, where the flag reveals only `rcm == 0` |
| `fp_is_square()` Euler criterion | Variable-time exponentiation | `src/pallas.c` | Applied to public hash outputs during hash-to-curve |

## Stack budget

All cryptographic functions stay within a **512-byte per-function** stack limit, verified by GCC `-fstack-usage`. Large intermediates (BLAKE2b state, bignum temporaries, curve points, the 564 B note plaintext + 580 B AEAD ciphertext scratch used by `orchard_compute_enc_ciphertext`) use `static` storage in BSS and are explicitly zeroed after use.

The signer state machine is single-threaded per call on every supported MCU, so the `static` pattern does not introduce re-entrancy risks; cross-call leakage is prevented by per-function `memzero()` at every exit path.

Build and verify:
```bash
cmake .. -DSTACK_ANALYSIS=ON && make
../scripts/check_stack.sh .
```

## Secret material lifecycle

1. **Derivation**: spending key derived from BIP39 seed via ZIP-32 (BLAKE2b-512).
2. **Use**: signing via RedPallas (deterministic nonce from BLAKE2b-512).
3. **Cleanup**: all intermediate scalars, points, hash states, and key bytes are zeroed via `memzero()` before function return. Static storage is wiped after each operation to prevent cross-call leakage.

## Test vector corpus

Known-answer tests in `tests/test_vectors.c` cross-check the C implementation against the Rust reference (librustzcash; vectors generated by `tools/gen_test_vectors`, orchard 0.10). Coverage:

- **BLAKE2b** with 5 personalization tags (ZcashIP32Orchard, Zcash_ExpandSeed, Zcash_RedPallasN, Zcash_RedPallasH, ZTxIdOrchardHash)
- **Pallas hash-to-curve** (3 domain/message pairs including SinsemillaQ)
- **Sinsemilla S-table** (5 sample points: indices 0, 1, 2, 512, 1023)
- **ZIP-32** full derivation chain (master key, spending key, ak, nk, rivk, diversifier, pk_d)
- **ZIP-32 child key intermediates** (per-hop sk + chaincode for each of the 3 derivation steps)
- **FF1-AES-256** diversifier encryption (3 synthetic + 1 real dk from ZIP-32 derivation)
- **RedPallas signing** with deterministic nonce (4 test cases: standard, alpha=0, sighash=0, large scalars; compiled with `TEST_DETERMINISTIC_NONCE`)
- **Sinsemilla end-to-end** (HashToPoint with 1 and 2 chunks, ShortCommit with synthetic 510-bit message, ShortCommit with real ak||nk and rivk from ZIP-32)
- **F4Jumble** forward (3 test cases: 48, 83, and 128 bytes) + inverse round-trip
- **ChaCha20-Poly1305** RFC 7539 §A.5 reference vector + tamper-detection round-trip (`chacha20poly1305_self_test()`, invoked from `test_orchard`)
- **`orchard_compute_enc_ciphertext`** consistency (signer test fixture in `tests/test_signer.c`): per-action recomputed `enc_ciphertext` + `epk` vs. on-action bytes, with positive and tamper-rejection cases (memo / rseed / enc_ciphertext bit-flips → `SIGNER_ERR_MEMO_MISMATCH` or `_NOTE_COMMITMENT_MISMATCH`)
- **Miner-fee math** (`tests/test_signer.c`): Orchard-only fee == value_balance, caching, negative-fee rejection, fee-confirmation gate
- **NU6.3 / Ironwood cross-validation** (`tests/test_ironwood.c`, vectors from `tools/gen_ironwood_vectors` against `orchard 0.15.0-pre.2`, `zcash_note_encryption 0.4.1`, `zcash_primitives 0.29.0-pre.0`): ZIP-2005 V3 note-commitment cmx (and V3 ≠ V2 divergence), V3 + legacy-V2 note encryption (epk, ciphertext, Poly1305 tag — also pins the `Zcash_OrchardKDF` input order `sharedSecret ‖ ephemeralKey`), v6 empty-bundle effects digests for the Orchard and Ironwood pools (`ZTxIdOrchardH_v6` / `ZTxIdIronwd_H_v6`), v6 TxMeta wire round-trip, and the full five-leaf v6 sighash both at the zip244 layer and end-to-end through the signer state machine (per-action + fee confirmation gates, bit-flipped-sighash rejection)
- **v6-only wire tier enforcement** (post-NU6.3 branch; `tests/test_signer.c`, `tests/test_hwp_dispatcher.c`): the device accepts ONLY the v6 wire tier. Legacy 125/129-byte v5 `TxMeta` layouts → `SIGNER_ERR_BAD_META` (signer) / `Error(BAD_FRAME)` with no ACK (dispatcher); v6-sized metas with pre-v6 header constants or forbidden pool flag bits → `SIGNER_ERR_BAD_META`; untagged 903/1415-byte v4/v5 action payloads and invalid pool tags → `Error(BAD_FRAME)` + session reset. The v5 four-leaf sighash entry point (`zip244_shielded_sighash`) no longer exists in the code
- **PIN-sealed storage + lockout** (`tests/test_h5.c`): AEAD seal/unseal self-test, in-place round-trip, wrong-key rejection, deterministic PIN KDF, and the `wallet_lockout` fail-count/wipe-threshold state machine including serialization corruption detection
- **Transparent address rendering** (`tests/test_base58.c`): `script_to_taddr()` Base58Check KATs for P2PKH/P2SH on mainnet and testnet (`t1`/`t3`/`tm`/`t2`)
- **Protocol layer** (`tests/test_hwp.c`, `tests/test_hwp_dispatcher.c`): frame encode/decode + CRC-mismatch detection, and a virtual-device dispatcher session (drain/parse/dispatch, PING/PONG, FVK exchange)

The whole test suite must run with assertions enabled. Release-mode builds (`-DNDEBUG`) silently turn `assert()` into a no-op; the test executables therefore force `-UNDEBUG` (see `tests/CMakeLists.txt`) so a broken invariant fails loudly rather than passing on a stripped binary.

Regenerate vectors:
- Orchard KAT corpus: `cd tools/gen_test_vectors && cargo run 2>/dev/null > ../../tests/test_vectors.h`
- Ironwood/NU6.3 vectors: `cd tools/gen_ironwood_vectors && cargo run --release` (hex output pasted into `tests/test_ironwood.c`)
