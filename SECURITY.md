# Security Properties

This document states, for audit reviewers: which host-supplied data the signature binds and which it does not; which secret-dependent operations are constant-time, by what technique and how that was checked; and what is and is not wiped. It describes the Orchard/Ironwood signing path. Transparent inputs are not supported (README, "Transparent inputs are not supported").

## Threat model

The library runs on single-core embedded MCUs (Cortex-M4, ESP32, Flipper Zero) with 4 KB stack budgets. The attacker model is:

- **Timing side-channels**: observable via USB/UART latency or EM emanation.
- **Stack overflow**: an oversized frame can corrupt control flow or leak secrets.
- **Compiler optimization**: dead-store elimination can skip secret cleanup.

The library does **not** defend against power analysis (DPA/SPA), fault injection, or cache-timing attacks. Those require hardware countermeasures beyond the scope of a pure-C library.

## What binds each host-supplied field

The host is assumed fully malicious. For every field it sends, this table says what the device does with it:

- **H** — hashed into the sighash the device signs (so the signature is valid only for a transaction with that value);
- **R** — recomputed on the device from other data and compared;
- **S** — shown to the user (by the firmware callbacks; the library hands it over, see the note on the review guard below);
- **F** — forced to a fixed value, or validated against a device-side rule, otherwise the session ends;
- **U** — unbound: not covered by anything the device checks. Each U is listed with why it is tolerated.

**TxMeta** (`TX_OUTPUT`, index `0xFFFF`)

| Field | H | R | S | F | U | Notes |
|---|---|---|---|---|---|---|
| `version`, `version_group_id` | ✓ | | | ✓ | | header digest; must be the v6 constants |
| `consensus_branch_id` | ✓ | | | ✓ | | header digest and sighash personalization; must be in `ORCHARD_SIGNER_ALLOWED_BRANCH_IDS`. The same on mainnet and testnet |
| `lock_time` | ✓ | | ✗ | | | header digest. **Not shown.** The host decides from when the transaction can be mined |
| `expiry_height` | ✓ | | ✗ | | | header digest. **Not shown.** The host decides how long the signed transaction stays valid (0 = forever) |
| `orchard_flags` / `ironwood_flags`, pool has ≥ 1 action | ✓ | | | ✓ | | bundle digest; flag policy (no reserved bits; sealed Orchard: cross-address bit clear) |
| `orchard_flags` / `ironwood_flags`, pool has no action | | | | (✓) | ✓ | not hashed (empty-bundle constant). Only the flag-policy check reads them; nothing is displayed or decided from them. Tolerated: there is no such field in the transaction |
| `value_balance` / `ironwood_value_balance`, pool has ≥ 1 action | ✓ | | ✓ | | | bundle digest; enters the fee and `total_leaving`, which are shown. On chain also bound by the binding signature |
| `value_balance` / `ironwood_value_balance`, pool has no action | | | | ✓ | | **must be 0** (`SIGNER_ERR_EMPTY_POOL_BALANCE`): not hashed, so it may not enter the fee. This was finding F1 |
| `anchor`, `ironwood_anchor` | | | | | ✓ | not in the v6 effects digest (they are in the authorizing-data commitment, which the device does not compute). Discarded on receipt. Tolerated: the signature is valid for any anchor, and the anchor is tied to the spends by the proof, which the host produces in any case |
| `transparent_sig_digest` | ✓ | ✓ | | ✓ | | recomputed from the streamed transparent outputs; without a stream it must be the empty-bundle constant |
| `sapling_digest` | ✓ | | | ✓ | | must be the empty-bundle constant |
| `coin_type` (extension) | | | | ✓ | (✓) | must equal the device's network, in every session. Not part of the transaction: a consistency check, not a binding — see "Network" in the README |
| `total_outputs` (action count, frame header) | (✓) | | | ✓ | | 1 … `ORCHARD_SIGNER_MAX_ACTIONS`; exactly that many actions must follow. The actions themselves are hashed, so a transaction with more or fewer has a different sighash |

**Action** (`TX_OUTPUT`, index 0 … N−1, 1416 bytes)

| Field | H | R | S | F | U | Notes |
|---|---|---|---|---|---|---|
| pool tag | ✓ | | | ✓ | | selects the pool digest the action is hashed into and the note version used for the recomputations; 0 or 1 |
| `cv_net` | ✓ | | | | | not interpreted |
| `nullifier` | ✓ | | | | | used as ρ of the output note in the recomputations; which note it spends is not known to the device |
| `rk` | ✓ | | | | | not compared with `ak` + `alpha` (see below) |
| `cmx` | ✓ | ✓ | | | | recomputed from recipient, value, rseed, ρ |
| `ephemeral_key`, `enc_ciphertext` | ✓ | ✓ | | | | recomputed from the note, the memo and the on-chip `esk`. One exception: for the sealed-Orchard spend dummy (value 0, own external address, expected `epk`, no declared memo) `enc_ciphertext` is hashed but not matched, and is checked not to be an encryption of that note |
| `out_ciphertext` | ✓ | | | | | not interpreted; a wrong one only affects recovery with the outgoing viewing key |
| recipient (`d`, `pk_d`), value | via `cmx` | | ✓ | | | shown for every output with a value or a memo, with the device's own ownership classification. For a zero-value output with an empty memo: **not shown**, counted |
| `rseed` | via `cmx`, `enc` | | | | | |
| memo | via `enc` | | ✓ | | | shown when not empty; "no memo" is reported explicitly. For the spend dummy the memo field is not established (nothing decrypts it) and the output is not shown |
| index / total (frame header) | | | | ✓ | | consecutive, total constant |

**Transparent output** (`TX_TRANSPARENT_OUTPUT`)

| Field | H | R | S | F | U | Notes |
|---|---|---|---|---|---|---|
| value | ✓ | | ✓ | | | outputs digest → transparent leaf; enters the fee and `total_leaving` |
| `script_pubkey` | ✓ | | ✓ | ✓ | | standard P2PKH / P2SH only; shown as a t-address |
| index / total (frame header) | | | | ✓ | | consecutive, total constant, at most `ORCHARD_SIGNER_MAX_T_OUTPUTS` |

**Other messages**

| Message / field | H | R | S | F | U | Notes |
|---|---|---|---|---|---|---|
| `TX_TRANSPARENT_INPUT` sentinel digest (index = total = 0) | | ✓ | | | | compared with the recomputed transparent digest |
| `TX_TRANSPARENT_INPUT` announcing an input | | | | ✓ | | refused: `TRANSPARENT_INPUTS_UNSUPPORTED` |
| `TX_OUTPUT` sighash sentinel | | ✓ | | | | compared with the sighash the device computed; the device's value is the one kept |
| `SIGN_REQ.sighash` | | | | ✓ | | must equal the verified sighash, otherwise the session ends |
| `SIGN_REQ.alpha` | | | | | ✓ | used as the spend-authorization randomizer. Tolerated: a wrong `alpha` gives `rk' ≠ rk`, a signature that verifies under no action — an invalid transaction. The message signed is still the verified sighash |
| `SIGN_REQ.amount`, `.fee`, `.recipient` | | | | | ✓ | ignored: they reach no screen and no decision |
| `FVK_REQ.coin_type` | | | | ✓ | | compared with the device's network if present and non-zero; sets nothing |
| `TRANSPARENT_SIGN_REQ` | | | | ✓ | | refused, always |
| frame header (`version`, `seq`, `type`, `length`, CRC) | | | | ✓ | | a frame with a bad CRC or an unsupported version produces an `Error` frame and ends the session. Stray bytes between frames and a header announcing an over-long payload are dropped without a reply; `seq` is echoed, not checked. None of this reaches the signer |

What is not in any table because the host never sends it: the spend side. The device does not learn which notes are spent, their values or their owners. It signs for the value balances (H above); it cannot attribute them. Hence `total_leaving` is an upper bound on what this wallet loses, exact when all inputs are the wallet's.

**The review guard is an ordering guard.** "S" means the library passes the value to the firmware's review callback (or makes it available through `orchard_signer_get_output()` / `get_totals()`) and refuses to reach `SIGNER_VERIFIED` until the corresponding `confirm_*` call. The library cannot observe a screen. A firmware holds `ask` and can call `confirm_action()` unconditionally or sign outside this API; the guard makes the safe sequence the default, it does not make it the only possible one.

**Session rules of the dispatcher.** Every `Error` frame ends the session: `send_error()` is the only function that emits one and it resets the signer first (`tests/test_hwp_dispatcher.c` asserts, on every Error frame of every wallet session it runs, that the signer is already IDLE with its viewing keys wiped when the frame is sent). A `TxMeta`, a PING and an ABORT each start from nothing. At most one signature per action is released per approved transaction, each for the verified sighash.

## Constant-time operation map

| Operation | Technique | File | Notes |
|-----------|-----------|------|-------|
| Scalar multiplication `[k]*P` | GLV split (`k = k1 + k2·λ`, constant-time Babai rounding) + interleaved fixed-window ladder; table entries selected by a masked scan of all `2^w` entries, signs by masked select | `src/pallas.c` pallas_point_mul() | Fixed iteration count; no branch or memory index depends on the scalar. The zero digit and the initial identity go through the same exception-free RCB addition (audit C-1) |
| Fixed-base scalar multiplication `[k]*B` (`B` = spend-auth `G`, NoteCommit `R`, CommitIvk `R`) | Lim-Lee comb (4 teeth × 2 blocks) over a precomputed table; entry selected by a masked scan of all 15 entries; digit 0 performs the same mixed addition on a dummy entry and the result is dropped by a masked select whose mask is read back from a `volatile` slot | `src/pallas.c` pallas_point_mul_fixed(), `src/pallas_fixed_base_table.h` | Fixed 32 doublings + 64 mixed additions; digit bit positions depend only on loop counters; no branch or memory index depends on the scalar. Used for `ask`, `rsk`, the RedPallas nonce, `rivk`, `rcm`. The digit state lives in two `volatile` stack slots cleared before returning. An out-of-range base id returns the point at infinity. Table integrity is **not** checked automatically: `pallas_verify_fixed_points()` rebuilds every entry from a fresh hash-to-curve of the base, but it is an optional self-check the integrator has to call (e.g. at boot); none of the bundled firmware integrations calls it today |
| Base-field multiplication / squaring `a * b mod p` | Schoolbook product + folding with `2^254 ≡ -c (mod p)`, masked final subtraction | `src/pallas.c` fp_mul(), fp_sqr(), fp_reduce_wide() | Straight-line limb arithmetic; replaces the data-dependent shift-compare-subtract loop (audit M-3) |
| Base-field add / sub / negate | Limb chain + masked conditional correction by `p` | `src/pallas.c` fp_add(), fp_sub(), fp_neg() | No branch on the operands |
| Base-field inversion | Constant-time safegcd: 20 batches of 30 masked divsteps (adapted from libsecp256k1 `modinv32`) | `src/pallas.c` fp_inv() | Fixed 600 divsteps regardless of the value; replaces Fermat exponentiation, which had replaced the variable-time Stein GCD (audit C-1) |
| Modular reduction `x mod q` | Fixed-iteration conditional subtraction via `bn_cmov()` | `src/redpallas.c` fq_full_reduce() | No variable-length while loops |
| Field multiplication `a * b mod p` | Shift-and-add with `bn_cmov()` conditional add | `src/redpallas.c` fq_mul() | No branching on secret bits |
| Nonce-is-zero check | `bn_cmov()` replaces zero with 1 | `src/redpallas.c` generate_nonce() | No `if` branch on nonce value |
| Wide-to-scalar reduction (64B -> 32B) | Horner's method with nibble processing | `src/redpallas.c` fq_from_wide() | Deterministic iteration count |
| Address ownership `pk_d == [ivk]·DiversifyHash(d)` | `pallas_point_mul()` on the public `g_d`, branch-free `repr_P` encoding (the sign bit is OR-ed in, not selected), `ct_memequal()` | `src/orchard.c` orchard_ivk_owns_address(), ivk_pk_d() | Constant-time in `ivk`. Only the returned bit depends on the key; it is the classification the device displays. The signer tries the internal key first and skips the external one on a match, so the time per output reveals "change / not change" — nothing the display, or the host holding the FVK, does not already have |
| `rivk_internal` | BLAKE2b + constant-time wide reduction (`reduce_512_mod`) | `src/orchard.c` orchard_derive_rivk_internal() | No report with `rivk` tainted |
| `Commit^ivk` blinding `[rivk]·R` | fixed-base comb (`PALLAS_BASE_COMMIT_IVK_R`); message packed with shifts, no branch on a key bit | `src/orchard.c` orchard_commit_ivk() | Constant-time in `rivk`. The Sinsemilla **message** is `ak ‖ nk`: its table lookups (or, without a table, its hash-to-curve calls) depend on those two values — see below |
| Sighash / cmx / enc_ciphertext / epk comparison | `ct_memequal()` (volatile XOR accumulator) | `src/orchard_signer.c` | Sighash is public data, but ct-comparing also memo-bound ciphertexts on the same code path keeps the timing profile uniform across all on-device verification checks |
| ChaCha20 stream cipher | Pure 32-bit `+`, `^`, rotates; no table lookups | `src/chacha20poly1305.c` | RFC 7539 §2.3 — inherently constant-time |
| Poly1305 MAC | 26-bit-limb representation (poly1305-donna); branch-free field arithmetic | `src/chacha20poly1305.c` | RFC 7539 §2.5 |
| ChaCha20-Poly1305 tag check | `ct_memequal_local()` (volatile XOR accumulator, no early-out) | `src/chacha20poly1305.c::chacha20poly1305_decrypt` | Tag verified before any plaintext is written |
| AES-256 (FF1 diversifier + AEAD sealed storage) | Masked full-scan S-box: every S-box byte touched on every lookup | `src/aes/aes_ct.c` | Replaces the cache-timing-leaky T-table AES (audit H-3); optional constant-time HW-AES backend via `orchard_set_aes256_encrypt()` |
| Memory comparison | `ct_memequal()` | `src/memzero.c` | Volatile accumulator prevents short-circuit |
| Secret cleanup | `memzero()` via platform-specific secure zeroing | `src/memzero.c` | Resists dead-store elimination; covers the per-output K_enc / esk / np buffer in `orchard_compute_enc_ciphertext` |


## How the constant-time property was checked

"Constant-time" above is a property of the compiled code, not only of the C source, so this is what was actually verified (November 2026) and with which compilers:

- **Method** — the library is run under valgrind memcheck 3.25.1 with the secret marked undefined (`ask` for `redpallas_sign` / `redpallas_derive_ak`; the scalar for `pallas_point_mul` and for `pallas_point_mul_fixed` on each of the three bases; `rcm` / `rivk` for `sinsemilla_short_commit` in both domains). memcheck then reports every conditional jump and every memory address that depends on the secret. This covers the paths exercised, on x86-64; it is not a proof, and it says nothing about power or EM leakage.
- **Compilers** — host `gcc` 16.2 at `-O2` and `-Os`, and `clang` 23.1 at `-O1`, `-Os`, `-O2`, `-O3`. All six builds report the same, and only, three sites, each of which branches on a value derived from the *result* of the multiplication, not on the scalar's bits:
  - `pallas_from_jac()`: "is the result the point at infinity" (`Z == 0`). The result is public for `ak`, `rk`, `R` and the commitment; for the intermediate `[rcm]·R` it reveals only whether `rcm ≡ 0 (mod q)`.
  - `pallas_point_encode()` (`redpallas.c`): the parity of the public point's `y` selects the sign bit of the encoding.
  - `redpallas_derive_ak()`: the same parity decides the public `ak` normalisation. (Inside `redpallas_sign()` the corresponding `ask` normalisation is a `bn_cmov` and is not reported.)
- **What clang did before the value barriers** — at a18827e and in the first version of the comb, clang compiled `fp_cond_sub_p()` to a real branch on the borrow (`-O1`, `-Os`, `-O3`), flagged the conditional subtraction in `glv_decompose()`, and turned the comb's zero-digit select into a select between two pointers followed by a load. GCC compiled all three as written. The masks now pass through a `volatile` object (`ct_mask_barrier()` in `src/pallas.c`), after which clang reports nothing beyond the three sites above.
- **Targets** — the firmware toolchains are GCC: `arm-none-eabi-gcc` 12.3 (Flipper Zero, Cortex-M4) and `xtensa-esp32s2-elf-gcc` 13.2 (ESP32-S2). valgrind cannot run their output, so for those two the check is weaker: the `-Os` disassembly of `pallas_point_mul_fixed()` and `fp_cond_sub_p()` was read by hand for both (only loop-counter, base-id and yield-counter branches, no conditional moves; the comb's digit is stored only in its two `volatile` stack slots, which are zeroed before the return). The other functions were not read instruction by instruction on those targets, and on Xtensa the windowed ABI can spill live registers to the stack on a window overflow, which C code cannot prevent. A value barrier is a strong hint to the optimizer, not a language guarantee: any new compiler or flag set should be re-checked the same way.
- **Ownership classification (November 2026)** — same method, same six builds, on the new code: `ivk` undefined for `orchard_ivk_owns_address()` (an own address and a foreign one) and `orchard_ivk_derive_pk_d()`; `rivk` undefined for `orchard_derive_rivk_internal()`, `orchard_commit_ivk()` and `orchard_derive_ivks()`. All six report only: `pallas_from_jac()` "is the result the identity" (for `[ivk]·g_d` that reveals only `ivk ≡ 0`, which no valid key satisfies; for the commitment as above), and one branch in `orchard_derive_ivks()` on "is an ivk zero / ⊥", the function's own error result. `orchard_derive_rivk_internal()` reports nothing.
- **What is *not* constant-time there, knowingly** — `Commit^ivk` hashes `ak ‖ nk` with Sinsemilla, whose S-table lookups are indexed by the message (with all three FVK components undefined, memcheck duly reports the lookup path, and without a table the variable-time hash-to-curve of each chunk). `ak` and `nk` are full-viewing-key components: the host receives them in `FVK_RSP`, and address derivation has always processed them the same way. What changes is frequency: this now runs once per signing session instead of once per wallet. On a target that serves the S table from external storage (Flipper Zero, SD card), the sequence of table offsets read during `feed_meta()` is therefore a function of `ak ‖ nk`. `rivk`, the one component that is blinding rather than message, goes through the constant-time comb.
- **Transparent (secp256k1) code: not constant-time, and no longer used for signing.** The history, plainly: until November 2026 the dispatcher signed transparent inputs with `secp256k1_ecdsa_sign_digest()`. With the secret key undefined that function reports 12 sites under memcheck (gcc `-O2`/`-Os`, clang `-O2`): `secp256k1_from_jac` (Z == 0), `secp256k1_jac_add_mixed` (operand at infinity, `h == 0`), `secp256k1_jac_double` (Z == 0), the range checks on the key and on the RFC 6979 nonce, and the `r == 0` / `s == 0` / low-S tests; the first three sit inside the ladder and depend on the nonce. After one approved session the dispatcher answered any number of signing requests without confirmation, so the host could collect timings at will. On top of that the signed value was not a valid ZIP 244 signature hash, and the field multiplication had an aliasing bug that made every public key whose ladder contains an addition wrong (1·G and 2·G were correct; 3·G onwards were not). The feature was disabled, not repaired: transparent inputs are refused, `TRANSPARENT_SIGN_REQ` is refused, the dispatcher has no transparent key, and the ECDSA code is compiled only with `ZCASH_ENABLE_TRANSPARENT_SIGNING=1` (default 0). The arithmetic bug is fixed (`tests/test_secp256k1.c`). What remains reachable by default is public-key derivation (`secp256k1_get_public_key33()`, `bip32_derive_transparent_sk()`), which is still variable-time in the secret key. No constant-time claim is made for any secp256k1 code.
- **Not covered** — the scalar-field helpers in `src/redpallas.c` and the rest of the library were exercised only as far as `redpallas_sign()` reaches them; Sinsemilla's S-table lookups are indexed by the message, which the host knows, and were not tainted.

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

The signer state machine is single-threaded per call on every supported MCU, so the `static` pattern does not introduce re-entrancy risks. What is and is not wiped from that static storage is specified under [Secret material lifecycle](#secret-material-lifecycle).

Build and verify:
```bash
cmake .. -DSTACK_ANALYSIS=ON && make
../scripts/check_stack.sh .
```

## Secret material lifecycle

1. **Derivation**: spending key derived from BIP39 seed via ZIP-32 (BLAKE2b-512).
2. **Use**: signing via RedPallas (deterministic nonce from BLAKE2b-512).
3. **Cleanup**: intermediate scalars, points, hash states and key bytes are zeroed via `memzero()` before the function that owns them returns.

### What is guaranteed about static storage

Static storage matters more than the stack here: on Flipper Zero an external app's `.data`/`.bss` is heap, and whatever is left in it survives the app.

**What is claimed.** On the paths listed below, when a library function returns, no `static` object of the library holds data derived from the caller's secrets (PIN, PIN-derived key, mnemonic, seed, spending/viewing key components, signing nonces, note randomness), with the exceptions in the table further down. This covers derived state — hash message schedules, HMAC key pads, field and point temporaries — not only verbatim copies of a key. It is a tested property of those paths, not a proof about every path through the library.

**How it is checked.** `tests/test_residue.c` (part of `ctest`) runs the following twice, with two unrelated sets of secrets, snapshots the whole `.data`/`.bss` of the process after each run and requires the two snapshots to be byte-identical; it also searches the snapshots for verbatim copies of each secret:

- PIN KDF, seal + unseal, mnemonic → seed, ZIP-32 and BIP-32 derivation, `ak`, default address (current and legacy), RedPallas signing (plain and domain-separated), cmx + `enc_ciphertext` recomputation, both incoming viewing keys, the ownership check, HMAC / SHA-256 / SHA-512 one-shots;
- signer sessions on a context placed in `.bss`: one carried to a signature and reset, and one for each way the library abandons a session — memo mismatch, note-commitment mismatch, a recipient that is not the declared one, bad pool, bad action size, value balance for a pool without actions, negative fee, a transparent input, a malformed transparent output, a transparent digest mismatch, a sighash mismatch after full confirmation, a non-empty transparent digest without a transparent pass;
- three dispatcher sessions on an `HwpDispatcher` placed in `.bss`, driven by scripted frames: `FVK_REQ` → review with a memo screen → totals → final confirmation → signature; the same cancelled by the user at the memo screen; the same aborted by the library on a memo mismatch. These cover the dispatcher's static memo scratch and its embedded buffers (TX buffer, RX parser, `SIGN_REQ` scratch), which `hwp_dispatcher_run()` wipes before returning;
- `f4jumble()` / `f4jumble_inv()`, `sha1_Raw()` and `pbkdf2_hmac_sha256()` on secret input.

It passes with gcc and clang, Debug and Release. On the release before this check existed it reports 4167 secret-dependent bytes in 143 ranges, among them the 64-byte PIN-derived wallet-seal key left verbatim by `pbkdf2_hmac_sha512()` (fixed), the SHA-256/SHA-512 message schedules, the secp256k1 ladder temporaries and the hash-to-curve / Sinsemilla intermediates (all fixed).

**How good the check is.** A mutation run (each `memzero` added since a55d168 removed in turn, `test_residue` re-run) is the measure of what the test would notice: see the numbers and the list of surviving mutants under "Limits of the check".

**Session state.** The signer context is caller-owned memory, but it holds viewing-key material for the length of a session: `ivk_external` and `ivk_internal`, derived by `orchard_signer_feed_meta()`. `orchard_signer_reset()` wipes the whole context with `memzero()` (keeping only the device's coin type). The library calls it on every rejected action, transparent output, totals / fee / sighash failure and transparent input. The dispatcher calls it before every `Error` frame it sends — there is one function that sends them — and on a new `TxMeta`, on PING / ABORT, after the last signature of a transaction and when `hwp_dispatcher_run()` returns. `tests/test_ownership.c` checks that the two keys are gone after each of those signer paths, `tests/test_hwp_dispatcher.c` at every Error frame of its wallet sessions and after each of them.

**Limits of the check.** It covers the paths that sequence executes, on an ELF/Linux host (elsewhere the test reports SKIP). Mutation run of November 2026 (method of the independent review: every `memzero` line added since a55d168 removed in turn, 97 mutants, gcc `-O2`): **62 are caught, 35 are not.** The review's run on the previous version of the test left 30 of 87 uncaught; of those, the ones in paths the test did not execute are now caught (the signer's error-path wipes, the dispatcher's static memo buffer, the F4Jumble scratch, SHA-1). What remains uncaught, i.e. **what this test does not establish**:

- 19 wipes of **stack locals** (10 in `orchard.c`: the ivk derivation and ownership-check scratch; `pbkdf2.c` `digest`; one Sinsemilla lookup buffer; the dispatcher's `FVK_RSP` / `SIGN_RSP` / signature locals and parser carry-over; the signer's transparent-digest local; the secp256k1 multiplication temporary). The test compares static storage; the stack is only scanned for verbatim secrets, for information.
- 6 wipes that are **masked by another wipe** of the same bytes on the tested paths: the dispatcher wipes its RX frame and `SIGN_REQ` scratch after every frame and again on return (4), and the signer clears the two anchors that every later reset clears again (2).
- 2 wipes on the **failure path of `orchard_derive_ivks()`** (an invalid full viewing key that passes the argument checks), which the test does not provoke.
- 6 lines in **`pallas.c`** — statics in `fp_is_square()`, `fq_reduce()`, the identity fallback of `pallas_jac_add_mixed()`, and the per-chunk point / chunk index / blinding-base point of the Sinsemilla routines — and 2 in **`secp256k1.c`** (early-exit paths of the mixed addition). On the tested paths their content either does not differ between the two secret sets, is cleared again later, or the path is not taken; the test gives no evidence about them either way.

Not driven at all: `secp256k1` ECDSA signing (compiled out by default), `orchard_decode_ua_orchard_receiver()`, the BIP-39 cache (off by default), and targets other than ELF/Linux.

**Exceptions — deliberately or knowingly not wiped:**

| Object | Holds | Why |
|---|---|---|
| `orchard_diversify_hash()` cache (`cached_d`, `cached_g_d`) | the last diversifier processed and its `g_d` | Public address data, kept so one action hashes it once. It does identify the last address handled (possibly the wallet's own) |
| `orchard_decode_ua_orchard_receiver()` (`hrp_decoded`, `data5`, `raw`) | the last address decoded | An address the caller supplied. The dispatcher no longer calls this function |
| `mnemonic_generate()` / `mnemonic_from_data()` (`mnemo`) | the generated mnemonic | It is the return value; the caller must call `mnemonic_clear()` when done |
| BIP-39 cache, only with `USE_BIP39_CACHE=1` (default 0) | mnemonic, passphrase and seed | Opt-in cache; `bip39_cache_clear()` empties it |
| Curve constants, init flags, callback pointers, the yield counter, the test-only LCG state | nothing secret | Configuration |

**Caller-owned memory is the caller's to wipe**: output buffers, and streaming hash/HMAC contexts that are never finalized. The signer context and the `HwpDispatcher` are caller-owned too, but the library wipes them itself at the points listed above; a caller that abandons a signer context mid-session without `orchard_signer_reset()` leaves the session's viewing keys in it.

**The stack is best effort.** Named stack buffers that hold secrets are `memzero()`ed, but C cannot control what a compiler spills or copies. `test_residue` also copies the dead stack right after the sequence and searches it for verbatim secrets; it finds none with gcc 16 and clang 23 on x86-64, but that result is reported for information only and is not part of the pass/fail verdict or of the guarantee.

## Test vector corpus

Known-answer tests in `tests/test_vectors.c` cross-check the C implementation against the Rust reference (librustzcash; vectors generated by `tools/gen_test_vectors`, orchard 0.10). Coverage:

- **BLAKE2b** with 5 personalization tags (ZcashIP32Orchard, Zcash_ExpandSeed, Zcash_RedPallasN, Zcash_RedPallasH, ZTxIdOrchardHash)
- **Pallas hash-to-curve** (3 domain/message pairs including SinsemillaQ)
- **Sinsemilla S-table** (5 sample points: indices 0, 1, 2, 512, 1023)
- **ZIP-32** full derivation chain (master key, spending key, ak, nk, rivk, diversifier, pk_d)
- **Default address vs the `orchard` crate** (`tests/test_address_vectors.h`, generated by `tools/gen_address_vectors` against `orchard` 0.16.0): 16 seed/network pairs (8 seeds × mainnet/testnet), 7 of them with an odd-y `[ask]·G`. For each: `ak`, default `d` and `pk_d` equal to `FullViewingKey::address_at(0, External)`, the UA string, and the pre-fix address returned by `orchard_derive_unified_address_legacy()` — equal to the default exactly when y is even. Before November 2026 the corpus had a single, even-y address vector, which is how a wrong diversifier key for odd-y seeds went unnoticed (see README, "Default address conformance")
- **Viewing keys and ownership vs the `orchard` crate** (same header and generator, `tests/test_vectors.c`): for the same 16 seed/network pairs, `nk`, `rivk`, `rivk_internal` (also with the sign bit of `ak` set: the derivation takes the normalised encoding), `ivk` for both scopes, the default change address `address_at(0, Internal)` (diversifier and `pk_d`), an own receiving address at a non-default diversifier index, and the ownership predicate in every combination: own addresses recognised, scopes not confused, foreign / negated / wrong-diversifier addresses rejected. `rivk_internal` is private in the crate; the generator recomputes it and checks it through `Commit^ivk` (evaluated with the `sinsemilla` crate) against the crate's internal ivk before emitting it
- **Signer against a lying host** (`tests/test_ownership.c`, built with the defaults and with FlipZcash's `MAX_ACTIONS=8` / `MAX_MEMOS=4`; transactions built by `tests/test_tx_fixture.h`): change → `OWN_INTERNAL`; change redirected to a foreign address (receiving or change address of another wallet) → `EXTERNAL` and counted as leaving; own receiving addresses → `OWN_EXTERNAL`; zero-value padding (verified like any output; a memo cannot be hidden on it — the sealed-pool spend dummy is the one output whose ciphertext is not matched, and it is checked not to be decryptable as its note); substituted memo / epk → `MEMO_MISMATCH`; corrupted ciphertext on own change; action, memo and ordering limits; branch allow-list; totals including every overflow boundary and the transparent case; the value balance of a pool without actions (F1) at feed, totals and verify; transparent inputs refused, transparent outputs P2PKH/P2SH only; the device network (unset, mismatch, survives resets, not in the sighash); viewing keys wiped on every exit
- **Whole sessions through the dispatcher** (`tests/test_hwp_dispatcher.c`, same two builds): what the UI callbacks receive for an honest send and for a redirected change, device totals at the final confirmation regardless of the host's `SIGN_REQ` amount / fee / recipient, and the frames that end a session — compact body, substituted memo, out-of-order / repeated / missing actions, a memo on a device with no memo screen, a branch outside the allow-list, signing requests before verification; a second transaction after a confirmed first
- **Regression tests for the November 2026 independent review** (same file, both builds): ports of the reviewer's attack drivers — A1 fee hidden in the value balance of an absent pool (both directions, and the zero-action case), A2 host-named address on the final screen, A3/A6/A7 transparent inputs and 200 unconfirmed transparent signing requests, A5 shielded → transparent and its edges (second pass, skipped stream, surplus / too many / overflowing / non-standard outputs), the A4 table (signature count, wrong-sighash `SIGN_REQ`, unreviewed second transaction, odd UI return values, PING / ABORT / double sentinel, negated and zero `pk_d`, pool-tag lie, flag policy, action-count extremes, value-balance extremes, near-empty memos), the hidden memo on a zero-value output, the error rule (unknown type, CRC, version, short frames), the device network, NULL keys, and a new `TxMeta` after a partly signed transaction
- **Shielded → transparent against the crates** (`tests/test_ironwood.c`, `tests/test_ztot_vector.h` from `tools/gen_ztot_vector`): a v6 transaction built by `zcash_primitives` 0.31.0 (Ironwood spend, transparent P2PKH output, Ironwood change, the builder's dummy output) replayed through the signer; the device's sighash must equal the one computed by the `pczt` 0.10.0 Signer role, and the dummy output must pass the ciphertext check with 512 zero bytes of memo
- **secp256k1 / BIP-32** (`tests/test_secp256k1.c`): k·G for 22 scalars against independent affine arithmetic, BIP-32 test vector 2 including non-hardened children, the Zcash BIP-44 transparent key of a known mnemonic for both coin types; and, built separately with `ZCASH_ENABLE_TRANSPARENT_SIGNING=1`, two RFC 6979 ECDSA vectors. Added after the arithmetic was found wrong with no test to notice
- **Secret residue** (`tests/test_residue.c`): see [What is guaranteed about static storage](#what-is-guaranteed-about-static-storage)
- **ZIP-32 child key intermediates** (per-hop sk + chaincode for each of the 3 derivation steps)
- **FF1-AES-256** diversifier encryption (3 synthetic + 1 real dk from ZIP-32 derivation)
- **RedPallas signing** with deterministic nonce (4 test cases: standard, alpha=0, sighash=0, large scalars; compiled with `TEST_DETERMINISTIC_NONCE`)
- **Sinsemilla end-to-end** (HashToPoint with 1 and 2 chunks, ShortCommit with synthetic 510-bit message, ShortCommit with real ak||nk and rivk from ZIP-32)
- **F4Jumble** forward (3 test cases: 48, 83, and 128 bytes) + inverse round-trip
- **ChaCha20-Poly1305** RFC 7539 §A.5 reference vector + tamper-detection round-trip (`chacha20poly1305_self_test()`, invoked from `test_orchard`)
- **`orchard_compute_enc_ciphertext`** consistency (signer test fixture in `tests/test_signer.c`): per-action recomputed `enc_ciphertext` + `epk` vs. on-action bytes, with positive and tamper-rejection cases (memo / rseed / enc_ciphertext bit-flips → `SIGNER_ERR_MEMO_MISMATCH` or `_NOTE_COMMITMENT_MISMATCH`)
- **Fee math** (`tests/test_signer.c`): fee == value balance of the pool that has the action, caching, negative-fee rejection, totals-confirmation gate
- **NU6.3 / Ironwood cross-validation** (`tests/test_ironwood.c`, vectors from `tools/gen_ironwood_vectors` against `orchard 0.15.0-pre.2`, `zcash_note_encryption 0.4.1`, `zcash_primitives 0.29.0-pre.0`): ZIP-2005 V3 note-commitment cmx (and V3 ≠ V2 divergence), V3 + legacy-V2 note encryption (epk, ciphertext, Poly1305 tag — also pins the `Zcash_OrchardKDF` input order `sharedSecret ‖ ephemeralKey`), v6 empty-bundle effects digests for the Orchard and Ironwood pools (`ZTxIdOrchardH_v6` / `ZTxIdIronwd_H_v6`), v6 TxMeta wire round-trip, and the full five-leaf v6 sighash both at the zip244 layer and end-to-end through the signer state machine (per-action + fee confirmation gates, bit-flipped-sighash rejection)
- **v6-only wire tier enforcement** (post-NU6.3 branch; `tests/test_signer.c`, `tests/test_hwp_dispatcher.c`): the device accepts ONLY the v6 wire tier. Legacy 125/129-byte v5 `TxMeta` layouts → `SIGNER_ERR_BAD_META` (signer) / `Error(BAD_FRAME)` with no ACK (dispatcher); v6-sized metas with pre-v6 header constants or forbidden pool flag bits → `SIGNER_ERR_BAD_META`; untagged 903/1415-byte v4/v5 action payloads and invalid pool tags → `Error(BAD_FRAME)` + session reset. The v5 four-leaf sighash entry point (`zip244_shielded_sighash`) no longer exists in the code
- **PIN-sealed storage + lockout** (`tests/test_h5.c`): AEAD seal/unseal self-test, in-place round-trip, wrong-key rejection, deterministic PIN KDF, and the `wallet_lockout` fail-count/wipe-threshold state machine including serialization corruption detection
- **Transparent address rendering** (`tests/test_base58.c`): `script_to_taddr()` Base58Check KATs for P2PKH/P2SH on mainnet and testnet (`t1`/`t3`/`tm`/`t2`)
- **Protocol layer** (`tests/test_hwp.c`, `tests/test_hwp_dispatcher.c`): frame encode/decode + CRC-mismatch detection, and a virtual-device dispatcher session (drain/parse/dispatch, PING/PONG, FVK exchange)

The whole test suite must run with assertions enabled. Release-mode builds (`-DNDEBUG`) silently turn `assert()` into a no-op; the test executables therefore force `-UNDEBUG` (see `tests/CMakeLists.txt`) so a broken invariant fails loudly rather than passing on a stripped binary.

Regenerate vectors:
- Orchard KAT corpus: `cd tools/gen_test_vectors && cargo run 2>/dev/null > ../../tests/test_vectors.h`
- Address / viewing-key vectors: `cd tools/gen_address_vectors && cargo run --release > ../../tests/test_address_vectors.h` (orchard 0.16.0; the run aborts if any of its cross-checks against the crate fails)
- Ironwood/NU6.3 vectors: `cd tools/gen_ironwood_vectors && cargo run --release` (hex output pasted into `tests/test_ironwood.c`)
- Shielded → transparent vector: `cd tools/gen_ztot_vector && cargo run --release > ../../tests/test_ztot_vector.h` (zcash_primitives 0.31.0, pczt 0.10.0, orchard 0.16.0; uses OS randomness, every run gives a different valid transaction)
