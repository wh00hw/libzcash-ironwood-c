# libzcash-ironwood-c

> Formerly `libzcash-orchard-c` — renamed after the NU6.3 / Ironwood migration. The CMake project and library target are named `zcash-ironwood-c` as well (renamed from `zcash-orchard-c` in July 2026 — update `target_link_libraries` when bumping). The `orchard_*` C symbol prefix is intentionally retained: it names the Orchard *protocol/circuit family*, which serves both the sealed Orchard pool and the Ironwood pool — mirroring upstream, where Ironwood lives inside the `orchard` crate.

> **WARNING — Proof of Concept.** This library has **not** been audited. It is published for review and experimentation only. **Do not use it to protect real funds** until an independent security audit has been completed. Use at your own risk.

Pure C11 library for signing Zcash Orchard/Ironwood (shielded) transactions on embedded hardware wallets. Shielded → transparent payments are supported; **spending from transparent addresses is not** (see [Transparent inputs are not supported](#transparent-inputs-are-not-supported)).

**NU6.3 / Ironwood ready:** implements the v6 transaction sighash (five-leaf ZIP-244 tree with the Ironwood pool digest, `ZTxIdOrchardH_v6` / `ZTxIdIronwd_H_v6` personalizations, anchors moved to the authorizing-data commitment), ZIP-2005 V3 note plaintexts (lead byte `0x03`, quantum-recoverable rcm bound to all note fields), pool-tagged action streaming, and the sealed-Orchard flag policy (cross-address bit enforced clear post-NU6.3). All cross-validated against `orchard` 0.15.0-pre.2 in `tests/test_ironwood.c`.

> **`v6-only` branch (post-NU6.3 activation merge):** this branch drops the legacy pre-v6 wire tiers entirely. `orchard_signer_feed_meta()` accepts only the 166/170-byte v6 `TxMeta` (legacy 125/129-byte v5 metas → `SIGNER_ERR_BAD_META`), the dispatcher accepts only pool-tagged action payloads (904 / 1416 bytes; untagged 903/1415-byte v4/v5 payloads → `Error(BAD_FRAME)`), and the v5 four-leaf sighash entry point has been removed. Intended for merge after Zcash mainnet activates NU6.3.

Implements key derivation, address generation, RedPallas signing, on-device transaction review, and a binary serial protocol (HWP) for host-device communication. Zero external dependencies — all cryptographic primitives are self-contained. No dynamic memory allocation, no OS calls, no hardware-specific code in the core.

> **Upgrade note — default address (November 2026).** `orchard_derive_unified_address()` now returns the address every librustzcash-based wallet derives from the same full viewing key (`FullViewingKey::address_at(0, External)` in the `orchard` crate). Earlier releases (up to a55d168) computed the diversifier key from the un-normalised `[ask]·G` encoding and, for seeds whose `[ask]·G` has an odd y-coordinate — about half of all seeds — returned a different default address. Keys, FVK, signatures and every other output are unchanged; seeds with an even y are not affected at all.
>
> If a wallet is affected, the address it showed before is **still its own**: an external address of the same incoming viewing key, so funds sent to it — past or future — are detected and spendable by the device and by any wallet holding the FVK. Only the *default* address differs. `orchard_derive_unified_address_legacy()` returns the pre-fix address; compare it with the current one to tell whether a seed is affected (see [Default address conformance](#default-address-conformance)).

## Features

- **ZIP-32 key derivation** — master key from BIP39 seed, hardened child derivation (`m_Orchard / 32' / coin_type' / account'`)
- **BIP-32 transparent key derivation** — `m / 44' / coin_type' / 0' / 0 / 0` (`bip32.h`), checked against BIP-32 test vector 2 and the Zcash key `zcash_transparent` derives. Until November 2026 the secp256k1 arithmetic underneath was wrong and this returned keys no other wallet derives (see [Known limitations](#known-limitations)). The library cannot spend from the resulting address: do not show it to users as a receiving address
- **Orchard Unified Addresses** — full derivation with F4Jumble (ZIP-316) and Bech32m encoding
- **Pallas / RedPallas** — curve arithmetic, Sinsemilla hash, spend authorization signing. The field and group layers are constant-time and tuned for 32-bit MCUs: special-form reduction for `p = 2^254 + c`, safegcd inversion, GLV-split fixed-window scalar multiplication, comb tables for the fixed bases, table-based square roots (see [Performance](#performance))
- **secp256k1** — public-key derivation (Montgomery ladder with masked swap — **not constant-time in the secret key**, see [Known limitations](#known-limitations)). ECDSA signing (RFC 6979, DER) exists in the source but is **compiled out by default** (`ZCASH_ENABLE_TRANSPARENT_SIGNING=0`) and nothing in the library calls it
- **ZIP-244 sighash, computed on-device** — the v6 (five-leaf, NU6.3/Ironwood) shielded signature hash for transactions **without transparent inputs**: header digest, per-pool action digests (compact / memos / noncompact sub-hashes), and the transparent leaf from the streamed transparent outputs. Cross-checked against `zcash_primitives` 0.31 with a real shielded → transparent transaction (`tests/test_ztot_vector.h`)
- **Transparent outputs** — the device recomputes the transparent digest from the outputs it is sent (P2PKH / P2SH only), shows each one as a t-address, and counts every one of them as leaving the wallet. A transaction with a transparent input is refused (`SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED`)
- **Sapling-component lockout** — Orchard-only invariant: `sapling_digest` enforced equal to the ZIP-244 empty-bundle constant on `TxMeta` receipt; any non-empty Sapling bundle aborts the session before action streaming
- **NoteCommitment (cmx) recomputation** — for every action, the device recomputes `cmx = Extract_P(NoteCommit(g_d, pk_d, v, ρ, ψ))` from the note plaintext (recipient, value, rseed) the companion declares, and rejects the action if it does not match the cmx field of the action it hashes. For every shielded output, recipient and value shown on the device are therefore the ones committed in the action the device signs
- **On-device ownership classification** — the device derives its own incoming viewing keys (external, and the ZIP 32 internal/change key) once per signing session and decides, for every output, whether `pk_d == [ivk]·DiversifyHash(d)`: `OWN_INTERNAL` (change), `OWN_EXTERNAL` (one of the wallet's receiving addresses) or `EXTERNAL`. The host has no say in it — there is no "is change" field anywhere. The firmware UI receives the classification with each output, so a "change" output redirected to somebody else's address is shown, and counted, as a payment leaving the wallet
- **`enc_ciphertext` recomputation, for every output** — cmx binds value and recipient but is silent about the 512-byte memo and about whether the recipient can decrypt the note at all. For every output — payment, own change, zero-value padding — the device recomputes `enc_ciphertext = ChaCha20-Poly1305(K_enc, IV=0, leadByte ‖ d ‖ value_LE ‖ rseed ‖ memo)` with `K_enc = BLAKE2b("Zcash_OrchardKDF", repr_P([esk]·pk_d) ‖ repr_P(epk))` and `esk = ToScalar(PRF^expand(rseed, [0x04] ‖ ρ))` derived on-chip (ZIP-212), and constant-time-compares it against the action's `enc_ciphertext` and `ephemeral_key`. There is no compact (no-memo) path: the 904-byte action body is answered with `Error(MEMO_REQUIRED)`
- **Review-before-sign ordering** — `orchard_signer_verify()` refuses to advance to `SIGNER_VERIFIED` unless every output with a value (or with a memo) has been confirmed via `orchard_signer_confirm_action()` and the totals via `orchard_signer_confirm_totals()`, and `sign()` requires `SIGNER_VERIFIED`. This is an API-ordering guard that makes the safe path the default; it does not stop a firmware — which holds the spending key — from calling `confirm_*` without showing anything. Outputs verified to carry neither value nor a memo (padding) are counted, not shown
- **On-device memo rendering** — non-empty verified memos are kept in a per-context pool (`ORCHARD_SIGNER_MAX_MEMOS` slots of 512 B) and exposed via `orchard_signer_get_action_memo()`; the dispatcher passes each one to the firmware's memo screen right after its output, and tells the firmware explicitly when an output has none (`HWP_MEMO_NONE`). The pool bounds the memos the user has to read, not the outputs that are verified; one memo too many is `SIGNER_ERR_TOO_MANY_MEMOS`, never a skipped screen
- **Totals computed on-device** — `orchard_signer_get_totals()` returns the fee (`value_balance(Orchard) + value_balance(Ironwood) − transparent_out`) and the one number the user has to check: **total leaving the wallet = external shielded outputs + transparent outputs + fee**, every addition overflow-checked. The device computes fee and total leaving from data bound by the sighash it signs — a value balance declared for a pool that has no action is not bound, and is refused unless zero (`SIGNER_ERR_EMPTY_POOL_BALANCE`). The total is an upper bound on what the wallet loses, exact when all inputs are the wallet's. The amount, fee and recipient the host puts in `SIGN_REQ` are ignored
- **Consensus branch allow-list** — `TxMeta.consensus_branch_id` must be in `ORCHARD_SIGNER_ALLOWED_BRANCH_IDS` (default NU6.3 `0x37A5165B` and NU7 `0x77190AD9`, v6 header only), otherwise `SIGNER_ERR_BRANCH_NOT_ALLOWED`. A later network upgrade needs a firmware update, by design
- **Unified Address encoding from arbitrary recipients** — `orchard_encode_ua_raw(d, pk_d, hrp)` produces the canonical ZIP-316 Bech32m string for an Orchard payment address that is *not* the device's own — needed to render the recipient of every output to the user before they confirm
- **Signing context** (`orchard_signer.h`) — state machine that composes all of the above: through this API a signature is released only for the sighash the device computed, after network + branch allow-list + sapling-empty + per-action cmx + ciphertext + ownership classification + the per-output and totals confirmation calls + sighash match
- **Hardware Wallet Protocol v6 only (post-NU6.3)** — framed binary serial protocol with CRC-16, incremental sighash verification, transparent-output digest verification and memo-verifying action payloads. The wire version byte stays `0x02` (framing is unchanged); the wire *tier* is v6-only: legacy v2–v5 hosts are rejected. `TxMeta` must be the 170-byte v6 layout with the device's coin type (125/129-byte v5 metas → `SIGNER_ERR_BAD_META` / `Error(BAD_FRAME)`; the 166-byte layout without a coin type → `Error(NETWORK_MISMATCH)`), and every action payload is 1416 B: the 1-byte pool tag (`0x00` sealed Orchard, `0x01` Ironwood) ‖ action ‖ recipient ‖ value ‖ rseed ‖ memo (esk never on the wire). The 904 B compact body → `Error(MEMO_REQUIRED)`; untagged 903/1415-byte v4/v5 payloads → `Error(BAD_FRAME)`. `TX_TRANSPARENT_INPUT` frames that announce an input and every `TRANSPARENT_SIGN_REQ` → `Error(TRANSPARENT_INPUTS_UNSUPPORTED)`. Every `Error` frame ends the session. `HWP_MAX_PAYLOAD` defaults to 2048 (compile-time overridable, minimum 1420). Compatible with [zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk) (Rust) speaking the v6 tier.
- **Device attestation (HWP v4, audit M1)** — identity + challenge/response messages (`HWP_MSG_IDENTITY_REQ/RSP` `0x0F`/`0x10`, `HWP_MSG_ATTEST_REQ/RSP` `0x11`/`0x12`): the host sends a fresh 32-byte challenge, the device signs it with a domain-separated RedPallas signature (`orchard_sign_with_personal`, personalization `"ZcashHWAttestV1!"`) so a paired host can pin the device identity pubkey and detect device substitution
- **Target-agnostic protocol dispatcher** (`hwp_dispatcher.h`) — the entire device-side state machine (drain → parse → switch → reply, PING/PONG keepalive, IDLE detection, multi-frame drain handling, per-output review orchestration, session and error rules) is contained in the library and exposed through a callback-based API. A new device target wires up six I/O callbacks (`serial_drain`, `serial_send`, `get_tick_ms`, `sleep_ms`, `should_exit`, plus UI callbacks for review/confirm) and gets the full protocol implementation for free. The same code runs on FlipZcash, the virtual-device test fixture, and future ESP32 / BOLOS ports — fix once, benefit everywhere.
- **Transparent t-address rendering on-device** (`base58.h`) — `script_to_taddr()` decodes a P2PKH or P2SH `script_pubkey` to the corresponding Zcash t-address string (mainnet `t1`/`t3`, testnet `tm`/`t2`) via Base58Check encoding. Lets the device display the actual destination of a transparent output (e.g. on a shielded → t-addr sweep) instead of only the change Orchard receivers.
- **BIP39 mnemonic** — generation and seed derivation (PBKDF2-HMAC-SHA512) with an optional progress callback (`pbkdf2_set_progress_cb`) so the UI can drive a bar during multi-second PIN-derived KDF.
- **PIN-sealed storage + lockout** — AES-256-CTR + HMAC-SHA256 AEAD (`aead.h`: `aead_aes256_ctr_hmac_seal/unseal`, `wallet_pin_kdf`) for sealing the wallet secret at rest, plus a PIN-failure lockout state machine (`wallet_lockout.h`) with wipe threshold and corruption-detecting serialization.
- **Tunable RAM footprint** — signer and dispatcher capacities are compile-time overridable for small-RAM targets: `ORCHARD_SIGNER_MAX_ACTIONS` (default 16), `ORCHARD_SIGNER_MAX_T_OUTPUTS` (default 8), `ORCHARD_SIGNER_MAX_MEMOS` (default = MAX_ACTIONS), `HWP_MAX_PAYLOAD` (default 2048, min 1420), `HWP_DISPATCHER_MAX_TX_PAYLOAD` (default 192). FlipZcash builds with `MAX_ACTIONS=8`, `MAX_MEMOS=4`, `HWP_MAX_PAYLOAD=1536`. Large per-function intermediates live in `static` (BSS) scratch, wiped after use, to honour the 512 B per-function stack budget.
- **Crypto primitives** — BLAKE2b, SHA-256/512, HMAC, PBKDF2, AES-256 (FF1), ChaCha20-Poly1305 (RFC 7539, used for Orchard note encryption verification), all in pure C
- **Platform-agnostic** — pluggable RNG, optional Sinsemilla table acceleration, portable compiler abstractions

## Target platforms

| Platform | Status | Notes |
|----------|--------|-------|
| ESP32 / ESP-IDF | Portable | Provide `random32()` via `esp_random()` |
| ARM Cortex-M (STM32, nRF52, ...) | Portable | Provide `random32()` via HW RNG peripheral |
| Flipper Zero | Portable | Provide `random32()` via `furi_hal_random_get()`, optional Sinsemilla table via storage API |
| RISC-V (GD32V, ESP32-C3) | Portable | Provide `random32()`, compile with GCC |
| Linux / macOS (testing) | Works | Opt in to the insecure LCG fallback with `-DUSE_PLATFORM_RNG=0 -DZORCHARD_INSECURE_LCG=1` (test only, **not secure**) |

## Platform security considerations

This library provides **cryptographic primitives**, not a complete hardware wallet. Running it on a generic microcontroller does **not** provide hardware wallet security guarantees.

| Platform | Signing isolation | Key storage | Threat model |
|----------|-------------------|-------------|--------------|
| Flipper Zero | Tactile confirmation (physical button + display) | Internal flash, no extraction API | Hardware wallet (with caveats) |
| Ledger / Trezor | Secure element + display confirmation | Secure enclave | Full hardware wallet |
| ESP32-S2 dev board | None — software only | Flash, extractable via JTAG | Development / prototyping **only** |
| STM32 bare metal | Depends on integration | Depends on MPU / TrustZone config | Varies |

A hardware wallet requires **at minimum**:
- Physical transaction confirmation (button + display)
- Key isolation (secure element or equivalent)
- Debug interface lockdown (JTAG / SWD disabled in production)
- Side-channel countermeasures beyond constant-time software

> **"Runs on ESP32" ≠ "hardware wallet threat model."** An ESP32-S2 dev board has no tactile signing isolation, no secure key storage, and an open debug interface. Use it for development and interoperability testing, not for protecting real funds.

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### Build options

CMake options:

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `ON` | Build test suite |
| `STACK_ANALYSIS` | `OFF` | Enable `-fstack-usage` for stack bound analysis (GCC only; see `scripts/check_stack.sh`) |

Compile-time macros (`include/options.h`, overridable via `CMAKE_C_FLAGS`):

| Macro | Default | Description |
|-------|---------|-------------|
| `USE_PLATFORM_RNG` | `1` | Expect platform-provided `random32()`/`random_buffer()` at link time (audit C-2). Setting it to `0` is refused at compile time unless `ZORCHARD_INSECURE_LCG=1` is also defined — the insecure LCG fallback is an explicit, test-only opt-in. |
| `PALLAS_POINT_MUL_WINDOW` | `4` | Window width `w` of `pallas_point_mul()`. The table of multiples takes `2^w` projective points of static RAM: 1728 B at `w = 4`, 864 B at `w = 3`, 432 B at `w = 2`. Smaller windows trade additions for RAM (`2·128/w` additions per multiplication); the doubling count and the constant-time behaviour are the same for every width. |

Example — test build against the deterministic LCG (never in production):

```bash
cmake .. -DCMAKE_C_FLAGS="-DUSE_PLATFORM_RNG=0 -DZORCHARD_INSECURE_LCG=1"
```

## Porting to your hardware

### 1. Implement `random32()` (required)

The library expects a platform hardware RNG by default (`USE_PLATFORM_RNG=1` in `options.h`): a build that does not provide `random32()`/`random_buffer()` fails at link time. A **non-cryptographic LCG fallback** exists for deterministic tests only, behind the explicit double opt-in `USE_PLATFORM_RNG=0` + `ZORCHARD_INSECURE_LCG=1` — the library refuses to compile against the LCG otherwise.

Provide your own implementations at link time:

```c
uint32_t random32(void);
void random_buffer(uint8_t *buf, size_t len);
```

**ESP32:**
```c
#include <esp_random.h>
uint32_t random32(void) { return esp_random(); }
void random_buffer(uint8_t *buf, size_t len) { esp_fill_random(buf, len); }
```

**STM32 (HAL):**
```c
#include "stm32f4xx_hal.h"
extern RNG_HandleTypeDef hrng;
uint32_t random32(void) {
    uint32_t val;
    HAL_RNG_GenerateRandomNumber(&hrng, &val);
    return val;
}
void random_buffer(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = random32();
        size_t n = (len - i < 4) ? len - i : 4;
        memcpy(buf + i, &r, n);
    }
}
```

**Flipper Zero:**
```c
#include <furi_hal_random.h>
uint32_t random32(void) { return furi_hal_random_get(); }
void random_buffer(uint8_t *buf, size_t len) { furi_hal_random_fill_buf(buf, len); }
```

### 2. Sinsemilla lookup table (optional, performance)

Sinsemilla hashing uses a table of 1024 elliptic-curve points (the S-table). There are **three strategies** for providing it, depending on your platform's memory and storage constraints:

#### Strategy A — Compute on-the-fly (no table, default)

Do nothing. If no lookup callback is registered, each point is computed via `pallas_group_hash()` at every Sinsemilla call. This requires **no extra RAM or storage** but every 10-bit chunk then costs a full hash-to-curve: a note commitment is about 30× slower than with the table (host benchmark, see [Performance](#performance)).

#### Strategy B — Embed in RAM via header (`sinsemilla_s.h`)

Include the precomputed compressed table directly in your firmware image. The header `src/sinsemilla_s.h` contains all 1024 points in compressed form (32 KB `static const` array). The points are stored as x-coordinate + parity bit and must be decompressed (y = sqrt(x³ + 5), fix parity) at lookup time.

```c
#include "sinsemilla_s.h"
#include "pallas.h"

bool sinsemilla_lookup_from_header(uint32_t index, uint8_t buf_out[64], void* ctx) {
    (void)ctx;
    // Decompress SINSEMILLA_S_COMPRESSED[index] into buf_out (x_le[32] || y_le[32])
    // ... (decompress x, compute y, write both into buf_out)
    return true;
}

pallas_set_sinsemilla_lookup(sinsemilla_lookup_from_header, NULL);
```

This uses ~32 KB of flash/ROM for the compressed table (or 64 KB if you store fully decompressed points in a `static const` array). Good for MCUs with enough flash but limited external storage.

#### Strategy C — Load binary from ROM / SD card (`sinsemilla_s.bin`)

Store the precomputed 64 KB binary (`src/sinsemilla_s.bin`) on external storage (SD card, SPI flash, etc.) and read entries on demand. Each entry is 64 bytes (x_le[32] || y_le[32], already decompressed), so entry `i` is at offset `i * 64`.

```c
#include "pallas.h"

bool sinsemilla_lookup_from_sd(uint32_t index, uint8_t buf_out[64], void* ctx) {
    // Read 64 bytes at offset (index * 64) from sinsemilla_s.bin on SD/flash
    return read_from_storage(index * 64, buf_out, 64);
}

pallas_set_sinsemilla_lookup(sinsemilla_lookup_from_sd, NULL);
```

This keeps the firmware image small and uses almost no RAM — only 64 bytes per lookup are read at a time. Ideal for platforms like Flipper Zero where an SD card is available.

#### Summary

| Strategy | RAM cost | Flash/storage cost | Speed | Best for |
|----------|----------|--------------------|-------|----------|
| A — Compute on-the-fly | 0 | 0 | Slow | Extremely constrained MCUs |
| B — Header in flash | 0 (const) | 32–64 KB flash | Fast | MCUs with enough flash |
| C — Binary from SD/ROM | 64 B | 64 KB external | Fast | Devices with external storage |

> **Table integrity (audit M-5):** any target that registers a lookup callback (strategies B/C) **must** call `pallas_verify_sinsemilla_table()` once at boot, before the first Sinsemilla operation. It checks a BLAKE2b digest over all 1024 entries (~10 ms on a 240 MHz core); a `false` return means the stored table was altered (supply-chain attack, fault injection, storage corruption) and the device must refuse to operate.

### 3. Platform callbacks (optional)

```c
// Progress reporting (e.g., update display during key derivation)
pallas_set_progress_cb(my_progress_handler, NULL);

// Yield callback (e.g., feed watchdog during long computations)
pallas_set_yield_cb(my_yield_handler, NULL);   // invoked every 256 field multiplications
```

## API overview

### Key derivation & addresses

```c
#include "orchard.h"

uint8_t sk[32], chain[32];
orchard_master_key(bip39_seed, sk, chain);
orchard_derive_account_sk(bip39_seed, 133, 0, sk); // mainnet, account 0

char ua[256];
int len = orchard_derive_unified_address(
    bip39_seed, 133, 0, "u", ua, sizeof(ua), NULL, NULL);
```

#### Default address conformance

The default address is the external address at diversifier index 0 of the account's full viewing key. The diversifier key is `dk = PRF^expand_rivk([0x82] ‖ ak ‖ nk)[..32]` (protocol spec §4.2.3), where `ak` is the spend validating key as encoded in the FVK — always with sign bit 0, because the spec negates `ask` when `[ask]·G` has an odd y. Releases up to a55d168 used the sign of the un-normalised point there, which changed `dk`, hence the default diversifier, for odd-y seeds. `ivk` (which only uses the x-coordinate), `ak`, `nk`, `rivk` and the signing path were always correct, so both the old and the new address belong to the same wallet.

To find out whether an upgrade changes the address a wallet has been showing:

```c
uint8_t d_new[11], pk_new[32], d_old[11], pk_old[32];
char ua_new[256], ua_old[256];
orchard_derive_unified_address(seed, coin, 0, hrp, ua_new, sizeof(ua_new), d_new, pk_new);
orchard_derive_unified_address_legacy(seed, coin, 0, hrp, ua_old, sizeof(ua_old), d_old, pk_old);
bool affected = strcmp(ua_new, ua_old) != 0;   // or compare ua_old with a stored address
```

Firmware that stored the address it displayed can equally compare the stored string with `ua_new`. An affected wallet should show the new address from now on (it is the one host wallets expect) and may keep listing `ua_old` as a previously used address; nothing needs to be moved. `tests/test_address_vectors.h` holds 16 seed/network vectors generated from `orchard` 0.16.0, seven of them odd-y, with both addresses.

### RedPallas signing (Orchard)

```c
#include "redpallas.h"

uint8_t sig[64], rk[32];
redpallas_sign(ask, alpha, sighash, sig, rk);
```

### Transparent keys

```c
#include "bip32.h"

// m/44'/coin_type'/0'/0/0 — the key other wallets derive from the same seed.
uint8_t sk[32], pubkey[33];
bip32_derive_transparent_sk(seed, 133 /* mainnet */, sk, pubkey);
```

That is all the library does with transparent keys. It does not sign with them: `secp256k1_ecdsa_sign_digest()` and `secp256k1_sig_to_der()` are compiled only with `-DZCASH_ENABLE_TRANSPARENT_SIGNING=1`, are not constant-time, and have no transparent signature hash to sign — see [Transparent inputs are not supported](#transparent-inputs-are-not-supported). The derivation itself is variable-time in the secret key.

### Hardware Wallet Protocol

```c
#include "hwp.h"

// Encode a frame
uint8_t buf[HWP_MAX_FRAME];
size_t n = hwp_encode(buf, seq, HWP_MSG_SIGN_REQ, payload, payload_len);

// Parse incoming bytes (1 byte at a time, suitable for UART IRQ)
HwpParser parser;
hwp_parser_init(&parser);
HwpFeedResult r = hwp_parser_feed(&parser, byte);
if (r == HWP_FEED_FRAME_READY) {
    // parser.frame contains the decoded frame
}
```

## Architecture

```
include/
  platform.h            — Compiler/platform abstraction (CLZ, packing, alignment)
  options.h             — Build-time feature flags
  orchard.h             — Key derivation, address generation, F4Jumble, NoteCommit + enc_ciphertext recomputation
  redpallas.h           — RedPallas spend authorization signing (Orchard)
  secp256k1.h           — secp256k1 public-key derivation (ECDSA signing compiled out by default)
  bip32.h               — BIP-32 transparent HD key derivation (HMAC-SHA512)
  pallas.h              — Pallas curve arithmetic, Sinsemilla hash
  hwp.h                 — Hardware Wallet Protocol, v6 wire tier only (serial framing, pool-tagged memo-carrying action payloads)
  hwp_dispatcher.h      — Device-side protocol driver (callback-based, target-agnostic)
  zip244.h              — ZIP-244 v6 (five-leaf, Ironwood) shielded sighash; transparent leaf for outputs only
  orchard_signer.h      — Signing context: sighash, cmx, ciphertext, on-device ownership classification, totals
  chacha20poly1305.h    — ChaCha20-Poly1305 AEAD (RFC 7539), used for on-device Orchard note encryption verification
  aead.h                — AES-256-CTR + HMAC-SHA256 AEAD + PIN KDF (used for PIN-sealed wallet storage)
  wallet_lockout.h      — PIN-failure lockout state machine (wipe threshold, serialize/deserialize)
  aes_ct.h              — Constant-time AES-256 (masked full-scan S-box; replaces the cache-timing-leaky T-table AES, audit H-3; pluggable HW-AES backend)
  base58.h              — Base58Check + transparent script_pubkey → t-address rendering
  bip39.h               — BIP39 mnemonic generation
  bignum.h              — 256-bit big number arithmetic
  blake2b.h             — BLAKE2b hash
  sha2.h                — SHA-256 / SHA-512
  hmac.h                — HMAC-SHA-256 / HMAC-SHA-512
  pbkdf2.h              — PBKDF2-HMAC-SHA-512
  rand.h                — RNG abstraction (pluggable backend)
  memzero.h             — Compiler-resistant secure memory wipe
  segwit_addr.h         — Bech32 / Bech32m encoding

src/
  aes/             — AES-256 (pure C, no hardware intrinsics)
  pallas_consts.h      — Fixed hash-to-curve outputs (Sinsemilla Q, commitment bases R, spend-auth base G); checked by pallas_verify_fixed_points()
  pallas_sqrt_table.h  — Square-root tables for the Pallas base field (generated by tools/gen_sqrt_table.py)
  pallas_fixed_base_table.h — Comb tables for pallas_point_mul_fixed(): spend-auth base G, NoteCommit and CommitIvk bases R (generated by tools/gen_fixed_base_table.py); checked by pallas_verify_fixed_points()
  sinsemilla_s.h   — Precomputed Sinsemilla S-table, compressed (32 KB static const, strategy B)
  sinsemilla_s.bin — Precomputed Sinsemilla S-table, decompressed (64 KB, strategy C)

tools/
  gen_test_vectors/     — Rust generator for the Orchard KAT corpus (vs librustzcash)
  gen_ironwood_vectors/ — Rust generator for the NU6.3 / Ironwood vectors
  gen_ztot_vector/      — Rust generator for tests/test_ztot_vector.h (a real shielded → transparent v6 transaction and its sighash from zcash_primitives 0.31 / pczt 0.10)
  gen_address_vectors/  — Rust generator for tests/test_address_vectors.h (default address, rivk_internal, both ivks, change address vs orchard 0.16.0, even- and odd-y seeds)
  gen_sqrt_table.py     — Generator for src/pallas_sqrt_table.h
  gen_fixed_base_table.py — Generator for src/pallas_fixed_base_table.h
  bench_pallas.c        — Host micro-benchmark for the Pallas hot path (built as tests/bench_pallas)

scripts/
  check_stack.sh   — Per-function stack bound analysis (with STACK_ANALYSIS=ON)
```

### Extension points

| Hook | How to use | Purpose |
|------|-----------|---------|
| `random32()` / `random_buffer()` | Link-time symbol | Hardware entropy source |
| `pallas_set_sinsemilla_lookup()` | Runtime callback | Fast Sinsemilla from storage |
| `pallas_set_progress_cb()` | Runtime callback | UI progress during key derivation |
| `pallas_set_yield_cb()` | Runtime callback | Watchdog / RTOS yield |

## On-Device Verification — what the host is, and is not, trusted for

The premise: **the companion app is hostile.** This section states what the device establishes for itself, what it leaves to the user, and what it does not check at all. It is deliberately not a claim that everything the host sends is verified or shown: several things are not, and they are listed.

What can be claimed:

- For every shielded output, recipient and value shown on the device are the ones committed in the action the device signs; the device recomputes the note commitment.
- Every output has its ciphertext and memo recomputed on-device — outputs with a non-zero value and zero-value padding alike; the compact body is refused.
- Whether an output is the wallet's change or own address is decided on-device from the device's keys; the wire protocol has no ownership hint.
- An own-classified output with value is decryptable with the wallet's incoming viewing key.
- The device computes fee and total leaving from data bound by the sighash it signs; the total is an upper bound on what the wallet loses, exact when all inputs are the wallet's.
- Sapling must be empty; the consensus branch must be in a compiled allow-list; a transaction with transparent inputs is refused.
- A signature is released only for the sighash the device computed after the review callbacks returned OK.

`orchard_signer.h` arranges these as a state machine. It is an API-ordering guard: through this API the signature comes after the checks and after the `confirm_*` calls, and a host cannot re-order or skip them by its choice of messages. It is not a defence against the firmware: the firmware holds `ask` and could call `confirm_action()` without showing anything, or `redpallas_sign()` directly. The library makes the safe path the default one; showing the screens is the firmware's job.

Which field of which message is hashed, recomputed, shown, forced or unbound is tabulated in [SECURITY.md](SECURITY.md#what-binds-each-host-supplied-field).

### What the device verifies itself

1. **The sighash.** The v6 (five-leaf, NU6.3/Ironwood) ZIP-244 signature hash is computed on the device:
   - `header_digest` from `TxMeta`. The header must be v6 (`0x80000006` / `0xD884B698`) and the consensus branch ID must be in the device's allow-list (`ORCHARD_SIGNER_ALLOWED_BRANCH_IDS`, default NU6.3 `0x37A5165B` and NU7 `0x77190AD9`) → `SIGNER_ERR_BRANCH_NOT_ALLOWED` otherwise. A network upgrade the firmware does not know needs a firmware update, by design. Lock time and expiry height are hashed here; they are not shown.
   - the transparent leaf, recomputed from the streamed transparent **outputs** (one transparent pass per session) and required to equal `TxMeta.transparent_sig_digest`; or required to be the empty-bundle constant if none were streamed. Transparent inputs do not exist for this library: with an empty `vin` the leaf is the ZIP 244 txid digest, which is what is computed.
   - `sapling_digest` required to be the empty-bundle constant (`SIGNER_ERR_SAPLING_NOT_EMPTY`): the wallet is Orchard/Ironwood-only.
   - `orchard_digest` / `ironwood_digest` from the streamed actions, routed by their pool tag, with the pool's flags and value balance from `TxMeta`; flag policy enforced (`enableCrossAddress` clear on sealed Orchard, no reserved bits). **A pool with no action contributes its empty-bundle constant, and then its flags and value balance in `TxMeta` are not hashed** — see item 5 for what the device does about that.
2. **Every note commitment.** For each action the device recomputes `cmx` from the note the host declares (`d`, `pk_d`, value, `rseed`, with ρ = the action's nullifier) and compares it with the action's `cmx` (`SIGNER_ERR_NOTE_COMMITMENT_MISMATCH`). After this, recipient and value are facts about the action being signed, not claims.

   ```
   g_d = DiversifyHash(d)
   rcm = ToScalar(PRF^expand(rseed, [0x05] || rho))                  // V2 (Orchard pool)
   rcm = ToScalar(PRF^expand(rseed, [0x0B] || repr_P(g_d) ||
                  repr_P(pk_d) || v_LE || rho || psi))               // V3 (Ironwood pool, ZIP-2005)
   psi = ToBase  (PRF^expand(rseed, [0x09] || rho))
   cmx = Extract_P(SinsemillaCommit("z.cash:Orchard-NoteCommit",
                   repr_P(g_d) || repr_P(pk_d) || I2LEBSP_64(v) || rho_lsb255 || psi_lsb255, rcm))
   ```
3. **The ciphertext of every output.** `enc_ciphertext` and `ephemeral_key` are recomputed from the declared note and memo (`esk` derived on-chip from `rseed` and ρ, never on the wire) and compared (`SIGNER_ERR_MEMO_MISMATCH`, `SIGNER_ERR_BAD_PK_D`). This is what binds the memo — and what shows that the recipient, or the wallet itself for its change, can decrypt the note.

   ```
   esk = ToScalar(PRF^expand(rseed, [0x04] || rho));  epk = [esk]·g_d;  ss = [esk]·pk_d
   K_enc = BLAKE2b("Zcash_OrchardKDF", repr_P(ss) || repr_P(epk))
   enc   = ChaCha20-Poly1305(K_enc, IV=0, leadByte || d || value_LE || rseed || memo)   // 0x02 Orchard, 0x03 Ironwood
   ```

   **There is no way to opt out.** The compact (no-memo) action body is refused for every output (`Error(MEMO_REQUIRED)`), zero-value padding included. Why own outputs: a change note with a ciphertext the wallet cannot decrypt still exists on chain, but only whoever kept its plaintext — the host that built it — can find it again. Why padding: a zero-value output is otherwise a 512-byte message to an address of the host's choosing that no screen shows.

   What this asks of an honest host: the memo of every output. For outputs it built it has it; the `orchard` crate's padding outputs carry 512 zero bytes (`tests/test_ztot_vector.h` is such a transaction, built by `zcash_primitives`, and passes); for any other output whose note (`rseed`) it knows, the memo is recoverable by decrypting `enc_ciphertext` with `esk` and `pk_d` (`zcash_note_encryption::try_output_recovery_with_pkd_esk`). A transaction containing an output whose ciphertext is not the ZIP 212 encryption of its note cannot be signed with this device.
4. **Who each output belongs to.** From the device's full viewing key, `feed_meta()` derives the two incoming viewing keys once per session (`ivk = Commit^ivk_rivk(ak, nk)`, and the ZIP 32 internal key with `rivk_internal = ToScalar(PRF^expand(rivk, [0x83] || ak || nk))`). Each output is then classified by `pk_d == [ivk]·DiversifyHash(d)`:

   | Classification | Meaning | What the UI must do |
   |---|---|---|
   | `ORCHARD_OUTPUT_OWN_INTERNAL` | the wallet's change | show "Change (your wallet)" and the value |
   | `ORCHARD_OUTPUT_OWN_EXTERNAL` | one of the wallet's own receiving addresses (any diversifier) | show "Your address" and the value |
   | `ORCHARD_OUTPUT_EXTERNAL` | anything else | show address and value as a payment leaving the wallet, and whether it has a memo |

   There is no host-supplied ownership hint, in the wire protocol or in the API. A host that sends the "change" to an address of its own gets it classified as an external payment and added to the amount leaving the wallet. Transparent outputs are always treated as external (the device does not recognise its own t-address).
5. **The totals.** `orchard_signer_get_totals()` computes, with overflow checks on every addition:

   ```
   fee           = value_balance(Orchard) + value_balance(Ironwood) − transparent_out
   total_leaving = Σ value(EXTERNAL shielded outputs) + Σ value(transparent outputs) + fee
   ```

   Every term is bound by the sighash the device signs. For the value balances that holds only for a pool that has actions, so **the value balance of a pool with no action must be zero** — otherwise `SIGNER_ERR_EMPTY_POOL_BALANCE`, checked when the last action arrives, when the totals are computed and again at `verify()`. (Until November 2026 it was added to the fee unconditionally: a host could declare `−(real fee − 0.0001 ZEC)` for an absent pool and have a 5 ZEC fee displayed as 0.0001.) A transaction with no action at all is refused (`SIGNER_ERR_NO_ACTIONS`).

   Own outputs are in neither sum; they enter only through `value_balance`, so change is never counted twice. Overflow or a negative fee aborts the session (`SIGNER_ERR_VALUE_OVERFLOW`, `SIGNER_ERR_FEE_OVERFLOW`, `SIGNER_ERR_FEE_NEGATIVE`).

   **`total_leaving` is an upper bound on what the wallet loses**, exact when every spent note is the wallet's. The device does not see the spend side. The value balance is bound by the sighash and, on chain, by the binding signature and the proof, so the transaction that can be mined is the one the numbers describe; but if the host funds part of it with notes that are not the wallet's, the wallet loses less than the screen says. It can never lose more.

### What the user must still do

Verification makes what is on the device's screen true of the transaction being signed. It cannot make it what the user wanted:

- **Read and approve every external recipient.** The device establishes that the address on its screen is where the funds go; it has no way to know whose address it is.
- **Read the memo** when there is one, if it matters (exchange deposit tags do) — and notice "Memo: none" when one was expected. The review data says explicitly whether an output has a memo (`OrchardOutputInfo.memo`, `HwpOutputReview.memo`); a firmware should show both cases.
- **Check "total leaving the wallet"** against what they meant to spend. It is the one number that catches a redirected change output, an inflated fee, or an extra output.

The state machine makes the corresponding *calls* a precondition of the signature: `verify()` returns `SIGNER_ERR_ACTION_NOT_CONFIRMED` unless `confirm_action()` was called for every output with a value or a memo, and `SIGNER_ERR_FEE_NOT_CONFIRMED` unless `confirm_totals()` was. With the bundled dispatcher those calls are made only after the firmware's `review_output` / `review_memo` / `review_totals` callbacks return `HWP_UI_OK`. Whether a callback actually put the data on a screen and waited for a button is the firmware's responsibility.

**Zero-value outputs.** Most transactions carry padding outputs: value 0, random address. They are not payments and are not presented as such: an output *verified* to have value 0 and an empty memo needs no confirmation and is only counted (`OrchardSignerTotals.n_zero_value`). A zero-value output that carries a memo is a message; it is shown, with its memo, and must be confirmed. "No memo" means exactly `0xF6` followed by 511 zero bytes, or 512 zero bytes — `0xF6` followed by anything else is shown. What remains hidden is therefore: the *address* of an output that carries neither value nor message (the host can make up to `MAX_ACTIONS − 1` of those, to any addresses; their holders learn that the transaction exists and nothing else), and its `out_ciphertext` (see below).

### What is NOT verified

| Item | Why | Consequence |
|---|---|---|
| The Halo 2 proof | the host is the prover; not re-verified on the MCU | a wrong proof gives a transaction the network rejects |
| The spend side: which notes are spent, their values, their nullifiers, whose they are | the device does not hold the note set or the commitment tree | the device cannot show "you are spending note X". The value balances are bound by the sighash and, on chain, by the binding signature and the proof; `total_leaving` is an upper bound on the wallet's loss (above) |
| Anchors | under the v6 format they are not in the effects digest the sighash covers; the device discards them on receipt | the signature is valid whatever anchor the host puts in the transaction. The proof is what ties the spends to an anchor, and the host makes the proof either way: nothing is lost that the host could not already do |
| `rk` against `ak` and `alpha` | `alpha` comes from the host in `SIGN_REQ`; the device signs with `ask + alpha` and does not compare the resulting `rk` with the `rk` field of any action | a wrong `alpha` gives a signature that verifies under no action of the transaction: the transaction is invalid. No value is at risk; the sighash signed is still the reviewed one |
| `cv_net`, `out_ciphertext` | hashed into the sighash, not interpreted | a wrong `out_ciphertext` means the sender cannot later recover the output with its outgoing viewing key; funds are not affected. A wrong `cv_net` fails the binding signature |
| Binding signature, other spend-authorization signatures | made by the host / not seen by the device | an invalid one gives a transaction the network rejects |
| Expiry height and lock time | bound by the sighash (header digest), **not shown** | the host decides for how long the signed transaction stays valid (expiry 0 = no expiry) and from when it can be mined; the user is not told. A signed transaction the host withholds can be broadcast later, up to its expiry |
| The network | nothing in a transaction or its sighash names it; mainnet and testnet share consensus branch IDs | see [Network](#network) |
| Transparent inputs | not supported | a transaction that has any is refused |
| That a transparent output is the wallet's own | no own-t-address detection | transparent change is displayed, and counted, as leaving |
| `SIGN_REQ.amount`, `.fee`, `.recipient` | ignored | nothing: they reach no screen and no decision |
| Timing between prompts, cancellation, denial of service | the host drives the session | it can refuse to build or broadcast |

Outside the library altogether: the device's own firmware and hardware. A device without a secure element stores keys in ordinary flash (see [Platform security considerations](#platform-security-considerations)); none of the above protects keys from someone with physical access to such a device, or from a malicious firmware. And the host necessarily knows the full viewing key (it is sent in `FVK_RSP` so the wallet can scan): **privacy** against the host is not a goal — it sees every address, amount and memo.

### Network

The device's network is a property of the device, set once by the firmware: `orchard_signer_init(ctx, coin_type)` with 133 (mainnet) or 1 (testnet), the same coin type the firmware derives its keys with. It survives every reset. Without it the signer does not start a session (`SIGNER_ERR_NETWORK_UNSET`).

What "network" can mean for a signature, precisely:

- **Keys.** ZIP 32 derivation includes the coin type, so a device set up for testnet holds different keys than the same seed on mainnet. This is what actually separates the networks: a testnet key authorises spends of notes sent to testnet-derived receivers only.
- **Display.** The address prefix (`u` / `utest`, `t1`/`t3` / `tm`/`t2`) on the device's screens follows the device's network.
- **The declared coin type.** Every `TxMeta` must carry the device's coin type; a different one, or none (the 166-byte layout), is refused with `SIGNER_ERR_NETWORK_MISMATCH` in every session. (Before, the check compared against a value taken from `FVK_REQ` and stored in session state, so it was skipped after any reset or PING.)
- **The sighash: nothing.** No field of a v6 transaction names the network, and mainnet and testnet use the same consensus branch IDs. The same bytes are a valid transaction on either chain if the notes exist there.

So the check stops a wallet application on one network from using a device set up for the other. It does not bind a hostile host, which declares whatever coin type passes. The residual case: an Orchard receiver is the same bytes on both networks, so somebody can encode a testnet wallet's receiver as a mainnet address and send mainnet funds to it; the host can then have the "testnet" device sign a mainnet spend of them while the device shows `utest…` addresses. A wallet that only ever receives on the network it was set up for is not exposed to this.

### Order of operations

```
init(coin_type)               once; the device's network
feed_meta(fvk, meta)          network, branch allow-list, v6 header, flags, sapling-empty, >= 1 action; derive ivk_external / ivk_internal
[transparent pass]            once; outputs only (P2PKH / P2SH); digest recomputed and matched against TxMeta
per action, in order:         cmx → ciphertext → classify → memo slot → hash → record; after the last: empty-pool rule
get_totals()                  only when every action is in and the transparent pass (if any) verified
confirm_action() × N          every output with a value or a memo
confirm_totals()
verify(sighash)               → SIGNER_VERIFIED
sign()
```

An action is recorded and hashed only if every step before it passed; any failure resets the context (which also wipes the session's viewing keys). There is one entry point for actions and it takes the memo, so no output reaches the sighash unverified or unclassified. Once the totals have been computed no action is accepted and the transparent pass cannot be re-opened.

The dispatcher adds the session rules:

- action and transparent-output frames must arrive with consecutive indices and the counts first announced;
- **every `Error` frame ends the session** — signer rejections, malformed frames, unknown message types, CRC and version errors, a wrong sighash in `SIGN_REQ`, a refusal by the user: the signer is reset before the frame is sent;
- **a `TxMeta` always starts a new transaction from nothing**, as do PING and ABORT: whatever was in progress or verified is dropped with its approvals;
- **at most one signature per action** of the approved transaction, each for the verified sighash; after the last one the session ends. A host that needs fewer (it signs dummy spends itself) simply stops asking;
- the final confirmation is asked again for every transaction.

### Putting it together

```c
#include "orchard_signer.h"
#include "orchard.h"

OrchardSignerCtx ctx;
orchard_signer_init(&ctx, ORCHARD_SIGNER_COIN_MAINNET);   // the coin type the keys were derived with

// 1. TxMeta (170 bytes, coin type included) + the device's OWN full viewing key (never one from the host).
OrchardSignerFvk fvk = { .ak = ak, .nk = nk, .rivk = rivk };
orchard_signer_feed_meta(&ctx, &fvk, meta_bytes, meta_len, num_actions);

// 2. (Optional) transparent OUTPUTS. A transaction with transparent inputs is refused.
if (n_t_out > 0) {
    orchard_signer_begin_transparent(&ctx, /* num_inputs = */ 0, n_t_out);
    for (size_t i = 0; i < n_t_out; i++) orchard_signer_feed_transparent_output(&ctx, t_out[i], len_out[i]);
    orchard_signer_verify_transparent(&ctx, expected_transparent_digest);
}

// 3. Per action, always with the memo.
for (size_t i = 0; i < num_actions; i++) {
    orchard_signer_feed_action_with_note_and_memo(
        &ctx, pool[i], action_bytes[i], 820,
        recipient_bytes[i], value[i], rseed[i], memo[i]);
}

// 4. Totals first (also proves the transaction is complete), then review.
OrchardSignerTotals totals;
orchard_signer_get_totals(&ctx, &totals);

// transparent outputs: orchard_signer_get_transparent_output_display() + script_to_taddr(); show as leaving

for (uint16_t i = 0; i < ctx.actions_received; i++) {
    OrchardOutputInfo out;
    orchard_signer_get_output(&ctx, i, &out);
    if (!out.review_required) continue;            // verified padding: counted in totals.n_zero_value

    char ua[200];
    orchard_encode_ua_raw(out.recipient, out.recipient + 11, "u", ua, sizeof(ua));
    switch (out.ownership) {
    case ORCHARD_OUTPUT_OWN_INTERNAL: /* "Change (your wallet)", out.value */      break;
    case ORCHARD_OUTPUT_OWN_EXTERNAL: /* "Your address", out.value */              break;
    case ORCHARD_OUTPUT_EXTERNAL:     /* payment: ua, out.value — user reads ua */ break;
    }
    if (out.memo == ORCHARD_MEMO_PRESENT) { /* orchard_signer_get_action_memo(&ctx, i, memo, &present); show it */ }
    else                                  { /* show "Memo: none" */ }
    // ... wait for the user's OK ...
    orchard_signer_confirm_action(&ctx, i);
}

// 5. Show totals.total_leaving and totals.fee, wait for OK.
orchard_signer_confirm_totals(&ctx);

// 6. Verify, then sign.
orchard_signer_verify(&ctx, expected_sighash);
orchard_signer_sign(&ctx, sighash, ask, alpha, sig, rk);
```

### Integrator migration (November 2026)

Two rounds of changes in November 2026. Both are made so that code written against the previous headers **does not compile** rather than keep the old behaviour. The first table is the ownership / totals round; the second is the round that followed the independent review (transparent inputs disabled, final screen, network, value-balance binding, compact body removed). A firmware coming from the October API needs both.

**Round 1 — ownership and totals**

| Before | Now |
|---|---|
| `orchard_signer_feed_meta(ctx, meta, len, n)` | `orchard_signer_feed_meta(ctx, const OrchardSignerFvk* fvk, meta, len, n)` — the device's own `ak`/`nk`/`rivk` |
| `orchard_signer_feed_action(ctx, pool, action, len)` | removed (hashed an action with no note: unverified, unclassified) |
| `orchard_signer_get_action_display(ctx, i, recipient, &value)` | `orchard_signer_get_output(ctx, i, OrchardOutputInfo* out)` — adds `ownership`, `review_required`, `has_memo` |
| `orchard_signer_get_fee(ctx, &fee)` | `orchard_signer_get_totals(ctx, OrchardSignerTotals* out)` — needs every action fed |
| `orchard_signer_confirm_fee(ctx)` | `orchard_signer_confirm_totals(ctx)` |
| `ui.review_output(idx, total, addr, value, ctx)` | `ui.review_output(const HwpOutputReview* out, ctx)` — `out->kind` is `HWP_OUTPUT_TRANSPARENT` / `_EXTERNAL` / `_OWN_CHANGE` / `_OWN_ADDRESS` |
| `ui.review_fee(fee, ctx)` (optional) | `ui.review_totals(const OrchardSignerTotals* t, ctx)` (**mandatory**) |
| `ui.review_memo` optional, memo silently not shown if `NULL` | may be `NULL`, but then a transaction with a memo is refused |

**Round 2 — after the review**

| Before | Now | Why |
|---|---|---|
| `orchard_signer_init(ctx)` | `orchard_signer_init(ctx, uint32_t coin_type)` — `ORCHARD_SIGNER_COIN_MAINNET` (133) or `ORCHARD_SIGNER_COIN_TESTNET` (1) | the network is a device property that survives resets; without it `feed_meta` returns `SIGNER_ERR_NETWORK_UNSET` |
| `ctx.coin_type` written by the firmware from `FVK_REQ` | do not write it; `orchard_signer_reset()` keeps it | — |
| `TxMeta` 166 or 170 bytes, coin type optional | 170 bytes with the device's coin type, else `SIGNER_ERR_NETWORK_MISMATCH` | the check used to be skippable |
| `feed_meta(..., total_actions = 0)` accepted | `SIGNER_ERR_NO_ACTIONS` | nothing to authorise |
| value balance of a pool without actions added to the fee | must be 0, else `SIGNER_ERR_EMPTY_POOL_BALANCE` (at the last action, at `get_totals`, at `verify`) | it is not bound by the sighash |
| `orchard_signer_feed_action_with_note(...)` (compact, zero-value only) | **removed**; every action goes through `orchard_signer_feed_action_with_note_and_memo(...)` | a zero-value compact output could carry an unshown message |
| `SIGNER_ERR_MEMO_REQUIRED`, `SIGNER_ERR_RECIPIENT_MISMATCH`, `SIGNER_ERR_TRANSPARENT_BAD_INPUT` | removed from the enum (values of later enumerators changed: do not persist them) | no longer produced |
| `orchard_signer_recipient_matches_any(ctx, r43)` | **removed**, no replacement | it matched hidden zero-value outputs and own change |
| `orchard_signer_begin_transparent(ctx, n_in, n_out)` with inputs | same signature; `n_in != 0` → `SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED` (session reset); `n_out > ORCHARD_SIGNER_MAX_T_OUTPUTS` → `SIGNER_ERR_TOO_MANY_ACTIONS` here, not at the ninth output | transparent inputs are not supported |
| `orchard_signer_feed_transparent_input(ctx, data, len)` hashed the input | always returns `SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED` and resets | same |
| `orchard_signer_feed_transparent_output`: any script ≤ 25 bytes | standard P2PKH / P2SH only, exact length; every error resets | every output must have an address to show |
| `zip244_hash_transparent_input()`, `zip244_transparent_per_input_sighash()` | **removed** | the latter returned the S.2 node, not a signature hash |
| `Zip244TransparentState` (five hashers, `t_in_total`, `inputs_received`) | one hasher, outputs only; `OrchardSignerCtx.transparent_inputs_expected` removed | — |
| `secp256k1_ecdsa_sign_digest()`, `secp256k1_sig_to_der()` | declared and compiled only with `-DZCASH_ENABLE_TRANSPARENT_SIGNING=1` (default 0) | variable-time, and nothing valid to sign |
| `secp256k1_get_public_key33()`, `bip32_derive_child()` (non-hardened), `bip32_derive_transparent_sk()` returned wrong keys | fixed (field-multiplication aliasing bug); **every transparent public key / address derived with an earlier revision is wrong** | see Known limitations |
| `HwpDispatcherKeys { ak, nk, rivk, ask, t_sk, t_pubkey }` | `{ ak, nk, rivk, ask }`; a NULL `ask` → `HWP_DISP_FATAL` at start | the dispatcher holds no transparent key |
| `ui.confirm_tx(const OrchardSignerTotals* t, const char* host_recipient, ctx)` | `ui.confirm_tx(const OrchardSignerTotals* t, ctx)` | no host-chosen string on the final screen |
| `HwpOutputReview { kind, index, total, address, value, has_memo }` | adds `HwpMemoStatus memo` (`HWP_MEMO_NONE` / `_PRESENT` / `_NOT_APPLICABLE`); `OrchardOutputInfo` adds `OrchardMemoStatus memo` | show "Memo: none" explicitly |
| `hwp_dispatcher_run()` with any `d.testnet` | returns `HWP_DISP_FATAL` unless `d.testnet` matches the signer's coin type | — |

Wire protocol (hosts):

| Before | Now |
|---|---|
| compact action body (904 B) accepted for zero-value outputs | `Error(MEMO_REQUIRED)` `0x14` for every output. Send 1416 B for all actions; for the builder's padding the memo is 512 zero bytes, or recover it with `try_output_recovery_with_pkd_esk` (esk from `rseed` and ρ) |
| `TxMeta` 166 B accepted | 170 B with the coin type, else `Error(NETWORK_MISMATCH)` |
| `TxMeta` with a non-zero value balance for a pool without actions | `Error(EMPTY_POOL_BALANCE)` `0x19` (new code). Flags and anchor of the absent pool are not read: send what the PCZT has |
| `TX_TRANSPARENT_INPUT` with inputs | `Error(TRANSPARENT_INPUTS_UNSUPPORTED)` `0x18` (new code). The frame is accepted only as the stream sentinel: index = total = 0 + the 32-byte digest |
| `TRANSPARENT_SIGN_REQ` → `TRANSPARENT_SIGN_RSP` (DER signature + pubkey) | always `Error(TRANSPARENT_INPUTS_UNSUPPORTED)`; no message carries a transparent public key any more (`FVK_RSP` never did) |
| a ninth transparent output → `Error(BAD_FRAME)` on the ninth frame | `Error(LIMIT_EXCEEDED)` on the first output frame, which announces the count |
| transparent outputs in any order | index must be the next one, total constant, else `Error(INVALID_STATE)` |
| `SIGN_REQ.recipient` had to be a `u…`/`utest…`/`t…` address of a reviewed output; empty → `Error(BAD_FRAME)`; mismatch → `Error(RECIPIENT_MISMATCH)` | `recipient`, `amount`, `fee` are ignored; `recipient_len` may be 0. `RECIPIENT_MISMATCH` `0x0E` is reserved and no longer sent |
| `SIGN_REQ` with a wrong sighash: error, session kept | error and the session ends (as after every `Error` frame) |
| second `TxMeta` while a transaction is in progress or verified → `Error(INVALID_STATE)` | starts the new transaction; the previous one and its approvals are gone |
| `FVK_REQ` coin type stored as the session's network | only compared with the device's network (mismatch → `Error(NETWORK_MISMATCH)`); 0 / empty → answered |

Earlier-round codes, unchanged: `HWP_ERR_BRANCH_NOT_ALLOWED` `0x15`, `HWP_ERR_LIMIT_EXCEEDED` `0x16`, `HWP_ERR_VALUE_OVERFLOW` `0x17`. A host that does not know a code sees "unknown" plus the message text.

Per firmware:

- **Dispatcher users (FlipZcash, the SDK's virtual device).**
  1. `orchard_signer_init(signer, testnet ? 1 : 133)`.
  2. Remove `d->keys.t_sk` / `d->keys.t_pubkey` and the code that derives them (`bip32_derive_transparent_sk` in FlipZcash `views/flipz_scene_1.c`): the transparent key must not be loaded for a signing session at all.
  3. `confirm_tx` loses its `host_recipient` parameter: show `totals->total_leaving`, `totals->fee` and, if useful, `totals->n_external` / `n_transparent_out` — nothing else.
  4. In `review_output`: title from `out->kind` ("Send to" / "Change (your wallet)" / "Your address"); for `HWP_OUTPUT_EXTERNAL` show "Memo: none" when `out->memo == HWP_MEMO_NONE`.
  5. `review_totals` (mandatory) shows `total_leaving` and `fee`.
  6. A headless test device needs `review_totals` and, for transactions with memos, `review_memo`.
- **Direct signer users (zcash-esp32, `main/main.c`).**
  1. `orchard_signer_init(&signer_ctx, coin_type)` once at boot with the device's configured network; delete the assignments to `signer_ctx.coin_type` in the `FVK_REQ` handler and the `coin_type ? … : default` fallbacks; refuse an `FVK_REQ` for the other network.
  2. Replace the `orchard_signer_feed_action_with_note` branch: only the 1416-byte body exists; answer 904 with `MEMO_REQUIRED`.
  3. Delete the `SIGN_REQ` recipient decoding and the `orchard_signer_recipient_matches_any` check; show the device totals on the final screen.
  4. Delete the transparent-input handler path (`orchard_signer_begin_transparent(.., total_inputs, 0)`, `orchard_signer_feed_transparent_input`) or let it forward to the library, which refuses; delete the whole `TRANSPARENT_SIGN_REQ` handler — `zip244_transparent_per_input_sighash`, `bip32_derive_transparent_sk`, `secp256k1_ecdsa_sign_digest` — and answer the message with `HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED`.
  5. Reset the signer on every error frame sent, on every new `TxMeta`, and give at most one signature per action, as the library dispatcher does (or switch to `hwp_dispatcher_run`).
- **Transparent addresses.** Neither FlipZcash nor zcash-esp32 shows a t-address or sends a transparent public key to the host today (FlipZcash derived `t_sk`/`t_pubkey` only to hand them to the dispatcher; zcash-esp32 only inside its `TRANSPARENT_SIGN_REQ` handler). Any transparent public key those code paths ever returned — in `TRANSPARENT_SIGN_RSP` — was wrong. A host that cached one, or built a UFVK / t-receiver from it, must discard it.
- **Hosts (zcash-hw-wallet-sdk).** Send the full body for every action including padding (see the table); treat `supports_transparent_inputs()` as false and stop sending `TRANSPARENT_SIGN_REQ`; `sign()` may leave the `SIGN_REQ` recipient empty; expect a session to be over after any `Error`.
- **RAM (Cortex-M4, FlipZcash tuning).** `sizeof(OrchardSignerCtx)` 5896 → 4928 bytes (four of the five transparent hashers are gone), `sizeof(HwpDispatcher)` 2176 → 2168. Library `.text`+`.rodata` 89 976 → 87 714 bytes, `.bss` 20 028 → 19 071 (`arm-none-eabi-gcc 12.3 -Os`).

## Device-side dispatcher (`hwp_dispatcher.h`)

The protocol code that drives the device side of an HWP session — drain CDC bytes, parse frames, dispatch by message type, reply with ACK/SignRsp/Error, keepalive, IDLE detection — is the same on every target. Reimplementing it once per device firmware (FlipZcash, zcash-esp32, future BOLOS) duplicates bugs and protocol drift. `hwp_dispatcher.h` factors that machinery into the library and exposes it as a single entry point driven by callbacks.

### API shape

```c
#include "hwp_dispatcher.h"

OrchardSignerCtx signer;
orchard_signer_init(&signer, is_testnet ? ORCHARD_SIGNER_COIN_TESTNET
                                        : ORCHARD_SIGNER_COIN_MAINNET);

HwpDispatcher d = {
    .io = {
        .serial_drain  = my_cdc_drain,     /* pull up to N bytes, non-blocking */
        .serial_send   = my_cdc_send,      /* block until queued/sent          */
        .get_tick_ms   = my_tick,
        .sleep_ms      = my_sleep,
        .should_exit   = my_should_exit,
    },
    .ui = {
        .review_output = my_review_screen, /* one output: kind, address, value */
        .review_memo   = my_memo_screen,   /* verified memo of that output     */
        .review_totals = my_totals_screen, /* total leaving the wallet + fee   */
        .confirm_tx    = my_confirm_tx,    /* final OK, device-computed totals */
        .network_error = my_net_err,
        .phase_update  = my_phase_cb,      /* persistent status footer         */
        .progress      = my_progress_cb,   /* mid-crypto % + label             */
    },
    .keys = { .ak = ak, .nk = nk, .rivk = rivk, .ask = ask },   /* no transparent key */
    .signer    = &signer,
    .testnet   = is_testnet,       /* must agree with the signer's coin type */
    .user_ctx  = my_app_context,
};

hwp_dispatcher_run(&d);   /* returns when should_exit() flips true; HWP_DISP_FATAL at once
                             if a mandatory callback or key is NULL, or the network disagrees */
```

The application supplies only target-specific glue:

| Concern | Owner |
|---|---|
| HWP framing, encode/decode | library (`hwp.h`) |
| Crypto, key derivation, signing | library (`redpallas.h`, `orchard.h`, `orchard_signer.h`) |
| ZIP-244 sighash recomputation | library (`zip244.h`, `orchard_signer.h`) |
| State machine + message dispatch | library (`hwp_dispatcher.h`) |
| PING/PONG keepalive, IDLE detection, drain back-pressure | library (`hwp_dispatcher.h`) |
| Per-output review + final confirm orchestration | library (`hwp_dispatcher.h`) |
| Address rendering (UA / t-addr), session and error rules | library (`hwp_dispatcher.h` + `base58.h` + `orchard.h`) |
| **USB CDC / UART primitives** | application |
| **Screen rendering + button input** | application |
| **Sealed-storage key load** | application |

A device firmware shrinks to ~50 lines of platform glue plus its UI scenes.

### What the review shows

After the host's sighash sentinel the dispatcher first computes the totals (which fails, before any prompt, if the transaction is incomplete or its sums overflow), then calls:

1. `review_output` for every **transparent output** (`HWP_OUTPUT_TRANSPARENT`, rendered as a t-address via `script_to_taddr`) — the real destination of a shielded → t-addr sweep;
2. `review_output` for every **shielded output with a value or a memo**, with the kind the device decided (`HWP_OUTPUT_EXTERNAL`, `HWP_OUTPUT_OWN_CHANGE`, `HWP_OUTPUT_OWN_ADDRESS`) and its memo status (`HWP_MEMO_NONE` / `HWP_MEMO_PRESENT`), followed by `review_memo` when it has a memo. Outputs verified to carry neither value nor memo are not sent to the UI;
3. `review_totals` with the device-computed `OrchardSignerTotals`.

`confirm_tx` at the first `SIGN_REQ` receives the same totals again, and nothing else. The recipient, amount and fee fields of `SIGN_REQ` are ignored: the final confirmation shows device-computed facts only. (An earlier revision passed the `SIGN_REQ` recipient string to this screen after matching it against *any* action of the transaction; a host could name a zero-value output that no screen had shown, or the wallet's own change address. Requiring the string to match a reviewed, leaving output would have made it redundant with the review; removing it removes the question.)

For transparent outputs, the device captures `(value, script_pubkey)` as each one streams in (at most `ORCHARD_SIGNER_MAX_T_OUTPUTS = 8`, refused with `LIMIT_EXCEEDED` when a larger count is announced; scripts other than standard P2PKH / P2SH are rejected at that point, so every transparent output hashed has an address to render).

### Protocol-layer fixes baked in

A handful of protocol bugs that were discovered in application-level re-implementations of the dispatcher are now fixed once, in the library:

- **IDLE-only IDLE_RESET** — multi-second Sinsemilla cmx recomputation can keep the worker out of the dispatch loop for >>1.5 s. Firing IDLE_RESET in that window flipped the device to `!connected`, restarting the 400 ms periodic PING. The host PONGed every one of them, queueing hundreds of PONGs in the CDC RX buffer, and the parser drain dropped the next legitimate frame (the host's subsequent action data). The dispatcher now skips IDLE_RESET while `signer.state != SIGNER_IDLE`.
- **Bounded carryover for multi-frame drains** — the parser callback used to early-return after `FRAME_READY`, silently dropping every byte that came in the same CDC chunk as the frame's tail. The dispatcher now stashes those bytes in a per-iteration carryover buffer (bounded by one CDC packet, 64 B) and replays them on the next loop iteration before pulling more from CDC.
- **Transparent-output stream** — the host sends the transparent outputs (shielded → t-addr) and closes the stream with a `TX_TRANSPARENT_INPUT` frame carrying index = total = 0 and the 32-byte digest; `orchard_signer_begin_transparent()` is invoked from the first output with `num_inputs = 0`.

These fixes apply to every device target that calls `hwp_dispatcher_run()`.

## Performance

The Pallas hot path — what the device spends its time on while verifying an action (cmx and `enc_ciphertext` recomputation) and signing — was reworked in October 2026. Results are bit-identical: the whole KAT corpus is unchanged.

| Operation (host, x86-64, `-O2`) | Before | After | Speed-up |
|---|---|---|---|
| `fp_mul` | 7.9 µs | 0.09 µs | ~85× |
| `fp_inv` | 2.56 ms | 1.7 µs | ~1500× |
| `fp_sqrt` | 9.56 ms | 34 µs | ~280× |
| `pallas_hash_to_curve` | 48.3 ms | 127 µs | ~380× |
| `pallas_point_mul` | 46.1 ms | 212 µs | ~215× |
| Sinsemilla, 1086-bit message (S table) | 72.8 ms | 212 µs | ~340× |
| `orchard_compute_cmx` (S table) | 223 ms | 455 µs | ~490× |
| `orchard_compute_cmx` (no table) | 5.64 s | 14.1 ms | ~400× |
| `orchard_compute_enc_ciphertext` | 152 ms | 482 µs | ~315× |
| **Per-action verification (cmx + enc)** | **375 ms** | **0.94 ms** | **~400×** |

Host figures are meaningful as ratios; absolute device timings depend on the core (reproduce with `tests/bench_pallas ../src/sinsemilla_s.bin` from the build directory). What changed:

- **Field multiplication** — the 522-step shift-compare-subtract reduction is replaced by folding with `2^254 ≡ -c (mod p)` (the Pasta primes are `2^254 + c` with a 126-bit `c`), plus a dedicated squaring and a small-constant multiply for the curve constant `3b`. Values stay in canonical form, so no caller or serialization changed.
- **Inversion** — Fermat exponentiation is replaced by the constant-time safegcd (Bernstein–Yang divsteps, adapted from libsecp256k1's `modinv32`).
- **Square root** — one exponentiation plus a 4-bit Pohlig–Hellman over the 2-Sylow subgroup with a 5 KB table, instead of three exponentiations and a Tonelli–Shanks loop over `S = 32`.
- **Scalar multiplication** — GLV split `k = k1 + k2·λ` (128 doublings instead of 256) with a constant-time fixed-window ladder; the endomorphism half reuses the same table.
- **Hash-to-curve** — one square-root attempt per SWU map doubles as the squareness test, one inversion instead of three, and `hash_to_field` reduces with two multiplications instead of 1024 shift steps.
- **No repeated work** — Sinsemilla `Q`, the commitment bases `R` and the spend-authorization base `G` are constants (`src/pallas_consts.h`, self-checked by `pallas_verify_fixed_points()`), and `g_d` is computed once per action instead of twice.
- **Sinsemilla** — each chunk is one doubling plus one mixed addition (`[2]acc + S`) instead of two general additions.

Cost: about 10 KB of flash (half of it tables) and 1.6 KB of static RAM on Cortex-M4; see `PALLAS_POINT_MUL_WINDOW` to trade the RAM back.

### Fixed-base multiplication (November 2026)

Signing and key derivation multiply almost only by bases that never change: the spend-authorization base `G` (three times per RedPallas signature, once for `ak`) and the commitment blinding bases `R` (`[rcm]·R` in every note commitment, `[rivk]·R` in `CommitIvk`). `pallas_point_mul_fixed()` serves them from a precomputed Lim-Lee comb table (4 teeth × 2 blocks: 32 doublings and 64 mixed additions, no GLV split, no table built at run time) instead of the general ladder. Outputs are bit-identical; the KAT corpus is unchanged.

| Operation (host, x86-64 i5-13500, GCC 16, `-O2`) | Before (a18827e) | After | Speed-up |
|---|---|---|---|
| `[k]·G`, fixed base (`redpallas_derive_ak`) | 207–214 µs | 102–105 µs | ~2.0× |
| `redpallas_sign` | 736–741 µs | 405–417 µs | ~1.8× |
| `orchard_compute_cmx` (S table) | 448–463 µs | 341–348 µs | ~1.3× |
| **Per-action verification (cmx + enc)** | **0.92–0.96 ms** | **0.81–0.84 ms** | **1.12–1.15×** |
| `orchard_derive_unified_address` | 1.18–1.21 ms | 0.95–0.98 ms | ~1.2× |

Ranges over repeated runs of `tests/bench_pallas` on an otherwise idle desktop (unpinned, so expect a few percent of spread); host figures, not device timings — nothing here has been timed on a Cortex-M4 or an ESP32-S2 yet. Variable-base multiplications (`[esk]·g_d`, `[esk]·pk_d`, `[ivk]·g_d`) still use `pallas_point_mul()` and are unchanged at ~212 µs, which is why per-action verification gains much less than signing.

Cost, measured on Cortex-M4 objects (`arm-none-eabi-gcc 12.3 -Os`, `pallas.o` + `redpallas.o` + `orchard.o`): +7.2 KB of code and read-only data (6.5 KB of it the three tables, 2160 B each) and −228 B of `.bss` (the per-caller copies of `G` are gone). Where that lands depends on the target:

- **Execute-in-place flash (ESP32-S2, bare-metal STM32)** — the tables stay in flash: +7.2 KB flash, −228 B RAM.
- **Flipper Zero `.fap`** — an external app is loaded into the heap as a whole, read-only data included, so the same 7.2 KB is RAM there: about +7 KB of heap, net of the 228 B saved.
- Integrators updating from a revision older than a18827e (FlipZcash and zcash-hw-wallet-sdk pin 94562b8 at the time of writing) take the October rework (about 10 KB, with the same caveat for `.fap`) and this change at once: about 17 KB of image.

`python3 tools/gen_fixed_base_table.py 4` regenerates the tables with four blocks (16 doublings instead of 32, about 12% faster per multiplication on the host, twice the table size); `1` halves the tables to 1080 B per base for 64 doublings.

Trading a per-base table for the doublings is what Zakura did for its verifier in `zakura-pasta-curves` `glv/fixed_base.rs` (`PreparedFixedBaseSum`, commit `9c9e9e02`, 2026-11-05: doubling-free signed 7-bit windows over GLV half-scalars, "about 76 KiB per base" per its source comment) and for value commitments in `zakura-orchard` (commit `3aeab211`: an embedded 22 KiB table of multiples of `V`). Both are variable-time and meant for public scalars. Only the idea is shared: the comb here is a different construction, sized for a microcontroller image and constant-time, because its scalars are `ask`, `rsk`, the signing nonce, `rivk` and `rcm`.

The GLV constants and the choice of techniques follow the Zakura engineering notes and `zakura-pasta-curves` ([zakura-core/common](https://github.com/zakura-core/common)). Zakura's fast paths are deliberately variable-time (public scalars: block validation, wallet scanning); here every one of them was re-derived in constant time, because the same code multiplies by spend-authorization keys.

### Ownership classification (November 2026)

Deciding on-device who each output belongs to costs two `Commit^ivk` per signing session and, per output, one variable-base multiplication `[ivk]·g_d` if the output is the wallet's change (the internal key is tried first) or two otherwise. `g_d` is not recomputed: it comes from the per-diversifier cache the note-commitment check has just filled.

| Operation (host, x86-64 i5-13500, GCC 16, `-O2`, S table) | Time |
|---|---|
| `orchard_derive_ivks` (once per session) | 0.41–0.43 ms |
| ownership check against one key | 0.21 ms |
| per output, before (cmx + enc) | 0.81–0.84 ms |
| per output, own change (cmx + enc + 1 check) | 1.02–1.03 ms (+26%) |
| per output, external (cmx + enc + 2 checks) | 1.21–1.23 ms (+50%) |
| zero-value padding (same path as an external output since the compact body was removed) | as the row above |

For the 8-action maximum of the FlipZcash build, all external with memos, that is about 10.3 ms on the host against 6.5 ms before (+58%). Verifying the ciphertext of padding outputs too (November 2026) adds one `enc` recomputation — about 0.45 ms on the host — per padding output. **All performance figures in this document are host (x86-64) figures and ratios; nothing here has been timed on a Cortex-M4 or an ESP32-S2.** The extra work is the same `pallas_point_mul()` the ciphertext check already runs twice per output, so on a device the verification of an output gets roughly 1.25–1.5× slower, whatever its absolute speed.

What timing tells an observer: each check is constant-time in the key, but an output that matches the internal key skips the second check, so the time per output reveals "change" versus "anything else". That is the classification the device then displays, and the host — which holds the full viewing key — can compute it itself.

Cost on Cortex-M4 (`arm-none-eabi-gcc 12.3 -Os`, FlipZcash tuning, whole library) when this was introduced: +1.9 KB of code and read-only data (0.4 KB of it error strings), `.bss` unchanged, `sizeof(OrchardSignerCtx)` 5832 → 5896 bytes. After the review round that removed transparent inputs: 4928 bytes, `sizeof(HwpDispatcher)` 2168.

## Known limitations

### Transparent inputs are not supported

**This library cannot spend from a transparent address, and refuses any transaction that does.** `orchard_signer_begin_transparent()` with a non-zero input count, any call to `orchard_signer_feed_transparent_input()`, any `TX_TRANSPARENT_INPUT` frame that announces an input and every `TRANSPARENT_SIGN_REQ` end the session with `SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED` / `Error(TRANSPARENT_INPUTS_UNSUPPORTED)`. Shielding (t → z) is therefore not possible with this device. Paying *to* a transparent address from shielded funds (z → t) is supported and tested against `zcash_primitives`.

The reason, plainly: the transparent-input code that existed until November 2026 did not work and was not safe, and it was disabled rather than repaired.

- The value ECDSA-signed for a transparent input was only the transparent node of the ZIP 244 digest tree (S.2), not the transaction's signature hash, and in the dispatcher three of its sub-digests had already been finalized and were zero. The signatures were invalid on chain and bound almost nothing of the transaction.
- The input data in the signing request was not compared with the inputs that had been streamed and reviewed.
- With transparent inputs present, the *shielded* signature hash was wrong too (the device used the txid form of the transparent leaf where ZIP 244 requires the signature form with amounts and scripts), so shielded signatures for such transactions were rejected by the network.
- `secp256k1_point_mul()` is variable-time in its scalar, and after one approved session the dispatcher answered any number of signing requests with no confirmation — a timing oracle on the ECDSA nonce, observed by the USB host, which is the adversary.
- Independently of all that, the secp256k1 field multiplication had an aliasing bug (`sfp_mul(r, a, b)` computed `a·a` when `r == b`), so every public key other than 1·G — and with it every BIP-32 non-hardened child, every transparent key and every signature — was wrong. That is fixed and covered by known-answer tests (`tests/test_secp256k1.c`); **any transparent public key or t-address obtained from an earlier revision of this library is not the one the seed's standard BIP-44 key controls.**

What is left in the tree: transparent *key derivation* (`bip32.h`, `secp256k1_get_public_key33()`), now correct but variable-time in the secret key; and the ECDSA signing code, compiled only with `-DZCASH_ENABLE_TRANSPARENT_SIGNING=1` (default 0) and called by nothing. `HwpDispatcherKeys` has no field for a transparent key. Since the device cannot spend from its transparent address, a firmware should not offer that address for receiving.

What a proper implementation would need:

1. the S.2 form of the transparent leaf (hash type, prevouts, amounts, scripts, sequences, outputs, per-input data) in the *shielded* signature hash whenever `vin` is non-empty;
2. for each input, the full root signature hash with that input's `txin_sig_digest`, not the S.2 node alone;
3. the input being signed identified by index and bound to the input that was streamed at that index (prevout, value, script, sequence), with nothing taken from the signing request;
4. input values and scripts shown or otherwise accounted for in the totals (they enter the fee);
5. exactly one signature per input, released only after the final confirmation, in the same `VERIFIED` session as the shielded signatures;
6. a constant-time scalar multiplication (complete addition formulas, one final inversion) and constant-time handling of the nonce and the low-S / range checks;
7. test vectors from `zcash_primitives` for t → z, z → t with transparent change, and mixed transactions.

### Other

- **secp256k1 public-key derivation is not constant-time.** `secp256k1_point_mul()` swaps its two ladder registers under a mask, but it converts to affine — a full field inversion — at every bit, and its point routines return early on the point at infinity and branch on `h == 0`, so the running time depends on the leading zero bits of the secret key. Do not treat a transparent key derived on the device as protected against a timing observer. The Orchard/Ironwood path (Pallas, RedPallas) does not share this code.
- **`total_leaving` is an upper bound**, not always the exact loss: the spend side (which notes, their values, whose they are) is not verified by the device. See [On-Device Verification](#on-device-verification--what-the-host-is-and-is-not-trusted-for).
- **Expiry height and lock time are not shown**; `rk` is not checked against `ak` and `alpha`; anchors are not bound by the signature; the network is not part of what is signed. Each is described with its consequence under [What is NOT verified](#what-is-not-verified) and [Network](#network).
- **Zero-value outputs with an empty memo are not shown**, so the addresses they go to are not reviewed. They are verified to carry no value and no message.
- **Performance numbers are host numbers.** No figure in this document was measured on a device.
- **The review guard is an API-ordering guard.** A firmware that does not show the screens, or that calls the signing primitive directly, is outside what the library can prevent.

- **Single-threaded** — global callback state in Pallas operations is not thread-safe (typical for embedded single-core MCUs; use a mutex wrapper if needed on multi-core platforms)
- **No transaction builder** — by design: this library handles key management and signing; transaction construction belongs on the companion host application
- **Sinsemilla performance** — without the precomputed table every chunk is a hash-to-curve, about 30× slower per note commitment (register `pallas_set_sinsemilla_lookup()` to accelerate)
- **F4Jumble input limit** — capped at 256 bytes (sufficient for Unified Addresses; override `F4JUMBLE_MAX_INPUT` if needed)

## Security hardening

- **Constant-time fixed-base multiplication** — `pallas_point_mul_fixed()` (spend-authorization base `G`, commitment bases `R`) is a comb over a precomputed table: digit bits are gathered at positions fixed by the loop counters, the entry is picked by a masked scan of all 15 table entries, and the zero digit runs the same mixed addition on a dummy entry whose result is discarded by a masked select. An unknown base id yields the point at infinity
- **Select masks behind a value barrier** — the masks of the hot conditional selects (`fp_cond_sub_p`, the GLV scalar reduction, the comb's zero-digit select) pass through a `volatile` object, because clang otherwise turns `(a & ~m) | (b & m)` back into a branch or a secret-dependent load address. How this was checked, and its limits, are in [SECURITY.md](SECURITY.md#how-the-constant-time-property-was-checked)
- **Constant-time scalar multiplication** — `pallas_point_mul()` splits the scalar with the GLV endomorphism and runs a fixed-window ladder: table entries are picked by a masked scan of the whole table, signs by masked select, and the exception-free RCB formulas absorb the zero digit, so neither branches nor memory accesses depend on the scalar. `secp256k1_point_mul()` (transparent key derivation only) is **not** constant-time despite its masked swap (see [Known limitations](#known-limitations))
- **Constant-time base-field arithmetic** — `fp_mul()` / `fp_sqr()` reduce by folding with `2^254 ≡ -c (mod p)` in straight-line code, `fp_add()` / `fp_sub()` / `fp_neg()` use masked corrections, and `fp_inv()` is the constant-time safegcd (fixed 600 divsteps) — no operand-dependent branch or loop count anywhere in the field layer (closes audit M-3)
- **Constant-time modular reduction** — `fq_full_reduce()` uses fixed-iteration conditional subtraction via `bn_cmov()`; no variable-length while loops
- **Constant-time field multiplication** — `fq_mul()` uses `bn_cmov()` for conditional add; no branching on secret bits
- **Constant-time nonce handling** — nonce == 0 check uses `bn_cmov()` instead of `if` branch
- **Session viewing keys do not outlive the session** — the two incoming viewing keys live in `OrchardSignerCtx` from `feed_meta()` to `orchard_signer_reset()`, which wipes the whole context (keeping only the device's network) and is called by the library on every rejected input and by the dispatcher before every `Error` frame, on a new `TxMeta`, PING and ABORT, after the last signature, and when it returns
- **Static scratch is wiped, on the tested paths** — `static` buffers that hold key-derived data are wiped before their function returns; `tests/test_residue.c` runs a seal → derive → sign → verify sequence, including signer and dispatcher sessions that succeed and that abort, with two different sets of secrets and fails if any byte of `.data`/`.bss` differs afterwards. That is evidence for the paths the test executes, not a proof for every path; what it covers, what it does not, and the deliberate exceptions are in [SECURITY.md](SECURITY.md#secret-material-lifecycle)
- **Secret cleanup** — intermediate scalars, points, and key material are explicitly zeroed via `memzero()` after use (including hash states, intermediate bignums, and point structures); the stack is best effort (see SECURITY.md)
- **Embedded-safe memory layout** — large cryptographic intermediates use `static` storage (BSS) to stay within 4 KB stack constraints (e.g. Flipper Zero); all are explicitly wiped after each operation
- **`ct_memequal()`** — constant-time memory comparison utility available for application use
- **`memzero()`** — uses `SecureZeroMemory` / `memset_s` / `explicit_bzero` / volatile fallback depending on platform; resists compiler dead-store elimination
- The default RNG is **not cryptographically secure**. Always provide a hardware entropy source in production (`USE_PLATFORM_RNG=1`).

## License

MIT — see [LICENSE](LICENSE).

Includes code derived from [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto) (MIT, Copyright 2013 Tomas Dzetkulic, Pavol Rusnak).
