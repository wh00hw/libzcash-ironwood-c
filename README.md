# libzcash-ironwood-c

> Formerly `libzcash-orchard-c` — renamed after the NU6.3 / Ironwood migration. The CMake project and library target keep the name `zcash-orchard-c` for build compatibility.

> **WARNING — Proof of Concept.** This library has **not** been audited. It is published for review and experimentation only. **Do not use it to protect real funds** until an independent security audit has been completed. Use at your own risk.

Pure C11 library for Zcash Orchard/Ironwood + Transparent transactions on embedded hardware wallets.

**NU6.3 / Ironwood ready:** implements the v6 transaction sighash (five-leaf ZIP-244 tree with the Ironwood pool digest, `ZTxIdOrchardH_v6` / `ZTxIdIronwd_H_v6` personalizations, anchors moved to the authorizing-data commitment), ZIP-2005 V3 note plaintexts (lead byte `0x03`, quantum-recoverable rcm bound to all note fields), pool-tagged action streaming, and the sealed-Orchard flag policy (cross-address bit enforced clear post-NU6.3). All cross-validated against `orchard` 0.15.0-pre.2 in `tests/test_ironwood.c`.

Implements key derivation, address generation, RedPallas signing, ECDSA transparent signing, and a binary serial protocol (HWP) for host-device communication. Zero external dependencies — all cryptographic primitives are self-contained. No dynamic memory allocation, no OS calls, no hardware-specific code in the core.

## Features

- **ZIP-32 key derivation** — master key from BIP39 seed, hardened child derivation (`m_Orchard / 32' / coin_type' / account'`)
- **BIP-32 transparent key derivation** — `m / 44' / coin_type' / 0' / 0 / 0` for secp256k1 transparent spending keys
- **Orchard Unified Addresses** — full derivation with F4Jumble (ZIP-316) and Bech32m encoding
- **Pallas / RedPallas** — curve arithmetic, Sinsemilla hash, spend authorization signing
- **secp256k1 / ECDSA** — curve arithmetic (constant-time Montgomery ladder), ECDSA signing with RFC 6979 deterministic nonce, DER encoding. No precomputed tables. ~600 bytes stack peak.
- **ZIP-244 sighash verification** — on-device computation of the full v5 shielded sighash (header, orchard actions digest with compact/memos/noncompact sub-hashes) AND transparent per-input sighash (prevouts, amounts, scripts, sequences, outputs, txin_sig digests)
- **Transparent digest verification** — device independently computes the transparent txid digest from raw inputs/outputs, preventing a compromised companion from forging the transparent digest
- **Sapling-component lockout** — Orchard-only invariant: `sapling_digest` enforced equal to the ZIP-244 empty-bundle constant on `TxMeta` receipt; any non-empty Sapling bundle aborts the session before action streaming
- **NoteCommitment (cmx) recomputation** — for every Orchard action, the device recomputes `cmx = Extract_P(NoteCommit(g_d, pk_d, v, ρ, ψ))` from the unencrypted note plaintext (recipient, value, rseed) the companion claims, and rejects the action if the recomputed cmx does not match the cmx field in the encrypted action bytes — closes the recipient-substitution attack a hostile companion would otherwise mount inside the Orchard bundle
- **`enc_ciphertext` recomputation (memo binding)** — cmx binds value and recipient but is silent about the 512-byte memo. For every Orchard action the device additionally recomputes `enc_ciphertext = ChaCha20-Poly1305(K_enc, IV=0, leadByte ‖ d ‖ value_LE ‖ rseed ‖ memo)` with `K_enc = BLAKE2b("Zcash_OrchardKDF", repr_P([esk]·pk_d) ‖ repr_P(epk))` and `esk = ToScalar(PRF^expand(rseed, [0x04] ‖ ρ))` derived on-chip (ZIP-212), and constant-time-compares it byte-for-byte against the action's `enc_ciphertext` and `ephemeral_key` fields. The lead byte is `0x02` for Orchard-pool (V2, ZIP-212) notes and `0x03` for Ironwood-pool (V3, ZIP-2005) notes. Closes the memo-substitution attack where a hostile companion would show "invoice #123" on its UI while embedding any arbitrary memo on chain. Sent via the HWP v5/v6 payload (memo + note plaintext, esk derived on-device).
- **Per-action user confirmation invariant** — `orchard_signer_verify()` refuses to advance to `SIGNER_VERIFIED` unless every captured action has been explicitly confirmed via `orchard_signer_confirm_action()`. Combined with the existing `sign()` precondition (`state == VERIFIED`), this enforces "no blind signing" at library level: a hostile firmware that skips the per-output user-confirmation UI cannot extract a signature
- **On-device memo rendering** — verified memos are captured in a per-context memo pool (`ORCHARD_SIGNER_MAX_MEMOS` slots of 512 B; empty ZIP-302 memos, lead byte `0xF6`, consume no slot) and exposed via `orchard_signer_get_action_memo()`. The dispatcher's optional `review_memo` UI callback shows each non-empty memo on the trusted screen right after its recipient/value review, closing the divergence between what the companion UI claims the memo says and what actually goes on chain
- **Miner-fee confirmation invariant** — the same no-blind-signing rule extended to the fee itself. The device computes `fee = transparent_in − transparent_out + value_balance` on-chip (with overflow + negative detection), exposes it via `orchard_signer_get_fee()`, and refuses to advance `verify()` until the user has approved it through `orchard_signer_confirm_fee()`. Without this, a hostile companion that inflates `value_balance` could silently siphon the surplus to miners while showing a small fee on its untrusted UI.
- **Unified Address encoding from arbitrary recipients** — `orchard_encode_ua_raw(d, pk_d, hrp)` produces the canonical ZIP-316 Bech32m string for an Orchard payment address that is *not* the device's own — needed to render the recipient of every output to the user before they confirm
- **Signing context** (`orchard_signer.h`) — library-level state machine that composes all of the above: a signature is only producible after sapling-empty + per-action cmx + per-action enc_ciphertext + per-action user confirmation + per-tx fee confirmation + sighash match all pass
- **Hardware Wallet Protocol v2/v3/v4/v5/v6** — framed binary serial protocol with CRC-16, incremental sighash verification, transparent digest verification, transparent ECDSA signing, and memo-verifying action payloads. The wire version byte stays `0x02`; v3–v6 are feature tiers discriminated by payload size and `TxMeta` layout. v5 action payload: 1415 B = action ‖ recipient ‖ value ‖ rseed ‖ memo (esk never on the wire). v6 (NU6.3/Ironwood) prepends a 1-byte pool tag (`0x00` sealed Orchard, `0x01` Ironwood): 1416 B full / 904 B compact; v6 sessions are recognised by the 166/170-byte `TxMeta` layout. `HWP_MAX_PAYLOAD` defaults to 2048 (compile-time overridable, minimum 1420). Compatible with [zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk) (Rust); v4 payloads (903 B, cmx-only) still accepted for backward compatibility when memo recovery is not available on the host side.
- **Target-agnostic protocol dispatcher** (`hwp_dispatcher.h`) — the entire device-side state machine (drain → parse → switch → reply, PING/PONG keepalive, IDLE detection, multi-frame drain handling, per-output review orchestration, recipient binding) is contained in the library and exposed through a callback-based API. A new device target wires up six I/O callbacks (`serial_drain`, `serial_send`, `get_tick_ms`, `sleep_ms`, `should_exit`, plus UI callbacks for review/confirm) and gets the full protocol implementation for free. The same code runs on FlipZcash, the virtual-device test fixture, and future ESP32 / BOLOS ports — fix once, benefit everywhere.
- **Transparent t-address rendering on-device** (`base58.h`) — `script_to_taddr()` decodes a P2PKH or P2SH `script_pubkey` to the corresponding Zcash t-address string (mainnet `t1`/`t3`, testnet `tm`/`t2`) via Base58Check encoding. Lets the device display the actual destination of a transparent output (e.g. on a shielded → t-addr sweep) instead of only the change Orchard receivers, extending the no-blind-signing invariant to transparent recipients.
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
| Linux / macOS (testing) | Works | Uses LCG fallback (test only, **not secure**) |

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

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `ON` | Build test suite |
| `USE_PLATFORM_RNG` | `0` | Expect platform-provided `random32()`/`random_buffer()` at link time |

Override at compile time:

```bash
cmake .. -DCMAKE_C_FLAGS="-DUSE_PLATFORM_RNG=1"
```

## Porting to your hardware

### 1. Implement `random32()` (required)

The library ships with a **non-cryptographic LCG fallback** for testing. You **must** replace it with your platform's hardware RNG for production use.

Define `USE_PLATFORM_RNG=1` and provide your own implementations at link time:

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

Do nothing. If no lookup callback is registered, each point is computed via `pallas_group_hash()` at every Sinsemilla call. This requires **no extra RAM or storage** but is slow (~seconds on Cortex-M4 @ 64 MHz per address derivation).

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

### 3. Platform callbacks (optional)

```c
// Progress reporting (e.g., update display during key derivation)
pallas_set_progress_cb(my_progress_handler, NULL);

// Yield callback (e.g., feed watchdog during long computations)
pallas_set_yield_cb(my_yield_handler, NULL);
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

### RedPallas signing (Orchard)

```c
#include "redpallas.h"

uint8_t sig[64], rk[32];
redpallas_sign(ask, alpha, sighash, sig, rk);
```

### ECDSA signing (Transparent)

```c
#include "secp256k1.h"
#include "bip32.h"

// Derive transparent spending key from BIP-39 seed
uint8_t sk[32], pubkey[33];
bip32_derive_transparent_sk(seed, 133 /* mainnet */, sk, pubkey);

// Sign a 32-byte digest (e.g., per-input transparent sighash)
uint8_t compact_sig[64];
secp256k1_ecdsa_sign_digest(sk, digest, compact_sig);

// DER encode for on-chain use
uint8_t der[72];
size_t der_len = secp256k1_sig_to_der(compact_sig, der);
```

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
  secp256k1.h           — secp256k1 curve + ECDSA signing + RFC 6979 (Transparent)
  bip32.h               — BIP-32 transparent HD key derivation (HMAC-SHA512)
  pallas.h              — Pallas curve arithmetic, Sinsemilla hash
  hwp.h                 — Hardware Wallet Protocol v2–v6 (serial framing, memo-verifying + pool-tagged action payloads)
  hwp_dispatcher.h      — Device-side protocol driver (callback-based, target-agnostic)
  zip244.h              — ZIP-244 v5 (four-leaf) + v6 (five-leaf, Ironwood) sighash (shielded + transparent per-input)
  orchard_signer.h      — Signing context with mandatory sighash + cmx + memo + fee verification
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
  segwit_addr.h         — Bech32 / Bech32m encoding

src/
  aes/             — AES-256 (pure C, no hardware intrinsics)
  sinsemilla_s.bin — Precomputed Sinsemilla S-table (64 KB)
```

### Extension points

| Hook | How to use | Purpose |
|------|-----------|---------|
| `random32()` / `random_buffer()` | Link-time symbol | Hardware entropy source |
| `pallas_set_sinsemilla_lookup()` | Runtime callback | Fast Sinsemilla from storage |
| `pallas_set_progress_cb()` | Runtime callback | UI progress during key derivation |
| `pallas_set_yield_cb()` | Runtime callback | Watchdog / RTOS yield |

## On-Device Verification — five composed invariants

`orchard_signer.h` enforces five checkpoints, in order, before any RedPallas signature is produced. Each is a library-level state-machine invariant: a hostile firmware cannot extract a signature by skipping any of them, and no component of the ZIP-244 sighash or of any output note is taken on faith from the companion.

### 1. ZIP-244 sighash recomputed on-device

For every component of the v5 (four-leaf) or v6 (five-leaf, NU6.3/Ironwood) shielded sighash:

- **header_digest** — recomputed on-device from `TxMeta` via `zip244_header_digest`
- **transparent_sig_digest** — when the transaction has transparent inputs/outputs, the companion streams them via `TxTransparentInput` / `TxTransparentOutput` (HWP v3), the device recomputes the digest from those bytes, and `orchard_signer_verify_transparent()` constant-time compares the recomputation against the value in `TxMeta`. For transparent signing the device also produces the per-input sighash on-device (`amounts_digest`, `scripts_digest`, `txin_sig_digest`) and signs with ECDSA secp256k1.
- **sapling_digest** — *Orchard-only invariant*: the wallet derives no Sapling keys, holds no Sapling notes, and does not send to Sapling-only recipients. `orchard_signer_feed_meta()` enforces `sapling_digest == BLAKE2b-256("ZTxIdSaplingHash", [])` (the ZIP-244 empty-bundle constant, exposed as `zip244_sapling_empty_digest`). Any non-empty value aborts the session with `SIGNER_ERR_SAPLING_NOT_EMPTY` before action streaming begins. Without this, a hostile companion could siphon value via a Sapling output the device never sees in the Orchard stream.
- **orchard_digest / ironwood_digest** — recomputed from streamed action data via three parallel BLAKE2b digesters (compact / memos / non-compact) per pool. Under v6 each streamed action carries a pool tag routing it to the sealed-Orchard or Ironwood digester (`ZTxIdOrchardH_v6` / `ZTxIdIronwd_H_v6` personalizations, action-level `ZTxIdIrnAct*H_v6`); anchors are no longer hashed in the effects digest (moved to the authorizing-data commitment). `feed_meta` additionally enforces the v6 header constants (`tx_version 0x80000006`, `version_group_id 0xD884B698`) and the sealed-Orchard flag policy: the Orchard bundle's `enableCrossAddress` bit (bit 2) must be clear post-NU6.3, and no reserved flag bits may be set in either pool → `SIGNER_ERR_BAD_META` otherwise.

`orchard_signer_verify()` recomputes the full sighash from the four (v5) or five (v6) leaves and constant-time compares against the value the companion sent. Mismatch → `SIGNER_ERR_SIGHASH_MISMATCH`, session aborted.

### 2. NoteCommitment (cmx) recomputed per action

Hashing the encrypted action stream is not enough by itself: the cmx field of an action is opaque to the hashing path, so a hostile companion could put a cmx that commits to `(attacker_address, value)` while telling the device's UI "send to <Mario>". Defence: the device recomputes the cmx from the unencrypted note plaintext the companion declares, and rejects the action if the recomputation does not match the cmx in the action bytes.

`orchard_signer_feed_action_with_note(ctx, pool, action, recipient, value, rseed)` computes:

```
g_d = DiversifyHash(d)
rcm = ToScalar(PRF^expand(rseed, [0x05] || rho))                  // V2 (Orchard pool)
rcm = ToScalar(PRF^expand(rseed, [0x0B] || repr_P(g_d) ||
               repr_P(pk_d) || v_LE || rho || psi))               // V3 (Ironwood pool, ZIP-2005:
                                                                  //  quantum-recoverable rcm bound
                                                                  //  to all note fields)
psi = ToBase  (PRF^expand(rseed, [0x09] || rho))
cmx_computed = Extract_P(SinsemillaCommit("z.cash:Orchard-NoteCommit",
                          repr_P(g_d) || repr_P(pk_d) || I2LEBSP_64(v) ||
                          rho_lsb255 || psi_lsb255,
                          rcm))
```

with `rho` taken from the action's nullifier field (Orchard's split-action design) and constant-time-compares `cmx_computed` against the cmx field at offset 96 of the action bytes. Mismatch → `SIGNER_ERR_NOTE_COMMITMENT_MISMATCH`, context reset, no further action data hashed. Closes recipient substitution; an attacker would have to break Sinsemilla.

### 3. Output `enc_ciphertext` recomputed per action (memo binding)

cmx recomputation closes recipient + value substitution, but the cmx domain does not cover the memo bytes: a host that has been forced through cmx-recomputation can still embed any 512-byte memo plaintext inside `enc_ciphertext` while showing the user something different on its untrusted UI. The recipient sees the attacker's memo on chain.

`orchard_signer_feed_action_with_note_and_memo(ctx, pool, action, recipient, value, rseed, memo)` therefore additionally recomputes the 580-byte AEAD ciphertext from the unencrypted note plaintext:

```
g_d          = DiversifyHash(d)
esk          = ToScalar(PRF^expand(rseed, [0x04] || rho))     // ZIP-212
epk          = [esk] · g_d
SharedSecret = [esk] · pk_d
K_enc        = BLAKE2b("Zcash_OrchardKDF", repr_P(ss) || repr_P(epk))
np           = leadByte || d || value_LE || rseed || memo         // 564 B
enc_computed = ChaCha20-Poly1305(K_enc, IV=0, np)                 // 580 B
```

with `leadByte = 0x02` (Orchard pool, V2) or `0x03` (Ironwood pool, V3 / ZIP-2005) selected by the action's pool tag; the same `Zcash_OrchardKDF` personalization is used for both pools. It then constant-time compares both `enc_computed` (against the action's `enc_ciphertext` at offset 160) and `repr_P(epk)` (against the action's `ephemeral_key` at offset 128). Mismatch → `SIGNER_ERR_MEMO_MISMATCH`, context reset.

`esk` is **not** carried on the wire. The device re-derives it on-chip from `rseed` (already needed for cmx) + the action's nullifier (= ρ) so the companion has one fewer field to lie about. Equivalent for `pk_d`-decoding failures → `SIGNER_ERR_BAD_PK_D`.

Closes memo substitution; an attacker would have to break ChaCha20-Poly1305 against a per-output key.

### 4. Per-action user confirmation (no blind signing)

cmx recomputation guarantees the cmx commits to *what the companion told the device*. For the user not to be signing blindly, the device must also display recipient + value to the user and the user must explicitly approve. The library lifts that requirement from a firmware convention to a state-machine invariant:

- `feed_action_with_note()` captures `(recipient, value, confirmed=false)` at index `actions_received` in `actions_display[]` (capped at `ORCHARD_SIGNER_MAX_ACTIONS`, default 16); the memo-verifying variant additionally stores each non-empty verified memo in the memo pool (`ORCHARD_SIGNER_MAX_MEMOS` slots), readable via `orchard_signer_get_action_memo(ctx, idx, memo_out, &present)`
- The firmware reads the captured info via `orchard_signer_get_action_display(ctx, idx, recipient_out, value_out)`, encodes the recipient as a Unified Address via `orchard_encode_ua_raw(d, pk_d, hrp)`, displays it on the device UI together with the value (and the verified memo, if any), and on user OK calls `orchard_signer_confirm_action(ctx, idx)` to set the confirm flag
- `orchard_signer_verify()` scans `actions_display[0 .. actions_received)` and returns `SIGNER_ERR_ACTION_NOT_CONFIRMED` if any entry has `confirmed == false`. Only after every action is confirmed does the context transition to `SIGNER_VERIFIED`.
- `orchard_signer_sign()` already refuses unless `state == SIGNER_VERIFIED`. So a firmware that skipped the confirmation UI gets `NOT_VERIFIED` and no signature.

### 5. Per-transaction fee confirmation (no blind signing for the miner fee)

The same invariant extended to the miner-fee number. cmx + enc_ciphertext recomputation + per-action confirmation make sure the user sees every output the transaction creates; but the *fee* (= value that leaves the wallet but does not appear in any output) is determined by `value_balance`, which is a `TxMeta` field. A host that inflates `value_balance` could silently overspend, siphoning the surplus to miners while displaying a small fee on its own UI.

The device computes the fee on-chip from already-collected data:

```
fee = transparent_in_total − transparent_out_total + value_balance
```

with overflow detection at every accumulation step (per-input / per-output sums tracked in `Zip244TransparentState`) and an i64 overflow / negative-fee check on the final combine. The firmware reads the value via `orchard_signer_get_fee()`, renders it on the trusted screen, and only after explicit user OK calls `orchard_signer_confirm_fee()`. `orchard_signer_verify()` returns `SIGNER_ERR_FEE_NOT_CONFIRMED` if confirmation is skipped, `SIGNER_ERR_FEE_OVERFLOW` on arithmetic overflow, and `SIGNER_ERR_FEE_NEGATIVE` if the bundle is unbalanced.

The HWP dispatcher drives this automatically after the per-output review (`ui.review_fee` if the firmware provides it, otherwise a backward-compat fallback to `ui.review_output` with `addr_str = "Network fee"`).

### Putting it together

```c
#include "orchard_signer.h"
#include "orchard.h"

OrchardSignerCtx ctx;
orchard_signer_init(&ctx);

// 1. TxMeta: feed_meta enforces sapling-empty + bounds the action count.
//    Wire size selects the tier: 125/129 B = v5, 166/170 B = v6 (Ironwood);
//    on v6 it also enforces the header constants + pool flag policy.
orchard_signer_feed_meta(&ctx, meta_bytes, meta_len, num_actions);

// 2. (Optional) Transparent flow — per-input / per-output digest + value sums
//    used both for transparent_sig_digest and for the on-device fee math.
if (has_transparent) {
    orchard_signer_begin_transparent(&ctx, n_t_in, n_t_out);
    for (size_t i = 0; i < n_t_in;  i++) orchard_signer_feed_transparent_input (&ctx, t_in [i], len_in [i]);
    for (size_t i = 0; i < n_t_out; i++) orchard_signer_feed_transparent_output(&ctx, t_out[i], len_out[i]);
    orchard_signer_verify_transparent(&ctx, expected_transparent_digest);
}

// 3. Per-action: cmx + enc_ciphertext + epk are all recomputed and matched;
//    recipient/value (+ memo) are captured for the UI. The pool argument is
//    ZIP244_POOL_ORCHARD or ZIP244_POOL_IRONWOOD (from the v6 pool tag;
//    v5 sessions always pass ZIP244_POOL_ORCHARD).
for (size_t i = 0; i < num_actions; i++) {
    orchard_signer_feed_action_with_note_and_memo(
        &ctx, pool[i], action_bytes[i], 820,
        recipient_bytes[i], value[i], rseed[i], memo[i]);
    // (legacy v4 callers can keep using feed_action_with_note — cmx only)
}

// 4. Per-output user confirmation — driven by the firmware UI
for (uint16_t i = 0; i < ctx.actions_received; i++) {
    uint8_t recipient[43];
    uint64_t value;
    orchard_signer_get_action_display(&ctx, i, recipient, &value);

    char ua[200];
    orchard_encode_ua_raw(recipient, recipient + 11, "u", ua, sizeof(ua));

    uint8_t memo[512]; bool memo_present;
    orchard_signer_get_action_memo(&ctx, i, memo, &memo_present);
    // Display ua + value (+ memo if present) to the user, wait for OK ...
    orchard_signer_confirm_action(&ctx, i);
}

// 5. Fee review — compute on-chip, show on the trusted screen, confirm.
uint64_t fee_zats;
orchard_signer_get_fee(&ctx, &fee_zats);
// Display fee_zats to the user, wait for OK ...
orchard_signer_confirm_fee(&ctx);

// 6. Verify: refuses if any invariant failed
orchard_signer_verify(&ctx, expected_sighash);
//   SIGNER_ERR_SAPLING_NOT_EMPTY        — caught at feed_meta
//   SIGNER_ERR_BAD_POOL                 — caught at feed_action* (bad pool tag)
//   SIGNER_ERR_NOTE_COMMITMENT_MISMATCH — caught at feed_action_with_note*
//   SIGNER_ERR_MEMO_MISMATCH            — caught at feed_action_with_note_and_memo
//   SIGNER_ERR_BAD_PK_D                 — caught at feed_action_with_note_and_memo
//   SIGNER_ERR_ACTION_NOT_CONFIRMED     — caught here if any output not confirmed
//   SIGNER_ERR_FEE_NOT_CONFIRMED        — caught here if fee not confirmed
//   SIGNER_ERR_FEE_OVERFLOW / _NEGATIVE — caught at get_fee on hostile values
//   SIGNER_ERR_SIGHASH_MISMATCH         — caught here on bad sighash

// 7. Sign — refuses with NOT_VERIFIED unless verify() advanced state
orchard_signer_sign(&ctx, sighash, ask, alpha, sig, rk);
```

### What the device sees vs. what it signs

| Component | Source | Verified on device? |
|---|---|---|
| `header_digest` | `TxMeta` fields | ✅ recomputed |
| `transparent_sig_digest` | streamed inputs/outputs | ✅ recomputed (or empty-bundle constant) |
| `sapling_digest` | `TxMeta` field | ✅ enforced equal to empty-bundle constant |
| `orchard_digest` / `ironwood_digest` (v6) | streamed (pool-tagged) action data | ✅ recomputed per pool |
| v6 header constants + pool flag bytes | `TxMeta` fields | ✅ enforced (`enableCrossAddress` clear on sealed Orchard, no reserved bits) |
| Per-action `cmx` | streamed action bytes | ✅ recomputed via Sinsemilla from declared note plaintext |
| Per-action `enc_ciphertext` (incl. **memo**) | streamed action bytes | ✅ recomputed via Pallas ECDH + Orchard KDF + ChaCha20-Poly1305 |
| Per-action `ephemeral_key` (epk) | streamed action bytes | ✅ recomputed as `[esk]·g_d` |
| Per-action `esk` | derived on-device | ✅ never on the wire (ZIP-212: `ToScalar(PRF^expand(rseed, [0x04]‖ρ))`) |
| Per-action recipient (UA) + value + memo | streamed note plaintext | ✅ shown to user; sign refuses unless every output explicitly confirmed |
| Per-tx miner fee | computed on-device from `t_in − t_out + value_balance` | ✅ shown to user; sign refuses unless fee explicitly confirmed |
| Anchor, nullifier provenance | streamed action bytes | ❌ no on-MCU recompute; constrained by Halo2 proof soundness |
| Halo2 proof | companion (prover role) | ❌ not re-verified on-device; a wrong proof produces a tx the network rejects, not one that pays an attacker |

The only thing the device trusts the companion for is the Halo2 proof itself — and a wrong proof produces a transaction the network rejects, not one that pays an attacker.

## Device-side dispatcher (`hwp_dispatcher.h`)

The protocol code that drives the device side of an HWP session — drain CDC bytes, parse frames, dispatch by message type, reply with ACK/SignRsp/Error, keepalive, IDLE detection — is the same on every target. Reimplementing it once per device firmware (FlipZcash, zcash-esp32, future BOLOS) duplicates bugs and protocol drift. `hwp_dispatcher.h` factors that machinery into the library and exposes it as a single entry point driven by callbacks.

### API shape

```c
#include "hwp_dispatcher.h"

OrchardSignerCtx signer;
orchard_signer_init(&signer);

HwpDispatcher d = {
    .io = {
        .serial_drain  = my_cdc_drain,     /* pull up to N bytes, non-blocking */
        .serial_send   = my_cdc_send,      /* block until queued/sent          */
        .get_tick_ms   = my_tick,
        .sleep_ms      = my_sleep,
        .should_exit   = my_should_exit,
    },
    .ui = {
        .review_output = my_review_screen, /* per-output recipient + value     */
        .review_memo   = my_memo_screen,   /* optional: verified memo review   */
        .review_fee    = my_fee_screen,    /* optional: on-chip fee review     */
        .confirm_tx    = my_confirm_tx,    /* final amount/fee/recipient OK    */
        .network_error = my_net_err,
        .phase_update  = my_phase_cb,      /* persistent status footer         */
        .progress      = my_progress_cb,   /* mid-crypto % + label             */
    },
    .keys = { .ak = ak, .nk = nk, .rivk = rivk,
               .ask = ask, .t_sk = t_sk, .t_pubkey = t_pubkey },
    .signer    = &signer,
    .testnet   = is_testnet,
    .user_ctx  = my_app_context,
};

hwp_dispatcher_run(&d);   /* returns when should_exit() flips true */
```

The application supplies only target-specific glue:

| Concern | Owner |
|---|---|
| HWP framing, encode/decode | library (`hwp.h`) |
| Crypto, key derivation, signing | library (`redpallas.h`, `secp256k1.h`, `orchard_signer.h`) |
| ZIP-244 sighash recomputation | library (`zip244.h`, `orchard_signer.h`) |
| State machine + message dispatch | library (`hwp_dispatcher.h`) |
| PING/PONG keepalive, IDLE detection, drain back-pressure | library (`hwp_dispatcher.h`) |
| Per-output review + final confirm orchestration | library (`hwp_dispatcher.h`) |
| Recipient binding (UA / t-addr) | library (`hwp_dispatcher.h` + `base58.h` + `orchard.h`) |
| **USB CDC / UART primitives** | application |
| **Screen rendering + button input** | application |
| **Sealed-storage key load** | application |

A device firmware shrinks to ~50 lines of platform glue plus its UI scenes.

### Per-output review covers both classes of recipient

The dispatcher's review loop iterates **both** transparent outputs (rendered as base58check t-addresses via `script_to_taddr`) and Orchard actions (rendered as Bech32m UAs via `orchard_encode_ua_raw`), in that order. Without this, a shielded → t-addr sweep would have the user confirm only the change Orchard receivers (which point back to their own wallet) while the actual destination — the transparent output — would never appear on the trusted screen.

For each Orchard action, after the recipient/value screen the dispatcher also shows the **verified memo** through the optional `review_memo` callback (skipped for empty ZIP-302 memos, lead byte `0xF6`, and when the callback is `NULL`). The memo shown is the one the device itself verified against `enc_ciphertext`, so the companion cannot show one memo in its UI and commit another on chain. The fee review then follows via `review_fee` (or the `review_output` fallback with `addr_str = "Network fee"`).

For transparent outputs, the device captures `(value, script_pubkey)` for each output as it streams in (`feed_transparent_output()` adds the entry to `OrchardSignerCtx.t_outputs_display[]`, bounded by `ORCHARD_SIGNER_MAX_T_OUTPUTS = 8`; non-standard or oversized scripts are rejected at this point, preserving the invariant that every output the device signs is renderable on-screen).

### Protocol-layer fixes baked in

A handful of protocol bugs that were discovered in application-level re-implementations of the dispatcher are now fixed once, in the library:

- **IDLE-only IDLE_RESET** — multi-second Sinsemilla cmx recomputation can keep the worker out of the dispatch loop for >>1.5 s. Firing IDLE_RESET in that window flipped the device to `!connected`, restarting the 400 ms periodic PING. The host PONGed every one of them, queueing hundreds of PONGs in the CDC RX buffer, and the parser drain dropped the next legitimate frame (the host's subsequent action data). The dispatcher now skips IDLE_RESET while `signer.state != SIGNER_IDLE`.
- **Bounded carryover for multi-frame drains** — the parser callback used to early-return after `FRAME_READY`, silently dropping every byte that came in the same CDC chunk as the frame's tail. The dispatcher now stashes those bytes in a per-iteration carryover buffer (bounded by one CDC packet, 64 B) and replays them on the next loop iteration before pulling more from CDC.
- **Transparent-output-only bootstrap** — if the host sends a pure transparent-output stream (shielded → t-addr sweep, zero transparent inputs), `orchard_signer_begin_transparent()` is now invoked from the output handler with `num_inputs=0`; previously the state machine remained in `RECEIVING_ACTIONS` and rejected the first output.
- **t-address network detection** — the SIGN_REQ recipient check now recognises every Zcash transparent-address prefix (`t1` / `t3` mainnet, `tm` / `t2` testnet) in addition to the shielded UA prefixes (`u` / `utest`). Previously a transparent recipient triggered a false `NETWORK_MISMATCH` error.

These fixes apply to every device target that calls `hwp_dispatcher_run()`.

## Known limitations

- **Single-threaded** — global callback state in Pallas operations is not thread-safe (typical for embedded single-core MCUs; use a mutex wrapper if needed on multi-core platforms)
- **No transaction builder** — by design: this library handles key management and signing; transaction construction belongs on the companion host application
- **Sinsemilla performance** — without precomputed table, address generation takes several seconds on Cortex-M4 @ 64 MHz (register `pallas_set_sinsemilla_lookup()` to accelerate)
- **F4Jumble input limit** — capped at 256 bytes (sufficient for Unified Addresses; override `F4JUMBLE_MAX_INPUT` if needed)

## Security hardening

- **Constant-time scalar multiplication** — Montgomery ladder in `pallas_point_mul()` and `secp256k1_point_mul()` with XOR-masked conditional swap; no branching on secret scalar bits
- **Constant-time modular reduction** — `fq_full_reduce()` uses fixed-iteration conditional subtraction via `bn_cmov()`; no variable-length while loops
- **Constant-time field multiplication** — `fq_mul()` uses `bn_cmov()` for conditional add; no branching on secret bits
- **Constant-time nonce handling** — nonce == 0 check uses `bn_cmov()` instead of `if` branch
- **Full secret cleanup** — all intermediate scalars, points, and key material are explicitly zeroed via `memzero()` after use (including hash states, intermediate bignums, and point structures)
- **Embedded-safe memory layout** — large cryptographic intermediates use `static` storage (BSS) to stay within 4 KB stack constraints (e.g. Flipper Zero); all are explicitly wiped after each operation
- **`ct_memequal()`** — constant-time memory comparison utility available for application use
- **`memzero()`** — uses `SecureZeroMemory` / `memset_s` / `explicit_bzero` / volatile fallback depending on platform; resists compiler dead-store elimination
- The default RNG is **not cryptographically secure**. Always provide a hardware entropy source in production (`USE_PLATFORM_RNG=1`).

## License

MIT — see [LICENSE](LICENSE).

Includes code derived from [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto) (MIT, Copyright 2013 Tomas Dzetkulic, Pavol Rusnak).
