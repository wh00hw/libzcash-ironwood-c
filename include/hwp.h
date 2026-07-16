/**
 * Hardware Wallet Protocol (HWP) v2 — Binary framed serial protocol.
 *
 * Frame: [MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]
 *
 * Compatible with zcash-hw-wallet-sdk (Rust).
 * Supports staged transaction verification: outputs are sent individually
 * and hashed incrementally on-device to verify sighash integrity before signing.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define HWP_MAGIC         0xFB
#define HWP_VERSION       0x02

#define HWP_HEADER_SIZE   6
#define HWP_CRC_SIZE      2
// Default generously sized above the largest protocol payload: the v6
// memo-verifying action (pool tag 1 + action 820 + recipient 43 + value 8 +
// rseed 32 + memo 512 = 1416 bytes) plus the 4-byte TX_OUTPUT header = 1420.
//
// RAM-constrained targets may override with a compile definition — the value
// sizes the RX frame buffer embedded in HwpDispatcher — as long as it stays
// >= 1420 (the protocol's real maximum) and is applied uniformly to every
// translation unit (struct layout!). FlipZcash builds with
// HWP_MAX_PAYLOAD=1536 to fit the Flipper's FAP loader budget.
#ifndef HWP_MAX_PAYLOAD
#define HWP_MAX_PAYLOAD   2048
#endif
_Static_assert(HWP_MAX_PAYLOAD >= 1420,
               "HWP_MAX_PAYLOAD must fit the v6 memo-verifying action payload (1420 bytes)");
#define HWP_MAX_FRAME     (HWP_HEADER_SIZE + HWP_MAX_PAYLOAD + HWP_CRC_SIZE)

// Action data size per TxOutput message (v2 sighash verification):
// cv_net(32) + nullifier(32) + rk(32) + cmx(32) + ephemeral_key(32) + enc_ciphertext(580) + out_ciphertext(80)
#define HWP_ACTION_DATA_SIZE 820

// Note plaintext appended to action data for on-device cmx verification (v4):
// recipient(43) + value(8 LE) + rseed(32) = 83 bytes
// Required so the device can recompute the action's NoteCommitment and reject
// recipient-substitution attacks. Total TX_OUTPUT action payload = 820 + 83 = 903.
#define HWP_NOTE_PLAINTEXT_SIZE  83
#define HWP_ACTION_DATA_SIZE_V4  (HWP_ACTION_DATA_SIZE + HWP_NOTE_PLAINTEXT_SIZE)

// Full note plaintext for v5 (memo-verifying) protocol:
// recipient(43) + value(8) + rseed(32) + memo(512) = 595 bytes
// Total TX_OUTPUT action payload for v5 = 820 + 595 = 1415 bytes.
//
// The device uses recipient/value/rseed/memo to recompute the action's
// `enc_ciphertext` byte-for-byte; mismatch aborts the session. Closes the
// memo-substitution attack that v4 (cmx-only) leaves open.
//
// `esk` is NOT on the wire: per ZIP-212 it is a deterministic function
// of rseed + rho (= action's nullifier), so the device derives it on-chip
// from the same inputs the companion already supplies. Keeping esk off
// the wire removes one trust-from-companion vector.
#define HWP_NOTE_PLAINTEXT_V5_SIZE  (HWP_NOTE_PLAINTEXT_SIZE + 512)
#define HWP_ACTION_DATA_SIZE_V5  (HWP_ACTION_DATA_SIZE + HWP_NOTE_PLAINTEXT_V5_SIZE)

// v6 (NU6.3 / Ironwood) action payloads: a 1-byte pool tag (0x00 = sealed
// Orchard pool, 0x01 = Ironwood pool) prefixed to the v4 or v5 payload.
// The dispatcher strips the tag and routes the action into the matching
// ZIP-244 pool digest tree; the remaining bytes reuse the v4/v5 layouts.
//   memo-verifying: 1 + 1415 = 1416 bytes
//   cmx-only:       1 + 903  = 904 bytes
// v6 sessions are recognized by the TxMeta layout (170/166 bytes, with the
// Ironwood bundle section); v5 sessions carry no pool tag.
#define HWP_POOL_TAG_SIZE 1
#define HWP_ACTION_DATA_SIZE_V6         (HWP_POOL_TAG_SIZE + HWP_ACTION_DATA_SIZE_V5)
#define HWP_ACTION_DATA_SIZE_V6_COMPACT (HWP_POOL_TAG_SIZE + HWP_ACTION_DATA_SIZE_V4)

// TxOutput special indices for v2 sighash verification protocol:
// 0xFFFF = transaction metadata (header + orchard bundle info, 61 bytes)
// 0..N-1 = action data (820 bytes each)
// N      = sentinel (expected 32-byte sighash for comparison)
#define HWP_TX_META_INDEX 0xFFFF

// --- Message types (matches zcash-hw-signer-sdk MsgType) ---
typedef enum {
    HWP_MSG_PING         = 0x01, // Keepalive / flow control
    HWP_MSG_PONG         = 0x02, // Keepalive response
    HWP_MSG_FVK_REQ      = 0x03, // Request full viewing key
    HWP_MSG_FVK_RSP      = 0x04, // FVK response: ak[32]||nk[32]||rivk[32] = 96 bytes
    HWP_MSG_SIGN_REQ     = 0x05, // Sign request (see payload format below)
    HWP_MSG_SIGN_RSP     = 0x06, // Signature response: sig[64]||rk[32] = 96 bytes
    HWP_MSG_ERROR        = 0x07, // Error: error_code[1]||message[N]
    HWP_MSG_TX_OUTPUT     = 0x08, // Individual tx output for incremental hashing (v2)
    HWP_MSG_TX_OUTPUT_ACK = 0x09, // Output hash acknowledged (v2)
    HWP_MSG_ABORT        = 0x0A, // Cancel signing session
    HWP_MSG_TX_TRANSPARENT_INPUT  = 0x0B, // Transparent input for digest verification (v3)
    HWP_MSG_TX_TRANSPARENT_OUTPUT = 0x0C, // Transparent output for digest verification (v3)
    HWP_MSG_TRANSPARENT_SIGN_REQ  = 0x0D, // Sign transparent input (ECDSA secp256k1, v3)
    HWP_MSG_TRANSPARENT_SIGN_RSP  = 0x0E, // Transparent signature response (v3)
    /* --- Device attestation (v4, audit M1) --- */
    HWP_MSG_IDENTITY_REQ = 0x0F, // Request device identity pubkey (no payload)
    HWP_MSG_IDENTITY_RSP = 0x10, // Identity response: device_pubkey[32]
    HWP_MSG_ATTEST_REQ   = 0x11, // Attestation request: challenge[32]
    HWP_MSG_ATTEST_RSP   = 0x12, // Attestation response: sig[64] || rk[32]
} HwpMsgType;

// --- Error codes (matches zcash-hw-signer-sdk ErrorCode) ---
typedef enum {
    HWP_ERR_UNKNOWN           = 0x00,
    HWP_ERR_BAD_FRAME         = 0x01, // CRC or format error
    HWP_ERR_BAD_SIGHASH       = 0x02, // Invalid sighash
    HWP_ERR_BAD_ALPHA         = 0x03, // Invalid alpha randomizer
    HWP_ERR_BAD_AMOUNT        = 0x04, // Invalid amount encoding
    HWP_ERR_NETWORK_MISMATCH  = 0x05, // Device on different network
    HWP_ERR_USER_CANCELLED    = 0x06, // User rejected on device
    HWP_ERR_SIGN_FAILED       = 0x07, // Signing operation failed
    HWP_ERR_UNSUPPORTED_VER   = 0x08, // Protocol version not supported
    HWP_ERR_SIGHASH_MISMATCH  = 0x09, // Device sighash != companion sighash (v2)
    HWP_ERR_INVALID_STATE     = 0x0A, // Unexpected message in current state (v2)
    HWP_ERR_TRANSPARENT_DIGEST_MISMATCH = 0x0B, // Transparent digest mismatch (v3)
    HWP_ERR_SAPLING_NOT_EMPTY           = 0x0C, // sapling_digest != empty-bundle
                                                // constant (Orchard-only invariant)
    HWP_ERR_NOTE_COMMITMENT_MISMATCH    = 0x0D, // Recomputed cmx != action.cmx
                                                // (recipient-substitution attempt)
    HWP_ERR_RECIPIENT_MISMATCH          = 0x0E, // SIGN_REQ.recipient (UA) does
                                                // not match any confirmed action
    HWP_ERR_MEMO_MISMATCH               = 0x0F, // Device-recomputed enc_ciphertext
                                                // (or epk) does not match the
                                                // action — companion lied about
                                                // memo/esk to extract a signature
                                                // for a different on-chain memo
    HWP_ERR_BAD_PK_D                    = 0x10, // pk_d does not decode to a
                                                // valid Pallas point
    HWP_ERR_FEE_NOT_CONFIRMED           = 0x11, // verify() reached without user
                                                // approving the on-device fee
    HWP_ERR_FEE_OVERFLOW                = 0x12, // transparent value sums or
                                                // value_balance combine to an
                                                // out-of-range fee
    HWP_ERR_FEE_NEGATIVE                = 0x13, // t_in + value_balance < t_out
} HwpErrorCode;

// FVK_REQ payload (v2.1+):
//   coin_type[4 LE]   (133 = mainnet, 1 = testnet)
// Empty payload accepted for backward compatibility (device uses default).
#define HWP_FVK_REQ_SIZE 4

// SIGN_REQ payload:
//   sighash[32] || alpha[32] || amount[8 LE] || fee[8 LE] || recipient_len[1] || recipient[N]
// Total: 81 + recipient_len
#define HWP_SIGN_REQ_FIXED 81 // 32+32+8+8+1

// Maximum recipient-string length. recipient_len is a single wire byte, so
// the hard ceiling is 255; the buffer holds that plus a NUL terminator. A
// multi-receiver Unified Address (Orchard + Sapling + transparent) runs well
// past 127 chars — a testnet UA with all three is ~217 — so the earlier
// 127-byte cap rejected perfectly valid destinations. Keep this in sync with
// HWP_MAX_RECIPIENT in the host SDK (src/protocol/hwp.rs).
#define HWP_MAX_RECIPIENT 255
_Static_assert(HWP_MAX_RECIPIENT <= 255,
               "recipient_len is a single wire byte; HWP_MAX_RECIPIENT cannot exceed 255");

// TX_OUTPUT payload:
//   output_index[2 LE] || total_outputs[2 LE] || output_data[N]
#define HWP_TX_OUTPUT_HEADER 4 // 2+2

// --- Parsed structures ---

typedef struct {
    uint8_t sighash[32];
    uint8_t alpha[32];
    uint64_t amount;
    uint64_t fee;
    uint8_t recipient_len;
    char recipient[HWP_MAX_RECIPIENT + 1]; // + NUL terminator
} HwpSignReq;

typedef struct {
    uint16_t output_index;
    uint16_t total_outputs;
    const uint8_t* output_data;
    uint16_t output_data_len;
} HwpTxOutput;

/**
 * View of a TX_OUTPUT action payload (v4 format) split into the on-the-wire
 * 820-byte action data and the appended 83-byte note plaintext.
 *
 *   wire_payload[output_data] = action[820] || recipient[43] || value[8 LE] || rseed[32]
 *
 * Pointers reference the original payload buffer (no copy). The device uses
 * `recipient`/`value`/`rseed` to recompute the action's NoteCommitment and
 * compares against `action[OFF_CMX]`. See `orchard_signer_feed_action_with_note`.
 */
typedef struct {
    const uint8_t* action;       /* HWP_ACTION_DATA_SIZE = 820 bytes */
    const uint8_t* recipient;    /* 43 bytes = d[11] || pk_d[32] */
    uint64_t value;              /* zatoshis (host order, parsed from 8 LE bytes) */
    const uint8_t* rseed;        /* 32 bytes */
} HwpActionV4;

/**
 * View of a TX_OUTPUT action payload (v5 format) — same as v4 plus the
 * 512-byte memo plaintext. The device uses these to recompute the action's
 * `enc_ciphertext` and `ephemeral_key`, closing the memo-substitution
 * attack that v4 leaves open (cmx alone binds value/recipient but not memo
 * bytes). `esk` is derived on-device from `rseed + rho` per ZIP-212.
 *
 *   wire_payload[output_data] =
 *     action[820] || recipient[43] || value[8 LE] || rseed[32] || memo[512]
 *
 * Pointers reference the original payload buffer (no copy).
 */
typedef struct {
    const uint8_t* action;       /* HWP_ACTION_DATA_SIZE = 820 bytes */
    const uint8_t* recipient;    /* 43 bytes = d[11] || pk_d[32] */
    uint64_t value;              /* zatoshis */
    const uint8_t* rseed;        /* 32 bytes */
    const uint8_t* memo;         /* 512 bytes (ZIP-302 note memo plaintext) */
} HwpActionV5;

typedef struct {
    uint8_t version;
    uint8_t seq;
    uint8_t type;
    uint16_t payload_len;
    uint8_t payload[HWP_MAX_PAYLOAD];
} HwpFrame;

// --- Frame parser (state machine, processes one byte at a time) ---
typedef enum {
    HWP_PARSE_WAIT_MAGIC,
    HWP_PARSE_VERSION,
    HWP_PARSE_SEQ,
    HWP_PARSE_TYPE,
    HWP_PARSE_LEN_LO,
    HWP_PARSE_LEN_HI,
    HWP_PARSE_PAYLOAD,
    HWP_PARSE_CRC_LO,
    HWP_PARSE_CRC_HI,
} HwpParserState;

typedef enum {
    HWP_FEED_INCOMPLETE,   // Need more bytes
    HWP_FEED_FRAME_READY,  // Complete valid frame in parser->frame
    HWP_FEED_CRC_ERROR,    // Frame received but CRC mismatch
    HWP_FEED_OVERFLOW,     // Payload too large
} HwpFeedResult;

typedef struct {
    HwpParserState state;
    HwpFrame frame;
    uint16_t payload_idx;
    uint8_t crc_lo;
} HwpParser;

// --- API ---

// CRC-16/CCITT (poly 0x1021, init 0xFFFF)
uint16_t hwp_crc16(const uint8_t* buf, size_t len);

// Initialize parser
void hwp_parser_init(HwpParser* p);

// Feed one byte to parser. Returns status.
HwpFeedResult hwp_parser_feed(HwpParser* p, uint8_t byte);

// Encode a frame into buf. Returns total frame size.
// Version is set to HWP_VERSION (0x02).
size_t hwp_encode(uint8_t* buf, uint8_t seq, uint8_t msg_type,
                  const uint8_t* payload, uint16_t payload_len);

// Convenience: encode an ERROR frame
size_t hwp_encode_error(uint8_t* buf, uint8_t seq, HwpErrorCode code, const char* msg);

// Parse a SIGN_REQ payload into struct. Returns true on success.
bool hwp_parse_sign_req(const uint8_t* payload, uint16_t len, HwpSignReq* out);

// Encode a SIGN_REQ payload. Returns payload size.
uint16_t hwp_encode_sign_req(uint8_t* payload, const HwpSignReq* req);

// Parse a TX_OUTPUT payload. Returns true on success.
// Note: output_data points into the payload buffer (not copied).
bool hwp_parse_tx_output(const uint8_t* payload, uint16_t len, HwpTxOutput* out);

// Split a v4 action+note-plaintext output_data block (HWP_ACTION_DATA_SIZE_V4
// = 903 bytes) into its constituents. Returns true on success, false if the
// data length is not exactly HWP_ACTION_DATA_SIZE_V4.
bool hwp_parse_action_v4(const uint8_t* output_data, uint16_t output_data_len,
                         HwpActionV4* out);

// Split a v5 action+full-note-plaintext+memo output_data block
// (HWP_ACTION_DATA_SIZE_V5 = 1415 bytes) into its constituents. Returns
// true on success, false if the data length is not exactly that.
// esk is NOT on the wire: the device derives it on-chip from rseed +
// the action's nullifier (= rho) per ZIP-212.
bool hwp_parse_action_v5(const uint8_t* output_data, uint16_t output_data_len,
                         HwpActionV5* out);

// TRANSPARENT_SIGN_REQ payload (v3):
//   input_index[2 LE] || total_inputs[2 LE] ||
//   input_data[N] (same wire format as TxTransparentInput data)
// The device computes the per-input sighash on-device and signs with ECDSA.
//
// TRANSPARENT_SIGN_RSP payload (v3):
//   der_sig_len[1] || der_sig[N] || sighash_type[1] || pubkey[33]
#define HWP_TRANSPARENT_SIGN_RSP_MAX (1 + 72 + 1 + 33) // 107

// Encode a TX_OUTPUT payload. Returns payload size.
uint16_t hwp_encode_tx_output(uint8_t* payload, uint16_t output_index, uint16_t total_outputs,
                              const uint8_t* output_data, uint16_t output_data_len);

/* --- Device attestation (v4, audit M1) ----------------------------------
 *
 * Each device has a long-term Pallas identity keypair generated at first
 * boot and persisted in NVS. The pubkey is exposed via IDENTITY_REQ and
 * is intended to be pinned by the companion at first pairing (typically
 * via a SEPARATE trusted CLI utility, since the everyday companion is
 * not in the trust circle for this check).
 *
 * Per signing session, the companion sends a 32-byte challenge nonce.
 * The device computes a deterministic hash of the challenge and signs
 * it with RedPallas using the identity scalar. Because alpha = 0 in
 * this signing path, the returned `rk` is exactly the device pubkey,
 * so the companion can both:
 *   1. verify rk == pinned device_pubkey (catches device substitution),
 *   2. verify the RedPallas signature (catches replay / forgery).
 *
 * Threat coverage:
 *   - USB-hub / cable MITM that swaps the device with a fake: caught by (1).
 *   - Localhost TCP impersonator (Speculos / fake virtual device): caught by (1).
 *   - Stolen-and-reflashed device: the identity key is regenerated on
 *     factory reset, so the new pubkey will not match the pinned one.
 *
 * NOT covered:
 *   - Hostile companion that lies about the verification result. The
 *     standalone CLI pairing tool defends against this: a user paranoid
 *     about their main companion runs the tool periodically and gets an
 *     independent verdict.
 *   - Confidentiality of FVK / sighash on the wire (channel encryption
 *     is a separate, larger fix; not in this commit).
 */
#define HWP_DEVICE_PUBKEY_SIZE   32
#define HWP_ATTEST_CHALLENGE_SIZE 32
#define HWP_ATTEST_SIG_SIZE      64
#define HWP_ATTEST_RSP_SIZE      (HWP_ATTEST_SIG_SIZE + HWP_DEVICE_PUBKEY_SIZE) /* 96 */

/* Personalization tag for the BLAKE2b-256 of (challenge) → "sighash" passed
 * to redpallas_sign. Domain-separates attestation signatures from any other
 * 32-byte value the device might sign. Exactly 16 bytes (BLAKE2b personal). */
#define HWP_ATTEST_PERSONAL "ZcashHWAttestV1!"  /* 16 bytes incl. trailing '!' */
