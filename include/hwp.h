/**
 * Hardware Wallet Protocol (HWP) v2 — Binary framed serial protocol.
 *
 * Frame: [MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]
 *
 * Compatible with zcash-hw-wallet-sdk (Rust).
 * Supports staged transaction verification: outputs are sent individually
 * and hashed incrementally on-device to verify sighash integrity before signing.
 *
 * v6-only (post-NU6.3 / Ironwood): the device accepts ONLY the v6 wire tier
 * — 166/170-byte TxMeta and pool-tagged action payloads (904 / 1416 bytes).
 * Legacy pre-v6 layouts (125/129-byte TxMeta, untagged 903/1415-byte
 * actions) are rejected. The frame VERSION byte (0x02) is unrelated to the
 * wire tier and is unchanged.
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

// Note plaintext appended to action data for on-device cmx verification:
// recipient(43) + value(8 LE) + rseed(32) = 83 bytes
// Required so the device can recompute the action's NoteCommitment and reject
// recipient-substitution attacks.
#define HWP_NOTE_PLAINTEXT_SIZE  83

// v6 (NU6.3 / Ironwood) action payload — the ONLY layout the device
// accepts: a 1-byte pool tag (0x00 = sealed Orchard pool, 0x01 = Ironwood
// pool) followed by the memo-carrying body. The dispatcher strips the tag
// and routes the action into the matching ZIP-244 pool digest tree.
//
//   body = action(820) + recipient(43) + value(8) + rseed(32) + memo(512)
//        = 1415 bytes; on the wire 1 + 1415 = 1416 bytes
//
// The device uses recipient/value/rseed to recompute the action's note
// commitment and, with the memo, its `enc_ciphertext` and `ephemeral_key`
// byte-for-byte; a mismatch ends the session (one exception, decided by the
// device: the sealed-Orchard spend dummy, see orchard_signer.c). `esk` is NOT on the wire: per
// ZIP-212 it is a deterministic function of rseed + rho (= the action's
// nullifier), so the device derives it itself.
//
// EVERY action needs this body — zero-value padding too. The compact body
// (same without the memo: 903 bytes, 904 on the wire) is refused with
// Error(MEMO_REQUIRED); HWP_ACTION_BODY_COMPACT_SIZE and hwp_parse_action_v4
// remain only so that a host library can name what it must not send. Legacy
// untagged v4/v5 payloads (903/1415 bytes) are refused with Error(BAD_FRAME).
#define HWP_POOL_TAG_SIZE 1
#define HWP_ACTION_BODY_COMPACT_SIZE (HWP_ACTION_DATA_SIZE + HWP_NOTE_PLAINTEXT_SIZE) /* 903 */
#define HWP_ACTION_BODY_MEMO_SIZE    (HWP_ACTION_BODY_COMPACT_SIZE + 512)             /* 1415 */
#define HWP_ACTION_DATA_SIZE_V6         (HWP_POOL_TAG_SIZE + HWP_ACTION_BODY_MEMO_SIZE)    /* 1416 */
#define HWP_ACTION_DATA_SIZE_V6_COMPACT (HWP_POOL_TAG_SIZE + HWP_ACTION_BODY_COMPACT_SIZE) /* 904 */

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
    HWP_MSG_TX_TRANSPARENT_INPUT  = 0x0B, // Accepted ONLY as the sentinel that
                                          // closes the transparent-output
                                          // stream: index = total = 0 and the
                                          // 32-byte transparent digest. Any
                                          // frame announcing an input ->
                                          // Error(TRANSPARENT_INPUTS_UNSUPPORTED)
    HWP_MSG_TX_TRANSPARENT_OUTPUT = 0x0C, // Transparent output (P2PKH / P2SH):
                                          // index[2] total[2] value[8]
                                          // script_len[2] script[N], in order
    HWP_MSG_TRANSPARENT_SIGN_REQ  = 0x0D, // RESERVED. Always answered with
                                          // Error(TRANSPARENT_INPUTS_UNSUPPORTED)
    HWP_MSG_TRANSPARENT_SIGN_RSP  = 0x0E, // RESERVED. Never sent.
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
    HWP_ERR_RECIPIENT_MISMATCH          = 0x0E, // RESERVED, no longer sent:
                                                // SIGN_REQ.recipient is ignored
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
    // The codes below were added with the on-device ownership / mandatory
    // ciphertext checks. The Error frame layout is unchanged (code byte +
    // message); a host that does not know a code reads it as "unknown" and
    // still gets the message text.
    HWP_ERR_MEMO_REQUIRED               = 0x14, // an action was sent as the
                                                // compact (no-memo, 904 B)
                                                // body. It is refused for every
                                                // output, zero-value padding
                                                // included: resend with the
                                                // memo-carrying body (1416 B)
    HWP_ERR_BRANCH_NOT_ALLOWED          = 0x15, // consensus branch ID not in
                                                // the device's allow-list
                                                // (firmware update needed for
                                                // a newer network upgrade)
    HWP_ERR_LIMIT_EXCEEDED              = 0x16, // more actions, memos or
                                                // transparent outputs (> 8 by
                                                // default) than the device can
                                                // review, or a memo
                                                // on a device without a memo
                                                // screen. Nothing was skipped:
                                                // the session was aborted
    HWP_ERR_VALUE_OVERFLOW              = 0x17, // output value sums / total
                                                // leaving the wallet overflow
    HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED = 0x18, // the transaction has
                                                // transparent inputs, or a
                                                // TRANSPARENT_SIGN_REQ was
                                                // sent: spending from a
                                                // t-address is not supported
    HWP_ERR_EMPTY_POOL_BALANCE          = 0x19, // TxMeta declares a non-zero
                                                // value balance for a pool
                                                // (Orchard / Ironwood) that has
                                                // no action in the transaction
} HwpErrorCode;

// FVK_REQ payload (v2.1+):
//   coin_type[4 LE]   (133 = mainnet, 1 = testnet)
// The device's network is fixed by its firmware. A request naming the other
// network is answered with Error(NETWORK_MISMATCH); an empty payload or coin
// type 0 ("not saying") is answered with the FVK. The request does not set
// anything on the device. FVK_RSP carries ak || nk || rivk only — no
// transparent key.
#define HWP_FVK_REQ_SIZE 4

// SIGN_REQ payload:
//   sighash[32] || alpha[32] || amount[8 LE] || fee[8 LE] || recipient_len[1] || recipient[N]
// Total: 81 + recipient_len
//
// The device USES sighash (must equal the sighash it verified, otherwise
// Error(SIGHASH_MISMATCH) and the session ends) and alpha. amount, fee and
// recipient are IGNORED: not validated, not displayed. recipient_len may be
// 0; if it is not, it only has to match the payload length. The final
// confirmation screen shows totals computed by the device.
//
// The device answers at most one SIGN_REQ per action of the approved
// transaction, each for the verified sighash; with the last one the session
// ends. A host that needs fewer signatures just stops asking: the next
// TX_OUTPUT carrying a TxMeta (or PING / ABORT) ends the previous
// transaction and clears every approval.
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
 * View of a tag-stripped v6 compact (cmx-only) action body split into the
 * 820-byte action data and the appended 83-byte note plaintext.
 *
 *   body = action[820] || recipient[43] || value[8 LE] || rseed[32]   (903 B)
 *
 * Pointers reference the original payload buffer (no copy). THE DEVICE
 * REFUSES THIS BODY (Error MEMO_REQUIRED): the struct and its parser remain
 * for host-side code and tests.
 * (The struct keeps its historical V4 name; the layout is byte-identical.)
 */
typedef struct {
    const uint8_t* action;       /* HWP_ACTION_DATA_SIZE = 820 bytes */
    const uint8_t* recipient;    /* 43 bytes = d[11] || pk_d[32] */
    uint64_t value;              /* zatoshis (host order, parsed from 8 LE bytes) */
    const uint8_t* rseed;        /* 32 bytes */
} HwpActionV4;

/**
 * View of a tag-stripped v6 memo-verifying action body — same as the
 * compact body plus the 512-byte memo plaintext. The device uses these to
 * recompute the action's `enc_ciphertext` and `ephemeral_key`, closing the
 * memo-substitution attack that the cmx-only body leaves open (cmx alone
 * binds value/recipient but not memo bytes). `esk` is derived on-device
 * from `rseed + rho` per ZIP-212.
 *
 *   body = action[820] || recipient[43] || value[8 LE] || rseed[32] || memo[512]   (1415 B)
 *
 * Pointers reference the original payload buffer (no copy).
 * (The struct keeps its historical V5 name; the layout is byte-identical.)
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

// Split a tag-stripped v6 compact action body (HWP_ACTION_BODY_COMPACT_SIZE
// = 903 bytes) into its constituents. Returns true on success, false if the
// data length is not exactly HWP_ACTION_BODY_COMPACT_SIZE.
bool hwp_parse_action_v4(const uint8_t* output_data, uint16_t output_data_len,
                         HwpActionV4* out);

// Split a tag-stripped v6 memo-verifying action body
// (HWP_ACTION_BODY_MEMO_SIZE = 1415 bytes) into its constituents. Returns
// true on success, false if the data length is not exactly that.
// esk is NOT on the wire: the device derives it on-chip from rseed +
// the action's nullifier (= rho) per ZIP-212.
bool hwp_parse_action_v5(const uint8_t* output_data, uint16_t output_data_len,
                         HwpActionV5* out);

// TRANSPARENT_SIGN_REQ / TRANSPARENT_SIGN_RSP: reserved message IDs. The
// device does not sign transparent inputs (README, "Transparent inputs are
// not supported"); the request is answered with
// Error(TRANSPARENT_INPUTS_UNSUPPORTED) and the session ends.
//
// ERRORS END THE SESSION. Whenever the device sends an Error frame — for any
// reason, including a CRC error, an unknown message type or an unsupported
// version — it has discarded the transaction in progress and every approval
// given for it. The host starts again from TxMeta.

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
