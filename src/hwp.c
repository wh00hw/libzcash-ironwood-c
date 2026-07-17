/**
 * Hardware Wallet Protocol (HWP) v2 implementation.
 * Compatible with zcash-hw-signer-sdk (Rust).
 */
#include "hwp.h"
#include <string.h>

// CRC-16/CCITT lookup table (poly 0x1021, init 0xFFFF)
static const uint16_t crc16_tab[256] = {
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50A5,0x60C6,0x70E7,
    0x8108,0x9129,0xA14A,0xB16B,0xC18C,0xD1AD,0xE1CE,0xF1EF,
    0x1231,0x0210,0x3273,0x2252,0x52B5,0x4294,0x72F7,0x62D6,
    0x9339,0x8318,0xB37B,0xA35A,0xD3BD,0xC39C,0xF3FF,0xE3DE,
    0x2462,0x3443,0x0420,0x1401,0x64E6,0x74C7,0x44A4,0x54A5,
    0xA54A,0xB56B,0x8508,0x9529,0xE5CE,0xF5EF,0xC58C,0xD5AD,
    0x3653,0x2672,0x1611,0x0630,0x76D7,0x66F6,0x5695,0x46B4,
    0xB75B,0xA77A,0x9719,0x8738,0xF7DF,0xE7FE,0xD79D,0xC7BC,
    0x4864,0x5845,0x6826,0x7807,0x08E0,0x18C1,0x28A2,0x38A3,
    0xC94C,0xD96D,0xE90E,0xF92F,0x89C8,0x99E9,0xA98A,0xB9AB,
    0x5A55,0x4A74,0x7A17,0x6A36,0x1AD1,0x0AF0,0x3A93,0x2AB2,
    0xDB5D,0xCB7C,0xFB1F,0xEB3E,0x9BD9,0x8BF8,0xAB9B,0xABBA,
    0x6CA6,0x7C87,0x4CE4,0x5CC5,0x2C22,0x3C03,0x0C60,0x1C41,
    0xEDAE,0xFD8F,0xCDEC,0xDDCD,0xAD2A,0xBD0B,0x8D68,0x9D49,
    0x7E97,0x6EB6,0x5ED5,0x4EF4,0x3E13,0x2E32,0x1E51,0x0E70,
    0xFF9F,0xEFBE,0xDFDD,0xCFFC,0xBF1B,0xAF3A,0x9F59,0x8F78,
    0x9188,0x81A9,0xB1CA,0xA1EB,0xD10C,0xC12D,0xF14E,0xE16F,
    0x1080,0x00A1,0x30C2,0x20E3,0x5004,0x4025,0x7046,0x6067,
    0x83B9,0x9398,0xA3FB,0xB3DA,0xC33D,0xD31C,0xE37F,0xF35E,
    0x02B1,0x1290,0x22F3,0x32D2,0x4235,0x5214,0x6277,0x7256,
    0xB5EA,0xA5CB,0x95A8,0x85A9,0xF54E,0xE56F,0xD50C,0xC52D,
    0x34C2,0x24E3,0x1480,0x04A1,0x7466,0x6447,0x5424,0x4405,
    0xA7DB,0xB7FA,0x8799,0x97B8,0xE75F,0xF77E,0xC71D,0xD73C,
    0x26D3,0x36F2,0x0691,0x16B0,0x6657,0x7676,0x4615,0x5634,
    0xD94C,0xC96D,0xF90E,0xE92F,0x99C8,0x89E9,0xB98A,0xA9AB,
    0x5844,0x4865,0x7806,0x6827,0x18C0,0x08E1,0x3882,0x28A3,
    0xCB7D,0xDB5C,0xEB3F,0xFB1E,0x8BD9,0x9BF8,0xAB9B,0xBBBA,
    0x4A55,0x5A74,0x6A17,0x7A36,0x0AD1,0x1AF0,0x2A93,0x3AB2,
    0xFD2E,0xED0F,0xDD6C,0xCD4D,0xBDAA,0xAD8B,0x9DE8,0x8DC9,
    0x7C26,0x6C07,0x5C64,0x4C45,0x3CA2,0x2C83,0x1CE0,0x0CC1,
    0xEF1F,0xFF3E,0xCF5D,0xDF7C,0xAF9B,0xBFBA,0x8FD9,0x9FF8,
    0x6E17,0x7E36,0x4E55,0x5E74,0x2E93,0x3EB2,0x0ED1,0x1EF0,
};

uint16_t hwp_crc16(const uint8_t* buf, size_t len) {
    uint16_t crc = 0xFFFF;
    for(size_t i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc16_tab[((crc >> 8) ^ buf[i]) & 0xFF];
    }
    return crc;
}

void hwp_parser_init(HwpParser* p) {
    memset(p, 0, sizeof(*p));
    p->state = HWP_PARSE_WAIT_MAGIC;
}

HwpFeedResult hwp_parser_feed(HwpParser* p, uint8_t byte) {
    switch(p->state) {
    case HWP_PARSE_WAIT_MAGIC:
        if(byte == HWP_MAGIC) {
            p->state = HWP_PARSE_VERSION;
        }
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_VERSION:
        p->frame.version = byte;
        // Accept v1 (0x01) and v2 (0x02) for backward compatibility
        p->state = HWP_PARSE_SEQ;
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_SEQ:
        p->frame.seq = byte;
        p->state = HWP_PARSE_TYPE;
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_TYPE:
        p->frame.type = byte;
        p->state = HWP_PARSE_LEN_LO;
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_LEN_LO:
        p->frame.payload_len = byte;
        p->state = HWP_PARSE_LEN_HI;
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_LEN_HI:
        p->frame.payload_len |= ((uint16_t)byte << 8);
        if(p->frame.payload_len > HWP_MAX_PAYLOAD) {
            p->state = HWP_PARSE_WAIT_MAGIC;
            return HWP_FEED_OVERFLOW;
        }
        p->payload_idx = 0;
        if(p->frame.payload_len == 0) {
            p->state = HWP_PARSE_CRC_LO;
        } else {
            p->state = HWP_PARSE_PAYLOAD;
        }
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_PAYLOAD:
        p->frame.payload[p->payload_idx++] = byte;
        if(p->payload_idx >= p->frame.payload_len) {
            p->state = HWP_PARSE_CRC_LO;
        }
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_CRC_LO:
        p->crc_lo = byte;
        p->state = HWP_PARSE_CRC_HI;
        return HWP_FEED_INCOMPLETE;

    case HWP_PARSE_CRC_HI: {
        uint16_t received_crc = p->crc_lo | ((uint16_t)byte << 8);

        // Reconstruct header for CRC check
        uint8_t hdr[HWP_HEADER_SIZE];
        hdr[0] = HWP_MAGIC;
        hdr[1] = p->frame.version;
        hdr[2] = p->frame.seq;
        hdr[3] = p->frame.type;
        hdr[4] = p->frame.payload_len & 0xFF;
        hdr[5] = (p->frame.payload_len >> 8) & 0xFF;

        // CRC over header + payload
        uint16_t crc = 0xFFFF;
        for(size_t i = 0; i < HWP_HEADER_SIZE; i++) {
            crc = (crc << 8) ^ crc16_tab[((crc >> 8) ^ hdr[i]) & 0xFF];
        }
        for(uint16_t i = 0; i < p->frame.payload_len; i++) {
            crc = (crc << 8) ^ crc16_tab[((crc >> 8) ^ p->frame.payload[i]) & 0xFF];
        }

        p->state = HWP_PARSE_WAIT_MAGIC;
        return (crc == received_crc) ? HWP_FEED_FRAME_READY : HWP_FEED_CRC_ERROR;
    }
    }

    p->state = HWP_PARSE_WAIT_MAGIC;
    return HWP_FEED_INCOMPLETE;
}

size_t hwp_encode(uint8_t* buf, uint8_t seq, uint8_t msg_type,
                  const uint8_t* payload, uint16_t payload_len) {
    buf[0] = HWP_MAGIC;
    buf[1] = HWP_VERSION;
    buf[2] = seq;
    buf[3] = msg_type;
    buf[4] = payload_len & 0xFF;
    buf[5] = (payload_len >> 8) & 0xFF;
    if(payload_len > 0 && payload) {
        memcpy(buf + HWP_HEADER_SIZE, payload, payload_len);
    }
    uint16_t crc = hwp_crc16(buf, HWP_HEADER_SIZE + payload_len);
    buf[HWP_HEADER_SIZE + payload_len] = crc & 0xFF;
    buf[HWP_HEADER_SIZE + payload_len + 1] = (crc >> 8) & 0xFF;
    return HWP_HEADER_SIZE + payload_len + HWP_CRC_SIZE;
}

size_t hwp_encode_error(uint8_t* buf, uint8_t seq, HwpErrorCode code, const char* msg) {
    uint8_t payload[129];
    payload[0] = (uint8_t)code;
    size_t msg_len = msg ? strlen(msg) : 0;
    if(msg_len > 128) msg_len = 128;
    if(msg_len > 0) memcpy(payload + 1, msg, msg_len);
    return hwp_encode(buf, seq, HWP_MSG_ERROR, payload, 1 + msg_len);
}

bool hwp_parse_sign_req(const uint8_t* payload, uint16_t len, HwpSignReq* out) {
    if(len < HWP_SIGN_REQ_FIXED) return false;
    memcpy(out->sighash, payload, 32);
    memcpy(out->alpha, payload + 32, 32);
    out->amount = 0;
    for(int i = 7; i >= 0; i--) out->amount = (out->amount << 8) | payload[64 + i];
    out->fee = 0;
    for(int i = 7; i >= 0; i--) out->fee = (out->fee << 8) | payload[72 + i];
    out->recipient_len = payload[80];
    /* recipient_len is a single wire byte (<= 255). The bound check is only
     * meaningful for a cap below that; guarding it keeps -Werror=type-limits
     * happy when HWP_MAX_RECIPIENT == 255 (the check would always be false). */
#if HWP_MAX_RECIPIENT < 255
    if(out->recipient_len > HWP_MAX_RECIPIENT) return false;
#endif
    if(len < HWP_SIGN_REQ_FIXED + out->recipient_len) return false;
    memcpy(out->recipient, payload + HWP_SIGN_REQ_FIXED, out->recipient_len);
    out->recipient[out->recipient_len] = '\0';
    return true;
}

uint16_t hwp_encode_sign_req(uint8_t* payload, const HwpSignReq* req) {
    memcpy(payload, req->sighash, 32);
    memcpy(payload + 32, req->alpha, 32);
    uint64_t v = req->amount;
    for(int i = 0; i < 8; i++) { payload[64 + i] = v & 0xFF; v >>= 8; }
    v = req->fee;
    for(int i = 0; i < 8; i++) { payload[72 + i] = v & 0xFF; v >>= 8; }
    payload[80] = req->recipient_len;
    memcpy(payload + HWP_SIGN_REQ_FIXED, req->recipient, req->recipient_len);
    return HWP_SIGN_REQ_FIXED + req->recipient_len;
}

bool hwp_parse_tx_output(const uint8_t* payload, uint16_t len, HwpTxOutput* out) {
    if(len < HWP_TX_OUTPUT_HEADER) return false;
    out->output_index = payload[0] | ((uint16_t)payload[1] << 8);
    out->total_outputs = payload[2] | ((uint16_t)payload[3] << 8);
    out->output_data = payload + HWP_TX_OUTPUT_HEADER;
    out->output_data_len = len - HWP_TX_OUTPUT_HEADER;
    return true;
}

bool hwp_parse_action_v4(const uint8_t* output_data, uint16_t output_data_len,
                         HwpActionV4* out) {
    if(output_data_len != HWP_ACTION_BODY_COMPACT_SIZE) return false;
    /* Layout (903 bytes):
     *   action[0..820]            -- 820 bytes ZIP-244 action data
     *   recipient[820..863]       -- 43 bytes d[11] || pk_d[32]
     *   value_le[863..871]        -- 8 bytes little-endian u64
     *   rseed[871..903]           -- 32 bytes
     */
    out->action    = output_data;
    out->recipient = output_data + HWP_ACTION_DATA_SIZE;
    {
        uint64_t v = 0;
        const uint8_t* vp = output_data + HWP_ACTION_DATA_SIZE + 43;
        for(int i = 7; i >= 0; i--) {
            v = (v << 8) | vp[i];
        }
        out->value = v;
    }
    out->rseed = output_data + HWP_ACTION_DATA_SIZE + 43 + 8;
    return true;
}

bool hwp_parse_action_v5(const uint8_t* output_data, uint16_t output_data_len,
                         HwpActionV5* out) {
    if(output_data_len != HWP_ACTION_BODY_MEMO_SIZE) return false;
    /* Layout (1415 bytes):
     *   action[0..820]
     *   recipient[820..863]
     *   value_le[863..871]
     *   rseed[871..903]
     *   memo[903..1415]
     */
    out->action    = output_data;
    out->recipient = output_data + HWP_ACTION_DATA_SIZE;
    {
        uint64_t v = 0;
        const uint8_t* vp = output_data + HWP_ACTION_DATA_SIZE + 43;
        for(int i = 7; i >= 0; i--) {
            v = (v << 8) | vp[i];
        }
        out->value = v;
    }
    out->rseed = output_data + HWP_ACTION_DATA_SIZE + 43 + 8;
    out->memo  = output_data + HWP_ACTION_DATA_SIZE + HWP_NOTE_PLAINTEXT_SIZE;
    return true;
}

uint16_t hwp_encode_tx_output(uint8_t* payload, uint16_t output_index, uint16_t total_outputs,
                              const uint8_t* output_data, uint16_t output_data_len) {
    payload[0] = output_index & 0xFF;
    payload[1] = (output_index >> 8) & 0xFF;
    payload[2] = total_outputs & 0xFF;
    payload[3] = (total_outputs >> 8) & 0xFF;
    if(output_data_len > 0 && output_data) {
        memcpy(payload + HWP_TX_OUTPUT_HEADER, output_data, output_data_len);
    }
    return HWP_TX_OUTPUT_HEADER + output_data_len;
}
