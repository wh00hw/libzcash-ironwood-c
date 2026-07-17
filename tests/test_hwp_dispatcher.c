/*
 * test_hwp_dispatcher — smoke test for the device-side HWP driver.
 *
 * Drives hwp_dispatcher_run() against stub I/O callbacks that play the
 * "host" half of the conversation: enqueue frames to be drained, capture
 * frames the dispatcher emits, exercise the handshake + FVK_REQ /
 * FVK_RSP exchange, then trip should_exit() to terminate the loop.
 *
 * Scope: the protocol-layer invariants the dispatcher owns (frame
 * encode/decode, message dispatch table, PING/PONG keepalive, signer
 * delegation). Crypto correctness, sighash recomputation, RedPallas
 * signing and per-output review are covered by test_signer and
 * test_orchard against the same OrchardSignerCtx the dispatcher drives.
 */
#include "hwp_dispatcher.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hwp.h"
#include "orchard_signer.h"
#include "zip244.h"

/* ── Stub callback state ──────────────────────────────────────────── */

typedef struct {
    /* Incoming-to-device byte stream (frames the "host" pushes). */
    uint8_t in_buf[2048];
    size_t  in_len;
    size_t  in_pos;

    /* Outgoing-from-device byte stream (frames the device emits). */
    uint8_t out_buf[2048];
    size_t  out_len;

    /* Monotonic ms counter. */
    uint32_t tick_ms;

    /* Loop control. */
    int      iterations;
    int      exit_after;

    /* Counters for assertions. */
    int      review_calls;
    int      confirm_calls;
} Stub;

static size_t stub_drain(uint8_t* out, size_t out_cap, void* ctx) {
    Stub* s = (Stub*)ctx;
    size_t remaining = s->in_len - s->in_pos;
    if(remaining == 0) return 0;
    size_t n = remaining < out_cap ? remaining : out_cap;
    /* Match real CDC: at most one packet (64 B) per call. */
    if(n > 64) n = 64;
    memcpy(out, s->in_buf + s->in_pos, n);
    s->in_pos += n;
    return n;
}

static void stub_send(const uint8_t* data, size_t len, void* ctx) {
    Stub* s = (Stub*)ctx;
    if(s->out_len + len > sizeof(s->out_buf)) return;
    memcpy(s->out_buf + s->out_len, data, len);
    s->out_len += len;
}

static uint32_t stub_tick(void* ctx) {
    Stub* s = (Stub*)ctx;
    return s->tick_ms;
}

static void stub_sleep(uint32_t ms, void* ctx) {
    Stub* s = (Stub*)ctx;
    s->tick_ms += ms;
}

static bool stub_should_exit(void* ctx) {
    Stub* s = (Stub*)ctx;
    if(++s->iterations >= s->exit_after) return true;
    return false;
}

static HwpUiResult stub_review(uint16_t idx, uint16_t total,
                                const char* addr, uint64_t value, void* ctx) {
    Stub* s = (Stub*)ctx;
    (void)idx; (void)total; (void)addr; (void)value;
    s->review_calls++;
    return HWP_UI_OK;
}

static HwpUiResult stub_confirm(uint64_t amount, uint64_t fee,
                                 const char* recipient, void* ctx) {
    Stub* s = (Stub*)ctx;
    (void)amount; (void)fee; (void)recipient;
    s->confirm_calls++;
    return HWP_UI_OK;
}

/* ── Helpers to enqueue frames into the stub's RX stream ──────────── */

static void push_frame(Stub* s, uint8_t seq, uint8_t msg_type,
                       const uint8_t* payload, uint16_t payload_len) {
    uint8_t buf[HWP_MAX_FRAME];
    size_t  n = hwp_encode(buf, seq, msg_type, payload, payload_len);
    assert(s->in_len + n <= sizeof(s->in_buf));
    memcpy(s->in_buf + s->in_len, buf, n);
    s->in_len += n;
}

/* Parse the first frame in `out_buf` from offset `*pos`, advancing the
 * cursor past it. Returns 0 on success, non-zero otherwise. */
static int pop_frame(const Stub* s, size_t* pos, HwpFrame* out) {
    HwpParser p;
    hwp_parser_init(&p);
    while(*pos < s->out_len) {
        HwpFeedResult r = hwp_parser_feed(&p, s->out_buf[(*pos)++]);
        if(r == HWP_FEED_FRAME_READY) {
            *out = p.frame;
            return 0;
        }
        if(r == HWP_FEED_CRC_ERROR) return -1;
    }
    return -1;
}

/* ── Tests ────────────────────────────────────────────────────────── */

static const uint8_t AK[32]   = {[0 ... 31] = 0x10};
static const uint8_t NK[32]   = {[0 ... 31] = 0x20};
static const uint8_t RIVK[32] = {[0 ... 31] = 0x30};
static const uint8_t ASK[32]  = {[0 ... 31] = 0x40};
static const uint8_t TSK[32]  = {[0 ... 31] = 0x50};
static const uint8_t TPUB[33] = {[0 ... 32] = 0x60};

static HwpDispatcher build_dispatcher(Stub* stub, OrchardSignerCtx* signer) {
    HwpDispatcher d = {
        .io = {
            .serial_drain = stub_drain,
            .serial_send  = stub_send,
            .get_tick_ms  = stub_tick,
            .sleep_ms     = stub_sleep,
            .should_exit  = stub_should_exit,
        },
        .ui = {
            .review_output = stub_review,
            .confirm_tx    = stub_confirm,
        },
        .keys = { .ak = AK, .nk = NK, .rivk = RIVK,
                   .ask = ASK, .t_sk = TSK, .t_pubkey = TPUB },
        .signer    = signer,
        .testnet   = true,
        .user_ctx  = stub,
    };
    return d;
}

static void test_initial_ping_emitted(void) {
    /* On entry the dispatcher MUST emit a PING so a host that just
     * connected immediately learns the device is alive. Earlier
     * versions only sent PINGs periodically when !connected; if the
     * host opens the port and blocks on read it would deadlock until
     * the first 400 ms keepalive timer expired. */
    Stub s = {0};
    s.exit_after = 1; /* exit on first iteration — no host bytes */
    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);

    HwpDispatchResult r = hwp_dispatcher_run(&d);
    assert(r == HWP_DISP_EXIT_REQUESTED);

    size_t pos = 0;
    HwpFrame f;
    assert(pop_frame(&s, &pos, &f) == 0);
    assert(f.type == HWP_MSG_PING);
    assert(f.payload_len == 0);
    printf("  PASS: initial PING emitted at session start\n");
}

static void test_pong_handshake(void) {
    /* Host's PONG response to the initial PING must be accepted
     * without an emitted reply (PONG is the terminal step of the
     * keepalive). The signer state must remain IDLE — no protocol
     * progression on a bare PONG. */
    Stub s = {0};
    s.exit_after = 8;
    push_frame(&s, /*seq=*/0, HWP_MSG_PONG, NULL, 0);
    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);

    HwpDispatchResult r = hwp_dispatcher_run(&d);
    assert(r == HWP_DISP_EXIT_REQUESTED);

    /* Only the initial PING was emitted; no reply to the PONG. */
    size_t pos = 0;
    HwpFrame f;
    assert(pop_frame(&s, &pos, &f) == 0);
    assert(f.type == HWP_MSG_PING);
    /* Either nothing more, or only further keepalive PINGs — never a
     * spurious response to the PONG. */
    while(pop_frame(&s, &pos, &f) == 0) {
        assert(f.type == HWP_MSG_PING);
    }
    assert(signer.state == SIGNER_IDLE);
    printf("  PASS: PONG accepted silently, signer stays IDLE\n");
}

static void test_fvk_req_emits_correct_fvk(void) {
    /* FVK_REQ with the device's coin_type → FVK_RSP carrying
     *   ak[32] || nk[32] || rivk[32]
     * from the dispatcher's HwpDispatcherKeys. This is the entry
     * point for first-pairing on the companion side. */
    Stub s = {0};
    s.exit_after = 10;
    /* coin_type = 1 (testnet), matches d.testnet == true. */
    uint8_t coin_le[4] = {0x01, 0x00, 0x00, 0x00};
    push_frame(&s, /*seq=*/7, HWP_MSG_FVK_REQ, coin_le, sizeof(coin_le));
    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);

    HwpDispatchResult r = hwp_dispatcher_run(&d);
    assert(r == HWP_DISP_EXIT_REQUESTED);

    /* Drain emitted frames; find the FVK_RSP. */
    size_t pos = 0;
    HwpFrame f;
    bool seen_fvk_rsp = false;
    while(pop_frame(&s, &pos, &f) == 0) {
        if(f.type == HWP_MSG_FVK_RSP) {
            seen_fvk_rsp = true;
            assert(f.seq == 7);
            assert(f.payload_len == 96);
            assert(memcmp(f.payload, AK, 32) == 0);
            assert(memcmp(f.payload + 32, NK, 32) == 0);
            assert(memcmp(f.payload + 64, RIVK, 32) == 0);
        }
    }
    assert(seen_fvk_rsp);
    printf("  PASS: FVK_REQ → FVK_RSP with correct ak||nk||rivk\n");
}

static void test_fvk_req_wrong_network_rejected(void) {
    /* FVK_REQ with the opposite network must be rejected with
     * HWP_ERR_NETWORK_MISMATCH; the FVK does NOT leak across networks
     * even though derivation is technically possible from the same
     * seed. */
    Stub s = {0};
    s.exit_after = 25;
    uint8_t main_coin_le[4] = {133, 0, 0, 0}; /* mainnet, against testnet device */
    push_frame(&s, /*seq=*/9, HWP_MSG_FVK_REQ, main_coin_le, sizeof(main_coin_le));
    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);

    /* network_error callback intentionally not provided — the dispatcher
     * must still emit the on-wire Error frame. */
    d.ui.network_error = NULL;

    HwpDispatchResult r = hwp_dispatcher_run(&d);
    assert(r == HWP_DISP_EXIT_REQUESTED);

    size_t pos = 0;
    HwpFrame f;
    bool seen_err = false;
    bool seen_fvk_rsp = false;
    while(pop_frame(&s, &pos, &f) == 0) {
        if(f.type == HWP_MSG_ERROR) {
            seen_err = true;
            assert(f.seq == 9);
            assert(f.payload_len >= 1);
            assert(f.payload[0] == HWP_ERR_NETWORK_MISMATCH);
        }
        if(f.type == HWP_MSG_FVK_RSP) seen_fvk_rsp = true;
    }
    assert(seen_err);
    assert(!seen_fvk_rsp);
    printf("  PASS: cross-network FVK_REQ rejected (NETWORK_MISMATCH, no FVK leak)\n");
}

static void test_unknown_message_yields_error(void) {
    /* An unsupported message type triggers an Error frame so the host
     * can fail fast instead of timing out on a missing ACK. */
    Stub s = {0};
    s.exit_after = 8;
    /* 0x7F is reserved/unused. */
    push_frame(&s, /*seq=*/3, 0x7F, NULL, 0);
    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);

    HwpDispatchResult r = hwp_dispatcher_run(&d);
    assert(r == HWP_DISP_EXIT_REQUESTED);

    size_t pos = 0;
    HwpFrame f;
    bool seen_err = false;
    while(pop_frame(&s, &pos, &f) == 0) {
        if(f.type == HWP_MSG_ERROR && f.seq == 3) {
            seen_err = true;
            assert(f.payload_len >= 1);
            assert(f.payload[0] == HWP_ERR_UNKNOWN);
        }
    }
    assert(seen_err);
    printf("  PASS: unknown message type → Error(HWP_ERR_UNKNOWN)\n");
}

/* ── v6-only wire tier enforcement (post-NU6.3) ───────────────────── */

/* Build a well-formed 166-byte v6 TxMeta wire (v6 header constants,
 * empty-bundle transparent + sapling digests, flags within policy) that
 * orchard_signer_feed_meta() accepts. */
static void build_v6_meta_wire(uint8_t buf[ZIP244_TX_META_V6_SIZE]) {
    memset(buf, 0, ZIP244_TX_META_V6_SIZE);
    buf[0]  = 0x06; buf[3]  = 0x80;                                  /* version */
    buf[4]  = 0x98; buf[5]  = 0xB6; buf[6]  = 0x84; buf[7]  = 0xD8;  /* vgi */
    buf[8]  = 0x5B; buf[9]  = 0x16; buf[10] = 0xA5; buf[11] = 0x37;  /* NU6.3 */
    buf[20] = 0x03;                                                  /* orchard_flags */
    buf[61] = 0x03;                                                  /* ironwood_flags */
    zip244_empty_digest("ZTxIdTranspaHash", buf + 102);
    zip244_sapling_empty_digest(buf + 134);
}

/* Wrap output_data in a TX_OUTPUT payload and enqueue the frame. */
static void push_tx_output(Stub* s, uint8_t seq, uint16_t index, uint16_t total,
                           const uint8_t* data, uint16_t data_len) {
    static uint8_t payload[HWP_MAX_PAYLOAD];
    uint16_t plen = hwp_encode_tx_output(payload, index, total, data, data_len);
    push_frame(s, seq, HWP_MSG_TX_OUTPUT, payload, plen);
}

/* Scan the device's TX stream counting ACKs and BAD_FRAME errors. */
static void count_ack_and_bad_frame(const Stub* s, int* acks, int* bad_frames) {
    *acks = 0;
    *bad_frames = 0;
    size_t pos = 0;
    HwpFrame f;
    while(pop_frame(s, &pos, &f) == 0) {
        if(f.type == HWP_MSG_TX_OUTPUT_ACK) (*acks)++;
        if(f.type == HWP_MSG_ERROR && f.payload_len >= 1 &&
           f.payload[0] == HWP_ERR_BAD_FRAME) (*bad_frames)++;
    }
}

static void test_v5_meta_rejected_by_dispatcher(void) {
    /* A legacy 125-byte v5 TxMeta must be answered with
     * Error(HWP_ERR_BAD_FRAME) and no ACK; the signer stays IDLE. */
    Stub s = {0};
    s.exit_after = 40;
    uint8_t v5_meta[125];
    memset(v5_meta, 0, sizeof(v5_meta));
    v5_meta[0] = 0x05;
    push_tx_output(&s, /*seq=*/1, HWP_TX_META_INDEX, 1, v5_meta, sizeof(v5_meta));

    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);
    assert(hwp_dispatcher_run(&d) == HWP_DISP_EXIT_REQUESTED);

    int acks, bad_frames;
    count_ack_and_bad_frame(&s, &acks, &bad_frames);
    assert(bad_frames >= 1);
    assert(acks == 0);
    assert(signer.state == SIGNER_IDLE);
    printf("  PASS: legacy v5 TxMeta (125 B) → Error(BAD_FRAME), no ACK\n");
}

static void test_untagged_action_rejected(uint16_t body_len, const char* label) {
    /* A valid v6 session is opened (meta ACKed), then a legacy UNTAGGED
     * action payload (903 or 1415 bytes — no pool tag) is fed. The
     * dispatcher must reject it with Error(HWP_ERR_BAD_FRAME) and reset
     * the signer. */
    Stub s = {0};
    s.exit_after = 80;
    uint8_t meta[ZIP244_TX_META_V6_SIZE];
    build_v6_meta_wire(meta);
    push_tx_output(&s, /*seq=*/1, HWP_TX_META_INDEX, 1, meta, sizeof(meta));

    static uint8_t action[HWP_ACTION_BODY_MEMO_SIZE]; /* max body size */
    memset(action, 0, sizeof(action));
    assert(body_len <= sizeof(action));
    push_tx_output(&s, /*seq=*/2, 0, 1, action, body_len);

    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);
    assert(hwp_dispatcher_run(&d) == HWP_DISP_EXIT_REQUESTED);

    int acks, bad_frames;
    count_ack_and_bad_frame(&s, &acks, &bad_frames);
    assert(acks == 1);        /* the meta only */
    assert(bad_frames >= 1);  /* the untagged action */
    assert(signer.state == SIGNER_IDLE); /* session was reset */
    printf("  PASS: untagged %s action rejected → Error(BAD_FRAME), signer reset\n",
           label);
}

static void test_bad_pool_tag_rejected(void) {
    /* A correctly-sized (904 B) action whose pool tag is neither 0x00 nor
     * 0x01 must be rejected. */
    Stub s = {0};
    s.exit_after = 80;
    uint8_t meta[ZIP244_TX_META_V6_SIZE];
    build_v6_meta_wire(meta);
    push_tx_output(&s, /*seq=*/1, HWP_TX_META_INDEX, 1, meta, sizeof(meta));

    static uint8_t action[HWP_ACTION_DATA_SIZE_V6_COMPACT];
    memset(action, 0, sizeof(action));
    action[0] = 0x02; /* invalid pool tag */
    push_tx_output(&s, /*seq=*/2, 0, 1, action, sizeof(action));

    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);
    assert(hwp_dispatcher_run(&d) == HWP_DISP_EXIT_REQUESTED);

    int acks, bad_frames;
    count_ack_and_bad_frame(&s, &acks, &bad_frames);
    assert(acks == 1);
    assert(bad_frames >= 1);
    assert(signer.state == SIGNER_IDLE);
    printf("  PASS: pool tag 0x02 rejected → Error(BAD_FRAME), signer reset\n");
}

static void test_null_callbacks_rejected(void) {
    /* Mandatory callbacks (drain/send/tick/sleep/should_exit + the two
     * blocking UI prompts) cannot be NULL — calling hwp_dispatcher_run
     * with a partially-initialised struct returns FATAL up-front
     * rather than crashing later in the loop. */
    Stub s = {0};
    OrchardSignerCtx signer;
    orchard_signer_init(&signer);
    HwpDispatcher d = build_dispatcher(&s, &signer);

    /* Drop one mandatory callback at a time and verify FATAL. */
    HwpDispatcher d2;

    d2 = d; d2.io.serial_drain = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);
    d2 = d; d2.io.serial_send = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);
    d2 = d; d2.ui.review_output = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);
    d2 = d; d2.ui.confirm_tx = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);
    d2 = d; d2.signer = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);

    printf("  PASS: missing mandatory callbacks → HWP_DISP_FATAL\n");
}

int main(void) {
    printf("HWP dispatcher smoke tests:\n");
    test_initial_ping_emitted();
    test_pong_handshake();
    test_fvk_req_emits_correct_fvk();
    test_fvk_req_wrong_network_rejected();
    test_unknown_message_yields_error();
    test_null_callbacks_rejected();

    printf("\nHWP dispatcher v6-only wire tier tests:\n");
    test_v5_meta_rejected_by_dispatcher();
    test_untagged_action_rejected(HWP_ACTION_BODY_COMPACT_SIZE, "903 B (ex-v4)");
    test_untagged_action_rejected(HWP_ACTION_BODY_MEMO_SIZE, "1415 B (ex-v5)");
    test_bad_pool_tag_rejected();
    printf("All dispatcher tests passed.\n");
    return 0;
}
