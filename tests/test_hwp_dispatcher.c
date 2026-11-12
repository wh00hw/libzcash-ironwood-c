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
 * delegation), and — in the second half — whole signing sessions played by
 * a host that tells the truth and by hosts that do not: what the user is
 * shown for each output (change / own address / external), the totals,
 * and which frames end the session. The transactions are real
 * (tests/test_tx_fixture.h); the signer-level view of the same attacks is
 * tests/test_ownership.c.
 */
#include "hwp_dispatcher.h"
#include "base58.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hwp.h"
#include "orchard_signer.h"
#include "zip244.h"
#include "test_tx_fixture.h"

/* ── Stub callback state ──────────────────────────────────────────── */

typedef struct {
    /* Incoming-to-device byte stream (frames the "host" pushes). */
    uint8_t in_buf[65536];
    size_t  in_len;
    size_t  in_pos;

    /* Outgoing-from-device byte stream (frames the device emits). */
    uint8_t out_buf[32768];
    size_t  out_len;

    /* Monotonic ms counter. */
    uint32_t tick_ms;

    /* Loop control. */
    int      iterations;
    int      exit_after;

    /* Counters for assertions. */
    int      review_calls;
    int      confirm_calls;

    /* What the "screen" was asked to show, in order. */
    HwpOutputReview reviews[16];
    char     review_addrs[16][200];
    int      memo_calls;
    uint8_t  last_memo[512];
    int      totals_calls;
    OrchardSignerTotals totals;          /* from review_totals */
    OrchardSignerTotals confirm_totals;  /* from confirm_tx */

    /* The "user": cancel the Nth review_output call (1-based; 0 = never),
     * the totals screen, or the final confirmation. */
    int      cancel_review_at;
    bool     cancel_totals;
    bool     cancel_confirm;
    /* 1: review_output returns 77; 2: review_totals returns -1;
     * 3: confirm_tx returns HWP_UI_EXIT. */
    int      odd_ui;
    /* When set: every Error frame the dispatcher emits is checked, at the
     * moment it is sent, against the rule "an error ends the session" —
     * the signer must already be IDLE with its viewing keys wiped. */
    OrchardSignerCtx* probe_signer;
    int      probe_hits;
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
    if(s->probe_signer && len >= 4 && data[3] == HWP_MSG_ERROR) {
        uint8_t acc = 0;
        for(int i = 0; i < 32; i++) {
            acc |= s->probe_signer->ivk_external[i] | s->probe_signer->ivk_internal[i];
        }
        assert(s->probe_signer->state == SIGNER_IDLE && !s->probe_signer->has_meta);
        assert(acc == 0);
        s->probe_hits++;
    }
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

static HwpUiResult stub_review(const HwpOutputReview* out, void* ctx) {
    Stub* s = (Stub*)ctx;
    assert(out->kind >= HWP_OUTPUT_TRANSPARENT && out->kind <= HWP_OUTPUT_OWN_ADDRESS);
    assert(out->index >= 1 && out->index <= out->total);
    if(s->review_calls < 16) {
        s->reviews[s->review_calls] = *out;
        strncpy(s->review_addrs[s->review_calls], out->address, 199);
        s->reviews[s->review_calls].address = s->review_addrs[s->review_calls];
    }
    s->review_calls++;
    if(s->odd_ui == 1) return (HwpUiResult)77;
    return (s->cancel_review_at == s->review_calls) ? HWP_UI_CANCELLED : HWP_UI_OK;
}

static HwpUiResult stub_review_memo(uint16_t idx, uint16_t total, const char* addr,
                                     const uint8_t memo[512], void* ctx) {
    Stub* s = (Stub*)ctx;
    (void)idx; (void)total; (void)addr;
    s->memo_calls++;
    memcpy(s->last_memo, memo, 512);
    return HWP_UI_OK;
}

static HwpUiResult stub_review_totals(const OrchardSignerTotals* totals, void* ctx) {
    Stub* s = (Stub*)ctx;
    s->totals_calls++;
    s->totals = *totals;
    if(s->odd_ui == 2) return (HwpUiResult)-1;
    return s->cancel_totals ? HWP_UI_CANCELLED : HWP_UI_OK;
}

static HwpUiResult stub_confirm(const OrchardSignerTotals* totals, void* ctx) {
    Stub* s = (Stub*)ctx;
    s->confirm_calls++;
    s->confirm_totals = *totals;
    if(s->odd_ui == 3) return HWP_UI_EXIT;
    return s->cancel_confirm ? HWP_UI_CANCELLED : HWP_UI_OK;
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
            .review_totals = stub_review_totals,
            .review_memo   = stub_review_memo,
            .confirm_tx    = stub_confirm,
        },
        .keys = { .ak = AK, .nk = NK, .rivk = RIVK,
                   .ask = ASK },
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 1; /* exit on first iteration — no host bytes */
    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 8;
    push_frame(&s, /*seq=*/0, HWP_MSG_PONG, NULL, 0);
    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 10;
    /* coin_type = 1 (testnet), matches d.testnet == true. */
    uint8_t coin_le[4] = {0x01, 0x00, 0x00, 0x00};
    push_frame(&s, /*seq=*/7, HWP_MSG_FVK_REQ, coin_le, sizeof(coin_le));
    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 25;
    uint8_t main_coin_le[4] = {133, 0, 0, 0}; /* mainnet, against testnet device */
    push_frame(&s, /*seq=*/9, HWP_MSG_FVK_REQ, main_coin_le, sizeof(main_coin_le));
    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 8;
    /* 0x7F is reserved/unused. */
    push_frame(&s, /*seq=*/3, 0x7F, NULL, 0);
    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
static void build_v6_meta_wire(uint8_t buf[ZIP244_TX_META_V6_EXT_SIZE]) {
    memset(buf, 0, ZIP244_TX_META_V6_EXT_SIZE);
    buf[0]  = 0x06; buf[3]  = 0x80;                                  /* version */
    buf[4]  = 0x98; buf[5]  = 0xB6; buf[6]  = 0x84; buf[7]  = 0xD8;  /* vgi */
    buf[8]  = 0x5B; buf[9]  = 0x16; buf[10] = 0xA5; buf[11] = 0x37;  /* NU6.3 */
    buf[20] = 0x03;                                                  /* orchard_flags */
    buf[61] = 0x03;                                                  /* ironwood_flags */
    zip244_empty_digest("ZTxIdTranspaHash", buf + 102);
    zip244_sapling_empty_digest(buf + 134);
    buf[ZIP244_TX_META_V6_SIZE] = 1; /* coin_type: testnet, the device under test */
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 40;
    uint8_t v5_meta[125];
    memset(v5_meta, 0, sizeof(v5_meta));
    v5_meta[0] = 0x05;
    push_tx_output(&s, /*seq=*/1, HWP_TX_META_INDEX, 1, v5_meta, sizeof(v5_meta));

    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 80;
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    build_v6_meta_wire(meta);
    push_tx_output(&s, /*seq=*/1, HWP_TX_META_INDEX, 1, meta, sizeof(meta));

    static uint8_t action[HWP_ACTION_BODY_MEMO_SIZE]; /* max body size */
    memset(action, 0, sizeof(action));
    assert(body_len <= sizeof(action));
    push_tx_output(&s, /*seq=*/2, 0, 1, action, body_len);

    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    /* A correctly-sized (1416 B) action whose pool tag is neither 0x00 nor
     * 0x01 must be rejected. */
    static Stub s;
    memset(&s, 0, sizeof(s));
    s.exit_after = 80;
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    build_v6_meta_wire(meta);
    push_tx_output(&s, /*seq=*/1, HWP_TX_META_INDEX, 1, meta, sizeof(meta));

    static uint8_t action[HWP_ACTION_DATA_SIZE_V6];
    memset(action, 0, sizeof(action));
    action[0] = 0x02; /* invalid pool tag */
    push_tx_output(&s, /*seq=*/2, 0, 1, action, sizeof(action));

    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    static Stub s;
    memset(&s, 0, sizeof(s));
    OrchardSignerCtx signer;
    orchard_signer_init(&signer, 1);
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
    /* The totals screen is not optional any more ... */
    d2 = d; d2.ui.review_totals = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);
    /* ... and neither is the device's own viewing key. */
    d2 = d; d2.keys.rivk = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);
    d2 = d; d2.keys.ak = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);
    d2 = d; d2.signer = NULL;
    assert(hwp_dispatcher_run(&d2) == HWP_DISP_FATAL);

    printf("  PASS: missing mandatory callbacks → HWP_DISP_FATAL\n");
}

/* ── Whole sessions: an honest host, and hosts that lie ───────────── */

/* The wallet's keys as the firmware holds them (ask derived from the
 * vector's seed; ak / nk / rivk are the orchard-crate FVK bytes). */
static uint8_t W_ASK[32];
static void wallet_keys_init(void) {
    uint8_t sk[32], nk[32], rivk[32], ak[32];
    orchard_derive_account_sk(fx_wallet()->seed, fx_wallet()->coin_type, 0, sk);
    orchard_derive_keys(sk, W_ASK, nk, rivk);
    redpallas_derive_ak(W_ASK, ak);
    assert(memcmp(ak, fx_wallet()->ak, 32) == 0);
    assert(memcmp(nk, fx_wallet()->nk, 32) == 0);
    assert(memcmp(rivk, fx_wallet()->rivk, 32) == 0);
}

static HwpDispatcher build_wallet_dispatcher(Stub* stub, OrchardSignerCtx* signer) {
    HwpDispatcher d = build_dispatcher(stub, signer);
    d.keys.ak = fx_wallet()->ak;
    d.keys.nk = fx_wallet()->nk;
    d.keys.rivk = fx_wallet()->rivk;
    d.keys.ask = W_ASK;
    d.testnet = (fx_wallet()->coin_type == 1);
    return d;
}

/* A transaction as the host holds it: what each action really contains,
 * and what the host will tell the device about it (the two start equal;
 * a test edits `told` to lie). */
#define TX_MAX 8
typedef struct {
    uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
    int n;
    uint8_t action[TX_MAX][820];
    FxNote told[TX_MAX];
    bool compact[TX_MAX];
} Tx;

static Tx g_tx;
static OrchardSignerCtx g_shadow, g_signer;
static Stub g_stub;

static void tx_begin(Tx* tx, uint32_t branch, int64_t ironwood_vb) {
    memset(tx, 0, sizeof(*tx));
    fx_build_meta(tx->meta, branch, 0, ironwood_vb);
}

static void tx_add(Tx* tx, const FxNote* note, bool compact) {
    assert(tx->n < TX_MAX);
    fx_build_action(tx->action[tx->n], note, (uint8_t)(tx->n + 1));
    tx->told[tx->n] = *note;
    tx->compact[tx->n] = compact;
    tx->n++;
}

/* The transaction's real sighash, from an honest replay of the same
 * actions through a second signer (so a device that reaches verify() has
 * the right value to compare against). Returns false if even the honest
 * replay is refused — then no sentinel value exists and the test sends
 * zeros. */
static bool tx_sighash(const Tx* tx, uint8_t out[32]) {
    OrchardSignerFvk fvk = fx_wallet_fvk();
    memset(out, 0, 32);
    orchard_signer_init(&g_shadow, 1);
    if(orchard_signer_feed_meta(&g_shadow, &fvk, tx->meta, sizeof(tx->meta),
                                (uint16_t)tx->n) != SIGNER_OK) {
        return false;
    }
    for(int i = 0; i < tx->n; i++) {
        /* The digest only depends on the action bytes: hash them through
         * the pool state directly. */
        Zip244ActionsState* st = (tx->told[i].pool == ZIP244_POOL_IRONWOOD)
                                     ? &g_shadow.ironwood_actions_state
                                     : &g_shadow.actions_state;
        assert(zip244_hash_action(st, tx->action[i], 820));
    }
    fx_sighash(&g_shadow, out);
    orchard_signer_reset(&g_shadow);
    return true;
}

static void push_action(Stub* s, uint8_t seq, uint16_t index, uint16_t total, const Tx* tx, int i) {
    static uint8_t body[HWP_ACTION_DATA_SIZE_V6];
    size_t n = 0;
    body[n++] = (uint8_t)tx->told[i].pool;
    memcpy(body + n, tx->action[i], 820); n += 820;
    memcpy(body + n, tx->told[i].recipient, 43); n += 43;
    for(int b = 0; b < 8; b++) body[n++] = (uint8_t)(tx->told[i].value >> (8 * b));
    memcpy(body + n, tx->told[i].rseed, 32); n += 32;
    if(!tx->compact[i]) {
        memcpy(body + n, tx->told[i].memo, 512); n += 512;
    }
    push_tx_output(s, seq, index, total, body, (uint16_t)n);
}

/* meta, every action in order, sentinel. */
static void push_whole_tx(Stub* s, const Tx* tx) {
    uint8_t sighash[32];
    tx_sighash(tx, sighash);
    uint8_t seq = 1;
    push_tx_output(s, seq++, HWP_TX_META_INDEX, (uint16_t)tx->n, tx->meta, sizeof(tx->meta));
    for(int i = 0; i < tx->n; i++) push_action(s, seq++, (uint16_t)i, (uint16_t)tx->n, tx, i);
    push_tx_output(s, seq++, (uint16_t)tx->n, (uint16_t)tx->n, sighash, 32);
}

static void push_sign_req(Stub* s, uint8_t seq, const Tx* tx, const char* recipient,
                          uint64_t host_amount, uint64_t host_fee) {
    static HwpSignReq req;
    memset(&req, 0, sizeof(req));
    tx_sighash(tx, req.sighash);
    req.alpha[0] = 9;
    req.amount = host_amount;
    req.fee = host_fee;
    req.recipient_len = (uint8_t)strlen(recipient);
    memcpy(req.recipient, recipient, req.recipient_len);
    static uint8_t payload[HWP_SIGN_REQ_FIXED + HWP_MAX_RECIPIENT];
    uint16_t plen = hwp_encode_sign_req(payload, &req);
    push_frame(s, seq, HWP_MSG_SIGN_REQ, payload, plen);
}

typedef struct {
    int acks, sign_rsps, t_sign_rsps, errors;
    int first_error; /* HwpErrorCode of the first Error frame, -1 if none */
    int last_error;
} Reply;

static Reply run_session(Stub* s, HwpDispatcher* d) {
    s->exit_after = 4000;
    assert(hwp_dispatcher_run(d) == HWP_DISP_EXIT_REQUESTED);
    /* The dispatcher never leaves a session (or its viewing keys) behind. */
    assert(d->signer->state == SIGNER_IDLE);
    assert(fx_ivks_wiped(d->signer));
    assert(s->in_pos == s->in_len); /* every host frame was consumed */

    Reply r = {0, 0, 0, 0, -1, -1};
    size_t pos = 0;
    static HwpFrame f;
    while(pop_frame(s, &pos, &f) == 0) {
        if(f.type == HWP_MSG_TX_OUTPUT_ACK) r.acks++;
        if(f.type == HWP_MSG_SIGN_RSP) r.sign_rsps++;
        if(f.type == HWP_MSG_TRANSPARENT_SIGN_RSP) r.t_sign_rsps++;
        if(f.type == HWP_MSG_ERROR) {
            assert(f.payload_len >= 1);
            if(r.errors == 0) r.first_error = f.payload[0];
            r.last_error = f.payload[0];
            r.errors++;
        }
    }
    return r;
}

static Stub* fresh_stub(void) {
    memset(&g_stub, 0, sizeof(g_stub));
    orchard_signer_init(&g_signer, 1);
    g_stub.probe_signer = &g_signer;
    return &g_stub;
}

static void ua_of(char out[200], const uint8_t recipient[43]) {
    assert(orchard_encode_ua_raw(recipient, recipient + 11, "utest", out, 200) > 0);
}

/* The standard story: 3 ZEC to a stranger with a memo, change back, one
 * padding output; fee 0.0001. */
static void tx_standard(Tx* tx, const uint8_t change_to[43]) {
    uint8_t to[43], rnd[43];
    fx_addr_foreign(to);
    fx_addr(rnd, ADDRESS_VECTORS[7].d, ADDRESS_VECTORS[7].pk_d);
    FxNote pay = fx_note(to, 3 * FX_ZEC, "invoice 42", 1);
    FxNote chg = fx_note(change_to, 7 * FX_ZEC - 10000, NULL, 2);
    FxNote pad = fx_note(rnd, 0, NULL, 3);
    tx_begin(tx, FX_BRANCH_NU6_3, 10000);
    tx_add(tx, &pay, false);
    tx_add(tx, &chg, false);
    tx_add(tx, &pad, false);
}

static void test_session_send_with_change(void) {
    Stub* s = fresh_stub();
    uint8_t change[43], to[43];
    char ua_to[200], ua_change[200];
    fx_addr_change(change);
    fx_addr_foreign(to);
    ua_of(ua_to, to);
    ua_of(ua_change, change);
    tx_standard(&g_tx, change);
    push_whole_tx(s, &g_tx);
    /* The host's SIGN_REQ claims an amount and a fee of its own. */
    push_sign_req(s, 20, &g_tx, ua_to, /*amount*/ 1, /*fee*/ 2);

    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    Reply r = run_session(s, &d);

    assert(r.errors == 0);
    assert(r.acks == 5); /* meta + 3 actions + sentinel */
    /* Two screens, not three: the padding output is not a payment. */
    assert(s->review_calls == 2);
    assert(s->reviews[0].kind == HWP_OUTPUT_EXTERNAL);
    assert(s->reviews[0].value == 3 * FX_ZEC && s->reviews[0].has_memo);
    assert(s->reviews[0].index == 1 && s->reviews[0].total == 2);
    assert(strcmp(s->reviews[0].address, ua_to) == 0);
    assert(s->reviews[1].kind == HWP_OUTPUT_OWN_CHANGE);
    assert(s->reviews[1].value == 7 * FX_ZEC - 10000 && !s->reviews[1].has_memo);
    assert(s->reviews[1].index == 2 && s->reviews[1].total == 2);
    assert(strcmp(s->reviews[1].address, ua_change) == 0);
    /* The memo shown is the verified one. */
    assert(s->memo_calls == 1);
    assert(memcmp(s->last_memo, g_tx.told[0].memo, 512) == 0);
    /* The totals: device arithmetic. */
    assert(s->totals_calls == 1);
    assert(s->totals.total_leaving == 3 * FX_ZEC + 10000 && s->totals.fee == 10000);
    assert(s->totals.own_internal == 7 * FX_ZEC - 10000);
    assert(s->totals.n_external == 1 && s->totals.n_own_internal == 1 &&
           s->totals.n_zero_value == 1);
    /* Final confirmation: the same device numbers, not the host's 1 and 2. */
    assert(s->confirm_calls == 1);
    assert(memcmp(&s->confirm_totals, &s->totals, sizeof(s->totals)) == 0);
    assert(r.sign_rsps == 1);
    printf("  PASS: honest send: [payment, change] shown, padding counted, device totals, signed\n");
}

static void test_session_change_redirected(void) {
    Stub* s = fresh_stub();
    uint8_t attacker[43], to[43];
    char ua_to[200];
    fx_addr_foreign_change(attacker);
    fx_addr_foreign(to);
    ua_of(ua_to, to);
    tx_standard(&g_tx, attacker);
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, ua_to, 3 * FX_ZEC, 10000);

    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    Reply r = run_session(s, &d);
    assert(r.errors == 0);
    assert(s->review_calls == 2);
    assert(s->reviews[0].kind == HWP_OUTPUT_EXTERNAL);
    assert(s->reviews[1].kind == HWP_OUTPUT_EXTERNAL); /* not "change" */
    assert(s->totals.n_external == 2 && s->totals.n_own_internal == 0);
    assert(s->totals.total_leaving == 10 * FX_ZEC); /* not 3.0001 */
    assert(s->confirm_totals.total_leaving == 10 * FX_ZEC);
    printf("  PASS: \"change\" to a foreign address: shown EXTERNAL, 10 ZEC leaving (host said 3)\n");

    /* A user who reads that and refuses: no signature, session over. */
    s = fresh_stub();
    s->cancel_totals = true;
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, ua_to, 3 * FX_ZEC, 10000);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_USER_CANCELLED);
    assert(r.acks == 4 && r.sign_rsps == 0 && s->confirm_calls == 0);
    printf("  PASS: user refuses the totals -> USER_CANCELLED, SIGN_REQ gets no signature\n");
}

static void test_session_own_address(void) {
    Stub* s = fresh_stub();
    uint8_t own[43];
    char ua_own[200];
    fx_addr_own_other(own);
    ua_of(ua_own, own);
    FxNote self = fx_note(own, 2 * FX_ZEC, NULL, 1);
    tx_begin(&g_tx, FX_BRANCH_NU7, 10000);
    tx_add(&g_tx, &self, false);
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, ua_own, 0, 0);
    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    Reply r = run_session(s, &d);
    assert(r.errors == 0 && r.sign_rsps == 1);
    assert(s->review_calls == 1 && s->reviews[0].kind == HWP_OUTPUT_OWN_ADDRESS);
    assert(s->totals.total_leaving == 10000 && s->totals.own_external == 2 * FX_ZEC);
    printf("  PASS: payment to an own address (non-default diversifier, NU7): OWN_ADDRESS\n");
}

static void test_session_compact_and_memo_attacks(void) {
    uint8_t change[43];
    fx_addr_change(change);
    Stub* s;
    HwpDispatcher d;
    Reply r;

    /* The payment sent as the compact body. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    g_tx.compact[0] = true;
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_MEMO_REQUIRED);
    assert(r.acks == 1 && s->review_calls == 0 && s->totals_calls == 0);
    printf("  PASS: compact body on the payment -> Error(MEMO_REQUIRED), nothing shown\n");

    /* The change sent as the compact body. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    g_tx.compact[1] = true;
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_MEMO_REQUIRED);
    assert(r.acks == 2 && s->review_calls == 0);
    printf("  PASS: compact body on own change -> Error(MEMO_REQUIRED)\n");

    /* A different memo declared than the one on chain. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    fx_memo_text(g_tx.told[0].memo, "invoice 43");
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_MEMO_MISMATCH);
    assert(r.acks == 1 && s->review_calls == 0 && s->memo_calls == 0);
    printf("  PASS: substituted memo -> Error(MEMO_MISMATCH)\n");

    /* Garbage ciphertext on the change. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    g_tx.action[1][160 + 40] ^= 0x10;
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_MEMO_MISMATCH);
    assert(r.acks == 2 && s->review_calls == 0);
    printf("  PASS: corrupted ciphertext on own change -> Error(MEMO_MISMATCH)\n");

    /* A different recipient declared than the one committed to. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    memcpy(g_tx.told[0].recipient, change, 43); /* "it's just change" */
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_NOTE_COMMITMENT_MISMATCH);
    assert(r.acks == 1 && s->review_calls == 0);
    printf("  PASS: payment declared as the wallet's change address -> NOTE_COMMITMENT_MISMATCH\n");
}

static void test_session_memo_without_screen(void) {
    /* A device with no memo screen does not sign a memo it cannot show —
     * and does not ask the user to approve the output first. */
    Stub* s = fresh_stub();
    uint8_t change[43];
    fx_addr_change(change);
    tx_standard(&g_tx, change);
    push_whole_tx(s, &g_tx);
    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    d.ui.review_memo = NULL;
    Reply r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_LIMIT_EXCEEDED);
    assert(r.acks == 4 && s->review_calls == 0 && s->totals_calls == 0);
    printf("  PASS: memo and no review_memo callback -> Error(LIMIT_EXCEEDED), not skipped\n");
}

static void test_session_limits(void) {
    Stub* s;
    HwpDispatcher d;
    Reply r;
    uint8_t to[43];
    fx_addr_foreign(to);

    /* More actions than the device reviews. */
    s = fresh_stub();
    tx_begin(&g_tx, FX_BRANCH_NU6_3, 0);
    push_tx_output(s, 1, HWP_TX_META_INDEX, ORCHARD_SIGNER_MAX_ACTIONS + 1, g_tx.meta,
                   sizeof(g_tx.meta));
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_LIMIT_EXCEEDED && r.acks == 0);
    printf("  PASS: too many actions -> Error(LIMIT_EXCEEDED) at TxMeta\n");

#if ORCHARD_SIGNER_MAX_MEMOS < ORCHARD_SIGNER_MAX_ACTIONS && ORCHARD_SIGNER_MAX_MEMOS < TX_MAX
    s = fresh_stub();
    tx_begin(&g_tx, FX_BRANCH_NU6_3, 0);
    for(int i = 0; i <= ORCHARD_SIGNER_MAX_MEMOS; i++) {
        FxNote o = fx_note(to, 1000, "memo", (uint8_t)(i + 1));
        tx_add(&g_tx, &o, false);
    }
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_LIMIT_EXCEEDED);
    assert(r.acks == 1 + ORCHARD_SIGNER_MAX_MEMOS && s->review_calls == 0);
    printf("  PASS: one memo more than the pool -> Error(LIMIT_EXCEEDED), nothing shown\n");
#else
    printf("  SKIP: memo pool == action table in this build (see the FlipZcash-tuned run)\n");
#endif
}

static void test_session_reordered(void) {
    uint8_t change[43];
    fx_addr_change(change);
    uint8_t sighash[32];
    Stub* s;
    HwpDispatcher d;
    Reply r;

    tx_standard(&g_tx, change);
    tx_sighash(&g_tx, sighash);

    /* Actions out of order: 1 before 0. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 1, 3, &g_tx, 1);
    push_action(s, 3, 0, 3, &g_tx, 0);
    push_action(s, 4, 2, 3, &g_tx, 2);
    push_tx_output(s, 5, 3, 3, sighash, 32);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_INVALID_STATE);
    assert(r.acks == 1 && s->review_calls == 0 && r.errors >= 4);
    printf("  PASS: actions out of order -> INVALID_STATE, session over, later frames refused\n");

    /* An action repeated (the change shown once, counted... never). */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 0, 3, &g_tx, 0);
    push_action(s, 3, 0, 3, &g_tx, 0);
    push_action(s, 4, 1, 3, &g_tx, 1);
    push_action(s, 5, 2, 3, &g_tx, 2);
    push_tx_output(s, 6, 3, 3, sighash, 32);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_INVALID_STATE && r.acks == 2 && s->review_calls == 0);
    printf("  PASS: repeated action -> INVALID_STATE\n");

    /* Sentinel before the last action (the change is "forgotten"). */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 0, 3, &g_tx, 0);
    push_tx_output(s, 3, 3, 3, sighash, 32);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_INVALID_STATE && r.acks == 2);
    assert(s->review_calls == 0 && s->totals_calls == 0); /* user not even asked */
    printf("  PASS: sentinel with actions missing -> INVALID_STATE before any prompt\n");

    /* A sentinel that claims a smaller transaction than the TxMeta did. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 0, 3, &g_tx, 0);
    push_tx_output(s, 3, 1, 1, sighash, 32);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_INVALID_STATE && s->review_calls == 0);
    /* ... and an action frame that does. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 0, 1, &g_tx, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_INVALID_STATE && r.acks == 1);
    printf("  PASS: frames disagreeing with TxMeta about the action count -> INVALID_STATE\n");

    /* TxMeta twice: the second one starts a new transaction from nothing
     * (the action fed in between is forgotten, so the sentinel for a
     * 1-action reading of the stream fails). */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 0, 3, &g_tx, 0);
    push_tx_output(s, 3, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 4, 1, 3, &g_tx, 1); /* would be next if action 0 had survived */
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 3 && r.errors == 1 && r.first_error == HWP_ERR_INVALID_STATE);
    printf("  PASS: a second TxMeta restarts from nothing (earlier actions forgotten)\n");

    /* SIGN_REQ without a verified transaction; and a transparent sign
     * request likewise (it used to need only the transparent digest). */
    s = fresh_stub();
    char ua[200];
    ua_of(ua, change);
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 0, 3, &g_tx, 0);
    push_sign_req(s, 3, &g_tx, ua, 0, 0);
    {
        uint8_t tsr[HWP_TX_OUTPUT_HEADER + 60] = {0};
        tsr[2] = 1; /* total_inputs = 1 */
        push_frame(s, 4, HWP_MSG_TRANSPARENT_SIGN_REQ, tsr, sizeof(tsr));
    }
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.errors == 2 && r.first_error == HWP_ERR_INVALID_STATE);
    assert(r.last_error == HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    assert(r.sign_rsps == 0 && r.t_sign_rsps == 0 && s->confirm_calls == 0);
    printf("  PASS: SIGN_REQ / TRANSPARENT_SIGN_REQ before VERIFIED -> no signature\n");
}

static void test_session_branch_and_recipient(void) {
    uint8_t change[43], to[43];
    char ua_to[200], ua_other[200];
    fx_addr_change(change);
    fx_addr_foreign(to);
    ua_of(ua_to, to);
    Stub* s;
    HwpDispatcher d;
    Reply r;

    /* Branch the firmware was not built for. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    fx_build_meta(g_tx.meta, FX_BRANCH_NU6, 0, 10000);
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_BRANCH_NOT_ALLOWED && r.acks == 0);
    printf("  PASS: branch outside the allow-list -> Error(BRANCH_NOT_ALLOWED)\n");

    /* SIGN_REQ.recipient is ignored: whatever the host writes there — an
     * address that is not in the transaction, a t-address, garbage, or
     * nothing — changes neither the outcome nor any screen. */
    {
        uint8_t stranger[43];
        fx_addr(stranger, ADDRESS_VECTORS[9].d, ADDRESS_VECTORS[9].pk_d);
        ua_of(ua_other, stranger);
    }
    const char* names[] = {ua_other, "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU",
                           "u1mainnetlookingstring", "garbage", ""};
    for(size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        s = fresh_stub();
        tx_standard(&g_tx, change);
        push_whole_tx(s, &g_tx);
        push_sign_req(s, 20, &g_tx, names[i], 0, 0);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.errors == 0 && r.acks == 5 && r.sign_rsps == 1 && s->confirm_calls == 1);
        assert(memcmp(&s->confirm_totals, &s->totals, sizeof(s->totals)) == 0);
    }
    printf("  PASS: SIGN_REQ recipient (foreign, t-addr, garbage, empty) is ignored\n");
    tx_standard(&g_tx, change);

    /* The user refuses at the final confirmation: the session ends; a
     * second SIGN_REQ does not get a second prompt. */
    s = fresh_stub();
    s->cancel_confirm = true;
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, ua_to, 0, 0);
    push_sign_req(s, 21, &g_tx, ua_to, 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_USER_CANCELLED && r.errors == 2);
    assert(s->confirm_calls == 1 && r.sign_rsps == 0);
    printf("  PASS: refusal at final confirmation ends the session (no re-prompt, no signature)\n");

    /* The user cancels at the first output. */
    s = fresh_stub();
    s->cancel_review_at = 1;
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, ua_to, 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_USER_CANCELLED && r.sign_rsps == 0);
    assert(s->review_calls == 1 && s->totals_calls == 0 && s->confirm_calls == 0);
    printf("  PASS: cancel at an output -> USER_CANCELLED, no totals, no signature\n");
}

static void test_session_second_tx_reconfirms(void) {
    /* Transaction A is verified and its final confirmation given, but not
     * every action is signed (so the session is not closed by the device).
     * The host then aborts into transaction B — which pays the attacker.
     * B must go through its own review AND its own final confirmation. */
    Stub* s = fresh_stub();
    uint8_t change[43], to[43], attacker[43];
    char ua_to[200];
    fx_addr_change(change);
    fx_addr_foreign(to);
    fx_addr_foreign_change(attacker);
    ua_of(ua_to, to);

    tx_standard(&g_tx, change);
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, ua_to, 0, 0);           /* A: confirm #1, signature #1 */

    static Tx tx_b;
    tx_standard(&tx_b, attacker);
    /* B's frames: its TxMeta ends A — VERIFIED, one signature given of
     * three allowed — and starts clean. */
    {
        uint8_t sighash[32];
        tx_sighash(&tx_b, sighash);
        uint8_t seq = 30;
        push_tx_output(s, seq++, HWP_TX_META_INDEX, 3, tx_b.meta, sizeof(tx_b.meta));
        for(int i = 0; i < 3; i++) push_action(s, seq++, (uint16_t)i, 3, &tx_b, i);
        push_tx_output(s, seq++, 3, 3, sighash, 32);
    }
    push_sign_req(s, 40, &tx_b, ua_to, 0, 0);            /* B: must prompt again */

    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    Reply r = run_session(s, &d);
    assert(r.errors == 0);
    assert(s->review_calls == 4);   /* A: 2 screens, B: 2 screens */
    assert(s->totals_calls == 2);
    assert(s->confirm_calls == 2);  /* one final confirmation per transaction */
    assert(s->confirm_totals.total_leaving == 10 * FX_ZEC); /* B's numbers */
    assert(r.sign_rsps == 2);
    printf("  PASS: a second transaction gets its own review and final confirmation\n");
}

/* ══ Regression tests for the November 2026 independent review ═════════
 * Each test is a port of one of the reviewer's attack drivers (A1…A7 and
 * the table of attempts A4.x / A5.x). "Before" in the comments is what the
 * reviewed tree did. */

static void meta_set_vb(uint8_t* meta, int64_t orchard_vb, int64_t ironwood_vb) {
    for(int i = 0; i < 8; i++) meta[21 + i] = (uint8_t)((uint64_t)orchard_vb >> (8 * i));
    for(int i = 0; i < 8; i++) meta[62 + i] = (uint8_t)((uint64_t)ironwood_vb >> (8 * i));
}

static size_t t_out_wire(uint8_t* b, uint8_t tag, uint64_t v) {
    for(int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    b[8] = 25; b[9] = 0;
    b[10] = 0x76; b[11] = 0xa9; b[12] = 0x14;
    memset(b + 13, tag, 20);
    b[33] = 0x88; b[34] = 0xac;
    return 35;
}
static size_t t_in_wire(uint8_t* b, uint8_t tag, uint64_t v) {
    memset(b, tag, 32); memset(b + 32, 0, 4); memset(b + 36, 0xff, 4);
    for(int i = 0; i < 8; i++) b[40 + i] = (uint8_t)(v >> (8 * i));
    b[48] = 25; b[49] = 0;
    b[50] = 0x76; b[51] = 0xa9; b[52] = 0x14;
    memset(b + 53, tag, 20);
    b[73] = 0x88; b[74] = 0xac;
    return 75;
}
static void push_t(Stub* s, uint8_t type, uint16_t idx, uint16_t tot, const uint8_t* data,
                   uint16_t n) {
    uint8_t pl[300];
    pl[0] = (uint8_t)idx; pl[1] = (uint8_t)(idx >> 8);
    pl[2] = (uint8_t)tot; pl[3] = (uint8_t)(tot >> 8);
    if(n) memcpy(pl + 4, data, n);
    push_frame(s, 3, type, pl, (uint16_t)(4 + n));
}
/* The transparent digest of `n` outputs, as the host computes it. */
static void t_digest_of(const uint8_t outs[][35], int n, uint8_t dg[32]) {
    Zip244TransparentState ts;
    zip244_transparent_init(&ts);
    for(int i = 0; i < n; i++) assert(zip244_hash_transparent_output(&ts, outs[i], 35));
    zip244_transparent_digest(&ts, dg);
}

/* A1 (F1, critical). Ironwood-only transaction: the wallet pays 3 ZEC, gets
 * 2 ZEC change, and the real Ironwood value balance is +5 ZEC — a 5 ZEC fee.
 * The host declares an ORCHARD value balance of -(5 ZEC - 10000) although
 * the transaction has no Orchard action.
 * Before: fee shown 10000, total leaving 3.0001 ZEC, two signatures given,
 * over the sighash of the transaction with no Orchard bundle (fee 5 ZEC).
 * Now: refused with EMPTY_POOL_BALANCE when the last action arrives. */
static void test_atk_a1_unbound_value_balance(void) {
    Stub* s = fresh_stub();
    uint8_t to[43], change[43];
    char ua_to[200];
    fx_addr_foreign(to);
    fx_addr_change(change);
    ua_of(ua_to, to);
    const int64_t real_fee = 5 * (int64_t)FX_ZEC;

    FxNote pay = fx_note(to, 3 * FX_ZEC, NULL, 1);
    FxNote chg = fx_note(change, 2 * FX_ZEC, NULL, 2);
    tx_begin(&g_tx, FX_BRANCH_NU6_3, real_fee);
    tx_add(&g_tx, &pay, false);
    tx_add(&g_tx, &chg, false);

    /* What the lie relied on: the sighash does not depend on the value
     * balance (or the flags) of a pool that has no action. */
    uint8_t h_true[32], h_lie[32];
    tx_sighash(&g_tx, h_true);
    meta_set_vb(g_tx.meta, -(real_fee - 10000), real_fee);
    {
        /* shadow replay without the signer's own check */
        Zip244TxMeta m;
        Zip244ActionsState o, w;
        assert(zip244_parse_tx_meta(g_tx.meta, sizeof(g_tx.meta), &m));
        zip244_actions_init_pool(&o, ZIP244_POOL_ORCHARD, true);
        zip244_actions_init_pool(&w, ZIP244_POOL_IRONWOOD, true);
        for(int i = 0; i < g_tx.n; i++) assert(zip244_hash_action(&w, g_tx.action[i], 820));
        zip244_shielded_sighash_v6(&m, &o, &w, h_lie);
    }
    assert(memcmp(h_true, h_lie, 32) == 0);

    uint8_t seq = 1;
    push_tx_output(s, seq++, HWP_TX_META_INDEX, 2, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, seq++, 0, 2, &g_tx, 0);
    push_action(s, seq++, 1, 2, &g_tx, 1);
    push_tx_output(s, seq++, 2, 2, h_lie, 32);
    {
        static HwpSignReq req;
        memset(&req, 0, sizeof(req));
        memcpy(req.sighash, h_lie, 32);
        req.recipient_len = (uint8_t)strlen(ua_to);
        memcpy(req.recipient, ua_to, req.recipient_len);
        static uint8_t payload[HWP_SIGN_REQ_FIXED + HWP_MAX_RECIPIENT];
        uint16_t plen = hwp_encode_sign_req(payload, &req);
        push_frame(s, seq++, HWP_MSG_SIGN_REQ, payload, plen);
        push_frame(s, seq++, HWP_MSG_SIGN_REQ, payload, plen);
    }
    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    Reply r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_EMPTY_POOL_BALANCE);
    assert(r.acks == 2);                       /* meta + first action */
    assert(s->review_calls == 0 && s->totals_calls == 0 && s->confirm_calls == 0);
    assert(r.sign_rsps == 0);
    printf("  PASS: A1 value balance of a pool without actions -> EMPTY_POOL_BALANCE, nothing shown, no signature\n");

    /* The mirror image: Orchard-only transaction, Ironwood value balance. */
    s = fresh_stub();
    pay.pool = ZIP244_POOL_ORCHARD;
    chg.pool = ZIP244_POOL_ORCHARD;
    tx_begin(&g_tx, FX_BRANCH_NU6_3, 0);
    tx_add(&g_tx, &pay, false);
    tx_add(&g_tx, &chg, false);
    meta_set_vb(g_tx.meta, real_fee, -(real_fee - 10000));
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_EMPTY_POOL_BALANCE && r.sign_rsps == 0 && s->totals_calls == 0);

    /* The honest version of the same transaction shows its real fee. The
     * flags of the absent pool are whatever the host's PCZT says (0x03
     * here): not hashed, not used. */
    s = fresh_stub();
    meta_set_vb(g_tx.meta, real_fee, 0);
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, "", 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.errors == 0 && r.sign_rsps == 1);
    assert(s->totals.fee == (uint64_t)real_fee);
    assert(s->totals.total_leaving == 3 * FX_ZEC + (uint64_t)real_fee);
    printf("  PASS: A1 both directions; the honest transaction shows its real 5 ZEC fee\n");

    /* A1b: no actions at all, Orchard value balance 777. Before: totals
     * screen "fee 777". Now: no session. */
    s = fresh_stub();
    tx_begin(&g_tx, FX_BRANCH_NU6_3, 0);
    meta_set_vb(g_tx.meta, 777, 0);
    push_tx_output(s, 1, HWP_TX_META_INDEX, 0, g_tx.meta, sizeof(g_tx.meta));
    {
        uint8_t z[32] = {0};
        push_tx_output(s, 2, 0, 0, z, 32);
    }
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 0 && r.errors == 2 && r.first_error == HWP_ERR_BAD_FRAME);
    assert(s->totals_calls == 0);
    printf("  PASS: A1b transaction with zero actions refused at TxMeta\n");
}

/* A2 (F5). The host pays the attacker and adds a zero-value padding output
 * addressed to the merchant the user means to pay, then names the merchant
 * in SIGN_REQ. Before: the final confirmation showed the merchant's
 * address, which no review screen had shown. Now: confirm_tx has no address
 * parameter at all; the only address ever shown is the attacker's, on its
 * review screen. A5.1: same with the wallet's own change address in a z->t
 * sweep. */
static void test_atk_a2_final_screen_shows_no_host_string(void) {
    Stub* s = fresh_stub();
    uint8_t attacker[43], merchant[43];
    char ua_attacker[200], ua_merchant[200];
    fx_addr_foreign(attacker);
    fx_addr(merchant, ADDRESS_VECTORS[7].d, ADDRESS_VECTORS[7].pk_d);
    ua_of(ua_attacker, attacker);
    ua_of(ua_merchant, merchant);

    FxNote pay = fx_note(attacker, 3 * FX_ZEC, NULL, 1);
    FxNote pad = fx_note(merchant, 0, NULL, 2);
    tx_begin(&g_tx, FX_BRANCH_NU6_3, 10000);
    tx_add(&g_tx, &pay, false);
    tx_add(&g_tx, &pad, false);
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, ua_merchant, 0, 0);
    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    Reply r = run_session(s, &d);
    /* The transaction is what it is — and the user saw exactly that. */
    assert(r.errors == 0 && r.sign_rsps == 1);
    assert(s->review_calls == 1 && s->reviews[0].kind == HWP_OUTPUT_EXTERNAL);
    assert(strcmp(s->review_addrs[0], ua_attacker) == 0);
    assert(s->reviews[0].memo == HWP_MEMO_NONE && !s->reviews[0].has_memo);
    assert(s->confirm_calls == 1);
    assert(s->confirm_totals.n_external == 1 && s->confirm_totals.n_zero_value == 1);
    assert(s->confirm_totals.total_leaving == 3 * FX_ZEC + 10000);
    printf("  PASS: A2 final confirmation carries device totals only; no host-named address exists to show\n");
}

/* A3 / A6 / A7 (F2-F4). Transparent inputs and transparent signing. Before:
 * inputs were hashed into a digest the network rejects, and after one
 * approved session the device answered 200/200 TRANSPARENT_SIGN_REQ frames
 * with ECDSA signatures over a host-chosen node, with no confirmation.
 * Now: any transparent input ends the session; TRANSPARENT_SIGN_REQ is
 * refused unconditionally. */
static void test_atk_a3_transparent_inputs_refused(void) {
    uint8_t change[43];
    fx_addr_change(change);
    uint8_t in0[80];
    uint8_t outs[1][35];
    size_t il = t_in_wire(in0, 0xA1, 9 * FX_ZEC);
    t_out_wire(outs[0], 0xB2, 1 * FX_ZEC);
    uint8_t dg[32];
    t_digest_of(outs, 1, dg);
    Stub* s;
    HwpDispatcher d;
    Reply r;

    /* (i) t-in + t-out + shielded change. */
    s = fresh_stub();
    FxNote chg = fx_note(change, 8 * FX_ZEC - 10000, NULL, 1);
    tx_begin(&g_tx, FX_BRANCH_NU6_3, -(int64_t)(8 * FX_ZEC - 10000));
    tx_add(&g_tx, &chg, false);
    memcpy(g_tx.meta + 102, dg, 32);
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 0, 1, in0, (uint16_t)il);
    push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, outs[0], 35);
    push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 1, 1, dg, 32);
    push_action(s, 5, 0, 1, &g_tx, 0);
    push_t(s, HWP_MSG_TRANSPARENT_SIGN_REQ, 0, 1, in0, (uint16_t)il);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    assert(r.acks == 1 && r.errors == 5);     /* meta ACKed; every later frame an error */
    assert(r.sign_rsps == 0 && r.t_sign_rsps == 0 && s->review_calls == 0);
    printf("  PASS: A3 transparent input -> TRANSPARENT_INPUTS_UNSUPPORTED, session over\n");

    /* A5.7: the 48-byte input that used to be read two bytes past its end. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    {
        uint8_t shorti[48];
        memset(shorti, 0x11, sizeof(shorti));
        push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 0, 1, shorti, 48);
    }
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.first_error == HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED && r.acks == 1);

    /* (ii) A7: an honest z->t sweep, fully reviewed and VERIFIED, then 200
     * transparent signing requests over host-chosen data. */
    s = fresh_stub();
    uint8_t sweep[1][35];
    t_out_wire(sweep[0], 0xB2, 4 * FX_ZEC);
    t_digest_of(sweep, 1, dg);
    chg = fx_note(change, 5 * FX_ZEC, NULL, 1);
    tx_begin(&g_tx, FX_BRANCH_NU6_3, (int64_t)(4 * FX_ZEC + 10000));
    tx_add(&g_tx, &chg, false);
    memcpy(g_tx.meta + 102, dg, 32);
    uint8_t sighash[32];
    assert(tx_sighash(&g_tx, sighash));
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, sweep[0], 35);
    push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 0, 0, dg, 32);
    push_action(s, 4, 0, 1, &g_tx, 0);
    push_tx_output(s, 5, 1, 1, sighash, 32);
    for(int i = 0; i < 200; i++) {
        uint8_t in[75];
        memset(in, i, sizeof(in));
        in[48] = 25; in[49] = 0;
        push_t(s, HWP_MSG_TRANSPARENT_SIGN_REQ, 0, 1, in, 75);
    }
    push_sign_req(s, 9, &g_tx, "", 0, 0);   /* the session is gone by now */
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 5 && r.t_sign_rsps == 0 && r.sign_rsps == 0);
    assert(r.errors == 201 && r.first_error == HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
    assert(s->review_calls == 2 && s->totals_calls == 1 && s->confirm_calls == 0);
    printf("  PASS: A6/A7 200 TRANSPARENT_SIGN_REQ after a verified z->t sweep -> 0 signatures, session ended\n");
}

/* A5. Shielded -> transparent keeps working, and its edges. */
static void test_atk_a5_transparent_outputs(void) {
    uint8_t change[43];
    char ua_change[200];
    fx_addr_change(change);
    ua_of(ua_change, change);
    uint8_t o[2][35];
    uint8_t dg[32], sighash[32];
    t_out_wire(o[0], 0xB2, 4 * FX_ZEC);
    t_out_wire(o[1], 0xC3, 4 * FX_ZEC);
    t_digest_of(o, 1, dg);
    Stub* s;
    HwpDispatcher d;
    Reply r;
    char taddr[64];
    assert(script_to_taddr(o[0] + 10, 25, true, taddr, sizeof(taddr)) > 0);

    FxNote chg = fx_note(change, 5 * FX_ZEC, NULL, 1);
    tx_begin(&g_tx, FX_BRANCH_NU6_3, (int64_t)(4 * FX_ZEC + 10000));
    tx_add(&g_tx, &chg, false);
    memcpy(g_tx.meta + 102, dg, 32);
    assert(tx_sighash(&g_tx, sighash));

    /* A5.1: honest sweep; SIGN_REQ names the wallet's own change address
     * (before: shown on the final screen as if it were the recipient). */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, o[0], 35);
    push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 0, 0, dg, 32);
    push_action(s, 4, 0, 1, &g_tx, 0);
    push_tx_output(s, 5, 1, 1, sighash, 32);
    push_sign_req(s, 6, &g_tx, ua_change, 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.errors == 0 && r.acks == 5 && r.sign_rsps == 1);
    assert(s->review_calls == 2);
    assert(s->reviews[0].kind == HWP_OUTPUT_TRANSPARENT && s->reviews[0].value == 4 * FX_ZEC);
    assert(s->reviews[0].memo == HWP_MEMO_NOT_APPLICABLE);
    assert(strcmp(s->review_addrs[0], taddr) == 0);
    assert(s->reviews[1].kind == HWP_OUTPUT_OWN_CHANGE);
    assert(s->totals.transparent_out == 4 * FX_ZEC && s->totals.fee == 10000);
    assert(s->totals.total_leaving == 4 * FX_ZEC + 10000 && s->totals.n_transparent_out == 1);
    printf("  PASS: A5.1 shielded -> t-address: output shown as leaving, device totals, signed\n");

    /* A5.2: a second transparent pass after the first was verified. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, o[0], 35);
    push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 0, 0, dg, 32);
    push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, o[1], 35);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 3 && r.first_error == HWP_ERR_INVALID_STATE);

    /* A5.3: non-empty transparent digest in TxMeta, no transparent stream. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    push_action(s, 2, 0, 1, &g_tx, 0);
    push_tx_output(s, 3, 1, 1, sighash, 32);
    push_sign_req(s, 4, &g_tx, "", 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.sign_rsps == 0 && r.first_error == HWP_ERR_INVALID_STATE);

    /* A5.5: one output announced, two sent. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, o[0], 35);
    push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, o[1], 35);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 2 && r.first_error == HWP_ERR_INVALID_STATE);
    printf("  PASS: A5.2/3/5 second pass, skipped stream, surplus output -> refused\n");

    /* A5.4 (and host finding B): a ninth transparent output. Before:
     * BAD_FRAME on the ninth frame, after eight had been ACKed. Now:
     * LIMIT_EXCEEDED on the first, which announces the count. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    for(int i = 0; i < ORCHARD_SIGNER_MAX_T_OUTPUTS + 1; i++) {
        push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, (uint16_t)i, ORCHARD_SIGNER_MAX_T_OUTPUTS + 1,
               o[0], 35);
    }
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 1 && r.first_error == HWP_ERR_LIMIT_EXCEEDED);
    /* ... and announcing 8 then sending a ninth. */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
    for(int i = 0; i < ORCHARD_SIGNER_MAX_T_OUTPUTS + 1; i++) {
        push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, (uint16_t)i, ORCHARD_SIGNER_MAX_T_OUTPUTS, o[0], 35);
    }
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 1 + ORCHARD_SIGNER_MAX_T_OUTPUTS && r.first_error == HWP_ERR_INVALID_STATE);
    printf("  PASS: A5.4 more transparent outputs than the device shows -> LIMIT_EXCEEDED\n");

    /* A5.6: transparent output values that overflow. */
    {
        uint8_t big[2][35];
        uint8_t d2[32];
        t_out_wire(big[0], 0xB2, UINT64_MAX);
        t_out_wire(big[1], 0xB2, UINT64_MAX);
        t_digest_of(big, 2, d2);
        static Tx tb;
        tb = g_tx;
        memcpy(tb.meta + 102, d2, 32);
        s = fresh_stub();
        push_tx_output(s, 1, HWP_TX_META_INDEX, 1, tb.meta, sizeof(tb.meta));
        push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 2, big[0], 35);
        push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 1, 2, big[1], 35);
        push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 0, 0, d2, 32);
        push_action(s, 5, 0, 1, &tb, 0);
        tx_sighash(&tb, sighash);
        push_tx_output(s, 6, 1, 1, sighash, 32);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        /* each value is above the supply: refused where it enters */
        assert(r.first_error == HWP_ERR_VALUE_OVERFLOW && s->review_calls == 0);
    }
    /* A4.33: a 25-byte script that is not P2PKH. Before: accepted at feed
     * time and only "unrenderable" at review. Now refused where it enters. */
    {
        uint8_t odd[1][35];
        uint8_t d2[32];
        t_out_wire(odd[0], 0xB2, 1 * FX_ZEC);
        odd[0][10] = 0x51;
        s = fresh_stub();
        push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
        push_t(s, HWP_MSG_TX_TRANSPARENT_OUTPUT, 0, 1, odd[0], 35);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.acks == 1 && r.first_error == HWP_ERR_BAD_FRAME);
        (void)d2;
    }
    /* An empty transparent stream closed with the empty-bundle digest is
     * fine (and is the only digest that closes it). */
    {
        uint8_t empty[32];
        zip244_empty_digest("ZTxIdTranspaHash", empty);
        uint8_t to[43];
        fx_addr_foreign(to);
        FxNote pay = fx_note(to, 1 * FX_ZEC, NULL, 1);
        tx_begin(&g_tx, FX_BRANCH_NU6_3, (int64_t)FX_ZEC + 10000);
        tx_add(&g_tx, &pay, false);
        tx_sighash(&g_tx, sighash);
        s = fresh_stub();
        push_tx_output(s, 1, HWP_TX_META_INDEX, 1, g_tx.meta, sizeof(g_tx.meta));
        push_t(s, HWP_MSG_TX_TRANSPARENT_INPUT, 0, 0, empty, 32);
        push_action(s, 3, 0, 1, &g_tx, 0);
        push_tx_output(s, 4, 1, 1, sighash, 32);
        push_sign_req(s, 5, &g_tx, "", 0, 0);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.errors == 0 && r.sign_rsps == 1 && s->totals.n_transparent_out == 0);
    }
    printf("  PASS: A5.6 / A4.33 overflowing and non-standard transparent outputs refused; empty stream ok\n");
}

/* The reviewer's table of attempts (A4.x) that the existing tests above do
 * not already cover. */
static void test_atk_a4_table(void) {
    uint8_t change[43], to[43];
    fx_addr_change(change);
    fx_addr_foreign(to);
    Stub* s;
    HwpDispatcher d;
    Reply r;
    uint8_t sighash[32];

    /* A4.0: honest baseline, one SIGN_REQ more than there are actions. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    push_whole_tx(s, &g_tx);
    for(int i = 0; i < 4; i++) push_sign_req(s, (uint8_t)(20 + i), &g_tx, "", 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.sign_rsps == 3 && r.errors == 1 && r.first_error == HWP_ERR_INVALID_STATE);
    assert(s->confirm_calls == 1);
    printf("  PASS: A4.0 at most one signature per action; the surplus request is refused\n");

    /* A4.11: SIGN_REQ for another sighash, then the right one. Before: the
     * session stayed VERIFIED and the second request was signed. */
    s = fresh_stub();
    push_whole_tx(s, &g_tx);
    {
        static HwpSignReq req;
        memset(&req, 0, sizeof(req));
        tx_sighash(&g_tx, req.sighash);
        req.sighash[0] ^= 1;
        static uint8_t payload[HWP_SIGN_REQ_FIXED + HWP_MAX_RECIPIENT];
        uint16_t plen = hwp_encode_sign_req(payload, &req);
        push_frame(s, 20, HWP_MSG_SIGN_REQ, payload, plen);
    }
    push_sign_req(s, 21, &g_tx, "", 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.sign_rsps == 0 && r.errors == 2 && r.first_error == HWP_ERR_SIGHASH_MISMATCH);
    assert(s->confirm_calls == 0);
    printf("  PASS: A4.11 SIGN_REQ with a wrong sighash ends the session\n");

    /* A4.12: a second transaction rides in without a sentinel. */
    s = fresh_stub();
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, "", 0, 0);
    {
        static Tx t2;
        FxNote big = fx_note(to, 9 * FX_ZEC, NULL, 7);
        tx_begin(&t2, FX_BRANCH_NU6_3, 9 * (int64_t)FX_ZEC + 10000);
        tx_add(&t2, &big, false);
        push_tx_output(s, 30, HWP_TX_META_INDEX, 1, t2.meta, sizeof(t2.meta));
        push_action(s, 31, 0, 1, &t2, 0);
        push_sign_req(s, 32, &t2, "", 0, 0);
        push_sign_req(s, 33, &g_tx, "", 0, 0); /* and the old one again */
    }
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.sign_rsps == 1 && s->confirm_calls == 1 && s->review_calls == 2);
    printf("  PASS: A4.12 unreviewed second transaction gets no signature; the first one's approval is gone\n");

    /* A4.14-16: UI callbacks returning anything but OK. */
    for(int k = 0; k < 3; k++) {
        s = fresh_stub();
        push_whole_tx(s, &g_tx);
        push_sign_req(s, 20, &g_tx, "", 0, 0);
        d = build_wallet_dispatcher(s, &g_signer);
        s->odd_ui = k + 1;
        r = run_session(s, &d);
        assert(r.sign_rsps == 0 && r.first_error == HWP_ERR_USER_CANCELLED);
    }
    printf("  PASS: A4.14-16 review=77 / totals=-1 / confirm=EXIT -> no signature\n");

    /* A4.19: PING (and ABORT) between verification and SIGN_REQ. */
    for(int k = 0; k < 2; k++) {
        s = fresh_stub();
        push_whole_tx(s, &g_tx);
        push_frame(s, 9, k ? HWP_MSG_ABORT : HWP_MSG_PING, NULL, 0);
        push_sign_req(s, 20, &g_tx, "", 0, 0);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.sign_rsps == 0 && r.first_error == HWP_ERR_INVALID_STATE && s->confirm_calls == 0);
    }
    printf("  PASS: A4.19 PING / ABORT after verification clears it\n");

    /* A4.18: the sentinel sent twice. */
    s = fresh_stub();
    push_whole_tx(s, &g_tx);
    tx_sighash(&g_tx, sighash);
    push_tx_output(s, 9, 3, 3, sighash, 32);
    push_sign_req(s, 20, &g_tx, "", 0, 0);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.sign_rsps == 0 && r.first_error == HWP_ERR_INVALID_STATE);
    /* (before: the whole review was shown a second time) */
    assert(s->review_calls == 2 && s->totals_calls == 1);

    /* A4.20 / A4.21: an output to (d_change, -pk_d_change), and to a
     * non-canonical encoding of the change pk_d: neither is the wallet's. */
    {
        uint8_t neg[43];
        memcpy(neg, change, 43);
        neg[42] ^= 0x80;
        FxNote n1 = fx_note(neg, 7 * FX_ZEC, NULL, 1);
        s = fresh_stub();
        tx_begin(&g_tx, FX_BRANCH_NU6_3, 10000);
        tx_add(&g_tx, &n1, false);
        push_whole_tx(s, &g_tx);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.errors == 0 && s->review_calls == 1);
        assert(s->reviews[0].kind == HWP_OUTPUT_EXTERNAL);
        assert(s->totals.total_leaving == 7 * FX_ZEC + 10000 && s->totals.own_internal == 0);
    }
    /* A4.22: pk_d = 32 zero bytes. */
    {
        uint8_t z[43];
        memcpy(z, change, 43);
        memset(z + 11, 0, 32);
        s = fresh_stub();
        tx_standard(&g_tx, change);
        memcpy(g_tx.told[0].recipient, z, 43);
        push_whole_tx(s, &g_tx);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.acks == 1 && s->review_calls == 0 &&
               (r.first_error == HWP_ERR_NOTE_COMMITMENT_MISMATCH ||
                r.first_error == HWP_ERR_BAD_PK_D));
    }
    printf("  PASS: A4.18/20/22 double sentinel, negated own pk_d (EXTERNAL), zero pk_d\n");

    /* A4.23: value outputs in the sealed Orchard pool. */
    {
        FxNote p = fx_note(to, 3 * FX_ZEC, NULL, 1);
        FxNote c = fx_note(change, 2 * FX_ZEC, NULL, 2);
        p.pool = ZIP244_POOL_ORCHARD;
        c.pool = ZIP244_POOL_ORCHARD;
        s = fresh_stub();
        tx_begin(&g_tx, FX_BRANCH_NU6_3, 0);
        meta_set_vb(g_tx.meta, 10000, 0);
        tx_add(&g_tx, &p, false);
        tx_add(&g_tx, &c, false);
        push_whole_tx(s, &g_tx);
        push_sign_req(s, 20, &g_tx, "", 0, 0);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.errors == 0 && r.sign_rsps == 1 && s->totals.fee == 10000);
        assert(s->reviews[0].kind == HWP_OUTPUT_EXTERNAL && s->reviews[1].kind == HWP_OUTPUT_OWN_CHANGE);
        /* A4.5: the same Orchard-pool action presented with the Ironwood tag. */
        s = fresh_stub();
        g_tx.told[0].pool = ZIP244_POOL_IRONWOOD;
        push_whole_tx(s, &g_tx);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.first_error == HWP_ERR_NOTE_COMMITMENT_MISMATCH && r.acks == 1);
    }
    /* A4.24: Orchard flags with the cross-address bit. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    g_tx.meta[20] = 0x07;
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 0 && r.first_error == HWP_ERR_BAD_FRAME);
    /* A4.29 / A4.30: absurd action counts; 0xFFFF collides with the meta index. */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    push_tx_output(s, 1, HWP_TX_META_INDEX, 0xFFFE, g_tx.meta, sizeof(g_tx.meta));
    push_tx_output(s, 2, HWP_TX_META_INDEX, 0xFFFF, g_tx.meta, sizeof(g_tx.meta));
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 0 && r.errors == 2 && r.first_error == HWP_ERR_LIMIT_EXCEEDED);
    printf("  PASS: A4.5/23/24/29/30 pool tag lie, sealed-pool outputs, flag policy, action counts\n");

    /* A4.26-28: value-balance extremes (both pools populated). */
    {
        FxNote a = fx_note(to, 1, NULL, 1);
        FxNote b = fx_note(to, 1, NULL, 2);
        b.pool = ZIP244_POOL_ORCHARD;
        /* Beyond the supply: refused with the TxMeta. Within it: a fee
         * above the supply, and a negative fee, are refused at the totals. */
        static const int64_t vbs[4][2] = {
            {INT64_MAX, INT64_MAX},
            {INT64_MIN, INT64_MAX},
            {2100000000000000ll, 2100000000000000ll},
            {-2100000000000000ll, 1}};
        static const int want[4] = {
            HWP_ERR_VALUE_OVERFLOW, HWP_ERR_VALUE_OVERFLOW,
            HWP_ERR_VALUE_OVERFLOW, HWP_ERR_FEE_NEGATIVE};
        for(int k = 0; k < 4; k++) {
            s = fresh_stub();
            tx_begin(&g_tx, FX_BRANCH_NU6_3, 0);
            meta_set_vb(g_tx.meta, vbs[k][0], vbs[k][1]);
            tx_add(&g_tx, &a, false);
            tx_add(&g_tx, &b, false);
            push_whole_tx(s, &g_tx);
            d = build_wallet_dispatcher(s, &g_signer);
            r = run_session(s, &d);
            assert(r.first_error == want[k] && s->review_calls == 0);
        }
        FxNote huge = fx_note(to, UINT64_MAX - 5, NULL, 1);
        s = fresh_stub();
        tx_begin(&g_tx, FX_BRANCH_NU6_3, INT64_MAX);
        tx_add(&g_tx, &huge, false);
        push_whole_tx(s, &g_tx);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.first_error == HWP_ERR_VALUE_OVERFLOW && s->review_calls == 0);
    }
    /* A4.32: 0xF6 followed by data, and 0x00 followed by data, are memos. */
    {
        FxNote m1 = fx_note(to, 3 * FX_ZEC, NULL, 1);
        m1.memo[511] = 1;
        FxNote m2 = fx_note(to, 0, NULL, 2);
        memset(m2.memo, 0, 512);
        m2.memo[300] = 'x';
        s = fresh_stub();
        tx_begin(&g_tx, FX_BRANCH_NU6_3, 3 * (int64_t)FX_ZEC + 10000);
        tx_add(&g_tx, &m1, false);
        tx_add(&g_tx, &m2, false);
        push_whole_tx(s, &g_tx);
        d = build_wallet_dispatcher(s, &g_signer);
        r = run_session(s, &d);
        assert(r.errors == 0 && s->review_calls == 2 && s->memo_calls == 2);
        assert(s->reviews[0].memo == HWP_MEMO_PRESENT && s->reviews[1].memo == HWP_MEMO_PRESENT);
        assert(s->reviews[1].value == 0);
    }
    printf("  PASS: A4.26-28/32 value-balance extremes; near-empty memos are shown\n");
}

/* Reviewer item: zero-value compact outputs could carry an unverified memo
 * to any address with no screen. The compact body is now refused for every
 * output; a zero-value output must prove its memo like any other. */
static void test_atk_zero_value_hidden_memo(void) {
    uint8_t change[43], to[43];
    fx_addr_change(change);
    fx_addr_foreign(to);
    Stub* s;
    HwpDispatcher d;
    Reply r;

    /* zero-value padding sent compact (what hosts did until now) */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    g_tx.compact[2] = true;
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 3 && r.first_error == HWP_ERR_MEMO_REQUIRED && s->review_calls == 0);

    /* zero-value output with a message, declared with an empty memo */
    s = fresh_stub();
    tx_standard(&g_tx, change);
    {
        FxNote msg = fx_note(to, 0, "send the rest to t1...", 3);
        fx_build_action(g_tx.action[2], &msg, 3);
        g_tx.told[2] = msg;
        fx_memo_none(g_tx.told[2].memo);
    }
    push_whole_tx(s, &g_tx);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 3 && r.first_error == HWP_ERR_MEMO_MISMATCH && s->review_calls == 0);
    printf("  PASS: zero-value output: compact body refused, a hidden memo is a MEMO_MISMATCH\n");
}

/* Every Error frame ends the session (reviewer: SECURITY.md said so, the
 * code did not for SIGN_REQ errors, short frames, unknown messages, CRC and
 * version errors). After each provocation the transaction in progress is
 * gone: the next action frame is out of sequence and the keys are wiped. */
static void test_error_always_ends_session(void) {
    uint8_t change[43];
    fx_addr_change(change);
    tx_standard(&g_tx, change);
    for(int k = 0; k < 8; k++) {
        Stub* s = fresh_stub();
        int expect = HWP_ERR_BAD_FRAME;
        push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
        push_action(s, 2, 0, 3, &g_tx, 0);
        switch(k) {
        case 0: { /* unknown message type */
            push_frame(s, 3, 0x7E, NULL, 0);
            expect = HWP_ERR_UNKNOWN;
        } break;
        case 1: { /* CRC error */
            size_t before = s->in_len;
            push_frame(s, 3, HWP_MSG_PONG, NULL, 0);
            s->in_buf[s->in_len - 1] ^= 0x55;
            (void)before;
        } break;
        case 2: { /* unsupported version */
            size_t before = s->in_len;
            push_frame(s, 3, HWP_MSG_PONG, NULL, 0);
            s->in_buf[before + 1] = 0x09;
            uint16_t crc = hwp_crc16(s->in_buf + before, s->in_len - before - 2);
            s->in_buf[s->in_len - 2] = (uint8_t)crc;
            s->in_buf[s->in_len - 1] = (uint8_t)(crc >> 8);
            expect = HWP_ERR_UNSUPPORTED_VER;
        } break;
        case 3: { /* TX_OUTPUT too short */
            uint8_t two[2] = {0, 0};
            push_frame(s, 3, HWP_MSG_TX_OUTPUT, two, 2);
        } break;
        case 4: { /* SIGN_REQ too short */
            uint8_t ten[10] = {0};
            push_frame(s, 3, HWP_MSG_SIGN_REQ, ten, 10);
            expect = HWP_ERR_BAD_SIGHASH;
        } break;
        case 5: { /* transparent output frame too short */
            uint8_t two[2] = {0, 0};
            push_frame(s, 3, HWP_MSG_TX_TRANSPARENT_OUTPUT, two, 2);
        } break;
        case 6: { /* transparent input frame too short */
            uint8_t two[2] = {0, 0};
            push_frame(s, 3, HWP_MSG_TX_TRANSPARENT_INPUT, two, 2);
        } break;
        default: { /* FVK_REQ for the other network */
            uint8_t coin[4] = {133, 0, 0, 0};
            push_frame(s, 3, HWP_MSG_FVK_REQ, coin, 4);
            expect = HWP_ERR_NETWORK_MISMATCH;
        } break;
        }
        push_action(s, 4, 1, 3, &g_tx, 1);
        HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
        Reply r = run_session(s, &d);
        if(k == 1) {
            /* After a CRC error the parser resynchronises and drops the
             * bytes that shared a packet with the bad frame, so the next
             * frame is lost rather than answered: one error, no third ACK. */
            assert(r.acks == 2 && r.errors == 1 && r.first_error == expect);
            assert(s->probe_hits == 1);
            continue;
        }
        assert(r.acks == 2 && r.errors == 2);
        assert(r.first_error == expect && r.last_error == HWP_ERR_INVALID_STATE);
        /* stub_send checked the signer (IDLE, keys wiped) at both errors */
        assert(s->probe_hits == 2);
    }
    printf("  PASS: unknown type / CRC / version / short frames / FVK network: every Error ends the session\n");
}

/* The device's network. Before: the check compared TxMeta with a coin type
 * taken from FVK_REQ and kept in the signer context — wiped by any reset or
 * PING, after which no check ran. */
static void test_network_is_a_device_property(void) {
    uint8_t change[43];
    fx_addr_change(change);
    Stub* s;
    HwpDispatcher d;
    Reply r;

    /* testnet device, mainnet TxMeta — first thing, after a PING, after an
     * aborted session. */
    tx_standard(&g_tx, change);
    g_tx.meta[ZIP244_TX_META_V6_SIZE] = 133;
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_frame(s, 2, HWP_MSG_PING, NULL, 0);
    push_tx_output(s, 3, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    push_frame(s, 4, HWP_MSG_ABORT, NULL, 0);
    push_tx_output(s, 5, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    {
        uint8_t coin[4] = {1, 0, 0, 0};
        push_frame(s, 6, HWP_MSG_FVK_REQ, coin, 4);
    }
    push_tx_output(s, 7, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 0 && r.errors == 4 && r.first_error == HWP_ERR_NETWORK_MISMATCH &&
           r.last_error == HWP_ERR_NETWORK_MISMATCH);

    /* TxMeta without the coin-type extension (166 bytes). */
    s = fresh_stub();
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, ZIP244_TX_META_V6_SIZE);
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.acks == 0 && r.first_error == HWP_ERR_NETWORK_MISMATCH);

    /* mainnet device, testnet TxMeta. */
    tx_standard(&g_tx, change);
    s = fresh_stub();
    orchard_signer_init(&g_signer, ORCHARD_SIGNER_COIN_MAINNET);
    push_tx_output(s, 1, HWP_TX_META_INDEX, 3, g_tx.meta, sizeof(g_tx.meta));
    d = build_wallet_dispatcher(s, &g_signer);
    d.testnet = false;
    r = run_session(s, &d);
    assert(r.acks == 0 && r.first_error == HWP_ERR_NETWORK_MISMATCH);
    assert(g_signer.coin_type == ORCHARD_SIGNER_COIN_MAINNET); /* survived the resets */

    /* `testnet` disagreeing with the signer, or a signer with no network. */
    s = fresh_stub();
    orchard_signer_init(&g_signer, ORCHARD_SIGNER_COIN_MAINNET);
    d = build_wallet_dispatcher(s, &g_signer);
    d.testnet = true;
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    orchard_signer_init(&g_signer, 0);
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    orchard_signer_init(&g_signer, 2);
    assert(g_signer.coin_type == 0);
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    assert(s->out_len == 0); /* not a byte sent */
    printf("  PASS: network: TxMeta must name the device's coin type in every session; survives resets\n");
}

/* F6: a NULL spending key is a FATAL at start, not a crash at the first
 * signature. */
static void test_null_ask_is_fatal(void) {
    Stub* s = fresh_stub();
    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    d.keys.ask = NULL;
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    d = build_wallet_dispatcher(s, &g_signer);
    d.keys.nk = NULL;
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    d = build_wallet_dispatcher(s, &g_signer);
    d.io.sleep_ms = NULL;
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    d = build_wallet_dispatcher(s, &g_signer);
    d.io.get_tick_ms = NULL;
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    d = build_wallet_dispatcher(s, &g_signer);
    d.io.should_exit = NULL;
    assert(hwp_dispatcher_run(&d) == HWP_DISP_FATAL);
    assert(s->out_len == 0);
    printf("  PASS: NULL keys.ask (or any mandatory key / callback) -> HWP_DISP_FATAL up front\n");
}

/* Host finding C: an honest host asks signatures only for its real spends.
 * After a two-action transaction with one SIGN_REQ the device is still
 * VERIFIED. Before: the next TxMeta on the same connection got
 * INVALID_STATE. Now it starts the next transaction, with nothing left of
 * the previous one. */
static void test_new_txmeta_ends_previous_transaction(void) {
    Stub* s = fresh_stub();
    uint8_t change[43], to[43];
    fx_addr_change(change);
    fx_addr_foreign(to);
    FxNote pay = fx_note(to, 1 * FX_ZEC, NULL, 1);
    FxNote chg = fx_note(change, 2 * FX_ZEC, NULL, 2);
    tx_begin(&g_tx, FX_BRANCH_NU6_3, 10000);
    tx_add(&g_tx, &pay, false);
    tx_add(&g_tx, &chg, false);
    static Tx tx_b;
    FxNote pay_b = fx_note(to, 5 * FX_ZEC, NULL, 3);
    FxNote chg_b = fx_note(change, 1 * FX_ZEC, NULL, 4);
    tx_begin(&tx_b, FX_BRANCH_NU6_3, 10000);
    tx_add(&tx_b, &pay_b, false);
    tx_add(&tx_b, &chg_b, false);

    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, "", 0, 0);   /* 1 of 2 */
    push_whole_tx(s, &tx_b);                 /* same connection, no PING, no ABORT */
    push_sign_req(s, 21, &g_tx, "", 0, 0);   /* A's sighash: A is over */
    HwpDispatcher d = build_wallet_dispatcher(s, &g_signer);
    Reply r = run_session(s, &d);
    assert(r.acks == 8 && r.sign_rsps == 1);
    assert(r.errors == 1 && r.first_error == HWP_ERR_SIGHASH_MISMATCH);
    assert(s->review_calls == 4 && s->totals_calls == 2 && s->confirm_calls == 1);

    s = fresh_stub();
    push_whole_tx(s, &g_tx);
    push_sign_req(s, 20, &g_tx, "", 0, 0);
    push_whole_tx(s, &tx_b);
    push_sign_req(s, 21, &tx_b, "", 0, 0);
    push_sign_req(s, 22, &tx_b, "", 0, 0);
    push_sign_req(s, 23, &tx_b, "", 0, 0);   /* third for a 2-action tx */
    d = build_wallet_dispatcher(s, &g_signer);
    r = run_session(s, &d);
    assert(r.sign_rsps == 3 && r.errors == 1 && r.first_error == HWP_ERR_INVALID_STATE);
    assert(s->confirm_calls == 2);
    assert(s->confirm_totals.total_leaving == 5 * FX_ZEC + 10000);
    printf("  PASS: a new TxMeta ends the previous (verified, partly signed) transaction and starts clean\n");
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

    printf("\nHWP dispatcher sessions (ownership, ciphertext, ordering):\n");
    wallet_keys_init();
    test_session_send_with_change();
    test_session_change_redirected();
    test_session_own_address();
    test_session_compact_and_memo_attacks();
    test_session_memo_without_screen();
    test_session_limits();
    test_session_reordered();
    test_session_branch_and_recipient();
    test_session_second_tx_reconfirms();

    printf("\nRegression tests for the November 2026 review (attack ports):\n");
    test_atk_a1_unbound_value_balance();
    test_atk_a2_final_screen_shows_no_host_string();
    test_atk_a3_transparent_inputs_refused();
    test_atk_a5_transparent_outputs();
    test_atk_a4_table();
    test_atk_zero_value_hidden_memo();
    test_error_always_ends_session();
    test_network_is_a_device_property();
    test_null_ask_is_fatal();
    test_new_txmeta_ends_previous_transaction();
    printf("All dispatcher tests passed.\n");
    return 0;
}
