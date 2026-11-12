/* Secret-residue regression test.
 *
 * The library keeps its large intermediates in `static` storage (the stack
 * budget is 512 B per function), so "wipe after use" has to hold for
 * .data/.bss, not only for the stack — on Flipper Zero an external app's
 * .bss is heap, and whatever is left there outlives the app.
 *
 * Method: run the same wallet sequence twice with two unrelated sets of
 * secrets (PIN, mnemonic, passphrase, note randomness), snapshot the whole
 * .data/.bss of this process after each run, and compare. Public state the
 * library legitimately keeps (curve constants, init flags, callbacks) is
 * identical in both snapshots; any byte that differs depends on the secrets
 * and is residue. This catches derived state (hash schedules, field
 * temporaries, key pads), not just verbatim copies of a key.
 *
 * The sequence: PIN KDF, seal + unseal, mnemonic -> seed, ZIP-32 and BIP-32
 * key derivation, ak, default address (current and legacy), RedPallas
 * signing (direct and domain-separated), per-action
 * verification (cmx + enc_ciphertext), HMAC and SHA-2 one-shots, the
 * incoming viewing keys of both scopes and the ownership predicate, and two
 * signer sessions on a context that lives in .bss — one carried through to
 * a signature and reset, one aborted by the library itself — so that the
 * session's viewing keys are covered both as static scratch and as session
 * state. Then every other way the signer abandons a session (commitment
 * mismatch, undecodable recipient, bad pool / size, unbound value balance,
 * negative fee, transparent input / bad output / digest mismatch, sighash
 * mismatch, non-empty transparent digest), three dispatcher sessions on a
 * static HwpDispatcher (signed; cancelled at the memo screen; aborted by a
 * memo mismatch), and F4Jumble / F4Jumble^-1, SHA-1 and PBKDF2-HMAC-SHA256
 * on secret input.
 *
 * Not covered by the pass/fail verdict: the dead stack. The library wipes
 * its named stack buffers, but what a compiler spills is outside the reach
 * of C; a verbatim scan of the dead stack is printed for information.
 *
 * ELF/Linux only (needs the linker's __data_start/_end); elsewhere the
 * test reports SKIP and passes. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "bip32.h"
#include "bip39.h"
#include "hmac.h"
#include "hwp.h"
#include "hwp_dispatcher.h"
#include "memzero.h"
#include "orchard.h"
#include "orchard_signer.h"
#include "pallas.h"
#include "pbkdf2.h"
#include "redpallas.h"
#include "secp256k1.h"
#include "sha2.h"
#include "zip244.h"

#if defined(__linux__) && defined(__ELF__) && !defined(__SANITIZE_ADDRESS__)

extern char __data_start, _end;

typedef struct {
    const char* mnemonic;
    const char* passphrase;
    uint8_t pin[6];
    uint8_t fill; /* seeds the note randomness / messages */
} secrets;

/* Verbatim secrets remembered (XOR-masked) for the scans. This is the one
 * object of the test itself that differs between the two runs; its range is
 * excluded from the snapshot comparison. */
typedef struct {
    const char* name;
    uint8_t masked[16];
} pattern;
static pattern s_patterns[64];

/* The signer context of the session below. Deliberately static: it is then
 * part of the .data/.bss snapshot, and anything a session leaves in it
 * after orchard_signer_reset() shows up as residue. */
static OrchardSignerCtx s_signer;
static int s_num_patterns;

static void remember(const char* name, const uint8_t* p) {
    pattern* q = &s_patterns[s_num_patterns++];
    q->name = name;
    for(int i = 0; i < 16; i++) q->masked[i] = p[i] ^ 0xA5;
}

/* A scripted host for the dispatcher sessions. The script and the
 * dispatcher are static so that they are inside the snapshot; the test
 * wipes its own script, the library has to have wiped everything else. */
static HwpDispatcher s_disp;
static struct {
    uint8_t in[4096];
    size_t in_len, in_pos;
    uint32_t tick;
    int iterations, variant;
    int sign_rsps, fvk_rsps, memo_screens;
} s_script;

static void residue_script_reset(int variant) {
    memzero(&s_script, sizeof(s_script));
    s_script.variant = variant;
}
/* tx_output != 0: wrap `data` in the index/total header of TX_OUTPUT. */
static void residue_push(uint8_t seq, uint8_t type, uint16_t idx, uint16_t total,
                         const uint8_t* data, uint16_t len, int tx_output) {
    static uint8_t payload[HWP_MAX_PAYLOAD];
    static uint8_t frame[HWP_MAX_FRAME];
    uint16_t plen = len;
    if(tx_output) {
        plen = hwp_encode_tx_output(payload, idx, total, data, len);
    } else {
        memcpy(payload, data, len);
    }
    size_t n = hwp_encode(frame, seq, type, payload, plen);
    assert(s_script.in_len + n <= sizeof(s_script.in));
    memcpy(s_script.in + s_script.in_len, frame, n);
    s_script.in_len += n;
    memzero(payload, sizeof(payload));
    memzero(frame, sizeof(frame));
}
static size_t residue_drain(uint8_t* out, size_t cap, void* ctx) {
    (void)ctx;
    size_t n = s_script.in_len - s_script.in_pos;
    if(n > cap) n = cap;
    if(n > 64) n = 64;
    memcpy(out, s_script.in + s_script.in_pos, n);
    s_script.in_pos += n;
    return n;
}
static void residue_send(const uint8_t* data, size_t len, void* ctx) {
    (void)ctx;
    if(len >= 4 && data[3] == HWP_MSG_SIGN_RSP) s_script.sign_rsps++;
    if(len >= 4 && data[3] == HWP_MSG_FVK_RSP) s_script.fvk_rsps++;
}
static uint32_t residue_tick(void* ctx) { (void)ctx; return s_script.tick; }
static void residue_sleep(uint32_t ms, void* ctx) { (void)ctx; s_script.tick += ms; }
static bool residue_exit(void* ctx) { (void)ctx; return ++s_script.iterations > 400; }
static HwpUiResult residue_review(const HwpOutputReview* o, void* ctx) {
    (void)o; (void)ctx;
    return HWP_UI_OK;
}
static HwpUiResult residue_memo(uint16_t i, uint16_t t, const char* a, const uint8_t m[512],
                                void* ctx) {
    (void)i; (void)t; (void)a; (void)m; (void)ctx;
    s_script.memo_screens++;
    return s_script.variant == 1 ? HWP_UI_CANCELLED : HWP_UI_OK;
}
static HwpUiResult residue_totals(const OrchardSignerTotals* t, void* ctx) {
    (void)t; (void)ctx;
    return HWP_UI_OK;
}
static HwpUiResult residue_confirm(const OrchardSignerTotals* t, void* ctx) {
    (void)t; (void)ctx;
    return HWP_UI_OK;
}

/* Everything the caller owns lives in this frame and is wiped before
 * returning, as an application is expected to do. */
__attribute__((noinline)) static void wallet_sequence(const secrets* s) {
    struct {
        uint8_t salt[16], key[AEAD_KEY_SIZE], nonce[AEAD_NONCE_SIZE], tag[AEAD_TAG_SIZE];
        uint8_t seed[64], sealed[64], unsealed[64];
        uint8_t sk[32], ask[32], nk[32], rivk[32], ak[32], tsk[32], tpk[33];
        uint8_t d[11], pk_d[32], d2[11], pk_d2[32];
        char ua[256];
        uint8_t alpha[32], sighash[32], sig[64], rk[32], personal[16];
        uint8_t tsig[64];
        uint8_t rho[32], rseed[32], cmx[32], epk[32], memo[512], enc[580];
        uint8_t mac[64], dig[64];
    } w;
    memset(&w, 0, sizeof(w));
    memset(w.salt, 0x11, sizeof(w.salt));
    memset(w.nonce, 0x22, sizeof(w.nonce));

    /* PIN -> AEAD key, seal and unseal the seed */
    wallet_pin_kdf(s->pin, sizeof(s->pin), w.salt, sizeof(w.salt), 64, w.key);
    remember("pin_key", w.key);
    remember("pin_key_mac", w.key + 32);
    mnemonic_to_seed(s->mnemonic, s->passphrase, w.seed, NULL);
    remember("seed", w.seed);
    remember("seed_hi", w.seed + 32);
    assert(aead_aes256_ctr_hmac_seal(w.key, w.nonce, NULL, 0, w.seed, 64, w.sealed, w.tag) == 0);
    assert(aead_aes256_ctr_hmac_unseal(w.key, w.nonce, NULL, 0, w.sealed, 64, w.tag, w.unsealed) == 0);
    assert(memcmp(w.seed, w.unsealed, 64) == 0);

    /* key derivation */
    orchard_derive_account_sk(w.seed, 1, 0, w.sk);
    remember("sk", w.sk);
    orchard_derive_keys(w.sk, w.ask, w.nk, w.rivk);
    remember("ask", w.ask);
    remember("nk", w.nk);
    remember("rivk", w.rivk);
    redpallas_derive_ak(w.ask, w.ak);
    assert(bip32_derive_transparent_sk(w.seed, 1, w.tsk, w.tpk) == 0);
    remember("t_sk", w.tsk);
    assert(orchard_derive_unified_address(w.seed, 1, 0, "utest", w.ua, sizeof(w.ua), w.d, w.pk_d) > 0);
    assert(orchard_derive_unified_address_legacy(
               w.seed, 1, 0, "utest", w.ua, sizeof(w.ua), w.d2, w.pk_d2) > 0);

    /* signing */
    memset(w.alpha, s->fill, 31);
    memset(w.sighash, s->fill ^ 0x5a, 32);
    memcpy(w.personal, "residue_test_sig", 16);
    assert(redpallas_sign(w.ask, w.alpha, w.sighash, w.sig, w.rk) == 0);
    assert(orchard_sign_with_personal(w.ask, w.personal, w.sighash, w.sig, w.rk) == 0);
#if ZCASH_ENABLE_TRANSPARENT_SIGNING
    assert(secp256k1_ecdsa_sign_digest(w.tsk, w.sighash, w.tsig) == 0);
#endif

    /* per-action verification of an output to our own address */
    memset(w.rho, s->fill ^ 0x33, 32);
    w.rho[31] = 0x1a;
    memset(w.rseed, s->fill ^ 0xc3, 32);
    remember("rseed", w.rseed);
    w.memo[0] = 0xf6;
    orchard_compute_cmx(w.d, w.pk_d, 12345, w.rho, w.rseed, ORCHARD_NOTE_V3, w.cmx);
    assert(orchard_compute_enc_ciphertext_from_rseed(
               w.d, w.pk_d, 12345, w.rseed, w.rho, w.memo, ORCHARD_NOTE_V3, w.enc, w.epk) == 0);

    /* Viewing keys of both scopes and the ownership predicate (static
     * scratch of orchard_commit_ivk / the scalar multiplication). */
    {
        uint8_t ivk_e[32], ivk_i[32], rivk_int[32], pk[32];
        assert(orchard_derive_ivks(w.ak, w.nk, w.rivk, ivk_e, ivk_i) == 0);
        orchard_derive_rivk_internal(w.ak, w.nk, w.rivk, rivk_int);
        remember("ivk_external", ivk_e);
        remember("ivk_internal", ivk_i);
        remember("rivk_internal", rivk_int);
        assert(orchard_ivk_owns_address(ivk_e, w.d, w.pk_d) == 1);
        assert(orchard_ivk_owns_address(ivk_i, w.d, w.pk_d) == 0);
        orchard_ivk_derive_pk_d(ivk_i, w.d, pk); /* an ivk-dependent point */
        memzero(ivk_e, 32);
        memzero(ivk_i, 32);
        memzero(rivk_int, 32);
        memzero(pk, 32);
    }

    /* Signer sessions: the context holds ivk_external / ivk_internal from
     * feed_meta() until reset. The output goes to our own address, with a
     * memo that takes a pool slot. */
    {
        static uint8_t action[820]; /* public transaction bytes, wiped below */
        uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE];
        const OrchardSignerFvk fvk = {.ak = w.ak, .nk = w.nk, .rivk = w.rivk};
        memset(meta, 0, sizeof(meta));
        meta[0] = 0x06; meta[3] = 0x80;
        meta[4] = 0x98; meta[5] = 0xB6; meta[6] = 0x84; meta[7] = 0xD8;
        meta[8] = 0x5B; meta[9] = 0x16; meta[10] = 0xA5; meta[11] = 0x37;
        meta[20] = 0x03; meta[61] = 0x03;
        zip244_empty_digest("ZTxIdTranspaHash", meta + 102);
        zip244_sapling_empty_digest(meta + 134);
        meta[ZIP244_TX_META_V6_SIZE] = 1; /* coin type: testnet */

        memset(action, s->fill, sizeof(action));
        memcpy(action + 32, w.rho, 32);
        memcpy(action + 96, w.cmx, 32);
        memcpy(action + 128, w.epk, 32);
        memcpy(action + 160, w.enc, 580);

        /* 1: aborted by the library (the memo declared is not the one in
         *    the ciphertext) — the abort path must leave nothing. */
        uint8_t dp[43];
        memcpy(dp, w.d, 11);
        memcpy(dp + 11, w.pk_d, 32);
        orchard_signer_init(&s_signer, 1);
        assert(orchard_signer_feed_meta(&s_signer, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
        w.memo[1] = s->fill;
        assert(orchard_signer_feed_action_with_note_and_memo(
                   &s_signer, ZIP244_POOL_IRONWOOD, action, sizeof(action), dp, 12345,
                   w.rseed, w.memo) == SIGNER_ERR_MEMO_MISMATCH);
        assert(s_signer.state == SIGNER_IDLE);

        /* 2: carried through to a signature, then reset by the caller. */
        assert(orchard_compute_enc_ciphertext_from_rseed(
                   w.d, w.pk_d, 12345, w.rseed, w.rho, w.memo, ORCHARD_NOTE_V3,
                   action + 160, action + 128) == 0);
        assert(orchard_signer_feed_meta(&s_signer, &fvk, meta, sizeof(meta), 1) == SIGNER_OK);
        assert(orchard_signer_feed_action_with_note_and_memo(
                   &s_signer, ZIP244_POOL_IRONWOOD, action, sizeof(action), dp, 12345,
                   w.rseed, w.memo) == SIGNER_OK);
        OrchardOutputInfo info;
        OrchardSignerTotals totals;
        assert(orchard_signer_get_output(&s_signer, 0, &info) == SIGNER_OK);
        assert(info.ownership == ORCHARD_OUTPUT_OWN_EXTERNAL && info.has_memo);
        assert(orchard_signer_get_totals(&s_signer, &totals) == SIGNER_OK);
        assert(totals.own_external == 12345 && totals.total_leaving == 0);
        assert(orchard_signer_confirm_action(&s_signer, 0) == SIGNER_OK);
        assert(orchard_signer_confirm_totals(&s_signer) == SIGNER_OK);
        {
            Zip244ActionsState o = s_signer.actions_state, i = s_signer.ironwood_actions_state;
            uint8_t sh[32];
            zip244_shielded_sighash_v6(&s_signer.tx_meta, &o, &i, sh);
            assert(orchard_signer_verify(&s_signer, sh) == SIGNER_OK);
            assert(orchard_signer_sign(&s_signer, sh, w.ask, w.alpha, w.sig, w.rk) == SIGNER_OK);
            memzero(&o, sizeof(o));
            memzero(&i, sizeof(i));
            memzero(sh, sizeof(sh));
        }
        orchard_signer_reset(&s_signer);
        memzero(action, sizeof(action));
        memzero(dp, sizeof(dp));
        memzero(&info, sizeof(info));
    }

    /* More signer exits, each taken with the session's viewing keys in the
     * context and note data in the static scratch: every way the library
     * itself abandons a session, and the paths the first two do not run. */
    {
        static uint8_t action[820];
        uint8_t meta[ZIP244_TX_META_V6_EXT_SIZE], dp[43], bad[43], sh[32];
        const OrchardSignerFvk fvk = {.ak = w.ak, .nk = w.nk, .rivk = w.rivk};
        OrchardSignerTotals totals;
        memset(meta, 0, sizeof(meta));
        meta[0] = 0x06; meta[3] = 0x80;
        meta[4] = 0x98; meta[5] = 0xB6; meta[6] = 0x84; meta[7] = 0xD8;
        meta[8] = 0x5B; meta[9] = 0x16; meta[10] = 0xA5; meta[11] = 0x37;
        meta[20] = 0x03; meta[61] = 0x03;
        zip244_empty_digest("ZTxIdTranspaHash", meta + 102);
        zip244_sapling_empty_digest(meta + 134);
        meta[ZIP244_TX_META_V6_SIZE] = 1;
        memcpy(dp, w.d, 11);
        memcpy(dp + 11, w.pk_d, 32);
        memset(action, s->fill, sizeof(action));
        memcpy(action + 32, w.rho, 32);
        orchard_compute_cmx(w.d, w.pk_d, 12345, w.rho, w.rseed, ORCHARD_NOTE_V3, action + 96);
        assert(orchard_compute_enc_ciphertext_from_rseed(
                   w.d, w.pk_d, 12345, w.rseed, w.rho, w.memo, ORCHARD_NOTE_V3,
                   action + 160, action + 128) == 0);
#define RESIDUE_OPEN() \
        assert(orchard_signer_feed_meta(&s_signer, &fvk, meta, sizeof(meta), 1) == SIGNER_OK)
#define RESIDUE_FEED(rcpt, val) \
        orchard_signer_feed_action_with_note_and_memo( \
            &s_signer, ZIP244_POOL_IRONWOOD, action, sizeof(action), rcpt, val, w.rseed, w.memo)

        /* note commitment mismatch (wrong value declared) */
        RESIDUE_OPEN();
        assert(RESIDUE_FEED(dp, 12346) == SIGNER_ERR_NOTE_COMMITMENT_MISMATCH);
        /* wrong recipient: a point that is not ours (and may not decode) */
        memcpy(bad, dp, 43);
        memset(bad + 11, s->fill, 32);
        bad[42] &= 0x3f;
        RESIDUE_OPEN();
        assert(RESIDUE_FEED(bad, 12345) != SIGNER_OK);
        /* wrong pool, wrong size, and a call in the wrong state */
        RESIDUE_OPEN();
        assert(orchard_signer_feed_action_with_note_and_memo(
                   &s_signer, (Zip244Pool)7, action, sizeof(action), dp, 12345, w.rseed,
                   w.memo) == SIGNER_ERR_BAD_POOL);
        RESIDUE_OPEN();
        assert(orchard_signer_feed_action_with_note_and_memo(
                   &s_signer, ZIP244_POOL_IRONWOOD, action, 819, dp, 12345, w.rseed,
                   w.memo) == SIGNER_ERR_BAD_ACTION);
        /* value balance for the pool that has no action */
        meta[21] = 1;
        RESIDUE_OPEN();
        assert(RESIDUE_FEED(dp, 12345) == SIGNER_ERR_EMPTY_POOL_BALANCE);
        meta[21] = 0;
        /* negative fee at the totals */
        memset(meta + 62, 0xFF, 8);
        RESIDUE_OPEN();
        assert(RESIDUE_FEED(dp, 12345) == SIGNER_OK);
        assert(orchard_signer_get_totals(&s_signer, &totals) == SIGNER_ERR_FEE_NEGATIVE);
        memset(meta + 62, 0, 8);
        /* transparent: an input; a bad output; a digest mismatch */
        RESIDUE_OPEN();
        assert(orchard_signer_begin_transparent(&s_signer, 1, 0) ==
               SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
        RESIDUE_OPEN();
        assert(orchard_signer_begin_transparent(&s_signer, 0, 1) == SIGNER_OK);
        assert(orchard_signer_feed_transparent_output(&s_signer, w.sighash, 12) ==
               SIGNER_ERR_TRANSPARENT_BAD_OUTPUT);
        RESIDUE_OPEN();
        assert(orchard_signer_begin_transparent(&s_signer, 0, 0) == SIGNER_OK);
        assert(orchard_signer_verify_transparent(&s_signer, w.sighash) ==
               SIGNER_ERR_TRANSPARENT_MISMATCH);
        /* reviewed, confirmed, and then the host's sighash is wrong */
        RESIDUE_OPEN();
        assert(RESIDUE_FEED(dp, 12345) == SIGNER_OK);
        assert(orchard_signer_get_totals(&s_signer, &totals) == SIGNER_OK);
        assert(orchard_signer_confirm_action(&s_signer, 0) == SIGNER_OK);
        assert(orchard_signer_confirm_totals(&s_signer) == SIGNER_OK);
        assert(orchard_signer_verify(&s_signer, w.sighash) == SIGNER_ERR_SIGHASH_MISMATCH);
        /* non-empty transparent digest with no transparent pass: refused
         * before anything is shown, at the totals */
        meta[102] ^= 1;
        RESIDUE_OPEN();
        assert(RESIDUE_FEED(dp, 12345) == SIGNER_OK);
        assert(orchard_signer_get_totals(&s_signer, &totals) ==
               SIGNER_ERR_TRANSPARENT_NOT_EMPTY);
        meta[102] ^= 1;
        assert(s_signer.state == SIGNER_IDLE);

        /* The dispatcher, on a context and with buffers that live in .bss:
         * a session carried to a signature (FVK_RSP, memo screen — the
         * static memo scratch — totals, final confirmation, SIGN_RSP), one
         * the user cancels at the memo, and one the library aborts. */
        for(int variant = 0; variant < 3; variant++) {
            residue_script_reset(variant);
            if(variant == 2) {
                w.memo[2] ^= 0x40; /* declared memo != the one in the ciphertext */
            }
            RESIDUE_OPEN();
            assert(RESIDUE_FEED(dp, 12345) == (variant == 2 ? SIGNER_ERR_MEMO_MISMATCH : SIGNER_OK));
            if(variant != 2) {
                Zip244ActionsState o = s_signer.actions_state, i = s_signer.ironwood_actions_state;
                zip244_shielded_sighash_v6(&s_signer.tx_meta, &o, &i, sh);
                memzero(&o, sizeof(o));
                memzero(&i, sizeof(i));
            }
            orchard_signer_reset(&s_signer);

            uint8_t coin[4] = {1, 0, 0, 0};
            residue_push(1, HWP_MSG_FVK_REQ, 0, 0, coin, 4, 0);
            residue_push(2, HWP_MSG_TX_OUTPUT, HWP_TX_META_INDEX, 1, meta, sizeof(meta), 1);
            {
                static uint8_t body[HWP_ACTION_DATA_SIZE_V6];
                size_t n = 0;
                body[n++] = ZIP244_POOL_IRONWOOD;
                memcpy(body + n, action, 820); n += 820;
                memcpy(body + n, dp, 43); n += 43;
                for(int b = 0; b < 8; b++) body[n++] = (uint8_t)(12345ull >> (8 * b));
                memcpy(body + n, w.rseed, 32); n += 32;
                memcpy(body + n, w.memo, 512); n += 512;
                residue_push(3, HWP_MSG_TX_OUTPUT, 0, 1, body, (uint16_t)n, 1);
                memzero(body, sizeof(body));
            }
            residue_push(4, HWP_MSG_TX_OUTPUT, 1, 1, sh, 32, 1);
            {
                uint8_t sr[HWP_SIGN_REQ_FIXED];
                memset(sr, 0, sizeof(sr));
                memcpy(sr, sh, 32);
                memcpy(sr + 32, w.alpha, 32);
                residue_push(5, HWP_MSG_SIGN_REQ, 0, 0, sr, sizeof(sr), 0);
                memzero(sr, sizeof(sr));
            }
            if(variant == 2) w.memo[2] ^= 0x40;

            memset(&s_disp, 0, sizeof(s_disp));
            s_disp.io.serial_drain = residue_drain;
            s_disp.io.serial_send = residue_send;
            s_disp.io.get_tick_ms = residue_tick;
            s_disp.io.sleep_ms = residue_sleep;
            s_disp.io.should_exit = residue_exit;
            s_disp.ui.review_output = residue_review;
            s_disp.ui.review_memo = residue_memo;
            s_disp.ui.review_totals = residue_totals;
            s_disp.ui.confirm_tx = residue_confirm;
            s_disp.keys.ak = w.ak;
            s_disp.keys.nk = w.nk;
            s_disp.keys.rivk = w.rivk;
            s_disp.keys.ask = w.ask;
            s_disp.signer = &s_signer;
            s_disp.testnet = true;
            assert(hwp_dispatcher_run(&s_disp) == HWP_DISP_EXIT_REQUESTED);
            assert(s_script.sign_rsps == (variant == 0 ? 1 : 0));
            assert(s_script.memo_screens == (variant == 2 ? 0 : 1));
            assert(s_script.fvk_rsps == 1);
            /* the dispatcher's pointers into this frame, and the script */
            memset(&s_disp.keys, 0, sizeof(s_disp.keys));
            residue_script_reset(0);
        }
#undef RESIDUE_OPEN
#undef RESIDUE_FEED
        memzero(action, sizeof(action));
        memzero(dp, sizeof(dp));
        memzero(bad, sizeof(bad));
        memzero(sh, sizeof(sh));
        memzero(&totals, sizeof(totals));
    }

    /* Primitives the sequence above does not reach, on secret input:
     * F4Jumble in both directions, SHA-1, PBKDF2-HMAC-SHA256. */
    {
        uint8_t j[83];
        memcpy(j, w.seed, 64);
        memcpy(j + 64, w.sk, 19);
        f4jumble(j, sizeof(j));
        f4jumble_inv(j, sizeof(j));
        assert(memcmp(j, w.seed, 64) == 0);
        sha1_Raw(w.sk, 32, w.dig);
        pbkdf2_hmac_sha256(w.sk, 32, w.salt, sizeof(w.salt), 3, w.dig, 48);
        memzero(j, sizeof(j));
    }

    /* keyed one-shots */
    hmac_sha256(w.sk, 32, w.sighash, 32, w.mac);
    hmac_sha512(w.sk, 32, w.sighash, 32, w.mac);
    sha256_Raw(w.sk, 32, w.dig);
    sha512_Raw(w.sk, 32, w.dig);

    /* The g_d cache keeps the last diversifier's DiversifyHash. That is a
     * public value (it is part of the address), deliberately not wiped;
     * leave it on a fixed diversifier so the snapshots compare equal. */
    {
        static const uint8_t fixed_d[11] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
        memset(w.rseed, 0x44, 32);
        orchard_compute_cmx(fixed_d, w.pk_d, 1, w.rho, w.rseed, ORCHARD_NOTE_V3, w.cmx);
    }

    memzero(&w, sizeof(w));
}

/* Dead-stack window: 48 KB below main's frame, skipping the 512 bytes
 * nearest to it (live frames of main and of the copy itself). */
#define DEAD_STACK_BYTES (48u * 1024u)
#define DEAD_STACK_SKIP 512u

static size_t image_size(void) {
    return (size_t)(&_end - &__data_start);
}

/* Offsets are relative to __data_start; `nm -n` on the test binary maps
 * them to the static object that holds the residue. */
static int scan_verbatim(const char* region, const uint8_t* lo, size_t len, int fatal) {
    int hits = 0;
    for(int r = 0; r < s_num_patterns; r++) {
        uint8_t pat[16];
        for(int i = 0; i < 16; i++) pat[i] = s_patterns[r].masked[i] ^ 0xA5;
        const uint8_t* p = memmem(lo, len, pat, sizeof(pat));
        if(p) {
            printf("  %s: verbatim %s in %s at +0x%zx\n", fatal ? "RESIDUE" : "note",
                   s_patterns[r].name, region, (size_t)(p - lo));
            hits++;
        }
        memzero(pat, sizeof(pat));
    }
    return hits;
}

int main(void) {
    static const secrets A = {
        "legal winner thank year wave sausage worth useful legal winner thank year wave "
        "sausage worth useful legal winner thank year wave sausage worth title",
        "", {3, 1, 4, 1, 5, 9}, 0x17};
    static const secrets B = {
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
        "amount doctor acoustic avoid letter advice cage above",
        "TREZOR", {2, 7, 1, 8, 2, 8}, 0xe2};

    const size_t n = image_size();
    uint8_t* snap_a = malloc(n);
    uint8_t* snap_b = malloc(n);
    assert(snap_a && snap_b);

    pallas_init();
    /* warm-up, so one-time initialisation is not mistaken for residue */
    wallet_sequence(&B);

    /* The dead stack is copied to the heap right after the sequence returns
     * and scanned there: scanning it in place would find the scanner's own
     * copies of the patterns. */
    volatile uint8_t marker = 0;
    /* through a volatile integer: the compiler must not reason about reads
     * below `marker` (it would, rightly, call them out of bounds) */
    volatile uintptr_t marker_addr = (uintptr_t)&marker;
    const uint8_t* sp_hi = (const uint8_t*)marker_addr;
    uint8_t* stack_copy = malloc(DEAD_STACK_BYTES);
    assert(stack_copy);

    s_num_patterns = 0;
    wallet_sequence(&A);
    memcpy(stack_copy, sp_hi - DEAD_STACK_BYTES - DEAD_STACK_SKIP, DEAD_STACK_BYTES);
    memcpy(snap_a, &__data_start, n);
    int verbatim = scan_verbatim(".data/.bss", snap_a, n, 1);
    int stack_notes = scan_verbatim("dead stack", stack_copy, DEAD_STACK_BYTES, 0);

    s_num_patterns = 0;
    wallet_sequence(&B);
    memcpy(stack_copy, sp_hi - DEAD_STACK_BYTES - DEAD_STACK_SKIP, DEAD_STACK_BYTES);
    memcpy(snap_b, &__data_start, n);
    verbatim += scan_verbatim(".data/.bss", snap_b, n, 1);
    stack_notes += scan_verbatim("dead stack", stack_copy, DEAD_STACK_BYTES, 0);
    free(stack_copy);

    const size_t own_lo = (size_t)((const char*)s_patterns - &__data_start);
    const size_t own_hi = own_lo + sizeof(s_patterns);
    size_t differing = 0, runs = 0;
    for(size_t i = 0; i < n; i++) {
        if(i >= own_lo && i < own_hi) continue;
        if(snap_a[i] != snap_b[i]) {
            if(i == 0 || snap_a[i - 1] == snap_b[i - 1]) {
                if(runs < 400) printf("  RESIDUE: secret-dependent bytes at +0x%zx\n", i);
                runs++;
            }
            differing++;
        }
    }

    printf("test_residue: %zu bytes of .data/.bss scanned, %zu secret-dependent "
           "(%zu ranges), %d verbatim; dead stack: %d verbatim (informational)\n",
           n, differing, runs, verbatim, stack_notes);

    fflush(stdout);

    free(snap_a);
    free(snap_b);
    assert(differing == 0);
    assert(verbatim == 0);
    printf("test_residue: OK\n");
    return 0;
}

#else

int main(void) {
    printf("test_residue: SKIP (needs ELF/Linux linker symbols, no ASan)\n");
    return 0;
}

#endif
