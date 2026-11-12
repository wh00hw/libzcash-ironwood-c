/*
 * test_tx_fixture.h — builds real transactions for the signer / dispatcher
 * state-machine tests.
 *
 * "Real" means: every action's cmx, ephemeral_key and enc_ciphertext are
 * computed from the note the test describes, with the library's own
 * primitives (which are cross-checked against the orchard crate elsewhere:
 * tests/test_vectors.c, tests/test_ironwood.c), and the wallet / foreign
 * addresses are orchard-crate vectors (tests/test_address_vectors.h). The
 * tests then lie to the device the way a hostile host would — a different
 * recipient, body or memo than the action commits to — and check what the
 * device makes of it.
 *
 * Header-only, static functions; included by test_ownership.c and
 * test_hwp_dispatcher.c.
 */
#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "orchard.h"
#include "orchard_signer.h"
#include "redpallas.h"
#include "zip244.h"
#include "test_address_vectors.h"

/* The wallet under test: "BIP-39 abandon...about", testnet, an odd-y seed
 * (the case the previous release got wrong in the diversifier key). */
#define FX_WALLET  1
/* Somebody else's wallet on the same network. */
#define FX_FOREIGN 3

#define FX_BRANCH_NU6_3 0x37A5165Bu
#define FX_BRANCH_NU7   0x77190AD9u
#define FX_BRANCH_NU6   0xC8E71055u /* pre-v6 upgrade: not in the allow-list */

#define FX_ZEC 100000000ull

static inline const address_vector* fx_wallet(void) { return &ADDRESS_VECTORS[FX_WALLET]; }
static inline const address_vector* fx_foreign(void) { return &ADDRESS_VECTORS[FX_FOREIGN]; }

/* The wallet's full viewing key, exactly as a firmware holds it. */
static inline OrchardSignerFvk fx_wallet_fvk(void) {
    const address_vector* w = fx_wallet();
    OrchardSignerFvk fvk = {.ak = w->ak, .nk = w->nk, .rivk = w->rivk};
    return fvk;
}

static inline void fx_addr(uint8_t out[43], const uint8_t d[11], const uint8_t pk_d[32]) {
    memcpy(out, d, 11);
    memcpy(out + 11, pk_d, 32);
}
/* The wallet's default change address (internal scope, index 0). */
static inline void fx_addr_change(uint8_t out[43]) {
    fx_addr(out, fx_wallet()->int_d, fx_wallet()->int_pk_d);
}
/* The wallet's default receiving address. */
static inline void fx_addr_own_default(uint8_t out[43]) {
    fx_addr(out, fx_wallet()->d, fx_wallet()->pk_d);
}
/* One of the wallet's receiving addresses at a non-default diversifier. */
static inline void fx_addr_own_other(uint8_t out[43]) {
    fx_addr(out, fx_wallet()->extj_d, fx_wallet()->extj_pk_d);
}
/* A stranger's receiving address — or the attacker's. */
static inline void fx_addr_foreign(uint8_t out[43]) {
    fx_addr(out, fx_foreign()->d, fx_foreign()->pk_d);
}
/* A stranger's CHANGE address: internal scope, but of another wallet. */
static inline void fx_addr_foreign_change(uint8_t out[43]) {
    fx_addr(out, fx_foreign()->int_d, fx_foreign()->int_pk_d);
}

/* ZIP-302 "no memo". */
static inline void fx_memo_none(uint8_t memo[512]) {
    memset(memo, 0, 512);
    memo[0] = 0xF6;
}
static inline void fx_memo_text(uint8_t memo[512], const char* text) {
    memset(memo, 0, 512);
    memcpy(memo, text, strlen(text));
}

/* One output note as the transaction really contains it. */
typedef struct {
    Zip244Pool pool;
    uint8_t recipient[43];
    uint64_t value;
    uint8_t rseed[32];
    uint8_t memo[512];
} FxNote;

static inline FxNote fx_note(const uint8_t recipient[43], uint64_t value,
                             const char* memo_text, uint8_t tag) {
    FxNote n;
    memset(&n, 0, sizeof(n));
    n.pool = ZIP244_POOL_IRONWOOD;
    memcpy(n.recipient, recipient, 43);
    n.value = value;
    for(int i = 0; i < 32; i++) n.rseed[i] = (uint8_t)(0xA0 + 7 * i + 31 * tag);
    if(memo_text) {
        fx_memo_text(n.memo, memo_text);
    } else {
        fx_memo_none(n.memo);
    }
    return n;
}

/* The 820-byte action that carries `note` as its output: a per-action
 * nullifier (used as rho), the note commitment, and the real
 * ephemeral key + enc_ciphertext. cv_net, rk and out_ciphertext are filler:
 * the device hashes them but does not interpret them. */
static inline void fx_build_action(uint8_t action[820], const FxNote* note, uint8_t tag) {
    uint8_t version = (note->pool == ZIP244_POOL_IRONWOOD) ? ORCHARD_NOTE_V3 : ORCHARD_NOTE_V2;
    for(int i = 0; i < 820; i++) action[i] = (uint8_t)(i * 13 + tag);
    /* nullifier: any canonical field element; top bits clear. */
    for(int i = 0; i < 32; i++) action[32 + i] = (uint8_t)(0x42 ^ i ^ (tag * 5));
    action[63] &= 0x1F;
    orchard_compute_cmx(note->recipient, note->recipient + 11, note->value,
                        action + 32, note->rseed, version, action + 96);
    int rc = orchard_compute_enc_ciphertext_from_rseed(
        note->recipient, note->recipient + 11, note->value, note->rseed,
        action + 32, note->memo, version, action + 160, action + 128);
    assert(rc == 0);
}

/* v6 TxMeta wire (170 B, with the coin type): header constants, flags within policy, empty
 * transparent + Sapling digests, the given branch and value balances. */
static inline void fx_build_meta(uint8_t buf[ZIP244_TX_META_V6_EXT_SIZE], uint32_t branch,
                                 int64_t orchard_vb, int64_t ironwood_vb) {
    memset(buf, 0, ZIP244_TX_META_V6_EXT_SIZE);
    buf[0] = 0x06; buf[3] = 0x80;                                   /* version */
    buf[4] = 0x98; buf[5] = 0xB6; buf[6] = 0x84; buf[7] = 0xD8;     /* vgi */
    for(int i = 0; i < 4; i++) buf[8 + i] = (uint8_t)(branch >> (8 * i));
    buf[20] = 0x03;                                                 /* orchard_flags */
    for(int i = 0; i < 8; i++) buf[21 + i] = (uint8_t)((uint64_t)orchard_vb >> (8 * i));
    buf[61] = 0x03;                                                 /* ironwood_flags */
    for(int i = 0; i < 8; i++) buf[62 + i] = (uint8_t)((uint64_t)ironwood_vb >> (8 * i));
    zip244_empty_digest("ZTxIdTranspaHash", buf + 102);
    zip244_sapling_empty_digest(buf + 134);
    buf[ZIP244_TX_META_V6_SIZE] = 1; /* coin_type: testnet, the device under test */
}

/* The sighash the host would send for the session `src` has accumulated:
 * snapshot the streaming hashers so `src` itself is not finalised. */
static inline void fx_sighash(const OrchardSignerCtx* src, uint8_t out[32]) {
    Zip244ActionsState orchard_snap = src->actions_state;
    Zip244ActionsState ironwood_snap = src->ironwood_actions_state;
    zip244_shielded_sighash_v6(&src->tx_meta, &orchard_snap, &ironwood_snap, out);
}

/* True iff the context holds no trace of the session's viewing keys. */
static inline bool fx_ivks_wiped(const OrchardSignerCtx* ctx) {
    uint8_t acc = 0;
    for(int i = 0; i < 32; i++) acc |= ctx->ivk_external[i] | ctx->ivk_internal[i];
    return acc == 0;
}
