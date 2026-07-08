//! Generate Ironwood (NU6.3) cross-validation vectors from orchard 0.15.0-pre.2
//! for the libzcash-orchard-c device implementation.

use orchard::bundle::commitments::{hash_bundle_auth_empty, hash_bundle_txid_empty};
use orchard::bundle::TxVersion;
use orchard::note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho};
use orchard::note::{Note, NoteVersion};
use orchard::value::NoteValue;
use orchard::Address;
use orchard::ValuePool;

fn main() {
    // Same inputs as the existing V2 note-commit vector in tests/test_vectors.h
    let recipient_bytes: [u8; 43] = hex::decode(
        "3c150e6098b861716cc7f62835f69feb302193c92660444f26624fd13e00ea7ac774cd55074d6367efef37",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let rho_bytes: [u8; 32] =
        hex::decode("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")
            .unwrap()
            .try_into()
            .unwrap();
    let rseed_bytes: [u8; 32] =
        hex::decode("cafebabedeadbeef0102030405060708090a0b0c0d0e0f101112131415161718")
            .unwrap()
            .try_into()
            .unwrap();
    let value: u64 = 12345678;

    let recipient = Address::from_raw_address_bytes(&recipient_bytes).unwrap();
    let rho = Rho::from_bytes(&rho_bytes).unwrap();
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).unwrap();

    // 1. V3 (ZIP-2005) note commitment — validates the C rcm_v3 derivation.
    let note_v3 = Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let cmx_v3 = ExtractedNoteCommitment::from(note_v3.commitment());
    println!("note_commit_v3_expected_cmx = {}", hex::encode(cmx_v3.to_bytes()));

    // Sanity: V2 must still match the existing vector
    // (02defb39c8f2e1ecc945189373cf2a8e21d4e154398efa1621d5fb989e1deb36).
    let note_v2 = Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V2,
    )
    .unwrap();
    let cmx_v2 = ExtractedNoteCommitment::from(note_v2.commitment());
    println!("note_commit_v2_cmx (sanity)  = {}", hex::encode(cmx_v2.to_bytes()));

    // 2. V3 note encryption — validates the C lead-byte-0x03 enc_ciphertext path.
    //    No OVK (out_ciphertext unused); memo = ZIP-302 empty (0xF6 then zeros).
    let mut memo = [0u8; 512];
    memo[0] = 0xF6;
    let ne = orchard::note_encryption::IronwoodNoteEncryption::new(None, note_v3, memo);
    let enc = ne.encrypt_note_plaintext();
    let enc_bytes: &[u8] = enc.as_ref();
    let epk = <orchard::note_encryption::IronwoodDomain as zcash_note_encryption::Domain>::epk_bytes(
        ne.epk(),
    );
    println!("enc_v3_epk       = {}", hex::encode(epk.0));
    println!("enc_v3_ct_first64  = {}", hex::encode(&enc_bytes[..64]));
    println!("enc_v3_ct_last16 = {}", hex::encode(&enc_bytes[564..]));

    // 2b. V2 note encryption with the same inputs — cross-validates the
    //     legacy path (and the KDF input order) against the reference.
    let ne2 = orchard::note_encryption::OrchardNoteEncryption::new(None, note_v2, memo);
    let enc2 = ne2.encrypt_note_plaintext();
    let enc2_bytes: &[u8] = enc2.as_ref();
    let epk2 = <orchard::note_encryption::OrchardDomain as zcash_note_encryption::Domain>::epk_bytes(
        ne2.epk(),
    );
    println!("enc_v2_epk       = {}", hex::encode(epk2.0));
    println!("enc_v2_ct_first64  = {}", hex::encode(&enc2_bytes[..64]));
    println!("enc_v2_ct_last16 = {}", hex::encode(&enc2_bytes[564..]));

    // 3. v6 empty-bundle digests — validate the C personalization strings.
    for (pool, name) in [(ValuePool::Orchard, "orchard"), (ValuePool::Ironwood, "ironwood")] {
        let txid = hash_bundle_txid_empty(pool, TxVersion::V6).unwrap();
        let auth = hash_bundle_auth_empty(pool, TxVersion::V6).unwrap();
        println!("empty_{}_v6_txid = {}", name, hex::encode(txid.as_bytes()));
        println!("empty_{}_v6_auth = {}", name, hex::encode(auth.as_bytes()));
    }
    let txid_v5 = hash_bundle_txid_empty(ValuePool::Orchard, TxVersion::V5).unwrap();
    println!("empty_orchard_v5_txid (sanity) = {}", hex::encode(txid_v5.as_bytes()));

    // 4. Full v6 shielded sighash for a transaction with a single-action
    //    Ironwood bundle (no transparent, no Sapling, empty Orchard pool),
    //    computed end-to-end through zcash_primitives' TxIdDigester +
    //    v6_signature_hash. The device must reproduce it bit-for-bit from
    //    TxMeta + the 820-byte action wire encoding.
    full_v6_sighash_vector(recipient_bytes, note_v3, cmx_v3, epk, enc_bytes);
}

/// Effects-only authorization mirroring `pczt::EffectsOnly`.
struct Effects;
impl zcash_primitives::transaction::Authorization for Effects {
    type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling_crypto::bundle::EffectsOnly;
    type OrchardAuth = orchard::bundle::EffectsOnly;
}

fn full_v6_sighash_vector(
    _recipient_bytes: [u8; 43],
    note_v3: Note,
    cmx_v3: ExtractedNoteCommitment,
    epk: zcash_note_encryption::EphemeralKeyBytes,
    enc_ciphertext: &[u8],
) {
    use orchard::bundle::{BundleVersion, EffectsOnly};
    use orchard::note::TransmittedNoteCiphertext;
    use orchard::primitives::redpallas;
    use orchard::value::{NoteValue as OrchardNoteValue, ValueCommitTrapdoor, ValueCommitment};
    use orchard::Anchor;
    use zcash_primitives::transaction::sighash::SignableInput;
    use zcash_primitives::transaction::sighash_v6::v6_signature_hash;
    use zcash_primitives::transaction::txid::TxIdDigester;
    use zcash_primitives::transaction::TransactionData;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    use zcash_protocol::value::ZatBalance;

    // Deterministic rk from a fixed spend-authorizing scalar.
    let ask = redpallas::SigningKey::<redpallas::SpendAuth>::try_from([7u8; 32])
        .expect("valid scalar");
    let rk = redpallas::VerificationKey::from(&ask);

    // cv_net = commit(value - 0) with a zero trapdoor: a valid, deterministic
    // Pallas point (the effects digest only hashes its 32-byte encoding).
    let v_net = OrchardNoteValue::from_raw(12345678) - OrchardNoteValue::from_raw(0);
    let cv_net = ValueCommitment::derive(v_net, ValueCommitTrapdoor::from_bytes({ let mut b = [0u8; 32]; b[0] = 1; b }).unwrap());

    let encrypted_note = TransmittedNoteCiphertext {
        epk_bytes: epk.0,
        enc_ciphertext: enc_ciphertext.try_into().expect("580 bytes"),
        out_ciphertext: [0x55u8; 80],
    };

    // rho doubles as the action's nullifier (Orchard's split-action design).
    let nf = orchard::note::Nullifier::from_bytes(&note_v3.rho().to_bytes()).unwrap();

    println!("v6tx_rk = {}", hex::encode(<[u8; 32]>::from(&rk)));
    println!("v6tx_cv_net = {}", hex::encode(cv_net.to_bytes()));

    let action = orchard::Action::from_parts(nf, rk, cmx_v3, encrypted_note, cv_net, ())
        .expect("valid action");

    let anchor = Anchor::empty_tree();
    let bundle_version = BundleVersion::ironwood_v3();
    let flags = bundle_version.default_flags(); // 0x07: spends+outputs+crossAddress
    // Positive net balance (a shielded-only spend paying a 10000-zat fee):
    // lets the device-side test drive the FULL signer path, whose fee rule
    // rejects negative fees.
    let value_balance = ZatBalance::from_i64(10_000).unwrap();
    let bundle = orchard::Bundle::<EffectsOnly, ZatBalance>::from_parts(
        nonempty::NonEmpty::new(action),
        flags,
        value_balance,
        anchor,
        EffectsOnly,
        bundle_version,
    )
    .expect("representable flags");

    println!("v6tx_flag_byte = {:02x}", bundle.flag_byte());
    println!("v6tx_anchor = {}", hex::encode(anchor.to_bytes()));

    let tx: TransactionData<Effects> = TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        7,                            // lock_time
        BlockHeight::from_u32(4_200_000), // expiry_height
        None,                         // transparent
        None,                         // sapling
        None,                         // orchard (sealed pool, absent)
        Some(bundle),                 // ironwood
    );

    let txid_parts = tx.digest(TxIdDigester);
    let sighash = v6_signature_hash(&tx, &SignableInput::Shielded, &txid_parts);
    println!("v6tx_shielded_sighash = {}", hex::encode(sighash.as_bytes()));
}
