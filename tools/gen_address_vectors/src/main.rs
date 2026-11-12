//! Generates tests/test_address_vectors.h:
//!
//!     cd tools/gen_address_vectors
//!     cargo run --release > ../../tests/test_address_vectors.h
//!
//! For each (seed, coin_type) the reference values come from the `orchard`
//! crate: SpendingKey::from_zip32_seed -> FullViewingKey -> address_at(0,
//! External). That is the default address every librustzcash-based wallet
//! derives from the same full viewing key.
//!
//! Two extra facts are emitted per vector, computed here and cross-checked
//! against the crate:
//!
//!   * `ak_odd`: whether the un-normalised [ask]G has an odd y. The spec
//!     (and the crate) then negate ask, so the `ak` of the FVK always
//!     encodes with sign bit 0.
//!   * the "legacy" address: what libzcash-ironwood-c releases up to a55d168
//!     returned. They fed the un-normalised encoding (sign bit set when y is
//!     odd) into the diversifier-key PRF. Identical to the reference when
//!     `ak_odd` is 0; otherwise a different diversifier under the same
//!     incoming viewing key.
//!
//! Viewing-key vectors (on-device change detection):
//!
//!   * `ivk_external` / `ivk_internal`: FullViewingKey::to_ivk(scope), the
//!     second half of IncomingViewingKey::to_bytes().
//!   * `rivk_internal`: ToScalar(PRF^expand(rivk, [0x83] || ak || nk)). The
//!     crate keeps it private, so it is computed here and cross-checked:
//!     Commit^ivk(ak, nk, rivk_internal), evaluated with the `sinsemilla`
//!     crate, must equal the crate's internal ivk (and the same commitment
//!     with rivk must equal the external ivk, which validates the check).
//!   * `int_d` / `int_pk_d`: address_at(0, Internal), the default change
//!     address.
//!   * `ext_j` / `extj_d` / `extj_pk_d`: address_at(ext_j, External) for a
//!     non-zero diversifier index — an own receiving address that is not
//!     the default one.

use aes::Aes256;
use blake2b_simd::Params;
use ff::{FromUniformBytes, PrimeField};
use fpe::ff1::{BinaryNumeralString, FF1};
use group::GroupEncoding;
use orchard::keys::{Diversifier, FullViewingKey, Scope, SpendingKey};
use pasta_curves::{arithmetic::CurveExt, pallas};
use zip32::AccountId;

fn prf_expand(key: &[u8; 32], t: &[u8]) -> [u8; 64] {
    let h = Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state()
        .update(key)
        .update(t)
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(h.as_bytes());
    out
}

fn default_diversifier(dk: &[u8; 32]) -> [u8; 11] {
    let ff = FF1::<Aes256>::new(dk, 2).expect("valid radix");
    let enc = ff
        .encrypt(&[], &BinaryNumeralString::from_bytes_le(&[0u8; 11]))
        .unwrap();
    enc.to_bytes_le().try_into().unwrap()
}

/// I2LEBSP_255 of a 32-byte little-endian field element encoding.
fn le_bits_255(b: &[u8; 32]) -> Vec<bool> {
    (0..255).map(|i| (b[i / 8] >> (i % 8)) & 1 == 1).collect()
}

/// Commit^ivk_rivk(ak, nk) with the reference Sinsemilla implementation;
/// the result as the 32-byte encoding of ivk.
fn commit_ivk(ak: &[u8; 32], nk: &[u8; 32], rivk: &pallas::Scalar) -> [u8; 32] {
    let domain = sinsemilla::CommitDomain::new("z.cash:Orchard-CommitIvk");
    let bits = le_bits_255(ak).into_iter().chain(le_bits_255(nk));
    let x: pallas::Base = Option::from(domain.short_commit(bits, rivk)).expect("not bottom");
    x.to_repr()
}

fn c_bytes(b: &[u8]) -> String {
    let v: Vec<String> = b.iter().map(|x| format!("0x{:02x}", x)).collect();
    format!("{{{}}}", v.join(","))
}

fn seeds() -> Vec<(String, [u8; 64])> {
    let mut out = Vec::new();
    // BIP-39 "abandon abandon ... about", empty passphrase.
    let abandon = hex::decode(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
         9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    )
    .unwrap();
    out.push(("BIP-39 abandon...about".to_string(), abandon.try_into().unwrap()));
    // Byte patterns: seed_i[j] = (29*i + 7*j + 3) mod 256.
    for i in 1u32..=7 {
        let mut s = [0u8; 64];
        for (j, b) in s.iter_mut().enumerate() {
            *b = (29 * i + 7 * j as u32 + 3) as u8;
        }
        out.push((format!("pattern {}", i), s));
    }
    out
}

fn main() {
    let g = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");

    println!("// Default-address known-answer vectors: seed -> default Orchard address");
    println!("// (diversifier index 0, external scope), account 0.");
    println!("//");
    println!("// Reference: orchard crate 0.16.0, FullViewingKey::address_at(0, External).");
    println!("// ak_odd: the un-normalised [ask]G has odd y (ask is negated by the spec).");
    println!("// legacy_*: the address libzcash-ironwood-c returned up to a55d168; equal");
    println!("// to d / pk_d when ak_odd is 0, otherwise another address of the same IVK.");
    println!("//");
    println!("// Viewing keys (same crate): nk / rivk from FullViewingKey::to_bytes();");
    println!("// ivk_external / ivk_internal from to_ivk(scope); rivk_internal =");
    println!("// ToScalar(PRF^expand(rivk, [0x83] || ak || nk)), cross-checked through");
    println!("// Commit^ivk against ivk_internal; int_* = address_at(0, Internal), the");
    println!("// default change address; extj_* = address_at(ext_j, External), an own");
    println!("// receiving address at a non-default diversifier index.");
    println!("//");
    println!("// Generated by tools/gen_address_vectors — do not edit.");
    println!("#pragma once");
    println!("#include <stdint.h>");
    println!();
    println!("typedef struct {{");
    println!("    const char* name;");
    println!("    uint8_t seed[64];");
    println!("    uint32_t coin_type;");
    println!("    int ak_odd;");
    println!("    uint8_t ak[32];");
    println!("    uint8_t d[11];");
    println!("    uint8_t pk_d[32];");
    println!("    uint8_t legacy_d[11];");
    println!("    uint8_t legacy_pk_d[32];");
    println!("    uint8_t nk[32];");
    println!("    uint8_t rivk[32];");
    println!("    uint8_t rivk_internal[32];");
    println!("    uint8_t ivk_external[32];");
    println!("    uint8_t ivk_internal[32];");
    println!("    uint8_t int_d[11];");
    println!("    uint8_t int_pk_d[32];");
    println!("    uint32_t ext_j;");
    println!("    uint8_t extj_d[11];");
    println!("    uint8_t extj_pk_d[32];");
    println!("}} address_vector;");
    println!();
    println!("static const address_vector ADDRESS_VECTORS[] = {{");

    let mut n = 0;
    let mut n_odd = 0;
    for (name, seed) in seeds() {
        for coin in [133u32, 1u32] {
            let sk = SpendingKey::from_zip32_seed(&seed, coin, AccountId::ZERO).unwrap();
            let fvk = FullViewingKey::from(&sk);
            let fvk_bytes = fvk.to_bytes();
            let ak: [u8; 32] = fvk_bytes[0..32].try_into().unwrap();
            let nk: [u8; 32] = fvk_bytes[32..64].try_into().unwrap();
            let rivk: [u8; 32] = fvk_bytes[64..96].try_into().unwrap();

            let addr = fvk.address_at(0u32, Scope::External);
            let raw = addr.to_raw_address_bytes();
            let d: [u8; 11] = raw[0..11].try_into().unwrap();
            let pk_d: [u8; 32] = raw[11..43].try_into().unwrap();

            // Un-normalised [ask]G, ask = ToScalar(PRF^expand_sk([0x06])).
            let ask = pallas::Scalar::from_uniform_bytes(&prf_expand(sk.to_bytes(), &[0x06]));
            let mut ak_raw = (g * ask).to_bytes();
            let ak_odd = ak_raw[31] >> 7;
            // Same x as the crate's ak, which always has the sign bit clear.
            assert_eq!(ak[31] >> 7, 0);
            let mut ak_raw_x = ak_raw;
            ak_raw_x[31] &= 0x7f;
            assert_eq!(ak_raw_x, ak);

            // dk as the spec defines it, from the normalised ak: must give
            // the crate's default diversifier (validates this replication).
            let mut t = vec![0x82u8];
            t.extend_from_slice(&ak);
            t.extend_from_slice(&nk);
            let dk: [u8; 32] = prf_expand(&rivk, &t)[..32].try_into().unwrap();
            assert_eq!(default_diversifier(&dk), d);

            // Legacy dk: the sign of the un-normalised point leaks into bit 255.
            let mut t = vec![0x82u8];
            t.extend_from_slice(&ak_raw);
            t.extend_from_slice(&nk);
            let dk_legacy: [u8; 32] = prf_expand(&rivk, &t)[..32].try_into().unwrap();
            let legacy_d = default_diversifier(&dk_legacy);
            let legacy_addr = fvk.address(Diversifier::from_bytes(legacy_d), Scope::External);
            let legacy_raw = legacy_addr.to_raw_address_bytes();
            let legacy_pk_d: [u8; 32] = legacy_raw[11..43].try_into().unwrap();
            // It is an external address of the same full viewing key ...
            assert_eq!(fvk.scope_for_address(&legacy_addr), Some(Scope::External));
            // ... and differs from the default exactly when [ask]G is odd.
            assert_eq!(legacy_d != d, ak_odd == 1);
            ak_raw.fill(0);

            // Incoming viewing keys, both scopes, from the crate.
            let ivk_external: [u8; 32] =
                fvk.to_ivk(Scope::External).to_bytes()[32..].try_into().unwrap();
            let ivk_internal: [u8; 32] =
                fvk.to_ivk(Scope::Internal).to_bytes()[32..].try_into().unwrap();
            assert_ne!(ivk_external, ivk_internal);

            // rivk_internal, replicated (private in the crate) ...
            let mut t = vec![0x83u8];
            t.extend_from_slice(&ak);
            t.extend_from_slice(&nk);
            let rivk_int_scalar = pallas::Scalar::from_uniform_bytes(&prf_expand(&rivk, &t));
            let rivk_internal: [u8; 32] = rivk_int_scalar.to_repr();
            // ... and validated against the crate through Commit^ivk. The
            // external commitment validates the Sinsemilla replication itself.
            let rivk_scalar: pallas::Scalar =
                Option::from(pallas::Scalar::from_repr(rivk)).expect("canonical rivk");
            assert_eq!(commit_ivk(&ak, &nk, &rivk_scalar), ivk_external);
            assert_eq!(commit_ivk(&ak, &nk, &rivk_int_scalar), ivk_internal);

            // Default change address, and an own receiving address at a
            // non-default diversifier index.
            let int_addr = fvk.address_at(0u32, Scope::Internal);
            assert_eq!(fvk.scope_for_address(&int_addr), Some(Scope::Internal));
            let int_raw = int_addr.to_raw_address_bytes();
            let int_d: [u8; 11] = int_raw[0..11].try_into().unwrap();
            let int_pk_d: [u8; 32] = int_raw[11..43].try_into().unwrap();

            let ext_j: u32 = 0x00c0_ffee + n as u32;
            let extj_addr = fvk.address_at(ext_j, Scope::External);
            assert_eq!(fvk.scope_for_address(&extj_addr), Some(Scope::External));
            let extj_raw = extj_addr.to_raw_address_bytes();
            let extj_d: [u8; 11] = extj_raw[0..11].try_into().unwrap();
            let extj_pk_d: [u8; 32] = extj_raw[11..43].try_into().unwrap();
            assert_ne!(extj_d, d);

            println!("    {{\"{} / coin {}\",", name, coin);
            println!("     {},", c_bytes(&seed));
            println!("     {}, {},", coin, ak_odd);
            println!("     {},", c_bytes(&ak));
            println!("     {},", c_bytes(&d));
            println!("     {},", c_bytes(&pk_d));
            println!("     {},", c_bytes(&legacy_d));
            println!("     {},", c_bytes(&legacy_pk_d));
            println!("     {},", c_bytes(&nk));
            println!("     {},", c_bytes(&rivk));
            println!("     {},", c_bytes(&rivk_internal));
            println!("     {},", c_bytes(&ivk_external));
            println!("     {},", c_bytes(&ivk_internal));
            println!("     {},", c_bytes(&int_d));
            println!("     {},", c_bytes(&int_pk_d));
            println!("     0x{:08x},", ext_j);
            println!("     {},", c_bytes(&extj_d));
            println!("     {}}},", c_bytes(&extj_pk_d));
            n += 1;
            n_odd += ak_odd as usize;
        }
    }
    println!("}};");
    println!();
    println!("#define ADDRESS_VECTORS_COUNT {}", n);
    println!("#define ADDRESS_VECTORS_ODD_COUNT {}", n_odd);
    assert!(n_odd >= 4 && n - n_odd >= 4, "need a mix of parities");
}
