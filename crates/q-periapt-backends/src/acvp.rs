//! NIST ACVP ground-truth conformance: ML-KEM-768 + ML-KEM-1024 (FIPS 203) and
//! ML-DSA-65 (FIPS 204).
//!
//! Validates our libcrux backends against the **authoritative** vectors published by
//! NIST (ACVP-Server `gen-val/json-files`). For each ML-KEM parameter set: deterministic
//! keygen from `(d, z)`, encapsulation from `(ek, m)`, and decapsulation — including the
//! VAL cases with modified ciphertexts that exercise the FO implicit-rejection path
//! (NIST's expected `k` is the pseudo-random reject value). For ML-DSA-65: deterministic
//! keygen from ξ, plus the sigGen/sigVer cases matching our backend's mode (see below).
//! This is ground-truth conformance complementing the multi-backend differential.
//! Vectors are vendored under `vectors/acvp-ml-{kem-768,kem-1024,dsa-65}.json`.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::{MlKem768, ML_KEM_768_CT_LEN, ML_KEM_768_KEYGEN_SEED_LEN, SHARED_SECRET_LEN};
use q_periapt_core::Kem;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[serde(rename = "keyGen")]
    key_gen: Vec<KeyGen>,
    encap: Vec<Encap>,
    decap: Vec<Decap>,
}
#[derive(Deserialize)]
struct KeyGen {
    d: String,
    z: String,
    dk: String,
    ek: String,
}
#[derive(Deserialize)]
struct Encap {
    ek: String,
    m: String,
    c: String,
    k: String,
}
#[derive(Deserialize)]
struct Decap {
    dk: String,
    c: String,
    k: String,
}

fn hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    (0..s.len() / 2)
        .map(|i| {
            let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

const VECTORS: &str = include_str!("../vectors/acvp-ml-kem-768.json");

#[test]
fn acvp_ml_kem_768_conformance() {
    let v: Vectors = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        (v.key_gen.len(), v.encap.len(), v.decap.len()),
        (25, 25, 10),
        "vendored ACVP ML-KEM-768 set incomplete"
    );
    const HALF: usize = ML_KEM_768_KEYGEN_SEED_LEN / 2;

    // keyGen: generate(d‖z) must reproduce NIST's (dk, ek) byte-for-byte.
    for t in &v.key_gen {
        let mut seed = [0u8; ML_KEM_768_KEYGEN_SEED_LEN];
        seed[..HALF].copy_from_slice(&hex(&t.d));
        seed[HALF..].copy_from_slice(&hex(&t.z));
        let (sk, pk) = MlKem768::generate(seed);
        assert_eq!(&sk[..], hex(&t.dk).as_slice(), "ACVP keyGen dk mismatch");
        assert_eq!(&pk[..], hex(&t.ek).as_slice(), "ACVP keyGen ek mismatch");
    }

    // encaps: encapsulate(ek, m) must reproduce NIST's (c, k).
    for t in &v.encap {
        let mut c = [0u8; ML_KEM_768_CT_LEN];
        let mut k = [0u8; SHARED_SECRET_LEN];
        MlKem768
            .encapsulate(&hex(&t.ek), &hex(&t.m), &mut c, &mut k)
            .unwrap();
        assert_eq!(&c[..], hex(&t.c).as_slice(), "ACVP encaps c mismatch");
        assert_eq!(&k[..], hex(&t.k).as_slice(), "ACVP encaps k mismatch");
    }

    // decaps: decapsulate(dk, c) must reproduce NIST's k — for valid AND modified
    // ciphertexts (the latter exercise implicit rejection).
    for t in &v.decap {
        let mut k = [0u8; SHARED_SECRET_LEN];
        MlKem768
            .decapsulate(&hex(&t.dk), &hex(&t.c), &mut k)
            .unwrap();
        assert_eq!(&k[..], hex(&t.k).as_slice(), "ACVP decaps k mismatch");
    }
}

#[derive(Deserialize)]
struct DsaVectors {
    #[serde(rename = "keyGen")]
    key_gen: Vec<DsaKeyGen>,
    #[serde(rename = "sigGen")]
    sig_gen: Vec<SigGen>,
    #[serde(rename = "sigVer")]
    sig_ver: Vec<SigVer>,
}
#[derive(Deserialize)]
struct DsaKeyGen {
    seed: String,
    sk: String,
    pk: String,
}
#[derive(Deserialize)]
struct SigGen {
    sk: String,
    message: String,
    signature: String,
}
#[derive(Deserialize)]
struct SigVer {
    pk: String,
    message: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

const ML_DSA_VECTORS: &str = include_str!("../vectors/acvp-ml-dsa-65.json");

/// NIST ACVP (FIPS 204) conformance for ML-DSA-65. keyGen is the full NIST set
/// (deterministic from ξ); the sigGen/sigVer cases are restricted to the NIST
/// vectors that match our backend's mode (external interface, pure, deterministic,
/// empty context) — broader signing/verification conformance is covered by the
/// multi-backend differential vs RustCrypto `ml-dsa`.
#[test]
fn acvp_ml_dsa_65_conformance() {
    use crate::{MlDsa65, ML_DSA_65_KEYGEN_SEED_LEN, ML_DSA_65_SIGN_RAND_LEN, ML_DSA_65_SIG_LEN};
    use q_periapt_sig::{Signer, Verifier};

    let v: DsaVectors = serde_json::from_str(ML_DSA_VECTORS).unwrap();
    assert_eq!(
        v.key_gen.len(),
        25,
        "vendored ACVP ML-DSA-65 keyGen incomplete"
    );
    assert!(!v.sig_gen.is_empty() && !v.sig_ver.is_empty());

    // keyGen: generate(ξ) reproduces NIST's (sk, pk) byte-for-byte.
    for t in &v.key_gen {
        let seed: [u8; ML_DSA_65_KEYGEN_SEED_LEN] = hex(&t.seed).try_into().unwrap();
        let (sk, pk) = MlDsa65::generate(seed);
        assert_eq!(
            &sk[..],
            hex(&t.sk).as_slice(),
            "ACVP ML-DSA keyGen sk mismatch"
        );
        assert_eq!(
            &pk[..],
            hex(&t.pk).as_slice(),
            "ACVP ML-DSA keyGen pk mismatch"
        );
    }

    // sigGen: deterministic external signing reproduces NIST's signature.
    for t in &v.sig_gen {
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        MlDsa65
            .sign(
                &hex(&t.sk),
                &hex(&t.message),
                &[0u8; ML_DSA_65_SIGN_RAND_LEN],
                &mut sig,
            )
            .unwrap();
        assert_eq!(
            &sig[..],
            hex(&t.signature).as_slice(),
            "ACVP ML-DSA sigGen mismatch"
        );
    }

    // sigVer: our verification verdict matches NIST's expected `testPassed`.
    for t in &v.sig_ver {
        let accepted = MlDsa65
            .verify(&hex(&t.pk), &hex(&t.message), &hex(&t.signature))
            .is_ok();
        assert_eq!(
            accepted, t.test_passed,
            "ACVP ML-DSA sigVer verdict mismatch"
        );
    }
}

const ML_KEM_1024_VECTORS: &str = include_str!("../vectors/acvp-ml-kem-1024.json");

/// NIST ACVP (FIPS 203) conformance for ML-KEM-1024 (the enhanced-mode KEM): the full
/// set — 25 keyGen, 25 encaps, 10 decaps (incl. implicit-rejection VAL cases).
#[test]
fn acvp_ml_kem_1024_conformance() {
    use crate::{MlKem1024, ML_KEM_1024_CT_LEN, ML_KEM_1024_KEYGEN_SEED_LEN};

    let v: Vectors = serde_json::from_str(ML_KEM_1024_VECTORS).unwrap();
    assert_eq!(
        (v.key_gen.len(), v.encap.len(), v.decap.len()),
        (25, 25, 10),
        "vendored ACVP ML-KEM-1024 set incomplete"
    );
    const HALF: usize = ML_KEM_1024_KEYGEN_SEED_LEN / 2;

    for t in &v.key_gen {
        let mut seed = [0u8; ML_KEM_1024_KEYGEN_SEED_LEN];
        seed[..HALF].copy_from_slice(&hex(&t.d));
        seed[HALF..].copy_from_slice(&hex(&t.z));
        let (sk, pk) = MlKem1024::generate(seed);
        assert_eq!(
            &sk[..],
            hex(&t.dk).as_slice(),
            "ACVP-1024 keyGen dk mismatch"
        );
        assert_eq!(
            &pk[..],
            hex(&t.ek).as_slice(),
            "ACVP-1024 keyGen ek mismatch"
        );
    }
    for t in &v.encap {
        let mut c = [0u8; ML_KEM_1024_CT_LEN];
        let mut k = [0u8; SHARED_SECRET_LEN];
        MlKem1024
            .encapsulate(&hex(&t.ek), &hex(&t.m), &mut c, &mut k)
            .unwrap();
        assert_eq!(&c[..], hex(&t.c).as_slice(), "ACVP-1024 encaps c mismatch");
        assert_eq!(&k[..], hex(&t.k).as_slice(), "ACVP-1024 encaps k mismatch");
    }
    for t in &v.decap {
        let mut k = [0u8; SHARED_SECRET_LEN];
        MlKem1024
            .decapsulate(&hex(&t.dk), &hex(&t.c), &mut k)
            .unwrap();
        assert_eq!(&k[..], hex(&t.k).as_slice(), "ACVP-1024 decaps k mismatch");
    }
}
