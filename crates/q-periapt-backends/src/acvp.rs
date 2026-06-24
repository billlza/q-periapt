//! NIST ACVP ground-truth conformance for the full FIPS parameter family:
//! ML-KEM-512/768/1024 (FIPS 203) and ML-DSA-44/65/87 (FIPS 204).
//!
//! Validates our libcrux backends against the **authoritative** vectors published by
//! NIST (ACVP-Server `gen-val/json-files`). For each ML-KEM parameter set: deterministic
//! keygen from `(d, z)`, encapsulation from `(ek, m)`, and decapsulation — including the
//! VAL cases with modified ciphertexts that exercise the FO implicit-rejection path
//! (NIST's expected `k` is the pseudo-random reject value). For each ML-DSA parameter
//! set: deterministic keygen from ξ, plus the default external/pure/deterministic/
//! empty-context sigGen/sigVer cases; the **broader signature modes** the backend's
//! extended surface can reproduce — external/pure with **non-empty contexts** and
//! **hedged** randomness, **HashML-DSA** with a SHAKE-128 pre-hash, and the **internal
//! interface** (FIPS 204 Alg. 7/8, via the libcrux `acvp` feature; `externalMu = false`,
//! deterministic + hedged) — are pinned separately
//! (`acvp_ml_dsa_{44,65,87}_signature_modes`). Still out of scope: `externalMu = true`
//! (libcrux has no μ-injection entry) and non-SHAKE128 pre-hash (libcrux wires only the
//! SHAKE-128 variant). This is ground-truth conformance complementing the multi-backend
//! differential. Vectors are vendored under `vectors/acvp-ml-{kem-512,kem-768,kem-1024,
//! dsa-44,dsa-65,dsa-87,dsa-44-modes,dsa-65-modes,dsa-87-modes}.json`.

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

const ML_DSA_87_VECTORS: &str = include_str!("../vectors/acvp-ml-dsa-87.json");

/// NIST ACVP (FIPS 204) conformance for ML-DSA-87 (the enhanced-mode signature).
/// keyGen is the full NIST set (deterministic from ξ); the sigGen/sigVer cases are
/// the NIST vectors matching our backend's mode (external interface, pure,
/// deterministic, empty context) — broader modes are covered by the differential.
#[test]
fn acvp_ml_dsa_87_conformance() {
    use crate::{MlDsa87, ML_DSA_87_KEYGEN_SEED_LEN, ML_DSA_87_SIGN_RAND_LEN, ML_DSA_87_SIG_LEN};
    use q_periapt_sig::{Signer, Verifier};

    let v: DsaVectors = serde_json::from_str(ML_DSA_87_VECTORS).unwrap();
    assert_eq!(
        v.key_gen.len(),
        25,
        "vendored ACVP ML-DSA-87 keyGen incomplete"
    );
    assert!(!v.sig_gen.is_empty() && !v.sig_ver.is_empty());

    for t in &v.key_gen {
        let seed: [u8; ML_DSA_87_KEYGEN_SEED_LEN] = hex(&t.seed).try_into().unwrap();
        let (sk, pk) = MlDsa87::generate(seed);
        assert_eq!(
            &sk[..],
            hex(&t.sk).as_slice(),
            "ACVP ML-DSA-87 keyGen sk mismatch"
        );
        assert_eq!(
            &pk[..],
            hex(&t.pk).as_slice(),
            "ACVP ML-DSA-87 keyGen pk mismatch"
        );
    }

    for t in &v.sig_gen {
        let mut sig = [0u8; ML_DSA_87_SIG_LEN];
        MlDsa87
            .sign(
                &hex(&t.sk),
                &hex(&t.message),
                &[0u8; ML_DSA_87_SIGN_RAND_LEN],
                &mut sig,
            )
            .unwrap();
        assert_eq!(
            &sig[..],
            hex(&t.signature).as_slice(),
            "ACVP ML-DSA-87 sigGen mismatch"
        );
    }

    for t in &v.sig_ver {
        let accepted = MlDsa87
            .verify(&hex(&t.pk), &hex(&t.message), &hex(&t.signature))
            .is_ok();
        assert_eq!(
            accepted, t.test_passed,
            "ACVP ML-DSA-87 sigVer verdict mismatch"
        );
    }
}

// --- Broader ML-DSA signature modes (FIPS 204) -------------------------------------
//
// Beyond the default external/pure/deterministic/empty-context mode above, these pin
// the modes the backend's extended surface (sign_ctx/verify_ctx,
// sign_pre_hashed_shake128/verify_pre_hashed_shake128, sign_internal/verify_internal)
// can reproduce against NIST:
//   * external / pure — deterministic AND **hedged** (caller rnd), across **contexts**;
//   * **HashML-DSA** with a SHAKE-128 pre-hash;
//   * the **internal interface** (FIPS 204 Alg. 7/8, via the libcrux `acvp` feature) —
//     deterministic + hedged, `externalMu = false`.
// Still out of scope: `externalMu = true` (libcrux exposes no μ-injection entry) and
// non-SHAKE128 pre-hash (libcrux wires only the SHAKE-128 variant) — documented, not
// silently skipped.

#[derive(Deserialize)]
struct ModeVectors {
    #[serde(rename = "ext_sigGen")]
    ext_sig_gen: Vec<ExtSigGen>,
    #[serde(rename = "ext_sigVer")]
    ext_sig_ver: Vec<ExtSigVer>,
    #[serde(rename = "prehash_shake128_sigGen")]
    ph_sig_gen: Vec<ExtSigGen>,
    #[serde(rename = "prehash_shake128_sigVer")]
    ph_sig_ver: Vec<ExtSigVer>,
    #[serde(rename = "internal_sigGen")]
    int_sig_gen: Vec<ExtSigGen>,
    #[serde(rename = "internal_sigVer")]
    int_sig_ver: Vec<ExtSigVer>,
}
#[derive(Deserialize)]
struct ExtSigGen {
    sk: String,
    message: String,
    context: String,
    rnd: String,
    signature: String,
}
#[derive(Deserialize)]
struct ExtSigVer {
    pk: String,
    message: String,
    context: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

/// Run the broader-mode ACVP checks against `$backend` (an ML-DSA backend exposing the
/// extended surface). Returns the per-mode case counts.
macro_rules! check_dsa_modes {
    ($backend:expr, $sig_len:expr, $vectors:expr) => {{
        let v: ModeVectors = serde_json::from_str($vectors).unwrap();
        for t in &v.ext_sig_gen {
            let mut sig = vec![0u8; $sig_len];
            $backend
                .sign_ctx(
                    &hex(&t.sk),
                    &hex(&t.message),
                    &hex(&t.context),
                    &hex(&t.rnd),
                    &mut sig,
                )
                .unwrap();
            assert_eq!(
                sig,
                hex(&t.signature),
                "external sigGen (ctx/hedged) mismatch"
            );
        }
        for t in &v.ext_sig_ver {
            let ok = $backend
                .verify_ctx(
                    &hex(&t.pk),
                    &hex(&t.message),
                    &hex(&t.context),
                    &hex(&t.signature),
                )
                .is_ok();
            assert_eq!(ok, t.test_passed, "external sigVer (ctx) verdict mismatch");
        }
        for t in &v.ph_sig_gen {
            let mut sig = vec![0u8; $sig_len];
            $backend
                .sign_pre_hashed_shake128(
                    &hex(&t.sk),
                    &hex(&t.message),
                    &hex(&t.context),
                    &hex(&t.rnd),
                    &mut sig,
                )
                .unwrap();
            assert_eq!(sig, hex(&t.signature), "pre-hash SHAKE128 sigGen mismatch");
        }
        for t in &v.ph_sig_ver {
            let ok = $backend
                .verify_pre_hashed_shake128(
                    &hex(&t.pk),
                    &hex(&t.message),
                    &hex(&t.context),
                    &hex(&t.signature),
                )
                .is_ok();
            assert_eq!(
                ok, t.test_passed,
                "pre-hash SHAKE128 sigVer verdict mismatch"
            );
        }
        // Internal interface (FIPS 204 Alg. 7/8): signs the message directly, no context.
        for t in &v.int_sig_gen {
            let mut sig = vec![0u8; $sig_len];
            $backend
                .sign_internal(&hex(&t.sk), &hex(&t.message), &hex(&t.rnd), &mut sig)
                .unwrap();
            assert_eq!(sig, hex(&t.signature), "internal-interface sigGen mismatch");
        }
        for t in &v.int_sig_ver {
            let ok = $backend
                .verify_internal(&hex(&t.pk), &hex(&t.message), &hex(&t.signature))
                .is_ok();
            assert_eq!(
                ok, t.test_passed,
                "internal-interface sigVer verdict mismatch"
            );
        }
        (
            v.ext_sig_gen.len(),
            v.ext_sig_ver.len(),
            v.ph_sig_gen.len(),
            v.ph_sig_ver.len(),
            v.int_sig_gen.len(),
            v.int_sig_ver.len(),
        )
    }};
}

#[test]
fn acvp_ml_dsa_65_signature_modes() {
    use crate::{MlDsa65, ML_DSA_65_SIG_LEN};
    let (eg, ev, pg, pv, ig, iv) = check_dsa_modes!(
        MlDsa65,
        ML_DSA_65_SIG_LEN,
        include_str!("../vectors/acvp-ml-dsa-65-modes.json")
    );
    assert_eq!(
        (eg, ev),
        (30, 15),
        "external/pure det+hedged set incomplete"
    );
    assert!(pg >= 1 && pv >= 1, "expected SHAKE-128 pre-hash cases");
    assert_eq!((ig, iv), (30, 15), "internal-interface set incomplete");
}

#[test]
fn acvp_ml_dsa_87_signature_modes() {
    use crate::{MlDsa87, ML_DSA_87_SIG_LEN};
    let (eg, ev, pg, pv, ig, iv) = check_dsa_modes!(
        MlDsa87,
        ML_DSA_87_SIG_LEN,
        include_str!("../vectors/acvp-ml-dsa-87-modes.json")
    );
    assert_eq!(
        (eg, ev),
        (30, 15),
        "external/pure det+hedged set incomplete"
    );
    assert!(pg >= 1 && pv >= 1, "expected SHAKE-128 pre-hash cases");
    assert_eq!((ig, iv), (30, 15), "internal-interface set incomplete");
}

// --- Lowest FIPS parameter sets: ML-KEM-512 (L1) + ML-DSA-44 (L2) -------------------

const ML_KEM_512_VECTORS: &str = include_str!("../vectors/acvp-ml-kem-512.json");

/// NIST ACVP (FIPS 203) conformance for ML-KEM-512 (NIST L1, the smallest set): the
/// full 25 keyGen + 25 encaps + 10 decaps (incl. implicit-rejection VAL cases).
#[test]
fn acvp_ml_kem_512_conformance() {
    use crate::{MlKem512, ML_KEM_512_CT_LEN, ML_KEM_512_KEYGEN_SEED_LEN};

    let v: Vectors = serde_json::from_str(ML_KEM_512_VECTORS).unwrap();
    assert_eq!(
        (v.key_gen.len(), v.encap.len(), v.decap.len()),
        (25, 25, 10),
        "vendored ACVP ML-KEM-512 set incomplete"
    );
    const HALF: usize = ML_KEM_512_KEYGEN_SEED_LEN / 2;

    for t in &v.key_gen {
        let mut seed = [0u8; ML_KEM_512_KEYGEN_SEED_LEN];
        seed[..HALF].copy_from_slice(&hex(&t.d));
        seed[HALF..].copy_from_slice(&hex(&t.z));
        let (sk, pk) = MlKem512::generate(seed);
        assert_eq!(
            &sk[..],
            hex(&t.dk).as_slice(),
            "ACVP-512 keyGen dk mismatch"
        );
        assert_eq!(
            &pk[..],
            hex(&t.ek).as_slice(),
            "ACVP-512 keyGen ek mismatch"
        );
    }
    for t in &v.encap {
        let mut c = [0u8; ML_KEM_512_CT_LEN];
        let mut k = [0u8; SHARED_SECRET_LEN];
        MlKem512
            .encapsulate(&hex(&t.ek), &hex(&t.m), &mut c, &mut k)
            .unwrap();
        assert_eq!(&c[..], hex(&t.c).as_slice(), "ACVP-512 encaps c mismatch");
        assert_eq!(&k[..], hex(&t.k).as_slice(), "ACVP-512 encaps k mismatch");
    }
    for t in &v.decap {
        let mut k = [0u8; SHARED_SECRET_LEN];
        MlKem512
            .decapsulate(&hex(&t.dk), &hex(&t.c), &mut k)
            .unwrap();
        assert_eq!(&k[..], hex(&t.k).as_slice(), "ACVP-512 decaps k mismatch");
    }
}

const ML_DSA_44_VECTORS: &str = include_str!("../vectors/acvp-ml-dsa-44.json");

/// NIST ACVP (FIPS 204) conformance for ML-DSA-44 (NIST L2, the smallest ML-DSA).
/// keyGen is the full set; sigGen/sigVer are the default external/pure/deterministic/
/// empty-context cases (the broader modes are covered by `acvp_ml_dsa_44_signature_modes`).
#[test]
fn acvp_ml_dsa_44_conformance() {
    use crate::{MlDsa44, ML_DSA_44_KEYGEN_SEED_LEN, ML_DSA_44_SIGN_RAND_LEN, ML_DSA_44_SIG_LEN};
    use q_periapt_sig::{Signer, Verifier};

    let v: DsaVectors = serde_json::from_str(ML_DSA_44_VECTORS).unwrap();
    assert_eq!(
        v.key_gen.len(),
        25,
        "vendored ACVP ML-DSA-44 keyGen incomplete"
    );
    assert!(!v.sig_gen.is_empty() && !v.sig_ver.is_empty());

    for t in &v.key_gen {
        let seed: [u8; ML_DSA_44_KEYGEN_SEED_LEN] = hex(&t.seed).try_into().unwrap();
        let (sk, pk) = MlDsa44::generate(seed);
        assert_eq!(
            &sk[..],
            hex(&t.sk).as_slice(),
            "ACVP ML-DSA-44 keyGen sk mismatch"
        );
        assert_eq!(
            &pk[..],
            hex(&t.pk).as_slice(),
            "ACVP ML-DSA-44 keyGen pk mismatch"
        );
    }
    for t in &v.sig_gen {
        let mut sig = [0u8; ML_DSA_44_SIG_LEN];
        MlDsa44
            .sign(
                &hex(&t.sk),
                &hex(&t.message),
                &[0u8; ML_DSA_44_SIGN_RAND_LEN],
                &mut sig,
            )
            .unwrap();
        assert_eq!(
            &sig[..],
            hex(&t.signature).as_slice(),
            "ACVP ML-DSA-44 sigGen mismatch"
        );
    }
    for t in &v.sig_ver {
        let accepted = MlDsa44
            .verify(&hex(&t.pk), &hex(&t.message), &hex(&t.signature))
            .is_ok();
        assert_eq!(
            accepted, t.test_passed,
            "ACVP ML-DSA-44 sigVer verdict mismatch"
        );
    }
}

#[test]
fn acvp_ml_dsa_44_signature_modes() {
    use crate::{MlDsa44, ML_DSA_44_SIG_LEN};
    let (eg, ev, pg, pv, ig, iv) = check_dsa_modes!(
        MlDsa44,
        ML_DSA_44_SIG_LEN,
        include_str!("../vectors/acvp-ml-dsa-44-modes.json")
    );
    assert_eq!(
        (eg, ev),
        (30, 15),
        "external/pure det+hedged set incomplete"
    );
    assert!(pg >= 1 && pv >= 1, "expected SHAKE-128 pre-hash cases");
    assert_eq!((ig, iv), (30, 15), "internal-interface set incomplete");
}
