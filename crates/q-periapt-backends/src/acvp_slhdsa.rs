//! NIST ACVP ground-truth conformance for the SLH-DSA-SHA2-{128,192,256}s backends
//! (FIPS 205), enabled by the `slh-dsa` cargo feature.
//!
//! Gives the hash-based signature backend the same authoritative assurance the
//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204) backends already have in `acvp.rs`,
//! validated against NIST's published vectors (ACVP-Server `gen-val/json-files`,
//! `SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205`).
//!
//! SLH-DSA ACVP keyGen is **deterministic** from `(SK.seed, SK.prf, PK.seed)`
//! (FIPS 205 Alg. 18, `slh_keygen_internal`). The `fips205` crate exposes that
//! determinism only through `try_keygen_with_rng`, whose keygen (Alg. 17) draws
//! `SK.seed`, then `SK.prf`, then `PK.seed` — each `N` bytes — via successive
//! `rng.try_fill_bytes` calls. Feeding a [`SeedReplayRng`] that yields exactly
//! `skSeed‖skPrf‖pkSeed` therefore reproduces NIST's `(sk, pk)` byte-for-byte.
//!
//! For sigGen we pin the NIST cases matching our backend's mode — **external**
//! interface, **pure** (no pre-hash), **deterministic**, **empty context** — which
//! is exactly what `Signer::sign` does (`try_sign(msg, b"", false)`); FIPS 205
//! deterministic signing substitutes `addrnd ← PK.seed`, a pure function of
//! `(sk, msg)`, so it is KAT-reproducible. sigVer pins NIST's verdict for a valid
//! signature and for a modified one (the FIPS 205 reject path). The internal
//! interface, pre-hash modes, hedged signing, and non-empty contexts are not
//! exercised by our backend's surface and are out of scope (documented, not
//! silently skipped) — mirroring the ML-DSA scope split in `acvp.rs`. Vectors are
//! vendored under `vectors/acvp-slh-dsa-sha2-{128,192,256}s.json`.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::{SlhDsaSha2_128s, SlhDsaSha2_192s, SlhDsaSha2_256s};
use q_periapt_sig::{Signer, Verifier};
use rand_core::{CryptoRng, RngCore};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[serde(rename = "keyGen")]
    key_gen: Vec<KeyGen>,
    #[serde(rename = "sigGen")]
    sig_gen: Vec<SigGen>,
    #[serde(rename = "sigVer")]
    sig_ver: Vec<SigVer>,
}
#[derive(Deserialize)]
struct KeyGen {
    #[serde(rename = "skSeed")]
    sk_seed: String,
    #[serde(rename = "skPrf")]
    sk_prf: String,
    #[serde(rename = "pkSeed")]
    pk_seed: String,
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

/// A deterministic `CryptoRngCore` that replays a fixed byte string in order.
///
/// Driving `fips205::*::try_keygen_with_rng` with `skSeed‖skPrf‖pkSeed` reproduces
/// the ACVP keyGen (which is deterministic from those three seeds). Marked
/// `CryptoRng` so it satisfies the `CryptoRngCore` bound; it is a test-only
/// ground-truth feeder, NOT a real generator. `next_u32`/`next_u64` are unused by
/// the keygen path (which only calls `try_fill_bytes`) and panic if reached.
struct SeedReplayRng {
    bytes: Vec<u8>,
    pos: usize,
}
impl SeedReplayRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }
}
impl RngCore for SeedReplayRng {
    fn next_u32(&mut self) -> u32 {
        unreachable!("SLH-DSA keygen draws only via fill_bytes")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("SLH-DSA keygen draws only via fill_bytes")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.pos + dest.len();
        assert!(end <= self.bytes.len(), "SeedReplayRng exhausted");
        dest.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for SeedReplayRng {}

/// Run the SLH-DSA ACVP conformance checks for one parameter set against `$backend`
/// and the matching `fips205` module `$m`. Verifies, in order:
///   * keyGen: deterministic `try_keygen_with_rng(skSeed‖skPrf‖pkSeed)` reproduces
///     NIST's `(sk, pk)` byte-for-byte;
///   * sigGen: our `Signer::sign` (deterministic / external / pure / empty-ctx)
///     reproduces NIST's signature byte-for-byte;
///   * sigVer: our `Verifier::verify` verdict matches NIST's `testPassed`.
macro_rules! check_slhdsa_acvp {
    ($backend:expr, $m:path, $sig_len:expr, $vectors:expr, $tag:literal) => {{
        use fips205::traits::{KeyGen as _, SerDes as _};
        let v: Vectors = serde_json::from_str($vectors).unwrap();
        assert_eq!(
            v.key_gen.len(),
            10,
            concat!("vendored ACVP ", $tag, " keyGen incomplete")
        );
        assert!(!v.sig_gen.is_empty() && !v.sig_ver.is_empty());

        // keyGen: deterministic try_keygen_with_rng(skSeed‖skPrf‖pkSeed) reproduces
        // NIST's (sk, pk) byte-for-byte.
        for t in &v.key_gen {
            let mut seed = hex(&t.sk_seed);
            seed.extend_from_slice(&hex(&t.sk_prf));
            seed.extend_from_slice(&hex(&t.pk_seed));
            let mut rng = SeedReplayRng::new(seed);
            let (vk, sk) = <$m>::try_keygen_with_rng(&mut rng).unwrap();
            assert_eq!(
                &sk.into_bytes()[..],
                hex(&t.sk).as_slice(),
                concat!("ACVP ", $tag, " keyGen sk mismatch")
            );
            assert_eq!(
                &vk.into_bytes()[..],
                hex(&t.pk).as_slice(),
                concat!("ACVP ", $tag, " keyGen pk mismatch")
            );
        }

        // sigGen: deterministic external/pure/empty-ctx signing reproduces NIST's
        // signature (the `_randomness` argument is unused for non-hedged SLH-DSA).
        for t in &v.sig_gen {
            let mut sig = vec![0u8; $sig_len];
            $backend
                .sign(&hex(&t.sk), &hex(&t.message), &[], &mut sig)
                .unwrap();
            assert_eq!(
                sig,
                hex(&t.signature),
                concat!("ACVP ", $tag, " sigGen mismatch")
            );
        }

        // sigVer: our verification verdict matches NIST's expected `testPassed`
        // (a valid signature, and a modified one that must be rejected).
        for t in &v.sig_ver {
            let accepted = $backend
                .verify(&hex(&t.pk), &hex(&t.message), &hex(&t.signature))
                .is_ok();
            assert_eq!(
                accepted, t.test_passed,
                concat!("ACVP ", $tag, " sigVer verdict mismatch")
            );
        }
    }};
}

/// NIST ACVP (FIPS 205) conformance for SLH-DSA-SHA2-128s (NIST L1, small variant).
#[test]
fn acvp_slh_dsa_sha2_128s_conformance() {
    check_slhdsa_acvp!(
        SlhDsaSha2_128s,
        fips205::slh_dsa_sha2_128s::KG,
        SlhDsaSha2_128s::SIG_LEN,
        include_str!("../vectors/acvp-slh-dsa-sha2-128s.json"),
        "SLH-DSA-SHA2-128s"
    );
}

/// NIST ACVP (FIPS 205) conformance for SLH-DSA-SHA2-192s (NIST L3, small variant).
#[test]
fn acvp_slh_dsa_sha2_192s_conformance() {
    check_slhdsa_acvp!(
        SlhDsaSha2_192s,
        fips205::slh_dsa_sha2_192s::KG,
        SlhDsaSha2_192s::SIG_LEN,
        include_str!("../vectors/acvp-slh-dsa-sha2-192s.json"),
        "SLH-DSA-SHA2-192s"
    );
}

/// NIST ACVP (FIPS 205) conformance for SLH-DSA-SHA2-256s (NIST L5, small variant).
/// 256s signing is the slowest variant; one sigGen case keeps the test tractable.
#[test]
fn acvp_slh_dsa_sha2_256s_conformance() {
    check_slhdsa_acvp!(
        SlhDsaSha2_256s,
        fips205::slh_dsa_sha2_256s::KG,
        SlhDsaSha2_256s::SIG_LEN,
        include_str!("../vectors/acvp-slh-dsa-sha2-256s.json"),
        "SLH-DSA-SHA2-256s"
    );
}
