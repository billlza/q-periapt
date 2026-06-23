//! Multi-backend differential test for ML-KEM-768.
//!
//! Cross-validates our libcrux backend ([`crate::MlKem768`]) against the
//! independent RustCrypto `ml-kem` implementation. FIPS 203 fixes every byte
//! encoding, so two conformant implementations **must** agree byte-for-byte on
//! keygen, encapsulation, and decapsulation for the same `(d‖z, m)` inputs — any
//! divergence is a conformance or integration bug that fixed known-answer vectors
//! (only 3 X-Wing points) would miss. Fully deterministic: per-iteration inputs are
//! `SHAKE-256(counter)`, so there is no RNG and the run is reproducible.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::{MlKem768, ML_KEM_768_CT_LEN, ML_KEM_768_KEYGEN_SEED_LEN, SHARED_SECRET_LEN};
use ml_kem::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768 as RcMlKem768, B32};
use q_periapt_core::Kem;

fn b32(s: &[u8]) -> B32 {
    B32::try_from(s).unwrap()
}

#[test]
fn ml_kem_768_byte_identical_to_independent_rustcrypto() {
    // FIPS 203 keygen seed is d‖z, each 32 bytes.
    const HALF: usize = ML_KEM_768_KEYGEN_SEED_LEN / 2;
    for ctr in 0u32..64 {
        // Deterministic per-iteration inputs: SHAKE-256(counter) -> 96 bytes
        // = a 64-byte keygen seed (d‖z) + a 32-byte encapsulation message m.
        let expand = libcrux_sha3::shake256::<96>(&ctr.to_le_bytes());
        let mut seed = [0u8; ML_KEM_768_KEYGEN_SEED_LEN];
        seed.copy_from_slice(&expand[..ML_KEM_768_KEYGEN_SEED_LEN]);
        let m = &expand[ML_KEM_768_KEYGEN_SEED_LEN..];

        // --- keygen: byte-identical decapsulation + encapsulation keys ---
        let (sk, pk) = MlKem768::generate(seed);
        let (dk_rc, ek_rc) =
            RcMlKem768::generate_deterministic(&b32(&seed[..HALF]), &b32(&seed[HALF..]));
        assert_eq!(
            &ek_rc.as_bytes()[..],
            &pk[..],
            "encapsulation key diverged @ {ctr}"
        );
        assert_eq!(
            &dk_rc.as_bytes()[..],
            &sk[..],
            "decapsulation key diverged @ {ctr}"
        );

        // --- encapsulation: byte-identical ciphertext + shared secret ---
        let mut ct = [0u8; ML_KEM_768_CT_LEN];
        let mut ss = [0u8; SHARED_SECRET_LEN];
        MlKem768.encapsulate(&pk, m, &mut ct, &mut ss).unwrap();
        let (ct_rc, ss_rc) = ek_rc.encapsulate_deterministic(&b32(m)).unwrap();
        assert_eq!(&ct_rc[..], &ct[..], "ciphertext diverged @ {ctr}");
        assert_eq!(&ss_rc[..], &ss[..], "encaps shared secret diverged @ {ctr}");

        // --- decapsulation: the independent impl recovers the same secret ---
        let mut ss_dec = [0u8; SHARED_SECRET_LEN];
        MlKem768.decapsulate(&sk, &ct, &mut ss_dec).unwrap();
        let ss_rc_dec = dk_rc.decapsulate(&ct_rc).unwrap();
        assert_eq!(&ss_dec[..], &ss[..], "our decaps != our encaps @ {ctr}");
        assert_eq!(
            &ss_rc_dec[..],
            &ss_dec[..],
            "rustcrypto decaps diverged @ {ctr}"
        );
    }
}
