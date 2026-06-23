#![no_main]
//! Fuzz ML-KEM-768 decapsulation with a valid key but an ARBITRARY ciphertext:
//! the implicit-rejection path must never panic and must always yield a secret
//! (no error oracle), for any attacker-chosen ciphertext.

use libfuzzer_sys::fuzz_target;
use pqt_backends::{MlKem768, ML_KEM_768_CT_LEN, ML_KEM_768_KEYGEN_SEED_LEN};
use pqt_core::Kem;

fuzz_target!(|data: &[u8]| {
    if data.len() < ML_KEM_768_KEYGEN_SEED_LEN + ML_KEM_768_CT_LEN {
        return;
    }
    let mut seed = [0u8; ML_KEM_768_KEYGEN_SEED_LEN];
    seed.copy_from_slice(&data[..ML_KEM_768_KEYGEN_SEED_LEN]);
    let (sk, _pk) = MlKem768::generate(seed);

    let ct = &data[ML_KEM_768_KEYGEN_SEED_LEN..ML_KEM_768_KEYGEN_SEED_LEN + ML_KEM_768_CT_LEN];
    let mut ss = [0u8; 32];
    // Must succeed (implicit rejection) for any ciphertext — never panic, never error.
    let r = MlKem768.decapsulate(&sk, ct, &mut ss);
    assert!(r.is_ok(), "decapsulate must not error on any well-sized ciphertext");
});
