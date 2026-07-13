//! Generate seed corpora for the cargo-fuzz targets (`fuzz/fuzz_targets/*`).
//!
//! Run from the workspace root:
//!   `cargo run -p q-periapt-backends --example gen_fuzz_corpus`
//!
//! Writes structured, deterministic seeds under `fuzz/corpus/{mlkem_decapsulate,combine}/`
//! — valid, boundary, and implicit-rejection inputs that give libFuzzer good starting
//! coverage instead of starting from random bytes. Re-running is idempotent (the seed
//! file names are stable).

#![allow(clippy::indexing_slicing)] // a dev-only generator over in-bounds fixed buffers

use q_periapt_backends::{MlKem768, ML_KEM_768_CT_LEN};
use q_periapt_core::Kem;
use std::fs;
use std::path::Path;

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::write(dir.join(name), bytes).expect("write seed");
}

/// Write a `seed(64) || ct` blob for the `mlkem_decapsulate` target, after
/// **self-checking the target's invariant**: decapsulation must never error (implicit
/// rejection — no oracle), for valid, boundary, AND perturbed ciphertexts alike.
fn write_mk(dir: &Path, name: &str, seed: [u8; 64], ct: &[u8]) {
    let (sk, _pk) = MlKem768::generate(seed).expect("deterministic ML-KEM key generation");
    let mut ss = [0u8; 32];
    assert!(
        MlKem768.decapsulate(&sk, ct, &mut ss).is_ok(),
        "seed {name} violates the decapsulate-never-errors invariant"
    );
    let mut v = Vec::with_capacity(64 + ct.len());
    v.extend_from_slice(&seed);
    v.extend_from_slice(ct);
    write(dir, name, &v);
}

/// A real ML-KEM-768 ciphertext that decapsulates cleanly under `seed`'s key.
fn valid_ct(seed: [u8; 64], rand: [u8; 32]) -> Vec<u8> {
    let (_sk, pk) = MlKem768::generate(seed).expect("deterministic ML-KEM key generation");
    let mut ct = vec![0u8; ML_KEM_768_CT_LEN];
    let mut ss = [0u8; 32];
    MlKem768
        .encapsulate(&pk, &rand, &mut ct, &mut ss)
        .expect("encapsulate");
    ct
}

fn main() {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/corpus".into());
    let mk = Path::new(&root).join("mlkem_decapsulate");
    let cb = Path::new(&root).join("combine");
    fs::create_dir_all(&mk).expect("mkdir mlkem_decapsulate");
    fs::create_dir_all(&cb).expect("mkdir combine");

    // --- mlkem_decapsulate: seed(64) || ct(1088) ---
    let seed_a = [1u8; 64];
    let ct_a = valid_ct(seed_a, [2u8; 32]);
    write_mk(&mk, "valid_a", seed_a, &ct_a); // happy path
    write_mk(&mk, "valid_b", [3u8; 64], &valid_ct([3u8; 64], [4u8; 32]));
    write_mk(
        &mk,
        "valid_zero_seed",
        [0u8; 64],
        &valid_ct([0u8; 64], [0u8; 32]),
    );

    // Boundary ciphertexts — all exercise the FO implicit-rejection branch.
    write_mk(&mk, "ct_zero", seed_a, &[0u8; ML_KEM_768_CT_LEN]);
    write_mk(&mk, "ct_ff", seed_a, &[0xffu8; ML_KEM_768_CT_LEN]);
    let ascending: Vec<u8> = (0..ML_KEM_768_CT_LEN).map(|i| i as u8).collect();
    write_mk(&mk, "ct_ascending", seed_a, &ascending);

    // The security-critical path: a *valid* ciphertext with a single perturbed byte
    // must still decapsulate (to a pseudorandom secret) — no decapsulation oracle.
    let mut flip_first = ct_a.clone();
    flip_first[0] ^= 1;
    write_mk(&mk, "ct_flip_first", seed_a, &flip_first);
    let mut flip_last = ct_a.clone();
    let last = flip_last.len() - 1;
    flip_last[last] ^= 0x80;
    write_mk(&mk, "ct_flip_last", seed_a, &flip_last);

    // --- combine: raw bytes (decoded by `arbitrary`) — diverse mutation starts that
    // complement the fuzzer-discovered corpus (empty fields hit the guard-reject paths).
    write(&cb, "seed_empty", &[]);
    write(&cb, "seed_zeros_256", &[0u8; 256]);
    write(&cb, "seed_ff_160", &[0xffu8; 160]);
    write(&cb, "seed_ascending_256", &(0..=255u8).collect::<Vec<u8>>());

    println!("wrote 8 mlkem_decapsulate seeds + 4 combine seeds under {root}/");
}
