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
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn io_context(error: io::Error, action: &str, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{action} {}: {error}", path.display()),
    )
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_context(error, "inspect directory", path))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "corpus directory must not be a symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

fn create_real_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_real_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|create_error| io_context(create_error, "create directory", path))?;
            require_real_directory(path)
        }
        Err(error) => Err(io_context(error, "inspect directory", path)),
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    assert!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'),
        "corpus seed name is not canonical: {name}"
    );
    let output = dir.join(name);
    let temporary = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| io_context(error, "create private corpus seed", &temporary))?;
    file.write_all(bytes)
        .map_err(|error| io_context(error, "write corpus seed", &temporary))?;
    file.sync_all()
        .map_err(|error| io_context(error, "sync corpus seed", &temporary))?;
    drop(file);
    if let Err(rename_error) = fs::rename(&temporary, &output) {
        let cleanup = fs::remove_file(&temporary)
            .map(|()| "pass".to_owned())
            .unwrap_or_else(|error| format!("failed: {error}"));
        return Err(io::Error::new(
            rename_error.kind(),
            format!(
                "publish corpus seed {}: {rename_error}; temporary cleanup: {cleanup:?}",
                output.display()
            ),
        ));
    }
    Ok(())
}

/// Write a `seed(64) || ct` blob for the `mlkem_decapsulate` target, after
/// **self-checking the target's invariant**: decapsulation must never error (implicit
/// rejection — no oracle), for valid, boundary, AND perturbed ciphertexts alike.
fn write_mk(dir: &Path, name: &str, seed: [u8; 64], ct: &[u8]) -> io::Result<()> {
    let (sk, _pk) = MlKem768::generate(seed).expect("deterministic ML-KEM key generation");
    let mut ss = [0u8; 32];
    assert!(
        MlKem768.decapsulate(&sk, ct, &mut ss).is_ok(),
        "seed {name} violates the decapsulate-never-errors invariant"
    );
    let mut v = Vec::with_capacity(64 + ct.len());
    v.extend_from_slice(&seed);
    v.extend_from_slice(ct);
    write(dir, name, &v)
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

fn main() -> io::Result<()> {
    assert!(
        std::env::args_os().nth(1).is_none(),
        "the corpus root is fixed at fuzz/corpus"
    );
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("q-periapt-backends must remain under the workspace crates directory");
    assert!(
        workspace.join("Cargo.toml").is_file(),
        "workspace Cargo.toml is missing"
    );
    require_real_directory(workspace)?;
    let fuzz = workspace.join("fuzz");
    require_real_directory(&fuzz)?;
    let root: PathBuf = workspace.join("fuzz/corpus");
    let mk = root.join("mlkem_decapsulate");
    let cb = root.join("combine");
    create_real_directory(&root)?;
    create_real_directory(&mk)?;
    create_real_directory(&cb)?;

    // --- mlkem_decapsulate: seed(64) || ct(1088) ---
    let seed_a = [1u8; 64];
    let ct_a = valid_ct(seed_a, [2u8; 32]);
    write_mk(&mk, "valid_a", seed_a, &ct_a)?; // happy path
    write_mk(&mk, "valid_b", [3u8; 64], &valid_ct([3u8; 64], [4u8; 32]))?;
    write_mk(
        &mk,
        "valid_zero_seed",
        [0u8; 64],
        &valid_ct([0u8; 64], [0u8; 32]),
    )?;

    // Boundary ciphertexts — all exercise the FO implicit-rejection branch.
    write_mk(&mk, "ct_zero", seed_a, &[0u8; ML_KEM_768_CT_LEN])?;
    write_mk(&mk, "ct_ff", seed_a, &[0xffu8; ML_KEM_768_CT_LEN])?;
    let ascending: Vec<u8> = (0..ML_KEM_768_CT_LEN).map(|i| i as u8).collect();
    write_mk(&mk, "ct_ascending", seed_a, &ascending)?;

    // The security-critical path: a *valid* ciphertext with a single perturbed byte
    // must still decapsulate (to a pseudorandom secret) — no decapsulation oracle.
    let mut flip_first = ct_a.clone();
    flip_first[0] ^= 1;
    write_mk(&mk, "ct_flip_first", seed_a, &flip_first)?;
    let mut flip_last = ct_a.clone();
    let last = flip_last.len() - 1;
    flip_last[last] ^= 0x80;
    write_mk(&mk, "ct_flip_last", seed_a, &flip_last)?;

    // --- combine: raw bytes (decoded by `arbitrary`) — diverse mutation starts that
    // complement the fuzzer-discovered corpus (empty fields hit the guard-reject paths).
    write(&cb, "seed_empty", &[])?;
    write(&cb, "seed_zeros_256", &[0u8; 256])?;
    write(&cb, "seed_ff_160", &[0xffu8; 160])?;
    write(&cb, "seed_ascending_256", &(0..=255u8).collect::<Vec<u8>>())?;

    println!(
        "wrote 8 mlkem_decapsulate seeds + 4 combine seeds under {}/",
        root.display()
    );
    Ok(())
}
