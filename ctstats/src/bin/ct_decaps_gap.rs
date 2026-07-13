//! Binary dataflow probe for the shipped ML-KEM decapsulation wrappers.
//!
//! This is an empirical check of the optimized, shipped `q-periapt-backends` binary, not a
//! source-level proof. It marks selected sub-fields of a FIPS 203 expanded decapsulation key and
//! runs the public ML-KEM-512/768/1024 APIs under Valgrind/Memcheck. Run as
//! `valgrind --track-origins=yes ct_decaps_gap <512|768|1024> <mode>`:
//!
//!   probe    mark genuine secret ŝ + z only              → MUST report 0 errors / 0 contexts
//!   ek       mark the embedded public encapsulation key     → diagnostic; no fixed count
//!   wholedk  mark the complete expanded decapsulation key   → diagnostic; no fixed count
//!   control  plant a secret-indexed memory access           → MUST report >0 errors
//!
//! Outside Valgrind every `mark_secret` is a no-op, so the binary still builds/runs anywhere.
use core::ffi::c_void;
use core::hint::black_box;

use q_periapt_backends::{
    MlKem1024, MlKem512, MlKem768, ML_KEM_1024_CT_LEN, ML_KEM_1024_PK_LEN, ML_KEM_1024_SK_LEN,
    ML_KEM_512_CT_LEN, ML_KEM_512_PK_LEN, ML_KEM_512_SK_LEN, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
    ML_KEM_768_SK_LEN,
};
use q_periapt_core::{Error, Kem};

const HASH_LEN: usize = 32;
const REJECTION_SEED_LEN: usize = 32;

#[link(name = "qperiapt_ct_shim", kind = "static")]
extern "C" {
    fn qperiapt_ct_mark_undefined(p: *mut c_void, n: usize);
}

/// Mark `buf` secret (Memcheck `MAKE_MEM_UNDEFINED`); a no-op outside Valgrind.
fn mark_secret(buf: &[u8]) {
    // SAFETY: valid pointer+len owned by `buf`, handed only to the Valgrind client request.
    unsafe { qperiapt_ct_mark_undefined(buf.as_ptr() as *mut c_void, buf.len()) };
}

fn fixture_error(parameter: &str, message: &str) -> ! {
    eprintln!("fixture error ({parameter}): {message}");
    std::process::exit(3);
}

fn fixture_result<T>(parameter: &str, message: &str, result: Result<T, Error>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("fixture error ({parameter}): {message}: {error}");
            std::process::exit(3);
        }
    }
}

fn planted_control(parameter: &str, dk: &[u8]) {
    // A deliberate secret-dependent memory index MUST be flagged by Memcheck. A simple branch is
    // insufficient because the optimizer may legitimately lower it to branchless arithmetic.
    let s0 = match dk.first() {
        Some(first) => [*first],
        None => fixture_error(parameter, "expanded decapsulation key is empty"),
    };
    mark_secret(&s0);

    // Force the marked byte through a volatile load so its known fixture value cannot be folded
    // into a constant. The table has all 256 entries, so every possible byte remains in bounds.
    // SAFETY: `s0` is an owned, valid one-byte array; undefinedness is Memcheck metadata only.
    let idx = unsafe { core::ptr::read_volatile(s0.as_ptr()) } as usize;
    let mut table = [0u8; 256];
    for (index, value) in table.iter_mut().enumerate() {
        *value = index as u8;
    }
    let table = black_box(table);
    // SAFETY: `idx` comes from one byte, hence is in 0..=255 and in bounds for `table`.
    // The secret-derived address is deliberate: this is the planted negative control.
    black_box(unsafe { core::ptr::read_volatile(table.as_ptr().add(idx)) });
    eprintln!("control ({parameter}): secret-indexed table load on ŝ[0] — Memcheck MUST flag it");
}

fn run_probe<K, const SK_LEN: usize, const PK_LEN: usize, const CT_LEN: usize>(
    parameter: &str,
    kem: &K,
    generate: fn([u8; 64]) -> Result<([u8; SK_LEN], [u8; PK_LEN]), Error>,
    mode: &str,
) where
    K: Kem,
{
    // FIPS 203 expanded DK layout for every parameter set:
    // dkPKE/ŝ ‖ ek ‖ H(ek) ‖ z. Derive the offsets from the public key and expanded-key
    // lengths rather than maintaining three independent sets of magic numbers.
    let public_suffix_len = match PK_LEN.checked_add(HASH_LEN + REJECTION_SEED_LEN) {
        Some(value) => value,
        None => fixture_error(parameter, "expanded-key layout overflow"),
    };
    let shat_end = match SK_LEN.checked_sub(public_suffix_len) {
        Some(value) => value,
        None => fixture_error(parameter, "expanded-key layout underflow"),
    };
    let ek_offset = shat_end;
    let ek_end = ek_offset + PK_LEN;
    let hash_end = ek_end + HASH_LEN;
    let z_offset = hash_end;
    if z_offset + REJECTION_SEED_LEN != SK_LEN {
        fixture_error(
            parameter,
            "expanded-key layout does not consume the complete key",
        );
    }

    // A valid ciphertext exercises decrypt→re-encrypt→accept (ŝ), while the mutation
    // exercises implicit rejection (z). Preflight both before marking any secret data so fixture
    // checks do not become part of the dataflow measurement.
    let (dk, ek) = fixture_result(
        parameter,
        "deterministic key generation failed",
        generate([0x42; 64]),
    );
    let mut ct_valid = [0u8; CT_LEN];
    let mut encapsulated_secret = [0u8; 32];
    fixture_result(
        parameter,
        "encapsulation failed",
        kem.encapsulate(&ek, &[0x37; 32], &mut ct_valid, &mut encapsulated_secret),
    );

    let mut ct_invalid = ct_valid;
    match ct_invalid.get_mut(CT_LEN / 2) {
        Some(byte) => *byte ^= 0x80,
        None => fixture_error(parameter, "ciphertext mutation offset out of range"),
    }

    let mut ss_valid_preflight = [0u8; 32];
    fixture_result(
        parameter,
        "valid decapsulation failed",
        kem.decapsulate(&dk, &ct_valid, &mut ss_valid_preflight),
    );
    if ss_valid_preflight != encapsulated_secret {
        fixture_error(
            parameter,
            "valid ciphertext did not reproduce the encapsulated secret",
        );
    }

    let mut ss_invalid_preflight = [0u8; 32];
    fixture_result(
        parameter,
        "implicit rejection returned an error",
        kem.decapsulate(&dk, &ct_invalid, &mut ss_invalid_preflight),
    );
    if ss_invalid_preflight == ss_valid_preflight {
        fixture_error(
            parameter,
            "invalid ciphertext did not exercise implicit rejection",
        );
    }

    if mode == "control" {
        planted_control(parameter, &dk);
        return;
    }

    let dk_marked = dk;
    match mode {
        "wholedk" => mark_secret(&dk_marked),
        "ek" => match dk_marked.get(ek_offset..ek_end) {
            Some(embedded_ek) => mark_secret(embedded_ek),
            None => fixture_error(parameter, "embedded-EK range out of bounds"),
        },
        "probe" => {
            // Only genuine secrets are marked. The embedded EK and H(EK) are public.
            match dk_marked.get(..shat_end) {
                Some(shat) => mark_secret(shat),
                None => fixture_error(parameter, "s-hat range out of bounds"),
            }
            match dk_marked.get(z_offset..) {
                Some(z) => mark_secret(z),
                None => fixture_error(parameter, "rejection-seed range out of bounds"),
            }
        }
        _ => {
            eprintln!("usage: ct_decaps_gap <512|768|1024> probe|ek|wholedk|control");
            std::process::exit(2);
        }
    }

    let mut ss_valid = [0u8; 32];
    fixture_result(
        parameter,
        "marked valid decapsulation failed",
        kem.decapsulate(&dk_marked, &ct_valid, &mut ss_valid),
    );
    black_box(ss_valid);

    let mut ss_invalid = [0u8; 32];
    fixture_result(
        parameter,
        "marked implicit rejection failed",
        kem.decapsulate(&dk_marked, &ct_invalid, &mut ss_invalid),
    );
    black_box(ss_invalid);

    eprintln!(
        "{mode} ({parameter}): ran the shipped q-periapt-backends {} wrapper over valid and \
         invalid ciphertexts; inspect Memcheck for data-dependent control flow and indexing",
        kem.algorithm()
    );
}

fn usage() -> ! {
    eprintln!("usage: ct_decaps_gap <512|768|1024> probe|ek|wholedk|control");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let parameter = match args.next() {
        Some(value) => value,
        None => usage(),
    };
    let mode = match args.next() {
        Some(value) => value,
        None => usage(),
    };
    if args.next().is_some() {
        usage();
    }

    match parameter.as_str() {
        "512" => run_probe::<_, ML_KEM_512_SK_LEN, ML_KEM_512_PK_LEN, ML_KEM_512_CT_LEN>(
            "ML-KEM-512",
            &MlKem512,
            MlKem512::generate,
            &mode,
        ),
        "768" => run_probe::<_, ML_KEM_768_SK_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_CT_LEN>(
            "ML-KEM-768",
            &MlKem768,
            MlKem768::generate,
            &mode,
        ),
        "1024" => run_probe::<_, ML_KEM_1024_SK_LEN, ML_KEM_1024_PK_LEN, ML_KEM_1024_CT_LEN>(
            "ML-KEM-1024",
            &MlKem1024,
            MlKem1024::generate,
            &mode,
        ),
        _ => usage(),
    }
}
