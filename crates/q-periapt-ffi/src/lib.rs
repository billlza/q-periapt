#![warn(missing_docs)]
#![allow(clippy::missing_safety_doc)] // safety contract documented per-function below

//! # q-periapt-ffi
//!
//! C ABI for the PQ/T hybrid suite, fixed to the default suite
//! **ML-KEM-768 + X25519** with SHA3-256 combining. One Rust core, callable from
//! C, Swift (via the static lib), Kotlin (via JNI/FFM), and anything with a C FFI.
//!
//! ## ABI conventions
//! - Every function returns an `int32` status ([`Q_PERIAPT_OK`] or a negative error).
//!   Errors encode **only public conditions** (null pointer, wrong length, policy)
//!   — never secret-dependent information.
//! - Buffers are passed as `(ptr, len)` pairs; lengths are validated.
//! - `decapsulate` always returns [`Q_PERIAPT_OK`] for a syntactically valid (correct
//!   length) ciphertext, even if cryptographically invalid: implicit rejection
//!   yields a pseudorandom secret, so there is **no decapsulation oracle**.
//! - Every entry point is wrapped in `catch_unwind`; a panic becomes
//!   [`Q_PERIAPT_ERR_PANIC`] instead of unwinding across the ABI (which is UB).

use core::slice;
use q_periapt_backends::{
    MlKem768, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN, X25519,
    X25519_LEN,
};
use q_periapt_core::{combine, CombineInput, Error, Profile};
use q_periapt_kem::HybridKem;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Success.
pub const Q_PERIAPT_OK: i32 = 0;
/// A required pointer was null.
pub const Q_PERIAPT_ERR_NULL: i32 = -1;
/// A buffer had the wrong length.
pub const Q_PERIAPT_ERR_LENGTH: i32 = -2;
/// The requested algorithm/profile combination is forbidden by policy.
pub const Q_PERIAPT_ERR_POLICY: i32 = -3;
/// A panic was caught at the ABI boundary.
pub const Q_PERIAPT_ERR_PANIC: i32 = -4;
/// An internal/backend error.
pub const Q_PERIAPT_ERR_INTERNAL: i32 = -5;

/// `profile = 1`: fast X-Wing-compatible combiner.
pub const Q_PERIAPT_PROFILE_COMPAT_XWING: u8 = 1;
/// `profile = 2`: context-bound combiner.
pub const Q_PERIAPT_PROFILE_CONTEXT_BOUND: u8 = 2;

// Literal values (so cbindgen emits numeric #defines for C), with compile-time
// assertions that they match the backend — they cannot silently drift.
/// ML-KEM-768 secret-key length, bytes.
pub const Q_PERIAPT_MLKEM768_SK_LEN: usize = 2400;
/// ML-KEM-768 public-key length, bytes.
pub const Q_PERIAPT_MLKEM768_PK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length, bytes.
pub const Q_PERIAPT_MLKEM768_CT_LEN: usize = 1088;
/// X25519 key / ciphertext length, bytes.
pub const Q_PERIAPT_X25519_LEN: usize = 32;
/// Combined shared-secret length, bytes.
pub const Q_PERIAPT_SECRET_LEN: usize = 32;

const _: () = {
    assert!(Q_PERIAPT_MLKEM768_SK_LEN == ML_KEM_768_SK_LEN);
    assert!(Q_PERIAPT_MLKEM768_PK_LEN == ML_KEM_768_PK_LEN);
    assert!(Q_PERIAPT_MLKEM768_CT_LEN == ML_KEM_768_CT_LEN);
    assert!(Q_PERIAPT_X25519_LEN == X25519_LEN);
};

unsafe fn in_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

unsafe fn out_slice<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts_mut(ptr, len))
    }
}

fn err_code(e: Error) -> i32 {
    match e {
        Error::InvalidLength => Q_PERIAPT_ERR_LENGTH,
        Error::PolicyDenied => Q_PERIAPT_ERR_POLICY,
        _ => Q_PERIAPT_ERR_INTERNAL,
    }
}

fn profile_from(p: u8) -> Option<Profile> {
    match p {
        Q_PERIAPT_PROFILE_COMPAT_XWING => Some(Profile::CompatXWing),
        Q_PERIAPT_PROFILE_CONTEXT_BOUND => Some(Profile::ContextBound),
        _ => None,
    }
}

/// Deterministically derive an ML-KEM-768 key pair from a 64-byte `seed`.
///
/// # Safety
/// `seed`/`out_sk`/`out_pk` must point to readable/writable regions of the given
/// lengths (`64` / [`Q_PERIAPT_MLKEM768_SK_LEN`] / [`Q_PERIAPT_MLKEM768_PK_LEN`]).
#[no_mangle]
pub unsafe extern "C" fn q_periapt_mlkem768_keypair(
    seed: *const u8,
    seed_len: usize,
    out_sk: *mut u8,
    out_sk_len: usize,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let (Some(seed), Some(sk_o), Some(pk_o)) = (
            in_slice(seed, seed_len),
            out_slice(out_sk, out_sk_len),
            out_slice(out_pk, out_pk_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        let Ok(seed) = <[u8; 64]>::try_from(seed) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        if sk_o.len() != ML_KEM_768_SK_LEN || pk_o.len() != ML_KEM_768_PK_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let (sk, pk) = MlKem768::generate(seed);
        sk_o.copy_from_slice(&sk);
        pk_o.copy_from_slice(&pk);
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Deterministically derive an X25519 key pair from a 32-byte scalar.
///
/// # Safety
/// All pointers must be valid for the given lengths (`32` each).
#[no_mangle]
pub unsafe extern "C" fn q_periapt_x25519_keypair(
    secret: *const u8,
    secret_len: usize,
    out_sk: *mut u8,
    out_sk_len: usize,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let (Some(secret), Some(sk_o), Some(pk_o)) = (
            in_slice(secret, secret_len),
            out_slice(out_sk, out_sk_len),
            out_slice(out_pk, out_pk_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        let Ok(secret) = <[u8; 32]>::try_from(secret) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        if sk_o.len() != X25519_LEN || pk_o.len() != X25519_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let (sk, pk) = X25519::generate(secret);
        sk_o.copy_from_slice(&sk);
        pk_o.copy_from_slice(&pk);
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Hybrid encapsulation to `(pk_pq, pk_trad)`.
///
/// Writes `out_ct_pq` ([`Q_PERIAPT_MLKEM768_CT_LEN`]), `out_ct_trad` ([`Q_PERIAPT_X25519_LEN`])
/// and `out_secret` ([`Q_PERIAPT_SECRET_LEN`]). `context` is bound only under
/// [`Q_PERIAPT_PROFILE_CONTEXT_BOUND`] and must then be non-empty.
///
/// # Safety
/// Every `(ptr, len)` pair must describe a valid region; output buffers must be
/// writable for their lengths.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn q_periapt_hybrid_encapsulate(
    profile: u8,
    suite_id: *const u8,
    suite_id_len: usize,
    policy_version: u32,
    pk_pq: *const u8,
    pk_pq_len: usize,
    pk_trad: *const u8,
    pk_trad_len: usize,
    context: *const u8,
    context_len: usize,
    rand_pq: *const u8,
    rand_pq_len: usize,
    rand_trad: *const u8,
    rand_trad_len: usize,
    out_ct_pq: *mut u8,
    out_ct_pq_len: usize,
    out_ct_trad: *mut u8,
    out_ct_trad_len: usize,
    out_secret: *mut u8,
    out_secret_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(profile) = profile_from(profile) else {
            return Q_PERIAPT_ERR_POLICY;
        };
        let (
            Some(suite),
            Some(pk_pq),
            Some(pk_trad),
            Some(context),
            Some(rand_pq),
            Some(rand_trad),
        ) = (
            in_slice(suite_id, suite_id_len),
            in_slice(pk_pq, pk_pq_len),
            in_slice(pk_trad, pk_trad_len),
            in_slice(context, context_len),
            in_slice(rand_pq, rand_pq_len),
            in_slice(rand_trad, rand_trad_len),
        )
        else {
            return Q_PERIAPT_ERR_NULL;
        };
        let (Some(ct_pq_o), Some(ct_trad_o), Some(secret_o)) = (
            out_slice(out_ct_pq, out_ct_pq_len),
            out_slice(out_ct_trad, out_ct_trad_len),
            out_slice(out_secret, out_secret_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if secret_o.len() != Q_PERIAPT_SECRET_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let (pq, trad) = (MlKem768, X25519);
        let kem =
            match HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version) {
                Ok(k) => k,
                Err(e) => return err_code(e),
            };
        let mut ss_pq = [0u8; 32];
        let mut ss_trad = [0u8; 32];
        match kem.encapsulate(
            pk_pq,
            pk_trad,
            context,
            rand_pq,
            rand_trad,
            ct_pq_o,
            &mut ss_pq,
            ct_trad_o,
            &mut ss_trad,
        ) {
            Ok(secret) => {
                secret_o.copy_from_slice(secret.as_bytes());
                Q_PERIAPT_OK
            }
            Err(e) => err_code(e),
        }
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Hybrid decapsulation. Returns [`Q_PERIAPT_OK`] and writes `out_secret`
/// ([`Q_PERIAPT_SECRET_LEN`]) for any correctly-sized ciphertext; an invalid ciphertext
/// yields a pseudorandom secret (implicit rejection — no oracle).
///
/// # Safety
/// Every `(ptr, len)` pair must describe a valid region; `out_secret` must be
/// writable for [`Q_PERIAPT_SECRET_LEN`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn q_periapt_hybrid_decapsulate(
    profile: u8,
    suite_id: *const u8,
    suite_id_len: usize,
    policy_version: u32,
    sk_pq: *const u8,
    sk_pq_len: usize,
    ct_pq: *const u8,
    ct_pq_len: usize,
    pk_pq: *const u8,
    pk_pq_len: usize,
    sk_trad: *const u8,
    sk_trad_len: usize,
    ct_trad: *const u8,
    ct_trad_len: usize,
    pk_trad: *const u8,
    pk_trad_len: usize,
    context: *const u8,
    context_len: usize,
    out_secret: *mut u8,
    out_secret_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(profile) = profile_from(profile) else {
            return Q_PERIAPT_ERR_POLICY;
        };
        let (
            Some(suite),
            Some(sk_pq),
            Some(ct_pq),
            Some(pk_pq),
            Some(sk_trad),
            Some(ct_trad),
            Some(pk_trad),
            Some(context),
        ) = (
            in_slice(suite_id, suite_id_len),
            in_slice(sk_pq, sk_pq_len),
            in_slice(ct_pq, ct_pq_len),
            in_slice(pk_pq, pk_pq_len),
            in_slice(sk_trad, sk_trad_len),
            in_slice(ct_trad, ct_trad_len),
            in_slice(pk_trad, pk_trad_len),
            in_slice(context, context_len),
        )
        else {
            return Q_PERIAPT_ERR_NULL;
        };
        let Some(secret_o) = out_slice(out_secret, out_secret_len) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if secret_o.len() != Q_PERIAPT_SECRET_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let (pq, trad) = (MlKem768, X25519);
        let kem =
            match HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version) {
                Ok(k) => k,
                Err(e) => return err_code(e),
            };
        let mut ss_pq = [0u8; 32];
        let mut ss_trad = [0u8; 32];
        match kem.decapsulate(
            sk_pq,
            ct_pq,
            pk_pq,
            sk_trad,
            ct_trad,
            pk_trad,
            context,
            &mut ss_pq,
            &mut ss_trad,
        ) {
            Ok(secret) => {
                secret_o.copy_from_slice(secret.as_bytes());
                Q_PERIAPT_OK
            }
            Err(e) => err_code(e),
        }
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Parse exactly nine fields, each prefixed by an 8-byte big-endian length. Returns
/// `None` on truncation or trailing bytes (an injective, unambiguous transport).
fn parse_lp9(mut buf: &[u8]) -> Option<[&[u8]; 9]> {
    let mut out: [&[u8]; 9] = [&[]; 9];
    for slot in &mut out {
        if buf.len() < 8 {
            return None;
        }
        let (len_bytes, rest) = buf.split_at(8);
        let len = u64::from_be_bytes(len_bytes.try_into().ok()?) as usize;
        if rest.len() < len {
            return None;
        }
        let (field, tail) = rest.split_at(len);
        *slot = field;
        buf = tail;
    }
    buf.is_empty().then_some(out)
}

/// Derive a combined secret directly from the combiner inputs — exposes the
/// `combine()` core (not the full hybrid) so the `ContextBound` / `CompatXWing`
/// reference vectors are reproducible byte-for-byte across every binding face.
///
/// `input` is the nine combiner fields, each 8-byte big-endian length-prefixed, in
/// the canonical order: `suite_id`, `policy_version` (a 4-byte big-endian `u32`),
/// `ss_pq`, `ss_trad`, `ct_pq`, `pk_pq`, `ct_trad`, `pk_trad`, `context`. `profile`
/// is [`Q_PERIAPT_PROFILE_COMPAT_XWING`] or [`Q_PERIAPT_PROFILE_CONTEXT_BOUND`].
///
/// # Safety
/// `input`/`out_secret` must be valid for `input_len` / [`Q_PERIAPT_SECRET_LEN`].
#[no_mangle]
pub unsafe extern "C" fn q_periapt_combine(
    profile: u8,
    input: *const u8,
    input_len: usize,
    out_secret: *mut u8,
    out_secret_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let (Some(input), Some(out)) = (
            in_slice(input, input_len),
            out_slice(out_secret, out_secret_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if out.len() != Q_PERIAPT_SECRET_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let Some(profile) = profile_from(profile) else {
            return Q_PERIAPT_ERR_POLICY;
        };
        let Some([suite, ver, ss_pq, ss_trad, ct_pq, pk_pq, ct_trad, pk_trad, context]) =
            parse_lp9(input)
        else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        let Ok(ver) = <[u8; 4]>::try_from(ver) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        let combine_input = CombineInput {
            suite_id: suite,
            policy_version: u32::from_be_bytes(ver),
            ss_pq,
            ss_trad,
            ct_pq,
            pk_pq,
            ct_trad,
            pk_trad,
            context,
        };
        match combine::<Sha3_256Xof>(profile, &combine_input) {
            Ok(secret) => {
                out.copy_from_slice(secret.as_bytes());
                Q_PERIAPT_OK
            }
            Err(e) => err_code(e),
        }
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn ffi_hybrid_roundtrip_context_bound() {
        let mut sk_pq = [0u8; Q_PERIAPT_MLKEM768_SK_LEN];
        let mut pk_pq = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        let seed = [3u8; 64];
        unsafe {
            assert_eq!(
                q_periapt_mlkem768_keypair(
                    seed.as_ptr(),
                    64,
                    sk_pq.as_mut_ptr(),
                    sk_pq.len(),
                    pk_pq.as_mut_ptr(),
                    pk_pq.len()
                ),
                Q_PERIAPT_OK
            );
        }
        let (mut sk_t, mut pk_t) = ([0u8; 32], [0u8; 32]);
        let xs = [4u8; 32];
        unsafe {
            assert_eq!(
                q_periapt_x25519_keypair(
                    xs.as_ptr(),
                    32,
                    sk_t.as_mut_ptr(),
                    32,
                    pk_t.as_mut_ptr(),
                    32
                ),
                Q_PERIAPT_OK
            );
        }

        let suite = b"ML-KEM-768+X25519";
        let ctx = b"ffi-ctx";
        let (r_pq, r_t) = ([1u8; 32], [2u8; 32]);
        let mut ct_pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut ct_t = [0u8; Q_PERIAPT_X25519_LEN];
        let mut sec = [0u8; Q_PERIAPT_SECRET_LEN];
        unsafe {
            assert_eq!(
                q_periapt_hybrid_encapsulate(
                    Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                    suite.as_ptr(),
                    suite.len(),
                    1,
                    pk_pq.as_ptr(),
                    pk_pq.len(),
                    pk_t.as_ptr(),
                    32,
                    ctx.as_ptr(),
                    ctx.len(),
                    r_pq.as_ptr(),
                    32,
                    r_t.as_ptr(),
                    32,
                    ct_pq.as_mut_ptr(),
                    ct_pq.len(),
                    ct_t.as_mut_ptr(),
                    32,
                    sec.as_mut_ptr(),
                    32
                ),
                Q_PERIAPT_OK
            );
        }

        let mut sec2 = [0u8; Q_PERIAPT_SECRET_LEN];
        unsafe {
            assert_eq!(
                q_periapt_hybrid_decapsulate(
                    Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                    suite.as_ptr(),
                    suite.len(),
                    1,
                    sk_pq.as_ptr(),
                    sk_pq.len(),
                    ct_pq.as_ptr(),
                    ct_pq.len(),
                    pk_pq.as_ptr(),
                    pk_pq.len(),
                    sk_t.as_ptr(),
                    32,
                    ct_t.as_ptr(),
                    32,
                    pk_t.as_ptr(),
                    32,
                    ctx.as_ptr(),
                    ctx.len(),
                    sec2.as_mut_ptr(),
                    32
                ),
                Q_PERIAPT_OK
            );
        }
        assert_eq!(sec, sec2, "FFI encap/decap must agree");
    }

    #[test]
    fn ffi_rejects_bad_profile_and_null() {
        let mut sec = [0u8; 32];
        // profile 0 is invalid
        let rc = unsafe {
            q_periapt_hybrid_decapsulate(
                0,
                core::ptr::null(),
                0,
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                sec.as_mut_ptr(),
                32,
            )
        };
        assert_eq!(rc, Q_PERIAPT_ERR_POLICY);
    }

    // Cross-platform consistency: the C ABI must reproduce the shared reference
    // vector (the same oracle the Swift/Kotlin/WASM bindings check against).
    #[test]
    fn ffi_matches_shared_vector() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../bindings/shared-test-vectors.json"
        );
        let json = std::fs::read_to_string(path).unwrap();
        let field = |k: &str| -> Vec<u8> {
            let pat = format!("\"{k}\"");
            let i = json.find(&pat).unwrap();
            let rest = &json[i + pat.len()..];
            let q1 = rest.find('"').unwrap();
            let q2 = rest[q1 + 1..].find('"').unwrap();
            let hex = &rest[q1 + 1..q1 + 1 + q2];
            (0..hex.len())
                .step_by(2)
                .map(|j| u8::from_str_radix(&hex[j..j + 2], 16).unwrap())
                .collect()
        };
        let suite = field("suite_id");
        let ctx = field("context");
        let sk_pq = field("sk_pq");
        let ct_pq = field("ct_pq");
        let pk_pq = field("pk_pq");
        let sk_t = field("sk_trad");
        let ct_t = field("ct_trad");
        let pk_t = field("pk_trad");
        let expected = field("secret");

        let mut sec = [0u8; Q_PERIAPT_SECRET_LEN];
        let rc = unsafe {
            q_periapt_hybrid_decapsulate(
                Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                suite.as_ptr(),
                suite.len(),
                1, // policy_version in the vector
                sk_pq.as_ptr(),
                sk_pq.len(),
                ct_pq.as_ptr(),
                ct_pq.len(),
                pk_pq.as_ptr(),
                pk_pq.len(),
                sk_t.as_ptr(),
                sk_t.len(),
                ct_t.as_ptr(),
                ct_t.len(),
                pk_t.as_ptr(),
                pk_t.len(),
                ctx.as_ptr(),
                ctx.len(),
                sec.as_mut_ptr(),
                32,
            )
        };
        assert_eq!(rc, Q_PERIAPT_OK);
        assert_eq!(
            &sec[..],
            &expected[..],
            "C ABI must reproduce the shared reference secret"
        );
    }

    /// The C ABI `q_periapt_combine` reproduces every combiner reference vector — the
    /// Rust face of the cross-platform `ContextBound`/`CompatXWing` vector check.
    #[test]
    fn combine_matches_reference_vectors() {
        const VECTORS: &str = include_str!("../../../bindings/contextbound-vectors.txt");
        let hex = |s: &str| {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let mut n = 0;
        for line in VECTORS.lines().filter(|l| !l.trim().is_empty()) {
            let p: Vec<&str> = line.split_whitespace().collect();
            let (profile, input, k) = (p[0].parse::<u8>().unwrap(), hex(p[1]), hex(p[2]));
            let mut out = [0u8; 32];
            let rc = unsafe {
                q_periapt_combine(
                    profile,
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                    out.len(),
                )
            };
            assert_eq!(rc, Q_PERIAPT_OK, "rc for: {line}");
            assert_eq!(&out[..], k.as_slice(), "combine K mismatch for: {line}");
            n += 1;
        }
        assert_eq!(n, 6, "expected 6 reference vectors");
    }
}
