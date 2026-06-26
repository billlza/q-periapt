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
//! - `decapsulate` returns [`Q_PERIAPT_OK`] for any correct-length ciphertext whose key shares are
//!   public-valid, even if the PQ ciphertext is *cryptographically* invalid: ML-KEM's implicit
//!   rejection yields a pseudorandom secret, so there is **no secret-dependent decapsulation
//!   oracle**. The only rejections are on **public** inputs an attacker already controls — a length
//!   mismatch ([`Q_PERIAPT_ERR_LENGTH`]) or a low-order / non-contributory X25519 share
//!   ([`Q_PERIAPT_ERR_INVALID_KEYSHARE`]) — which reveal nothing about the secret key.
//! - Every entry point is wrapped in `catch_unwind`; a panic becomes
//!   [`Q_PERIAPT_ERR_PANIC`] instead of unwinding across the ABI (which is UB).
//! - **No aliasing (caller obligation):** within a single call, the input `(ptr, len)`
//!   buffers and the output `(ptr, len)` buffers **must not overlap**. Each call
//!   materializes its inputs as `&[u8]` and its outputs as `&mut [u8]` at the same time;
//!   an overlap would create simultaneous shared/mutable references to the same memory,
//!   which is undefined behavior. Pass distinct buffers (their required lengths differ in
//!   any case). This obligation is part of every function's `# Safety` contract below.

use core::slice;
use q_periapt_backends::{
    MlDsa65, MlKem768, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN,
    X25519, X25519_LEN,
};
use q_periapt_core::{combine, secure_wipe, CombineInput, Error, Profile};
use q_periapt_kem::HybridKem;
use q_periapt_policy::Policy;
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
/// A supplied **public** key share was invalid (e.g. a low-order / non-contributory X25519 share,
/// which would force an all-zero DH secret). This is a public-input validity rejection — it depends
/// only on attacker-known inputs, **not** on the secret key, so it is not a decapsulation oracle.
pub const Q_PERIAPT_ERR_INVALID_KEYSHARE: i32 = -6;

/// `profile = 1`: fast X-Wing-compatible combiner.
pub const Q_PERIAPT_PROFILE_COMPAT_XWING: u8 = 1;
/// `profile = 2`: context-bound combiner.
pub const Q_PERIAPT_PROFILE_CONTEXT_BOUND: u8 = 2;

/// The only suite this fixed C ABI implements. The combiner binds `suite_id`, so encapsulate /
/// decapsulate **reject** any other value: a caller must not bind false agility metadata (e.g.
/// claim `ML-KEM-1024`) into a key that this build actually derives from ML-KEM-768 + X25519.
pub const Q_PERIAPT_SUITE_ID: &[u8] = b"ML-KEM-768+X25519";

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

/// Materialize an input buffer as `&[u8]`. The caller must ensure it does not overlap any
/// output buffer in the same call (see the module-level no-aliasing convention).
unsafe fn in_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

/// Materialize an output buffer as `&mut [u8]`. The caller must ensure it does not overlap any
/// input or other output buffer in the same call (see the module-level no-aliasing convention).
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
        Error::InvalidKeyShare => Q_PERIAPT_ERR_INVALID_KEYSHARE,
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

/// Verify a detached-signed agility policy (`toml` + `signature`) under `vk` with the suite's
/// ML-DSA-65 root verifier, and write the combiner profile code its `select_profile()` chooses
/// into `out_profile` (one byte: [`Q_PERIAPT_PROFILE_COMPAT_XWING`] or
/// [`Q_PERIAPT_PROFILE_CONTEXT_BOUND`]). This threads the policy engine into the C ABI: load a
/// signed policy once, then pass the returned code to encapsulate/decapsulate instead of
/// hard-coding a profile. **Fail-closed:** an unauthenticated, weak-signer, or rolled-back policy
/// yields [`Q_PERIAPT_ERR_POLICY`]. Rollback is enforced against `last_trusted_version`: a
/// validly-signed policy whose `policy_version` is *older* than that is refused (pass `0` to accept
/// any version on first load; persist the accepted `policy_version` and pass it back thereafter).
///
/// # Safety
/// `toml`/`signature`/`vk` must be readable for their lengths; `out_profile` writable for
/// `out_profile_len` (which must be `1`). Input and output buffers must not overlap (see the
/// module-level no-aliasing convention).
#[no_mangle]
pub unsafe extern "C" fn q_periapt_profile_from_signed_policy(
    toml: *const u8,
    toml_len: usize,
    signature: *const u8,
    signature_len: usize,
    vk: *const u8,
    vk_len: usize,
    last_trusted_version: u32,
    out_profile: *mut u8,
    out_profile_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let (Some(toml), Some(sig), Some(vk), Some(out)) = (
            in_slice(toml, toml_len),
            in_slice(signature, signature_len),
            in_slice(vk, vk_len),
            out_slice(out_profile, out_profile_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if out.len() != 1 {
            return Q_PERIAPT_ERR_LENGTH;
        }
        // load_signed_monotonic (not load_signed) so a validly-signed but OLDER policy_version than
        // `last_trusted_version` is refused as a rollback — the documented fail-closed behaviour.
        match Policy::load_signed_monotonic(&MlDsa65, vk, toml, sig, last_trusted_version) {
            Ok(policy) => {
                out.copy_from_slice(&[policy.select_profile().to_u8()]);
                Q_PERIAPT_OK
            }
            Err(_) => Q_PERIAPT_ERR_POLICY,
        }
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
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
        let Ok(mut seed) = <[u8; 64]>::try_from(seed) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        if sk_o.len() != ML_KEM_768_SK_LEN || pk_o.len() != ML_KEM_768_PK_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let (mut sk, pk) = MlKem768::generate(seed);
        sk_o.copy_from_slice(&sk);
        pk_o.copy_from_slice(&pk);
        // Wipe our local copies of the long-term secret material (the caller keeps its own
        // copy in out_sk); the seed (d‖z) and sk are non-`Drop` arrays that would otherwise
        // linger in the freed stack frame.
        secure_wipe(&mut sk);
        secure_wipe(&mut seed);
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
        let Ok(mut secret) = <[u8; 32]>::try_from(secret) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        if sk_o.len() != X25519_LEN || pk_o.len() != X25519_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let (mut sk, pk) = X25519::generate(secret);
        sk_o.copy_from_slice(&sk);
        pk_o.copy_from_slice(&pk);
        // Wipe local copies of the long-term secret scalar + derived sk (see mlkem keypair).
        secure_wipe(&mut sk);
        secure_wipe(&mut secret);
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
        if suite != Q_PERIAPT_SUITE_ID {
            // This fixed ABI is ML-KEM-768 + X25519; reject a caller claiming any other suite so a
            // mismatched suite_id cannot be bound into the key as false agility metadata.
            return Q_PERIAPT_ERR_POLICY;
        }
        let (pq, trad) = (MlKem768, X25519);
        let kem =
            match HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version) {
                Ok(k) => k,
                Err(e) => return err_code(e),
            };
        match kem.encapsulate(
            pk_pq, pk_trad, context, rand_pq, rand_trad, ct_pq_o, ct_trad_o,
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
        if suite != Q_PERIAPT_SUITE_ID {
            // Fixed ML-KEM-768 + X25519 ABI: reject a mismatched suite_id (see encapsulate).
            return Q_PERIAPT_ERR_POLICY;
        }
        let (pq, trad) = (MlKem768, X25519);
        let kem =
            match HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version) {
                Ok(k) => k,
                Err(e) => return err_code(e),
            };
        match kem.decapsulate(sk_pq, ct_pq, pk_pq, sk_trad, ct_trad, pk_trad, context) {
            Ok(secret) => {
                secret_o.copy_from_slice(secret.as_bytes());
                Q_PERIAPT_OK
            }
            Err(e) => err_code(e),
        }
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
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
        let Some(combine_input) = CombineInput::from_transport(input) else {
            return Q_PERIAPT_ERR_LENGTH;
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
    fn profile_from_signed_policy_returns_selected_code_and_blocks_rollback() {
        use q_periapt_backends::ML_DSA_65_SIG_LEN;
        use q_periapt_sig::Signer;
        // A signed floor-3 / ContextBound policy at policy_version 2.
        let policy_toml = "schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\n\
            default_profile = \"ContextBound\"\n\
            allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
            allowed_sigs = [\"ML-DSA-65\"]\n";
        let (sk, vk) = MlDsa65::generate([8u8; 32]);
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let n = MlDsa65
            .sign(&sk, policy_toml.as_bytes(), &[0u8; 32], &mut sig)
            .unwrap();
        let mut prof = [0u8; 1];
        let prof_ptr = prof.as_mut_ptr();
        let run = |sig_ptr: *const u8, last_trusted: u32| -> i32 {
            unsafe {
                q_periapt_profile_from_signed_policy(
                    policy_toml.as_ptr(),
                    policy_toml.len(),
                    sig_ptr,
                    n,
                    vk.as_ptr(),
                    vk.len(),
                    last_trusted,
                    prof_ptr,
                    1,
                )
            }
        };
        // version 2 >= last-trusted 2 -> accepted, selects ContextBound.
        assert_eq!(run(sig.as_ptr(), 2), Q_PERIAPT_OK);
        assert_eq!(prof[0], Q_PERIAPT_PROFILE_CONTEXT_BOUND);
        // version 2 < last-trusted 3 -> ROLLBACK, refused (this is the doc'd fail-closed behaviour
        // that load_signed alone did NOT enforce).
        assert_eq!(run(sig.as_ptr(), 3), Q_PERIAPT_ERR_POLICY);
        // tampered signature -> refused.
        let mut bad = sig;
        bad[0] ^= 1;
        assert_eq!(run(bad.as_ptr(), 0), Q_PERIAPT_ERR_POLICY);
    }

    #[test]
    fn hybrid_encapsulate_rejects_forged_suite_id() {
        // The fixed ML-KEM-768+X25519 ABI must refuse a caller claiming a different suite, so a
        // mismatched suite_id cannot be bound into the key as false agility metadata.
        let (mut sk_pq, mut pk_pq) = (
            [0u8; Q_PERIAPT_MLKEM768_SK_LEN],
            [0u8; Q_PERIAPT_MLKEM768_PK_LEN],
        );
        let seed = [3u8; 64];
        let (mut sk_t, mut pk_t) = ([0u8; 32], [0u8; 32]);
        let xs = [4u8; 32];
        let (mut ct_pq, mut ct_t, mut secret) =
            ([0u8; Q_PERIAPT_MLKEM768_CT_LEN], [0u8; 32], [0u8; 32]);
        unsafe {
            q_periapt_mlkem768_keypair(
                seed.as_ptr(),
                64,
                sk_pq.as_mut_ptr(),
                sk_pq.len(),
                pk_pq.as_mut_ptr(),
                pk_pq.len(),
            );
            q_periapt_x25519_keypair(
                xs.as_ptr(),
                32,
                sk_t.as_mut_ptr(),
                32,
                pk_t.as_mut_ptr(),
                32,
            );
            let forged = b"ML-KEM-1024+X25519"; // a stronger suite this build does NOT implement
            let rc = q_periapt_hybrid_encapsulate(
                Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                forged.as_ptr(),
                forged.len(),
                1,
                pk_pq.as_ptr(),
                pk_pq.len(),
                pk_t.as_ptr(),
                32,
                b"ctx".as_ptr(),
                3,
                [0u8; 32].as_ptr(),
                32,
                [2u8; 32].as_ptr(),
                32,
                ct_pq.as_mut_ptr(),
                ct_pq.len(),
                ct_t.as_mut_ptr(),
                32,
                secret.as_mut_ptr(),
                32,
            );
            assert_eq!(
                rc, Q_PERIAPT_ERR_POLICY,
                "forged suite_id must be rejected, not keyed"
            );
            assert_eq!(secret, [0u8; 32], "no key material on the rejected path");
        }
    }

    #[test]
    fn hybrid_encapsulate_rejects_low_order_x25519_share_as_public_error() {
        // A low-order pk_trad (all-zero) is a PUBLIC-invalid key share: it must be rejected with the
        // dedicated public error code, NOT mislabeled internal, and NOT keyed.
        let (mut sk_pq, mut pk_pq) = (
            [0u8; Q_PERIAPT_MLKEM768_SK_LEN],
            [0u8; Q_PERIAPT_MLKEM768_PK_LEN],
        );
        let (mut ct_pq, mut ct_t, mut secret) =
            ([0u8; Q_PERIAPT_MLKEM768_CT_LEN], [0u8; 32], [0u8; 32]);
        unsafe {
            q_periapt_mlkem768_keypair(
                [3u8; 64].as_ptr(),
                64,
                sk_pq.as_mut_ptr(),
                sk_pq.len(),
                pk_pq.as_mut_ptr(),
                pk_pq.len(),
            );
            let low_order = [0u8; 32]; // a low-order X25519 point
            let rc = q_periapt_hybrid_encapsulate(
                Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                Q_PERIAPT_SUITE_ID.as_ptr(),
                Q_PERIAPT_SUITE_ID.len(),
                1,
                pk_pq.as_ptr(),
                pk_pq.len(),
                low_order.as_ptr(),
                32,
                b"ctx".as_ptr(),
                3,
                [0u8; 32].as_ptr(),
                32,
                [2u8; 32].as_ptr(),
                32,
                ct_pq.as_mut_ptr(),
                ct_pq.len(),
                ct_t.as_mut_ptr(),
                32,
                secret.as_mut_ptr(),
                32,
            );
            assert_eq!(
                rc, Q_PERIAPT_ERR_INVALID_KEYSHARE,
                "low-order X25519 share must be a public key-share error, not internal"
            );
            assert_eq!(secret, [0u8; 32], "no key material on the rejected path");
        }
    }

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
