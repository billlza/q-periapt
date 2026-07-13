#![warn(missing_docs)]
#![allow(clippy::missing_safety_doc)] // safety contract documented per-function below

//! # q-periapt-ffi
//!
//! C ABI for the PQ/T hybrid suite, fixed to the default suite
//! **ML-KEM-768 + X25519** with SHA3-256 combining. One Rust core, callable from
//! C, Swift (via the static lib), Kotlin/JVM (via FFM), Android (via the JNI
//! adapter in `bindings/android`), and anything with a C FFI.
//!
//! ## ABI conventions
//! - Every function returns an `int32` status ([`Q_PERIAPT_OK`] or a negative error).
//!   Public input failures are classified (null pointer, wrong length, policy, aliasing, or an
//!   invalid public key share). Entropy and local key/provider failures cross the ABI only as
//!   coarse [`Q_PERIAPT_ERR_ENTROPY`] or [`Q_PERIAPT_ERR_INTERNAL`] statuses; no provider-specific
//!   or local-secret diagnostic is exposed.
//! - Buffers are passed as `(ptr, len)` pairs; lengths are validated.
//! - `decapsulate` returns [`Q_PERIAPT_OK`] for any correct-length ciphertext whose key shares are
//!   public-valid, even if the PQ ciphertext is *cryptographically* invalid: ML-KEM's implicit
//!   rejection yields a pseudorandom secret, so there is **no secret-dependent decapsulation
//!   oracle**. The only rejections are on **public** inputs an attacker already controls — a length
//!   mismatch ([`Q_PERIAPT_ERR_LENGTH`]) or an invalid public key share (a non-canonical ML-KEM
//!   encapsulation key, or a low-order/non-contributory X25519 point,
//!   [`Q_PERIAPT_ERR_INVALID_KEYSHARE`]) — which reveal nothing about the secret key. A malformed
//!   local expanded ML-KEM decapsulation key is an opaque [`Q_PERIAPT_ERR_INTERNAL`] failure and is
//!   never confused with peer behavior.
//! - Every entry point is wrapped in `catch_unwind`; a panic becomes
//!   [`Q_PERIAPT_ERR_PANIC`] instead of unwinding across the ABI (which is UB).
//! - **No aliasing (checked):** within a single call, the input `(ptr, len)` buffers and the
//!   output `(ptr, len)` buffers must not overlap — materializing the inputs as `&[u8]` and the
//!   outputs as `&mut [u8]` at the same time would create simultaneous shared/mutable references to
//!   the same memory (UB). Rather than rely on the caller, the multi-buffer entry points **check
//!   the raw `(ptr, len)` ranges up front and return [`Q_PERIAPT_ERR_ALIASING`]** before any slice
//!   is formed, turning the footgun into a defined error. Pass distinct buffers (their required
//!   lengths differ in any case).

use core::slice;
use q_periapt_backends::{
    MlDsa65, MlKem768, MlKem768XWingSeed, Sha3_256Xof, DEFAULT_SUITE_ID, DEFAULT_SUITE_ID_CSTR,
    X25519,
};
#[cfg(test)]
use q_periapt_backends::{
    ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN, ML_KEM_768_XWING_SEED_LEN, X25519_LEN,
};
#[cfg(test)]
use q_periapt_core::{combine, CombineInput};
use q_periapt_core::{
    encode_policy_bound_context, policy_bound_context_len, Error, Profile, ZeroizingBytes,
};
use q_periapt_kem::HybridKem;
use q_periapt_policy::{HybridSuite, Policy, TrustedPolicyState};
use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// C ABI version for this header/library contract.
pub const Q_PERIAPT_ABI_VERSION: u32 = 2;
/// Maximum exact signed-policy document size accepted by the policy ABI.
pub const Q_PERIAPT_MAX_SIGNED_POLICY_BYTES: usize = 65_536;
/// Maximum application-context size accepted by policy-bound operations.
pub const Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES: usize = 65_536;
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
/// An output buffer overlapped an input (or another output) buffer. Rather than risk the undefined
/// behavior of materializing aliasing `&[u8]`/`&mut [u8]`, the call is rejected. (Callers should pass
/// disjoint buffers; their required lengths differ in any case.)
pub const Q_PERIAPT_ERR_ALIASING: i32 = -7;
/// The operating-system cryptographic random-number generator failed.
pub const Q_PERIAPT_ERR_ENTROPY: i32 = -8;

/// `profile = 2`: context-bound combiner.
pub const Q_PERIAPT_PROFILE_CONTEXT_BOUND: u8 = 2;
/// Canonical signed-policy decision encoding version.
pub const Q_PERIAPT_POLICY_DECISION_VERSION: u8 = 1;
/// Length of a trusted policy state (`version_be || SHA3-256(exact_policy_bytes)`).
pub const Q_PERIAPT_TRUSTED_POLICY_STATE_LEN: usize = 36;
/// Length of an authenticated fixed-suite decision.
///
/// Layout: `decision_version || suite_code || profile_code || key_format_code ||
/// policy_version_be || policy_digest`.
pub const Q_PERIAPT_POLICY_DECISION_LEN: usize = 40;
/// Suite code for the fixed ML-KEM-768 + X25519 ABI.
pub const Q_PERIAPT_SUITE_MLKEM768_X25519: u8 = 1;
/// Expanded/importable secret-key representation.
pub const Q_PERIAPT_KEY_FORMAT_EXPANDED: u8 = 1;
// Internal conformance key format; never emitted or accepted by product ABI 2.
#[cfg(test)]
const KEY_FORMAT_SEED_DERIVED: u8 = 2;

/// The only suite this fixed C ABI implements. The combiner binds `suite_id`, so encapsulate /
/// decapsulate **reject** any other value: a caller must not bind false agility metadata (e.g.
/// claim `ML-KEM-1024`) into a key that this build actually derives from ML-KEM-768 + X25519.
fn fixed_suite_id() -> &'static [u8] {
    DEFAULT_SUITE_ID
}

// Literal values (so cbindgen emits numeric #defines for C), with compile-time
// assertions that they match the backend — they cannot silently drift.
/// ML-KEM-768 secret-key length, bytes.
pub const Q_PERIAPT_MLKEM768_SK_LEN: usize = 2400;
// Internal X-Wing conformance seed length.
#[cfg(test)]
const MLKEM768_XWING_SEED_LEN: usize = 32;
/// ML-KEM-768 public-key length, bytes.
pub const Q_PERIAPT_MLKEM768_PK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length, bytes.
pub const Q_PERIAPT_MLKEM768_CT_LEN: usize = 1088;
/// X25519 key / ciphertext length, bytes.
pub const Q_PERIAPT_X25519_LEN: usize = 32;
/// Combined shared-secret length, bytes.
pub const Q_PERIAPT_SECRET_LEN: usize = 32;

/// Return the C ABI version implemented by this library. Consumers should compare this against
/// [`Q_PERIAPT_ABI_VERSION`] at startup before trusting any length constants or entry points.
#[no_mangle]
pub extern "C" fn q_periapt_abi_version() -> u32 {
    Q_PERIAPT_ABI_VERSION
}

/// Return the crate version string for the linked native library.
#[no_mangle]
pub extern "C" fn q_periapt_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Return the fixed suite id implemented by this C ABI as a NUL-terminated ASCII string.
#[no_mangle]
pub extern "C" fn q_periapt_fixed_suite_id() -> *const c_char {
    DEFAULT_SUITE_ID_CSTR.as_ptr().cast()
}

/// Return the fixed suite id length, excluding the terminating NUL.
#[no_mangle]
pub extern "C" fn q_periapt_fixed_suite_id_len() -> usize {
    fixed_suite_id().len()
}

/// Return a stable ASCII name for a status code. Unknown status codes return `UNKNOWN_STATUS`.
#[no_mangle]
pub extern "C" fn q_periapt_status_name(code: i32) -> *const c_char {
    let name = match code {
        Q_PERIAPT_OK => b"OK\0" as &[u8],
        Q_PERIAPT_ERR_NULL => b"ERR_NULL\0",
        Q_PERIAPT_ERR_LENGTH => b"ERR_LENGTH\0",
        Q_PERIAPT_ERR_POLICY => b"ERR_POLICY\0",
        Q_PERIAPT_ERR_PANIC => b"ERR_PANIC\0",
        Q_PERIAPT_ERR_INTERNAL => b"ERR_INTERNAL\0",
        Q_PERIAPT_ERR_INVALID_KEYSHARE => b"ERR_INVALID_KEYSHARE\0",
        Q_PERIAPT_ERR_ALIASING => b"ERR_ALIASING\0",
        Q_PERIAPT_ERR_ENTROPY => b"ERR_ENTROPY\0",
        _ => b"UNKNOWN_STATUS\0",
    };
    name.as_ptr().cast()
}

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

/// Whether `[a, a+a_len)` and `[b, b+b_len)` overlap as byte ranges. Zero-length ranges never
/// overlap. (Pointers are compared as integers purely for range disjointness — never dereferenced.)
fn ranges_overlap(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let (a0, b0) = (a as usize, b as usize);
    a0 < b0.saturating_add(b_len) && b0 < a0.saturating_add(a_len)
}

/// Reject (return `true`) if any output region overlaps an input region or another output region.
/// Inputs may freely alias one another (concurrent shared reads are fine); only the `&mut [u8]`
/// outputs must be disjoint from everything, since aliasing a shared and a mutable reference is UB.
fn outputs_alias(inputs: &[(*const u8, usize)], outputs: &[(*const u8, usize)]) -> bool {
    outputs.iter().enumerate().any(|(i, &(op, ol))| {
        inputs
            .iter()
            .any(|&(ip, il)| ranges_overlap(op, ol, ip, il))
            || outputs
                .iter()
                .skip(i + 1)
                .any(|&(op2, ol2)| ranges_overlap(op, ol, op2, ol2))
    })
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
        // Internal conformance profile code; never admitted by the product
        // decision parser or emitted in the public header.
        1 => Some(Profile::CompatXWing),
        Q_PERIAPT_PROFILE_CONTEXT_BOUND => Some(Profile::ContextBound),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct ParsedPolicyDecision {
    profile: Profile,
    policy_version: u32,
    policy_digest: [u8; 32],
}

fn parse_policy_decision(encoded: &[u8]) -> Option<ParsedPolicyDecision> {
    if encoded.len() != Q_PERIAPT_POLICY_DECISION_LEN
        || *encoded.first()? != Q_PERIAPT_POLICY_DECISION_VERSION
        || *encoded.get(1)? != Q_PERIAPT_SUITE_MLKEM768_X25519
    {
        return None;
    }
    let profile = profile_from(*encoded.get(2)?)?;
    let key_format = *encoded.get(3)?;
    if profile != Profile::ContextBound || key_format != Q_PERIAPT_KEY_FORMAT_EXPANDED {
        return None;
    }
    let policy_version = u32::from_be_bytes(encoded.get(4..8)?.try_into().ok()?);
    if policy_version == 0 {
        return None;
    }
    let policy_digest = encoded.get(8..)?.try_into().ok()?;
    Some(ParsedPolicyDecision {
        profile,
        policy_version,
        policy_digest,
    })
}

fn policy_bound_context(
    decision: ParsedPolicyDecision,
    application_context: &[u8],
) -> Result<Vec<u8>, Error> {
    // CompatXWing ignores context by construction. Refuse it here rather than
    // pretending the authenticated policy digest was committed by the KDF.
    if decision.profile != Profile::ContextBound {
        return Err(Error::PolicyDenied);
    }
    let len = policy_bound_context_len(application_context.len()).ok_or(Error::InvalidLength)?;
    let mut context = Vec::new();
    context
        .try_reserve_exact(len)
        .map_err(|_| Error::InvalidLength)?;
    context.resize(len, 0);
    encode_policy_bound_context(&decision.policy_digest, application_context, &mut context)?;
    Ok(context)
}

/// Verify a detached, domain-separated signed agility policy and atomically resolve it against
/// the only suite implemented by this ABI (ML-KEM-768 + X25519).
///
/// On success `out_decision` receives [`Q_PERIAPT_POLICY_DECISION_LEN`] canonical bytes containing
/// the selected suite, profile, key format, non-zero policy version, and SHA3-256 identity of the
/// exact signed policy. A policy that requires L5/ML-KEM-1024 is rejected instead of silently
/// executing this L3 fixed suite. Persist bytes 4..40 as the next `last_trusted_state`; pass an
/// empty state only for an explicitly provisioned first load. A lower version or different policy
/// reusing the same version is rejected. The verification key is a trust root and therefore must
/// be pinned by the host; accepting it from the same untrusted channel as the policy permits an
/// attacker to self-sign a replacement policy. **Fail-closed:** after the caller supplies a valid,
/// disjoint, exact-length output, every subsequent length/authentication/parse/resolve error leaves
/// that output all-zero. Earlier public output-contract or aliasing errors return without writing an
/// output whose extent or disjointness is invalid. A legacy ABI 1 four-byte version is rejected:
/// it cannot be upgraded without the exact previously accepted policy bytes and must go through an
/// explicit host-authorized re-enrollment/reset flow.
///
/// # Safety
/// `toml`/`signature`/`vk`/`last_trusted_state` must be readable for their lengths;
/// `out_decision` writable for `out_decision_len`, which must equal
/// [`Q_PERIAPT_POLICY_DECISION_LEN`]. `last_trusted_state_len` must be zero or
/// [`Q_PERIAPT_TRUSTED_POLICY_STATE_LEN`]. Inputs and output must not overlap.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_decision_from_signed_policy(
    toml: *const u8,
    toml_len: usize,
    signature: *const u8,
    signature_len: usize,
    vk: *const u8,
    vk_len: usize,
    last_trusted_state: *const u8,
    last_trusted_state_len: usize,
    out_decision: *mut u8,
    out_decision_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // Reject overlapping buffers up front (before any slice is materialized) so we never form
        // aliasing &[u8]/&mut [u8] — a defined error in place of undefined behavior.
        if outputs_alias(
            &[
                (toml, toml_len),
                (signature, signature_len),
                (vk, vk_len),
                (last_trusted_state, last_trusted_state_len),
            ],
            &[(out_decision.cast_const(), out_decision_len)],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
        let (Some(toml), Some(sig), Some(vk), Some(last_state), Some(out)) = (
            in_slice(toml, toml_len),
            in_slice(signature, signature_len),
            in_slice(vk, vk_len),
            in_slice(last_trusted_state, last_trusted_state_len),
            out_slice(out_decision, out_decision_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if out.len() != Q_PERIAPT_POLICY_DECISION_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        // Once the caller provides a valid, disjoint output extent, every
        // subsequent failure is fail-closed. In particular, a legacy ABI 1
        // four-byte version is not a migration source: it cannot authenticate
        // the exact policy digest required by ABI 2, so reject it and erase any
        // stale decision bytes.
        out.fill(0);
        if !matches!(last_state.len(), 0 | Q_PERIAPT_TRUSTED_POLICY_STATE_LEN) {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let last_state = if last_state.is_empty() {
            None
        } else {
            match TrustedPolicyState::decode(last_state) {
                Ok(state) => Some(state),
                Err(_) => return Q_PERIAPT_ERR_POLICY,
            }
        };
        let authenticated =
            match Policy::load_signed_monotonic(&MlDsa65, vk, toml, sig, last_state.as_ref()) {
                Ok(policy) => policy,
                Err(_) => return Q_PERIAPT_ERR_POLICY,
            };
        let decision = match authenticated.resolve_suite(&[HybridSuite::MlKem768X25519]) {
            Ok(decision) => decision,
            Err(_) => return Q_PERIAPT_ERR_POLICY,
        };
        let resolved = decision.resolved();
        if resolved.profile() != Profile::ContextBound {
            return Q_PERIAPT_ERR_POLICY;
        }
        let state = decision.trusted_state();
        let mut encoded = Vec::with_capacity(Q_PERIAPT_POLICY_DECISION_LEN);
        encoded.extend_from_slice(&[
            Q_PERIAPT_POLICY_DECISION_VERSION,
            resolved.suite().to_u8(),
            resolved.profile().to_u8(),
            resolved.key_format().to_u8(),
        ]);
        encoded.extend_from_slice(&resolved.policy_version().to_be_bytes());
        encoded.extend_from_slice(&state.digest());
        debug_assert_eq!(encoded.len(), Q_PERIAPT_POLICY_DECISION_LEN);
        out.copy_from_slice(&encoded);
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Deterministically derive an ML-KEM-768 key pair from a 64-byte `seed` for
/// internal KAT and conformance coverage.
///
/// # Safety
/// `seed`/`out_sk`/`out_pk` must point to readable/writable regions of the given
/// lengths (`64` / [`Q_PERIAPT_MLKEM768_SK_LEN`] / [`Q_PERIAPT_MLKEM768_PK_LEN`]).
#[cfg(test)]
unsafe fn mlkem768_keypair_raw(
    seed: *const u8,
    seed_len: usize,
    out_sk: *mut u8,
    out_sk_len: usize,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // Reject overlapping buffers before any slice is materialized (defined error, not UB).
        if outputs_alias(
            &[(seed, seed_len)],
            &[
                (out_sk.cast_const(), out_sk_len),
                (out_pk.cast_const(), out_pk_len),
            ],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
        let (Some(seed_in), Some(sk_o), Some(pk_o)) = (
            in_slice(seed, seed_len),
            out_slice(out_sk, out_sk_len),
            out_slice(out_pk, out_pk_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        // Validate every public buffer length before constructing the local
        // ZeroizingBytes owner. Copies created by by-value backend calls remain
        // backend-managed and are outside this owner's Drop guarantee.
        if sk_o.len() != ML_KEM_768_SK_LEN || pk_o.len() != ML_KEM_768_PK_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let Ok(seed) = <[u8; 64]>::try_from(seed_in) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        let seed = ZeroizingBytes::from_bytes(seed);
        let (sk, pk) = match MlKem768::generate(*seed.as_bytes()) {
            Ok(keypair) => keypair,
            Err(error) => return err_code(error),
        };
        let sk = ZeroizingBytes::from_bytes(sk);
        sk_o.copy_from_slice(sk.as_bytes());
        pk_o.copy_from_slice(&pk);
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Deterministically derive an X-Wing-compatible ML-KEM-768 key pair from a 32-byte seed.
///
/// The returned secret key is the 32-byte seed accepted by
/// internal CompatXWing decapsulation. The expanded 2400-byte secret key
/// produced by the internal expanded-key helper is intentionally **not** admitted to
/// `CompatXWing`; use it with [`Q_PERIAPT_PROFILE_CONTEXT_BOUND`].
///
/// # Safety
/// `seed`/`out_sk_seed`/`out_pk` must point to readable/writable regions of the given
/// lengths (`32` / the internal X-Wing seed length /
/// [`Q_PERIAPT_MLKEM768_PK_LEN`]).
#[cfg(test)]
unsafe fn mlkem768_xwing_keypair_raw(
    seed: *const u8,
    seed_len: usize,
    out_sk_seed: *mut u8,
    out_sk_seed_len: usize,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if outputs_alias(
            &[(seed, seed_len)],
            &[
                (out_sk_seed.cast_const(), out_sk_seed_len),
                (out_pk.cast_const(), out_pk_len),
            ],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
        let (Some(seed_in), Some(sk_o), Some(pk_o)) = (
            in_slice(seed, seed_len),
            out_slice(out_sk_seed, out_sk_seed_len),
            out_slice(out_pk, out_pk_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if sk_o.len() != ML_KEM_768_XWING_SEED_LEN || pk_o.len() != ML_KEM_768_PK_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let Ok(seed) = <[u8; ML_KEM_768_XWING_SEED_LEN]>::try_from(seed_in) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        let seed = ZeroizingBytes::from_bytes(seed);
        let (sk_seed, pk) = match MlKem768XWingSeed::generate(*seed.as_bytes()) {
            Ok(keypair) => keypair,
            Err(error) => return err_code(error),
        };
        let sk_seed = ZeroizingBytes::from_bytes(sk_seed);
        sk_o.copy_from_slice(sk_seed.as_bytes());
        pk_o.copy_from_slice(&pk);
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Deterministically derive an X25519 key pair from a 32-byte scalar for
/// internal KAT and conformance coverage.
///
/// # Safety
/// All pointers must be valid for the given lengths (`32` each).
#[cfg(test)]
unsafe fn x25519_keypair_raw(
    secret: *const u8,
    secret_len: usize,
    out_sk: *mut u8,
    out_sk_len: usize,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // Reject overlapping buffers before any slice is materialized (defined error, not UB).
        if outputs_alias(
            &[(secret, secret_len)],
            &[
                (out_sk.cast_const(), out_sk_len),
                (out_pk.cast_const(), out_pk_len),
            ],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
        let (Some(secret_in), Some(sk_o), Some(pk_o)) = (
            in_slice(secret, secret_len),
            out_slice(out_sk, out_sk_len),
            out_slice(out_pk, out_pk_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        // Validate every public buffer length before constructing the local
        // ZeroizingBytes owner. Copies created by by-value backend calls remain
        // backend-managed and are outside this owner's Drop guarantee.
        if sk_o.len() != X25519_LEN || pk_o.len() != X25519_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let Ok(secret) = <[u8; 32]>::try_from(secret_in) else {
            return Q_PERIAPT_ERR_LENGTH;
        };
        let secret = ZeroizingBytes::from_bytes(secret);
        let (sk, pk) = X25519::generate(*secret.as_bytes());
        let sk = ZeroizingBytes::from_bytes(sk);
        sk_o.copy_from_slice(sk.as_bytes());
        pk_o.copy_from_slice(&pk);
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Generate the fixed-suite ML-KEM-768 and X25519 key pairs from the operating
/// system CSPRNG under one authenticated policy decision.
///
/// The decision must select the context-bound/expanded-key product profile. No
/// deterministic seed is accepted by the product ABI; deterministic derivation
/// remains an internal KAT facility so production callers cannot accidentally
/// reuse low-entropy test material.
///
/// The encoded decision is an integrity-preserving value between trusted
/// components in one process, not an unforgeable capability. The host must pin
/// the verification key used to create it and isolate untrusted native code.
///
/// # Safety
/// `decision` must be readable for `decision_len`. All four outputs must be
/// writable for their exact published lengths and disjoint from the input and
/// from one another.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn q_periapt_generate_keypair(
    decision: *const u8,
    decision_len: usize,
    out_sk_pq: *mut u8,
    out_sk_pq_len: usize,
    out_pk_pq: *mut u8,
    out_pk_pq_len: usize,
    out_sk_trad: *mut u8,
    out_sk_trad_len: usize,
    out_pk_trad: *mut u8,
    out_pk_trad_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let outputs = [
            (out_sk_pq.cast_const(), out_sk_pq_len),
            (out_pk_pq.cast_const(), out_pk_pq_len),
            (out_sk_trad.cast_const(), out_sk_trad_len),
            (out_pk_trad.cast_const(), out_pk_trad_len),
        ];
        if outputs_alias(&[(decision, decision_len)], &outputs) {
            return Q_PERIAPT_ERR_ALIASING;
        }
        let (Some(sk_pq_out), Some(pk_pq_out), Some(sk_trad_out), Some(pk_trad_out)) = (
            out_slice(out_sk_pq, out_sk_pq_len),
            out_slice(out_pk_pq, out_pk_pq_len),
            out_slice(out_sk_trad, out_sk_trad_len),
            out_slice(out_pk_trad, out_pk_trad_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if sk_pq_out.len() != Q_PERIAPT_MLKEM768_SK_LEN
            || pk_pq_out.len() != Q_PERIAPT_MLKEM768_PK_LEN
            || sk_trad_out.len() != Q_PERIAPT_X25519_LEN
            || pk_trad_out.len() != Q_PERIAPT_X25519_LEN
        {
            return Q_PERIAPT_ERR_LENGTH;
        }
        sk_pq_out.fill(0);
        pk_pq_out.fill(0);
        sk_trad_out.fill(0);
        pk_trad_out.fill(0);

        let Some(decision) = in_slice(decision, decision_len) else {
            return Q_PERIAPT_ERR_NULL;
        };
        let Some(decision) = parse_policy_decision(decision) else {
            return Q_PERIAPT_ERR_POLICY;
        };
        if decision.profile != Profile::ContextBound {
            return Q_PERIAPT_ERR_POLICY;
        }

        let mut seed_pq = ZeroizingBytes::from_bytes([0u8; 64]);
        let mut seed_trad = ZeroizingBytes::from_bytes([0u8; 32]);
        if getrandom::fill(seed_pq.as_mut_bytes()).is_err()
            || getrandom::fill(seed_trad.as_mut_bytes()).is_err()
        {
            return Q_PERIAPT_ERR_ENTROPY;
        }
        let (sk_pq, pk_pq) = match MlKem768::generate(*seed_pq.as_bytes()) {
            Ok(keypair) => keypair,
            Err(error) => return err_code(error),
        };
        let (sk_trad, pk_trad) = X25519::generate(*seed_trad.as_bytes());
        let sk_pq = ZeroizingBytes::from_bytes(sk_pq);
        let sk_trad = ZeroizingBytes::from_bytes(sk_trad);

        sk_pq_out.copy_from_slice(sk_pq.as_bytes());
        pk_pq_out.copy_from_slice(&pk_pq);
        sk_trad_out.copy_from_slice(sk_trad.as_bytes());
        pk_trad_out.copy_from_slice(&pk_trad);
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Hybrid encapsulation to `(pk_pq, pk_trad)`.
///
/// Writes `out_ct_pq` ([`Q_PERIAPT_MLKEM768_CT_LEN`]), `out_ct_trad` ([`Q_PERIAPT_X25519_LEN`])
/// and `out_secret` ([`Q_PERIAPT_SECRET_LEN`]). `context` is bound only under
/// [`Q_PERIAPT_PROFILE_CONTEXT_BOUND`] and must then be non-empty. `CompatXWing`
/// uses the X-Wing-safe ML-KEM seed backend internally; `ContextBound` uses the
/// expanded ML-KEM backend.
///
/// # Safety
/// Every `(ptr, len)` pair must describe a valid region; output buffers must be
/// writable for their lengths.
#[allow(clippy::too_many_arguments)]
unsafe fn hybrid_encapsulate_raw(
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
        // Reject overlapping buffers up front (before any slice is materialized) so we never form
        // aliasing &[u8]/&mut [u8] — a defined error in place of undefined behavior.
        if outputs_alias(
            &[
                (suite_id, suite_id_len),
                (pk_pq, pk_pq_len),
                (pk_trad, pk_trad_len),
                (context, context_len),
                (rand_pq, rand_pq_len),
                (rand_trad, rand_trad_len),
            ],
            &[
                (out_ct_pq.cast_const(), out_ct_pq_len),
                (out_ct_trad.cast_const(), out_ct_trad_len),
                (out_secret.cast_const(), out_secret_len),
            ],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
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
        if suite != fixed_suite_id() {
            // This fixed ABI is ML-KEM-768 + X25519; reject a caller claiming any other suite so a
            // mismatched suite_id cannot be bound into the key as false agility metadata.
            return Q_PERIAPT_ERR_POLICY;
        }
        let result = match profile {
            Profile::ContextBound => {
                let (pq, trad) = (MlKem768, X25519);
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version)
                    .and_then(|kem| {
                        kem.encapsulate(
                            pk_pq, pk_trad, context, rand_pq, rand_trad, ct_pq_o, ct_trad_o,
                        )
                    })
            }
            Profile::CompatXWing => {
                let (pq, trad) = (MlKem768XWingSeed, X25519);
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version)
                    .and_then(|kem| {
                        kem.encapsulate(
                            pk_pq, pk_trad, context, rand_pq, rand_trad, ct_pq_o, ct_trad_o,
                        )
                    })
            }
        };
        match result {
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
/// `sk_pq` is profile-specific: [`Q_PERIAPT_PROFILE_CONTEXT_BOUND`] expects the
/// 2400-byte expanded key from the internal deterministic keypair helper, while
/// internal CompatXWing conformance expects the 32-byte seed from
/// the internal X-Wing conformance keypair helper.
///
/// # Safety
/// Every `(ptr, len)` pair must describe a valid region; `out_secret` must be
/// writable for [`Q_PERIAPT_SECRET_LEN`].
#[allow(clippy::too_many_arguments)]
unsafe fn hybrid_decapsulate_raw(
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
        // Reject overlapping buffers up front (see encapsulate): the single output must be disjoint
        // from every input so no aliasing &[u8]/&mut [u8] is formed.
        if outputs_alias(
            &[
                (suite_id, suite_id_len),
                (sk_pq, sk_pq_len),
                (ct_pq, ct_pq_len),
                (pk_pq, pk_pq_len),
                (sk_trad, sk_trad_len),
                (ct_trad, ct_trad_len),
                (pk_trad, pk_trad_len),
                (context, context_len),
            ],
            &[(out_secret.cast_const(), out_secret_len)],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
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
        if suite != fixed_suite_id() {
            // Fixed ML-KEM-768 + X25519 ABI: reject a mismatched suite_id (see encapsulate).
            return Q_PERIAPT_ERR_POLICY;
        }
        let result = match profile {
            Profile::ContextBound => {
                let (pq, trad) = (MlKem768, X25519);
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version)
                    .and_then(|kem| {
                        kem.decapsulate(sk_pq, ct_pq, pk_pq, sk_trad, ct_trad, pk_trad, context)
                    })
            }
            Profile::CompatXWing => {
                let (pq, trad) = (MlKem768XWingSeed, X25519);
                HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, suite, policy_version)
                    .and_then(|kem| {
                        kem.decapsulate(sk_pq, ct_pq, pk_pq, sk_trad, ct_trad, pk_trad, context)
                    })
            }
        };
        match result {
            Ok(secret) => {
                secret_o.copy_from_slice(secret.as_bytes());
                Q_PERIAPT_OK
            }
            Err(e) => err_code(e),
        }
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Hybrid encapsulation authorized by an authenticated policy decision.
///
/// This is the only product encapsulation entry point. It derives suite/profile/version from one
/// canonical decision and injectively wraps `application_context` together with the exact signed
/// policy digest before invoking the context-bound combiner. `CompatXWing` decisions are rejected
/// because that profile intentionally ignores context and therefore cannot commit the digest.
/// Encapsulation coins come from the operating-system CSPRNG; deterministic coins are not exposed
/// by the product ABI.
///
/// The decision is an integrity-preserving high-level API between trusted components of one
/// process; C memory is caller-writable, so hostile native code in the same process can still forge
/// it or bypass this entry point. Use process isolation when local native callers are untrusted.
///
/// # Safety
/// Every `(ptr, len)` pair must describe a valid region. Outputs must be writable and disjoint
/// from every input and from each other.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn q_periapt_encapsulate(
    decision: *const u8,
    decision_len: usize,
    pk_pq: *const u8,
    pk_pq_len: usize,
    pk_trad: *const u8,
    pk_trad_len: usize,
    application_context: *const u8,
    application_context_len: usize,
    out_ct_pq: *mut u8,
    out_ct_pq_len: usize,
    out_ct_trad: *mut u8,
    out_ct_trad_len: usize,
    out_secret: *mut u8,
    out_secret_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if outputs_alias(
            &[
                (decision, decision_len),
                (pk_pq, pk_pq_len),
                (pk_trad, pk_trad_len),
                (application_context, application_context_len),
            ],
            &[
                (out_ct_pq.cast_const(), out_ct_pq_len),
                (out_ct_trad.cast_const(), out_ct_trad_len),
                (out_secret.cast_const(), out_secret_len),
            ],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
        let (Some(ct_pq_out), Some(ct_trad_out), Some(secret_out)) = (
            out_slice(out_ct_pq, out_ct_pq_len),
            out_slice(out_ct_trad, out_ct_trad_len),
            out_slice(out_secret, out_secret_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if ct_pq_out.len() != Q_PERIAPT_MLKEM768_CT_LEN
            || ct_trad_out.len() != Q_PERIAPT_X25519_LEN
            || secret_out.len() != Q_PERIAPT_SECRET_LEN
        {
            return Q_PERIAPT_ERR_LENGTH;
        }
        ct_pq_out.fill(0);
        ct_trad_out.fill(0);
        secret_out.fill(0);

        let (Some(decision), Some(pk_pq_input), Some(pk_trad_input), Some(application_context)) = (
            in_slice(decision, decision_len),
            in_slice(pk_pq, pk_pq_len),
            in_slice(pk_trad, pk_trad_len),
            in_slice(application_context, application_context_len),
        ) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if pk_pq_input.len() != Q_PERIAPT_MLKEM768_PK_LEN
            || pk_trad_input.len() != Q_PERIAPT_X25519_LEN
        {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let Some(decision) = parse_policy_decision(decision) else {
            return Q_PERIAPT_ERR_POLICY;
        };
        let context = match policy_bound_context(decision, application_context) {
            Ok(context) => context,
            Err(error) => return err_code(error),
        };
        let mut rand_pq = ZeroizingBytes::from_bytes([0u8; 32]);
        let mut rand_trad = ZeroizingBytes::from_bytes([0u8; 32]);
        if getrandom::fill(rand_pq.as_mut_bytes()).is_err()
            || getrandom::fill(rand_trad.as_mut_bytes()).is_err()
        {
            return Q_PERIAPT_ERR_ENTROPY;
        }
        let mut ct_pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut ct_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut secret = ZeroizingBytes::from_bytes([0u8; Q_PERIAPT_SECRET_LEN]);
        let rc = hybrid_encapsulate_raw(
            decision.profile.to_u8(),
            fixed_suite_id().as_ptr(),
            fixed_suite_id().len(),
            decision.policy_version,
            pk_pq,
            pk_pq_len,
            pk_trad,
            pk_trad_len,
            context.as_ptr(),
            context.len(),
            rand_pq.as_bytes().as_ptr(),
            rand_pq.as_bytes().len(),
            rand_trad.as_bytes().as_ptr(),
            rand_trad.as_bytes().len(),
            ct_pq.as_mut_ptr(),
            ct_pq.len(),
            ct_trad.as_mut_ptr(),
            ct_trad.len(),
            secret.as_mut_bytes().as_mut_ptr(),
            secret.as_bytes().len(),
        );
        if rc != Q_PERIAPT_OK {
            return rc;
        }
        ct_pq_out.copy_from_slice(&ct_pq);
        ct_trad_out.copy_from_slice(&ct_trad);
        secret_out.copy_from_slice(secret.as_bytes());
        Q_PERIAPT_OK
    }))
    .unwrap_or(Q_PERIAPT_ERR_PANIC)
}

/// Hybrid decapsulation authorized by an authenticated policy decision.
///
/// Suite/profile/version and the policy-bound context are reconstructed exactly as in
/// [`q_periapt_encapsulate`]. See that function for the same-process trust
/// boundary and `CompatXWing` rejection rationale.
///
/// # Safety
/// Every `(ptr, len)` pair must describe a valid region. `out_secret` must be writable and
/// disjoint from every input.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn q_periapt_decapsulate(
    decision: *const u8,
    decision_len: usize,
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
    application_context: *const u8,
    application_context_len: usize,
    out_secret: *mut u8,
    out_secret_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if outputs_alias(
            &[
                (decision, decision_len),
                (sk_pq, sk_pq_len),
                (ct_pq, ct_pq_len),
                (pk_pq, pk_pq_len),
                (sk_trad, sk_trad_len),
                (ct_trad, ct_trad_len),
                (pk_trad, pk_trad_len),
                (application_context, application_context_len),
            ],
            &[(out_secret.cast_const(), out_secret_len)],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
        let Some(secret_out) = out_slice(out_secret, out_secret_len) else {
            return Q_PERIAPT_ERR_NULL;
        };
        if secret_out.len() != Q_PERIAPT_SECRET_LEN {
            return Q_PERIAPT_ERR_LENGTH;
        }
        secret_out.fill(0);

        let (
            Some(decision),
            Some(sk_pq_input),
            Some(ct_pq_input),
            Some(pk_pq_input),
            Some(sk_trad_input),
            Some(ct_trad_input),
            Some(pk_trad_input),
            Some(application_context),
        ) = (
            in_slice(decision, decision_len),
            in_slice(sk_pq, sk_pq_len),
            in_slice(ct_pq, ct_pq_len),
            in_slice(pk_pq, pk_pq_len),
            in_slice(sk_trad, sk_trad_len),
            in_slice(ct_trad, ct_trad_len),
            in_slice(pk_trad, pk_trad_len),
            in_slice(application_context, application_context_len),
        )
        else {
            return Q_PERIAPT_ERR_NULL;
        };
        if sk_pq_input.len() != Q_PERIAPT_MLKEM768_SK_LEN
            || ct_pq_input.len() != Q_PERIAPT_MLKEM768_CT_LEN
            || pk_pq_input.len() != Q_PERIAPT_MLKEM768_PK_LEN
            || sk_trad_input.len() != Q_PERIAPT_X25519_LEN
            || ct_trad_input.len() != Q_PERIAPT_X25519_LEN
            || pk_trad_input.len() != Q_PERIAPT_X25519_LEN
        {
            return Q_PERIAPT_ERR_LENGTH;
        }
        let Some(decision) = parse_policy_decision(decision) else {
            return Q_PERIAPT_ERR_POLICY;
        };
        let context = match policy_bound_context(decision, application_context) {
            Ok(context) => context,
            Err(error) => return err_code(error),
        };
        let mut secret = ZeroizingBytes::from_bytes([0u8; Q_PERIAPT_SECRET_LEN]);
        let rc = hybrid_decapsulate_raw(
            decision.profile.to_u8(),
            fixed_suite_id().as_ptr(),
            fixed_suite_id().len(),
            decision.policy_version,
            sk_pq,
            sk_pq_len,
            ct_pq,
            ct_pq_len,
            pk_pq,
            pk_pq_len,
            sk_trad,
            sk_trad_len,
            ct_trad,
            ct_trad_len,
            pk_trad,
            pk_trad_len,
            context.as_ptr(),
            context.len(),
            secret.as_mut_bytes().as_mut_ptr(),
            secret.as_bytes().len(),
        );
        if rc != Q_PERIAPT_OK {
            return rc;
        }
        secret_out.copy_from_slice(secret.as_bytes());
        Q_PERIAPT_OK
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
/// selects the internal CompatXWing or [`Q_PERIAPT_PROFILE_CONTEXT_BOUND`] profile.
///
/// # Safety
/// `input`/`out_secret` must be valid for `input_len` / [`Q_PERIAPT_SECRET_LEN`].
#[cfg(test)]
unsafe fn combine_raw(
    profile: u8,
    input: *const u8,
    input_len: usize,
    out_secret: *mut u8,
    out_secret_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // Reject overlapping buffers before any slice is materialized (defined error, not UB).
        if outputs_alias(
            &[(input, input_len)],
            &[(out_secret.cast_const(), out_secret_len)],
        ) {
            return Q_PERIAPT_ERR_ALIASING;
        }
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
    use q_periapt_backends::ML_KEM_768_CT_LEN;

    #[test]
    fn abi_constants_match_backend_lengths() {
        assert_eq!(q_periapt_abi_version(), Q_PERIAPT_ABI_VERSION);
        assert_eq!(Q_PERIAPT_ABI_VERSION, 2);
        assert_eq!(q_periapt_fixed_suite_id_len(), fixed_suite_id().len());
        assert_eq!(Q_PERIAPT_MLKEM768_SK_LEN, ML_KEM_768_SK_LEN);
        assert_eq!(MLKEM768_XWING_SEED_LEN, ML_KEM_768_XWING_SEED_LEN);
        assert_eq!(Q_PERIAPT_MLKEM768_PK_LEN, ML_KEM_768_PK_LEN);
        assert_eq!(Q_PERIAPT_MLKEM768_CT_LEN, ML_KEM_768_CT_LEN);
        assert_eq!(Q_PERIAPT_X25519_LEN, X25519_LEN);
        assert_eq!(
            Q_PERIAPT_MAX_SIGNED_POLICY_BYTES,
            q_periapt_policy::MAX_SIGNED_POLICY_BYTES
        );
        assert_eq!(
            Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES,
            q_periapt_core::MAX_APPLICATION_CONTEXT_BYTES
        );
        assert_eq!(
            Q_PERIAPT_TRUSTED_POLICY_STATE_LEN,
            TrustedPolicyState::ENCODED_LEN
        );
        assert_eq!(
            Q_PERIAPT_SUITE_MLKEM768_X25519,
            HybridSuite::MlKem768X25519 as u8
        );
        assert_eq!(
            Q_PERIAPT_KEY_FORMAT_EXPANDED,
            q_periapt_policy::KeyFormat::Expanded as u8
        );
        assert_eq!(
            KEY_FORMAT_SEED_DERIVED,
            q_periapt_policy::KeyFormat::SeedDerived as u8
        );
    }

    #[test]
    fn policy_bound_context_cap_accepts_boundary_and_rejects_oversize_before_crypto() {
        let decision = ParsedPolicyDecision {
            profile: Profile::ContextBound,
            policy_version: 1,
            policy_digest: [0xA5; 32],
        };
        let boundary = vec![0x11; Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES];
        assert!(policy_bound_context(decision, &boundary).is_ok());
        let oversized = vec![0x22; Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES + 1];
        assert_eq!(
            policy_bound_context(decision, &oversized).unwrap_err(),
            Error::InvalidLength
        );

        let mut encoded = [0u8; Q_PERIAPT_POLICY_DECISION_LEN];
        encoded[0] = Q_PERIAPT_POLICY_DECISION_VERSION;
        encoded[1] = Q_PERIAPT_SUITE_MLKEM768_X25519;
        encoded[2] = Q_PERIAPT_PROFILE_CONTEXT_BOUND;
        encoded[3] = Q_PERIAPT_KEY_FORMAT_EXPANDED;
        encoded[7] = 1;
        let mut ct_pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut ct_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut secret = [0u8; Q_PERIAPT_SECRET_LEN];
        let rc = unsafe {
            q_periapt_encapsulate(
                encoded.as_ptr(),
                encoded.len(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                oversized.as_ptr(),
                oversized.len(),
                ct_pq.as_mut_ptr(),
                ct_pq.len(),
                ct_trad.as_mut_ptr(),
                ct_trad.len(),
                secret.as_mut_ptr(),
                secret.len(),
            )
        };
        assert_eq!(rc, Q_PERIAPT_ERR_LENGTH);
    }

    #[test]
    fn metadata_exports_are_stable_and_c_string_terminated() {
        use std::ffi::CStr;

        let version = unsafe { CStr::from_ptr(q_periapt_version()) }
            .to_str()
            .unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        let suite = unsafe { CStr::from_ptr(q_periapt_fixed_suite_id()) }
            .to_str()
            .unwrap();
        assert_eq!(suite.as_bytes(), fixed_suite_id());
        assert_eq!(
            unsafe { CStr::from_ptr(q_periapt_status_name(Q_PERIAPT_OK)) }
                .to_str()
                .unwrap(),
            "OK"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(q_periapt_status_name(Q_PERIAPT_ERR_ALIASING)) }
                .to_str()
                .unwrap(),
            "ERR_ALIASING"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(q_periapt_status_name(12345)) }
                .to_str()
                .unwrap(),
            "UNKNOWN_STATUS"
        );
    }

    #[test]
    fn decision_from_signed_policy_binds_suite_state_and_blocks_rollback() {
        use q_periapt_backends::ML_DSA_65_SIG_LEN;
        use q_periapt_policy::policy_signature_message;
        use q_periapt_sig::Signer;

        let policy_toml = "schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\n\
            default_profile = \"ContextBound\"\n\
            allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
            allowed_sigs = [\"ML-DSA-65\"]\n\
            deprecated = []\n";
        let (sk, vk) = MlDsa65::generate([8u8; 32]);
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let message = policy_signature_message(policy_toml.as_bytes());
        let n = MlDsa65.sign(&sk, &message, &[0u8; 32], &mut sig).unwrap();
        let run = |signature: &[u8], last_state: &[u8], out: &mut [u8]| -> i32 {
            unsafe {
                q_periapt_decision_from_signed_policy(
                    policy_toml.as_ptr(),
                    policy_toml.len(),
                    signature.as_ptr(),
                    signature.len(),
                    vk.as_ptr(),
                    vk.len(),
                    last_state.as_ptr(),
                    last_state.len(),
                    out.as_mut_ptr(),
                    out.len(),
                )
            }
        };

        let mut decision = [0u8; Q_PERIAPT_POLICY_DECISION_LEN];
        assert_eq!(run(&sig[..n], &[], &mut decision), Q_PERIAPT_OK);
        assert_eq!(decision[0], Q_PERIAPT_POLICY_DECISION_VERSION);
        assert_eq!(decision[1], Q_PERIAPT_SUITE_MLKEM768_X25519);
        assert_eq!(decision[2], Q_PERIAPT_PROFILE_CONTEXT_BOUND);
        assert_eq!(decision[3], Q_PERIAPT_KEY_FORMAT_EXPANDED);
        assert_eq!(&decision[4..8], &2u32.to_be_bytes());

        let trusted_state = decision[4..].to_vec();
        assert_eq!(run(&sig[..n], &trusted_state, &mut decision), Q_PERIAPT_OK);

        // ABI 1 persisted only a four-byte version. That value cannot prove
        // the exact policy identity required by ABI 2 and must never be
        // interpreted as a fresh install or padded into a synthetic digest.
        decision.fill(0xA5);
        assert_eq!(
            run(&sig[..n], &2u32.to_be_bytes(), &mut decision),
            Q_PERIAPT_ERR_LENGTH
        );
        assert!(decision.iter().all(|byte| *byte == 0));

        let newer_state = TrustedPolicyState::new(3, [3u8; 32]).unwrap().encode();
        assert_eq!(
            run(&sig[..n], &newer_state, &mut decision),
            Q_PERIAPT_ERR_POLICY
        );
        assert!(decision.iter().all(|byte| *byte == 0));

        let mut bad = sig;
        bad[0] ^= 1;
        decision.fill(0xA5);
        assert_eq!(run(&bad[..n], &[], &mut decision), Q_PERIAPT_ERR_POLICY);
        assert!(decision.iter().all(|byte| *byte == 0));
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
            mlkem768_keypair_raw(
                seed.as_ptr(),
                64,
                sk_pq.as_mut_ptr(),
                sk_pq.len(),
                pk_pq.as_mut_ptr(),
                pk_pq.len(),
            );
            x25519_keypair_raw(
                xs.as_ptr(),
                32,
                sk_t.as_mut_ptr(),
                32,
                pk_t.as_mut_ptr(),
                32,
            );
            let forged = b"ML-KEM-1024+X25519"; // a stronger suite this build does NOT implement
            let rc = hybrid_encapsulate_raw(
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
    fn xwing_seed_abi_roundtrips_compat_xwing() {
        let mut pk_pq = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        let mut sk_pq = [0u8; MLKEM768_XWING_SEED_LEN];
        let mut pk_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut sk_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut ct_pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut ct_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut secret_e = [0u8; Q_PERIAPT_SECRET_LEN];
        let mut secret_d = [0u8; Q_PERIAPT_SECRET_LEN];
        unsafe {
            assert_eq!(
                mlkem768_xwing_keypair_raw(
                    [3u8; 32].as_ptr(),
                    32,
                    sk_pq.as_mut_ptr(),
                    sk_pq.len(),
                    pk_pq.as_mut_ptr(),
                    pk_pq.len()
                ),
                Q_PERIAPT_OK
            );
            assert_eq!(
                x25519_keypair_raw(
                    [4u8; 32].as_ptr(),
                    32,
                    sk_trad.as_mut_ptr(),
                    sk_trad.len(),
                    pk_trad.as_mut_ptr(),
                    pk_trad.len()
                ),
                Q_PERIAPT_OK
            );
            let rc = hybrid_encapsulate_raw(
                Profile::CompatXWing.to_u8(),
                fixed_suite_id().as_ptr(),
                fixed_suite_id().len(),
                1,
                pk_pq.as_ptr(),
                pk_pq.len(),
                pk_trad.as_ptr(),
                pk_trad.len(),
                core::ptr::null(),
                0,
                [1u8; 32].as_ptr(),
                32,
                [2u8; 32].as_ptr(),
                32,
                ct_pq.as_mut_ptr(),
                ct_pq.len(),
                ct_trad.as_mut_ptr(),
                ct_trad.len(),
                secret_e.as_mut_ptr(),
                secret_e.len(),
            );
            assert_eq!(rc, Q_PERIAPT_OK);
            assert_eq!(
                hybrid_decapsulate_raw(
                    Profile::CompatXWing.to_u8(),
                    fixed_suite_id().as_ptr(),
                    fixed_suite_id().len(),
                    1,
                    sk_pq.as_ptr(),
                    sk_pq.len(),
                    ct_pq.as_ptr(),
                    ct_pq.len(),
                    pk_pq.as_ptr(),
                    pk_pq.len(),
                    sk_trad.as_ptr(),
                    sk_trad.len(),
                    ct_trad.as_ptr(),
                    ct_trad.len(),
                    pk_trad.as_ptr(),
                    pk_trad.len(),
                    core::ptr::null(),
                    0,
                    secret_d.as_mut_ptr(),
                    secret_d.len(),
                ),
                Q_PERIAPT_OK
            );
            assert_eq!(secret_e, secret_d, "CompatXWing seed-dk ABI must roundtrip");
            assert_ne!(secret_d, [0u8; Q_PERIAPT_SECRET_LEN]);
        }
    }

    #[test]
    fn expanded_key_abi_rejects_compat_xwing_decapsulation() {
        // The expanded-key ABI remains ContextBound-only for decapsulation. CompatXWing accepts
        // the 32-byte seed secret produced by the internal X-Wing keypair helper, not a 2400-byte
        // FIPS-expanded secret key.
        let mut pk_pq = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        let mut sk_pq = [0u8; Q_PERIAPT_MLKEM768_SK_LEN];
        let mut pk_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut sk_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut ct_pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut ct_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut secret = [0u8; Q_PERIAPT_SECRET_LEN];
        unsafe {
            assert_eq!(
                mlkem768_keypair_raw(
                    [3u8; 64].as_ptr(),
                    64,
                    sk_pq.as_mut_ptr(),
                    sk_pq.len(),
                    pk_pq.as_mut_ptr(),
                    pk_pq.len()
                ),
                Q_PERIAPT_OK
            );
            assert_eq!(
                x25519_keypair_raw(
                    [4u8; 32].as_ptr(),
                    32,
                    sk_trad.as_mut_ptr(),
                    sk_trad.len(),
                    pk_trad.as_mut_ptr(),
                    pk_trad.len()
                ),
                Q_PERIAPT_OK
            );
            assert_eq!(
                hybrid_encapsulate_raw(
                    Profile::CompatXWing.to_u8(),
                    fixed_suite_id().as_ptr(),
                    fixed_suite_id().len(),
                    1,
                    pk_pq.as_ptr(),
                    pk_pq.len(),
                    pk_trad.as_ptr(),
                    pk_trad.len(),
                    core::ptr::null(),
                    0,
                    [1u8; 32].as_ptr(),
                    32,
                    [2u8; 32].as_ptr(),
                    32,
                    ct_pq.as_mut_ptr(),
                    ct_pq.len(),
                    ct_trad.as_mut_ptr(),
                    ct_trad.len(),
                    secret.as_mut_ptr(),
                    secret.len(),
                ),
                Q_PERIAPT_OK
            );
            secret = [0u8; Q_PERIAPT_SECRET_LEN];
            let rc = hybrid_decapsulate_raw(
                Profile::CompatXWing.to_u8(),
                fixed_suite_id().as_ptr(),
                fixed_suite_id().len(),
                1,
                sk_pq.as_ptr(),
                sk_pq.len(),
                ct_pq.as_ptr(),
                ct_pq.len(),
                pk_pq.as_ptr(),
                pk_pq.len(),
                sk_trad.as_ptr(),
                sk_trad.len(),
                ct_trad.as_ptr(),
                ct_trad.len(),
                pk_trad.as_ptr(),
                pk_trad.len(),
                core::ptr::null(),
                0,
                secret.as_mut_ptr(),
                secret.len(),
            );
            assert_eq!(rc, Q_PERIAPT_ERR_LENGTH);
            assert_eq!(secret, [0u8; Q_PERIAPT_SECRET_LEN]);
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
            mlkem768_keypair_raw(
                [3u8; 64].as_ptr(),
                64,
                sk_pq.as_mut_ptr(),
                sk_pq.len(),
                pk_pq.as_mut_ptr(),
                pk_pq.len(),
            );
            let low_order = [0u8; 32]; // a low-order X25519 point
            let rc = hybrid_encapsulate_raw(
                Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                fixed_suite_id().as_ptr(),
                fixed_suite_id().len(),
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
    fn hybrid_encapsulate_rejects_overlapping_buffers() {
        // An output that overlaps an input must be a defined Q_PERIAPT_ERR_ALIASING, never UB.
        let mut buf = [7u8; Q_PERIAPT_MLKEM768_PK_LEN]; // used as BOTH pk_pq (input) and out_ct_pq
        let pk_trad = [4u8; 32];
        let (mut ct_trad, mut secret) = ([0u8; 32], [0u8; 32]);
        let p = buf.as_mut_ptr();
        unsafe {
            let rc = hybrid_encapsulate_raw(
                Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                fixed_suite_id().as_ptr(),
                fixed_suite_id().len(),
                1,
                p, // pk_pq input ...
                Q_PERIAPT_MLKEM768_PK_LEN,
                pk_trad.as_ptr(),
                32,
                b"ctx".as_ptr(),
                3,
                [0u8; 32].as_ptr(),
                32,
                [2u8; 32].as_ptr(),
                32,
                p, // ... and out_ct_pq output -> overlap
                Q_PERIAPT_MLKEM768_CT_LEN,
                ct_trad.as_mut_ptr(),
                32,
                secret.as_mut_ptr(),
                32,
            );
            assert_eq!(
                rc, Q_PERIAPT_ERR_ALIASING,
                "overlapping in/out must be a defined error"
            );
            assert_eq!(
                secret, [0u8; 32],
                "no key material on the aliasing-rejected path"
            );
        }
    }

    #[test]
    fn keypair_rejects_overlapping_buffers() {
        // seed (input) overlapping out_sk (output) must be a defined Q_PERIAPT_ERR_ALIASING,
        // never UB from aliasing &[u8]/&mut [u8].
        let mut sk = [0u8; Q_PERIAPT_MLKEM768_SK_LEN];
        let mut pk = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        let p = sk.as_mut_ptr();
        unsafe {
            let rc = mlkem768_keypair_raw(
                p.cast_const(), // seed input ...
                64,
                p, // ... overlaps out_sk output
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
            );
            assert_eq!(
                rc, Q_PERIAPT_ERR_ALIASING,
                "overlapping seed/out_sk must be rejected"
            );
            assert_eq!(
                sk, [0u8; Q_PERIAPT_MLKEM768_SK_LEN],
                "no key material written on the aliasing-rejected path"
            );
        }
    }

    #[test]
    fn keypair_wrong_output_length_is_length_error_before_secret_copy() {
        // The length check now runs BEFORE the 64-byte seed copy, so this path returns a defined
        // ERR_LENGTH and never materializes (then leaks) the secret seed on the stack.
        let seed = [5u8; 64];
        let mut sk_short = [0u8; 10];
        let mut pk = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        unsafe {
            let rc = mlkem768_keypair_raw(
                seed.as_ptr(),
                64,
                sk_short.as_mut_ptr(),
                sk_short.len(),
                pk.as_mut_ptr(),
                pk.len(),
            );
            assert_eq!(rc, Q_PERIAPT_ERR_LENGTH);
        }
    }

    #[test]
    fn combine_rejects_overlapping_buffers() {
        // input overlapping out_secret must be a defined Q_PERIAPT_ERR_ALIASING.
        let mut buf = [0u8; 64];
        let p = buf.as_mut_ptr();
        unsafe {
            let rc = combine_raw(
                Q_PERIAPT_PROFILE_CONTEXT_BOUND,
                p.cast_const(), // input ...
                buf.len(),
                p, // ... overlaps out_secret
                Q_PERIAPT_SECRET_LEN,
            );
            assert_eq!(
                rc, Q_PERIAPT_ERR_ALIASING,
                "overlapping input/out_secret must be rejected"
            );
        }
    }

    #[test]
    fn ffi_hybrid_roundtrip_context_bound() {
        let mut sk_pq = [0u8; Q_PERIAPT_MLKEM768_SK_LEN];
        let mut pk_pq = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        let seed = [3u8; 64];
        unsafe {
            assert_eq!(
                mlkem768_keypair_raw(
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
                x25519_keypair_raw(
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
                hybrid_encapsulate_raw(
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
                hybrid_decapsulate_raw(
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
            hybrid_decapsulate_raw(
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
            hybrid_decapsulate_raw(
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

    #[test]
    fn signed_policy_product_path_binds_digest_context_and_generated_keys() {
        use q_periapt_backends::ML_DSA_65_SIG_LEN;
        use q_periapt_policy::policy_signature_message;
        use q_periapt_sig::Signer;

        let policy_toml = "schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\n\
            default_profile = \"ContextBound\"\n\
            allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
            allowed_sigs = [\"ML-DSA-65\"]\n\
            deprecated = []\n";
        let (signing_key, verification_key) = MlDsa65::generate([8u8; 32]);
        let mut signature = [0u8; ML_DSA_65_SIG_LEN];
        let signature_len = MlDsa65
            .sign(
                &signing_key,
                &policy_signature_message(policy_toml.as_bytes()),
                &[0u8; 32],
                &mut signature,
            )
            .unwrap();
        let mut decision = [0u8; Q_PERIAPT_POLICY_DECISION_LEN];
        assert_eq!(
            unsafe {
                q_periapt_decision_from_signed_policy(
                    policy_toml.as_ptr(),
                    policy_toml.len(),
                    signature.as_ptr(),
                    signature_len,
                    verification_key.as_ptr(),
                    verification_key.len(),
                    core::ptr::null(),
                    0,
                    decision.as_mut_ptr(),
                    decision.len(),
                )
            },
            Q_PERIAPT_OK
        );

        let mut sk_pq = [0u8; Q_PERIAPT_MLKEM768_SK_LEN];
        let mut pk_pq = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        let mut sk_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut pk_trad = [0u8; Q_PERIAPT_X25519_LEN];
        assert_eq!(
            unsafe {
                q_periapt_generate_keypair(
                    decision.as_ptr(),
                    decision.len(),
                    sk_pq.as_mut_ptr(),
                    sk_pq.len(),
                    pk_pq.as_mut_ptr(),
                    pk_pq.len(),
                    sk_trad.as_mut_ptr(),
                    sk_trad.len(),
                    pk_trad.as_mut_ptr(),
                    pk_trad.len(),
                )
            },
            Q_PERIAPT_OK
        );

        let application_context = b"ffi-policy-context";
        let mut ct_pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut ct_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut enc_secret = [0u8; Q_PERIAPT_SECRET_LEN];
        let rc = unsafe {
            q_periapt_encapsulate(
                decision.as_ptr(),
                decision.len(),
                pk_pq.as_ptr(),
                pk_pq.len(),
                pk_trad.as_ptr(),
                pk_trad.len(),
                application_context.as_ptr(),
                application_context.len(),
                ct_pq.as_mut_ptr(),
                ct_pq.len(),
                ct_trad.as_mut_ptr(),
                ct_trad.len(),
                enc_secret.as_mut_ptr(),
                enc_secret.len(),
            )
        };
        assert_eq!(rc, Q_PERIAPT_OK);

        let low_order_trad = [0u8; Q_PERIAPT_X25519_LEN];
        let mut rejected_ct_pq = [0xA5u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut rejected_ct_trad = [0xA5u8; Q_PERIAPT_X25519_LEN];
        let mut rejected_secret = [0xA5u8; Q_PERIAPT_SECRET_LEN];
        let rejected = unsafe {
            q_periapt_encapsulate(
                decision.as_ptr(),
                decision.len(),
                pk_pq.as_ptr(),
                pk_pq.len(),
                low_order_trad.as_ptr(),
                low_order_trad.len(),
                application_context.as_ptr(),
                application_context.len(),
                rejected_ct_pq.as_mut_ptr(),
                rejected_ct_pq.len(),
                rejected_ct_trad.as_mut_ptr(),
                rejected_ct_trad.len(),
                rejected_secret.as_mut_ptr(),
                rejected_secret.len(),
            )
        };
        assert_eq!(rejected, Q_PERIAPT_ERR_INVALID_KEYSHARE);
        assert!(rejected_ct_pq.iter().all(|byte| *byte == 0));
        assert!(rejected_ct_trad.iter().all(|byte| *byte == 0));
        assert!(rejected_secret.iter().all(|byte| *byte == 0));

        let mut noncanonical_pq = pk_pq;
        noncanonical_pq[0] = 0xFF;
        noncanonical_pq[1] = 0x0F;
        rejected_ct_pq.fill(0xA5);
        rejected_ct_trad.fill(0xA5);
        rejected_secret.fill(0xA5);
        let rejected = unsafe {
            q_periapt_encapsulate(
                decision.as_ptr(),
                decision.len(),
                noncanonical_pq.as_ptr(),
                noncanonical_pq.len(),
                pk_trad.as_ptr(),
                pk_trad.len(),
                application_context.as_ptr(),
                application_context.len(),
                rejected_ct_pq.as_mut_ptr(),
                rejected_ct_pq.len(),
                rejected_ct_trad.as_mut_ptr(),
                rejected_ct_trad.len(),
                rejected_secret.as_mut_ptr(),
                rejected_secret.len(),
            )
        };
        assert_eq!(rejected, Q_PERIAPT_ERR_INVALID_KEYSHARE);
        assert!(rejected_ct_pq.iter().all(|byte| *byte == 0));
        assert!(rejected_ct_trad.iter().all(|byte| *byte == 0));
        assert!(rejected_secret.iter().all(|byte| *byte == 0));

        let decapsulate = |decision_bytes: &[u8], context: &[u8]| {
            let mut secret = [0u8; Q_PERIAPT_SECRET_LEN];
            let rc = unsafe {
                q_periapt_decapsulate(
                    decision_bytes.as_ptr(),
                    decision_bytes.len(),
                    sk_pq.as_ptr(),
                    sk_pq.len(),
                    ct_pq.as_ptr(),
                    ct_pq.len(),
                    pk_pq.as_ptr(),
                    pk_pq.len(),
                    sk_trad.as_ptr(),
                    sk_trad.len(),
                    ct_trad.as_ptr(),
                    ct_trad.len(),
                    pk_trad.as_ptr(),
                    pk_trad.len(),
                    context.as_ptr(),
                    context.len(),
                    secret.as_mut_ptr(),
                    secret.len(),
                )
            };
            (rc, secret)
        };
        let (rc, dec_secret) = decapsulate(&decision, application_context);
        assert_eq!(rc, Q_PERIAPT_OK);
        assert_eq!(enc_secret, dec_secret);

        let (_, wrong_context) = decapsulate(&decision, b"wrong-context");
        assert_ne!(enc_secret, wrong_context);
        let last_digest_byte = decision.last_mut().unwrap();
        *last_digest_byte ^= 1;
        let (_, wrong_policy) = decapsulate(&decision, application_context);
        assert_ne!(enc_secret, wrong_policy);

        decision[2] = Profile::CompatXWing.to_u8();
        decision[3] = KEY_FORMAT_SEED_DERIVED;
        assert_eq!(
            decapsulate(&decision, application_context).0,
            Q_PERIAPT_ERR_POLICY
        );
    }

    /// The internal raw combiner helper reproduces every combiner reference vector — the
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
                combine_raw(
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
