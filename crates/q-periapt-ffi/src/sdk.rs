// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Additive 0.2.0 owner API within ABI major 2. The original nine signatures are
//! unchanged. An explicit, bounded registry owns opaque integer handles; these
//! are same-process ownership identifiers, not security capabilities.

mod connection;
mod persistent;
mod registry;
use super::{
    in_slice, out_buf, outputs_alias, region_ok, Q_PERIAPT_ERR_ALIASING, Q_PERIAPT_ERR_ENTROPY,
    Q_PERIAPT_ERR_INTERNAL, Q_PERIAPT_ERR_INVALID_KEYSHARE, Q_PERIAPT_ERR_LENGTH,
    Q_PERIAPT_ERR_NULL, Q_PERIAPT_ERR_PANIC, Q_PERIAPT_ERR_POLICY, Q_PERIAPT_OK,
};
pub use connection::*;
pub use persistent::*;
use q_periapt_policy::TrustedPolicyState;
use q_periapt_sdk::{self as sdk, Ciphertext, PublicKey};
use registry::{Object, Registry};
use std::{
    mem::size_of,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

/// Closed, stale, nonexistent or wrong-type owner handle.
pub const Q_PERIAPT_ERR_CLOSED: i32 = -9;
/// An explicit object or operation budget is exhausted; no crypto fallback occurs.
pub const Q_PERIAPT_ERR_RESOURCE_LIMIT: i32 = -10;
/// Runtime limits or extension options are invalid.
pub const Q_PERIAPT_ERR_LIMITS: i32 = -11;
/// Unknown key purpose or invalid printable-ASCII protocol label.
pub const Q_PERIAPT_ERR_PURPOSE: i32 = -12;
/// Invalid private-key format, integrity or pairwise consistency.
pub const Q_PERIAPT_ERR_INVALID_PRIVATE_KEY: i32 = -13;
/// Owned SDK extension contract revision within C ABI major 2.
pub const Q_PERIAPT_SDK_EXTENSION_VERSION: u32 = 1;
/// Process-wide maximum of live and pending owner handles in this library instance.
pub const Q_PERIAPT_SDK_MAX_HANDLES: usize = 1024;
/// Process-wide maximum concurrent SDK calls; disposal and prepared policy
/// activation are exempt so exhaustion cannot block revocation.
pub const Q_PERIAPT_SDK_MAX_CALLS: usize = 64;
/// Canonical public key: ML-KEM-768 public key followed by X25519 public key.
pub const Q_PERIAPT_SDK_PUBLIC_KEY_LEN: usize = 1216;
/// Canonical ciphertext: ML-KEM-768 ciphertext followed by X25519 share.
pub const Q_PERIAPT_SDK_CIPHERTEXT_LEN: usize = 1120;
/// Explicit expert transfer: eight-byte QPK header, 2400-byte PQ key, 32-byte scalar.
pub const Q_PERIAPT_SDK_EXPANDED_KEY_LEN: usize = 2440;
/// Previous and next trusted policy states, each 36 canonical bytes.
pub const Q_PERIAPT_SDK_POLICY_UPDATE_STATES_LEN: usize = 72;
/// Maximum protocol/algorithm label length; bytes must be ASCII 0x21..=0x7e.
pub const Q_PERIAPT_SDK_MAX_PROTOCOL_LABEL_BYTES: usize = 255;
/// Application traffic from initiator to responder.
pub const Q_PERIAPT_PURPOSE_INITIATOR_TRAFFIC: u32 = 1;
/// Application traffic from responder to initiator.
pub const Q_PERIAPT_PURPOSE_RESPONDER_TRAFFIC: u32 = 2;
/// Initiator key confirmation (the protocol supplies the exchange).
pub const Q_PERIAPT_PURPOSE_INITIATOR_CONFIRMATION: u32 = 3;
/// Responder key confirmation (the protocol supplies the exchange).
pub const Q_PERIAPT_PURPOSE_RESPONDER_CONFIRMATION: u32 = 4;
/// Application exporter; protocol labels distinguish individual uses.
pub const Q_PERIAPT_PURPOSE_EXPORTER: u32 = 5;

type StatusResult<T> = Result<T, i32>;
fn owner_registry() -> &'static Registry<Q_PERIAPT_SDK_MAX_HANDLES> {
    static OWNERS: Registry<Q_PERIAPT_SDK_MAX_HANDLES> = Registry::new();
    &OWNERS
}
fn call_count() -> &'static AtomicUsize {
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    &ACTIVE
}

/// Borrowed input bytes. Null is allowed only when length is zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QPeriaptInput {
    /// Readable bytes, stable for the entire call.
    pub data: *const u8,
    /// Byte length.
    pub len: usize,
}
/// Caller-owned output bytes. Storage may initially be uninitialized.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QPeriaptOutput {
    /// Writable storage disjoint from all inputs and other outputs.
    pub data: *mut u8,
    /// Fixed output size or bounded capacity, as specified by each function.
    pub len: usize,
}
/// Runtime construction options. Initialize every field; `struct_size` equals
/// `sizeof(QPeriaptRuntimeOptions)`, and extension version equals the header value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QPeriaptRuntimeOptions {
    /// Complete structure size, for mismatched-header rejection.
    pub struct_size: u32,
    /// SDK extension revision; ABI major remains 2.
    pub extension_version: u32,
    /// Exact signed policy document, at most 64 KiB.
    pub policy: QPeriaptInput,
    /// Detached ML-DSA-65 policy signature, 3309 bytes.
    pub signature: QPeriaptInput,
    /// Host-pinned ML-DSA-65 root, 1952 bytes.
    pub trust_root: QPeriaptInput,
    /// Empty for first installation, otherwise 36 trusted persistent bytes.
    pub previous_state: QPeriaptInput,
    /// Maximum retained keys for this runtime, 1..=1024.
    pub max_live_keys: u32,
    /// Maximum active KEM operations for this runtime, 1..=64.
    pub max_in_flight: u32,
}

// All three repr(C) options types start with these two u32 fields. Inspect
// only the supported prefix before reading pointer-bearing fields. A rejected
// header is a shape failure: no output is initialized or handle consulted.
// SAFETY: four readable immutable bytes are required initially; matching size
// requires eight, and a matching revision requires the complete options object.
unsafe fn validate_options_prefix(options: *const u8, expected: usize) -> StatusResult<()> {
    if options.is_null() {
        return Err(Q_PERIAPT_ERR_NULL);
    }
    if !region_ok(options, size_of::<u32>()) {
        return Err(Q_PERIAPT_ERR_LENGTH);
    }
    // SAFETY: the initial size word is readable even for an unsupported layout.
    let supplied = unsafe { options.cast::<u32>().read_unaligned() };
    if supplied as usize != expected {
        return Err(Q_PERIAPT_ERR_LIMITS);
    }
    if !region_ok(options, 2 * size_of::<u32>()) {
        return Err(Q_PERIAPT_ERR_LENGTH);
    }
    // SAFETY: matching size requires the two-word prefix; no other field is read.
    let revision = unsafe { options.add(size_of::<u32>()).cast::<u32>().read_unaligned() };
    if revision != Q_PERIAPT_SDK_EXTENSION_VERSION {
        return Err(Q_PERIAPT_ERR_LIMITS);
    }
    if !region_ok(options, expected) {
        return Err(Q_PERIAPT_ERR_LENGTH);
    }
    Ok(())
}

fn map_error(error: sdk::Error) -> i32 {
    match error {
        sdk::Error::Closed => Q_PERIAPT_ERR_CLOSED,
        sdk::Error::InvalidLength => Q_PERIAPT_ERR_LENGTH,
        sdk::Error::PolicyDenied => Q_PERIAPT_ERR_POLICY,
        sdk::Error::UpdateOwnerRequired => Q_PERIAPT_ERR_STORAGE_REQUIRED,
        sdk::Error::InvalidKeyShare => Q_PERIAPT_ERR_INVALID_KEYSHARE,
        sdk::Error::Entropy => Q_PERIAPT_ERR_ENTROPY,
        sdk::Error::ResourceLimit => Q_PERIAPT_ERR_RESOURCE_LIMIT,
        sdk::Error::InvalidLimits => Q_PERIAPT_ERR_LIMITS,
        sdk::Error::InvalidPurpose => Q_PERIAPT_ERR_PURPOSE,
        sdk::Error::InvalidPrivateKey => Q_PERIAPT_ERR_INVALID_PRIVATE_KEY,
        sdk::Error::Backend => Q_PERIAPT_ERR_INTERNAL,
    }
}

struct Admission;
impl Admission {
    fn enter() -> StatusResult<Self> {
        let counter = call_count();
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if current >= Q_PERIAPT_SDK_MAX_CALLS {
                return Err(Q_PERIAPT_ERR_RESOURCE_LIMIT);
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(observed) => current = observed,
            }
        }
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        call_count().fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy)]
struct InputSpec {
    span: QPeriaptInput,
    min: usize,
    max: usize,
}
fn input(span: QPeriaptInput, min: usize, max: usize) -> InputSpec {
    InputSpec { span, min, max }
}
struct OutputGuard<const N: usize> {
    outputs: [QPeriaptOutput; N],
    committed: bool,
}
impl<const N: usize> OutputGuard<N> {
    // Call only after complete range/shape/alias checks and the C validity contract.
    unsafe fn initialize(outputs: [QPeriaptOutput; N]) -> Self {
        for output in outputs {
            // SAFETY: the caller guarantees each validated region is writable.
            unsafe {
                std::ptr::write_bytes(output.data, 0, output.len);
            }
        }
        Self {
            outputs,
            committed: false,
        }
    }
}
impl<const N: usize> Drop for OutputGuard<N> {
    fn drop(&mut self) {
        if !self.committed {
            for output in self.outputs {
                // SAFETY: initialize wrote every byte; the C call still owns the
                // valid, disjoint region. Erase success fragments even on panic.
                unsafe {
                    q_periapt_core::secure_wipe(std::slice::from_raw_parts_mut(
                        output.data,
                        output.len,
                    ));
                }
            }
        }
    }
}

/// Invalid pointer shapes/lengths or aliasing leave outputs untouched. Once the
/// entire I/O shape is validated, every subsequent failure leaves outputs zero.
unsafe fn execute<const I: usize, const O: usize>(
    inputs: [InputSpec; I],
    outputs: [(QPeriaptOutput, usize); O],
    operation: impl FnOnce() -> StatusResult<()>,
) -> i32 {
    // SAFETY: the identical public validity contract applies to both paths.
    unsafe { execute_with_admission(inputs, outputs, true, operation) }
}

// Activation, like close, must remain available under call-budget exhaustion.
// It uses only resources reserved before the host persists the next policy.
unsafe fn execute_with_admission<const I: usize, const O: usize>(
    inputs: [InputSpec; I],
    outputs: [(QPeriaptOutput, usize); O],
    admit: bool,
    operation: impl FnOnce() -> StatusResult<()>,
) -> i32 {
    for spec in inputs {
        if spec.span.len < spec.min
            || spec.span.len > spec.max
            || !region_ok(spec.span.data, spec.span.len)
        {
            return Q_PERIAPT_ERR_LENGTH;
        }
        if spec.span.len != 0 && spec.span.data.is_null() {
            return Q_PERIAPT_ERR_NULL;
        }
    }
    for (span, expected) in outputs {
        if span.len != expected || !region_ok(span.data, span.len) {
            return Q_PERIAPT_ERR_LENGTH;
        }
        if span.data.is_null() {
            return Q_PERIAPT_ERR_NULL;
        }
    }
    if outputs_alias(
        &inputs.map(|i| (i.span.data, i.span.len)),
        &outputs.map(|(o, _)| (o.data.cast_const(), o.len)),
    ) {
        return Q_PERIAPT_ERR_ALIASING;
    }
    // SAFETY: every shape and alias check succeeded; validity is the public C contract.
    let mut guard = unsafe { OutputGuard::initialize(outputs.map(|(span, _)| span)) };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _admission = if admit {
            Some(Admission::enter()?)
        } else {
            None
        };
        operation()
    }))
    .unwrap_or(Err(Q_PERIAPT_ERR_PANIC));
    match result {
        Ok(()) => {
            guard.committed = true;
            Q_PERIAPT_OK
        }
        Err(error) => error,
    }
}

unsafe fn read<'a>(span: QPeriaptInput) -> StatusResult<&'a [u8]> {
    // SAFETY: execute validated the bounded input; the enclosing C caller
    // guarantees its readability and lifetime through this synchronous call.
    unsafe { in_slice(span.data, span.len) }.ok_or(Q_PERIAPT_ERR_NULL)
}
unsafe fn write(span: QPeriaptOutput, bytes: &[u8]) -> StatusResult<()> {
    // SAFETY: execute established a valid disjoint output of the exact size.
    let mut output = unsafe { out_buf(span.data, span.len) }.ok_or(Q_PERIAPT_ERR_NULL)?;
    if output.len() != bytes.len() {
        return Err(Q_PERIAPT_ERR_INTERNAL);
    }
    output.copy_from_slice(bytes);
    Ok(())
}
fn handle_output(out: *mut u64) -> QPeriaptOutput {
    QPeriaptOutput {
        data: out.cast(),
        len: 8,
    }
}

fn runtime(handle: u64) -> StatusResult<Arc<sdk::Runtime>> {
    match owner_registry().get(handle)?.0 {
        Object::Runtime(runtime) => Ok(runtime),
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        Object::Persistent(owner) => Ok(Arc::clone(&owner.runtime)),
        _ => Err(Q_PERIAPT_ERR_CLOSED),
    }
}

/// Return the additive SDK contract revision, without changing C ABI major 2.
#[no_mangle]
pub extern "C" fn q_periapt_sdk_extension_version() -> u32 {
    const _: [(); Q_PERIAPT_SDK_PUBLIC_KEY_LEN] = [(); sdk::PUBLIC_KEY_LEN];
    const _: [(); Q_PERIAPT_SDK_CIPHERTEXT_LEN] = [(); sdk::CIPHERTEXT_LEN];
    const _: [(); Q_PERIAPT_SDK_EXPANDED_KEY_LEN] = [(); sdk::expert::EXPANDED_KEY_LEN];
    Q_PERIAPT_SDK_EXTENSION_VERSION
}

/// Explicit expert import of the expanded ContextBound format. Uses fresh
/// platform coins for pairwise validation and derives the paired public keys.
/// # Safety
/// `encoded` is readable/immutable for 2440 bytes; `out_key` is writable for eight
/// bytes and disjoint. The caller owns and must protect/erase the input copy.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_expert_key_import(
    handle: u64,
    encoded: QPeriaptInput,
    out_key: *mut u64,
) -> i32 {
    let output = handle_output(out_key);
    // SAFETY: execute validates all buffer shapes/aliases before access.
    unsafe {
        execute(
            [input(
                encoded,
                sdk::expert::EXPANDED_KEY_LEN,
                sdk::expert::EXPANDED_KEY_LEN,
            )],
            [(output, 8)],
            || {
                let runtime = runtime(handle)?;
                let mut slot = owner_registry().reserve(handle)?;
                let key =
                    sdk::expert::import_expanded(&runtime, read(encoded)?).map_err(map_error)?;
                slot.install(Object::Key(Arc::new(RwLock::new(key))))?;
                write(output, &slot.id().to_ne_bytes())?;
                slot.publish()
            },
        )
    }
}

/// Explicit plaintext export for professional key transfer. This is not a
/// default getter, encrypted storage, an authorization token or a seed key.
/// # Safety
/// `output` is writable for exactly 2440 bytes; the caller owns its erasure.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_expert_key_export(
    handle: u64,
    output: QPeriaptOutput,
) -> i32 {
    // SAFETY: the public output validity/lifetime contract applies.
    unsafe {
        execute([], [(output, sdk::expert::EXPANDED_KEY_LEN)], || {
            let Object::Key(key) = owner_registry().get(handle)?.0 else {
                return Err(Q_PERIAPT_ERR_CLOSED);
            };
            let key = key.read().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
            write(
                output,
                sdk::expert::export_expanded(&key)
                    .map_err(map_error)?
                    .as_bytes(),
            )
        })
    }
}

/// Prepare a strictly newer signed policy using the runtime's pinned root.
/// No new-policy key operation is possible before explicit activation.
/// # Safety
/// Policy/signature are readable and immutable, `out_update` is writable for
/// eight bytes and disjoint from inputs. Policy <=64 KiB, signature 3309 bytes.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_prepare_update(
    handle: u64,
    policy: QPeriaptInput,
    signature: QPeriaptInput,
    out_update: *mut u64,
) -> i32 {
    let output = handle_output(out_update);
    // SAFETY: shapes and aliasing precede reads/publication.
    unsafe {
        execute(
            [input(policy, 1, 65_536), input(signature, 3309, 3309)],
            [(output, 8)],
            || {
                let runtime = match owner_registry().get(handle)?.0 {
                    Object::Runtime(runtime) => runtime,
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    Object::Persistent(_) => return Err(Q_PERIAPT_ERR_STORAGE_REQUIRED),
                    _ => return Err(Q_PERIAPT_ERR_CLOSED),
                };
                let mut slot = owner_registry().reserve(handle)?;
                let update = runtime
                    .prepare_policy_update(read(policy)?, read(signature)?)
                    .map_err(map_error)?;
                slot.install_policy_update(update)?;
                write(output, &slot.id().to_ne_bytes())?;
                slot.publish()
            },
        )
    }
}

/// Return previous || next trusted states (36 bytes each) for the host's atomic
/// compare-and-persist operation. These public bytes are not an authority token.
/// # Safety
/// `output` is writable for exactly 72 bytes for the entire call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_policy_update_states(
    handle: u64,
    output: QPeriaptOutput,
) -> i32 {
    // SAFETY: the validated output remains writable throughout the call.
    unsafe {
        execute(
            [],
            [(output, Q_PERIAPT_SDK_POLICY_UPDATE_STATES_LEN)],
            || {
                let Object::PolicyUpdate { value, .. } = owner_registry().get(handle)?.0 else {
                    return Err(Q_PERIAPT_ERR_CLOSED);
                };
                let update = value.read().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
                let (previous, next) = update
                    .as_ref()
                    .ok_or(Q_PERIAPT_ERR_CLOSED)?
                    .states()
                    .map_err(map_error)?;
                let mut bytes = [0; Q_PERIAPT_SDK_POLICY_UPDATE_STATES_LEN];
                let (left, right) = bytes.split_at_mut(36);
                left.copy_from_slice(&previous.encode());
                right.copy_from_slice(&next.encode());
                write(output, &bytes)
            },
        )
    }
}

/// Activate only after host compare-and-persist succeeds. Consumes the update
/// handle, returns a different runtime handle and revokes/drains old children.
/// Activation/disposal are exempt from the call budget and need no new slot.
/// On failure after persistence, stop old-runtime use and recover from the
/// signed policy plus persisted state; the SDK cannot inspect external storage.
/// # Safety
/// `out_runtime` is writable for eight bytes throughout the call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_policy_update_activate(
    handle: u64,
    out_runtime: *mut u64,
) -> i32 {
    let output = handle_output(out_runtime);
    // SAFETY: the unmetered transition retains the full shape/alias/output checks.
    unsafe {
        execute_with_admission([], [(output, 8)], false, || {
            let (Object::PolicyUpdate { value, successor }, parent) =
                owner_registry().get(handle)?
            else {
                return Err(Q_PERIAPT_ERR_CLOSED);
            };
            let mut update = match value.write() {
                Ok(update) => update,
                Err(poisoned) => {
                    drop(poisoned);
                    // Cleanup may recover the poisoned update only to dispose it.
                    // Preserve an internal-error result even if disposal succeeds.
                    return match owner_registry().close(parent) {
                        Ok(()) | Err(Q_PERIAPT_ERR_CLOSED) => Err(Q_PERIAPT_ERR_INTERNAL),
                        Err(error) => Err(error),
                    };
                }
            };
            write(output, &successor.to_ne_bytes())?;
            let (slot, parent) =
                owner_registry().activate_policy_update(handle, &value, &mut update)?;
            drop(update); // parent disposal must never wait on our own update lock
            match owner_registry().close(parent) {
                Ok(()) | Err(Q_PERIAPT_ERR_CLOSED) => {} // another closer may own disposal
                Err(error) => return Err(error),
            }
            slot.publish()
        })
    }
}

/// Construct a verified immutable runtime; no serialized decision is accepted.
/// Persist its trusted state atomically before use. A valid policy excluding the
/// fixed suite/profile creates a disabled runtime; query runtime_enabled. Its
/// key operations return POLICY, while future signed updates remain possible.
///
/// # Safety
/// `options` initially provides four readable immutable bytes (`struct_size`).
/// Matching size requires the eight-byte size/revision prefix; matching revision
/// requires the fully initialized complete structure. Unsupported size/revision
/// returns LIMITS without reading later fields or writing output. Every accepted
/// input buffer is readable and immutable for its length throughout the call;
/// `out_runtime` is writable for eight bytes. No input/output regions may overlap.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_new(
    options: *const QPeriaptRuntimeOptions,
    out_runtime: *mut u64,
) -> i32 {
    // SAFETY: the caller supplies the readable prefix and, when supported,
    // the complete object according to the staged validity contract above.
    if let Err(error) =
        unsafe { validate_options_prefix(options.cast(), size_of::<QPeriaptRuntimeOptions>()) }
    {
        return error;
    }
    // SAFETY: complete initialized structure is required by this function's contract.
    let config = unsafe { options.read_unaligned() };
    let header = QPeriaptInput {
        data: options.cast(),
        len: size_of::<QPeriaptRuntimeOptions>(),
    };
    let output = handle_output(out_runtime);
    // SAFETY: the documented C contract covers all input and output buffers.
    unsafe {
        execute(
            [
                input(header, header.len, header.len),
                input(config.policy, 1, 65_536),
                input(config.signature, 3309, 3309),
                input(config.trust_root, 1952, 1952),
                input(
                    config.previous_state,
                    if config.previous_state.len == 0 {
                        0
                    } else {
                        TrustedPolicyState::ENCODED_LEN
                    },
                    TrustedPolicyState::ENCODED_LEN,
                ),
            ],
            [(output, 8)],
            || {
                let mut slot = owner_registry().reserve(0)?;
                let previous = read(config.previous_state)?;
                let previous = if previous.is_empty() {
                    None
                } else {
                    Some(TrustedPolicyState::decode(previous).map_err(|_| Q_PERIAPT_ERR_POLICY)?)
                };
                let runtime = sdk::Runtime::from_signed_policy(
                    read(config.policy)?,
                    read(config.signature)?,
                    read(config.trust_root)?,
                    previous.as_ref(),
                    sdk::Limits {
                        max_live_keys: config.max_live_keys as usize,
                        max_in_flight: config.max_in_flight as usize,
                    },
                )
                .map_err(map_error)?;
                slot.install(Object::Runtime(Arc::new(runtime)))?;
                write(output, &slot.id().to_ne_bytes())?;
                slot.publish()
            },
        )
    }
}

/// Read the authenticated persistent state (36 bytes).
/// # Safety
/// `output` is a valid writable region of exactly 36 bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_state(handle: u64, output: QPeriaptOutput) -> i32 {
    // SAFETY: output validity is required by the public contract.
    unsafe {
        execute([], [(output, 36)], || {
            let runtime = runtime(handle)?;
            // An unwind can revoke a persistent epoch before its registry slot
            // is explicitly disposed. Closed owners must not report stale
            // metadata as a successful recovery-state query.
            runtime.is_enabled().map_err(map_error)?;
            write(output, &runtime.trusted_state().encode())
        })
    }
}

/// Return whether this runtime's authenticated policy permits the fixed suite:
/// one means enabled, zero means disabled. This is not a lease across close.
/// # Safety
/// `out_enabled` is writable for four bytes throughout the call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_enabled(handle: u64, out_enabled: *mut u32) -> i32 {
    let output = QPeriaptOutput {
        data: out_enabled.cast(),
        len: 4,
    };
    // SAFETY: the output's validity/lifetime is the caller's contract.
    unsafe {
        execute([], [(output, 4)], || {
            let enabled = u32::from(runtime(handle)?.is_enabled().map_err(map_error)?);
            write(output, &enabled.to_ne_bytes())
        })
    }
}

/// Generate a hybrid key using platform randomness. Private bytes remain owned.
/// # Safety
/// `out_key` is writable for eight bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_key_generate(handle: u64, out_key: *mut u64) -> i32 {
    let output = handle_output(out_key);
    // SAFETY: output validity is required by the public contract.
    unsafe {
        execute([], [(output, 8)], || {
            let runtime = runtime(handle)?;
            let mut slot = owner_registry().reserve(handle)?;
            let key = runtime.generate_key().map_err(map_error)?;
            slot.install(Object::Key(Arc::new(RwLock::new(key))))?;
            write(output, &slot.id().to_ne_bytes())?;
            slot.publish()
        })
    }
}

/// Export only the key's canonical public bytes (1216 bytes).
/// # Safety
/// `output` is a valid writable region of exactly the published public-key size.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_key_public(handle: u64, output: QPeriaptOutput) -> i32 {
    // SAFETY: output validity is required by the public contract.
    unsafe {
        execute([], [(output, Q_PERIAPT_SDK_PUBLIC_KEY_LEN)], || {
            let Object::Key(key) = owner_registry().get(handle)?.0 else {
                return Err(Q_PERIAPT_ERR_CLOSED);
            };
            let key = key.read().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
            write(output, &key.public_key().map_err(map_error)?.to_bytes())
        })
    }
}

/// Encapsulate with fresh platform randomness, returning ciphertext and a secret owner.
/// # Safety
/// Input regions are readable/immutable for the call. Outputs are writable for
/// their stated lengths and disjoint from all inputs and each other.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_encapsulate(
    handle: u64,
    peer: QPeriaptInput,
    context: QPeriaptInput,
    ciphertext: QPeriaptOutput,
    out_secret: *mut u64,
) -> i32 {
    let secret_out = handle_output(out_secret);
    // SAFETY: the caller guarantees buffer validity; execute checks shapes/aliasing first.
    unsafe {
        execute(
            [
                input(peer, sdk::PUBLIC_KEY_LEN, sdk::PUBLIC_KEY_LEN),
                input(context, 0, 65_536),
            ],
            [(ciphertext, sdk::CIPHERTEXT_LEN), (secret_out, 8)],
            || {
                let runtime = runtime(handle)?;
                let mut slot = owner_registry().reserve(handle)?;
                let peer = PublicKey::from_bytes(read(peer)?).map_err(map_error)?;
                let result = runtime
                    .encapsulate(&peer, read(context)?)
                    .map_err(map_error)?;
                slot.install(Object::Secret(Arc::new(RwLock::new(result.secret))))?;
                write(ciphertext, &result.ciphertext.to_bytes())?;
                write(secret_out, &slot.id().to_ne_bytes())?;
                slot.publish()
            },
        )
    }
}

/// Decapsulate with the owner's paired keys and verified runtime. Correct-length
/// invalid PQ ciphertexts still succeed with an implicit-rejection secret.
/// # Safety
/// Inputs are readable/immutable for the call; `out_secret` is writable for
/// eight bytes and disjoint from inputs.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_decapsulate(
    handle: u64,
    ciphertext: QPeriaptInput,
    context: QPeriaptInput,
    out_secret: *mut u64,
) -> i32 {
    let output = handle_output(out_secret);
    // SAFETY: the documented validity/lifetime contract applies to all regions.
    unsafe {
        execute(
            [
                input(ciphertext, sdk::CIPHERTEXT_LEN, sdk::CIPHERTEXT_LEN),
                input(context, 0, 65_536),
            ],
            [(output, 8)],
            || {
                let (object, parent) = owner_registry().get(handle)?;
                let Object::Key(key) = object else {
                    return Err(Q_PERIAPT_ERR_CLOSED);
                };
                let mut slot = owner_registry().reserve(parent)?;
                let key = key.read().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
                let ciphertext = Ciphertext::from_bytes(read(ciphertext)?).map_err(map_error)?;
                let secret = key
                    .decapsulate(&ciphertext, read(context)?)
                    .map_err(map_error)?;
                slot.install(Object::Secret(Arc::new(RwLock::new(secret))))?;
                write(output, &slot.id().to_ne_bytes())?;
                slot.publish()
            },
        )
    }
}

/// Explicitly copy a combined secret for an external protocol/KDF. The caller
/// owns this exported copy; this is not a private-key export or key confirmation.
/// # Safety
/// `output` is a valid writable region of exactly 32 bytes for the call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_secret_export(handle: u64, output: QPeriaptOutput) -> i32 {
    // SAFETY: output validity is required by the public contract.
    unsafe {
        execute([], [(output, 32)], || {
            let Object::Secret(secret) = owner_registry().get(handle)?.0 else {
                return Err(Q_PERIAPT_ERR_CLOSED);
            };
            let secret = secret.read().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
            write(
                output,
                secret.export_for_protocol().map_err(map_error)?.as_bytes(),
            )
        })
    }
}

/// Derive an owned 256-bit application key using version-1 HKDF-SHA-256. Binds
/// runtime policy/root, fixed suite/profile, purpose, protocol label and context.
/// This is not a TLS key schedule, peer authentication or key confirmation.
/// # Safety
/// Inputs are readable/immutable for the call; `out_key` is writable for eight
/// bytes and disjoint from inputs. Label is 1..=255 bytes; context is <=64 KiB.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_secret_derive(
    handle: u64,
    purpose: u32,
    protocol_label: QPeriaptInput,
    context: QPeriaptInput,
    out_key: *mut u64,
) -> i32 {
    let output = handle_output(out_key);
    // SAFETY: execute validates all public extents/aliasing before accessing them.
    unsafe {
        execute(
            [
                input(protocol_label, 1, sdk::MAX_PROTOCOL_LABEL_BYTES),
                input(context, 0, 65_536),
            ],
            [(output, 8)],
            || {
                let purpose = sdk::KeyPurpose::try_from(purpose).map_err(map_error)?;
                let (object, parent) = owner_registry().get(handle)?;
                let Object::Secret(secret) = object else {
                    return Err(Q_PERIAPT_ERR_CLOSED);
                };
                let mut slot = owner_registry().reserve(parent)?;
                let secret = secret.read().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
                let key = secret
                    .derive_key(purpose, read(protocol_label)?, read(context)?)
                    .map_err(map_error)?;
                slot.install(Object::DerivedKey(Arc::new(RwLock::new(key))))?;
                write(output, &slot.id().to_ne_bytes())?;
                slot.publish()
            },
        )
    }
}

/// Explicitly copy one derived application key. A KEM-secret handle is rejected.
/// The caller owns and must erase the exported copy.
/// # Safety
/// `output` is writable for exactly 32 bytes for the entire call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_derived_key_export(
    handle: u64,
    output: QPeriaptOutput,
) -> i32 {
    // SAFETY: output validity is required by the caller contract.
    unsafe {
        execute([], [(output, 32)], || {
            let Object::DerivedKey(key) = owner_registry().get(handle)?.0 else {
                return Err(Q_PERIAPT_ERR_CLOSED);
            };
            let key = key.read().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
            write(
                output,
                key.export_for_protocol().map_err(map_error)?.as_bytes(),
            )
        })
    }
}

/// Revoke an owner handle. Runtime close also revokes all child handles and
/// disposes those still registered. Operations retain memory until their lease
/// ends; no new child can publish after runtime revocation. A concurrent closer
/// may already own disposal of a child. Repeated close returns ERR_CLOSED.
#[no_mangle]
pub extern "C" fn q_periapt_sdk_close(handle: u64) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| owner_registry().close(handle))) {
        Ok(Ok(())) => Q_PERIAPT_OK,
        Ok(Err(error)) => error,
        Err(_) => Q_PERIAPT_ERR_PANIC,
    }
}

#[cfg(test)]
mod tests;
