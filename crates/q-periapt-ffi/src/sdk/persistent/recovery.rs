// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded public statements and durable independently authorized policy recovery.
use super::*;

/// Original recovery trust is required, or this store was not enrolled for recovery.
pub const Q_PERIAPT_ERR_RECOVERY_REQUIRED: i32 = -25;
/// Canonical recovery request, without either role signature.
pub const Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN: usize = 2168;
/// Request followed by recovery-authority and incoming-key ML-DSA-65 signatures.
pub const Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN: usize = 8786;
/// Full domain-separated enrollment message for the independently pinned recovery key.
pub const Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN: usize = 3968;
/// Full domain-separated transition message for the recovery authority.
pub const Q_PERIAPT_POLICY_RECOVERY_APPROVAL_MESSAGE_LEN: usize = 2203;
/// Full domain-separated transition message for the incoming online policy key.
pub const Q_PERIAPT_POLICY_RECOVERY_POSSESSION_MESSAGE_LEN: usize = 2204;
/// This call committed and activated the original authorized recovery.
pub const Q_PERIAPT_POLICY_RECOVERY_APPLIED: u32 = 1;
/// Original recovery was already applied and its exact policy is still current.
pub const Q_PERIAPT_POLICY_RECOVERY_ALREADY_APPLIED: u32 = 2;
/// Original recovery was applied, followed by a later policy or root transition.
pub const Q_PERIAPT_POLICY_RECOVERY_APPLIED_THEN_ADVANCED: u32 = 3;

/// Explicit recovery-enabled store configuration. Original scope and both roots
/// must be retained independently of incoming policies and the database itself.
/// Existing v1 stores are never implicitly enrolled or overwritten.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QPeriaptRecoverableStoreOptions {
    /// Exact complete structure size; the staged size/revision contract applies.
    pub struct_size: u32,
    /// Q_PERIAPT_SDK_EXTENSION_VERSION; existing layouts and ABI 2 are unchanged.
    pub extension_version: u32,
    /// Private, absolute UTF-8 store path, at most 4096 bytes, with no NUL.
    pub path: QPeriaptInput,
    /// Desired exact signed policy, at most 65536 bytes.
    pub policy: QPeriaptInput,
    /// Detached policy signature, exactly 3309 bytes.
    pub signature: QPeriaptInput,
    /// Independently selected nonzero 32-byte authorization scope.
    pub scope: QPeriaptInput,
    /// ORIGINAL online policy root, exactly 1952 bytes, retained across recoveries.
    pub initial_root: QPeriaptInput,
    /// Independent recovery root, exactly 1952 bytes, distinct from the online root.
    pub recovery_root: QPeriaptInput,
    /// Exactly 3309 bytes for provision; canonical empty input for either open.
    pub enrollment_signature: QPeriaptInput,
    /// Per-runtime key quota, 1..=1024.
    pub max_live_keys: u32,
    /// Per-runtime operation quota, 1..=64.
    pub max_in_flight: u32,
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryOpenMode {
    Provision,
    Configured,
    Recovering,
}
fn outcome_output(pointer: *mut u32) -> QPeriaptOutput {
    QPeriaptOutput {
        data: pointer.cast(),
        len: 4,
    }
}

/// Build the public enrollment statement to sign before first provisioning.
/// This does not verify authority, perform I/O, or enroll an existing store.
/// Available on the reviewed macOS/Linux persistent-store hosts.
/// # Safety
/// Inputs are readable/immutable for 32, 1952 and 1952 bytes respectively.
/// Output is writable for exactly 3968 bytes and disjoint from every input.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_policy_recovery_enrollment_message(
    scope: QPeriaptInput,
    initial_root: QPeriaptInput,
    recovery_root: QPeriaptInput,
    output: QPeriaptOutput,
) -> i32 {
    // SAFETY: execute checks shapes/aliases before borrowing any bytes.
    unsafe {
        execute(
            [
                input(scope, 32, 32),
                input(initial_root, 1952, 1952),
                input(recovery_root, 1952, 1952),
            ],
            [(output, Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN)],
            || {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    let trust = supported::recovery::trust(
                        read(scope)?,
                        read(initial_root)?,
                        read(recovery_root)?,
                    )?;
                    write(output, &trust.enrollment_message())
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    Err(Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM)
                }
            },
        )
    }
}

unsafe fn construct_recoverable(
    options: *const QPeriaptRecoverableStoreOptions,
    mode: RecoveryOpenMode,
    authorization: QPeriaptInput,
    out_runtime: *mut u64,
    out_outcome: *mut u32,
) -> i32 {
    // SAFETY: public entry points require the staged readable prefix.
    if let Err(error) = unsafe {
        validate_options_prefix(options.cast(), size_of::<QPeriaptRecoverableStoreOptions>())
    } {
        return error;
    }
    // SAFETY: a matching size/revision requires the complete initialized object.
    let config = unsafe { options.read_unaligned() };
    let header = QPeriaptInput {
        data: options.cast(),
        len: size_of::<QPeriaptRecoverableStoreOptions>(),
    };
    let enrollment_len = if matches!(mode, RecoveryOpenMode::Provision) {
        3309
    } else {
        0
    };
    let authorization_len = if matches!(mode, RecoveryOpenMode::Recovering) {
        Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN
    } else {
        0
    };
    let handle = handle_output(out_runtime);
    let outcome = outcome_output(out_outcome);
    // SAFETY: accepted spans/output regions are valid, immutable/disjoint as documented.
    unsafe {
        execute(
            [
                input(header, header.len, header.len),
                input(config.path, 1, Q_PERIAPT_STORE_MAX_PATH_BYTES),
                input(config.policy, 1, 65536),
                input(config.signature, 3309, 3309),
                input(config.scope, 32, 32),
                input(config.initial_root, 1952, 1952),
                input(config.recovery_root, 1952, 1952),
                input(config.enrollment_signature, enrollment_len, enrollment_len),
                input(authorization, authorization_len, authorization_len),
            ],
            [(handle, 8), (outcome, 4)],
            || {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    let path = std::str::from_utf8(read(config.path)?)
                        .map_err(|_| Q_PERIAPT_ERR_LENGTH)?;
                    if path.as_bytes().contains(&0) {
                        return Err(Q_PERIAPT_ERR_LENGTH);
                    }
                    let configuration = supported::recovery::Configuration {
                        path,
                        trust: supported::recovery::trust(
                            read(config.scope)?,
                            read(config.initial_root)?,
                            read(config.recovery_root)?,
                        )?,
                        policy: read(config.policy)?,
                        signature: read(config.signature)?,
                        enrollment: read(config.enrollment_signature)?,
                        limits: sdk::Limits {
                            max_live_keys: config.max_live_keys as usize,
                            max_in_flight: config.max_in_flight as usize,
                        },
                    };
                    let mut slot = owner_registry().reserve(0)?;
                    let (owner, disposition) =
                        supported::recovery::construct(configuration, mode, read(authorization)?)?;
                    slot.install(Object::Persistent(Arc::new(owner)))?;
                    write(handle, &slot.id().to_ne_bytes())?;
                    write(outcome, &disposition.to_ne_bytes())?;
                    slot.publish()
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    Err(Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM)
                }
            },
        )
    }
}

/// Provision a new recovery-enabled macOS/Linux store with an enrollment proof.
/// Original independent trust must be preserved outside the database. Existing
/// files, including v1 stores, are never replaced or implicitly upgraded.
/// # Safety
/// Options initially supplies four readable immutable size bytes; matching size
/// requires eight prefix bytes, and matching revision requires the entire object.
/// Accepted referenced inputs remain readable/immutable throughout the call.
/// out_runtime is writable for eight bytes, disjoint from all accepted inputs.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_provision_recoverable_store(
    options: *const QPeriaptRecoverableStoreOptions,
    out_runtime: *mut u64,
) -> i32 {
    let mut disposition = 0;
    // SAFETY: same staged options/input/output contract; private outcome is disjoint.
    unsafe {
        construct_recoverable(
            options,
            RecoveryOpenMode::Provision,
            QPeriaptInput {
                data: std::ptr::null(),
                len: 0,
            },
            out_runtime,
            &mut disposition,
        )
    }
}

/// Open a recovery-enabled store using ORIGINAL trust and reconcile a configured
/// ordinary policy under its current authorized root. Enrollment input is empty.
/// Recover uncertain root replacement with runtime_open_recovering_store instead.
/// # Safety
/// Same staged options/input/output contract as runtime_provision_recoverable_store.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_open_recoverable_store(
    options: *const QPeriaptRecoverableStoreOptions,
    out_runtime: *mut u64,
) -> i32 {
    let mut disposition = 0;
    // SAFETY: public contract and separate private outcome cover common construction.
    unsafe {
        construct_recoverable(
            options,
            RecoveryOpenMode::Configured,
            QPeriaptInput {
                data: std::ptr::null(),
                len: 0,
            },
            out_runtime,
            &mut disposition,
        )
    }
}

/// Reconcile the original signed recovery before exposing a runtime. On success,
/// always returns a new owner and APPLIED/ALREADY_APPLIED/APPLIED_THEN_ADVANCED.
/// A later authorized state is retained; the old target is never rolled back.
/// Enrollment input is empty. Keep the original authorization across retries.
/// # Safety
/// Same staged options contract; authorization is readable/immutable for 8786
/// bytes. Both outputs are writable for eight/four bytes and mutually disjoint
/// from each other and every accepted input. Failure leaves valid outputs zero.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_open_recovering_store(
    options: *const QPeriaptRecoverableStoreOptions,
    authorization: QPeriaptInput,
    out_runtime: *mut u64,
    out_outcome: *mut u32,
) -> i32 {
    // SAFETY: the shared constructor validates every accepted shape and alias.
    unsafe {
        construct_recoverable(
            options,
            RecoveryOpenMode::Recovering,
            authorization,
            out_runtime,
            out_outcome,
        )
    }
}

/// Prepare a public recovery request without mutation or a usable candidate runtime.
/// Operation is an original nonzero 32-byte ID. Incoming root and target policy
/// are verified; independent recovery and possession signatures remain required.
/// # Safety
/// Inputs are readable/immutable for their declared lengths: operation32,
/// policy1..65536, signature3309, incoming_root1952. Output is writable for exactly
/// 2168 bytes, disjoint from every input. A persistent recovery-enabled owner is required.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_prepare_recovery(
    handle: u64,
    operation: QPeriaptInput,
    policy: QPeriaptInput,
    signature: QPeriaptInput,
    incoming_root: QPeriaptInput,
    output: QPeriaptOutput,
) -> i32 {
    // SAFETY: all shapes and alias checks precede registry/storage admission.
    unsafe {
        execute(
            [
                input(operation, 32, 32),
                input(policy, 1, 65536),
                input(signature, 3309, 3309),
                input(incoming_root, 1952, 1952),
            ],
            [(output, Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN)],
            || {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    write(
                        output,
                        &supported::recovery::prepare(
                            owner_registry(),
                            handle,
                            read(operation)?,
                            read(policy)?,
                            read(signature)?,
                            read(incoming_root)?,
                        )?,
                    )
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    let _ = handle;
                    Err(Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM)
                }
            },
        )
    }
}

/// Parse a public request and return its two complete, distinct signing messages.
/// This verifies grammar only. An approver must independently inspect the scope,
/// predecessor, incoming root, target policy and original operation before signing.
/// Authorization encoding is request || authority_signature || possession_signature.
/// # Safety
/// Request is readable/immutable for2168 bytes. Outputs are writable for2203 and
///2204 bytes respectively and disjoint from each other and the request.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_policy_recovery_signing_messages(
    request: QPeriaptInput,
    approval: QPeriaptOutput,
    possession: QPeriaptOutput,
) -> i32 {
    // SAFETY: execute retains the complete shape/alias/output-failure contract.
    unsafe {
        execute(
            [input(
                request,
                Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN,
                Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN,
            )],
            [
                (approval, Q_PERIAPT_POLICY_RECOVERY_APPROVAL_MESSAGE_LEN),
                (possession, Q_PERIAPT_POLICY_RECOVERY_POSSESSION_MESSAGE_LEN),
            ],
            || {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    let request = supported::recovery::request(read(request)?)?;
                    write(approval, &request.authorization_message())?;
                    write(possession, &request.possession_message())
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    Err(Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM)
                }
            },
        )
    }
}

/// Durably recover the online root using BOTH role signatures and the original
/// request. APPLIED returns a distinct successor and revokes the old owner/children.
/// ALREADY_APPLIED/APPLIED_THEN_ADVANCED return a zero successor and preserve this
/// owner and its children. Those are successful no-mutation outcomes, not rollback.
/// On failure, valid outputs are zero. After uncertain/committed failure or lost
/// reply, close old ownership and open_recovering_store with the SAME authorization.
/// # Safety
/// Authorization8786, policy1..65536 and signature3309 inputs remain readable and
/// immutable. Runtime/outcome outputs are writable for8/4 bytes and mutually
/// disjoint from all inputs. Persistent disk work is synchronous and may block.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_recover_authority(
    handle: u64,
    authorization: QPeriaptInput,
    policy: QPeriaptInput,
    signature: QPeriaptInput,
    out_runtime: *mut u64,
    out_outcome: *mut u32,
) -> i32 {
    let runtime = handle_output(out_runtime);
    let outcome = outcome_output(out_outcome);
    // SAFETY: execute validates both outputs before any recovery mutation.
    unsafe {
        execute(
            [
                input(
                    authorization,
                    Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN,
                    Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN,
                ),
                input(policy, 1, 65536),
                input(signature, 3309, 3309),
            ],
            [(runtime, 8), (outcome, 4)],
            || {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    supported::recovery::recover(
                        owner_registry(),
                        handle,
                        read(authorization)?,
                        read(policy)?,
                        read(signature)?,
                        |successor, disposition| {
                            write(runtime, &successor.to_ne_bytes())?;
                            write(outcome, &disposition.to_ne_bytes())
                        },
                    )
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    let _ = handle;
                    Err(Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM)
                }
            },
        )
    }
}
