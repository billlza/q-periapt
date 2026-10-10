// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Persistent runtime roots reuse the ordinary flat registry ownership graph.
//! Disk work is synchronous and never runs under the registry table lock.
use super::*;

mod recovery;
pub use recovery::*;

/// Protected storage is missing, insecure, corrupt, or failed an I/O operation.
pub const Q_PERIAPT_ERR_STORAGE: i32 = -19;
/// Another process/owner holds the store's exclusive lifetime lease.
pub const Q_PERIAPT_ERR_STORE_BUSY: i32 = -20;
/// Commit outcome is uncertain. Reconcile the configured policy before use.
pub const Q_PERIAPT_ERR_COMMIT_UNCERTAIN: i32 = -21;
/// Policy committed but no new runtime was returned; reopen with that policy.
pub const Q_PERIAPT_ERR_STORE_COMMITTED: i32 = -22;
/// This host has no reviewed persistent-store implementation.
pub const Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM: i32 = -23;
/// Use the persistent update entry point; manual activation would bypass storage.
pub const Q_PERIAPT_ERR_STORAGE_REQUIRED: i32 = -24;
/// Maximum UTF-8 absolute store path bytes, excluding any NUL terminator.
pub const Q_PERIAPT_STORE_MAX_PATH_BYTES: usize = 4096;

/// Host-owned persistent runtime configuration. Every open supplies the desired
/// signed policy, which is reconciled against the recovered floor before use.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QPeriaptStoreOptions {
    /// Exact initialized structure size.
    pub struct_size: u32,
    /// Q_PERIAPT_SDK_EXTENSION_VERSION; C ABI major remains 2.
    pub extension_version: u32,
    /// UTF-8 absolute path, 1..=4096 bytes, with no NUL or symlink components.
    /// Parent must already be private and owned by the effective user.
    pub path: QPeriaptInput,
    /// Desired exact signed document, 1..=65536 bytes.
    pub policy: QPeriaptInput,
    /// Detached ML-DSA-65 signature, exactly 3309 bytes.
    pub signature: QPeriaptInput,
    /// Independently pinned root, exactly 1952 bytes.
    pub trust_root: QPeriaptInput,
    /// Per-runtime key quota, 1..=1024.
    pub max_live_keys: u32,
    /// Per-runtime operation quota, 1..=64.
    pub max_in_flight: u32,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod supported;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) use supported::PersistentRuntime;

unsafe fn construct(
    options: *const QPeriaptStoreOptions,
    out_runtime: *mut u64,
    provision: bool,
) -> i32 {
    // SAFETY: the public constructor requires the staged readable prefix.
    if let Err(error) =
        unsafe { validate_options_prefix(options.cast(), size_of::<QPeriaptStoreOptions>()) }
    {
        return error;
    }
    // SAFETY: the caller supplies a complete initialized options object.
    let config = unsafe { options.read_unaligned() };
    let header = QPeriaptInput {
        data: options.cast(),
        len: size_of::<QPeriaptStoreOptions>(),
    };
    let output = handle_output(out_runtime);
    // SAFETY: execute checks complete shapes and aliases before borrowing inputs.
    unsafe {
        execute(
            [
                input(header, header.len, header.len),
                input(config.path, 1, Q_PERIAPT_STORE_MAX_PATH_BYTES),
                input(config.policy, 1, 65_536),
                input(config.signature, 3309, 3309),
                input(config.trust_root, 1952, 1952),
            ],
            [(output, 8)],
            || {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    let mut slot = owner_registry().reserve(0)?;
                    let path = std::str::from_utf8(read(config.path)?)
                        .map_err(|_| Q_PERIAPT_ERR_LENGTH)?;
                    if path.as_bytes().contains(&0) {
                        return Err(Q_PERIAPT_ERR_LENGTH);
                    }
                    let owner = supported::construct(
                        path,
                        read(config.policy)?,
                        read(config.signature)?,
                        read(config.trust_root)?,
                        sdk::Limits {
                            max_live_keys: config.max_live_keys as usize,
                            max_in_flight: config.max_in_flight as usize,
                        },
                        provision,
                    )?;
                    slot.install(Object::Persistent(Arc::new(owner)))?;
                    write(output, &slot.id().to_ne_bytes())?;
                    slot.publish()
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    let _ = provision;
                    Err(Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM)
                }
            },
        )
    }
}

/// Explicitly provision a new macOS/Linux store; never overwrite an existing path.
/// This call can block on filesystem synchronization. Only public policy/state
/// are persisted, not private KEM/TLS keys. The returned runtime owns its lease.
/// # Safety
/// Options initially provides four readable immutable bytes (struct_size).
/// Matching size requires the eight-byte size/revision prefix; matching revision
/// requires the complete initialized structure and readable immutable inputs.
/// Unsupported size/revision returns LIMITS with output untouched. out_runtime
/// is writable for eight bytes, disjoint from every accepted input/options object.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_provision_store(
    options: *const QPeriaptStoreOptions,
    out_runtime: *mut u64,
) -> i32 {
    // SAFETY: this wrapper retains construct's identical validity contract.
    unsafe { construct(options, out_runtime, true) }
}

/// Open an existing macOS/Linux store and reconcile the configured signed policy.
/// Missing/corrupt storage and rollback fail; they never become first installation.
/// A newer valid revocation persists a disabled runtime. Disk work can block.
/// # Safety
/// Same staged options prefix and disjoint input/output contract as
/// runtime_provision_store.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_open_store(
    options: *const QPeriaptStoreOptions,
    out_runtime: *mut u64,
) -> i32 {
    // SAFETY: the common constructor enforces the documented buffer contract.
    unsafe { construct(options, out_runtime, false) }
}

/// Atomically persist a strictly newer policy and return a new runtime handle.
/// Revokes the old handle/children, reuses its slot, and never reuses its ID.
/// This call can block on disk. Cancellation/close cannot undo a committed policy.
/// COMMIT_UNCERTAIN or STORE_COMMITTED requires reopening/reconciling that policy.
/// No output handle is usable on failure. Requires a persistent runtime root.
/// # Safety
/// policy/signature are readable and immutable, 1..=65536 and 3309 bytes;
/// out_runtime is writable for eight disjoint bytes throughout the call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_runtime_update_store(
    handle: u64,
    policy: QPeriaptInput,
    signature: QPeriaptInput,
    out_runtime: *mut u64,
) -> i32 {
    let output = handle_output(out_runtime);
    // SAFETY: the caller supplies these complete, disjoint valid regions.
    unsafe {
        execute(
            [input(policy, 1, 65_536), input(signature, 3309, 3309)],
            [(output, 8)],
            || {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    supported::update(
                        owner_registry(),
                        handle,
                        read(policy)?,
                        read(signature)?,
                        |successor| write(output, &successor.to_ne_bytes()),
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
