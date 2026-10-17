// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Foreign owner of the existing native managed account-root lifecycle.
use super::*;
pub(crate) mod alternative;
mod cleanup;
mod paired;
mod recovery;
pub(crate) use cleanup::step as cleanup_step;
use recovery::Recovery;

const PLAN_BYTES: usize = 128 * 1024;
const RECEIPT_BYTES: usize = 128 * 1024;
const PROPOSAL_BYTES: usize = 65_536;

/// Independently retained original application checkpoint and witness pin.
#[repr(C)]
pub struct Scope {
    pub struct_size: u32,
    pub checkpoint: account_authority::Checkpoint,
    pub witness: [u8; 32],
    pub public_key: *const u8,
    pub public_key_length: usize,
}
struct Approval {
    expected: p::AccountAuthorityCheckpoint,
    pin: p::AnchorPin,
}
impl Approval {
    unsafe fn read(pointer: *const Scope) -> Result<Self> {
        // SAFETY: first read only the repr(C) size header, then the exact object.
        unsafe { account_authority::check_options(pointer) }?;
        let value = unsafe { &*pointer };
        let public = p::PublicKey::decode(&unsafe {
            bytes(
                value.public_key,
                value.public_key_length,
                p::PUBLIC_KEY_BYTES,
            )
        }?)?;
        Ok(Self {
            expected: value.checkpoint.native()?,
            pin: p::AnchorPin::new(
                p::AnchorIdentity::from_trusted_state(value.witness)?,
                public,
            ),
        })
    }
}
pub(crate) struct Owner {
    native: p::ManagedAccountRootReplacement,
    pin: p::AnchorPin,
    access: p::AccountAuthorityAccess,
    report: Option<p::retired_device::Report>,
}
impl Owner {
    pub(crate) fn access(&self) -> p::AccountAuthorityAccess {
        self.access.clone()
    }
}
fn phase(state: p::AccountAuthorityReplacementState) -> u32 {
    match state {
        p::AccountAuthorityReplacementState::Preparing => 1,
        p::AccountAuthorityReplacementState::Pending => 2,
        p::AccountAuthorityReplacementState::Committed => 3,
        p::AccountAuthorityReplacementState::Closed => 4,
    }
}
fn take_registry(slot: &mut Option<Owned>) -> Result<p::AccountAuthorityStore> {
    match slot.as_ref() {
        Some(Owned::AccountAuthority(_)) => {}
        Some(_) => return Err(failure(6)),
        None => return Err(failure(2)),
    }
    match slot.take() {
        Some(Owned::AccountAuthority(owner)) => Ok(owner.into_store()),
        _ => Err(failure(5)),
    }
}
fn with_root<T>(
    handle: u64,
    deadline: Instant,
    action: impl FnOnce(&mut Owner, &Entry) -> Result<T>,
) -> Result<T> {
    with_entry(handle, deadline, |slot, entry| {
        opening::check(&entry.cancel, deadline)?;
        let result = match slot.as_mut() {
            Some(Owned::RootReplacement(owner)) => action(owner, entry),
            Some(_) => Err(failure(6)),
            None => Err(failure(2)),
        }?;
        // Late cancellation can hide a commit. Do not leave a live controller
        // behind an unsuccessful foreign return. Invalid receipts are native
        // preflight failures and preserve the controller as documented there.
        if let Err(error) = opening::check(&entry.cancel, deadline) {
            slot.take();
            return Err(error);
        }
        Ok(result)
    })
}
unsafe fn plan(pointer: *const u8, length: usize) -> Result<Box<p::AnchorAccountReplacementPlan>> {
    // Large public-key descriptors must not be copied through every admitted
    // call and unwind frame on a foreign thread's default stack.
    Ok(Box::new(
        p::AnchorAccountReplacementPlan::from_trusted_state(&unsafe {
            bytes(pointer, length, PLAN_BYTES)
        }?)?,
    ))
}

/// Convert the registry handle into a controller and consume the registered device.
/// # Safety
/// All bounded immutable inputs and the exclusive error record obey the C header.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_begin(
    registry: u64,
    device: u64,
    scope: *const Scope,
    approved_plan: *const u8,
    length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        let scope = unsafe { Approval::read(scope) }?;
        let plan = unsafe { plan(approved_plan, length) }?;
        paired::with(
            registry,
            device,
            deadline,
            |registry_slot, _, device_slot, _| {
                match registry_slot.as_ref() {
                    Some(Owned::AccountAuthority(_)) => {}
                    Some(_) => return Err(failure(6)),
                    None => return Err(failure(2)),
                }
                let shared = match device_slot.as_ref() {
                    Some(Owned::Device(device)) => Arc::clone(device),
                    Some(_) => return Err(failure(6)),
                    None => return Err(failure(2)),
                };
                shared.transfer_enrolled(deadline, |original| {
                    let store = take_registry(registry_slot)?;
                    device_slot.take();
                    let access = store.access()?;
                    let native = p::ManagedAccountRootReplacement::begin(
                        store,
                        scope.expected,
                        *plan,
                        original,
                        scope.pin.clone(),
                    )?;
                    *registry_slot = Some(Owned::RootReplacement(Box::new(Owner {
                        native,
                        pin: scope.pin,
                        access,
                        report: None,
                    })));
                    Ok(())
                })
            },
        )
    };
    // SAFETY: forwarded invocation-local diagnostic and bounded region contract.
    unsafe { boundary(error, false, action) }
}

/// Resume only original existing storage and approval; convert the registry handle.
/// # Safety
/// The path, original intent, scope, plan and error regions satisfy the C header.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_resume(
    registry: u64,
    path: *const u8,
    path_length: usize,
    intent: *const enrollment::Intent,
    scope: *const Scope,
    approved_plan: *const u8,
    length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        let recovery = unsafe { Recovery::read(path, path_length, intent, scope) }?;
        let plan = unsafe { plan(approved_plan, length) }?;
        recovery.resume(registry, deadline, |store, recovery| {
            Ok(p::ManagedAccountRootReplacement::resume_original(
                store,
                recovery.scope.expected,
                *plan,
                recovery.paths,
                recovery.intent,
                recovery.scope.pin,
            )?)
        })
    };
    // SAFETY: forwarded invocation-local diagnostic and bounded region contract.
    unsafe { boundary(error, false, action) }
}

/// Local preparation/pending/committed/closed state; no traffic permission.
/// # Safety
/// State and error are aligned, writable and nonoverlapping outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_state(
    handle: u64,
    state: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(state)?;
        let value = with_root(handle, deadline, |owner, _| {
            Ok(phase(owner.native.state()?))
        })?;
        unsafe { put(state, value) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Retain a verified freeze before copying the complete bound proposal.
/// # Safety
/// Buffer has at least QPC_ROOT_PROPOSAL_CAPACITY writable bytes. All output and
/// input regions are distinct and live as declared in the header.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_bind_freeze(
    handle: u64,
    receipt: *const u8,
    length: usize,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        unsafe { proposal_output(buffer, capacity, written) }?;
        let receipt = unsafe { bytes(receipt, length, RECEIPT_BYTES) }?;
        let wire = with_root(handle, deadline, |owner, _| {
            Ok(owner.native.bind_witness_freeze(&receipt)?.to_bytes()?)
        })?;
        unsafe { copy_proposal(&wire, buffer, written) }
    };
    unsafe { boundary(error, false, action) }
}

/// Retain actual witness retirement and select the same successor once.
/// # Safety
/// Receipt is an immutable bounded region; checkpoint/error are distinct outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_retain_retirement(
    handle: u64,
    receipt: *const u8,
    length: usize,
    checkpoint: *mut account_authority::Checkpoint,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(checkpoint)?;
        let receipt = unsafe { bytes(receipt, length, RECEIPT_BYTES) }?;
        let value = with_root(handle, deadline, |owner, _| {
            Ok(owner.native.retain_witness_retirement(&receipt)?)
        })?;
        unsafe { put(checkpoint, account_authority::Checkpoint::observed(value)) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Record signed non-commit; this never unfreezes the original account.
/// # Safety
/// Receipt and exclusive outputs satisfy the header's bounded region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_retain_noncommit(
    handle: u64,
    receipt: *const u8,
    length: usize,
    state: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(state)?;
        let receipt = unsafe { bytes(receipt, length, RECEIPT_BYTES) }?;
        let value = with_root(handle, deadline, |owner, _| {
            Ok(phase(owner.native.retain_witness_noncommit(&receipt)?))
        })?;
        unsafe { put(state, value) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Consume the exact target registration into a current managed device handle.
/// # Safety
/// Error is a distinct writable diagnostic output. Both handles must be live,
/// idle and distinct. Admitted failures may consume both owners after commits.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_activate_successor(
    handle: u64,
    enrollment: u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        paired::with(
            handle,
            enrollment,
            deadline,
            |root_slot, root_entry, target_slot, target_entry| {
                match root_slot.as_ref() {
                    Some(Owned::RootReplacement(_)) => {}
                    Some(_) => return Err(failure(6)),
                    None => return Err(failure(2)),
                }
                match target_slot.as_ref() {
                    Some(Owned::Enrollment(_)) => {}
                    Some(_) => return Err(failure(6)),
                    None => return Err(failure(2)),
                }
                let Some(Owned::RootReplacement(mut root)) = root_slot.take() else {
                    return Err(failure(5));
                };
                let Some(Owned::Enrollment(target)) = target_slot.take() else {
                    return Err(failure(5));
                };
                let device =
                    target.activate_root(&mut root.native, &root.pin, target_entry, deadline)?;
                opening::check(&root_entry.cancel, deadline)?;
                opening::check(&target_entry.cancel, deadline)?;
                *root_slot = Some(Owned::RootReplacement(root));
                *target_slot = Some(Owned::Device(device));
                Ok(())
            },
        )
    };
    // SAFETY: forwarded synchronous handle and diagnostic contract.
    unsafe { boundary(error, false, action) }
}

unsafe fn proposal_output(buffer: *mut u8, capacity: usize, written: *mut usize) -> Result<()> {
    output(written)?;
    if buffer.is_null() || capacity < PROPOSAL_BYTES {
        return Err(Failure::argument());
    }
    unsafe { put(written, 0) };
    Ok(())
}
unsafe fn copy_proposal(wire: &[u8], buffer: *mut u8, written: *mut usize) -> Result<()> {
    if wire.len() > PROPOSAL_BYTES {
        return Err(failure(5));
    }
    // SAFETY: the output was validated before mutation and is disjoint from this
    // private bounded vector. No reference to the whole caller capacity is formed.
    unsafe {
        std::ptr::copy_nonoverlapping(wire.as_ptr(), buffer, wire.len());
        put(written, wire.len());
    }
    Ok(())
}
