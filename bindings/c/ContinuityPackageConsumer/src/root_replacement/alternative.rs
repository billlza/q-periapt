// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently approved alternatives use the native transition/adoption proofs.
use super::*;

/// Exact retained original plan, separately approved next plan or committed
/// proposal, and signed original non-commit plus next freeze or retirement.
#[repr(C)]
pub struct Alternative {
    pub struct_size: u32,
    pub original: *const u8,
    pub original_length: usize,
    pub approved: *const u8,
    pub approved_length: usize,
    pub noncommit: *const u8,
    pub noncommit_length: usize,
    pub receipt: *const u8,
    pub receipt_length: usize,
}
struct Evidence {
    original: Box<p::AnchorAccountReplacementPlan>,
    approved: Vec<u8>,
    noncommit: Vec<u8>,
    receipt: Vec<u8>,
}
impl Evidence {
    unsafe fn read(pointer: *const Alternative) -> Result<Self> {
        unsafe { account_authority::check_options(pointer) }?;
        let value = unsafe { &*pointer };
        Ok(Self {
            original: unsafe { plan(value.original, value.original_length) }?,
            approved: unsafe { bytes(value.approved, value.approved_length, PLAN_BYTES) }?,
            noncommit: unsafe { bytes(value.noncommit, value.noncommit_length, RECEIPT_BYTES) }?,
            receipt: unsafe { bytes(value.receipt, value.receipt_length, RECEIPT_BYTES) }?,
        })
    }
    // Construct large verified public approvals in this short-lived frame.
    // Deep recovery/signature verification retains only a Box, not another
    // full approval on the foreign worker stack.
    fn transition(&self, pin: &p::AnchorPin) -> Result<Box<p::ManagedAccountRootTransition>> {
        Ok(Box::new(p::ManagedAccountRootTransition::verify(
            pin,
            &self.original,
            p::AnchorAccountReplacementPlan::from_trusted_state(&self.approved)?,
            &self.noncommit,
            &self.receipt,
        )?))
    }
    fn adoption(&self, pin: &p::AnchorPin) -> Result<Box<p::ManagedAccountRootAdoption>> {
        Ok(Box::new(p::ManagedAccountRootAdoption::verify(
            pin,
            &self.original,
            p::AnchorAccountReplacementProposal::from_trusted_state(&self.approved)?,
            &self.noncommit,
            &self.receipt,
        )?))
    }
}

/// Retain signed non-commit and the separately approved next plan and freeze.
/// # Safety
/// Options and their bounded inputs, the full proposal buffer, written and error
/// follow the header's lifetime, alignment and nonoverlap contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_transition(
    handle: u64,
    options: *const Alternative,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        unsafe { proposal_output(buffer, capacity, written) }?;
        let evidence = unsafe { Evidence::read(options) }?;
        let wire = with_root(handle, deadline, |owner, _| {
            let transition = evidence.transition(&owner.pin)?;
            Ok(owner
                .native
                .transition_after_noncommit(&transition)?
                .to_bytes()?)
        })?;
        unsafe { copy_proposal(&wire, buffer, written) }
    };
    unsafe { boundary(error, false, action) }
}

/// Adopt an independently approved committed proposal, never an inferred winner.
/// # Safety
/// Options and referenced inputs remain live; checkpoint/error are distinct outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_adopt(
    handle: u64,
    options: *const Alternative,
    checkpoint: *mut account_authority::Checkpoint,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(checkpoint)?;
        let evidence = unsafe { Evidence::read(options) }?;
        let value = with_root(handle, deadline, |owner, _| {
            let adoption = evidence.adoption(&owner.pin)?;
            Ok(owner.native.adopt_committed_winner(&adoption)?)
        })?;
        unsafe { put(checkpoint, account_authority::Checkpoint::observed(value)) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Resume this exact approved transition from the existing original storage.
/// # Safety
/// All input objects and pointed-to byte ranges and error obey the C header.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_resume_transition(
    registry: u64,
    path: *const u8,
    path_length: usize,
    intent: *const enrollment::Intent,
    scope: *const Scope,
    options: *const Alternative,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        let recovery = unsafe { Recovery::read(path, path_length, intent, scope) }?;
        let transition = unsafe { Evidence::read(options) }?.transition(&recovery.scope.pin)?;
        recovery.resume(registry, deadline, |store, recovery| {
            Ok(p::ManagedAccountRootReplacement::resume_transition(
                store,
                recovery.scope.expected,
                recovery.paths,
                recovery.intent,
                recovery.scope.pin,
                &transition,
            )?)
        })
    };
    unsafe { boundary(error, false, action) }
}

/// Resume this exact approved winner without manufacturing a replacement plan.
/// # Safety
/// Original path, intent, scope, evidence and error obey the C header.
#[no_mangle]
pub unsafe extern "C" fn qpc_root_v1_resume_adoption(
    registry: u64,
    path: *const u8,
    path_length: usize,
    intent: *const enrollment::Intent,
    scope: *const Scope,
    options: *const Alternative,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        let recovery = unsafe { Recovery::read(path, path_length, intent, scope) }?;
        let adoption = unsafe { Evidence::read(options) }?.adoption(&recovery.scope.pin)?;
        recovery.resume(registry, deadline, |store, recovery| {
            Ok(p::ManagedAccountRootReplacement::resume_adoption(
                store,
                recovery.scope.expected,
                recovery.paths,
                recovery.intent,
                recovery.scope.pin,
                &adoption,
            )?)
        })
    };
    unsafe { boundary(error, false, action) }
}
