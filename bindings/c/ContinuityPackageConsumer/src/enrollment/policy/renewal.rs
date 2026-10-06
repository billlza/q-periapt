// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent policy-only lifecycle. Original request bytes survive owner restart.
use super::*;
mod witness;

#[repr(C)]
pub struct PolicyCheckpoint {
    pub version: u64,
    pub digest: [u8; 32],
}
impl PolicyCheckpoint {
    pub(in crate::enrollment) fn observed(value: p::PolicyCheckpoint) -> Self {
        Self {
            version: value.version(),
            digest: value.digest(),
        }
    }
    pub(in crate::enrollment) fn empty() -> Self {
        Self {
            version: 0,
            digest: [0; 32],
        }
    }
    fn native(&self) -> Result<p::PolicyCheckpoint> {
        Ok(p::PolicyCheckpoint::from_trusted_state(
            self.version,
            self.digest,
        )?)
    }
}
#[repr(C)]
pub struct Scope {
    pub operation: [u8; 32],
    pub journal: [u8; 32],
    pub original_owner: [u8; 32],
    pub original_credential: [u8; 32],
    pub current_credential: [u8; 32],
    pub current_roster: Checkpoint,
    pub original_policy: PolicyCheckpoint,
    pub previous_policy: PolicyCheckpoint,
    pub previous_authorization: [u8; 32],
    pub has_previous_authorization: u32,
    pub reserved: u32,
}
impl Scope {
    fn observed(s: &p::PolicyRenewalScope) -> Self {
        Self {
            operation: *s.operation.as_bytes(),
            journal: *s.journal.as_bytes(),
            original_owner: s.original_owner,
            original_credential: s.original_credential,
            current_credential: s.current_credential,
            current_roster: Checkpoint::observed(s.current_roster),
            original_policy: PolicyCheckpoint::observed(s.original_policy),
            previous_policy: PolicyCheckpoint::observed(s.previous_policy),
            previous_authorization: s.previous_authorization.unwrap_or([0; 32]),
            has_previous_authorization: u32::from(s.previous_authorization.is_some()),
            reserved: 0,
        }
    }
    fn native(&self) -> Result<p::PolicyRenewalScope> {
        if self.reserved != 0
            || [
                self.original_owner,
                self.original_credential,
                self.current_credential,
            ]
            .contains(&[0; 32])
        {
            return Err(Failure::argument());
        }
        let previous_authorization =
            match (self.has_previous_authorization, self.previous_authorization) {
                (0, value) if value == [0; 32] => None,
                (1, value) if value != [0; 32] => Some(value),
                _ => return Err(Failure::argument()),
            };
        Ok(p::PolicyRenewalScope {
            operation: p::PolicyRenewalId::from_trusted_state(self.operation)?,
            journal: p::JournalIdentity::from_trusted_state(self.journal)?,
            original_owner: self.original_owner,
            original_credential: self.original_credential,
            current_credential: self.current_credential,
            current_roster: self.current_roster.native()?,
            original_policy: self.original_policy.native()?,
            previous_policy: self.previous_policy.native()?,
            previous_authorization,
        })
    }
}
#[repr(C)]
pub struct PublicRecord {
    pub length: u32,
    pub bytes: [u8; 8192],
}
impl PublicRecord {
    fn observed(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 8192 {
            return Err(failure(5));
        }
        let mut result = Self {
            length: u32::try_from(bytes.len()).map_err(|_| failure(5))?,
            bytes: [0; 8192],
        };
        result
            .bytes
            .get_mut(..bytes.len())
            .ok_or_else(|| failure(5))?
            .copy_from_slice(bytes);
        Ok(result)
    }
    fn copied(&self) -> Result<Vec<u8>> {
        let n = usize::try_from(self.length).map_err(|_| Failure::argument())?;
        if n == 0
            || n > 8192
            || self
                .bytes
                .get(n..)
                .ok_or_else(Failure::argument)?
                .iter()
                .any(|x| *x != 0)
        {
            return Err(Failure::argument());
        }
        Ok(self.bytes.get(..n).ok_or_else(Failure::argument)?.to_vec())
    }
}
#[repr(C)]
pub struct PolicyRequest {
    pub scope: Scope,
    pub account: [u8; 32],
    pub original_roster_checkpoint: Checkpoint,
    pub original_credential: PublicRecord,
    pub original_roster: PublicRecord,
    pub current_credential: PublicRecord,
    pub current_roster: PublicRecord,
}
struct CopiedRequest {
    scope: p::PolicyRenewalScope,
    account: [u8; 32],
    original_roster_checkpoint: p::RosterCheckpoint,
    original_credential: Vec<u8>,
    original_roster: Vec<u8>,
    current_credential: Vec<u8>,
    current_roster: Vec<u8>,
}
impl PolicyRequest {
    // Copy the large ABI value only after all admission and crypto frames have
    // returned. Inlining would reserve this temporary during those operations.
    #[inline(never)]
    unsafe fn publish(self: Box<Self>, output: *mut Self) {
        // SAFETY: the caller has validated its separate writable request output.
        unsafe { put(output, *self) };
    }
    // Keep the 33-KiB public record out of every generic admission/panic frame.
    // The complete record is copied to the caller only after successful admission.
    fn observed(r: &p::PolicyRenewalRequest) -> Result<Box<Self>> {
        Ok(Box::new(Self {
            scope: Scope::observed(r.scope()),
            account: r.original_device().account_id(),
            original_roster_checkpoint: Checkpoint::observed(
                r.original_device().roster().checkpoint(),
            ),
            original_credential: PublicRecord::observed(r.original_credential())?,
            original_roster: PublicRecord::observed(r.original_roster())?,
            current_credential: PublicRecord::observed(r.current_credential())?,
            current_roster: PublicRecord::observed(r.current_roster())?,
        }))
    }
    unsafe fn read(pointer: *const Self) -> Result<CopiedRequest> {
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: caller provides one aligned immutable complete request record.
        let r = unsafe { &*pointer };
        if r.account == [0; 32] {
            return Err(Failure::argument());
        }
        Ok(CopiedRequest {
            scope: r.scope.native()?,
            account: r.account,
            original_roster_checkpoint: r.original_roster_checkpoint.native()?,
            original_credential: r.original_credential.copied()?,
            original_roster: r.original_roster.copied()?,
            current_credential: r.current_credential.copied()?,
            current_roster: r.current_roster.copied()?,
        })
    }
}
#[repr(C)]
pub struct PolicyStatus {
    pub phase: u32,
    pub reason: u32,
    pub operation: [u8; 32],
    pub statement: [u8; 32],
    pub target: PolicyCheckpoint,
    pub observed_roster: Checkpoint,
    pub observed_at: u64,
}
impl PolicyStatus {
    fn observed(value: p::PolicyRenewalStatus) -> Self {
        let mut result = Self {
            phase: 0,
            reason: 0,
            operation: [0; 32],
            statement: [0; 32],
            target: PolicyCheckpoint::empty(),
            observed_roster: Checkpoint::empty(),
            observed_at: 0,
        };
        match value {
            p::PolicyRenewalStatus::Absent => {}
            p::PolicyRenewalStatus::Pending {
                operation,
                statement,
                target,
            }
            | p::PolicyRenewalStatus::Committed {
                operation,
                statement,
                target,
            } => {
                result.phase = if matches!(value, p::PolicyRenewalStatus::Pending { .. }) {
                    1
                } else {
                    2
                };
                result.operation = *operation.as_bytes();
                result.statement = statement;
                result.target = PolicyCheckpoint::observed(target);
            }
            p::PolicyRenewalStatus::AbandonedUncommitted {
                operation,
                statement,
                target,
                reason,
                observed_roster,
                observed_at,
            } => {
                result.phase = 3;
                result.operation = *operation.as_bytes();
                result.statement = statement;
                result.target = PolicyCheckpoint::observed(target);
                result.reason = match reason {
                    p::PolicyRenewalAbandonment::Expired => 1,
                    p::PolicyRenewalAbandonment::RosterAdvanced => 2,
                };
                result.observed_roster = Checkpoint::observed(observed_roster);
                result.observed_at = observed_at;
            }
        };
        result
    }
}

/// Read an original operation's exact public issuer request without reservation.
/// # Safety
/// Operation contains32 readable bytes. Request/error are disjoint aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_policy_renewal_request(
    handle: u64,
    operation: *const u8,
    request: *mut PolicyRequest,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(request)?;
        // SAFETY: copied before owner admission.
        let operation = p::PolicyRenewalId::from_trusted_state(unsafe { fixed(operation)? })?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            PolicyRequest::observed(
                &owner
                    .enrollment
                    .policy_renewal_request(operation, &original)?,
            )
        })?;
        // SAFETY: publish only after native readback and invocation checks.
        unsafe { result.publish(request) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
/// Inspect the independent policy axis; this is never current Device permission.
/// # Safety
/// Status/error are disjoint aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_policy_renewal_status(
    handle: u64,
    status: *mut PolicyStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        let result = with_owner(handle, deadline, |owner, _| {
            Ok(PolicyStatus::observed(
                owner.enrollment.policy_renewal_status()?,
            ))
        })?;
        // SAFETY: validated success output.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
/// Reverify retained request materials and stage exact two-root approvals. This
/// accepts the original request again after Pending or a lost commit response;
/// it never generates a new request to bypass the pending operation.
/// # Safety
/// Request, pins, document and approval bytes are immutable readable inputs;
/// status/error are separate aligned writable records, disjoint from every input.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_stage_policy_renewal(
    handle: u64,
    request: *const PolicyRequest,
    original_pin: *const Pin,
    current_pin: *const Pin,
    approvals: *const u8,
    approvals_length: usize,
    previous: *const Document,
    status: *mut PolicyStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        if approvals_length != p::MAX_POLICY_RENEWAL_BYTES {
            return Err(Failure::argument());
        }
        // SAFETY: bounded independent input copies precede owner admission.
        let (r, original_pin, current_pin, approvals, previous) = unsafe {
            (
                PolicyRequest::read(request)?,
                Pin::read(original_pin)?,
                Pin::read(current_pin)?,
                bytes(approvals, approvals_length, p::MAX_POLICY_RENEWAL_BYTES)?,
                Document::read(previous)?,
            )
        };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let target = owner.current_target()?;
            let previous = previous.pin.verify_historical(&previous.wire)?;
            let original_device = original_pin
                .verify_historical_device(&r.original_credential, &r.original_roster)?;
            let current_device =
                current_pin.verify_historical_device(&r.current_credential, &r.current_roster)?;
            if original_device.account_id() != r.account
                || original_device.roster().checkpoint() != r.original_roster_checkpoint
            {
                return Err(p::DurableError::Conflict.into());
            }
            let now = owner::now().map_err(Failure::configuration)?;
            let verified = p::VerifiedPolicyRenewal::from_bytes(
                &approvals,
                &r.scope,
                &p::PolicyRenewalMaterials {
                    original: &original,
                    previous: &previous,
                    target: &target,
                    original_device: &original_device,
                    current_device: &current_device,
                },
                now,
            )?;
            opening::check(&entry.cancel, deadline)?;
            Ok(PolicyStatus::observed(
                owner.enrollment.stage_policy_renewal(
                    &verified,
                    r.scope.operation,
                    &original,
                    &target,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: validated result published only after all native and invocation checks.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
/// Recover the exact retained first approval bytes of an original Pending.
/// # Safety
/// Operation contains32 readable bytes. Record/error are separate aligned outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_pending_policy_renewal_approval(
    handle: u64,
    operation: *const u8,
    record: *mut PublicRecord,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(record)?;
        // SAFETY: exact operation copied before admission.
        let operation = p::PolicyRenewalId::from_trusted_state(unsafe { fixed(operation)? })?;
        let result = with_owner(handle, deadline, |owner, _| {
            PublicRecord::observed(
                &owner
                    .enrollment
                    .pending_policy_renewal_approval(operation)?,
            )
        })?;
        // SAFETY: validated success output.
        unsafe { put(record, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
/// Coordinate an exact Pending with its journal under selected current target.
/// # Safety
/// Status/error are disjoint aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_reconcile_policy_renewal(
    handle: u64,
    status: *mut PolicyStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let target = owner.current_target()?;
            Ok(PolicyStatus::observed(
                owner.enrollment.reconcile_policy_renewal(
                    &original,
                    &target,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: validated success output.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
/// Resolve one original outcome from signed history, without runtime/TLS/Device.
/// # Safety
/// Operation/statement contain32 readable bytes; document/buffers are immutable;
/// status/error are separate aligned outputs disjoint from inputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_resolve_policy_renewal(
    handle: u64,
    operation: *const u8,
    statement: *const u8,
    target: *const Document,
    status: *mut PolicyStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        // SAFETY: bounded original expectations copied before admission.
        let (operation, statement, target) = unsafe {
            (
                p::PolicyRenewalId::from_trusted_state(fixed(operation)?)?,
                fixed(statement)?,
                Document::read(target)?,
            )
        };
        if statement == [0; 32] {
            return Err(Failure::argument());
        }
        let target = target.pin.verify_historical(&target.wire)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            Ok(PolicyStatus::observed(
                owner.enrollment.resolve_policy_renewal(
                    operation,
                    statement,
                    &original,
                    &target,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: publish only native historical fact after invocation checks.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
/// Transfer the same original enrollment into the selected independent-policy Device.
/// # Safety
/// Error is an aligned writable invocation-local record.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_activate_policy_renewal(
    handle: u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        with_entry(handle, deadline, |slot, entry| {
            let owner = take_owner(slot, entry, deadline)?;
            let device =
                owner.activate_continued(entry, deadline, ContinuationKind::Independent)?;
            opening::check(&entry.cancel, deadline)?;
            *slot = Some(Owned::Device(device));
            Ok(())
        })
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
