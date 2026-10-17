// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently typed P coordination through the original retained enrollment.
use super::*;

#[repr(C)]
pub struct Proposal {
    pub bytes: [u8; 296],
}
impl Proposal {
    fn observed(proposal: p::AnchorPolicyRenewalProposal) -> Result<Self> {
        Ok(Self {
            bytes: proposal.to_bytes().try_into().map_err(|_| failure(5))?,
        })
    }
    unsafe fn read(pointer: *const Self) -> Result<p::AnchorPolicyRenewalProposal> {
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: caller provides one immutable aligned complete descriptor.
        let bytes = unsafe { (*pointer).bytes };
        Ok(p::AnchorPolicyRenewalProposal::from_trusted_state(&bytes)?)
    }
}
#[repr(C)]
pub struct Preparation {
    pub present: u32,
    pub reserved: u32,
    pub proposal: Proposal,
}
#[repr(C)]
pub struct Progress {
    pub phase: u32,
    pub retired: u32,
    pub proposal: Proposal,
    pub target: PolicyCheckpoint,
}
impl Progress {
    fn observed(value: Option<p::WitnessedPolicyRenewalProgress>) -> Result<Self> {
        let mut result = Self {
            phase: 0,
            retired: 0,
            proposal: Proposal { bytes: [0; 296] },
            target: PolicyCheckpoint::empty(),
        };
        match value {
            None => {}
            Some(p::WitnessedPolicyRenewalProgress::Reserved { proposal, target }) => {
                result.phase = 1;
                result.proposal = Proposal::observed(proposal)?;
                result.target = PolicyCheckpoint::observed(target);
            }
            Some(p::WitnessedPolicyRenewalProgress::Terminal {
                proposal,
                target,
                disposition,
                retired,
            }) => {
                result.phase = match disposition {
                    p::WitnessedPolicyRenewalDisposition::Applied => 2,
                    p::WitnessedPolicyRenewalDisposition::Closed => 3,
                };
                result.retired = u32::from(retired);
                result.proposal = Proposal::observed(proposal)?;
                result.target = PolicyCheckpoint::observed(target);
            }
        }
        Ok(result)
    }
}
impl Owner {
    pub(in crate::enrollment) fn policy_client(
        &mut self,
        original: &p::HistoricalSessionPolicy,
        entry: &Entry,
    ) -> Result<p::AnchorClient> {
        let configured = self
            .witness
            .as_ref()
            .ok_or(p::DurableError::AnchorRequired)?;
        let parameters =
            configured.parameters(&self.path, entry.cancel.clone(), entry.invocation.clone())?;
        Ok(self.enrollment.policy_renewal_anchor_client(
            original,
            parameters.pin,
            parameters.transport,
            parameters.timeout,
        )?)
    }
    fn check_policy_proposal(
        &mut self,
        original: &p::HistoricalSessionPolicy,
        expected: &p::AnchorPolicyRenewalProposal,
    ) -> Result<()> {
        let saved = match self.enrollment.witnessed_policy_renewal_progress()? {
            Some(p::WitnessedPolicyRenewalProgress::Reserved { proposal, .. })
            | Some(p::WitnessedPolicyRenewalProgress::Terminal { proposal, .. }) => proposal,
            None => self
                .enrollment
                .recover_witnessed_policy_renewal_preparation(original)?
                .ok_or(p::DurableError::Suspended)?,
        };
        if saved != *expected {
            return Err(p::DurableError::Conflict.into());
        }
        Ok(())
    }
}
/// Export the original required journal's current independent-P issuer request.
/// # Safety
/// Operation has32 readable bytes; request/error are separate aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_witnessed_policy_renewal_request(
    handle: u64,
    operation: *const u8,
    request: *mut PolicyRequest,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(request)?;
        // SAFETY: bounded immutable identity copied before original owner admission.
        let operation = p::PolicyRenewalId::from_trusted_state(unsafe { fixed(operation)? })?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let client = owner.policy_client(&original, entry)?;
            PolicyRequest::observed(
                &owner
                    .enrollment
                    .witnessed_policy_renewal_request(operation, &original, client)?,
            )
        })?;
        // SAFETY: publish only successful readback after final invocation checks.
        unsafe { result.publish(request) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Prepare one exact staged P target; witness preparation remains an independent decision.
/// # Safety
/// Previous document/buffers are immutable; proposal/error are disjoint aligned outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_prepare_witnessed_policy_renewal(
    handle: u64,
    previous: *const Document,
    proposal: *mut Proposal,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(proposal)?;
        // SAFETY: bounded document and buffers copied before owner/I/O admission.
        let previous = unsafe { Document::read(previous)? };
        let previous = previous.pin.verify_historical(&previous.wire)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let target = owner.current_target()?;
            let client = owner.policy_client(&original, entry)?;
            Proposal::observed(owner.enrollment.prepare_witnessed_policy_renewal(
                &original,
                &previous,
                &target,
                owner::now().map_err(Failure::configuration)?,
                client,
            )?)
        })?;
        // SAFETY: exact original descriptor is published only on success.
        unsafe { put(proposal, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Recover the original local descriptor without runtime, witness dispatch or resealing.
/// present=0 means local absence only, never a witness outcome.
/// # Safety
/// Preparation/error are disjoint aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_recover_witnessed_policy_renewal_preparation(
    handle: u64,
    preparation: *mut Preparation,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(preparation)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let saved = owner
                .enrollment
                .recover_witnessed_policy_renewal_preparation(&original)?;
            Ok(Preparation {
                present: u32::from(saved.is_some()),
                reserved: 0,
                proposal: match saved {
                    Some(p) => Proposal::observed(p)?,
                    None => Proposal { bytes: [0; 296] },
                },
            })
        })?;
        // SAFETY: canonical complete output on success only.
        unsafe { put(preparation, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Observe original durable P coordination, without live runtime or signer authority.
/// # Safety
/// Progress/error are disjoint aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_witnessed_policy_renewal_progress(
    handle: u64,
    progress: *mut Progress,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(progress)?;
        let result = with_owner(handle, deadline, |owner, _| {
            Progress::observed(owner.enrollment.witnessed_policy_renewal_progress()?)
        })?;
        // SAFETY: output is not exposed on any failed invocation.
        unsafe { put(progress, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}
#[derive(Clone, Copy)]
enum Action {
    Commit,
    Status,
    Close,
}
fn state(value: p::AnchorPolicyRenewalState) -> u32 {
    match value {
        p::AnchorPolicyRenewalState::Prepared => 1,
        p::AnchorPolicyRenewalState::Applied => 2,
        p::AnchorPolicyRenewalState::Closed => 3,
        p::AnchorPolicyRenewalState::Acknowledged => 4,
        p::AnchorPolicyRenewalState::Unavailable => 5,
    }
}
unsafe fn run(
    handle: u64,
    proposal: *const Proposal,
    observed: *mut u32,
    error: *mut ErrorRecord,
    kind: Action,
) -> i32 {
    let action = |deadline| {
        output(observed)?;
        // SAFETY: original complete immutable proposal copied before owner admission.
        let expected = unsafe { Proposal::read(proposal)? };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            // Native historical status uses operation/statement. The C contract
            // additionally pins the caller's complete expected descriptor first.
            owner.check_policy_proposal(&original, &expected)?;
            let mut client = owner.policy_client(&original, entry)?;
            let observed = match kind {
                Action::Commit => {
                    let target = owner.current_target()?;
                    owner.enrollment.commit_witnessed_policy_renewal(
                        &expected,
                        &original,
                        &target,
                        owner::now().map_err(Failure::configuration)?,
                        &mut client,
                    )?
                }
                Action::Status => owner.enrollment.reconcile_witnessed_policy_renewal(
                    expected.operation(),
                    expected.statement(),
                    &original,
                    &mut client,
                )?,
                Action::Close => owner.enrollment.close_witnessed_policy_renewal(
                    expected.operation(),
                    expected.statement(),
                    &original,
                    &mut client,
                )?,
            };
            Ok(state(observed))
        })?;
        // SAFETY: no output is synthesized from a failed or late invocation.
        unsafe { put(observed, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Commit the independently prepared exact P while current target authority is live.
/// # Safety
/// Proposal is immutable; observed/error are disjoint aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_commit_witnessed_policy_renewal(
    handle: u64,
    proposal: *const Proposal,
    observed: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded complete proposal/output contract.
    unsafe { run(handle, proposal, observed, error, Action::Commit) }
}
/// Historical exact reconciliation persists the original terminal before ACK/cleanup.
/// # Safety
/// Proposal is immutable; observed/error are disjoint aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_reconcile_witnessed_policy_renewal(
    handle: u64,
    proposal: *const Proposal,
    observed: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded complete proposal/output contract.
    unsafe { run(handle, proposal, observed, error, Action::Status) }
}
/// Close this exact P; a previously Applied target remains Applied.
/// # Safety
/// Proposal is immutable; observed/error are disjoint aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_close_witnessed_policy_renewal(
    handle: u64,
    proposal: *const Proposal,
    observed: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded complete proposal/output contract.
    unsafe { run(handle, proposal, observed, error, Action::Close) }
}
