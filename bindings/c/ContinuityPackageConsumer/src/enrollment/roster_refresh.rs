// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same-original atomic R coordination; C outputs remain historical metadata.
use super::policy::renewal::PolicyCheckpoint;
use super::*;

#[repr(C)]
pub struct Proposal {
    pub bytes: [u8; 417],
}
impl Proposal {
    fn observed(value: p::AnchorRosterRefreshProposal) -> Result<Self> {
        Ok(Self {
            bytes: value.to_bytes().try_into().map_err(|_| failure(5))?,
        })
    }
    unsafe fn read(pointer: *const Self) -> Result<p::AnchorRosterRefreshProposal> {
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: caller supplies one complete immutable descriptor.
        let bytes = unsafe { (*pointer).bytes };
        Ok(p::AnchorRosterRefreshProposal::from_trusted_state(&bytes)?)
    }
}
#[repr(C)]
pub struct Scope {
    pub operation: [u8; 32],
    pub previous: Checkpoint,
    pub target: Checkpoint,
    pub policy: PolicyCheckpoint,
    pub policy_authorization: [u8; 32],
    pub has_policy_authorization: u32,
    pub reserved: u32,
}
impl Scope {
    fn empty() -> Self {
        Self {
            operation: [0; 32],
            previous: Checkpoint::empty(),
            target: Checkpoint::empty(),
            policy: PolicyCheckpoint::empty(),
            policy_authorization: [0; 32],
            has_policy_authorization: 0,
            reserved: 0,
        }
    }
    fn observed(value: &p::RosterRefreshScope) -> Self {
        Self {
            operation: *value.operation.as_bytes(),
            previous: Checkpoint::observed(value.previous),
            target: Checkpoint::observed(value.target),
            policy: PolicyCheckpoint::observed(value.policy),
            policy_authorization: value.policy_authorization.unwrap_or([0; 32]),
            has_policy_authorization: u32::from(value.policy_authorization.is_some()),
            reserved: 0,
        }
    }
}
#[repr(C)]
pub struct Preparation {
    pub present: u32,
    pub proposal: Proposal,
    pub reserved: [u8; 3],
}
#[repr(C)]
pub struct Progress {
    pub phase: u32,
    pub retired: u32,
    pub scope: Scope,
    pub proposal: Proposal,
    pub reserved: [u8; 7],
}
impl Progress {
    fn observed(value: Option<p::WitnessedRosterRefreshProgress>) -> Result<Self> {
        let mut result = Self {
            phase: 0,
            retired: 0,
            scope: Scope::empty(),
            proposal: Proposal { bytes: [0; 417] },
            reserved: [0; 7],
        };
        match value {
            None => {}
            Some(p::WitnessedRosterRefreshProgress::Staged(scope)) => {
                result.phase = 1;
                result.scope = Scope::observed(&scope);
            }
            Some(p::WitnessedRosterRefreshProgress::AbandonedBeforePreparation(scope)) => {
                result.phase = 5;
                result.scope = Scope::observed(&scope);
            }
            Some(p::WitnessedRosterRefreshProgress::Reserved(proposal)) => {
                result.phase = 2;
                result.scope = Scope::observed(proposal.scope());
                result.proposal = Proposal::observed(proposal)?;
            }
            Some(p::WitnessedRosterRefreshProgress::Terminal {
                proposal,
                disposition,
                retired,
            }) => {
                result.phase = match disposition {
                    p::WitnessedRosterRefreshDisposition::Applied => 3,
                    p::WitnessedRosterRefreshDisposition::Closed => 4,
                };
                result.retired = u32::from(retired);
                result.scope = Scope::observed(proposal.scope());
                result.proposal = Proposal::observed(proposal)?;
            }
        }
        Ok(result)
    }
}
#[repr(C)]
pub struct Target {
    pub certificate: *const u8,
    pub certificate_length: usize,
    pub roster: *const u8,
    pub roster_length: usize,
    pub pin: *const Pin,
}
struct CopiedTarget {
    certificate: Vec<u8>,
    roster: Vec<u8>,
    pin: p::AccountPin,
}
impl Target {
    unsafe fn read(pointer: *const Self) -> Result<CopiedTarget> {
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: caller supplies aligned immutable descriptor and public buffers.
        let t = unsafe { &*pointer };
        if t.certificate_length == 0 || t.roster_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: bounded copies precede owner admission and any I/O.
        let (certificate, roster, pin) = unsafe {
            (
                bytes(t.certificate, t.certificate_length, 8192)?,
                bytes(t.roster, t.roster_length, 8192)?,
                Pin::read(t.pin)?,
            )
        };
        Ok(CopiedTarget {
            certificate,
            roster,
            pin,
        })
    }
}
#[derive(Clone, Copy)]
enum PolicySource {
    Original,
    Selected,
}
impl PolicySource {
    fn read(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Original),
            1 => Ok(Self::Selected),
            _ => Err(Failure::argument()),
        }
    }
}
impl Owner {
    fn roster_policy(
        &mut self,
        source: PolicySource,
        entry: &Entry,
        deadline: Instant,
    ) -> Result<Arc<p::VerifiedSessionPolicy>> {
        match source {
            PolicySource::Original => {
                self.ensure_policy(&entry.cancel, deadline)?;
                Ok(Arc::clone(
                    &self.authority.as_ref().ok_or_else(|| failure(5))?.policy,
                ))
            }
            PolicySource::Selected => self.current_target(),
        }
    }
}
/// Prepare one original same-credential R using explicit current policy selection.
/// This retains exact intent/proposal, but does not independently prepare the witness.
/// # Safety
/// Operation has32 readable bytes; target and public inputs are immutable;
/// proposal/error are separate aligned outputs disjoint from every input.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_prepare_witnessed_roster_refresh(
    handle: u64,
    operation: *const u8,
    policy_source: u32,
    target: *const Target,
    proposal: *mut Proposal,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(proposal)?;
        let source = PolicySource::read(policy_source)?;
        // SAFETY: bounded independently pinned inputs copied before owner admission.
        let (operation, target) = unsafe {
            (
                p::RosterRefreshId::from_trusted_state(fixed(operation)?)?,
                Target::read(target)?,
            )
        };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let policy = owner.roster_policy(source, entry, deadline)?;
            let now = owner::now().map_err(Failure::configuration)?;
            let target = target
                .pin
                .verify_device(&target.certificate, &target.roster, now)?;
            let client = owner.policy_client(&original, entry)?;
            Proposal::observed(owner.enrollment.prepare_witnessed_roster_refresh(
                operation, &original, &policy, &target, now, client,
            )?)
        })?;
        // SAFETY: publish the exact original proposal only after final invocation checks.
        unsafe { put(proposal, result) };
        Ok(())
    };
    // SAFETY: forwarded per-invocation diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Inspect original R preparation without current runtime, signing or network.
/// present=0 is local absence only; it is never witness Closed/no-commit.
/// # Safety
/// Preparation/error are separate aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_recover_witnessed_roster_refresh_preparation(
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
                .recover_witnessed_roster_refresh_preparation(&original)?;
            Ok(Preparation {
                present: u32::from(saved.is_some()),
                proposal: match saved {
                    Some(p) => Proposal::observed(p)?,
                    None => Proposal { bytes: [0; 417] },
                },
                reserved: [0; 3],
            })
        })?;
        // SAFETY: output includes canonical absent bytes and explicit zero padding.
        unsafe { put(preparation, result) };
        Ok(())
    };
    // SAFETY: forwarded per-invocation diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Observe original R coordination without current runtime or private signer.
/// # Safety
/// Progress/error are separate aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_witnessed_roster_refresh_progress(
    handle: u64,
    progress: *mut Progress,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(progress)?;
        let result = with_owner(handle, deadline, |owner, _| {
            Progress::observed(owner.enrollment.witnessed_roster_refresh_progress()?)
        })?;
        // SAFETY: no historical result is published after a failed invocation.
        unsafe { put(progress, result) };
        Ok(())
    };
    // SAFETY: forwarded per-invocation diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Abandon only an original staged intent with no released proposal and no local
/// pending under its service lease. This is not a witness terminal or ACK authority.
/// # Safety
/// Operation has32 readable bytes; progress/error are separate aligned outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_abandon_unprepared_roster_refresh(
    handle: u64,
    operation: *const u8,
    progress: *mut Progress,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(progress)?;
        // SAFETY: original immutable operation copied before admission.
        let operation = p::RosterRefreshId::from_trusted_state(unsafe { fixed(operation)? })?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            Progress::observed(Some(
                owner
                    .enrollment
                    .abandon_unprepared_roster_refresh(operation, &original)?,
            ))
        })?;
        // SAFETY: only an authenticated read-back local result is published.
        unsafe { put(progress, result) };
        Ok(())
    };
    // SAFETY: forwarded per-invocation diagnostics contract.
    unsafe { boundary(error, false, action) }
}
#[derive(Clone, Copy)]
enum Action {
    Status,
    Close,
}
fn state(value: p::AnchorRosterRefreshState) -> u32 {
    match value {
        p::AnchorRosterRefreshState::Prepared => 1,
        p::AnchorRosterRefreshState::Applied => 2,
        p::AnchorRosterRefreshState::Closed => 3,
        p::AnchorRosterRefreshState::Acknowledged => 4,
        p::AnchorRosterRefreshState::Unavailable => 5,
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
        // SAFETY: entire immutable expected proposal copied before original owner admission.
        let proposal = unsafe { Proposal::read(proposal)? };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let mut client = owner.policy_client(&original, entry)?;
            let value = match kind {
                Action::Status => owner.enrollment.reconcile_witnessed_roster_refresh(
                    &proposal,
                    &original,
                    &mut client,
                )?,
                Action::Close => owner.enrollment.close_witnessed_roster_refresh(
                    &proposal,
                    &original,
                    &mut client,
                )?,
            };
            Ok(state(value))
        })?;
        // SAFETY: failure/late success cannot write a synthesized result.
        unsafe { put(observed, result) };
        Ok(())
    };
    // SAFETY: forwarded per-invocation diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Commit only the exact independently prepared R under explicit current P.
/// # Safety
/// Proposal is immutable; observed/error are separate aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_commit_witnessed_roster_refresh(
    handle: u64,
    proposal: *const Proposal,
    policy_source: u32,
    observed: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    // Validate source inside the normal boundary, preserving the original deadline
    // and avoiding a second invocation admission around the shared run helper.
    let action = |deadline| {
        output(observed)?;
        let source = PolicySource::read(policy_source)?;
        // SAFETY: complete proposal copied before admission.
        let proposal = unsafe { Proposal::read(proposal)? };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let policy = owner.roster_policy(source, entry, deadline)?;
            let mut client = owner.policy_client(&original, entry)?;
            Ok(state(owner.enrollment.commit_witnessed_roster_refresh(
                &proposal,
                &original,
                &policy,
                owner::now().map_err(Failure::configuration)?,
                &mut client,
            )?))
        })?;
        // SAFETY: complete success output after invocation checks only.
        unsafe { put(observed, result) };
        Ok(())
    };
    // SAFETY: forwarded per-invocation diagnostics contract.
    unsafe { boundary(error, false, action) }
}
/// Reconcile the exact original R, preserving durable terminal before ACK/cleanup.
/// # Safety
/// Proposal is immutable; observed/error are separate aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_reconcile_witnessed_roster_refresh(
    handle: u64,
    proposal: *const Proposal,
    observed: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded complete proposal/output contract.
    unsafe { run(handle, proposal, observed, error, Action::Status) }
}
/// Close only the exact original R. An already Applied target stays Applied.
/// # Safety
/// Proposal is immutable; observed/error are separate aligned writable outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_close_witnessed_roster_refresh(
    handle: u64,
    proposal: *const Proposal,
    observed: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded complete proposal/output contract.
    unsafe { run(handle, proposal, observed, error, Action::Close) }
}
