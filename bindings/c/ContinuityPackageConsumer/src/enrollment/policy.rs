// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit pinned policy inputs and the existing enrolled G/T transaction.
use super::*;
pub(crate) mod renewal;

#[derive(Clone, Copy)]
enum ContinuationKind {
    Joint,
    Independent,
}

#[repr(C)]
pub struct Document {
    pub root: *const u8,
    pub root_length: usize,
    pub family: [u8; 32],
    pub version: u64,
    pub digest: [u8; 32],
    pub wire: *const u8,
    pub wire_length: usize,
}
struct CopiedDocument {
    pin: p::PolicyPin,
    wire: Vec<u8>,
}
impl Document {
    unsafe fn read(pointer: *const Self) -> Result<CopiedDocument> {
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: caller provides one aligned live immutable document and its buffers.
        let document = unsafe { &*pointer };
        if document.wire_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: bounded public inputs are copied before owner admission or I/O.
        let (root, wire) = unsafe {
            (
                bytes(document.root, document.root_length, p::PUBLIC_KEY_BYTES)?,
                bytes(document.wire, document.wire_length, 8192)?,
            )
        };
        Ok(CopiedDocument {
            pin: p::PolicyPin::new(
                document.family,
                p::PublicKey::decode(&root)?,
                p::PolicyCheckpoint::from_trusted_state(document.version, document.digest)?,
            )?,
            wire,
        })
    }
}

#[repr(C)]
pub struct ProposalBytes {
    pub length: u32,
    pub bytes: [u8; 329],
}
impl ProposalBytes {
    fn observed(proposal: p::AnchorCredentialRenewalProposal) -> Result<Self> {
        let wire = proposal.to_bytes();
        let mut result = Self {
            length: u32::try_from(wire.len()).map_err(|_| failure(5))?,
            bytes: [0; 329],
        };
        result
            .bytes
            .get_mut(..wire.len())
            .ok_or_else(|| failure(5))?
            .copy_from_slice(&wire);
        Ok(result)
    }
}
#[repr(C)]
pub struct CancellationBytes {
    pub length: u32,
    pub bytes: [u8; 281],
}
impl Owner {
    pub(crate) fn select_supplied_policy(
        &mut self,
        mut source: crate::first_install::SuppliedPolicy,
        source_cancel: &Cancellation,
        entry: &Entry,
        deadline: Instant,
    ) -> Result<()> {
        if self.target_authority.is_some() {
            return Err(p::DurableError::Conflict.into());
        }
        let original = self.historical_policy(entry, deadline)?;
        let target = source.historical()?;
        if target.family() != self.family || target.checkpoint() == original.checkpoint() {
            return Err(p::Error::Scope.into());
        }
        opening::check(source_cancel, deadline)?;
        let authority =
            device::PolicyAuthority::from_supplied(&mut source, &entry.cancel, deadline)?;
        opening::check(source_cancel, deadline)?;
        self.target_authority = Some(authority);
        Ok(())
    }

    pub(in crate::enrollment) fn current_target(&self) -> Result<Arc<p::VerifiedSessionPolicy>> {
        self.target_authority.as_ref().map(|a| Arc::clone(&a.policy)).ok_or_else(|| Failure {
            code: 1, message: "select an independently pinned current continuation policy for this enrollment owner".into(),
        })
    }
    fn activate_continued(
        self: Box<Self>,
        entry: &Entry,
        deadline: Instant,
        kind: ContinuationKind,
    ) -> Result<Arc<device::Shared>> {
        self.prepare_continued(entry, deadline, kind)?
            .activate(entry, deadline)
    }

    // Finish configuration/signing-client preparation before reopening the
    // durable journal and checking its retained signatures on the caller stack.
    #[inline(never)]
    fn prepare_continued(
        mut self: Box<Self>,
        entry: &Entry,
        deadline: Instant,
        kind: ContinuationKind,
    ) -> Result<Box<ContinuedActivation>> {
        let original = self.historical_policy(entry, deadline)?;
        self.current_target()?;
        let authority = self.target_authority.take().ok_or_else(|| failure(5))?;
        let mut environment =
            device::Environment::from_policy(&self.path, authority, &entry.cancel, deadline)?;
        environment.original_policy = Some(original.clone());
        let required = original.anchor_requirement().binding().is_some();
        if !required && self.witness.is_some() {
            return Err(p::DurableError::Conflict.into());
        }
        let anchor = if required {
            Some(match kind {
                ContinuationKind::Independent => self.policy_client(&original, entry)?,
                ContinuationKind::Joint => self.renewal_client(&original, entry)?,
            })
        } else {
            None
        };
        opening::check(&entry.cancel, deadline)?;
        Ok(Box::new(ContinuedActivation {
            owner: self,
            environment,
            original,
            anchor,
            kind,
        }))
    }
}

// Keep every original owner alive through activation; preparation must not
// close an unused original runtime earlier than the previous single-stage path.
struct ContinuedActivation {
    owner: Box<Owner>,
    environment: device::Environment,
    original: p::HistoricalSessionPolicy,
    anchor: Option<p::AnchorClient>,
    kind: ContinuationKind,
}
type LocalActivation = fn(
    p::DeviceEnrollment,
    &p::HistoricalSessionPolicy,
    &p::VerifiedSessionPolicy,
    u64,
) -> std::result::Result<p::EnrolledDevice, p::DurableError>;
type WitnessedActivation = fn(
    p::DeviceEnrollment,
    &p::HistoricalSessionPolicy,
    &p::VerifiedSessionPolicy,
    u64,
    p::AnchorClient,
) -> std::result::Result<p::EnrolledDevice, p::DurableError>;
impl ContinuedActivation {
    fn activate(self: Box<Self>, entry: &Entry, deadline: Instant) -> Result<Arc<device::Shared>> {
        opening::check(&entry.cancel, deadline)?;
        let now = owner::now().map_err(Failure::configuration)?;
        // Select the native operation before the call instead of retaining
        // separate large value-return temporaries for all four match arms.
        let enrolled = if let Some(anchor) = self.anchor {
            let activate: WitnessedActivation = match self.kind {
                ContinuationKind::Independent => {
                    p::DeviceEnrollment::activate_witnessed_policy_renewal
                }
                ContinuationKind::Joint => {
                    p::DeviceEnrollment::activate_witnessed_policy_continuation
                }
            };
            activate(
                self.owner.enrollment,
                &self.original,
                &self.environment.authority.policy,
                now,
                anchor,
            )?
        } else {
            let activate: LocalActivation = match self.kind {
                ContinuationKind::Independent => p::DeviceEnrollment::activate_policy_renewal,
                ContinuationKind::Joint => p::DeviceEnrollment::activate_policy_continuation,
            };
            activate(
                self.owner.enrollment,
                &self.original,
                &self.environment.authority.policy,
                now,
            )?
        };
        opening::check(&entry.cancel, deadline)?;
        device::Shared::from_enrolled(
            enrolled,
            self.environment,
            entry.cancel.clone(),
            entry.invocation.clone(),
        )
    }
}

/// Select one independently pinned current policy, retaining its complete runtime owner.
/// This is in-memory configuration only; it grants no journal or session authority.
/// # Safety
/// All public inputs and the writable error record are distinct and live for the call.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_select_continued_policy(
    handle: u64,
    sdk_path: *const u8,
    sdk_path_length: usize,
    document: *const Document,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        // SAFETY: validated bounded copies precede taking the owning registration.
        let (path, document) = unsafe {
            (
                text(sdk_path, sdk_path_length, 4096)?,
                Document::read(document)?,
            )
        };
        with_owner(handle, deadline, |owner, entry| {
            if owner.target_authority.is_some() {
                return Err(p::DurableError::Conflict.into());
            }
            let original = owner.historical_policy(entry, deadline)?;
            let target = device::PolicyAuthority::from_pinned_input(
                Path::new(&path),
                &document.pin,
                &document.wire,
                &entry.cancel,
                deadline,
            )?;
            if target.family != owner.family || target.policy.checkpoint() == original.checkpoint()
            {
                return Err(p::Error::Scope.into());
            }
            owner.target_authority = Some(target);
            Ok(())
        })
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Stage exact account and policy approvals against independently retained predecessor metadata.
/// # Safety
/// Buffers/pins/document are immutable readable inputs. previous_t is null only for P0,
/// otherwise exactly32 readable bytes. Status/error are separate aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_stage_policy_continuation(
    handle: u64,
    grant: *const u8,
    grant_length: usize,
    pin: *const Pin,
    operation: *const u8,
    approvals: *const u8,
    approvals_length: usize,
    previous: *const Document,
    previous_t: *const u8,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        if grant_length == 0 || approvals_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: exact independent public inputs copied before taking the owner.
        let (grant, pin, operation, approvals, previous, previous_t) = unsafe {
            (
                bytes(grant, grant_length, p::MAX_CREDENTIAL_RENEWAL_BYTES)?,
                Pin::read(pin)?,
                p::CredentialRenewalId::from_trusted_state(fixed(operation)?)?,
                bytes(
                    approvals,
                    approvals_length,
                    p::MAX_POLICY_CONTINUATION_BYTES,
                )?,
                Document::read(previous)?,
                if previous_t.is_null() {
                    None
                } else {
                    Some(fixed(previous_t)?)
                },
            )
        };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let target = owner.current_target()?;
            let previous = previous.pin.verify_historical(&previous.wire)?;
            let now = owner::now().map_err(Failure::configuration)?;
            let grant = p::VerifiedCredentialRenewal::verify(
                &grant,
                &pin,
                original.checkpoint().digest(),
                now,
            )?;
            let scope = p::PolicyContinuationScope {
                operation,
                journal: p::JournalIdentity::from_trusted_state(owner.status()?.journal)?,
                original_owner: grant.original_storage_owner(),
                original_credential: grant.original_credential_digest(),
                previous_credential: grant.previous_device().credential_digest(),
                previous_roster: grant.previous_device().roster().checkpoint(),
                original_policy: original.checkpoint(),
                previous_policy: previous.checkpoint(),
                previous_authorization: previous_t,
            };
            let continuation = p::VerifiedPolicyContinuation::from_bytes(
                &approvals,
                &scope,
                &p::PolicyContinuationMaterials {
                    original: &original,
                    previous: &previous,
                    target: &target,
                    credential: &grant,
                },
                now,
            )?;
            opening::check(&entry.cancel, deadline)?;
            Ok(RenewalStatus::observed(
                owner.enrollment.stage_policy_continuation(
                    &grant,
                    &continuation,
                    operation,
                    &target,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: validated output is published only after complete native success.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Stage a credential-only renewal while retaining the actual adopted continuation.
/// # Safety
/// Inputs and outputs obey the same disjoint pointer contract as credential staging.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_stage_continued_credential_renewal(
    handle: u64,
    wire: *const u8,
    wire_length: usize,
    pin: *const Pin,
    operation: *const u8,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        if wire_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: copy bounded public inputs before native ownership or I/O.
        let (wire, pin, operation) = unsafe {
            (
                bytes(wire, wire_length, p::MAX_CREDENTIAL_RENEWAL_BYTES)?,
                Pin::read(pin)?,
                p::CredentialRenewalId::from_trusted_state(fixed(operation)?)?,
            )
        };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let target = owner.current_target()?;
            let now = owner::now().map_err(Failure::configuration)?;
            let grant = p::VerifiedCredentialRenewal::verify(
                &wire,
                &pin,
                original.checkpoint().digest(),
                now,
            )?;
            Ok(RenewalStatus::observed(
                owner
                    .enrollment
                    .stage_credential_renewal(&grant, operation, &target, now)?,
            ))
        })?;
        // SAFETY: validated exclusive output.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Recover original public metadata or prepare exactly one G/T sealed target.
/// # Safety
/// Proposal/error are distinct aligned writable invocation-local records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_prepare_witnessed_policy_continuation(
    handle: u64,
    proposal: *mut ProposalBytes,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(proposal)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let now = owner::now().map_err(Failure::configuration)?;
            let retained = owner
                .enrollment
                .recover_witnessed_credential_renewal_preparation(&original, now)?;
            let proposal = match retained {
                Some(p) => p,
                None => {
                    let target = owner.current_target()?;
                    let client = owner.renewal_client(&original, entry)?;
                    owner
                        .enrollment
                        .prepare_witnessed_policy_continuation(&original, &target, now, client)?
                }
            };
            ProposalBytes::observed(proposal)
        })?;
        // SAFETY: validated output; exact bytes and zero tail only on success.
        unsafe { put(proposal, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Historical target-free cancellation supports both unchanged G and explicit G/T grammar.
/// # Safety
/// Cancellation/error are distinct aligned writable invocation-local records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_prepare_witnessed_policy_cancellation(
    handle: u64,
    cancellation: *mut CancellationBytes,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(cancellation)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let wire = owner
                .enrollment
                .prepare_witnessed_credential_cancellation(
                    &original,
                    owner::now().map_err(Failure::configuration)?,
                )?
                .to_bytes();
            let mut result = CancellationBytes {
                length: u32::try_from(wire.len()).map_err(|_| failure(5))?,
                bytes: [0; 281],
            };
            result
                .bytes
                .get_mut(..wire.len())
                .ok_or_else(|| failure(5))?
                .copy_from_slice(&wire);
            Ok(result)
        })?;
        // SAFETY: validated exclusive output.
        unsafe { put(cancellation, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Reconcile/commit the original local G/T transaction, publishing historical status only.
/// # Safety
/// Status/error are separate aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_reconcile_policy_continuation(
    handle: u64,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let target = owner.current_target()?;
            Ok(RenewalStatus::observed(
                owner.enrollment.reconcile_policy_continuation(
                    &original,
                    &target,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: validated exclusive output.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Reconcile history first; only a still-Pending exact target can use current P1 to commit.
/// # Safety
/// Operation/statement are32 readable bytes; status/error are separate aligned outputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_commit_witnessed_policy_continuation(
    handle: u64,
    operation: *const u8,
    statement: *const u8,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        // SAFETY: immutable public operation identity copied before owner admission.
        let (operation, statement) = unsafe {
            (
                p::CredentialRenewalId::from_trusted_state(fixed(operation)?)?,
                fixed(statement)?,
            )
        };
        if statement == [0; 32] {
            return Err(Failure::argument());
        }
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let mut client = owner.renewal_client(&original, entry)?;
            let observed = owner.enrollment.reconcile_witnessed_credential_renewal(
                operation,
                statement,
                &original,
                owner::now().map_err(Failure::configuration)?,
                &mut client,
            )?;
            let observed = match observed {
                p::CredentialRenewalStatus::Pending { .. } => {
                    let target = owner.current_target()?;
                    let proposal = owner
                        .enrollment
                        .recover_witnessed_credential_renewal_preparation(
                            &original,
                            owner::now().map_err(Failure::configuration)?,
                        )?
                        .ok_or(p::DurableError::Suspended)?;
                    if proposal.operation() != operation
                        || proposal.transaction_statement() != statement
                    {
                        return Err(p::DurableError::Conflict.into());
                    }
                    owner.enrollment.commit_witnessed_policy_continuation(
                        &proposal,
                        &original,
                        &target,
                        owner::now().map_err(Failure::configuration)?,
                        &mut client,
                    )?
                }
                p::CredentialRenewalStatus::Committed { .. }
                | p::CredentialRenewalStatus::Closed { .. } => observed,
                _ => return Err(p::DurableError::Conflict.into()),
            };
            Ok(RenewalStatus::observed(observed))
        })?;
        // SAFETY: validated output is never synthesized after a failed invocation.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Finish an exact existing local journal commit from independently pinned policy history.
/// No SDK store/runtime or TLS configuration is loaded and no Device is published.
/// # Safety
/// Operation/statement are32 readable bytes; document and all its inputs are live
/// and immutable; status/error are distinct aligned writable records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_recover_historical_policy_continuation(
    handle: u64,
    operation: *const u8,
    statement: *const u8,
    target: *const Document,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        // SAFETY: bounded public expectations copied before owner admission.
        let (operation, statement, target) = unsafe {
            (
                p::CredentialRenewalId::from_trusted_state(fixed(operation)?)?,
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
            Ok(RenewalStatus::observed(
                owner.enrollment.recover_historical_policy_continuation(
                    operation,
                    statement,
                    &original,
                    &target,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: publish only the observed native historical result on success.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Consume registration into a continued device, transferring the full target runtime owner.
/// # Safety
/// Error is an aligned writable invocation-local record.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_activate_policy_continuation(
    handle: u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        with_entry(handle, deadline, |slot, entry| {
            let owner = take_owner(slot, entry, deadline)?;
            let device = owner.activate_continued(entry, deadline, ContinuationKind::Joint)?;
            opening::check(&entry.cancel, deadline)?;
            *slot = Some(Owned::Device(device));
            Ok(())
        })
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
