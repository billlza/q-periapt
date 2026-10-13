// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original public G issuer inputs, without borrowing a live traffic owner.
use super::{
    policy::renewal::{PolicyCheckpoint, PublicRecord},
    *,
};

#[repr(C)]
pub struct CredentialRequest {
    pub operation: [u8; 32],
    pub journal: [u8; 32],
    pub original_owner: [u8; 32],
    pub original_policy_digest: [u8; 32],
    pub current_policy: PolicyCheckpoint,
    pub current_policy_authorization: [u8; 32],
    pub has_current_policy_authorization: u32,
    pub reserved: u32,
    pub previous_roster_checkpoint: Checkpoint,
    pub original_roster_checkpoint: Checkpoint,
    pub previous_valid_from: u64,
    pub previous_valid_until: u64,
    pub account: [u8; 32],
    pub original_credential: PublicRecord,
    pub original_roster: PublicRecord,
    pub previous_credential: PublicRecord,
    pub previous_roster: PublicRecord,
}
impl CredentialRequest {
    fn observed(request: &p::CredentialRenewalRequest) -> Result<Box<Self>> {
        let authority = request.current_policy_authorization();
        Ok(Box::new(Self {
            operation: *request.operation().as_bytes(),
            journal: *request.journal().as_bytes(),
            original_owner: request.original_owner(),
            original_policy_digest: request.authorization().policy_digest,
            current_policy: PolicyCheckpoint::observed(request.current_policy()),
            current_policy_authorization: authority.unwrap_or([0; 32]),
            has_current_policy_authorization: u32::from(authority.is_some()),
            reserved: 0,
            previous_roster_checkpoint: Checkpoint::observed(request.authorization().previous),
            original_roster_checkpoint: Checkpoint::observed(
                request.original_device().roster().checkpoint(),
            ),
            previous_valid_from: request.previous_validity().from(),
            previous_valid_until: request.previous_validity().until(),
            account: request.original_device().account_id(),
            original_credential: PublicRecord::observed(request.original_credential())?,
            original_roster: PublicRecord::observed(request.original_roster())?,
            previous_credential: PublicRecord::observed(request.previous_credential())?,
            previous_roster: PublicRecord::observed(request.previous_roster())?,
        }))
    }
    // Keep the large output copy outside generic owner/admission/panic frames.
    #[inline(never)]
    unsafe fn publish(self: Box<Self>, output: *mut Self) {
        // SAFETY: the invocation validated a separate aligned complete output.
        unsafe { put(output, *self) };
    }
}

impl Owner {
    fn credential_request_client(
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
        Ok(self.enrollment.credential_renewal_request_anchor_client(
            original,
            parameters.pin,
            parameters.transport,
            parameters.timeout,
        )?)
    }
}

unsafe fn request(
    handle: u64,
    operation: *const u8,
    request: *mut CredentialRequest,
    error: *mut ErrorRecord,
    witnessed: bool,
) -> i32 {
    let action = |deadline| {
        output(request)?;
        // SAFETY: caller supplies32 immutable readable operation bytes.
        let operation = p::CredentialRenewalId::from_trusted_state(unsafe { fixed(operation)? })?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let value = if witnessed {
                let client = owner.credential_request_client(&original, entry)?;
                owner
                    .enrollment
                    .witnessed_credential_renewal_request(operation, &original, client)?
            } else {
                owner
                    .enrollment
                    .credential_renewal_request(operation, &original)?
            };
            CredentialRequest::observed(&value)
        })?;
        // SAFETY: publish only after all owner, cancellation and deadline checks.
        unsafe { result.publish(request) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local disjoint diagnostics contract.
    unsafe { boundary(error, false, action) }
}

/// Export local G issuer inputs from the original acknowledged journal.
/// # Safety
/// Operation has32 readable bytes. Request/error are aligned writable complete
/// records; all input/output regions are disjoint and live for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_credential_renewal_request(
    handle: u64,
    operation: *const u8,
    output: *mut CredentialRequest,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwards the complete caller contract without retaining pointers.
    unsafe { request(handle, operation, output, error, false) }
}

/// Export required-witness G inputs, checking the original witness and journal.
/// # Safety
/// Operation has32 readable bytes. Request/error are aligned writable complete
/// records; all input/output regions are disjoint and live for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_witnessed_credential_renewal_request(
    handle: u64,
    operation: *const u8,
    output: *mut CredentialRequest,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: required-witness admission never falls back to the local path.
    unsafe { request(handle, operation, output, error, true) }
}
