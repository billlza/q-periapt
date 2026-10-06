// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public issuer inputs from the original enrollment and its matched journal.
use super::*;
use crate::{
    durable::RenewalRequestSnapshot, CredentialRenewalAuthorization, CredentialRenewalMaterials,
    HistoricalPolicyContinuation, HistoricalPolicyRenewal, HistoricalSessionPolicy,
    PolicyCheckpoint, PolicyRenewalId, PolicyRenewalScope, Validity,
};

/// Historical preparation for an independently authorized real G operation.
/// This is public metadata, not proof of user authentication, a reservation,
/// a signed grant or a runtime owner. Retain the request and operation before
/// submitting it; the issuer must independently authorize, serialize and dedup.
pub struct CredentialRenewalRequest {
    operation: CredentialRenewalId,
    snapshot: RenewalRequestSnapshot,
    original_credential: Vec<u8>,
    previous_credential: Vec<u8>,
    previous_roster: Vec<u8>,
    original_device: VerifiedDevice,
}
impl CredentialRenewalRequest {
    /// Caller-retained original G request identity, never a policy-only ID.
    pub fn operation(&self) -> CredentialRenewalId {
        self.operation
    }
    /// Original journal observed at preparation; G itself binds its original owner.
    pub fn journal(&self) -> JournalIdentity {
        self.snapshot.journal
    }
    /// Original immutable storage owner observed in the matching journal.
    pub fn original_owner(&self) -> [u8; 32] {
        self.snapshot.original_owner
    }
    /// Actual adopted policy at preparation. This is context, not an extra G binding.
    pub fn current_policy(&self) -> PolicyCheckpoint {
        self.snapshot.current_policy
    }
    /// Actual independent or joint policy authorization, if one was adopted.
    /// G continues to bind original P0; activation checks the then-current policy.
    pub fn current_policy_authorization(&self) -> Option<[u8; 32]> {
        self.snapshot.current_policy_authorization
    }
    /// Historical verified predecessor; retaining this does not grant current use.
    pub fn previous_device(&self) -> &VerifiedDevice {
        &self.snapshot.current_device
    }
    /// Signed credential validity before extension, which may already have ended.
    pub fn previous_validity(&self) -> Validity {
        self.snapshot.current_device.description.validity
    }
    /// Original signature-verified identity snapshot, not current permission.
    pub fn original_device(&self) -> &VerifiedDevice {
        &self.original_device
    }
    /// Exact signed roster authenticating that original snapshot.
    pub fn original_roster(&self) -> &[u8] {
        self.original_device.roster().as_bytes()
    }
    /// Exact original retained public credential bytes, without re-signing.
    pub fn original_credential(&self) -> &[u8] {
        &self.original_credential
    }
    /// Exact public predecessor credential bytes retained by this enrollment.
    pub fn previous_credential(&self) -> &[u8] {
        &self.previous_credential
    }
    /// Exact public predecessor roster observed in the original journal.
    pub fn previous_roster(&self) -> &[u8] {
        &self.previous_roster
    }
    /// Existing G scope: original operation, exact predecessor and original P0.
    /// The account issuer still needs independent approval and current-head control.
    pub fn authorization(&self) -> CredentialRenewalAuthorization {
        CredentialRenewalAuthorization {
            operation: self.operation,
            previous: self.snapshot.current_roster,
            policy_digest: self.snapshot.original_policy.digest(),
        }
    }
    /// Combine original SDK-retained inputs with independently issued target
    /// credential/roster bytes for the existing account-root G signing method.
    pub fn materials<'a>(
        &'a self,
        successor_credential: &'a [u8],
        successor_roster: &'a [u8],
    ) -> CredentialRenewalMaterials<'a> {
        CredentialRenewalMaterials {
            original_credential: &self.original_credential,
            previous_credential: &self.previous_credential,
            previous_roster: &self.previous_roster,
            successor_credential,
            successor_roster,
        }
    }
}

pub(in crate::enrollment) struct PreparedRenewalRequest {
    image: Image,
    original: VerifiedDevice,
    current: VerifiedDevice,
    completed: Option<HistoricalPolicyRenewal>,
    joint: Option<HistoricalPolicyContinuation>,
    authority: RetainedInstallationAuthority,
    service: DeviceService,
}
impl PreparedRenewalRequest {
    pub(in crate::enrollment) fn policy_scope(
        &mut self,
        operation: PolicyRenewalId,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<PolicyRenewalScope, DurableError> {
        self.service.stores()?.0.policy_renewal_request_scope(
            &crate::installation::PolicyScope {
                authority: &self.authority,
                original_policy,
                original_device: &self.original,
            },
            &self.current,
            operation,
            self.completed.as_ref(),
            self.joint.as_ref(),
        )
    }
    pub(in crate::enrollment) fn policy_request(
        mut self,
        operation: PolicyRenewalId,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<crate::PolicyRenewalRequest, DurableError> {
        let scope = self.policy_scope(operation, original_policy)?;
        let Phase::Accepted { admission, .. } = &self.image.phase else {
            return Err(DurableError::Corrupt);
        };
        let original_credential = self
            .image
            .renewal
            .as_ref()
            .map_or(&admission.certificate, |r| &r.origin.certificate)
            .clone();
        Ok(crate::PolicyRenewalRequest::new(
            scope,
            self.original,
            self.current,
            original_credential,
            admission.certificate.clone(),
        ))
    }
    fn credential_snapshot(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<RenewalRequestSnapshot, DurableError> {
        self.service.stores()?.0.renewal_request_snapshot(
            &crate::installation::PolicyScope {
                authority: &self.authority,
                original_policy,
                original_device: &self.original,
            },
            &self.current,
            self.completed.as_ref(),
            self.joint.as_ref(),
        )
    }
}

impl DeviceEnrollment {
    pub(in crate::enrollment) fn prepare_renewal_request(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<PreparedRenewalRequest, DurableError> {
        let image = self.image()?;
        if image.policy_pending.is_some()
            || image
                .renewal
                .as_ref()
                .is_some_and(|r| !r.permits_policy_pending())
        {
            return Err(DurableError::Suspended);
        }
        if original_policy.anchor_requirement().binding().is_some() {
            return Err(DurableError::AnchorRequired);
        }
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        if admission.policy != original_policy.checkpoint().digest() {
            return Err(DurableError::Conflict);
        }
        let original = self.original_device_metadata(&image)?;
        let current = self.historical_device_metadata(
            &admission.certificate,
            &admission.roster,
            admission.checkpoint,
        )?;
        let completed = self.completed_policy_approval(&image)?;
        let joint = image
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_predecessor)
            .map(|b| self.retained_policy(b))
            .transpose()?;
        let authority =
            RetainedInstallationAuthority::active_installation(&original, original_policy);
        let mut service = DeviceInstallation::reconcile_original_enrollment(
            self.paths.installation.clone(),
            self.key()?,
            &original,
            original_policy,
            None,
        )?;
        if service.stores()?.0.identity()? != admission.journal {
            return Err(DurableError::Conflict);
        }
        Ok(PreparedRenewalRequest {
            image,
            original,
            current,
            completed,
            joint,
            authority,
            service,
        })
    }

    /// Prepare real credential-renewal issuer materials from this original
    /// enrollment and the actual acknowledged journal predecessor. Keep the
    /// caller-generated operation and returned request before submission.
    /// No private signer or live runtime is needed, including after expiry.
    ///
    /// Pending operations, changed credentials, revocation, unacknowledged receipts
    /// and a retained completed/abandoned G ID are refused. This local metadata
    /// snapshot may carry a newer actual roster for the same retained credential,
    /// so expired credentials do not need a live-C roster refresh before renewal.
    /// It does not reserve or sign anything. Independent issuer approval,
    /// exact retry/dedup and current staging/commit checks remain mandatory.
    pub fn credential_renewal_request(
        &mut self,
        operation: CredentialRenewalId,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<CredentialRenewalRequest, DurableError> {
        let result = (|| {
            let mut prepared = self.prepare_renewal_request(original_policy)?;
            if prepared.image.renewal.as_ref().is_some_and(|r| {
                r.completed
                    .as_ref()
                    .is_some_and(|c| c.operation == operation)
                    || r.expired.as_ref().is_some_and(|e| e.operation == operation)
            }) {
                return Err(DurableError::Conflict);
            }
            let snapshot = prepared.credential_snapshot(original_policy)?;
            let Phase::Accepted { admission, .. } = &prepared.image.phase else {
                return Err(DurableError::Corrupt);
            };
            let original_credential = prepared
                .image
                .renewal
                .as_ref()
                .map_or(&admission.certificate, |r| &r.origin.certificate)
                .clone();
            let previous_credential = admission.certificate.clone();
            let previous_roster = snapshot.current_device.roster().as_bytes().to_vec();
            Ok(CredentialRenewalRequest {
                operation,
                snapshot,
                original_credential,
                previous_credential,
                previous_roster,
                original_device: prepared.original,
            })
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
