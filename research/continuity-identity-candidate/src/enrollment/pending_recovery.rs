// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment and storage leases for exact ordinary-intent recovery.
use super::*;
use crate::{
    AnchorHead, AnchorPendingWriteRecoveryProposal, DeviceJournal, HistoricalPolicyContinuation,
    HistoricalPolicyRenewal, HistoricalSessionPolicy, PendingWriteRecoveryRequest,
    RetainedInstallationAuthority, SessionArchiveStore,
};

struct Inputs {
    image: Image,
    original: VerifiedDevice,
    current: VerifiedDevice,
    completed: Option<HistoricalPolicyRenewal>,
    policy_completion: Option<std::sync::Arc<EnrollmentPolicyCompletion>>,
    joint: Option<HistoricalPolicyContinuation>,
    authority: RetainedInstallationAuthority,
}
impl Inputs {
    fn lineage<'a>(
        &'a self,
        policy: &'a HistoricalSessionPolicy,
    ) -> crate::durable::PendingRecoveryLineage<'a> {
        crate::durable::PendingRecoveryLineage {
            scope: crate::installation::PolicyScope {
                authority: &self.authority,
                original_policy: policy,
                original_device: &self.original,
            },
            current: &self.current,
            completed: self.completed.as_ref(),
            policy_completion: self.policy_completion.as_ref(),
            joint: self.joint.as_ref(),
            witnessed_completion: self
                .image
                .renewal
                .as_ref()
                .and_then(LocalRenewal::witnessed_completion),
        }
    }
}
// Drop journal/archive leases before the installation configuration lease.
struct Owners {
    journal: Database,
    archives: SessionArchiveStore,
    _installation: DeviceInstallation,
    key: JournalKey,
    signer: DeviceSigningKey,
    inputs: Inputs,
    id: JournalIdentity,
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Prepare complete metadata and the original device's historical signature
    /// for independent approval of this exact retained ordinary write. This does
    /// not replay, cancel, replace or reserve any journal state and creates no
    /// Runtime. Missing state is refused; it is not proof of prior completion.
    ///
    /// Locally staged G/T/P/R approvals remain intact. Their bound journal intents,
    /// root replacement and permanent retirement use their own flows. The operator
    /// must approve the intended effect independently of this old-device signature
    /// and durably retain all original inputs. The witness pin must stay original.
    pub async fn pending_write_recovery_request(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        pin: &AnchorPin,
    ) -> Result<PendingWriteRecoveryRequest, DurableError> {
        let result = self
            .pending_write_recovery_request_attempt(original_policy, pin)
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn pending_write_recovery_request_attempt(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        pin: &AnchorPin,
    ) -> Result<PendingWriteRecoveryRequest, DurableError> {
        let mut owners = self
            .pending_write_recovery_owners(original_policy, pin)
            .await?;
        DeviceJournal::pending_write_recovery_in_database(
            &owners.journal,
            &owners.key,
            owners.id,
            &owners.inputs.lineage(original_policy),
            &mut owners.archives,
        )?
        .sign(&owners.signer)
    }

    /// Confirm the exact target with a fresh signed read-only witness query, then
    /// apply only the original authenticated pending image under the original
    /// leases. Retain the approved proposal and complete metadata after errors.
    /// This sends no new Advance and grants no current credential or Runtime.
    ///
    /// Retry after a lost result requires both the exact authenticated local
    /// target and the witness's exact original last command. Absence alone is
    /// never completion. A later head conflicts; this is not a historical audit.
    /// Any staged G/T/P/R authorization is preserved for its existing flow.
    pub async fn confirm_pending_write_recovery(
        &mut self,
        approved: &AnchorPendingWriteRecoveryProposal,
        recorded_metadata: &[u8],
        original_policy: &HistoricalSessionPolicy,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorHead, DurableError> {
        let result = self
            .confirm_pending_write_recovery_attempt(
                approved,
                recorded_metadata,
                original_policy,
                pin,
                transport,
                timeout,
            )
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn confirm_pending_write_recovery_attempt(
        &mut self,
        approved: &AnchorPendingWriteRecoveryProposal,
        recorded_metadata: &[u8],
        original_policy: &HistoricalSessionPolicy,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorHead, DurableError> {
        approved.check_metadata(recorded_metadata)?;
        let mut owners = self
            .pending_write_recovery_owners(original_policy, &pin)
            .await?;
        let mut client = AnchorClient::new(pin, owners.signer, transport, timeout)?;
        DeviceJournal::confirm_pending_write_recovery_in_database(
            &owners.journal,
            &owners.key,
            owners.id,
            &owners.inputs.lineage(original_policy),
            &mut owners.archives,
            approved,
            &mut client,
        )
        .await
    }
    async fn pending_write_recovery_owners(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        pin: &AnchorPin,
    ) -> Result<Owners, DurableError> {
        // Unlike a new renewal request, recovery can inspect the generic intent
        // that precedes an already staged approval. image() still authenticates
        // and validates every enrollment sidecar; none is changed here.
        let image = self.image()?;
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
        if original_policy.anchor_requirement().binding() != Some(pin.binding())
            || pin.public_key().shares_component(&original.authority_key)
            || pin.public_key().shares_component(&original.key)
        {
            return Err(DurableError::Conflict);
        }
        original_policy.check_external_signer(pin.public_key())?;
        let current = self.historical_device_metadata(
            &admission.certificate,
            &admission.roster,
            admission.checkpoint,
        )?;
        let completed = self.completed_policy_approval(&image)?;
        let policy_completion =
            self.retained_policy_enrollment_completion(&image, original_policy, &original)?;
        let joint = image
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_predecessor)
            .map(|p| self.retained_policy(p))
            .transpose()?;
        let authority =
            RetainedInstallationAuthority::active_installation(&original, original_policy);
        let installation = self
            .witness_lease(&original, original_policy, admission.journal)
            .await?;
        let archives = SessionArchiveStore::open_with_storage(
            self.storage.clone(),
            self.paths.installation.files()[2],
            admission.journal,
        )
        .await?;
        let journal = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        let key = self.key().await?;
        let signer = self.signer(image.identity, false).await?;
        if signer.public_key()? != original.key {
            return Err(DurableError::Conflict);
        }
        Ok(Owners {
            journal,
            archives,
            _installation: installation,
            key,
            signer,
            id: admission.journal,
            inputs: Inputs {
                image,
                original,
                current,
                completed,
                policy_completion,
                joint,
                authority,
            },
        })
    }
}
