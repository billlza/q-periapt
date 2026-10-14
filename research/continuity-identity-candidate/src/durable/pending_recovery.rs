// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete read-only source/target metadata for one retained ordinary intent.
use super::*;
use crate::anchor::PendingWriteRecoveryScope;
use crate::{
    AnchorHead, AnchorPendingWriteRecoveryProposal, HistoricalPolicyContinuation,
    HistoricalPolicyRenewal,
};

/// One authenticated local image. Its position is source or proposed target;
/// neither position claims that the witness has or has not committed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingWriteRecoveryView {
    /// Exact original image head.
    pub head: AnchorHead,
    /// Original account identity.
    pub local_account: [u8; 32],
    /// Retained next aggregate ordinal, not a new-work permission.
    pub next_fanout_ordinal: u64,
    /// Every actual record, using the shared complete public metadata grammar.
    pub records: Vec<retired_report::RecordMetadataEntry>,
}
/// Immutable request, complete host metadata and original historical signature.
/// It contains no plaintext, private keys, runtime or approval capability.
/// Retain the proposal and complete metadata before independently approving the
/// exact intended effect. Keep these original inputs after an unknown result.
pub struct PendingWriteRecoveryRequest {
    proposal: AnchorPendingWriteRecoveryProposal,
    source: PendingWriteRecoveryView,
    target: PendingWriteRecoveryView,
    metadata: Vec<u8>,
    request: Vec<u8>,
}
impl PendingWriteRecoveryRequest {
    /// Exact expectation to retain independently before submitting a mutation.
    pub fn proposal(&self) -> &AnchorPendingWriteRecoveryProposal {
        &self.proposal
    }
    /// Original stored image, without guessing the witness outcome.
    pub fn source(&self) -> &PendingWriteRecoveryView {
        &self.source
    }
    /// Original sealed next image, never recomputed or applied by preparation.
    pub fn target(&self) -> &PendingWriteRecoveryView {
        &self.target
    }
    /// Full canonical QPWRMD01 public metadata, including source and target.
    /// Account/device linkage and lengths are private host metadata.
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
    /// Purpose-26 dual signature over the exact proposal and metadata digest.
    /// A valid old-device signature is not independent approval.
    pub fn signed_request(&self) -> &[u8] {
        &self.request
    }
}

pub(crate) struct PendingRecoveryLineage<'a> {
    pub(crate) scope: crate::installation::PolicyScope<'a>,
    pub(crate) current: &'a VerifiedDevice,
    pub(crate) completed: Option<&'a HistoricalPolicyRenewal>,
    pub(crate) policy_completion:
        Option<&'a std::sync::Arc<crate::enrollment::EnrollmentPolicyCompletion>>,
    pub(crate) joint: Option<&'a HistoricalPolicyContinuation>,
    pub(crate) witnessed_completion: Option<&'a LocalRenewalCommit>,
}
impl PendingRecoveryLineage<'_> {
    pub(super) fn attach_completion(&self, image: &mut Image) -> Result<(), DurableError> {
        if let Some(completion) = self.policy_completion {
            rosters::check_enrollment_policy_completion(image, completion)?;
            image.enrollment_completion = Some(std::sync::Arc::clone(completion));
        }
        Ok(())
    }
    pub(super) fn inspect(&self, image: &Image) -> Result<RenewalRequestSnapshot, DurableError> {
        rosters::inspect_renewal_snapshot(
            image,
            &self.scope,
            self.current,
            self.completed,
            self.joint,
            rosters::RequestRoster::Actual,
            self.witnessed_completion,
        )
    }
}
pub(crate) struct PendingRecoverySnapshot {
    pub(crate) scope: PendingWriteRecoveryScope,
    pub(crate) source: PendingWriteRecoveryView,
    pub(crate) target: PendingWriteRecoveryView,
}
impl PendingRecoverySnapshot {
    pub(super) fn expectation(
        &self,
    ) -> Result<(AnchorPendingWriteRecoveryProposal, Vec<u8>), DurableError> {
        let mut metadata = self.scope.metadata_prefix()?;
        for view in [&self.source, &self.target] {
            let encoded = retired_report::encode_public_view(
                view.head,
                view.local_account,
                view.next_fanout_ordinal,
                &view.records,
            )?;
            let size = metadata
                .len()
                .checked_add(8)
                .and_then(|n| n.checked_add(encoded.len()))
                .ok_or(DurableError::Capacity)?;
            if size > crate::anchor::MAX_PENDING_RECOVERY_METADATA {
                return Err(DurableError::Capacity);
            }
            metadata.extend_from_slice(
                &u64::try_from(encoded.len())
                    .map_err(|_| DurableError::Capacity)?
                    .to_be_bytes(),
            );
            metadata.extend_from_slice(&encoded);
        }
        let proposal = self.scope.clone().proposal(&metadata)?;
        Ok((proposal, metadata))
    }
    pub(crate) fn sign(
        self,
        signer: &DeviceSigningKey,
    ) -> Result<PendingWriteRecoveryRequest, DurableError> {
        let (proposal, metadata) = self.expectation()?;
        let body = proposal.to_bytes();
        let signature = signer.sign(crate::crypto::Purpose::PendingWriteRecovery, &body)?;
        let request = crate::crypto::envelope(&body, &signature)?;
        Ok(PendingWriteRecoveryRequest {
            proposal,
            source: self.source,
            target: self.target,
            metadata,
            request,
        })
    }
}
