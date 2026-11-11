// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete read-only source/target metadata for one retained ordinary intent.
use super::*;
use crate::anchor::PendingWriteRecoveryScope;
use crate::{
    AnchorHead, AnchorPendingWriteRecoveryProposal, HistoricalPolicyContinuation,
    HistoricalPolicyRenewal,
};

#[cfg(test)]
mod inspection_tests;

/// Complete public description of a source or proposed target image. A local
/// request derives it from authenticated storage; inspecting received bytes does
/// not authenticate that claim. Neither position establishes witness commitment.
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

/// Bounded, complete inspection of the metadata bound to a public proposal.
/// This proves framing and proposal consistency only. It does not authenticate
/// the sender, encrypted local images, the intended effect or current authority.
/// The independent controller must make and durably retain its own approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingWriteRecoveryInspection {
    source: PendingWriteRecoveryView,
    target: PendingWriteRecoveryView,
}
impl PendingWriteRecoveryInspection {
    /// Complete claimed source, with no assertion that it is the current head.
    pub fn source(&self) -> &PendingWriteRecoveryView {
        &self.source
    }
    /// Complete claimed target; proposed outcomes are never delivery receipts.
    pub fn target(&self) -> &PendingWriteRecoveryView {
        &self.target
    }
}
impl AnchorPendingWriteRecoveryProposal {
    /// Decode both complete public views for independent control-plane review.
    /// Checks the proposal's metadata commitment, scope, view heads and bounded
    /// grammar. It performs no I/O, signature verification or privileged action.
    /// Public signed roster/publication histories remain verbatim byte fields;
    /// their domain-specific verification uses the independently trusted roots.
    pub fn inspect_metadata(
        &self,
        recorded_metadata: &[u8],
    ) -> Result<PendingWriteRecoveryInspection, Error> {
        self.check_metadata(recorded_metadata)?;
        let mut input = Decoder::new(recorded_metadata);
        input.take(self.scope.metadata_prefix()?.len())?;
        let mut view = || {
            let size = usize::try_from(input.u64()?).map_err(|_| Error::Encoding)?;
            retired_report::decode_public_view(input.take(size)?)
        };
        let source = view()?;
        let target = view()?;
        input.finish()?;
        if source.head != self.expected_head() || target.head != self.target_head() {
            return Err(Error::Scope);
        }
        Ok(PendingWriteRecoveryInspection { source, target })
    }
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
