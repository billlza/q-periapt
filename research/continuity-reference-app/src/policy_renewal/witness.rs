// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original public P preparation; independent operator trust is never embedded.
use crate::enrollment::wire;
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Export before requesting witness approval. The approval bytes are the first
/// exact two-root result retained by enrollment, not a newly signed replacement.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub schema: String,
    pub binding: [u8; 32],
    #[serde(with = "wire")]
    pub proposal: Vec<u8>,
    #[serde(with = "wire")]
    pub approval: Vec<u8>,
}
impl Preparation {
    pub(crate) fn new(
        proposal: sdk::AnchorPolicyRenewalProposal,
        approval: Vec<u8>,
    ) -> Result<Self> {
        let value = Self {
            schema: "qperiapt-policy-witness-preparation/1".into(),
            binding: proposal.binding(),
            proposal: proposal.to_bytes(),
            approval,
        };
        value.as_proposal()?;
        Ok(value)
    }
    /// Public expectation only. The witness separately verifies both signatures
    /// against its independently selected request, identity and policy materials.
    pub fn as_proposal(&self) -> Result<sdk::AnchorPolicyRenewalProposal> {
        if self.schema != "qperiapt-policy-witness-preparation/1"
            || self.approval.is_empty()
            || self.approval.len() > sdk::MAX_POLICY_RENEWAL_BYTES
        {
            return Err("Policy preparation schema or approval size differs".into());
        }
        let p = sdk::AnchorPolicyRenewalProposal::from_trusted_state(&self.proposal)?;
        if p.binding() != self.binding || p.to_bytes() != self.proposal {
            return Err("Policy preparation binding differs".into());
        }
        Ok(p)
    }
}

/// Historical witness result, never a live permission or proof from Unavailable.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub binding: [u8; 32],
    pub state: State,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum State {
    Prepared,
    Applied,
    Closed,
    Acknowledged,
    Unavailable,
}
impl Outcome {
    pub(crate) fn new(preparation: &Preparation, state: sdk::AnchorPolicyRenewalState) -> Self {
        Self {
            binding: preparation.binding,
            state: match state {
                sdk::AnchorPolicyRenewalState::Prepared => State::Prepared,
                sdk::AnchorPolicyRenewalState::Applied => State::Applied,
                sdk::AnchorPolicyRenewalState::Closed => State::Closed,
                sdk::AnchorPolicyRenewalState::Acknowledged => State::Acknowledged,
                sdk::AnchorPolicyRenewalState::Unavailable => State::Unavailable,
            },
        }
    }
}
