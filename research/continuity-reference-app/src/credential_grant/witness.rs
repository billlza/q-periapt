// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public original G proposal; it carries expectations, never issuer authority.
use crate::enrollment::wire;
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub schema: String,
    pub operation: [u8; 32],
    pub journal: [u8; 32],
    #[serde(with = "wire")]
    pub proposal: Vec<u8>,
}
impl Preparation {
    /// Encode public expectations only; this cannot authorize a witness target.
    pub fn from_proposal(
        proposal: sdk::AnchorCredentialRenewalProposal,
        journal: [u8; 32],
    ) -> Result<Self> {
        let value = Self {
            schema: "qperiapt-credential-witness-proposal/1".into(),
            operation: *proposal.operation().as_bytes(),
            journal,
            proposal: proposal.to_bytes(),
        };
        value.as_proposal()?;
        Ok(value)
    }
    pub fn as_proposal(&self) -> Result<sdk::AnchorCredentialRenewalProposal> {
        if self.schema != "qperiapt-credential-witness-proposal/1" {
            return Err("Credential proposal schema differs".into());
        }
        let p = sdk::AnchorCredentialRenewalProposal::from_trusted_state(&self.proposal)?;
        if p.operation().as_bytes() != &self.operation
            || p.to_bytes() != self.proposal
            || p.subject().to_bytes().get(..32) != Some(self.journal.as_slice())
        {
            return Err("Credential proposal correlation differs from its original subject".into());
        }
        Ok(p)
    }
}

/// An exact witness observation, not current device or traffic permission.
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
    pub(crate) fn new(
        p: sdk::AnchorCredentialRenewalProposal,
        state: sdk::AnchorCredentialRenewalState,
    ) -> Self {
        Self {
            binding: p.binding(),
            state: match state {
                sdk::AnchorCredentialRenewalState::Prepared => State::Prepared,
                sdk::AnchorCredentialRenewalState::Applied => State::Applied,
                sdk::AnchorCredentialRenewalState::Closed => State::Closed,
                sdk::AnchorCredentialRenewalState::Acknowledged => State::Acknowledged,
                sdk::AnchorCredentialRenewalState::Unavailable => State::Unavailable,
            },
        }
    }
}
