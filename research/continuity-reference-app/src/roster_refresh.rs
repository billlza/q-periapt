// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public original R proposal and identity evidence; no issuer or runtime permit.
use crate::enrollment::{wire, RootInfo};
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Retain this complete export before independent witness approval. Identity
/// evidence is checked under separately selected account trust, never its own root.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub binding: [u8; 32],
    #[serde(with = "wire")]
    pub proposal: Vec<u8>,
    #[serde(with = "wire")]
    pub certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub previous_roster: Vec<u8>,
}
impl Request {
    pub(crate) fn from_owner(
        proposal: sdk::AnchorRosterRefreshProposal,
        admission: &sdk::EnrollmentPublicAdmission,
    ) -> Result<Self> {
        if admission.checkpoint() != proposal.scope().previous {
            return Err("Roster proposal differs from retained predecessor admission".into());
        }
        Ok(Self {
            schema: "qperiapt-roster-refresh-request/1".into(),
            binding: proposal.binding(),
            proposal: proposal.to_bytes(),
            certificate: admission.certificate().to_vec(),
            previous_roster: admission.roster().to_vec(),
        })
    }
    /// Restore only the exact original public expectation. This is not approval.
    pub fn as_proposal(&self) -> Result<sdk::AnchorRosterRefreshProposal> {
        if self.schema != "qperiapt-roster-refresh-request/1" {
            return Err("Roster request schema differs".into());
        }
        let p = sdk::AnchorRosterRefreshProposal::from_trusted_state(&self.proposal)?;
        if p.binding() != self.binding || p.to_bytes() != self.proposal {
            return Err("Roster request binding differs".into());
        }
        Ok(p)
    }
    pub(crate) fn previous(&self, account: &RootInfo) -> Result<sdk::VerifiedDevice> {
        let p = self.as_proposal()?;
        Ok(sdk::AccountPin::new(
            account.account,
            sdk::PublicKey::decode(&account.public_key)?,
            p.scope().previous,
            account.family,
        )?
        .verify_historical_device(&self.certificate, &self.previous_roster)?)
    }
    pub(crate) fn target_pin(&self, account: &RootInfo) -> Result<sdk::AccountPin> {
        let roster = account
            .roster
            .as_ref()
            .ok_or("Explicit target roster required")?;
        if account.revision == 0
            || roster.checkpoint.as_sdk()? != self.as_proposal()?.scope().target
        {
            return Err(
                "Selected account target differs from the original roster operation".into(),
            );
        }
        Ok(sdk::AccountPin::new(
            account.account,
            sdk::PublicKey::decode(&account.public_key)?,
            roster.checkpoint.as_sdk()?,
            account.family,
        )?)
    }
}

/// Historical transaction observation. Unavailable never proves non-commit;
/// Applied/Acknowledged never grants current device or session permission.
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
    pub(crate) fn new(request: &Request, state: sdk::AnchorRosterRefreshState) -> Self {
        Self {
            binding: request.binding,
            state: match state {
                sdk::AnchorRosterRefreshState::Prepared => State::Prepared,
                sdk::AnchorRosterRefreshState::Applied => State::Applied,
                sdk::AnchorRosterRefreshState::Closed => State::Closed,
                sdk::AnchorRosterRefreshState::Acknowledged => State::Acknowledged,
                sdk::AnchorRosterRefreshState::Unavailable => State::Unavailable,
            },
        }
    }
}
