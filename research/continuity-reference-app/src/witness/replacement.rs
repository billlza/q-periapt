// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit trusted operator inputs for one original device replacement.
use super::*;
use crate::{enrollment::Checkpoint, policy_publisher::PolicyInput};

/// Independently approved predecessor state, never selected by a device export.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePredecessorTrust {
    #[serde(with = "crate::enrollment::wire")]
    pub subject: Vec<u8>,
    pub checkpoint: Checkpoint,
    pub policy: PolicyInput,
}

/// Account-authorized successor and the complete original witness predecessor set.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReplacementTrust {
    pub schema: String,
    pub successor: EnrollmentTrust,
    pub predecessors: Vec<DevicePredecessorTrust>,
}

/// Retain before commit. This public expectation is not a reservation or authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReplacementDecision {
    pub schema: String,
    pub binding: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub proposal: Vec<u8>,
}
impl DeviceReplacementDecision {
    fn from_sdk(proposal: sdk::AnchorDeviceReplacementProposal) -> Result<Self> {
        Ok(Self {
            schema: "qperiapt-witness-device-replacement-decision/1".into(),
            binding: proposal.binding()?,
            proposal: proposal.to_bytes()?,
        })
    }
    fn as_sdk(&self) -> Result<sdk::AnchorDeviceReplacementProposal> {
        if self.schema != "qperiapt-witness-device-replacement-decision/1" {
            return Err("Device replacement decision schema differs".into());
        }
        let proposal = sdk::AnchorDeviceReplacementProposal::from_trusted_state(&self.proposal)?;
        if proposal.binding()? != self.binding || proposal.to_bytes()? != self.proposal {
            return Err("Device replacement decision binding differs".into());
        }
        Ok(proposal)
    }
}

/// Historical observation only. Committed grants no current device or traffic owner.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceReplacementOutcome {
    pub binding: [u8; 32],
    pub status: DeviceReplacementStatus,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceReplacementStatus {
    Committed,
    Unavailable,
}
fn outcome(
    binding: [u8; 32],
    state: sdk::AnchorDeviceReplacementState,
) -> DeviceReplacementOutcome {
    DeviceReplacementOutcome {
        binding,
        status: match state {
            sdk::AnchorDeviceReplacementState::Committed => DeviceReplacementStatus::Committed,
            sdk::AnchorDeviceReplacementState::Unavailable => DeviceReplacementStatus::Unavailable,
        },
    }
}

struct Predecessor {
    subject: sdk::AnchorSubject,
    checkpoint: sdk::RosterCheckpoint,
    policy: sdk::HistoricalSessionPolicy,
}
impl DeviceReplacementTrust {
    fn predecessors(&self, pin: &sdk::AnchorPin) -> Result<Vec<Predecessor>> {
        if self.schema != "qperiapt-witness-device-replacement-trust/1"
            || self.predecessors.is_empty()
            || self.predecessors.len() > 256
        {
            return Err("Device replacement trust schema or predecessor capacity differs".into());
        }
        self.predecessors
            .iter()
            .map(|old| {
                let (policy, witness) = old
                    .policy
                    .pins
                    .verify_historical(&old.policy.materials, self.successor.account.family)?;
                if witness.as_ref().map(|p| p.binding()) != Some(pin.binding()) {
                    return Err("Replacement predecessor uses another witness".into());
                }
                Ok(Predecessor {
                    subject: sdk::AnchorSubject::from_trusted_state(&old.subject)?,
                    checkpoint: old.checkpoint.as_sdk()?,
                    policy,
                })
            })
            .collect()
    }
}

pub(super) fn prepare(
    store: &mut sdk::AnchorStore,
    trust: &DeviceReplacementTrust,
    request: &EnrollmentRequest,
    now: u64,
) -> Result<DeviceReplacementDecision> {
    let pin = store.pin()?;
    let previous = trust.predecessors(&pin)?;
    let proofs: Vec<_> = previous
        .iter()
        .map(|p| (p.subject, p.checkpoint, &p.policy))
        .collect();
    let (genesis, next, policy) = trust.successor.inputs(&pin, request, now)?;
    DeviceReplacementDecision::from_sdk(
        store.device_replacement_proposal(&genesis, &next, &policy, &proofs, now)?,
    )
}

pub(super) fn commit(
    store: &mut sdk::AnchorStore,
    trust: &DeviceReplacementTrust,
    request: &EnrollmentRequest,
    decision: &DeviceReplacementDecision,
    now: u64,
) -> Result<DeviceReplacementOutcome> {
    let proposal = decision.as_sdk()?;
    let pin = store.pin()?;
    let previous = trust.predecessors(&pin)?;
    let proofs: Vec<_> = previous
        .iter()
        .map(|p| (p.subject, p.checkpoint, &p.policy))
        .collect();
    let (genesis, next, policy) = trust.successor.inputs(&pin, request, now)?;
    let state = store.replace_device(&proposal, &genesis, &next, &policy, &proofs, now)?;
    #[cfg(test)]
    boundary("witness-device-replacement-committed")?;
    Ok(outcome(decision.binding, state))
}

pub(super) fn status(
    store: &mut sdk::AnchorStore,
    decision: &DeviceReplacementDecision,
) -> Result<DeviceReplacementOutcome> {
    Ok(outcome(
        decision.binding,
        store.device_replacement_status(&decision.as_sdk()?)?,
    ))
}
