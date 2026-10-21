// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public wrappers for independently selected native root-replacement records.
use super::*;

/// Selected by the trusted operator, never derived from the device preparation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRootTrust {
    pub schema: String,
    pub operation: [u8; 32],
    pub freeze_operation: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub previous_root: Vec<u8>,
    pub successor: EnrollmentTrust,
}
impl AccountRootTrust {
    pub(super) fn selected(
        &self,
        pin: &sdk::AnchorPin,
    ) -> Result<(
        sdk::AnchorAccountReplacementId,
        sdk::PublicKey,
        sdk::AnchorAccountFreezeRequest,
    )> {
        if self.schema != "qperiapt-witness-account-root-trust/1"
            || self.operation == self.freeze_operation
        {
            return Err("Account root trust schema or distinct operation IDs differ".into());
        }
        let root = sdk::PublicKey::decode(&self.previous_root)?;
        let request = sdk::AnchorAccountFreezeRequest::from_trusted_state(
            sdk::AnchorAccountFreezeId::from_trusted_state(self.freeze_operation)?,
            root.clone(),
            pin,
        )?;
        Ok((
            sdk::AnchorAccountReplacementId::from_trusted_state(self.operation)?,
            root,
            request,
        ))
    }
}

/// Retain and independently approve this original plan before freezing authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRootPlan {
    pub schema: String,
    pub binding: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub plan: Vec<u8>,
}
impl AccountRootPlan {
    pub(super) fn from_sdk(plan: sdk::AnchorAccountReplacementPlan) -> Result<Self> {
        Ok(Self {
            schema: "qperiapt-witness-account-root-plan/1".into(),
            binding: plan.binding()?,
            plan: plan.to_bytes()?,
        })
    }
    pub(super) fn as_sdk(&self) -> Result<sdk::AnchorAccountReplacementPlan> {
        if self.schema != "qperiapt-witness-account-root-plan/1" {
            return Err("Account root plan schema differs".into());
        }
        let plan = sdk::AnchorAccountReplacementPlan::from_trusted_state(&self.plan)?;
        if plan.binding()? != self.binding || plan.to_bytes()? != self.plan {
            return Err("Account root plan binding differs".into());
        }
        Ok(plan)
    }
}

/// Exact original frozen snapshot and target, not a new authorization source.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRootDecision {
    pub schema: String,
    pub plan_binding: [u8; 32],
    pub binding: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub proposal: Vec<u8>,
}
impl AccountRootDecision {
    pub(super) fn from_sdk(
        plan_binding: [u8; 32],
        proposal: sdk::AnchorAccountReplacementProposal,
    ) -> Result<Self> {
        Ok(Self {
            schema: "qperiapt-witness-account-root-decision/1".into(),
            plan_binding,
            binding: proposal.binding()?,
            proposal: proposal.to_bytes()?,
        })
    }
    pub(super) fn as_sdk(&self) -> Result<sdk::AnchorAccountReplacementProposal> {
        if self.schema != "qperiapt-witness-account-root-decision/1" || self.plan_binding == [0; 32]
        {
            return Err("Account root decision schema differs".into());
        }
        let proposal = sdk::AnchorAccountReplacementProposal::from_trusted_state(&self.proposal)?;
        if proposal.binding()? != self.binding || proposal.to_bytes()? != self.proposal {
            return Err("Account root decision binding differs".into());
        }
        Ok(proposal)
    }
}

/// Every terminal proof is historical; none releases a current traffic owner.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum AccountRootOutcome {
    Unavailable {
        binding: [u8; 32],
    },
    Committed {
        binding: [u8; 32],
        #[serde(with = "crate::enrollment::wire")]
        receipt: Vec<u8>,
    },
    Closed {
        binding: [u8; 32],
        #[serde(with = "crate::enrollment::wire")]
        receipt: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRootFreeze {
    pub plan_binding: [u8; 32],
    pub freeze_binding: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub receipt: Vec<u8>,
}
