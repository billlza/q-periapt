// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted local P approval. Network input cannot select issuer trust or target.
use super::*;
use crate::{
    enrollment::RootInfo,
    policy_publisher::PolicyInput,
    policy_renewal::{
        witness::{Outcome, Preparation},
        Request, VerifiedPolicyIdentities,
    },
};

/// The operator selects this complete request, original subject and proposal
/// binding independently. A device export is not authorization to populate it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRenewalTrust {
    pub schema: String,
    pub account: RootInfo,
    pub device: [u8; 16],
    pub generation: u64,
    #[serde(with = "crate::enrollment::wire")]
    pub subject: Vec<u8>,
    pub proposal_binding: [u8; 32],
    pub request: Request,
    pub original: PolicyInput,
    pub previous: PolicyInput,
    pub target: PolicyInput,
}
impl PolicyRenewalTrust {
    fn inputs(
        &self,
        preparation: &Preparation,
        witness: &sdk::AnchorPin,
        now: Option<u64>,
    ) -> Result<(sdk::AnchorPolicyRenewalProposal, VerifiedPolicyIdentities)> {
        let p = preparation.as_proposal()?;
        if self.schema != "qperiapt-witness-policy-renewal-trust/1"
            || p.subject() != sdk::AnchorSubject::from_trusted_state(&self.subject)?
            || p.binding() != self.proposal_binding
            || p.witness_binding() != witness.binding()
            || p.operation().as_bytes() != &self.request.scope.operation
        {
            return Err("Policy proposal differs from independent operator approval".into());
        }
        let identities = match now {
            Some(now) => self.request.verify_identities(&self.account, now)?,
            None => self.request.verify_historical_identities(&self.account)?,
        };
        Ok((p, identities))
    }
    fn historical(
        &self,
        input: &PolicyInput,
        witness: &sdk::AnchorPin,
    ) -> Result<sdk::HistoricalSessionPolicy> {
        let (policy, selected) = input
            .pins
            .verify_historical(&input.materials, self.account.family)?;
        if selected.as_ref().map(|p| p.binding()) != Some(witness.binding()) {
            return Err("Selected policy requires another witness".into());
        }
        Ok(policy)
    }
    fn device(&self, m: &sdk::HistoricalPolicyRenewalMaterials<'_>) -> Result<()> {
        if [m.original_device, m.current_device]
            .iter()
            .any(|d| d.device_id() != self.device || d.generation() != self.generation)
        {
            return Err("Policy identity differs from independently selected device".into());
        }
        Ok(())
    }
}
pub(super) fn prepare(
    store: &mut sdk::AnchorStore,
    trust: &PolicyRenewalTrust,
    preparation: &Preparation,
    now: u64,
) -> Result<Outcome> {
    if trust.account.suspended {
        return Err("Selected policy account is suspended".into());
    }
    let witness = store.pin()?;
    let (p, identities) = trust.inputs(preparation, &witness, Some(now))?;
    let original = trust.historical(&trust.original, &witness)?;
    let previous = trust.historical(&trust.previous, &witness)?;
    let (target, selected) =
        trust
            .target
            .pins
            .verify(&trust.target.materials, trust.account.family, now)?;
    if selected.as_ref().map(|p| p.binding()) != Some(witness.binding()) {
        return Err("Target policy requires another witness".into());
    }
    let materials = identities.materials(&original, &previous, &target);
    trust.device(&identities.historical_materials(&original, &previous, target.historical()))?;
    let approval = sdk::VerifiedPolicyRenewal::from_bytes(
        &preparation.approval,
        identities.scope(),
        &materials,
        now,
    )?;
    let state = store.prepare_policy_renewal(p, &approval, &materials, now)?;
    #[cfg(test)]
    boundary("witness-policy-prepared")?;
    Ok(Outcome::new(preparation, state))
}
pub(super) fn close(
    store: &mut sdk::AnchorStore,
    trust: &PolicyRenewalTrust,
    preparation: &Preparation,
) -> Result<Outcome> {
    let witness = store.pin()?;
    let (p, identities) = trust.inputs(preparation, &witness, None)?;
    let original = trust.historical(&trust.original, &witness)?;
    let previous = trust.historical(&trust.previous, &witness)?;
    let target = trust.historical(&trust.target, &witness)?;
    let materials = identities.historical_materials(&original, &previous, &target);
    trust.device(&materials)?;
    let approval = sdk::HistoricalPolicyRenewal::from_bytes(
        &preparation.approval,
        identities.scope(),
        &materials,
    )?;
    let state = store.close_policy_renewal(p, &approval, &materials)?;
    #[cfg(test)]
    boundary("witness-policy-closed")?;
    Ok(Outcome::new(preparation, state))
}
