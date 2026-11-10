// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent operator admission of G, including G under an acknowledged P.
use super::*;
use crate::{
    credential_grant::{
        witness::{Outcome, Preparation},
        IssuedCredentialGrant,
    },
    enrollment::RootInfo,
    policy_publisher::PolicyInput,
};

/// Explicit policy lineage. An independent P must already be retained and
/// acknowledged by this witness; the declaration itself never adopts it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialPolicy {
    Original,
    Independent { statement: [u8; 32] },
}
/// Select through the authenticated operator channel. The original subject and
/// full proposal binding must come from the retained enrollment/approved intent.
/// They cannot be chosen by the incoming device proposal or grant response.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRenewalTrust {
    pub schema: String,
    pub account: RootInfo,
    pub enrollment: [u8; 32],
    pub operation: [u8; 32],
    pub statement: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub subject: Vec<u8>,
    pub proposal_binding: [u8; 32],
    pub lineage: CredentialPolicy,
    pub original: PolicyInput,
    pub policy: PolicyInput,
}
impl CredentialRenewalTrust {
    fn inputs(
        &self,
        preparation: &Preparation,
        issued: &IssuedCredentialGrant,
        witness: &sdk::AnchorPin,
    ) -> Result<(sdk::AnchorCredentialRenewalProposal, sdk::AccountPin)> {
        let p = preparation.as_proposal()?;
        if self.schema != "qperiapt-witness-credential-renewal-trust/1"
            || p.subject() != sdk::AnchorSubject::from_trusted_state(&self.subject)?
            || p.binding() != self.proposal_binding
            || p.witness_binding() != witness.binding()
            || p.operation().as_bytes() != &self.operation
            || p.statement() != self.statement
            || issued.enrollment != self.enrollment
            || self.enrollment == [0; 32]
            || issued.root_revision != self.account.revision
            || self.account.revision == 0
            || issued.operation != self.operation
            || issued.statement != self.statement
            || issued.journal != preparation.journal
            || p.policy_continuation().is_some()
            || p.adopts_policy()
        {
            return Err("Credential proposal differs from independent operator selection".into());
        }
        let expected = match self.lineage {
            CredentialPolicy::Original => None,
            CredentialPolicy::Independent { statement } => Some(statement),
        };
        if p.policy_renewal() != expected {
            return Err("Credential proposal changes the selected policy lineage".into());
        }
        let roster = self
            .account
            .roster
            .as_ref()
            .ok_or("Selected target roster is required")?;
        if roster.checkpoint != issued.checkpoint {
            return Err("Credential grant target differs from selected account".into());
        }
        let pin = sdk::AccountPin::new(
            self.account.account,
            sdk::PublicKey::decode(&self.account.public_key)?,
            roster.checkpoint.as_sdk()?,
            self.account.family,
        )?;
        pin.verify_historical_roster(&roster.bytes)?;
        Ok((p, pin))
    }
    fn original(&self, witness: &sdk::AnchorPin) -> Result<sdk::HistoricalSessionPolicy> {
        let (policy, pin) = self
            .original
            .pins
            .verify_historical(&self.original.materials, self.account.family)?;
        self.witness(pin.as_ref(), witness)?;
        Ok(policy)
    }
    fn witness(&self, pin: Option<&sdk::AnchorPin>, witness: &sdk::AnchorPin) -> Result<()> {
        if pin.map(|p| p.binding()) != Some(witness.binding()) {
            return Err("Credential policy selects another witness".into());
        }
        Ok(())
    }
    fn policy(
        &self,
        original: &sdk::HistoricalSessionPolicy,
        current: &sdk::HistoricalSessionPolicy,
    ) -> Result<()> {
        match self.lineage {
            CredentialPolicy::Original if current.checkpoint() == original.checkpoint() => Ok(()),
            CredentialPolicy::Independent { statement }
                if statement != [0; 32]
                    && current.checkpoint().version() > original.checkpoint().version() =>
            {
                Ok(())
            }
            _ => Err("Selected credential policy lineage differs".into()),
        }
    }
    fn grant(
        &self,
        p: sdk::AnchorCredentialRenewalProposal,
        g: &sdk::HistoricalCredentialRenewal,
    ) -> Result<()> {
        if g.operation().as_bytes() != &self.operation
            || g.statement_digest() != self.statement
            || p.subject().to_bytes().get(32..64) != Some(g.original_storage_owner().as_slice())
        {
            return Err("Root grant does not authorize the original selected owner".into());
        }
        Ok(())
    }
}
pub(super) fn prepare(
    store: &mut sdk::AnchorStore,
    trust: &CredentialRenewalTrust,
    preparation: &Preparation,
    issued: &IssuedCredentialGrant,
    now: u64,
) -> Result<Outcome> {
    if trust.account.suspended {
        return Err("Selected credential account is suspended".into());
    }
    let witness = store.pin()?;
    let (p, pin) = trust.inputs(preparation, issued, &witness)?;
    let original = trust.original(&witness)?;
    let (policy, selected) =
        trust
            .policy
            .pins
            .verify(&trust.policy.materials, trust.account.family, now)?;
    trust.witness(selected.as_ref(), &witness)?;
    trust.policy(&original, policy.historical())?;
    let grant = sdk::VerifiedCredentialRenewal::verify(
        &issued.grant,
        &pin,
        original.checkpoint().digest(),
        now,
    )?;
    trust.grant(p, grant.historical())?;
    let state = match trust.lineage {
        CredentialPolicy::Original => store.prepare_credential_renewal(p, &grant, &policy, now)?,
        CredentialPolicy::Independent { .. } => {
            store.prepare_policy_renewed_credential_renewal(p, &grant, &original, &policy, now)?
        }
    };
    #[cfg(test)]
    boundary("witness-credential-prepared")?;
    Ok(Outcome::new(p, state))
}
pub(super) fn close(
    store: &mut sdk::AnchorStore,
    trust: &CredentialRenewalTrust,
    preparation: &Preparation,
    issued: &IssuedCredentialGrant,
) -> Result<Outcome> {
    let witness = store.pin()?;
    let (p, pin) = trust.inputs(preparation, issued, &witness)?;
    let original = trust.original(&witness)?;
    let (policy, selected) = trust
        .policy
        .pins
        .verify_historical(&trust.policy.materials, trust.account.family)?;
    trust.witness(selected.as_ref(), &witness)?;
    trust.policy(&original, &policy)?;
    let grant = sdk::HistoricalCredentialRenewal::verify(
        &issued.grant,
        &pin,
        original.checkpoint().digest(),
    )?;
    trust.grant(p, &grant)?;
    let state = match trust.lineage {
        CredentialPolicy::Original => store.close_credential_renewal(p, &grant, &policy)?,
        CredentialPolicy::Independent { .. } => {
            store.close_policy_renewed_credential_renewal(p, &grant, &original, &policy)?
        }
    };
    #[cfg(test)]
    boundary("witness-credential-closed")?;
    Ok(Outcome::new(p, state))
}
