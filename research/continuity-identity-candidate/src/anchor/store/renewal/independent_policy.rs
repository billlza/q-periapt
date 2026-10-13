// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A later G carries the exact independently adopted P without adopting T.
use super::*;

impl Entry {
    pub(super) fn retained_independent_policy(
        &self,
        statement: [u8; 32],
        target: &HistoricalSessionPolicy,
    ) -> Result<PolicyAuthority, DurableError> {
        let state = self
            .independent_policy
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        let retained = state.current.ok_or(DurableError::Conflict)?;
        if state.pending()
            || self.policy_authorization.is_some()
            || retained.statement != statement
            || retained.checkpoint != target.checkpoint()
            || retained.validity != target.validity()
        {
            return Err(DurableError::Conflict);
        }
        Ok(retained)
    }
}

impl AnchorStore {
    /// Independently prepare G under an already applied and acknowledged P.
    /// The proposal must name the witness's exact retained P; P0 remains the
    /// immutable journal scope. This does not adopt a policy or release an owner.
    pub fn prepare_policy_renewed_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        original: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        if proposal.policy_renewal().is_none() {
            return Err(DurableError::Conflict);
        }
        self.retain_credential_renewal(
            proposal,
            grant.as_ref(),
            original,
            policy.historical(),
            Some((policy, now)),
            None,
        )
    }

    /// Close the exact original G under retained P using historical inputs.
    /// An applied G remains Applied, including after C or P expiry.
    pub fn close_policy_renewed_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &impl AsRef<HistoricalCredentialRenewal>,
        original: &HistoricalSessionPolicy,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        if proposal.policy_renewal().is_none() {
            return Err(DurableError::Conflict);
        }
        self.retain_credential_renewal(proposal, grant.as_ref(), original, policy, None, None)
    }

    /// Close an exact G with no sealed proposal, retaining the acknowledged P.
    /// Existing proposal history conflicts rather than being called uncommitted.
    pub fn close_unprepared_policy_renewed_credential_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &impl AsRef<HistoricalCredentialRenewal>,
        original: &HistoricalSessionPolicy,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        if cancellation.policy_renewal().is_none() {
            return Err(DurableError::Conflict);
        }
        self.close_unprepared_renewal(cancellation, grant.as_ref(), original, None, Some(policy))
    }
}
