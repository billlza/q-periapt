// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact target-free closure under one committed target authorization.
use super::*;
use crate::{
    AnchorCredentialCancellationState, AnchorCredentialRenewalCancellation,
    HistoricalCredentialRenewal, HistoricalPolicyContinuation,
    HistoricalPolicyContinuationMaterials,
};

impl AnchorTransferredControl<'_> {
    /// Close an independently approved original G without inventing a target.
    /// Existing proposal history still conflicts, and version floors survive ACK.
    pub fn close_unprepared_credential_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        self.store.close_unprepared_renewal_controlled(
            self.scope.bind(cancellation, cancellation.subject())?,
            grant,
            policy,
            None,
            None,
        )
    }
    /// Close the original jointly approved G/T, preserving its exact T binding.
    pub fn close_unprepared_policy_continuation(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        continuation: &HistoricalPolicyContinuation,
        materials: &HistoricalPolicyContinuationMaterials<'_>,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        if !cancellation.adopts_policy() {
            return Err(DurableError::Conflict);
        }
        let checked = HistoricalPolicyContinuation::from_bytes(
            continuation.as_bytes(),
            continuation.scope(),
            materials,
        )?;
        self.store.close_unprepared_renewal_controlled(
            self.scope.bind(cancellation, cancellation.subject())?,
            materials.credential,
            materials.original,
            Some((&checked, materials.target)),
            None,
        )
    }
    /// Close a later G without discarding the independently adopted T.
    pub fn close_unprepared_continued_credential_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &HistoricalCredentialRenewal,
        original: &HistoricalSessionPolicy,
        retained: &HistoricalPolicyContinuation,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        if cancellation.adopts_policy() {
            return Err(DurableError::Conflict);
        }
        self.store.close_unprepared_renewal_controlled(
            self.scope.bind(cancellation, cancellation.subject())?,
            grant,
            original,
            Some((retained, policy)),
            None,
        )
    }
    /// Close a later G while retaining its acknowledged independent P.
    pub fn close_unprepared_policy_renewed_credential_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &HistoricalCredentialRenewal,
        original: &HistoricalSessionPolicy,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        if cancellation.policy_renewal().is_none() {
            return Err(DurableError::Conflict);
        }
        self.store.close_unprepared_renewal_controlled(
            self.scope.bind(cancellation, cancellation.subject())?,
            grant,
            original,
            None,
            Some(policy),
        )
    }
}
