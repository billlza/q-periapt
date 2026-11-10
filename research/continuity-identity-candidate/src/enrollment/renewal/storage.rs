// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original renewal database leases use the enrollment's retained platform storage.
use super::*;
use crate::{DeviceJournal, HistoricalSessionPolicy};

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    pub(super) async fn inspect_original_credential_intent(
        &self,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
    ) -> Result<Option<WitnessedCredentialIntent>, DurableError> {
        self.inspect_original_credential_intent_using(original, policy, id, None)
            .await
    }
    pub(super) async fn inspect_original_credential_intent_using(
        &self,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        client: Option<&AnchorClient>,
    ) -> Result<Option<WitnessedCredentialIntent>, DurableError> {
        self.check_witness_client(client)?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        DeviceJournal::inspect_witnessed_credential_intent_in_database(
            &db,
            &self.key().await?,
            original,
            policy,
            id,
            client,
        )
    }
    pub(super) async fn reserve_original_credential_cancellation(
        &mut self,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        target: crate::durable::CredentialCancellationTarget<'_>,
        plan: Option<&crate::WitnessJournalAdoptionPlan>,
    ) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
        if let Some(plan) = plan {
            let mut child = self
                .selected_cancellation_journal(policy, plan.clone())
                .await?;
            return child.reserve_credential_cancellation(original, policy, id, target);
        }
        self.check_witness_client(None)?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        let key = self.key().await?;
        if target.continuation.is_some() || target.independent.is_some() {
            DeviceJournal::reserve_bound_cancellation_in_database(
                &db, &key, original, policy, id, target,
            )
        } else {
            DeviceJournal::reserve_credential_cancellation_in_database(
                &db,
                &key,
                original,
                policy,
                id,
                target.grant,
                target.completed,
            )
        }
    }
    pub(super) async fn recover_original_credential_intent(
        &self,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        intent: WitnessedCredentialIntent,
        client: &mut AnchorClient,
    ) -> Result<crate::AnchorCredentialRenewalState, DurableError> {
        self.check_witness_client(Some(client))?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        DeviceJournal::recover_witnessed_credential_intent_in_database(
            &db,
            &self.key().await?,
            original,
            policy,
            id,
            intent,
            client,
        )
        .await
    }
    pub(super) async fn retire_original_credential_intent(
        &self,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        terminal: &PersistedRenewalTerminal,
        client: &mut AnchorClient,
    ) -> Result<(), DurableError> {
        self.check_witness_client(Some(client))?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        DeviceJournal::retire_witnessed_credential_intent_in_database(
            &db,
            &self.key().await?,
            original,
            policy,
            id,
            terminal,
            client,
        )
        .await
    }
}
