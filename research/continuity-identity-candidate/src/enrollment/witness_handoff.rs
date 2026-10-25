// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bind the current witness to the original parent and its retained signer.
use super::*;
use crate::{
    HistoricalSessionPolicy, WitnessJournalAdoption, WitnessJournalAdoptionPlan,
    WitnessJournalAdoptionState,
};
use redb::ReadableTable;
mod codec;
pub(super) use codec::State;
pub(super) const ROW: &str = "witness-handoff";

// A cancelled polled browser operation closes the parent just like an error.
struct Attempt<'a> {
    owner: &'a mut DeviceEnrollment,
    success: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.success {
            self.owner.close();
        }
    }
}
impl DeviceEnrollment {
    pub(super) fn witness_selection(&self) -> Result<Option<State>, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, self.binding)?;
        if snapshot.retirement.is_some() || snapshot.root_replacement.is_some() {
            return Err(DurableError::Suspended);
        }
        Ok(snapshot.witness_handoff)
    }
    pub(super) fn check_witness_client(
        &self,
        client: Option<&AnchorClient>,
    ) -> Result<(), DurableError> {
        match self.witness_selection()? {
            Some(state) => client
                .ok_or(DurableError::Suspended)?
                .check_journal_selection(
                    &state.request,
                    state.receipt.as_deref().ok_or(DurableError::Suspended)?,
                )
                .map_err(Into::into),
            None if client.is_some_and(AnchorClient::is_transferred) => {
                Err(DurableError::Suspended)
            }
            None => Ok(()),
        }
    }
    fn witness_handoff_scope(
        &self,
        image: &Image,
        policy: &HistoricalSessionPolicy,
        plan: &WitnessJournalAdoptionPlan,
    ) -> Result<(VerifiedDevice, JournalIdentity), DurableError> {
        let Phase::Accepted {
            admission, stage, ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        if !matches!(
            stage,
            AdmissionPhase::Active
                | AdmissionPhase::Refreshing { .. }
                | AdmissionPhase::RosterResolved { .. }
        ) || admission.policy != policy.checkpoint().digest()
        {
            return Err(DurableError::Conflict);
        }
        let original = self.original_device_metadata(image)?;
        plan.check_original_enrollment(&original, policy, admission.journal)?;
        Ok((original, admission.journal))
    }
    fn save_witness_selection(
        &self,
        previous: Option<&State>,
        next: &State,
    ) -> Result<(), DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let before = previous
            .map(|s| s.encode(&active.key, self.binding))
            .transpose()?;
        let after = next.encode(&active.key, self.binding)?;
        if before.as_deref() == Some(after.as_slice()) {
            return Ok(());
        }
        let tx = transaction(&active.database)?;
        {
            let mut table = tx.open_table(TABLE).map_err(storage)?;
            if table.len().map_err(storage)? != 1 + u64::from(previous.is_some())
                || table.get(ROW).map_err(storage)?.as_ref().map(|r| r.value()) != before.as_deref()
            {
                return Err(DurableError::Conflict);
            }
            let saved = table
                .get("enrollment")
                .map_err(storage)?
                .ok_or(DurableError::Corrupt)?;
            next.check_image(&decode_image(saved.value(), &active.key, self.binding)?)?;
            drop(saved);
            table.insert(ROW, after.as_slice()).map_err(storage)?;
        }
        #[cfg(all(test, unix))]
        tests::witness_selection_boundary(
            if next.receipt.is_some() {
                "parent-adopt"
            } else {
                "parent-prepare"
            },
            false,
        );
        tx.commit().map_err(DurableError::CommitUncertain)?;
        #[cfg(all(test, unix))]
        tests::witness_selection_boundary(
            if next.receipt.is_some() {
                "parent-adopt"
            } else {
                "parent-prepare"
            },
            true,
        );
        if self.witness_selection()?.as_ref() != Some(next) {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn retain_witness_child(
        &self,
        image: &Image,
        plan: &WitnessJournalAdoptionPlan,
        previous: Option<&State>,
        child: &WitnessJournalAdoption,
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let progress = child.enrollment_selection()?;
        if let Some(old) = previous {
            old.check_plan(plan)?;
            old.check_child(&progress)?;
        }
        let next = State {
            identity: image.identity,
            request: plan.authorization_request().to_vec(),
            prepared_at: progress.0,
            receipt: progress.1,
        };
        next.check_image(image)?;
        self.save_witness_selection(previous, &next)?;
        Ok(next.status())
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Prepare or reconcile the same independently approved witness selection on
    /// the existing installation. Child preparation precedes parent publication;
    /// no current client is released until both agree. Once the parent records a
    /// selection, a missing child control row is never recreated. Exact historical
    /// retries retain the first decision; this does not extend traffic permission.
    pub async fn prepare_witness_handoff(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
        trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let mut attempt = Attempt {
            owner: self,
            success: false,
        };
        let result = attempt
            .owner
            .prepare_witness_handoff_attempt(original_policy, plan, trusted_time)
            .await;
        attempt.success = result.is_ok();
        result
    }
    async fn prepare_witness_handoff_attempt(
        &mut self,
        policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
        trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let image = self.image()?;
        let (original, id) = self.witness_handoff_scope(&image, policy, &plan)?;
        State::reserve_capacity(plan.authorization_request().len())?;
        let previous = self.witness_selection()?;
        if let Some(old) = &previous {
            old.check_plan(&plan)?;
        }
        let _installation = self.witness_lease(&original, policy, id).await?;
        let key = self.key().await?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        let child = if previous.is_some() {
            WitnessJournalAdoption::resume_in_database(db, key, plan.clone())?
        } else {
            WitnessJournalAdoption::prepare_in_database(db, key, plan.clone(), trusted_time)?
        };
        self.retain_witness_child(&image, &plan, previous.as_ref(), &child)
    }
    /// Durably adopt one exact target receipt in child then parent. A failure may
    /// follow either commit; retry this original plan and receipt after reopening.
    /// No original G/P/R operation is committed, cancelled or acknowledged here.
    pub async fn adopt_witness_handoff(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
        receipt: &[u8],
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let mut attempt = Attempt {
            owner: self,
            success: false,
        };
        let result = attempt
            .owner
            .adopt_witness_handoff_attempt(original_policy, plan, receipt)
            .await;
        attempt.success = result.is_ok();
        result
    }
    async fn adopt_witness_handoff_attempt(
        &mut self,
        policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
        receipt: &[u8],
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let image = self.image()?;
        let (original, id) = self.witness_handoff_scope(&image, policy, &plan)?;
        let previous = self.witness_selection()?.ok_or(DurableError::Absent)?;
        previous.check_plan(&plan)?;
        let _installation = self.witness_lease(&original, policy, id).await?;
        let key = self.key().await?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        let mut child = WitnessJournalAdoption::resume_in_database(db, key, plan.clone())?;
        previous.check_child(&child.enrollment_selection()?)?;
        child.adopt_authorization(receipt)?;
        self.retain_witness_child(&image, &plan, Some(&previous), &child)
    }
    /// Read the parent checkpoint and its original child without a signing key.
    /// Prepared can include a child commit whose parent response was lost. Resume
    /// that exact preparation/adoption to finish it; status never writes repairs.
    pub async fn witness_handoff_status(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let mut attempt = Attempt {
            owner: self,
            success: false,
        };
        let result = attempt
            .owner
            .witness_handoff_status_attempt(original_policy, plan)
            .await;
        attempt.success = result.is_ok();
        result
    }
    async fn witness_handoff_status_attempt(
        &mut self,
        policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let image = self.image()?;
        let (original, id) = self.witness_handoff_scope(&image, policy, &plan)?;
        let selected = self.witness_selection()?.ok_or(DurableError::Absent)?;
        selected.check_plan(&plan)?;
        let _installation = self.witness_lease(&original, policy, id).await?;
        let key = self.key().await?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        let child = WitnessJournalAdoption::resume_in_database(db, key, plan)?;
        selected.check_child(&child.enrollment_selection()?)?;
        Ok(selected.status())
    }
    /// Construct the selected current-witness carrier using this enrollment's
    /// existing protected signer. Both persisted checkpoints must already agree;
    /// signer/child absence is an error, never first-use provisioning. Each later
    /// lifecycle command and operational release still enforces current authority.
    pub async fn current_witness_anchor_client(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        let mut attempt = Attempt {
            owner: self,
            success: false,
        };
        let result = attempt
            .owner
            .current_witness_anchor_client_attempt(original_policy, plan, transport, timeout)
            .await;
        attempt.success = result.is_ok();
        result
    }
    async fn current_witness_anchor_client_attempt(
        &mut self,
        policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        let image = self.image()?;
        let (original, id) = self.witness_handoff_scope(&image, policy, &plan)?;
        let selected = self.witness_selection()?.ok_or(DurableError::Absent)?;
        selected.check_plan(&plan)?;
        if selected.receipt.is_none() {
            return Err(DurableError::Suspended);
        }
        let _installation = self.witness_lease(&original, policy, id).await?;
        let key = self.key().await?;
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        let mut child = WitnessJournalAdoption::resume_in_database(db, key, plan)?;
        selected.check_child(&child.enrollment_selection()?)?;
        let signer = self.signer(image.identity, false).await?;
        signer.check_device(&original)?;
        child.attach_current_witness(signer, transport, timeout)?;
        let client = child.into_current_witness()?;
        self.check_witness_client(Some(&client))?;
        Ok(client)
    }
}
