// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete original inventory projection and independently approved report retention.
use super::*;
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl RetiredInstallationRecovery {
    /// Prepare the complete report, then retain its exact expectation in the independent
    /// installation before returning a dispatchable proposal. An existing request is
    /// recovered without rereading a backup; full report release still requires all data.
    pub async fn prepare_report(
        &mut self,
        retained: &AnchorRetiredCleanup,
    ) -> Result<crate::AnchorRetiredReportProposal, DurableError> {
        let result = self.prepare_report_attempt(retained).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn prepare_report_attempt(
        &mut self,
        retained: &AnchorRetiredCleanup,
    ) -> Result<crate::AnchorRetiredReportProposal, DurableError> {
        if self.proposal()? != *retained.proposal() {
            return Err(DurableError::Conflict);
        }
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let saved = read_configuration(&owners.configuration)?;
        let control = owners.control(&saved)?;
        if let Some(control) = &control {
            AnchorRetiredCleanup::from_transferred(
                control.verified(CleanupStage::Inventory)?,
                &owners.proposal,
            )?;
        }
        if let Some(proposal) = saved.retired_report {
            return Ok(proposal);
        }
        let mut archives = crate::SessionArchiveStore::open_with_storage(
            owners.storage.clone(),
            &owners.paths.archives,
            saved.identity,
        )
        .await?;
        let journal = owners.storage.open_database(&owners.paths.journal).await?;
        let report = DeviceJournal::retired_report_in_database(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            retained,
            &mut archives,
            owners.context.as_deref(),
        )?;
        drop(journal);
        let proposal = report.proposal().clone();
        let next_control = control
            .as_ref()
            .map(|c| c.with_report(&proposal)?.encode(&owners.key))
            .transpose()?;
        let tx = transaction(&owners.configuration)?;
        {
            let mut table = tx.open_table(TABLE).map_err(storage)?;
            let expected = request_wire(&owners.proposal, saved.retired_context);
            if table.len().map_err(storage)? != 2 + u64::from(control.is_some())
                || table
                    .get("retired-cleanup")
                    .map_err(storage)?
                    .as_ref()
                    .map(|v| v.value())
                    != Some(expected.as_slice())
                || table.get("retired-report").map_err(storage)?.is_some()
                || table
                    .get("retired-authority")
                    .map_err(storage)?
                    .as_ref()
                    .map(|v| v.value())
                    != saved.retired_control.as_deref()
            {
                return Err(DurableError::Conflict);
            }
            table
                .insert("retired-report", proposal.to_bytes().as_slice())
                .map_err(storage)?;
            if let Some(wire) = &next_control {
                table
                    .insert("retired-authority", wire.as_slice())
                    .map_err(storage)?;
            }
        }
        #[cfg(all(test, unix))]
        super::super::tests::at_boundary("retired-report-before-commit");
        tx.commit().map_err(DurableError::CommitUncertain)?;
        #[cfg(all(test, unix))]
        super::super::tests::at_boundary("retired-report-after-commit");
        Ok(proposal)
    }
    /// Read only the original independently saved report request, including after data loss.
    /// None means no saved request in this configuration, never witness non-commit.
    pub fn report_proposal(
        &mut self,
    ) -> Result<Option<crate::AnchorRetiredReportProposal>, DurableError> {
        let result = (|| {
            self.proposal()?;
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            Ok(read_configuration(&owners.configuration)?.retired_report)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Release the complete metadata only after verifying independent retention of this
    /// exact saved report. Missing archives/data or changed inventory fails explicitly.
    /// This never acknowledges host effects or authorizes logical erasure.
    pub async fn report(
        &mut self,
        retained: &AnchorRetiredCleanup,
        pin: &AnchorPin,
        receipt: &[u8],
    ) -> Result<crate::retired_device::Report, DurableError> {
        let result = self.report_attempt(retained, pin, receipt).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn report_attempt(
        &mut self,
        retained: &AnchorRetiredCleanup,
        pin: &AnchorPin,
        receipt: &[u8],
    ) -> Result<crate::retired_device::Report, DurableError> {
        let proposal = self.report_proposal()?.ok_or(DurableError::Suspended)?;
        self.verify_report_retention(retained, pin, receipt)?;
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let saved = read_configuration(&owners.configuration)?;
        let control = owners.control(&saved)?;
        let authority = owners.proof_authority(pin, control.as_ref())?;
        let journal = owners.storage.open_database(&owners.paths.journal).await?;
        if DeviceJournal::retired_journal_has_terminal(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            authority,
            &proposal,
        )? {
            return Err(Error::Retired.into());
        }
        let mut archives = crate::SessionArchiveStore::open_with_storage(
            owners.storage.clone(),
            &owners.paths.archives,
            saved.identity,
        )
        .await?;
        let report = DeviceJournal::retired_report_in_database(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            retained,
            &mut archives,
            owners.context.as_deref(),
        )?;
        if report.proposal() != &proposal {
            return Err(DurableError::Conflict);
        }
        Ok(report)
    }
    /// Verify retention of this installation's exact saved report. In transferred
    /// recovery the independently prepared approval and verified receipt are
    /// retained before returning. This does not acknowledge host effects or erase.
    pub fn verify_report_retention(
        &mut self,
        retained: &AnchorRetiredCleanup,
        pin: &AnchorPin,
        wire: &[u8],
    ) -> Result<crate::AnchorRetiredReport, DurableError> {
        let result = (|| {
            if self.proposal()? != *retained.proposal() {
                return Err(DurableError::Conflict);
            }
            let expected = self.report_proposal()?.ok_or(DurableError::Suspended)?;
            if self
                .active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .context
                .is_some()
            {
                let receipt = self.retain_transferred_receipt(pin, CleanupStage::Report, wire)?;
                crate::AnchorRetiredReport::from_transferred(&receipt, &expected)
            } else {
                Ok(pin.verify_retired_report(retained, &expected, wire)?)
            }
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
