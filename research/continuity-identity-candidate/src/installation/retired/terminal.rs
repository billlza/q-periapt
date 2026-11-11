// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact host accounting and authenticated logical journal erasure.
use super::*;
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl RetiredInstallationRecovery {
    /// Persist an explicit host-accounted intent AFTER the host has durably retained
    /// the complete report and deduplicated its effects by this report ID. This never
    /// performs those external host effects. Supply the complete canonical bytes from
    /// the host accounting record and verified independent report retention. This also
    /// works after journal/archive loss; partial or changed bytes fail authentication.
    /// Exact retries do not rewrite the intent.
    /// The returned original report is the expectation for a separate authorized
    /// witness acknowledgement; neither this call nor its return erases the journal.
    pub fn prepare_host_acknowledgement(
        &mut self,
        recorded_report: &[u8],
        retained: &crate::AnchorRetiredReport,
    ) -> Result<crate::AnchorRetiredReportProposal, DurableError> {
        let result = (|| {
            let expected = self.report_proposal()?.ok_or(DurableError::Suspended)?;
            if retained.proposal() != &expected {
                return Err(DurableError::Conflict);
            }
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            crate::retired_device::verify_recorded_report(&owners.key, &expected, recorded_report)?;
            let saved = read_configuration(&owners.configuration)?;
            let control = owners.control(&saved)?;
            if let Some(control) = &control {
                crate::AnchorRetiredReport::from_transferred(
                    control.verified(CleanupStage::Report)?,
                    &expected,
                )?;
            }
            if let Some(ack) = saved.retired_ack {
                return Ok(ack);
            }
            let body = expected.to_bytes();
            let mut wire = b"QPCIAK01".to_vec();
            wire.extend_from_slice(&body);
            let next_control = control
                .as_ref()
                .map(|c| c.with_accounted(&expected)?.encode(&owners.key))
                .transpose()?;
            let tx = transaction(&owners.configuration)?;
            {
                let mut table = tx.open_table(TABLE).map_err(storage)?;
                if table.len().map_err(storage)? != 3 + u64::from(control.is_some())
                    || table
                        .get("retired-report")
                        .map_err(storage)?
                        .as_ref()
                        .map(|v| v.value())
                        != Some(body.as_slice())
                    || table.get("retired-ack").map_err(storage)?.is_some()
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
                    .insert("retired-ack", wire.as_slice())
                    .map_err(storage)?;
                if let Some(control) = &next_control {
                    table
                        .insert("retired-authority", control.as_slice())
                        .map_err(storage)?;
                }
            }
            #[cfg(all(test, unix))]
            super::super::tests::at_boundary("retired-ack-before-commit");
            tx.commit().map_err(DurableError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            super::super::tests::at_boundary("retired-ack-after-commit");
            Ok(expected)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Recover only the original host-accounted expectation, even after journal loss.
    /// None is local absence, not proof that an external host effect did not commit.
    pub fn host_acknowledgement_proposal(
        &mut self,
    ) -> Result<Option<crate::AnchorRetiredReportProposal>, DurableError> {
        let result = (|| {
            self.proposal()?;
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            Ok(read_configuration(&owners.configuration)?.retired_ack)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Authenticate the exact saved host intent: legacy purpose 21, or the independently
    /// approved transferred purpose-38 Acknowledged stage.
    /// This grants no current runtime and performs no logical or physical erasure.
    pub fn verify_host_acknowledgement(
        &mut self,
        pin: &AnchorPin,
        wire: &[u8],
    ) -> Result<crate::AnchorRetiredReportAcknowledgement, DurableError> {
        let result = (|| {
            let expected = self
                .host_acknowledgement_proposal()?
                .ok_or(DurableError::Suspended)?;
            if self
                .active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .context
                .is_some()
            {
                let proof =
                    self.retain_transferred_receipt(pin, CleanupStage::Acknowledged, wire)?;
                return crate::AnchorRetiredReportAcknowledgement::from_transferred(
                    &proof, &expected,
                );
            }
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            Ok(pin.verify_retired_report_acknowledgement(owners.retired, &expected, wire)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read the exact original journal inventory or its authenticated terminal proof.
    /// Missing or different state is an error, never evidence of successful erasure.
    /// This requires the independently saved host intent but performs no erasure.
    pub async fn journal_erasure_status(
        &mut self,
        pin: &AnchorPin,
    ) -> Result<crate::retired_device::JournalErasureState, DurableError> {
        let result = self.journal_erasure_status_attempt(pin).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn journal_erasure_status_attempt(
        &mut self,
        pin: &AnchorPin,
    ) -> Result<crate::retired_device::JournalErasureState, DurableError> {
        let expected = self
            .host_acknowledgement_proposal()?
            .ok_or(DurableError::Suspended)?;
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let saved = read_configuration(&owners.configuration)?;
        let journal = owners.storage.open_database(&owners.paths.journal).await?;
        let control = owners.control(&saved)?;
        let authority = owners.proof_authority(pin, control.as_ref())?;
        DeviceJournal::retired_journal_state(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            authority,
            &expected,
        )
    }
    /// Atomically replace the exact original image, pending and validated fence/selection
    /// rows with a terminal authenticated by the original key and exact witness ACK.
    /// A verified receipt must match the independently saved host-accounted intent.
    /// Always closes this owner; after an uncertain commit, reopen the same installation
    /// and inspect/retry the same decision. An existing matching terminal is read-only.
    /// This is logical journal erasure, not erasure of old pages, backups, archives,
    /// wrapping/signing key files or the independent installation/host report.
    pub async fn erase_journal(
        &mut self,
        pin: &AnchorPin,
        receipt: &[u8],
    ) -> Result<(), DurableError> {
        let result = self.erase_journal_attempt(pin, receipt).await;
        self.close();
        result
    }
    async fn erase_journal_attempt(
        &mut self,
        pin: &AnchorPin,
        receipt: &[u8],
    ) -> Result<(), DurableError> {
        self.verify_host_acknowledgement(pin, receipt)?;
        let expected = self
            .host_acknowledgement_proposal()?
            .ok_or(DurableError::Suspended)?;
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let saved = read_configuration(&owners.configuration)?;
        let journal = owners.storage.open_database(&owners.paths.journal).await?;
        let control = owners.control(&saved)?;
        let authority = owners.proof_authority(pin, control.as_ref())?;
        DeviceJournal::erase_retired_journal_in_database(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            authority,
            &expected,
            receipt,
        )
    }
}
