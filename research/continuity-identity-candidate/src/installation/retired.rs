// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retain the original retired inventory request outside journal backups.
use super::*;
use crate::{
    AnchorPin, AnchorRetiredCleanup, AnchorRetiredCleanupProposal as Proposal,
    AnchorRetiredSubject, RetainedInstallationAuthority as Authority,
};
use redb::ReadableTable;

const REQUEST_TAG: &[u8; 8] = b"QPCICL01";

pub(super) fn decode_request(
    bytes: &[u8],
    scope: &[u8],
    status: InstallationStatus,
) -> Result<Proposal, DurableError> {
    if status != InstallationStatus::Active
        || bytes.get(..8) != Some(REQUEST_TAG.as_slice())
        || scope.len() != 201
        || scope.get(168) != Some(&1)
    {
        return Err(DurableError::Corrupt);
    }
    let proposal = Proposal::from_trusted_state(bytes.get(8..).ok_or(DurableError::Corrupt)?)
        .map_err(|_| DurableError::Corrupt)?;
    let (journal, owner, policy) = proposal.subject().journal_parts();
    if scope.get(8..40) != Some(journal.as_slice())
        || scope.get(40..72) != Some(owner.as_slice())
        || scope.get(72..104) != Some(policy.as_slice())
        || scope.get(169..201) != Some(proposal.witness_binding().as_slice())
    {
        return Err(DurableError::Corrupt);
    }
    Ok(proposal)
}

struct Owners {
    configuration: Database,
    storage: crate::storage::Storage,
    paths: InstallationPaths,
    key: JournalKey,
    retired: AnchorRetiredSubject,
    proposal: Proposal,
}

/// Original independently stored request for one permanently retired installation.
/// This owns only recovery metadata and the original wrapping key. It cannot return
/// a service/journal or perform external host effects. Host-accounted intent is
/// explicitly recorded only after the caller durably stores the report. A complete historical
/// report requires independent retention of both inventory and report identity.
/// The configuration database must remain outside old-journal backups.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{DeviceService, RetiredInstallationRecovery};
/// fn ordinary_service(owner: RetiredInstallationRecovery) -> DeviceService { owner }
/// ```
pub struct RetiredInstallationRecovery {
    active: Option<Owners>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl RetiredInstallationRecovery {
    /// Capture and durably retain the original complete inventory before returning
    /// a dispatchable request. This requires an existing Active installation, its
    /// original paths/key and a previously verified permanent retirement proof.
    /// Once retained, reopen returns that same request without requiring the old
    /// journal to exist. This permits reconciliation of an unknown witness commit,
    /// not reporting or erasure of missing state. It never selects another backup.
    /// Any commit error returns no owner: reopen this exact installation/proof.
    pub async fn open(
        paths: InstallationPaths,
        key: JournalKey,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        Self::open_with_storage(crate::storage::Storage::native()?, paths, key, retired).await
    }
    pub(crate) async fn open_with_storage(
        storage: crate::storage::Storage,
        paths: InstallationPaths,
        key: JournalKey,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        let configuration = storage.open_database(&paths.configuration).await?;
        Self::open_database_with_storage(configuration, storage, paths, key, retired).await
    }
    #[cfg(all(test, unix))]
    async fn open_database(
        configuration: Database,
        paths: InstallationPaths,
        key: JournalKey,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        Self::open_database_with_storage(
            configuration,
            crate::storage::Storage::native()?,
            paths,
            key,
            retired,
        )
        .await
    }
    async fn open_database_with_storage(
        configuration: Database,
        store: crate::storage::Storage,
        paths: InstallationPaths,
        key: JournalKey,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        let saved = read_configuration(&configuration)?;
        check_authority(&saved, &paths, &key, retired)?;
        let proposal = if let Some(proposal) = saved.retired {
            proposal
                .check_retirement(retired)
                .map_err(|_| DurableError::Conflict)?;
            proposal
        } else {
            let journal = store.open_database(&paths.journal).await?;
            let proposal = DeviceJournal::retired_cleanup_inventory_in_database(
                &journal,
                &key,
                saved.identity,
                retired,
            )?;
            drop(journal);
            let mut wire = REQUEST_TAG.to_vec();
            wire.extend_from_slice(&proposal.to_bytes());
            let tx = transaction(&configuration)?;
            {
                let mut table = tx.open_table(TABLE).map_err(storage)?;
                let mut original = saved.scope;
                original.push(InstallationStatus::Active.byte());
                if table
                    .get("installation")
                    .map_err(storage)?
                    .as_ref()
                    .map(|v| v.value())
                    != Some(original.as_slice())
                    || table.get("retired-cleanup").map_err(storage)?.is_some()
                    || table.len().map_err(storage)? != 1
                {
                    return Err(DurableError::Conflict);
                }
                table
                    .insert("retired-cleanup", wire.as_slice())
                    .map_err(storage)?;
            }
            #[cfg(all(test, unix))]
            super::tests::at_boundary("retired-cleanup-before-commit");
            tx.commit().map_err(DurableError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            super::tests::at_boundary("retired-cleanup-after-commit");
            proposal
        };
        let mut owner = Self {
            active: Some(Owners {
                configuration,
                storage: store,
                paths,
                key,
                retired,
                proposal,
            }),
        };
        owner.proposal()?;
        Ok(owner)
    }
    /// Exact independently retained original request. No journal read, witness
    /// dispatch, operational admission or new request identity is performed.
    pub fn proposal(&mut self) -> Result<Proposal, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let saved = read_configuration(&owners.configuration)?;
            check_authority(&saved, &owners.paths, &owners.key, owners.retired)?;
            if saved.retired.as_ref() != Some(&owners.proposal) {
                return Err(DurableError::Conflict);
            }
            Ok(owners.proposal.clone())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Verify witness retention against the request recovered from the independent
    /// installation, never against a newly selected journal backup. This permanent
    /// fact grants no report/ACK/erasure or ordinary network authority.
    pub fn verify_retained(
        &mut self,
        pin: &AnchorPin,
        wire: &[u8],
    ) -> Result<AnchorRetiredCleanup, DurableError> {
        let result = (|| {
            let proposal = self.proposal()?;
            let retired = self.active.as_ref().ok_or(DurableError::Closed)?.retired;
            Ok(pin.verify_retired_cleanup(retired, &proposal, wire)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
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
        )?;
        drop(journal);
        let proposal = report.proposal().clone();
        let tx = transaction(&owners.configuration)?;
        {
            let mut table = tx.open_table(TABLE).map_err(storage)?;
            let mut expected = REQUEST_TAG.to_vec();
            expected.extend_from_slice(&owners.proposal.to_bytes());
            if table.len().map_err(storage)? != 2
                || table
                    .get("retired-cleanup")
                    .map_err(storage)?
                    .as_ref()
                    .map(|v| v.value())
                    != Some(expected.as_slice())
                || table.get("retired-report").map_err(storage)?.is_some()
            {
                return Err(DurableError::Conflict);
            }
            table
                .insert("retired-report", proposal.to_bytes().as_slice())
                .map_err(storage)?;
        }
        #[cfg(all(test, unix))]
        super::tests::at_boundary("retired-report-before-commit");
        tx.commit().map_err(DurableError::CommitUncertain)?;
        #[cfg(all(test, unix))]
        super::tests::at_boundary("retired-report-after-commit");
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
        pin.verify_retired_report(retained, &proposal, receipt)?;
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let saved = read_configuration(&owners.configuration)?;
        let journal = owners.storage.open_database(&owners.paths.journal).await?;
        if DeviceJournal::retired_journal_has_terminal(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            pin,
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
        )?;
        if report.proposal() != &proposal {
            return Err(DurableError::Conflict);
        }
        Ok(report)
    }
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
            if let Some(ack) = saved.retired_ack {
                return Ok(ack);
            }
            let body = expected.to_bytes();
            let mut wire = b"QPCIAK01".to_vec();
            wire.extend_from_slice(&body);
            let tx = transaction(&owners.configuration)?;
            {
                let mut table = tx.open_table(TABLE).map_err(storage)?;
                if table.len().map_err(storage)? != 3
                    || table
                        .get("retired-report")
                        .map_err(storage)?
                        .as_ref()
                        .map(|v| v.value())
                        != Some(body.as_slice())
                    || table.get("retired-ack").map_err(storage)?.is_some()
                {
                    return Err(DurableError::Conflict);
                }
                table
                    .insert("retired-ack", wire.as_slice())
                    .map_err(storage)?;
            }
            #[cfg(all(test, unix))]
            super::tests::at_boundary("retired-ack-before-commit");
            tx.commit().map_err(DurableError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            super::tests::at_boundary("retired-ack-after-commit");
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
    /// Authenticate independent purpose-21 acknowledgement of the exact saved host intent.
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
        DeviceJournal::retired_journal_state(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            pin,
            &expected,
        )
    }
    /// Atomically replace the exact original image and pending rows with a terminal
    /// authenticated by the original key and purpose-21 witness acknowledgement.
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
        let expected = self
            .host_acknowledgement_proposal()?
            .ok_or(DurableError::Suspended)?;
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let saved = read_configuration(&owners.configuration)?;
        let journal = owners.storage.open_database(&owners.paths.journal).await?;
        DeviceJournal::erase_retired_journal_in_database(
            &journal,
            &owners.key,
            saved.identity,
            owners.retired,
            pin,
            &expected,
            receipt,
        )
    }
    /// Release original owners without changing the request or acknowledging loss.
    pub fn close(&mut self) {
        self.active = None;
    }
}

fn check_authority(
    saved: &Configuration,
    paths: &InstallationPaths,
    key: &JournalKey,
    retired: AnchorRetiredSubject,
) -> Result<(), DurableError> {
    if saved.status != InstallationStatus::Active {
        return Err(DurableError::Suspended);
    }
    let authority = Authority::retained(&saved.scope, paths, saved.identity, key)?;
    let (journal, owner, policy) = retired.subject().journal_parts();
    if journal != *saved.identity.as_bytes()
        || owner != authority.owner
        || policy != authority.policy
        || Some(retired.witness_binding()) != authority.witness
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
