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
    paths: InstallationPaths,
    key: JournalKey,
    retired: AnchorRetiredSubject,
    proposal: Proposal,
}

/// Original independently stored request for one permanently retired installation.
/// This owns only recovery metadata and the original wrapping key. It cannot return
/// a service/journal, release a loss report, acknowledge host effects or erase data.
/// The configuration database must remain outside old-journal backups.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{DeviceService, RetiredInstallationRecovery};
/// fn ordinary_service(owner: RetiredInstallationRecovery) -> DeviceService { owner }
/// ```
pub struct RetiredInstallationRecovery {
    active: Option<Owners>,
}
impl RetiredInstallationRecovery {
    /// Capture and durably retain the original complete inventory before returning
    /// a dispatchable request. This requires an existing Active installation, its
    /// original paths/key and a previously verified permanent retirement proof.
    /// Once retained, reopen returns that same request without requiring the old
    /// journal to exist. This permits reconciliation of an unknown witness commit,
    /// not reporting or erasure of missing state. It never selects another backup.
    /// Any commit error returns no owner: reopen this exact installation/proof.
    pub fn open(
        paths: InstallationPaths,
        key: JournalKey,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        let configuration = open_private_database(&paths.configuration)?;
        Self::open_database(configuration, paths, key, retired)
    }
    fn open_database(
        configuration: Database,
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
            let proposal = DeviceJournal::retired_cleanup_inventory(
                &paths.journal,
                &key,
                saved.identity,
                retired,
            )?;
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
