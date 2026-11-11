// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retain the original retired inventory request outside journal backups.
use super::*;
use crate::retired_device::transferred::{authority::ReceiptAuthority, control::Control};
use crate::{
    AnchorPin, AnchorRetiredCleanup, AnchorRetiredCleanupProposal as Proposal,
    AnchorRetiredSubject, RetainedInstallationAuthority as Authority,
};
use crate::{AnchorTransferredCleanupStage as CleanupStage, TransferredRetirementContext};
use redb::ReadableTable;
mod report;
mod terminal;
mod transferred;

const REQUEST_TAG: &[u8; 8] = b"QPCICL01";

pub(super) fn decode_request(
    bytes: &[u8],
    scope: &[u8],
    status: InstallationStatus,
) -> Result<(Proposal, Option<[u8; 32]>), DurableError> {
    let transferred = bytes.get(..8) == Some(b"QPCICL02");
    if status != InstallationStatus::Active
        || (!transferred && bytes.get(..8) != Some(REQUEST_TAG.as_slice()))
        || scope.len() != 201
        || scope.get(168) != Some(&1)
    {
        return Err(DurableError::Corrupt);
    }
    let context = if transferred {
        let binding = bytes
            .get(8..40)
            .ok_or(DurableError::Corrupt)?
            .try_into()
            .map_err(|_| DurableError::Corrupt)?;
        crate::codec::nonzero(&binding)?;
        Some(binding)
    } else {
        None
    };
    let proposal = Proposal::from_trusted_state(
        bytes
            .get(if transferred { 40 } else { 8 }..)
            .ok_or(DurableError::Corrupt)?,
    )
    .map_err(|_| DurableError::Corrupt)?;
    let (journal, owner, policy) = proposal.subject().journal_parts();
    if scope.get(8..40) != Some(journal.as_slice())
        || scope.get(40..72) != Some(owner.as_slice())
        || scope.get(72..104) != Some(policy.as_slice())
        || (!transferred && scope.get(169..201) != Some(proposal.witness_binding().as_slice()))
    {
        return Err(DurableError::Corrupt);
    }
    Ok((proposal, context))
}
fn request_wire(proposal: &Proposal, context: Option<[u8; 32]>) -> Vec<u8> {
    let mut wire = if context.is_some() {
        b"QPCICL02".to_vec()
    } else {
        REQUEST_TAG.to_vec()
    };
    if let Some(context) = context {
        wire.extend_from_slice(&context);
    }
    wire.extend_from_slice(&proposal.to_bytes());
    wire
}

struct Owners {
    configuration: Database,
    storage: crate::storage::Storage,
    paths: InstallationPaths,
    key: JournalKey,
    retired: AnchorRetiredSubject,
    proposal: Proposal,
    context: Option<Box<TransferredRetirementContext>>,
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
        Self::open_database_with_storage(configuration, storage, paths, key, retired, None).await
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
            None,
        )
        .await
    }
    async fn open_database_with_storage(
        configuration: Database,
        store: crate::storage::Storage,
        paths: InstallationPaths,
        key: JournalKey,
        retired: AnchorRetiredSubject,
        context: Option<Box<TransferredRetirementContext>>,
    ) -> Result<Self, DurableError> {
        let saved = read_configuration(&configuration)?;
        check_authority(&saved, &paths, &key, retired, context.as_deref())?;
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
                context.as_deref(),
            )?;
            drop(journal);
            let wire = request_wire(&proposal, context.as_ref().map(|c| c.binding()));
            let control = context
                .as_ref()
                .map(|c| Control::new(c, &proposal)?.encode(&key))
                .transpose()?;
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
                if let Some(control) = &control {
                    table
                        .insert("retired-authority", control.as_slice())
                        .map_err(storage)?;
                }
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
                context,
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
            check_authority(
                &saved,
                &owners.paths,
                &owners.key,
                owners.retired,
                owners.context.as_deref(),
            )?;
            owners.control(&saved)?;
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
            if self
                .active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .context
                .is_some()
            {
                let receipt =
                    self.retain_transferred_receipt(pin, CleanupStage::Inventory, wire)?;
                return AnchorRetiredCleanup::from_transferred(&receipt, &proposal);
            }
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
    context: Option<&TransferredRetirementContext>,
) -> Result<(), DurableError> {
    if saved.status != InstallationStatus::Active {
        return Err(DurableError::Suspended);
    }
    let authority = Authority::retained(&saved.scope, paths, saved.identity, key)?;
    if context.is_some_and(|c| c.retired_subject() != retired)
        || (saved.retired.is_some() && saved.retired_context != context.map(|c| c.binding()))
    {
        return Err(DurableError::Conflict);
    }
    let (journal, owner, policy) = retired.subject().journal_parts();
    if journal != *saved.identity.as_bytes()
        || owner != authority.owner
        || policy != authority.policy
        || Some(context.map_or(retired.witness_binding(), |c| c.logical())) != authority.witness
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
