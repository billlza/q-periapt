// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Read a frozen journal's complete original inventory without operational recovery.
use super::*;
use crate::{AnchorRetiredCleanupProposal, AnchorRetiredSubject};
mod erasure;

fn check_scope(
    image: &Image,
    expected: JournalIdentity,
    retired: AnchorRetiredSubject,
    context: Option<&crate::TransferredRetirementContext>,
) -> Result<(), DurableError> {
    if context.is_some_and(|c| c.retired_subject() != retired) {
        return Err(DurableError::Conflict);
    }
    let (journal, owner, policy) = retired.subject().journal_parts();
    let Protection::Required {
        witness,
        policy: original,
        ..
    } = image.protection
    else {
        return Err(DurableError::AnchorRequired);
    };
    if image.id != *expected.as_bytes()
        || image.id != journal
        || image.owner != owner
        || witness != context.map_or(retired.witness_binding(), |c| c.logical())
        || original != policy
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
impl DeviceJournal {
    pub(crate) fn observe_transferred_retirement_in_database(
        db: &Database,
        key: &JournalKey,
        identity: JournalIdentity,
        context: &crate::TransferredRetirementContext,
    ) -> Result<crate::retired_device::transferred::RetirementObservation, DurableError> {
        let (image, pending, inventory) =
            snapshot(db, key, identity, context.retired_subject(), Some(context))?;
        let tx = db.begin_read().map_err(storage)?;
        let table = image_table(&tx)?;
        let root = table
            .get("account-root-fence")
            .map_err(storage)?
            .ok_or(DurableError::Conflict)?;
        let selection = table.get(witness_handoff::ROW).map_err(storage)?;
        let parent_fence = account_root::validate_transferred_retired_snapshot(
            key,
            &image,
            pending.as_ref(),
            root.value(),
            selection.as_ref().map(|r| r.value()),
            context,
        )?;
        let original_child = crate::TransferredAccountRootPreparation::original_child_checkpoint(
            &image.id,
            &image.owner,
            &image.digest,
            pending.as_ref().map(|p| p.wire()),
            selection.as_ref().map(|r| r.value()),
        );
        Ok(crate::retired_device::transferred::RetirementObservation {
            inventory,
            original_child,
            parent_fence,
        })
    }
    /// Read the exact authenticated image and pending record of a permanently
    /// retired journal. The pinned retirement proof must already be verified.
    /// No current policy/signing owner, network request, rewrite, intent apply,
    /// report release or erasure occurs. The original exclusive lease is required.
    /// Retain the returned proposal independently of old-journal backups before
    /// submitting it to the authorized witness controller. Different backups can
    /// have the same image but different pending inventory and must not substitute.
    pub fn retired_cleanup_proposal(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        retired: AnchorRetiredSubject,
    ) -> Result<AnchorRetiredCleanupProposal, DurableError> {
        Self::retired_cleanup_inventory(path, &key, expected, retired)
    }
    pub(crate) fn retired_cleanup_inventory(
        path: &Path,
        key: &JournalKey,
        expected: JournalIdentity,
        retired: AnchorRetiredSubject,
    ) -> Result<AnchorRetiredCleanupProposal, DurableError> {
        let db = open_private_database(path)?;
        Self::retired_cleanup_inventory_in_database(&db, key, expected, retired, None)
    }
    pub(crate) fn retired_cleanup_inventory_in_database(
        db: &Database,
        key: &JournalKey,
        expected: JournalIdentity,
        retired: AnchorRetiredSubject,
        context: Option<&crate::TransferredRetirementContext>,
    ) -> Result<AnchorRetiredCleanupProposal, DurableError> {
        Ok(snapshot(db, key, expected, retired, context)?.2)
    }
}

fn snapshot(
    db: &Database,
    key: &JournalKey,
    expected: JournalIdentity,
    retired: AnchorRetiredSubject,
    context: Option<&crate::TransferredRetirementContext>,
) -> Result<(Image, Option<PendingIntent>, AnchorRetiredCleanupProposal), DurableError> {
    let (_, owner, _) = retired.subject().journal_parts();
    let admission = context.map_or(
        SnapshotAdmission::RetiredCleanup(&retired),
        SnapshotAdmission::TransferredRetiredCleanup,
    );
    let (image, pending) = load_pending_snapshot(db, key, owner, admission)?;
    check_scope(&image, expected, retired, context)?;
    let current = image.protection.head(image.revision, image.digest)?;
    if current != retired.observed_head() {
        let Some(PendingIntent::Write(pending)) = &pending else {
            return Err(DurableError::Conflict);
        };
        let target = pending.authenticated_target(key, owner)?;
        check_scope(&target, expected, retired, context)?;
        if target.protection.head(target.revision, target.digest)? != retired.observed_head() {
            return Err(DurableError::Conflict);
        }
    }
    let fingerprint = pending
        .as_ref()
        .map(|p| digest(b"Q-PERIAPT-CONTINUITY-RETIRED-LOCAL-INTENT/v1", p.wire()));
    let proposal = AnchorRetiredCleanupProposal::from_journal(retired, image.digest, fingerprint)?;
    Ok((image, pending, proposal))
}

impl DeviceJournal {
    #[cfg(all(test, unix))]
    pub(crate) fn retired_report(
        path: &Path,
        key: &JournalKey,
        expected: JournalIdentity,
        retired: AnchorRetiredSubject,
        retained: &crate::AnchorRetiredCleanup,
        archives: &mut crate::SessionArchiveStore,
    ) -> Result<crate::retired_device::Report, DurableError> {
        let db = open_private_database(path)?;
        Self::retired_report_in_database(&db, key, expected, retired, retained, archives, None)
    }
    pub(crate) fn retired_report_in_database(
        db: &Database,
        key: &JournalKey,
        expected: JournalIdentity,
        retired: AnchorRetiredSubject,
        retained: &crate::AnchorRetiredCleanup,
        archives: &mut crate::SessionArchiveStore,
        context: Option<&crate::TransferredRetirementContext>,
    ) -> Result<crate::retired_device::Report, DurableError> {
        use crate::retired_device::{Intent, Transaction, ViewRole};
        let (image, pending, inventory) = snapshot(db, key, expected, retired, context)?;
        if &inventory != retained.proposal() {
            return Err(DurableError::Conflict);
        }
        let current = image.protection.head(image.revision, image.digest)?;
        let mut views = Vec::new();
        let intent = match &pending {
            None => Intent::None,
            Some(PendingIntent::Cancellation(p)) => Intent::Cancellation(p.cancellation.to_bytes()),
            Some(PendingIntent::Write(p)) => {
                let target = p.authenticated_target(key, image.owner)?;
                check_scope(&target, expected, retired, context)?;
                let target_head = target.protection.head(target.revision, target.digest)?;
                if current != target_head {
                    let target_committed = target_head == retired.observed_head();
                    views.push(super::super::retired_report::project(
                        &image,
                        key,
                        archives,
                        if target_committed {
                            ViewRole::SupersededSource
                        } else {
                            ViewRole::Authoritative
                        },
                    )?);
                    views.push(super::super::retired_report::project(
                        &target,
                        key,
                        archives,
                        if target_committed {
                            ViewRole::Authoritative
                        } else {
                            ViewRole::UncommittedTarget
                        },
                    )?);
                }
                let transaction = match p.binding {
                    None => Transaction::Ordinary,
                    Some(BoundTransaction::Credential(RenewalBinding {
                        operation,
                        credential,
                        policy: Some(PolicyIntent::RetainIndependent(policy)),
                    })) => Transaction::CredentialUnderPolicy {
                        operation: *operation.as_bytes(),
                        statement: credential,
                        policy,
                    },
                    Some(BoundTransaction::Credential(binding)) => Transaction::Credential {
                        operation: *binding.operation.as_bytes(),
                        statement: binding.credential,
                        policy: binding.policy.map(|p| (p.adopts(), p.statement())),
                    },
                    Some(BoundTransaction::Policy(binding)) => Transaction::Policy {
                        operation: *binding.operation.as_bytes(),
                        statement: binding.statement,
                    },
                    Some(BoundTransaction::Roster { scope, .. }) => {
                        let mut bytes = Vec::new();
                        scope.encode(&mut bytes);
                        Transaction::Roster(bytes)
                    }
                };
                Intent::Write {
                    expected: p.protection.head(p.expected_revision, p.expected_digest)?,
                    target: target_head,
                    transaction,
                }
            }
        };
        if views.is_empty() {
            views.push(super::super::retired_report::project(
                &image,
                key,
                archives,
                ViewRole::Authoritative,
            )?);
        }
        // The lease spans both exact-inventory admission and complete metadata projection.
        crate::retired_device::Report::new(key, &inventory, intent, views)
    }
}
