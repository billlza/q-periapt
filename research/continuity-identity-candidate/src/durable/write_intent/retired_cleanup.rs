// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Read a frozen journal's complete original inventory without operational recovery.
use super::*;
use crate::{AnchorRetiredCleanupProposal, AnchorRetiredSubject};

fn check_scope(
    image: &Image,
    expected: JournalIdentity,
    retired: AnchorRetiredSubject,
) -> Result<(), DurableError> {
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
        || witness != retired.witness_binding()
        || original != policy
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
impl DeviceJournal {
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
        Ok(snapshot(&db, key, expected, retired)?.2)
    }
}

fn snapshot(
    db: &Database,
    key: &JournalKey,
    expected: JournalIdentity,
    retired: AnchorRetiredSubject,
) -> Result<(Image, Option<PendingIntent>, AnchorRetiredCleanupProposal), DurableError> {
    let (_, owner, _) = retired.subject().journal_parts();
    let (image, pending) =
        load_pending_snapshot(db, key, owner, SnapshotAdmission::RetiredCleanup)?;
    check_scope(&image, expected, retired)?;
    let current = image.protection.head(image.revision, image.digest)?;
    if current != retired.observed_head() {
        let Some(PendingIntent::Write(pending)) = &pending else {
            return Err(DurableError::Conflict);
        };
        let target = pending.authenticated_target(key, owner)?;
        check_scope(&target, expected, retired)?;
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
    pub(crate) fn retired_report(
        path: &Path,
        key: &JournalKey,
        expected: JournalIdentity,
        retired: AnchorRetiredSubject,
        retained: &crate::AnchorRetiredCleanup,
        archives: &mut crate::SessionArchiveStore,
    ) -> Result<crate::retired_device::Report, DurableError> {
        use crate::retired_device::{Intent, Transaction, ViewRole};
        let db = open_private_database(path)?;
        let (image, pending, inventory) = snapshot(&db, key, expected, retired)?;
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
                check_scope(&target, expected, retired)?;
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
                    Some(BoundTransaction::Credential(binding)) => Transaction::Credential {
                        operation: *binding.operation.as_bytes(),
                        statement: binding.credential,
                        policy: binding.policy.map(|p| (p.adopts(), p.statement())),
                    },
                    Some(BoundTransaction::Policy(binding)) => Transaction::Policy {
                        operation: *binding.operation.as_bytes(),
                        statement: binding.statement,
                    },
                    Some(BoundTransaction::Roster(scope)) => {
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
        let report = crate::retired_device::Report::new(key, &inventory, intent, views)?;
        drop(db);
        Ok(report)
    }
}
