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
        let (_, owner, _) = retired.subject().journal_parts();
        let db = open_private_database(path)?;
        let (image, pending) =
            load_pending_snapshot(&db, &key, owner, SnapshotAdmission::RetiredCleanup)?;
        check_scope(&image, expected, retired)?;
        let current = image.protection.head(image.revision, image.digest)?;
        if current != retired.observed_head() {
            let Some(PendingIntent::Write(pending)) = &pending else {
                return Err(DurableError::Conflict);
            };
            let target = pending.authenticated_target(&key, owner)?;
            check_scope(&target, expected, retired)?;
            if target.protection.head(target.revision, target.digest)? != retired.observed_head() {
                return Err(DurableError::Conflict);
            }
        }
        let fingerprint = pending
            .as_ref()
            .map(|p| digest(b"Q-PERIAPT-CONTINUITY-RETIRED-LOCAL-INTENT/v1", p.wire()));
        Ok(AnchorRetiredCleanupProposal::from_journal(
            retired,
            image.digest,
            fingerprint,
        )?)
    }
}
