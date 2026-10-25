// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Inspect and confirm only the original MAC-bound generic intent.
use super::*;
use crate::durable::pending_recovery::{
    PendingRecoveryLineage, PendingRecoverySnapshot, PendingWriteRecoveryView,
};
use crate::{AnchorHead, AnchorOperation, AnchorPendingWriteRecoveryProposal, AnchorSubject};

impl DeviceJournal {
    pub(crate) fn pending_write_recovery_in_database(
        db: &Database,
        key: &JournalKey,
        expected: JournalIdentity,
        lineage: &PendingRecoveryLineage<'_>,
        archives: &mut crate::SessionArchiveStore,
    ) -> Result<PendingRecoverySnapshot, DurableError> {
        let owner = bootstrap::storage_owner(lineage.scope.original_device);
        let (mut image, pending) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::Ordinary)?;
        lineage.attach_completion(&mut image)?;
        if image.id != *expected.as_bytes() {
            return Err(DurableError::Conflict);
        }
        let pending = ordinary(pending)?.ok_or(DurableError::Absent)?;
        inspect(&image, &pending, key, lineage, archives)
    }
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceJournal {
    pub(crate) async fn confirm_pending_write_recovery_in_database(
        db: &Database,
        key: &JournalKey,
        expected: JournalIdentity,
        lineage: &PendingRecoveryLineage<'_>,
        archives: &mut crate::SessionArchiveStore,
        approved: &AnchorPendingWriteRecoveryProposal,
        client: &mut crate::AnchorClient,
    ) -> Result<AnchorHead, DurableError> {
        let original = lineage.scope.original_device;
        let owner = bootstrap::storage_owner(original);
        let (mut image, pending) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::Ordinary)?;
        lineage.attach_completion(&mut image)?;
        let pending = ordinary(pending)?;
        if image.id != *expected.as_bytes()
            || approved.subject()
                != AnchorSubject::for_device(expected, original, lineage.scope.original_policy)?
            || client.pin().binding() != approved.scope.witness
        {
            return Err(DurableError::Conflict);
        }
        client.check_device(original)?;
        match pending.as_ref() {
            Some(pending) => {
                if inspect(&image, pending, key, lineage, archives)?
                    .expectation()?
                    .0
                    != *approved
                {
                    return Err(DurableError::Conflict);
                }
            }
            None => {
                // The saved target digest authenticates the whole local image.
                // Require its actual authority lineage too, never infer success
                // merely from a missing pending record or a retained proposal.
                let current = lineage.inspect(&image)?;
                if image.protection.head(image.revision, image.digest)? != approved.target_head()
                    || current.current_device.authority_binding() != approved.expected_authority()
                    || current.current_policy.digest() != approved.expected_policy_digest()
                    || current.current_policy_authorization
                        != approved.expected_policy_authorization()
                {
                    return Err(DurableError::Conflict);
                }
            }
        }
        let reply = client
            .exchange(approved.subject(), AnchorOperation::query())
            .await?;
        approved.confirm_reply(&reply)?;
        if let Some(pending) = &pending {
            apply(db, key, pending, Some(client))?;
        }
        let (readback, retained) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::Ordinary)?;
        if retained.is_some()
            || readback
                .protection
                .head(readback.revision, readback.digest)?
                != approved.target_head()
        {
            return Err(DurableError::Conflict);
        }
        Ok(approved.target_head())
    }
}

fn ordinary(pending: Option<PendingIntent>) -> Result<Option<PendingWrite>, DurableError> {
    match pending {
        Some(PendingIntent::Write(pending)) if pending.binding.is_none() => Ok(Some(pending)),
        Some(_) => Err(DurableError::Suspended),
        None => Ok(None),
    }
}
fn inspect(
    image: &Image,
    pending: &PendingWrite,
    key: &JournalKey,
    lineage: &PendingRecoveryLineage<'_>,
    archives: &mut crate::SessionArchiveStore,
) -> Result<PendingRecoverySnapshot, DurableError> {
    let owner = bootstrap::storage_owner(lineage.scope.original_device);
    let mut target = pending.authenticated_target(key, owner)?;
    lineage.attach_completion(&mut target)?;
    let source_scope = lineage.inspect(image)?;
    let target_scope = lineage.inspect(&target)?;
    if source_scope.journal != target_scope.journal
        || source_scope.original_owner != target_scope.original_owner
        || source_scope.current_device.authority_binding()
            != target_scope.current_device.authority_binding()
        || source_scope.current_policy != target_scope.current_policy
        || source_scope.current_policy_authorization != target_scope.current_policy_authorization
    {
        return Err(DurableError::Conflict);
    }
    let Protection::Required {
        witness, policy, ..
    } = image.protection
    else {
        return Err(DurableError::AnchorRequired);
    };
    let mut subject = image.id.to_vec();
    subject.extend_from_slice(&image.owner);
    subject.extend_from_slice(&policy);
    let scope = crate::anchor::PendingWriteRecoveryScope {
        witness,
        subject: AnchorSubject::from_trusted_state(&subject)?,
        expected: image.protection.head(image.revision, image.digest)?,
        target: target.protection.head(target.revision, target.digest)?,
        authority: source_scope.current_device.authority_binding(),
        policy: source_scope.current_policy.digest(),
        policy_authorization: source_scope.current_policy_authorization,
        intent: digest(
            b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-INTENT/v1",
            &pending.wire,
        ),
    };
    Ok(PendingRecoverySnapshot {
        scope,
        source: pending_view(image, key, archives)?,
        target: pending_view(&target, key, archives)?,
    })
}
fn pending_view(
    image: &Image,
    key: &JournalKey,
    archives: &mut crate::SessionArchiveStore,
) -> Result<PendingWriteRecoveryView, DurableError> {
    Ok(PendingWriteRecoveryView {
        head: image.protection.head(image.revision, image.digest)?,
        local_account: image.local_account,
        next_fanout_ordinal: image.next_fanout,
        records: super::super::retired_report::project_records(image, key, archives)?,
    })
}
