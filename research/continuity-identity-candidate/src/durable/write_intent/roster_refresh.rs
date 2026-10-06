// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Recover only the exact saved roster target after the original witness's Applied.
use super::*;
use crate::{
    AnchorOperation, AnchorRosterRefreshProposal as Proposal, AnchorRosterRefreshState as State,
    AnchorSubject, HistoricalSessionPolicy, RosterRefreshScope,
};
impl PendingWrite {
    fn roster_proposal(&self, image: &Image) -> Result<Proposal, DurableError> {
        let Some(BoundTransaction::Roster(scope)) = self.binding else {
            return Err(DurableError::Conflict);
        };
        self.check_transaction_image(image)?;
        let Protection::Required {
            policy,
            witness,
            fence,
        } = image.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        let mut subject = image.id.to_vec();
        subject.extend_from_slice(&image.owner);
        subject.extend_from_slice(&policy);
        Ok(Proposal::from_journal(
            witness,
            AnchorSubject::from_trusted_state(&subject)?,
            scope,
            crate::AnchorHead::from_trusted_state(
                fence,
                self.expected_revision,
                self.expected_digest,
            )?,
            crate::AnchorHead::from_trusted_state(fence, self.next_revision, self.next_digest)?,
        )?)
    }
}
pub(in crate::durable) fn reserve_roster_refresh(
    active: &Active,
    image: &Image,
    target: &[u8],
    scope: RosterRefreshScope,
) -> Result<Proposal, DurableError> {
    let pending =
        PendingWrite::new_bound(active, image, target, Some(BoundTransaction::Roster(scope)))?;
    reserve(active, &pending)?;
    #[cfg(all(test, unix))]
    tests::after_bound_preparation();
    let (current, readback) = load_snapshot_as(
        &active.db,
        &active.key,
        active.owner,
        SnapshotAdmission::RosterRecovery,
    )?;
    let readback = readback.ok_or(DurableError::Conflict)?;
    if readback.wire != pending.wire {
        return Err(DurableError::Conflict);
    }
    readback.roster_proposal(&current)
}
impl DeviceJournal {
    /// Read original authenticated R preparation before or after target installation.
    /// None means local absence only. This sends nothing, reseals nothing and does
    /// not establish witness no-commit. Other bound transaction types are refused.
    pub fn inspect_roster_refresh_preparation(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
    ) -> Result<Option<Proposal>, DurableError> {
        let db = open_private_database(path)?;
        let (image, pending) = load_pending_snapshot(
            &db,
            &key,
            bootstrap::storage_owner(original),
            SnapshotAdmission::RosterRecovery,
        )?;
        credential_cancellation::check_scope(&image, original, policy, id)?;
        match pending {
            None => Ok(None),
            Some(PendingIntent::Write(p)) => Ok(Some(p.roster_proposal(&image)?)),
            Some(PendingIntent::Cancellation(_)) => Err(DurableError::Conflict),
        }
    }
    /// Only a fresh exact original R Applied may install the saved sealed target.
    /// Pending is retained even after installation. This sends no Commit/Close/ACK,
    /// grants no live owner and never treats Unavailable as no-commit.
    pub fn recover_roster_refresh(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        proposal: Proposal,
        client: &mut crate::AnchorClient,
    ) -> Result<State, DurableError> {
        let db = open_private_database(path)?;
        Self::recover_roster_refresh_in_database(&db, &key, original, policy, id, proposal, client)
    }
    pub(crate) fn recover_roster_refresh_in_database(
        db: &Database,
        key: &JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        proposal: Proposal,
        client: &mut crate::AnchorClient,
    ) -> Result<State, DurableError> {
        let owner = bootstrap::storage_owner(original);
        let (image, pending) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::RosterRecovery)?;
        credential_cancellation::check_scope(&image, original, policy, id)?;
        let Some(PendingIntent::Write(pending)) = pending else {
            return Err(DurableError::Conflict);
        };
        if pending.roster_proposal(&image)? != proposal
            || client.pin().binding() != proposal.witness_binding()
        {
            return Err(DurableError::Conflict);
        }
        client.check_device(original)?;
        policy.check_external_signer(client.pin().public_key())?;
        if client
            .pin()
            .public_key()
            .shares_component(&original.authority_key)
        {
            return Err(Error::Scope.into());
        }
        let reply = client.exchange(
            proposal.subject(),
            AnchorOperation::roster_refresh_status(&proposal),
        )?;
        let state = reply.roster_refresh_state(&proposal)?;
        match state {
            State::Applied => {
                apply_bound_target(db, &pending)?;
                let (after, retained) =
                    load_pending_snapshot(db, key, owner, SnapshotAdmission::RosterRecovery)?;
                if after.protection.head(after.revision, after.digest)? != proposal.target_head()
                    || retained.ok_or(DurableError::Conflict)?.wire() != pending.wire
                {
                    return Err(DurableError::Conflict);
                }
            }
            State::Prepared | State::Closed => {
                if image.protection.head(image.revision, image.digest)? != proposal.expected_head()
                {
                    return Err(DurableError::Conflict);
                }
            }
            State::Unavailable => {}
            State::Acknowledged => return Err(Error::State.into()),
        }
        Ok(state)
    }
}

impl DeviceJournal {
    pub(crate) fn retire_roster_refresh(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        terminal: &crate::enrollment::PersistedRosterTerminal,
        client: &mut crate::AnchorClient,
    ) -> Result<(), DurableError> {
        let db = open_private_database(path)?;
        Self::retire_roster_refresh_in_database(&db, &key, original, policy, id, terminal, client)
    }
    pub(crate) fn retire_roster_refresh_in_database(
        db: &Database,
        key: &JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        terminal: &crate::enrollment::PersistedRosterTerminal,
        client: &mut crate::AnchorClient,
    ) -> Result<(), DurableError> {
        let owner = bootstrap::storage_owner(original);
        let (image, pending) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::RosterRecovery)?;
        credential_cancellation::check_scope(&image, original, policy, id)?;
        let proposal = terminal.proposal();
        let expected = match terminal.disposition() {
            crate::WitnessedRosterRefreshDisposition::Applied => proposal.target_head(),
            crate::WitnessedRosterRefreshDisposition::Closed => proposal.expected_head(),
        };
        if proposal.subject() != AnchorSubject::for_device(id, original, policy)?
            || client.pin().binding() != proposal.witness_binding()
            || policy.anchor_requirement().binding() != Some(proposal.witness_binding())
            || image.protection.head(image.revision, image.digest)? != expected
        {
            return Err(DurableError::Conflict);
        }
        match &pending {
            None => {}
            Some(PendingIntent::Write(p)) if p.roster_proposal(&image)? == proposal => {}
            _ => return Err(DurableError::Conflict),
        }
        rosters::check_witnessed_roster_terminal(&image, original, terminal)?;
        client.check_device(original)?;
        policy.check_external_signer(client.pin().public_key())?;
        if client
            .pin()
            .public_key()
            .shares_component(&original.authority_key)
        {
            return Err(Error::Scope.into());
        }
        let reply = client.exchange(
            proposal.subject(),
            AnchorOperation::acknowledge_roster_refresh(&proposal),
        )?;
        if reply.observed_head() != expected
            || !matches!(
                reply.roster_refresh_state(&proposal)?,
                State::Acknowledged | State::Unavailable
            )
        {
            return Err(DurableError::Conflict);
        }
        // Missing history can retire only an already authenticated original terminal.
        // It never authorizes a target install or creates a new disposition.
        remove_retired_bound_pending(db, key, owner, expected, pending.as_ref())
    }
}
