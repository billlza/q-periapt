// SPDX-License-Identifier: Apache-2.0 OR MIT
//! P-only preparation and historical installation of the exact sealed target.
use super::*;
use crate::{
    AnchorOperation, AnchorPolicyRenewalProposal as Proposal, AnchorPolicyRenewalState as State,
    AnchorSubject, HistoricalSessionPolicy,
};

impl PendingWrite {
    fn policy_proposal(&self, image: &Image) -> Result<Proposal, DurableError> {
        let Some(BoundTransaction::Policy(binding)) = self.binding else {
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
            binding.operation,
            binding.statement,
            crate::AnchorHead::from_trusted_state(
                fence,
                self.expected_revision,
                self.expected_digest,
            )?,
            crate::AnchorHead::from_trusted_state(fence, self.next_revision, self.next_digest)?,
        )?)
    }
}
pub(in crate::durable) fn reserve_policy_renewal(
    active: &Active,
    image: &Image,
    target: &[u8],
    binding: PolicyRenewalBinding,
) -> Result<Proposal, DurableError> {
    let pending = PendingWrite::new_bound(
        active,
        image,
        target,
        Some(BoundTransaction::Policy(binding)),
    )?;
    reserve(active, &pending)?;
    #[cfg(all(test, unix))]
    tests::after_bound_preparation();
    let (current, readback) = load_snapshot_as(
        &active.db,
        &active.key,
        active.owner,
        SnapshotAdmission::PolicyRecovery,
    )?;
    let readback = readback.ok_or(DurableError::Conflict)?;
    if readback.wire != pending.wire {
        return Err(DurableError::Conflict);
    }
    readback.policy_proposal(&current)
}
impl DeviceJournal {
    /// Read the exact original authenticated P preparation without signing,
    /// dispatching, resealing or releasing an owner. None is only local absence;
    /// it never proves that a witness target did not commit. G/T intents refuse.
    pub fn inspect_policy_renewal_preparation(
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
            SnapshotAdmission::PolicyRecovery,
        )?;
        credential_cancellation::check_scope(&image, original, policy, id)?;
        match pending {
            None => Ok(None),
            Some(PendingIntent::Write(p)) => Ok(Some(p.policy_proposal(&image)?)),
            Some(PendingIntent::Cancellation(_)) => Err(DurableError::Conflict),
        }
    }
    /// Reconcile one retained P target by a fresh signed status query to its
    /// original witness. Only exact Applied installs the already sealed bytes.
    /// Original intent remains even after local installation. This never sends
    /// Commit, Close or ACK, removes intent, or returns an operational owner.
    pub fn recover_policy_renewal(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        proposal: Proposal,
        client: &mut crate::AnchorClient,
    ) -> Result<State, DurableError> {
        let db = open_private_database(path)?;
        recover_policy_renewal(&db, &key, original, policy, id, proposal, client)
    }
}
pub(in crate::durable) fn recover_policy_renewal(
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
        load_pending_snapshot(db, key, owner, SnapshotAdmission::PolicyRecovery)?;
    credential_cancellation::check_scope(&image, original, policy, id)?;
    let Some(PendingIntent::Write(pending)) = pending else {
        return Err(DurableError::Conflict);
    };
    if pending.policy_proposal(&image)? != proposal
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
        AnchorOperation::policy_renewal_status(&proposal),
    )?;
    let state = reply.policy_renewal_state(&proposal)?;
    match state {
        State::Applied => {
            apply_bound_target(db, &pending)?;
            let (after, retained) =
                load_pending_snapshot(db, key, owner, SnapshotAdmission::PolicyRecovery)?;
            if after.protection.head(after.revision, after.digest)? != proposal.target_head()
                || retained.ok_or(DurableError::Conflict)?.wire() != pending.wire
            {
                return Err(DurableError::Conflict);
            }
        }
        State::Prepared | State::Closed => {
            if image.protection.head(image.revision, image.digest)? != proposal.expected_head() {
                return Err(DurableError::Conflict);
            }
        }
        State::Unavailable => {}
        State::Acknowledged => return Err(Error::State.into()),
    }
    Ok(state)
}

impl DeviceJournal {
    // Only a read-back authenticated original enrollment terminal can grant ACK
    // authority. Keep the original pending bytes until that exact ACK is observed.
    pub(crate) fn retire_policy_renewal(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        terminal: &crate::enrollment::PersistedPolicyTerminal,
        client: &mut crate::AnchorClient,
    ) -> Result<(), DurableError> {
        let db = open_private_database(path)?;
        Self::retire_policy_renewal_in_database(&db, &key, original, policy, id, terminal, client)
    }
    pub(crate) fn retire_policy_renewal_in_database(
        db: &Database,
        key: &JournalKey,
        original: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        id: JournalIdentity,
        terminal: &crate::enrollment::PersistedPolicyTerminal,
        client: &mut crate::AnchorClient,
    ) -> Result<(), DurableError> {
        terminal.approval().check_original_policy(policy)?;
        let owner = bootstrap::storage_owner(original);
        let (image, pending) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::PolicyRecovery)?;
        credential_cancellation::check_scope(&image, original, policy, id)?;
        let proposal = terminal.proposal();
        let expected = match terminal.disposition() {
            crate::WitnessedPolicyRenewalDisposition::Applied => proposal.target_head(),
            crate::WitnessedPolicyRenewalDisposition::Closed => proposal.expected_head(),
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
            Some(PendingIntent::Write(p)) if p.policy_proposal(&image)? == proposal => {}
            _ => return Err(DurableError::Conflict),
        }
        rosters::check_witnessed_policy_terminal(&image, original, terminal)?;
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
            AnchorOperation::acknowledge_policy_renewal(&proposal),
        )?;
        if reply.observed_head() != expected
            || !matches!(
                reply.policy_renewal_state(&proposal)?,
                State::Acknowledged | State::Unavailable
            )
        {
            return Err(DurableError::Conflict);
        }
        // Unavailable is usable only with this already durable exact terminal;
        // it cannot invent an Applied/Closed result or authorize an image change.
        remove_retired_bound_pending(db, key, owner, expected, pending.as_ref())
    }
}
