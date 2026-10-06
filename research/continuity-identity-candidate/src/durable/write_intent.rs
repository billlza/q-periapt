// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Persist the exact sealed aggregate before attempting its state transaction.
use super::*;
use hmac::{Hmac, Mac};
use redb::ReadableDatabase;
use sha2::Sha256;

const INTENT_HEADER: usize = 8 + 32 + 32 + 8 + 32 + 8 + 32 + 4;
const MAX_TARGET: usize = HEADER + MAX_IMAGE + 16;
const MAX_BOUND_BINDING_BYTES: usize = crate::RosterRefreshScope::ENCODED_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PolicyIntent {
    Adopt([u8; 32]),
    Retain([u8; 32]),
}
impl PolicyIntent {
    pub(super) fn statement(self) -> [u8; 32] {
        match self {
            Self::Adopt(s) | Self::Retain(s) => s,
        }
    }
    pub(super) fn adopts(self) -> bool {
        matches!(self, Self::Adopt(_))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RenewalBinding {
    pub(super) operation: crate::CredentialRenewalId,
    pub(super) credential: [u8; 32],
    pub(super) policy: Option<PolicyIntent>,
}
impl RenewalBinding {
    pub(super) fn transaction_statement(self) -> [u8; 32] {
        match self.policy {
            Some(PolicyIntent::Adopt(s)) => s,
            _ => self.credential,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PolicyRenewalBinding {
    pub(super) operation: crate::PolicyRenewalId,
    pub(super) statement: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundTransaction {
    Credential(RenewalBinding),
    Policy(PolicyRenewalBinding),
    Roster(crate::RosterRefreshScope),
}
mod roster_refresh;
pub(super) use roster_refresh::reserve_roster_refresh;
mod policy_renewal;
#[cfg(all(test, unix))]
pub(super) use policy_renewal::recover_policy_renewal;
pub(super) use policy_renewal::reserve_policy_renewal;

mod credential_cancellation;
#[cfg(all(test, unix))]
pub(super) mod tests;
pub(crate) use credential_cancellation::CredentialCancellationTarget;
use credential_cancellation::PendingCancellation;
pub(crate) use credential_cancellation::WitnessedCredentialIntent;

enum PendingIntent {
    Write(PendingWrite),
    Cancellation(PendingCancellation),
}
impl PendingIntent {
    fn wire(&self) -> &[u8] {
        match self {
            Self::Write(p) => &p.wire,
            Self::Cancellation(p) => &p.wire,
        }
    }
    fn credential_intent(&self, image: &Image) -> Result<WitnessedCredentialIntent, DurableError> {
        match self {
            Self::Write(p) => Ok(WitnessedCredentialIntent::Proposal(
                p.credential_proposal(image)?,
            )),
            Self::Cancellation(p) => {
                p.check_current(image)?;
                Ok(WitnessedCredentialIntent::Cancellation(p.cancellation))
            }
        }
    }
}

pub(super) struct PendingWrite {
    expected_revision: u64,
    expected_digest: [u8; 32],
    next_revision: u64,
    next_digest: [u8; 32],
    target: Vec<u8>,
    wire: Vec<u8>,
    protection: Protection,
    local_account: [u8; 32],
    binding: Option<BoundTransaction>,
}
impl PendingWrite {
    pub(super) fn authenticated_target(
        &self,
        key: &JournalKey,
        owner: [u8; 32],
    ) -> Result<Image, DurableError> {
        unseal(key, owner, &self.target)
    }

    fn new(active: &Active, image: &Image, target: &[u8]) -> Result<Self, DurableError> {
        Self::new_bound(active, image, target, None)
    }
    fn new_bound(
        active: &Active,
        image: &Image,
        target: &[u8],
        binding: Option<BoundTransaction>,
    ) -> Result<Self, DurableError> {
        let expected_revision = image.revision.checked_sub(1).ok_or(DurableError::Corrupt)?;
        let mut wire = match binding {
            Some(BoundTransaction::Roster(_)) => b"QPWINT07".to_vec(),
            Some(BoundTransaction::Policy(_)) => b"QPWINT06".to_vec(),
            Some(BoundTransaction::Credential(r)) if r.policy.is_some() => b"QPWINT04".to_vec(),
            Some(BoundTransaction::Credential(_)) => b"QPWINT02".to_vec(),
            None => b"QPWINT01".to_vec(),
        };
        if let Some(BoundTransaction::Roster(scope)) = binding {
            scope.encode(&mut wire);
        }
        if let Some(BoundTransaction::Policy(p)) = binding {
            wire.extend_from_slice(p.operation.as_bytes());
            wire.extend_from_slice(&p.statement);
        }
        if let Some(BoundTransaction::Credential(binding)) = binding {
            wire.extend_from_slice(binding.operation.as_bytes());
            wire.extend_from_slice(&binding.credential);
            if let Some(policy) = binding.policy {
                wire.push(u8::from(policy.adopts()));
                wire.extend_from_slice(&policy.statement());
            }
        }
        wire.extend_from_slice(&active.id);
        wire.extend_from_slice(&active.owner);
        wire.extend_from_slice(&expected_revision.to_be_bytes());
        wire.extend_from_slice(&image.digest);
        wire.extend_from_slice(&image.revision.to_be_bytes());
        wire.extend_from_slice(&image_hash(target));
        let length = u32::try_from(target.len()).map_err(|_| DurableError::Capacity)?;
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(target);
        let mut auth = authenticator(&active.key)?;
        auth.update(&wire);
        wire.extend_from_slice(&auth.finalize().into_bytes());
        Self::decode(&active.key, active.owner, active.id, &wire)
    }
    fn decode(
        key: &JournalKey,
        owner: [u8; 32],
        id: [u8; 32],
        wire: &[u8],
    ) -> Result<Self, DurableError> {
        match Self::decode_checked(key, owner, id, wire) {
            Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
            result => result,
        }
    }
    fn decode_checked(
        key: &JournalKey,
        owner: [u8; 32],
        id: [u8; 32],
        wire: &[u8],
    ) -> Result<Self, DurableError> {
        if !(INTENT_HEADER + HEADER + 16 + 115 + 32
            ..=INTENT_HEADER + MAX_BOUND_BINDING_BYTES + MAX_TARGET + 32)
            .contains(&wire.len())
        {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let binding = match d.array::<8>()? {
            tag if tag == *b"QPWINT01" => None,
            tag if tag == *b"QPWINT07" => Some(BoundTransaction::Roster(
                crate::RosterRefreshScope::decode(&mut d)?,
            )),
            tag if tag == *b"QPWINT06" => {
                let operation = crate::PolicyRenewalId::from_trusted_state(d.array()?)?;
                let statement = d.array()?;
                crate::codec::nonzero(&statement)?;
                Some(BoundTransaction::Policy(PolicyRenewalBinding {
                    operation,
                    statement,
                }))
            }
            tag if tag == *b"QPWINT02" || tag == *b"QPWINT04" => {
                let operation = crate::CredentialRenewalId::from_trusted_state(d.array()?)?;
                let credential = d.array()?;
                crate::codec::nonzero(&credential)?;
                let policy = if tag == *b"QPWINT04" {
                    let [mode] = d.array()?;
                    let statement = d.array()?;
                    crate::codec::nonzero(&statement)?;
                    Some(match mode {
                        0 => PolicyIntent::Retain(statement),
                        1 => PolicyIntent::Adopt(statement),
                        _ => return Err(DurableError::Corrupt),
                    })
                } else {
                    None
                };
                Some(BoundTransaction::Credential(RenewalBinding {
                    operation,
                    credential,
                    policy,
                }))
            }
            _ => return Err(DurableError::Corrupt),
        };
        if d.array::<32>()? != id || d.array::<32>()? != owner {
            return Err(DurableError::Conflict);
        }
        let expected_revision = u64::from_be_bytes(d.array()?);
        let expected_digest = d.array()?;
        let next_revision = u64::from_be_bytes(d.array()?);
        let next_digest = d.array()?;
        let length = u32::from_be_bytes(d.array()?) as usize;
        if expected_revision == 0
            || next_revision == u64::MAX
            || expected_revision.checked_add(1) != Some(next_revision)
            || length > MAX_TARGET
        {
            return Err(DurableError::Corrupt);
        }
        let target = d.take(length)?.to_vec();
        d.finish()?;
        if image_hash(&target) != next_digest {
            return Err(DurableError::Corrupt);
        }
        let next = unseal(key, owner, &target)?;
        if next.id != id || next.revision != next_revision {
            return Err(DurableError::Conflict);
        }
        match binding {
            Some(BoundTransaction::Credential(r)) => {
                rosters::check_credential_renewal_intent(&next, r)?
            }
            Some(BoundTransaction::Policy(p)) => rosters::check_policy_renewal_intent(&next, p)?,
            Some(BoundTransaction::Roster(scope)) => {
                rosters::check_roster_refresh_intent(&next, scope)?
            }
            None => {}
        }
        Ok(Self {
            expected_revision,
            expected_digest,
            next_revision,
            next_digest,
            target,
            wire: wire.to_vec(),
            protection: next.protection,
            local_account: next.local_account,
            binding,
        })
    }
    fn check_current(&self, current: &Image) -> Result<(), DurableError> {
        if current.revision == self.expected_revision
            && current.digest == self.expected_digest
            && current.protection == self.protection
            && current.local_account == self.local_account
        {
            Ok(())
        } else {
            Err(DurableError::Conflict)
        }
    }
    fn credential_proposal(
        &self,
        current: &Image,
    ) -> Result<crate::AnchorCredentialRenewalProposal, DurableError> {
        let Some(BoundTransaction::Credential(binding)) = self.binding else {
            return Err(DurableError::Conflict);
        };
        self.check_transaction_image(current)?;
        let Protection::Required {
            policy,
            witness,
            fence,
        } = current.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        let mut subject = current.id.to_vec();
        subject.extend_from_slice(&current.owner);
        subject.extend_from_slice(&policy);
        let proposal = crate::AnchorCredentialRenewalProposal::from_journal(
            witness,
            crate::AnchorSubject::from_trusted_state(&subject)?,
            binding.operation,
            binding.credential,
            crate::AnchorHead::from_trusted_state(
                fence,
                self.expected_revision,
                self.expected_digest,
            )?,
            crate::AnchorHead::from_trusted_state(fence, self.next_revision, self.next_digest)?,
        )?;
        Ok(match binding.policy {
            Some(policy) => {
                proposal.bind_policy_expectation(policy.statement(), policy.adopts())?
            }
            None => proposal,
        })
    }
    fn check_transaction_image(&self, current: &Image) -> Result<(), DurableError> {
        if self.binding.is_some()
            && current.revision == self.next_revision
            && current.digest == self.next_digest
            && current.protection == self.protection
            && current.local_account == self.local_account
        {
            Ok(())
        } else {
            self.check_current(current)
        }
    }
}

fn authenticator(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let derived = key.write_intent_key()?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| DurableError::Protocol(Error::Provider))
}

pub(super) fn load_snapshot(
    db: &Database,
    key: &JournalKey,
    owner: [u8; 32],
) -> Result<(Image, Option<PendingWrite>), DurableError> {
    load_snapshot_as(db, key, owner, SnapshotAdmission::Ordinary)
}

enum SnapshotAdmission {
    Ordinary,
    CredentialRecovery,
    PolicyRecovery,
    RosterRecovery,
}

fn load_snapshot_as(
    db: &Database,
    key: &JournalKey,
    owner: [u8; 32],
    admission: SnapshotAdmission,
) -> Result<(Image, Option<PendingWrite>), DurableError> {
    let (image, pending) = load_pending_snapshot(db, key, owner, admission)?;
    match pending {
        Some(PendingIntent::Cancellation(_)) => Err(DurableError::Suspended),
        Some(PendingIntent::Write(p)) => Ok((image, Some(p))),
        None => Ok((image, None)),
    }
}

fn load_pending_snapshot(
    db: &Database,
    key: &JournalKey,
    owner: [u8; 32],
    admission: SnapshotAdmission,
) -> Result<(Image, Option<PendingIntent>), DurableError> {
    let read = db.begin_read().map_err(storage)?;
    let table = image_table(&read)?;
    let value = table
        .get("image")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    let image = unseal(key, owner, value.value())?;
    let pending = table.get("pending").map_err(storage)?;
    if table.len().map_err(storage)? != if pending.is_some() { 2 } else { 1 } {
        return Err(DurableError::Corrupt);
    }
    let pending = pending
        .map(|bytes| {
            if bytes.value().starts_with(b"QPWINT03") || bytes.value().starts_with(b"QPWINT05") {
                PendingCancellation::decode(key, bytes.value()).map(PendingIntent::Cancellation)
            } else {
                PendingWrite::decode(key, owner, image.id, bytes.value()).map(PendingIntent::Write)
            }
        })
        .transpose()?;
    if let Some(PendingIntent::Cancellation(intent)) = &pending {
        intent.check_current(&image)?;
    }
    if let Some(PendingIntent::Write(intent)) = &pending {
        if matches!(
            (&admission, intent.binding),
            (
                SnapshotAdmission::CredentialRecovery,
                Some(BoundTransaction::Credential(_))
            ) | (
                SnapshotAdmission::PolicyRecovery,
                Some(BoundTransaction::Policy(_))
            ) | (
                SnapshotAdmission::RosterRecovery,
                Some(BoundTransaction::Roster(_))
            )
        ) && value.value() == intent.target
        {
            intent.check_transaction_image(&image)?;
        } else {
            intent.check_current(&image)?;
        }
    }
    Ok((image, pending))
}

// The writer lease is held throughout. The expected image and exact intent are
// still checked inside the write transaction, not from a cached pre-lock read.
fn apply(db: &Database, pending: &PendingWrite) -> Result<(), DurableError> {
    // Ordinary recovery cannot commit a credential or independent-policy
    // transition without its exact witness head-and-authority transaction.
    if pending.binding.is_some() {
        return Err(DurableError::Suspended);
    }
    let tx = transaction(db)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        let current = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        let current_digest = image_hash(current.value());
        if current_digest != pending.expected_digest && current_digest != pending.next_digest {
            return Err(DurableError::Conflict);
        }
        drop(current);
        let saved = table.get("pending").map_err(storage)?;
        match saved.as_ref() {
            None if current_digest == pending.next_digest && table.len().map_err(storage)? == 1 => {
                return Ok(()); // Exact state already committed; no second advance.
            }
            Some(saved)
                if saved.value() == pending.wire
                    && current_digest == pending.expected_digest
                    && table.len().map_err(storage)? == 2 => {}
            _ => return Err(DurableError::Conflict),
        }
        drop(saved);
        table
            .insert("image", pending.target.as_slice())
            .map_err(storage)?;
        table.remove("pending").map_err(storage)?;
    }
    tx.commit().map_err(DurableError::CommitUncertain)
}

pub(super) fn commit(
    active: &mut Active,
    image: &Image,
    target: &[u8],
) -> Result<(), DurableError> {
    let pending = PendingWrite::new(active, image, target)?;
    reserve(active, &pending)?;
    #[cfg(all(test, unix))]
    tests::after_intent(&pending, image);
    reconcile(active, &pending)
}

pub(super) fn reconcile(active: &mut Active, pending: &PendingWrite) -> Result<(), DurableError> {
    if pending.binding.is_some() {
        return Err(DurableError::Suspended);
    }
    if pending.protection != active.protection {
        return Err(DurableError::Conflict);
    }
    active.advance_anchor(
        pending.expected_revision,
        pending.expected_digest,
        pending.next_digest,
    )?;
    apply(&active.db, pending)
}

pub(super) fn reserve_credential_renewal(
    active: &Active,
    image: &Image,
    target: &[u8],
    binding: RenewalBinding,
) -> Result<crate::AnchorCredentialRenewalProposal, DurableError> {
    let pending = PendingWrite::new_bound(
        active,
        image,
        target,
        Some(BoundTransaction::Credential(binding)),
    )?;
    reserve(active, &pending)?;
    #[cfg(all(test, unix))]
    {
        tests::after_bound_preparation();
        tests::after_intent(&pending, image);
    }
    let (current, readback) = load_snapshot(&active.db, &active.key, active.owner)?;
    let readback = readback.ok_or(DurableError::Conflict)?;
    if readback.wire != pending.wire {
        return Err(DurableError::Conflict);
    }
    readback.credential_proposal(&current)
}

impl DeviceJournal {
    /// Read original authenticated preparation metadata without applying its
    /// target, dispatching to a witness, or claiming current authority. `None`
    /// means no local pending record; it is never evidence of witness NoCommit.
    /// A different pending operation is explicitly rejected.
    pub fn inspect_credential_renewal_preparation(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        expected_id: JournalIdentity,
    ) -> Result<Option<crate::AnchorCredentialRenewalProposal>, DurableError> {
        Self::inspect_witnessed_credential_intent(path, key, original, policy, expected_id)?
            .map(WitnessedCredentialIntent::proposal)
            .transpose()
    }
    pub(crate) fn inspect_witnessed_credential_intent(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        expected_id: JournalIdentity,
    ) -> Result<Option<WitnessedCredentialIntent>, DurableError> {
        let db = open_private_database(path)?;
        let (image, pending) = load_pending_snapshot(
            &db,
            &key,
            bootstrap::storage_owner(original),
            SnapshotAdmission::CredentialRecovery,
        )?;
        credential_cancellation::check_scope(&image, original, policy.as_ref(), expected_id)?;
        pending
            .map(|intent| intent.credential_intent(&image))
            .transpose()
    }

    /// Reconcile this exact retained preparation using a fresh signed status
    /// request. Only Applied installs the original sealed target. The pending
    /// record remains intact even after that local write, including on retry.
    ///
    /// This historical operation never commits/closes/acknowledges a witness
    /// proposal, erases local intent, or releases an operational journal owner.
    /// Unavailable is an unresolved witness observation, never NoCommit. Original
    /// enrollment must durably retain the terminal before later acknowledgement.
    pub fn recover_credential_renewal(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        expected_id: JournalIdentity,
        proposal: crate::AnchorCredentialRenewalProposal,
        client: &mut crate::AnchorClient,
    ) -> Result<crate::AnchorCredentialRenewalState, DurableError> {
        let policy = policy.as_ref();
        let db = open_private_database(path)?;
        recover_credential_renewal(&db, &key, original, policy, expected_id, proposal, client)
    }
}

pub(super) fn recover_credential_renewal(
    db: &Database,
    key: &JournalKey,
    original: &crate::VerifiedDevice,
    policy: &impl AsRef<crate::HistoricalSessionPolicy>,
    expected_id: JournalIdentity,
    proposal: crate::AnchorCredentialRenewalProposal,
    client: &mut crate::AnchorClient,
) -> Result<crate::AnchorCredentialRenewalState, DurableError> {
    recover_witnessed_credential_intent(
        db,
        key,
        original,
        policy,
        expected_id,
        WitnessedCredentialIntent::Proposal(proposal),
        client,
    )
}

pub(super) fn recover_witnessed_credential_intent(
    db: &Database,
    key: &JournalKey,
    original: &crate::VerifiedDevice,
    policy: &impl AsRef<crate::HistoricalSessionPolicy>,
    expected_id: JournalIdentity,
    proposal: WitnessedCredentialIntent,
    client: &mut crate::AnchorClient,
) -> Result<crate::AnchorCredentialRenewalState, DurableError> {
    use crate::AnchorCredentialRenewalState as State;
    let policy = policy.as_ref();
    let owner = bootstrap::storage_owner(original);
    let (image, pending) =
        load_pending_snapshot(db, key, owner, SnapshotAdmission::CredentialRecovery)?;
    if image.id != expected_id.0 || image.local_account != original.account_id() {
        return Err(DurableError::Conflict);
    }
    image.protection.check_policy(policy)?;
    let pending = pending.ok_or(DurableError::Conflict)?;
    if pending.credential_intent(&image)? != proposal
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
    let reply = client.exchange(proposal.subject(), proposal.status_operation())?;
    let observed = proposal.interpret(&reply)?;
    match observed {
        State::Applied => {
            let PendingIntent::Write(pending) = &pending else {
                return Err(DurableError::Conflict);
            };
            apply_bound_target(db, pending)?;
            #[cfg(all(test, unix))]
            tests::after_credential_recovery();
            let (current, readback) =
                load_pending_snapshot(db, key, owner, SnapshotAdmission::CredentialRecovery)?;
            if current.revision != pending.next_revision
                || current.digest != pending.next_digest
                || readback.ok_or(DurableError::Conflict)?.wire() != pending.wire
            {
                return Err(DurableError::Conflict);
            }
        }
        State::Prepared | State::Closed if image.digest != proposal.expected_head().digest() => {
            return Err(DurableError::Conflict);
        }
        State::Prepared | State::Closed | State::Unavailable => {}
        State::Acknowledged => return Err(Error::State.into()),
    }
    Ok(observed)
}

impl DeviceJournal {
    // Original enrollment calls this only after authenticated terminal readback.
    // Terminal metadata is historical and never supplies current authority.
    pub(crate) fn retire_witnessed_credential_intent(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        expected_id: JournalIdentity,
        terminal: &crate::enrollment::PersistedRenewalTerminal,
        client: &mut crate::AnchorClient,
    ) -> Result<(), DurableError> {
        let policy = policy.as_ref();
        let db = open_private_database(path)?;
        Self::retire_witnessed_credential_intent_in_database(
            &db,
            &key,
            original,
            policy,
            expected_id,
            terminal,
            client,
        )
    }
    pub(crate) fn retire_witnessed_credential_intent_in_database(
        db: &Database,
        key: &JournalKey,
        original: &crate::VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        expected_id: JournalIdentity,
        terminal: &crate::enrollment::PersistedRenewalTerminal,
        client: &mut crate::AnchorClient,
    ) -> Result<(), DurableError> {
        use crate::AnchorCredentialRenewalState as State;
        let policy = policy.as_ref();
        let (proposal, state, adopted_policy) = terminal.parts();
        let expected = match state {
            State::Applied => proposal.proposal()?.target_head(),
            State::Closed => proposal.expected_head(),
            _ => return Err(DurableError::Conflict),
        };
        let owner = bootstrap::storage_owner(original);
        let (image, pending) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::CredentialRecovery)?;
        image.protection.check_policy(policy)?;
        if image.id != expected_id.0
            || image.local_account != original.account_id()
            || proposal.subject()
                != crate::AnchorSubject::for_device(expected_id, original, policy)?
            || client.pin().binding() != proposal.witness_binding()
            || policy.anchor_requirement().binding() != Some(proposal.witness_binding())
            || image.protection.head(image.revision, image.digest)? != expected
        {
            return Err(DurableError::Conflict);
        }
        if let Some(pending) = &pending {
            if pending.credential_intent(&image)? != proposal {
                return Err(DurableError::Conflict);
            }
        }
        rosters::check_terminal_completion(&image, adopted_policy, terminal.completed())?;
        client.check_device(original)?;
        policy.check_external_signer(client.pin().public_key())?;
        if client
            .pin()
            .public_key()
            .shares_component(&original.authority_key)
        {
            return Err(Error::Scope.into());
        }
        let reply = client.exchange(proposal.subject(), proposal.acknowledge_operation())?;
        match proposal.interpret(&reply)? {
            State::Acknowledged | State::Unavailable => {}
            _ => return Err(DurableError::Conflict),
        }
        // Unavailable is accepted ONLY with the durable original Terminal: a
        // monotonic witness cannot replace an unacknowledged terminal slot. Its
        // bounded last-ACK may have been overwritten by later approved work.
        // It never creates an Applied/Closed fact and never authorizes image edits.
        let tx = transaction(db)?;
        {
            let mut table = tx.open_table(TABLE).map_err(storage)?;
            let current = table
                .get("image")
                .map_err(storage)?
                .ok_or(DurableError::Corrupt)?;
            if image_hash(current.value()) != expected.digest() {
                return Err(DurableError::Conflict);
            }
            drop(current);
            let saved = table.get("pending").map_err(storage)?;
            match (saved.as_ref(), pending.as_ref()) {
                (None, None) if table.len().map_err(storage)? == 1 => return Ok(()),
                (Some(saved), Some(pending))
                    if saved.value() == pending.wire() && table.len().map_err(storage)? == 2 => {}
                _ => return Err(DurableError::Conflict),
            }
            drop(saved);
            table.remove("pending").map_err(storage)?;
        }
        tx.commit().map_err(DurableError::CommitUncertain)?;
        let (readback, retained) = load_snapshot(db, key, owner)?;
        if retained.is_some()
            || readback
                .protection
                .head(readback.revision, readback.digest)?
                != expected
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}

fn apply_bound_target(db: &Database, pending: &PendingWrite) -> Result<(), DurableError> {
    if pending.binding.is_none() {
        return Err(DurableError::Conflict);
    }
    let tx = transaction(db)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        if table.len().map_err(storage)? != 2 {
            return Err(DurableError::Conflict);
        }
        let saved = table
            .get("pending")
            .map_err(storage)?
            .ok_or(DurableError::Conflict)?;
        if saved.value() != pending.wire {
            return Err(DurableError::Conflict);
        }
        drop(saved);
        let current = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        if current.value() == pending.target {
            return Ok(()); // Keep the exact original intent; do not write again.
        }
        if image_hash(current.value()) != pending.expected_digest {
            return Err(DurableError::Conflict);
        }
        drop(current);
        table
            .insert("image", pending.target.as_slice())
            .map_err(storage)?;
    }
    tx.commit().map_err(DurableError::CommitUncertain)
}

fn reserve(active: &Active, pending: &PendingWrite) -> Result<(), DurableError> {
    reserve_bytes(&active.db, pending.expected_digest, &pending.wire)
}
fn reserve_bytes(
    db: &Database,
    expected_digest: [u8; 32],
    wire: &[u8],
) -> Result<(), DurableError> {
    let tx = transaction(db)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        if table.len().map_err(storage)? != 1 || table.get("pending").map_err(storage)?.is_some() {
            return Err(DurableError::Conflict);
        }
        let current = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        if image_hash(current.value()) != expected_digest {
            return Err(DurableError::Conflict);
        }
        drop(current);
        table.insert("pending", wire).map_err(storage)?;
    }
    tx.commit().map_err(DurableError::CommitUncertain)
}

/// Read-only cleanup admission. An untrusted header is only a decryption hint;
/// the complete image and independent expected ID authenticate before any write.
pub(super) fn load_cleanup_snapshot(
    db: &Database,
    key: &JournalKey,
    expected: JournalIdentity,
) -> Result<(Image, Option<PendingWrite>), DurableError> {
    let owner = {
        let read = db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        let value = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        let wire = value.value();
        if !(HEADER + 16..=HEADER + MAX_IMAGE + 16).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        wire.get(40..72)
            .ok_or(DurableError::Corrupt)?
            .try_into()
            .map_err(|_| DurableError::Corrupt)?
    };
    let (image, pending) = load_snapshot(db, key, owner)?;
    if image.id != expected.0 {
        return Err(DurableError::Conflict);
    }
    Ok((image, pending))
}

pub(super) fn recover(
    db: &Database,
    key: &JournalKey,
    owner: [u8; 32],
    expected_id: JournalIdentity,
) -> Result<Image, DurableError> {
    let (image, pending) = load_snapshot(db, key, owner)?;
    if image.id != expected_id.0 {
        return Err(DurableError::Conflict);
    }
    if image.protection != Protection::Local {
        return Err(DurableError::AnchorRequired);
    }
    if let Some(pending) = pending {
        apply(db, &pending)?;
        let recovered = load(db, key, owner)?;
        if recovered.id != image.id
            || recovered.revision != pending.next_revision
            || recovered.digest != pending.next_digest
        {
            return Err(DurableError::Conflict);
        }
        Ok(recovered)
    } else {
        Ok(image)
    }
}

// Shared final cleanup kernel. Callers must authenticate their independently typed
// original enrollment terminal and exact signed witness ACK before entering.
fn remove_retired_bound_pending(
    db: &Database,
    key: &JournalKey,
    owner: [u8; 32],
    expected: crate::AnchorHead,
    pending: Option<&PendingIntent>,
) -> Result<(), DurableError> {
    let tx = transaction(db)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        let current = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        if image_hash(current.value()) != expected.digest() {
            return Err(DurableError::Conflict);
        }
        drop(current);
        let saved = table.get("pending").map_err(storage)?;
        match (saved.as_ref(), pending) {
            (None, None) if table.len().map_err(storage)? == 1 => return Ok(()),
            (Some(saved), Some(pending))
                if saved.value() == pending.wire() && table.len().map_err(storage)? == 2 => {}
            _ => return Err(DurableError::Conflict),
        }
        drop(saved);
        table.remove("pending").map_err(storage)?;
    }
    tx.commit().map_err(DurableError::CommitUncertain)?;
    let (readback, retained) = load_snapshot(db, key, owner)?;
    if retained.is_some()
        || readback
            .protection
            .head(readback.revision, readback.digest)?
            != expected
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
