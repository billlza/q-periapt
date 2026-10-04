// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Target-free reservation, sharing the journal's exclusive pending slot.
use super::*;
use crate::{
    AnchorCredentialRenewalCancellation as Cancellation,
    AnchorCredentialRenewalProposal as Proposal, AnchorCredentialRenewalState as State,
    AnchorOperation, AnchorSubject,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WitnessedCredentialIntent {
    Proposal(Proposal),
    Cancellation(Cancellation),
}
impl WitnessedCredentialIntent {
    pub(crate) fn proposal(self) -> Result<Proposal, DurableError> {
        match self {
            Self::Proposal(p) => Ok(p),
            Self::Cancellation(_) => Err(DurableError::Suspended),
        }
    }
    pub(crate) fn operation(self) -> crate::CredentialRenewalId {
        match self {
            Self::Proposal(p) => p.operation(),
            Self::Cancellation(c) => c.operation(),
        }
    }
    pub(crate) fn statement(self) -> [u8; 32] {
        match self {
            Self::Proposal(p) => p.statement(),
            Self::Cancellation(c) => c.statement(),
        }
    }
    pub(crate) fn subject(self) -> AnchorSubject {
        match self {
            Self::Proposal(p) => p.subject(),
            Self::Cancellation(c) => c.subject(),
        }
    }
    pub(crate) fn witness_binding(self) -> [u8; 32] {
        match self {
            Self::Proposal(p) => p.witness_binding(),
            Self::Cancellation(c) => c.witness_binding(),
        }
    }
    pub(crate) fn expected_head(self) -> crate::AnchorHead {
        match self {
            Self::Proposal(p) => p.expected_head(),
            Self::Cancellation(c) => c.expected_head(),
        }
    }
    pub(super) fn status_operation(self) -> AnchorOperation {
        match self {
            Self::Proposal(p) => AnchorOperation::credential_renewal_status(&p),
            Self::Cancellation(c) => AnchorOperation::credential_cancellation_status(&c),
        }
    }
    pub(super) fn acknowledge_operation(self) -> AnchorOperation {
        match self {
            Self::Proposal(p) => AnchorOperation::acknowledge_credential_renewal(&p),
            Self::Cancellation(c) => AnchorOperation::acknowledge_credential_cancellation(&c),
        }
    }
    pub(crate) fn interpret(self, reply: &crate::AnchorReply) -> Result<State, DurableError> {
        use crate::AnchorCredentialCancellationState as CancellationState;
        Ok(match self {
            Self::Proposal(p) => reply.credential_renewal_state(&p)?,
            Self::Cancellation(c) => match reply.credential_cancellation_state(&c)? {
                CancellationState::Closed => State::Closed,
                CancellationState::Acknowledged => State::Acknowledged,
                CancellationState::Unavailable => State::Unavailable,
            },
        })
    }
}

pub(super) struct PendingCancellation {
    pub(super) cancellation: Cancellation,
    pub(super) wire: Vec<u8>,
    local_account: [u8; 32],
}
impl PendingCancellation {
    fn new(
        key: &JournalKey,
        image: &Image,
        cancellation: Cancellation,
    ) -> Result<Self, DurableError> {
        let mut wire = b"QPWINT03".to_vec();
        wire.extend_from_slice(&image.local_account);
        wire.extend_from_slice(&cancellation.to_bytes());
        let mut auth = authenticator(key)?;
        auth.update(&wire);
        wire.extend_from_slice(&auth.finalize().into_bytes());
        let pending = Self::decode(key, &wire)?;
        pending.check_current(image)?;
        Ok(pending)
    }
    pub(super) fn decode(key: &JournalKey, wire: &[u8]) -> Result<Self, DurableError> {
        if wire.len() != 320 {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(288);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *b"QPWINT03" {
            return Err(DurableError::Corrupt);
        }
        let local_account = d.array()?;
        crate::codec::nonzero(&local_account)?;
        let cancellation = Cancellation::from_trusted_state(d.take(248)?)?;
        d.finish()?;
        Ok(Self {
            cancellation,
            wire: wire.to_vec(),
            local_account,
        })
    }
    pub(super) fn check_current(&self, image: &Image) -> Result<(), DurableError> {
        let Protection::Required {
            policy, witness, ..
        } = image.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        let mut subject = image.id.to_vec();
        subject.extend_from_slice(&image.owner);
        subject.extend_from_slice(&policy);
        if image.local_account != self.local_account
            || self.cancellation.subject() != AnchorSubject::from_trusted_state(&subject)?
            || self.cancellation.witness_binding() != witness
            || self.cancellation.expected_head()
                != image.protection.head(image.revision, image.digest)?
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}

pub(super) fn check_scope(
    image: &Image,
    original: &crate::VerifiedDevice,
    policy: &crate::HistoricalSessionPolicy,
    id: JournalIdentity,
) -> Result<(), DurableError> {
    if image.id != id.0
        || image.owner != bootstrap::storage_owner(original)
        || image.local_account != original.account_id()
    {
        return Err(DurableError::Conflict);
    }
    image.protection.check_policy(policy)?;
    if !matches!(image.protection, Protection::Required { .. }) {
        return Err(DurableError::AnchorRequired);
    }
    Ok(())
}

impl DeviceJournal {
    // Only the original enrollment may supply the authenticated prior completion.
    // The database lease spans validation, reservation and exact readback.
    pub(crate) fn reserve_enrollment_credential_cancellation(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        policy: &crate::HistoricalSessionPolicy,
        id: JournalIdentity,
        grant: &crate::HistoricalCredentialRenewal,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<Cancellation, DurableError> {
        let db = open_private_database(path)?;
        Self::reserve_credential_cancellation_in_database(
            &db, &key, original, policy, id, grant, completed,
        )
    }
    pub(crate) fn reserve_credential_cancellation_in_database(
        db: &Database,
        key: &JournalKey,
        original: &crate::VerifiedDevice,
        policy: &crate::HistoricalSessionPolicy,
        id: JournalIdentity,
        grant: &crate::HistoricalCredentialRenewal,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<Cancellation, DurableError> {
        let owner = bootstrap::storage_owner(original);
        let (image, pending) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::CredentialRecovery)?;
        check_scope(&image, original, policy, id)?;
        rosters::check_credential_cancellation(&image, grant, completed)?;
        if let Some(pending) = pending {
            return match pending {
                PendingIntent::Cancellation(p)
                    if p.cancellation.operation() == grant.operation()
                        && p.cancellation.statement() == grant.statement_digest() =>
                {
                    Ok(p.cancellation)
                }
                _ => Err(DurableError::Conflict),
            };
        }
        let mut bytes = b"QPCRNC01".to_vec();
        bytes.extend_from_slice(
            &policy
                .anchor_requirement()
                .binding()
                .ok_or(DurableError::AnchorRequired)?,
        );
        bytes.extend_from_slice(&AnchorSubject::for_device(id, original, policy)?.to_bytes());
        bytes.extend_from_slice(grant.operation().as_bytes());
        bytes.extend_from_slice(&grant.statement_digest());
        let head = image.protection.head(image.revision, image.digest)?;
        bytes.extend_from_slice(&head.fence().to_be_bytes());
        bytes.extend_from_slice(&head.revision().to_be_bytes());
        bytes.extend_from_slice(&head.digest());
        let cancellation = Cancellation::from_trusted_state(&bytes)?;
        let pending = PendingCancellation::new(key, &image, cancellation)?;
        reserve_bytes(db, image.digest, &pending.wire)?;
        let (image, readback) =
            load_pending_snapshot(db, key, owner, SnapshotAdmission::CredentialRecovery)?;
        let readback = readback.ok_or(DurableError::Conflict)?;
        if readback.wire() != pending.wire
            || readback.credential_intent(&image)?
                != WitnessedCredentialIntent::Cancellation(cancellation)
        {
            return Err(DurableError::Conflict);
        }
        Ok(cancellation)
    }
    pub(crate) fn recover_witnessed_credential_intent(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        policy: &crate::HistoricalSessionPolicy,
        id: JournalIdentity,
        intent: WitnessedCredentialIntent,
        client: &mut crate::AnchorClient,
    ) -> Result<State, DurableError> {
        let db = open_private_database(path)?;
        super::recover_witnessed_credential_intent(&db, &key, original, policy, id, intent, client)
    }
}
