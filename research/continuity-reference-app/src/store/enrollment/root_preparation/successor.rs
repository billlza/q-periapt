// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Route one original enrollment through its selected issuer, without selecting it as current.
use super::*;
use crate::root_preparation::{SuccessorObservation, SuccessorRequest};

pub(in super::super) enum Issuer {
    Current(Root),
    Candidate(Record),
}
impl Issuer {
    pub(in super::super) fn root(&self) -> &Root {
        match self {
            Self::Current(root) => root,
            Self::Candidate(record) => &record.candidate,
        }
    }
    pub(in super::super) fn root_mut(&mut self) -> &mut Root {
        match self {
            Self::Current(root) => root,
            Self::Candidate(record) => &mut record.candidate,
        }
    }
    pub(in super::super) fn persist(
        &self,
        tx: &redb::WriteTransaction,
        account: &Account,
    ) -> Result<(), Error> {
        match self {
            Self::Current(root) => save_root(tx, root),
            Self::Candidate(record) => {
                record.check(account, record.operation)?;
                save(tx, record)
            }
        }
    }
    pub(in super::super) fn retain_reapproval(
        &mut self,
        tx: &redb::WriteTransaction,
        account: &Account,
        enrollment: [u8; 32],
    ) -> Result<(), Error> {
        if let Self::Candidate(record) = self {
            record.enrollment = Some(enrollment);
            record.check(account, record.operation)?;
            save(tx, record)?;
        }
        Ok(())
    }
}
impl Record {
    fn admits_successor(&self, current: &Root, family: [u8; 32]) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Conflict(
                "Original root preparation is permanently closed",
            ));
        }
        let old = current.info(family)?;
        if old.revision != self.request.predecessor.revision
            || old.account != self.request.predecessor.account
        {
            return Err(Error::Conflict(
                "Candidate predecessor is no longer the current account root",
            ));
        }
        // Old suspension and private-key availability are independent of candidate issuance.
        self.candidate.info(family)?;
        Ok(())
    }
}
impl Store {
    /// Recover this candidate's latest original enrollment link, even if an
    /// earlier invitation was reapproved before its caller received the reply.
    pub fn root_successor(
        &mut self,
        account: &Account,
        preparation: [u8; 32],
    ) -> Result<SuccessorObservation, Error> {
        self.action(|store| {
            store.admits_root_preparation(account)?;
            if !store.root_successors {
                return Err(Error::Conflict(
                    "Root successor enrollment requires explicit schema-9 upgrade",
                ));
            }
            let record = store.root_preparation_record(account, preparation)?;
            let enrollment = match record.enrollment {
                None => None,
                Some(id) => {
                    let op = store
                        .operation(account, id)
                        .map_err(|e| Error::internal("retained candidate enrollment", e))?;
                    if op.root_preparation != Some(preparation) {
                        return Err(Error::Internal);
                    }
                    Some(op.invitation)
                }
            };
            Ok(SuccessorObservation {
                preparation,
                enrollment,
            })
        })
    }
    pub(in super::super) fn enrollment_issuer(
        &self,
        account: &Account,
        op: &Operation,
    ) -> Result<Issuer, Error> {
        let current = self.root(account)?;
        let Some(preparation) = op.root_preparation else {
            return Ok(Issuer::Current(current));
        };
        if !self.root_successors {
            return Err(Error::Internal);
        }
        let record = self.root_preparation_record(account, preparation)?;
        if record.enrollment != Some(op.invitation.operation) {
            return Err(Error::Conflict(
                "Candidate enrollment has a different original successor",
            ));
        }
        record.admits_successor(&current, self.family()?)?;
        record
            .candidate
            .admits_authority(&op.invitation, self.family()?)?;
        Ok(Issuer::Candidate(record))
    }
    pub(in super::super) fn link_root_successor(
        &self,
        tx: &redb::WriteTransaction,
        account: &Account,
        preparation: [u8; 32],
        invitation: &Invitation,
    ) -> Result<(), Error> {
        if !self.root_successors {
            return Err(Error::Conflict(
                "Root successor enrollment requires explicit schema-9 upgrade",
            ));
        }
        let mut record = self.root_preparation_record(account, preparation)?;
        record.admits_successor(&self.root(account)?, self.family()?)?;
        if record.enrollment.is_some() || !record.candidate.members.is_empty() {
            return Err(Error::Conflict(
                "Candidate already has an original successor enrollment",
            ));
        }
        record.candidate.admits(invitation, self.family()?)?;
        record.enrollment = Some(invitation.operation);
        record.check(account, preparation)?;
        save(tx, &record)
    }
    /// Invite one target under an explicitly selected candidate. Approval and
    /// issuance use the existing original-operation APIs and never change ROOTS.
    pub fn invite_root_successor(
        &mut self,
        account: &Account,
        request: &SuccessorRequest,
    ) -> Result<Invitation, Error> {
        self.action(|store| {
            store.admits_root_preparation(account)?;
            if !store.root_successors {
                return Err(Error::Conflict(
                    "Root successor enrollment requires explicit schema-9 upgrade",
                ));
            }
            if request.preparation == [0; 32] || request.request_id == [0; 32] {
                return Err(Error::Invalid(
                    "Nonzero candidate and enrollment correlation required",
                ));
            }
            if let Some(saved) = store.invitation_for_request(account, request.request_id)? {
                if saved.root_preparation != Some(request.preparation) {
                    return Err(Error::Conflict(
                        "Original candidate enrollment request differs",
                    ));
                }
                return Ok(saved.invitation);
            }
            let record = store.root_preparation_record(account, request.preparation)?;
            record.admits_successor(&store.root(account)?, store.family()?)?;
            if record.enrollment.is_some() {
                return Err(Error::Conflict(
                    "Candidate already has an original successor enrollment",
                ));
            }
            let info = record.candidate.info(store.family()?)?;
            let now = now()?;
            let invitation = Invitation {
                operation: random()?,
                request_id: request.request_id,
                application: account.application_id,
                root_revision: info.revision,
                root: info.public_key,
                family: info.family,
                device: random()?,
                generation: 1,
                valid_from: now,
                valid_until: now.checked_add(3600).ok_or(Error::Capacity)?,
                deadline: now.checked_add(300).ok_or(Error::Capacity)?,
                predecessor: None,
            };
            store.persist_invitation(account, &invitation, None, Some(request.preparation))?;
            Ok(invitation)
        })
    }
}
