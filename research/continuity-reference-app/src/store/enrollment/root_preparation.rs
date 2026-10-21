// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retained candidate-key creation; current issuer and its suspension are unchanged.
use super::*;
use crate::root_preparation::{Candidate, Preparation, Request, Status};
mod schema;
mod successor;
pub(super) use successor::Issuer;

pub(super) const PREPARATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("root_preparations");
pub(super) const CORRELATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("root_preparation_correlations");

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    operation: [u8; 32],
    request: Request,
    #[serde(with = "wire")]
    previous_root: Vec<u8>,
    candidate: Root,
    closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enrollment: Option<[u8; 32]>,
}
impl Record {
    fn check(&self, account: &Account, operation: [u8; 32]) -> Result<(), Error> {
        if self.operation != operation
            || operation == [0; 32]
            || self.request.request_id == [0; 32]
            || self.request.predecessor.account == [0; 32]
            || self.request.predecessor.revision == 0
            || self.request.predecessor.revision.checked_add(1) != Some(self.candidate.revision)
            || self.candidate.application != account.application_id
            || self.candidate.signing_id == [0; 32]
            || self.enrollment == Some([0; 32])
            || (self.enrollment.is_some()
                && !matches!(self.candidate.phase, RootPhase::Ready { .. }))
            || self.candidate.members.len() > 1
            || (self.enrollment.is_none() && !self.candidate.members.is_empty())
            || (self.candidate.members.is_empty() != self.candidate.roster.is_none())
        {
            return Err(Error::Internal);
        }
        sdk::PublicKey::decode(&self.previous_root).map_err(db_error)?;
        if let RootPhase::Ready {
            public,
            account,
            suspended,
        } = &self.candidate.phase
        {
            sdk::PublicKey::decode(public).map_err(db_error)?;
            if *suspended
                || *account == [0; 32]
                || *account == self.request.predecessor.account
                || public == &self.previous_root
            {
                return Err(Error::Internal);
            }
        }
        Ok(())
    }
    fn description(&self, family: [u8; 32]) -> Result<Preparation, Error> {
        let status = if self.closed {
            Status::Closed
        } else {
            match &self.candidate.phase {
                RootPhase::Wrapping | RootPhase::Signing => Status::Preparing,
                RootPhase::Ready { .. } => {
                    let info = self.candidate.info(family)?;
                    Status::Prepared {
                        candidate: Candidate {
                            revision: info.revision,
                            account: info.account,
                            public_key: info.public_key,
                            family: info.family,
                        },
                    }
                }
            }
        };
        Ok(Preparation {
            schema: "qperiapt-root-preparation/1".into(),
            operation: self.operation,
            request: self.request,
            status,
        })
    }
}
fn correlation(account: &Account, request: [u8; 32]) -> Vec<u8> {
    let mut key = account.application_id.to_vec();
    key.extend_from_slice(&request);
    key
}
fn save(tx: &redb::WriteTransaction, record: &Record) -> Result<(), Error> {
    tx.open_table(PREPARATIONS)
        .map_err(db_error)?
        .insert(
            record.operation.as_slice(),
            encode(record, MAX_ROOT)?.as_slice(),
        )
        .map_err(db_error)?;
    Ok(())
}
impl Store {
    fn admits_root_preparation(&self, account: &Account) -> Result<(), Error> {
        self.authorized(account)?;
        if !self.root_preparations {
            return Err(Error::Conflict(
                "Root preparation requires explicit schema-8 upgrade",
            ));
        }
        Ok(())
    }
    fn root_preparation_record(
        &self,
        account: &Account,
        operation: [u8; 32],
    ) -> Result<Record, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(PREPARATIONS).map_err(db_error)?;
        let raw = table
            .get(operation.as_slice())
            .map_err(db_error)?
            .ok_or(Error::Conflict("Original root preparation is absent"))?;
        let record: Record = decode(raw.value(), MAX_ROOT)?;
        if record.candidate.application != account.application_id {
            return Err(Error::Unauthorized);
        }
        record.check(account, operation)?;
        if record.enrollment.is_some() && !self.root_successors {
            return Err(Error::Internal);
        }
        let key = correlation(account, record.request.request_id);
        if tx
            .open_table(CORRELATIONS)
            .map_err(db_error)?
            .get(key.as_slice())
            .map_err(db_error)?
            .is_none_or(|v| v.value() != operation)
        {
            return Err(Error::Internal);
        }
        Ok(record)
    }
    /// Prepare a separate root under host account authentication. This does not
    /// sign a credential, select the candidate, suspend the issuer or unfreeze it.
    pub fn prepare_account_root(
        &mut self,
        account: &Account,
        request: &Request,
    ) -> Result<Preparation, Error> {
        self.action(|store| {
            store.admits_root_preparation(account)?;
            if request.request_id == [0; 32]
                || request.predecessor.account == [0; 32]
                || request.predecessor.revision == 0
            {
                return Err(Error::Invalid(
                    "Original nonzero root preparation correlation and predecessor required",
                ));
            }
            let key = correlation(account, request.request_id);
            let previous = {
                let tx = store.db.begin_read().map_err(db_error)?;
                tx.open_table(CORRELATIONS)
                    .map_err(db_error)?
                    .get(key.as_slice())
                    .map_err(db_error)?
                    .map(|v| <[u8; 32]>::try_from(v.value()).map_err(db_error))
                    .transpose()?
            };
            let record = if let Some(operation) = previous {
                let record = store.root_preparation_record(account, operation)?;
                if record.request != *request {
                    return Err(Error::Conflict("Original root preparation request differs"));
                }
                record
            } else {
                let current = store.root(account)?;
                let info = current.info(store.family()?)?;
                if info.revision != request.predecessor.revision
                    || info.account != request.predecessor.account
                {
                    return Err(Error::Conflict(
                        "Current root differs from the selected predecessor",
                    ));
                }
                let revision = info.revision.checked_add(1).ok_or(Error::Capacity)?;
                let record = Record {
                    operation: random()?,
                    request: *request,
                    previous_root: info.public_key,
                    candidate: Root {
                        application: account.application_id,
                        signing_id: random()?,
                        revision,
                        phase: RootPhase::Wrapping,
                        members: Vec::new(),
                        roster: None,
                    },
                    closed: false,
                    enrollment: None,
                };
                let tx = transaction(&store.db)?;
                {
                    let rows = tx.open_table(PREPARATIONS).map_err(db_error)?;
                    let links = tx.open_table(CORRELATIONS).map_err(db_error)?;
                    if rows.len().map_err(db_error)? != links.len().map_err(db_error)? {
                        return Err(Error::Internal);
                    }
                    if rows.len().map_err(db_error)? >= MAX_OPERATIONS {
                        return Err(Error::Capacity);
                    }
                    if rows
                        .get(record.operation.as_slice())
                        .map_err(db_error)?
                        .is_some()
                        || links.get(key.as_slice()).map_err(db_error)?.is_some()
                    {
                        return Err(Error::Conflict("Root preparation identity collision"));
                    }
                }
                save(&tx, &record)?;
                tx.open_table(CORRELATIONS)
                    .map_err(db_error)?
                    .insert(key.as_slice(), record.operation.as_slice())
                    .map_err(db_error)?;
                tx.commit().map_err(db_error)?;
                #[cfg(test)]
                test_boundary("root-preparation-retained", record.operation.as_slice())?;
                record
            };
            if record.closed {
                return Err(Error::Conflict(
                    "Original root preparation is permanently closed",
                ));
            }
            let mut root = record.candidate.clone();
            store.prepare_root_keys(&mut root, |changed| {
                let mut next = record.clone();
                next.candidate = changed.clone();
                next.check(account, record.operation)?;
                let tx = transaction(&store.db)?;
                save(&tx, &next)?;
                tx.commit().map_err(db_error)
            })?;
            let result = store.root_preparation_record(account, record.operation)?;
            result.description(store.family()?)
        })
    }
    /// Read original public history even when original signing files are unavailable.
    pub fn account_root_preparation(
        &mut self,
        account: &Account,
        operation: [u8; 32],
    ) -> Result<Preparation, Error> {
        self.action(|store| {
            store.admits_root_preparation(account)?;
            store
                .root_preparation_record(account, operation)?
                .description(store.family()?)
        })
    }
    /// Permanently close an unselected candidate. Preserve files and current root;
    /// closure is not key erasure or evidence that a prior invocation did not write.
    pub fn close_account_root_preparation(
        &mut self,
        account: &Account,
        operation: [u8; 32],
    ) -> Result<Preparation, Error> {
        self.action(|store| {
            store.admits_root_preparation(account)?;
            let mut record = store.root_preparation_record(account, operation)?;
            if !record.closed {
                record.closed = true;
                let tx = transaction(&store.db)?;
                save(&tx, &record)?;
                if let Some(enrollment) = record.enrollment {
                    let mut op = store.operation(account, enrollment)?;
                    if op.root_preparation != Some(operation) {
                        return Err(Error::Internal);
                    }
                    if !matches!(op.phase, Phase::Issued { .. }) {
                        op.phase = Phase::Closed;
                        save_operation(&tx, &op)?;
                    }
                }
                #[cfg(test)]
                test_boundary("root-preparation-close-before-commit", operation.as_slice())?;
                tx.commit().map_err(db_error)?;
                #[cfg(test)]
                test_boundary("root-preparation-closed", operation.as_slice())?;
            }
            record.description(store.family()?)
        })
    }
}
