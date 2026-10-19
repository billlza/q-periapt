// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

mod schema;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    successor: [u8; 32],
    prior: PriorPhase,
    #[serde(with = "wire")]
    original_request: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
enum PriorPhase {
    Invited,
    Approved,
}

impl Store {
    /// Explicitly approve the same original device under a newly selected roster.
    /// Retain a fresh request_id before sending; retries recover this decision,
    /// never change its deadline/roster or revive a subsequently closed successor.
    /// The original credential interval, root, device metadata and request bytes stay fixed.
    pub fn reapprove_enrollment(
        &mut self,
        account: &Account,
        previous: [u8; 32],
        request_id: [u8; 32],
        predecessor: Option<Checkpoint>,
        request: &[u8],
    ) -> Result<Invitation, Error> {
        self.action(|store| {
            store.authorized(account)?;
            if !store.enrollment_reapproval {
                return Err(Error::Conflict(
                    "Reapproval requires explicit schema-3 upgrade",
                ));
            }
            if request_id == [0; 32] || request.len() > 8192 {
                return Err(Error::Invalid(
                    "Invalid reapproval correlation identity or request size",
                ));
            }
            let mut old = store.operation(account, previous)?;
            let mut correlation = account.application_id.to_vec();
            correlation.extend_from_slice(&request_id);
            let saved = store
                .db
                .begin_read()
                .map_err(db_error)?
                .open_table(REQUESTS)
                .map_err(db_error)?
                .get(correlation.as_slice())
                .map_err(db_error)?
                .map(|v| <[u8; 32]>::try_from(v.value()).map_err(|_| Error::Internal))
                .transpose()?;
            if let Some(id) = saved {
                let (transition, next) =
                    store
                        .reapproval_transition(account, &old)?
                        .ok_or(Error::Conflict(
                            "Correlation identity belongs to another operation",
                        ))?;
                if transition.successor != id
                    || transition.original_request != request
                    || next.invitation.request_id != request_id
                    || next.invitation.predecessor != predecessor
                {
                    return Err(Error::Conflict("Original reapproval decision differs"));
                }
                return Ok(next.invitation);
            }
            let prior = match &old.phase {
                Phase::Invited => PriorPhase::Invited,
                Phase::Approved { request: original } if original == request => {
                    PriorPhase::Approved
                }
                Phase::Approved { .. } => {
                    return Err(Error::Conflict("Original approved request differs"))
                }
                Phase::Closed | Phase::Issued { .. } => {
                    return Err(Error::Conflict(
                        "Closed or issued enrollment cannot be reapproved",
                    ))
                }
            };
            let now = now()?;
            if now < old.invitation.valid_from || now >= old.invitation.valid_until {
                return Err(Error::Conflict(
                    "Original credential interval ended; reapproval cannot extend it",
                ));
            }
            let root = store.root(account)?;
            root.admits_authority(&old.invitation, store.family()?)?;
            let current = root.info(store.family()?)?.roster.map(|r| r.checkpoint);
            if current != predecessor {
                return Err(Error::Conflict(
                    "Explicitly selected roster predecessor changed",
                ));
            }
            if root.members.len() >= sdk::MAX_DEVICES {
                return Err(Error::Capacity);
            }
            let intent = old.invitation.intent().map_err(db_error)?;
            let verified = sdk::VerifiedEnrollmentRequest::verify(request, &intent, now)
                .map_err(|_| Error::Invalid("Request does not prove the original device intent"))?;
            let signer = signer_scope(account, &root, &verified);
            let mut invitation = old.invitation.clone();
            invitation.operation = random()?;
            invitation.request_id = request_id;
            invitation.predecessor = predecessor;
            invitation.deadline = now
                .checked_add(300)
                .ok_or(Error::Capacity)?
                .min(invitation.valid_until);
            let tx = transaction(&store.db)?;
            {
                let operations = tx.open_table(OPERATIONS).map_err(db_error)?;
                if operations.len().map_err(db_error)? >= MAX_OPERATIONS {
                    return Err(Error::Capacity);
                }
                if operations
                    .get(invitation.operation.as_slice())
                    .map_err(db_error)?
                    .is_some()
                {
                    return Err(Error::Internal);
                }
            }
            {
                let mut signers = tx.open_table(SIGNERS).map_err(db_error)?;
                let owner = signers
                    .get(signer.as_slice())
                    .map_err(db_error)?
                    .map(|v| <[u8; 32]>::try_from(v.value()).map_err(|_| Error::Internal))
                    .transpose()?;
                match (&prior, owner) {
                    (PriorPhase::Invited, None) => {}
                    (PriorPhase::Approved, Some(id)) if id == previous => {}
                    (PriorPhase::Approved, None) => return Err(Error::Internal),
                    _ => {
                        return Err(Error::Conflict(
                            "Original signer belongs to another operation",
                        ))
                    }
                }
                signers
                    .insert(signer.as_slice(), invitation.operation.as_slice())
                    .map_err(db_error)?;
            }
            let transition = Transition {
                successor: invitation.operation,
                prior,
                original_request: request.to_vec(),
            };
            {
                let mut links = tx.open_table(REAPPROVALS).map_err(db_error)?;
                if links.get(previous.as_slice()).map_err(db_error)?.is_some() {
                    return Err(Error::Internal);
                }
                links
                    .insert(
                        previous.as_slice(),
                        encode(&transition, MAX_RECORD)?.as_slice(),
                    )
                    .map_err(db_error)?;
            }
            old.phase = Phase::Closed;
            save_operation(&tx, &old)?;
            save_operation(
                &tx,
                &Operation {
                    invitation: invitation.clone(),
                    phase: Phase::Approved {
                        request: request.to_vec(),
                    },
                },
            )?;
            tx.open_table(REQUESTS)
                .map_err(db_error)?
                .insert(correlation.as_slice(), invitation.operation.as_slice())
                .map_err(db_error)?;
            invitation.current(crate::enrollment::now()?)?;
            #[cfg(test)]
            test_boundary(
                "reapproval-before-commit",
                &encode(&invitation, MAX_RECORD)?,
            )?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("reapproval-after-commit", &encode(&invitation, MAX_RECORD)?)?;
            Ok(invitation)
        })
    }

    pub(super) fn reapproved_successor(
        &self,
        account: &Account,
        old: &Operation,
    ) -> Result<Option<Invitation>, Error> {
        Ok(self
            .reapproval_transition(account, old)?
            .map(|(_, next)| next.invitation))
    }
    fn reapproval_transition(
        &self,
        account: &Account,
        old: &Operation,
    ) -> Result<Option<(Transition, Operation)>, Error> {
        if !self.enrollment_reapproval {
            return Ok(None);
        }
        let tx = self.db.begin_read().map_err(db_error)?;
        let links = tx.open_table(REAPPROVALS).map_err(db_error)?;
        let Some(row) = links
            .get(old.invitation.operation.as_slice())
            .map_err(db_error)?
        else {
            return Ok(None);
        };
        let transition: Transition = decode(row.value(), MAX_RECORD)?;
        if !matches!(old.phase, Phase::Closed)
            || transition.successor == old.invitation.operation
            || transition.original_request.len() > 8192
        {
            return Err(Error::Internal);
        }
        let next = self
            .operation(account, transition.successor)
            .map_err(|e| Error::internal("retained reapproval successor", e))?;
        if !same_device(&old.invitation, &next.invitation)
            || next.invitation.deadline > next.invitation.valid_until
        {
            return Err(Error::Internal);
        }
        match &next.phase {
            Phase::Approved { request } | Phase::Issued { request, .. }
                if *request == transition.original_request => {}
            Phase::Closed => {} // A later explicit cancellation/reapproval is terminal for this successor.
            _ => return Err(Error::Internal),
        }
        let mut key = account.application_id.to_vec();
        key.extend_from_slice(&next.invitation.request_id);
        if tx
            .open_table(REQUESTS)
            .map_err(db_error)?
            .get(key.as_slice())
            .map_err(db_error)?
            .is_none_or(|v| v.value() != next.invitation.operation)
        {
            return Err(Error::Internal);
        }
        Ok(Some((transition, next)))
    }
}

fn same_device(a: &Invitation, b: &Invitation) -> bool {
    a.application == b.application
        && a.root_revision == b.root_revision
        && a.root == b.root
        && a.family == b.family
        && a.device == b.device
        && a.generation == b.generation
        && a.valid_from == b.valid_from
        && a.valid_until == b.valid_until
}
