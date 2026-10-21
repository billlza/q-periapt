// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl Store {
    /// Create a host-selected, five-minute invitation for a one-hour device credential.
    /// This local reference profile is not an SDK validity requirement.
    /// Retain request_id on the caller before sending. An uncertain reply is retried
    /// with that same ID, including when the host-generated operation ID was lost.
    pub fn invite_enrollment(
        &mut self,
        account: &Account,
        request_id: [u8; 32],
    ) -> Result<Invitation, Error> {
        self.action(|store| {
            store.authorized(account)?;
            if request_id == [0; 32] {
                return Err(Error::Invalid(
                    "Invitation request identity must be nonzero",
                ));
            }
            if let Some(original) = store.invitation_for_request(account, request_id)? {
                if original.replacement.is_some() {
                    return Err(Error::Conflict(
                        "Correlation identity belongs to a replacement invitation",
                    ));
                }
                return Ok(original.invitation);
            }
            let root = store.root(account)?;
            let info = root.info(store.family()?)?;
            if info.suspended {
                return Err(Error::Conflict("Enrollment root is suspended"));
            }
            if root.members.len() >= sdk::MAX_DEVICES {
                return Err(Error::Capacity);
            }
            let now = now()?;
            let invitation = Invitation {
                operation: random()?,
                request_id,
                application: account.application_id,
                root_revision: info.revision,
                root: info.public_key,
                family: info.family,
                device: random()?,
                generation: 1,
                valid_from: now,
                valid_until: now.checked_add(3600).ok_or(Error::Capacity)?,
                deadline: now.checked_add(300).ok_or(Error::Capacity)?,
                predecessor: info.roster.as_ref().map(|r| r.checkpoint),
            };
            store.persist_invitation(account, &invitation, None)?;
            Ok(invitation)
        })
    }
    /// The host explicitly approves this exact device request after authenticating its account.
    pub fn approve_enrollment(
        &mut self,
        account: &Account,
        id: [u8; 32],
        request: &[u8],
    ) -> Result<(), Error> {
        self.action(|store| {
            store.authorized(account)?;
            if request.len() > 8192 {
                return Err(Error::Invalid("Enrollment request exceeds bound"));
            }
            let mut op = store.operation(account, id)?;
            match &op.phase {
                Phase::Approved { request: saved } | Phase::Issued { request: saved, .. } => {
                    return if saved == request {
                        Ok(())
                    } else {
                        Err(Error::Conflict("Original approved request differs"))
                    };
                }
                Phase::Closed => return Err(Error::Conflict("Original enrollment is closed")),
                Phase::Invited => {}
            }
            op.invitation.current(now()?)?;
            let root = store.root(account)?;
            root.admits(&op.invitation, store.family()?)?;
            let verified = op.verify_request(&root, store.family()?, request, now()?)?;
            let key = signer_scope(account, &root, &verified);
            let tx = transaction(&store.db)?;
            {
                let mut index = tx.open_table(SIGNERS).map_err(db_error)?;
                if index.get(key.as_slice()).map_err(db_error)?.is_some() {
                    return Err(Error::Conflict(
                        "Original signing identity already has an operation",
                    ));
                }
                index
                    .insert(key.as_slice(), id.as_slice())
                    .map_err(db_error)?;
            }
            op.phase = Phase::Approved {
                request: request.to_vec(),
            };
            save_operation(&tx, &op)?;
            op.invitation.current(now()?)?;
            tx.commit().map_err(db_error)
        })
    }
    /// Commit complete membership and the exact response before returning signed bytes.
    /// An already-issued operation returns its original bytes, even after authority changes.
    pub fn issue_enrollment(&mut self, account: &Account, id: [u8; 32]) -> Result<Vec<u8>, Error> {
        self.action(|store| {
            store.authorized(account)?;
            let mut op = store.operation(account, id)?;
            let request = match &op.phase {
                Phase::Issued { response, .. } => return Ok(response.clone()),
                Phase::Approved { request } => request.clone(),
                _ => {
                    return Err(Error::Conflict(
                        "Explicit approval of the original request is required",
                    ))
                }
            };
            op.invitation.current(now()?)?;
            let mut root = store.root(account)?;
            root.admits(&op.invitation, store.family()?)?;
            if op.replacement.is_none() && root.members.len() >= sdk::MAX_DEVICES {
                return Err(Error::Capacity);
            }
            if op.replacement.is_none()
                && root
                    .members
                    .iter()
                    .any(|m| m.device == op.invitation.device)
            {
                return Err(Error::Conflict(
                    "Device identity already belongs to the current roster",
                ));
            }
            let signer = store.open_signer(&root)?;
            let verified = op.verify_request(&root, store.family()?, &request, now()?)?;
            let certificate = signer
                .issue_enrollment(&verified, now()?)
                .map_err(db_error)?;
            let mut entries = root
                .members
                .iter()
                .filter(|m| op.replacement.is_none() || m.device != op.invitation.device)
                .map(|m| signer.roster_entry(&m.certificate))
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
            entries.push(signer.roster_entry(&certificate).map_err(db_error)?);
            let version = op
                .invitation
                .predecessor
                .map_or(0, |p| p.version)
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            let validity = match &op.replacement {
                Some(replacement) => {
                    let previous = replacement.roster(&op.invitation)?.validity();
                    sdk::Validity::new(
                        previous.from().min(op.invitation.valid_from),
                        previous.until().max(op.invitation.valid_until),
                    )
                    .map_err(db_error)?
                }
                None => sdk::Validity::new(op.invitation.valid_from, op.invitation.valid_until)
                    .map_err(db_error)?,
            };
            let roster = signer
                .issue_roster(version, validity, &entries)
                .map_err(db_error)?;
            let response = encode(
                &IssuedEnrollment {
                    operation: id,
                    root_revision: root.revision,
                    certificate: certificate.clone(),
                    roster: roster.as_bytes().to_vec(),
                    checkpoint: roster.checkpoint().into(),
                },
                MAX_RECORD,
            )?;
            if op.replacement.is_some() {
                root.members
                    .iter_mut()
                    .find(|m| m.device == op.invitation.device)
                    .ok_or(Error::Internal)?
                    .certificate = certificate;
            } else {
                root.members.push(Member {
                    device: op.invitation.device,
                    certificate,
                });
            }
            root.roster = Some(RosterSnapshot {
                checkpoint: roster.checkpoint().into(),
                bytes: roster.as_bytes().to_vec(),
            });
            op.phase = Phase::Issued {
                request,
                response: response.clone(),
            };
            let tx = transaction(&store.db)?;
            save_root(&tx, &root)?;
            save_operation(&tx, &op)?;
            op.invitation.current(now()?)?;
            #[cfg(test)]
            test_boundary("issue-before-commit", &response)?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("issue-after-commit", &response)?;
            Ok(response)
        })
    }
    /// Read historical operation progress with a separate current-root observation.
    pub fn enrollment_status(
        &mut self,
        account: &Account,
        id: [u8; 32],
    ) -> Result<EnrollmentStatus, Error> {
        self.action(|store| {
            store.authorized(account)?;
            let op = store.operation(account, id)?;
            if let Some(successor) = store.reapproved_successor(account, &op)? {
                return Ok(EnrollmentStatus::Reapproved { successor });
            }
            Ok(match op.phase {
                Phase::Invited => EnrollmentStatus::Invited {
                    invitation: op.invitation,
                },
                Phase::Approved { .. } => EnrollmentStatus::Approved {
                    invitation: op.invitation,
                },
                Phase::Issued { response, .. } => EnrollmentStatus::Issued {
                    response,
                    current: store.root(account)?.info(store.family()?)?,
                },
                Phase::Closed => EnrollmentStatus::Closed,
            })
        })
    }
    /// Explicitly close an unissued operation. Its identity and signer reservation remain retained.
    pub fn cancel_enrollment(&mut self, account: &Account, id: [u8; 32]) -> Result<(), Error> {
        self.action(|store| {
            store.authorized(account)?;
            let mut op = store.operation(account, id)?;
            if store.reapproved_successor(account, &op)?.is_some() {
                return Err(Error::Conflict(
                    "Cancel the explicit successor approval, not its history",
                ));
            }
            if matches!(op.phase, Phase::Issued { .. }) {
                return Err(Error::Conflict(
                    "Issued enrollment requires device revocation",
                ));
            }
            op.phase = Phase::Closed;
            let tx = transaction(&store.db)?;
            save_operation(&tx, &op)?;
            tx.commit().map_err(db_error)
        })
    }
}

impl Store {
    pub(super) fn invitation_for_request(
        &self,
        account: &Account,
        request_id: [u8; 32],
    ) -> Result<Option<Operation>, Error> {
        let mut key = account.application_id.to_vec();
        key.extend_from_slice(&request_id);
        let saved = self
            .db
            .begin_read()
            .map_err(db_error)?
            .open_table(REQUESTS)
            .map_err(db_error)?
            .get(key.as_slice())
            .map_err(db_error)?
            .map(|v| <[u8; 32]>::try_from(v.value()).map_err(|_| Error::Internal))
            .transpose()?;
        let Some(id) = saved else {
            return Ok(None);
        };
        let original = self
            .operation(account, id)
            .map_err(|e| Error::internal("original invitation index", e))?;
        if original.invitation.request_id != request_id {
            return Err(Error::Internal);
        }
        if matches!(original.phase, Phase::Closed) {
            return Err(Error::Conflict("Original invitation is closed"));
        }
        Ok(Some(original))
    }

    pub(super) fn persist_invitation(
        &self,
        account: &Account,
        invitation: &Invitation,
        replacement: Option<replacement::Intent>,
    ) -> Result<(), Error> {
        let mut key = account.application_id.to_vec();
        key.extend_from_slice(&invitation.request_id);
        let tx = transaction(&self.db)?;
        {
            let table = tx.open_table(OPERATIONS).map_err(db_error)?;
            if table.len().map_err(db_error)? >= MAX_OPERATIONS {
                return Err(Error::Capacity);
            }
            if table
                .get(invitation.operation.as_slice())
                .map_err(db_error)?
                .is_some()
            {
                return Err(Error::Internal);
            }
            let mut pending = 0;
            for row in table.iter().map_err(db_error)? {
                let (_, value) = row.map_err(db_error)?;
                let op: Operation = decode(value.value(), MAX_RECORD)?;
                if op.invitation.application == account.application_id
                    && matches!(op.phase, Phase::Invited | Phase::Approved { .. })
                {
                    pending += 1;
                }
            }
            if pending >= 8 {
                return Err(Error::Capacity);
            }
        }
        save_operation(
            &tx,
            &Operation {
                invitation: invitation.clone(),
                phase: Phase::Invited,
                replacement,
            },
        )?;
        tx.open_table(REQUESTS)
            .map_err(db_error)?
            .insert(key.as_slice(), invitation.operation.as_slice())
            .map_err(db_error)?;
        #[cfg(test)]
        test_boundary("invitation-before-commit", &encode(invitation, MAX_RECORD)?)?;
        tx.commit().map_err(db_error)?;
        #[cfg(test)]
        test_boundary("invitation-after-commit", &encode(invitation, MAX_RECORD)?)?;
        Ok(())
    }
}
