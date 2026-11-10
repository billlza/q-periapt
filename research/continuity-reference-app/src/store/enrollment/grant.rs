// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::credential_grant::{CredentialGrantRequest, IssuedCredentialGrant};
mod inputs;
mod schema;
mod state;

const MAX_GRANT_RECORD: usize = 256 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    request: CredentialGrantRequest,
    phase: GrantPhase,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum GrantPhase {
    Pending,
    Issued {
        #[serde(with = "wire")]
        response: Vec<u8>,
    },
    Closed,
}
fn key(account: &Account, operation: [u8; 32]) -> Vec<u8> {
    [account.application_id.as_slice(), operation.as_slice()].concat()
}

impl Store {
    fn grant(&self, account: &Account, operation: [u8; 32]) -> Result<Option<Record>, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(GRANTS).map_err(db_error)?;
        table
            .get(key(account, operation).as_slice())
            .map_err(db_error)?
            .map(|v| decode(v.value(), MAX_GRANT_RECORD))
            .transpose()
    }
    fn save_grant(
        &self,
        account: &Account,
        record: &Record,
        create: bool,
        at: u64,
        target: Option<&inputs::Target>,
    ) -> Result<(), Error> {
        let bytes = encode(record, MAX_GRANT_RECORD)?;
        let request = &record.request;
        let tx = transaction(&self.db)?;
        {
            let mut table = tx.open_table(GRANTS).map_err(db_error)?;
            let identity = key(account, request.retained.operation);
            let old = table
                .get(identity.as_slice())
                .map_err(db_error)?
                .map(|v| decode::<Record>(v.value(), MAX_GRANT_RECORD))
                .transpose()?;
            match (create, old) {
                (true, None) => {
                    if table.len().map_err(db_error)? >= MAX_OPERATIONS {
                        return Err(Error::Capacity);
                    }
                }
                (false, Some(old))
                    if old.request == *request && matches!(old.phase, GrantPhase::Pending) => {}
                _ => return Err(Error::Conflict("Original retained grant decision changed")),
            }
            table
                .insert(identity.as_slice(), bytes.as_slice())
                .map_err(db_error)?;
        }
        if let Some(target) = target {
            let table = tx.open_table(ROOTS).map_err(db_error)?;
            let row = table
                .get(account.application_id.as_slice())
                .map_err(db_error)?
                .ok_or(Error::Internal)?;
            let root: Root = decode(row.value(), MAX_ROOT)?;
            let info = root.info(self.family()?)?;
            if info.suspended
                || info.revision != request.retained.root_revision
                || info.roster.as_ref().map(|r| r.checkpoint) != Some(request.target_checkpoint)
            {
                return Err(Error::Conflict("Retained grant current root changed"));
            }
            let committed_at = now()?;
            if committed_at < at
                || target
                    .pin
                    .verify_device(&target.certificate, &target.roster, committed_at)
                    .is_err()
            {
                return Err(Error::Conflict(
                    "Retained grant target is no longer current",
                ));
            }
        }
        let boundary = match record.phase {
            GrantPhase::Pending => "grant-pending",
            GrantPhase::Issued { .. } => "grant-issued",
            GrantPhase::Closed => "grant-closed",
        };
        #[cfg(test)]
        test_boundary(&format!("{boundary}-before-commit"), &bytes)?;
        tx.commit().map_err(db_error)?;
        #[cfg(test)]
        test_boundary(&format!("{boundary}-after-commit"), &bytes)?;
        #[cfg(not(test))]
        let _ = boundary;
        Ok(())
    }
    /// Account authentication and exact host selections are mandatory. A device
    /// report is not proof of user authorization. Retrying a committed decision
    /// returns its exact historical bytes, even if later authority changed.
    pub fn issue_credential_grant(
        &mut self,
        account: &Account,
        request: &CredentialGrantRequest,
    ) -> Result<Vec<u8>, Error> {
        self.action(|store| {
            store.authorized(account)?;
            if !store.credential_grants {
                return Err(Error::Conflict(
                    "Retained grants require explicit schema-5 upgrade",
                ));
            }
            inputs::shape(request)?;
            let original = store.operation(account, request.retained.enrollment)?;
            let Phase::Issued { response, .. } = &original.phase else {
                return Err(Error::Conflict("Retained grant requires original issuance"));
            };
            let existing = store.grant(account, request.retained.operation)?;
            if let Some(saved) = &existing {
                if saved.request != *request {
                    return Err(Error::Conflict("Original retained grant request differs"));
                }
                match &saved.phase {
                    GrantPhase::Issued { response } => return Ok(response.clone()),
                    GrantPhase::Closed => {
                        return Err(Error::Conflict("Original retained grant is closed"))
                    }
                    GrantPhase::Pending => {}
                }
            }
            let at = now()?;
            let target = store.grant_inputs(account, request, &original, response, at)?;
            let authority = store.authority_guard(account, &target.root)?;
            let mut record = Record {
                request: request.clone(),
                phase: GrantPhase::Pending,
            };
            if existing.is_none() {
                authority.check()?;
                store.save_grant(account, &record, true, at, Some(&target))?;
            }
            let signer = store.open_signer(&target.root)?;
            let issued = signer
                .issue_credential_renewal(
                    sdk::CredentialRenewalMaterials {
                        original_credential: &request.retained.original_certificate,
                        previous_credential: &request.retained.previous_certificate,
                        successor_credential: &target.certificate,
                        previous_roster: &request.retained.previous_roster,
                        successor_roster: &target.roster,
                    },
                    &sdk::CredentialRenewalAuthorization {
                        operation: sdk::CredentialRenewalId::from_trusted_state(
                            request.retained.operation,
                        )
                        .map_err(|_| Error::Invalid("Retained grant operation"))?,
                        previous: request
                            .retained
                            .previous_checkpoint
                            .as_sdk()
                            .map_err(|_| Error::Invalid("Grant predecessor"))?,
                        policy_digest: request.retained.original_policy.digest,
                    },
                    &target.pin,
                    at,
                )
                .map_err(|_| Error::Conflict("Retained grant materials or scope differ"))?;
            let verified = sdk::VerifiedCredentialRenewal::verify(
                issued.as_bytes(),
                &target.pin,
                request.retained.original_policy.digest,
                at,
            )
            .map_err(db_error)?;
            if verified.original_storage_owner() != request.retained.original_owner {
                return Err(Error::Conflict(
                    "Reported original owner differs from credential",
                ));
            }
            let response = encode(
                &IssuedCredentialGrant {
                    enrollment: request.retained.enrollment,
                    operation: request.retained.operation,
                    journal: request.retained.journal,
                    root_revision: request.retained.root_revision,
                    statement: verified.statement_digest(),
                    checkpoint: request.target_checkpoint,
                    grant: issued.as_bytes().to_vec(),
                },
                MAX_RECORD,
            )?;
            record.phase = GrantPhase::Issued {
                response: response.clone(),
            };
            authority.check()?;
            store.save_grant(account, &record, false, at, Some(&target))?;
            Ok(response)
        })
    }
}
