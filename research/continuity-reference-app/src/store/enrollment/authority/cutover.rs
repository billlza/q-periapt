// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host intents around the original native authority registry; terminal host writes are atomic.
use super::*;
use crate::account_authority::{Cutover, CutoverRequest, CutoverStatus, Retirement};
mod reconciliation;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    application: [u8; 32],
    operation: [u8; 32],
    request: CutoverRequest,
    previous: Root,
    successor: Root,
    phase: CutoverPhase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum CutoverPhase {
    Approved,
    Retiring {
        proof: Retirement,
    },
    Closing {
        #[serde(with = "wire")]
        receipt: Vec<u8>,
    },
    Committed {
        proof: Retirement,
    },
    Closed {
        #[serde(with = "wire")]
        receipt: Vec<u8>,
    },
}
impl Record {
    fn result(&self, family: [u8; 32]) -> Result<Cutover, Error> {
        Ok(Cutover {
            schema: "qperiapt-account-root-cutover/1".into(),
            operation: self.operation,
            preparation: self.request.preparation,
            status: match self.phase {
                CutoverPhase::Approved => CutoverStatus::AwaitingOutcome,
                CutoverPhase::Retiring { .. } | CutoverPhase::Closing { .. } => {
                    CutoverStatus::Reconciling
                }
                CutoverPhase::Committed { .. } => CutoverStatus::Committed {
                    successor: self.successor.info(family)?,
                },
                CutoverPhase::Closed { .. } => CutoverStatus::Closed,
            },
        })
    }
    fn plan(&self) -> Result<sdk::AnchorAccountReplacementPlan, Error> {
        let plan = self.request.plan.as_sdk().map_err(db_error)?;
        if plan.operation().as_bytes() != &self.operation
            || self.application != self.previous.application
            || self.application != self.successor.application
            || self.previous.revision.checked_add(1) != Some(self.successor.revision)
            || self.previous.authority.is_none()
            || self.successor.authority != self.previous.authority
        {
            return Err(Error::Internal);
        }
        Ok(plan)
    }
}
fn save_cutover(tx: &redb::WriteTransaction, record: &Record) -> Result<(), Error> {
    tx.open_table(CUTOVERS)
        .map_err(db_error)?
        .insert(
            record.operation.as_slice(),
            encode(record, MAX_ROOT)?.as_slice(),
        )
        .map_err(db_error)?;
    Ok(())
}
fn native_error(error: sdk::DurableError) -> Error {
    match error {
        sdk::DurableError::Capacity => Error::Capacity,
        sdk::DurableError::Conflict
        | sdk::DurableError::Suspended
        | sdk::DurableError::Protocol(sdk::Error::Scope | sdk::Error::Retired) => {
            Error::Conflict("Original authority operation requires reconciliation")
        }
        other => Error::internal("original account authority operation", other),
    }
}
fn retirement(
    record: &Record,
    pin: &sdk::AnchorPin,
    proof: &Retirement,
) -> Result<sdk::AnchorRetiredAccount, Error> {
    let proposal = proof
        .decision
        .as_sdk()
        .map_err(|_| Error::Invalid("Account retirement decision encoding or binding"))?;
    if proof.decision.plan_binding != record.request.plan.binding
        || proposal.operation().as_bytes() != &record.operation
    {
        return Err(Error::Conflict(
            "Retirement differs from the original approved plan",
        ));
    }
    let retired = pin
        .verify_retired_account(&proposal, &proof.receipt)
        .map_err(|_| Error::Invalid("Original witness retirement proof"))?;
    record.plan()?.verify_retirement(&retired).map_err(|_| {
        Error::Conflict("Retirement target differs from the original approved plan")
    })?;
    Ok(retired)
}
impl Store {
    fn cutover_record(
        &self,
        account: &Account,
        operation: [u8; 32],
    ) -> Result<Option<Record>, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(CUTOVERS).map_err(db_error)?;
        let record = table
            .get(operation.as_slice())
            .map_err(db_error)?
            .map(|v| decode::<Record>(v.value(), MAX_ROOT))
            .transpose()?;
        if let Some(record) = &record {
            if record.application != account.application_id {
                return Err(Error::Unauthorized);
            }
            if record.operation != operation {
                return Err(Error::Internal);
            }
            record.plan()?;
        }
        Ok(record)
    }
    fn cutover_authority(
        &self,
        account: &Account,
    ) -> Result<(AssociationRecord, sdk::AnchorPin), Error> {
        self.admits_authority_association(account)?;
        let association = self.authority_record(account)?.ok_or(Error::Conflict(
            "Original account authority must be associated first",
        ))?;
        if !matches!(association.phase, RegistryPhase::Ready) {
            return Err(Error::Conflict(
                "Original authority initialization requires reconciliation",
            ));
        }
        let (_, pin) = association
            .selected(self.family()?)
            .map_err(|e| Error::internal("retained authority association", e))?;
        Ok((association, pin))
    }
    /// Retain exact independent approval and fence the old issuer before witness freeze.
    pub fn approve_account_root(
        &mut self,
        account: &Account,
        request: &CutoverRequest,
    ) -> Result<Cutover, Error> {
        self.action(|store| {
            let (mut association, pin) = store.cutover_authority(account)?;
            encode(request, MAX_RECORD)?;
            let plan = request
                .plan
                .as_sdk()
                .map_err(|_| Error::Invalid("Account root plan encoding or binding"))?;
            let operation = *plan.operation().as_bytes();
            if let Some(mut record) = store.cutover_record(account, operation)? {
                if record.request != *request {
                    return Err(Error::Conflict("Original account-root approval differs"));
                }
                return store.reconcile_cutover(account, &mut association, &pin, &mut record);
            }
            if association.active.is_some() {
                return Err(Error::Conflict(
                    "An original account-root operation still requires reconciliation",
                ));
            }
            let previous = store.root(account)?;
            if previous.authority != Some(association.registry) {
                return Err(Error::Internal);
            }
            let mut successor = store.cutover_candidate(
                account,
                request.preparation,
                request.enrollment,
                request.roster,
            )?;
            let info = successor.info(store.family()?)?;
            let member = successor.members.first().ok_or(Error::Internal)?;
            let original = store.operation(account, request.enrollment)?;
            let trust = crate::witness::EnrollmentTrust {
                schema: "qperiapt-witness-enrollment-trust/1".into(),
                account: info,
                device: member.device,
                generation: original.invitation.generation,
                journal: request.journal,
                genesis_head: request.genesis_head,
                certificate: member.certificate.clone(),
                policy: request.policy.clone(),
            };
            let (genesis, device, policy) =
                trust.inputs(&pin, &request.target, now()?).map_err(|_| {
                    Error::Invalid("Candidate preparation differs from independent approval")
                })?;
            let (baseline, _) = association
                .request
                .policy
                .pins
                .verify_historical(&association.request.policy.materials, store.family()?)?;
            if policy.checkpoint().version() < baseline.checkpoint().version()
                || (policy.checkpoint().version() == baseline.checkpoint().version()
                    && policy.checkpoint() != baseline.checkpoint())
            {
                return Err(Error::Conflict(
                    "Target policy precedes the retained authority association",
                ));
            }
            plan.verify_target(
                &sdk::PublicKey::decode(&previous.info(store.family()?)?.public_key)
                    .map_err(db_error)?,
                &genesis,
                &device,
                &policy,
                &pin,
            )
            .map_err(|_| Error::Conflict("Plan differs from the exact approved candidate"))?;
            // Ensure the original registry/key is available before changing host authority.
            drop(store.open_authority_registry(&association, &pin)?);
            successor.authority = Some(association.registry);
            let mut record = Record {
                application: account.application_id,
                operation,
                request: request.clone(),
                previous,
                successor,
                phase: CutoverPhase::Approved,
            };
            record.plan()?;
            let mut fenced = record.previous.clone();
            let RootPhase::Ready { suspended, .. } = &mut fenced.phase else {
                return Err(Error::Internal);
            };
            *suspended = true;
            association.active = Some(operation);
            let tx = transaction(&store.db)?;
            if tx
                .open_table(CUTOVERS)
                .map_err(db_error)?
                .len()
                .map_err(db_error)?
                >= MAX_OPERATIONS
            {
                return Err(Error::Capacity);
            }
            store.hold_root_candidate(&tx, account, request.preparation, operation)?;
            save_root(&tx, &fenced)?;
            save(&tx, &association)?;
            save_cutover(&tx, &record)?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("root-cutover-approved", operation.as_slice())?;
            store.reconcile_cutover(account, &mut association, &pin, &mut record)
        })
    }
    /// Authenticate and retain the original retirement before any cross-store commit.
    pub fn commit_account_root(
        &mut self,
        account: &Account,
        operation: [u8; 32],
        proof: &Retirement,
    ) -> Result<Cutover, Error> {
        self.action(|store| {
            let (mut association, pin) = store.cutover_authority(account)?;
            let mut record = store
                .cutover_record(account, operation)?
                .ok_or(Error::Conflict("Original account-root approval is absent"))?;
            retirement(&record, &pin, proof)?;
            match &record.phase {
                CutoverPhase::Approved => {
                    record.phase = CutoverPhase::Retiring {
                        proof: proof.clone(),
                    };
                    let tx = transaction(&store.db)?;
                    save_cutover(&tx, &record)?;
                    tx.commit().map_err(db_error)?;
                    #[cfg(test)]
                    test_boundary("root-cutover-retirement-retained", operation.as_slice())?;
                }
                CutoverPhase::Retiring { proof: original }
                | CutoverPhase::Committed { proof: original } => {
                    if original.decision != proof.decision {
                        return Err(Error::Conflict("Original retirement decision differs"));
                    }
                }
                _ => {
                    return Err(Error::Conflict(
                        "Original account-root operation is closing or closed",
                    ))
                }
            }
            store.reconcile_cutover(account, &mut association, &pin, &mut record)
        })
    }
    /// Permanently reconcile non-commit using the original witness plan-closure proof.
    pub fn close_account_root(
        &mut self,
        account: &Account,
        operation: [u8; 32],
        receipt: &[u8],
    ) -> Result<Cutover, Error> {
        self.action(|store| {
            let (mut association, pin) = store.cutover_authority(account)?;
            let mut record = store
                .cutover_record(account, operation)?
                .ok_or(Error::Conflict("Original account-root approval is absent"))?;
            pin.verify_closed_account_preparation(&record.plan()?, receipt)
                .map_err(|_| Error::Invalid("Original witness plan-closure proof"))?;
            match record.phase {
                CutoverPhase::Approved => {
                    record.phase = CutoverPhase::Closing {
                        receipt: receipt.to_vec(),
                    };
                    let tx = transaction(&store.db)?;
                    save_cutover(&tx, &record)?;
                    tx.commit().map_err(db_error)?;
                    #[cfg(test)]
                    test_boundary("root-cutover-closure-retained", operation.as_slice())?;
                }
                CutoverPhase::Closing { .. } | CutoverPhase::Closed { .. } => {}
                _ => {
                    return Err(Error::Conflict(
                        "Original account-root operation is retiring or committed",
                    ))
                }
            }
            store.reconcile_cutover(account, &mut association, &pin, &mut record)
        })
    }
    pub fn resume_account_root(
        &mut self,
        account: &Account,
        operation: [u8; 32],
    ) -> Result<Cutover, Error> {
        self.action(|store| {
            let (mut association, pin) = store.cutover_authority(account)?;
            let mut record = store
                .cutover_record(account, operation)?
                .ok_or(Error::Conflict("Original account-root approval is absent"))?;
            store.reconcile_cutover(account, &mut association, &pin, &mut record)
        })
    }
    pub fn account_root_cutover(
        &mut self,
        account: &Account,
        operation: [u8; 32],
    ) -> Result<Cutover, Error> {
        self.action(|store| {
            let (_, pin) = store.cutover_authority(account)?;
            let record = store
                .cutover_record(account, operation)?
                .ok_or(Error::Conflict("Original account-root approval is absent"))?;
            match &record.phase {
                CutoverPhase::Retiring { proof } | CutoverPhase::Committed { proof } => {
                    retirement(&record, &pin, proof)?;
                }
                CutoverPhase::Closing { receipt } | CutoverPhase::Closed { receipt } => {
                    pin.verify_closed_account_preparation(&record.plan()?, receipt)
                        .map_err(db_error)?;
                }
                CutoverPhase::Approved => {}
            }
            record.result(store.family()?)
        })
    }
}
