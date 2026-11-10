// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original native decision first, then one atomic host mapping/history transaction.
use super::*;

fn archive_key(account: &Account, revision: u64) -> Vec<u8> {
    let mut key = account.application_id.to_vec();
    key.extend_from_slice(&revision.to_be_bytes());
    key
}
impl Store {
    fn require_cutover_fence(&self, account: &Account, record: &Record) -> Result<Root, Error> {
        let mut expected = record.previous.clone();
        let RootPhase::Ready { suspended, .. } = &mut expected.phase else {
            return Err(Error::Internal);
        };
        *suspended = true;
        let current = self.root(account)?;
        if encode(&current, MAX_ROOT)? != encode(&expected, MAX_ROOT)? {
            return Err(Error::Conflict("Original account-root fence changed"));
        }
        Ok(current)
    }
    pub(super) fn reconcile_cutover(
        &self,
        account: &Account,
        association: &mut AssociationRecord,
        pin: &sdk::AnchorPin,
        record: &mut Record,
    ) -> Result<Cutover, Error> {
        match &record.phase {
            CutoverPhase::Committed { proof } => {
                retirement(record, pin, proof)?;
                return record.result(self.family()?);
            }
            CutoverPhase::Closed { receipt } => {
                pin.verify_closed_account_preparation(&record.plan()?, receipt)
                    .map_err(db_error)?;
                return record.result(self.family()?);
            }
            _ => {}
        }
        if association.active != Some(record.operation) {
            return Err(Error::Internal);
        }
        let fenced = self.require_cutover_fence(account, record)?;
        let mut owner = self.open_authority_registry(association, pin)?;
        let expected = association.expected(&record.previous, self.family()?)?;
        let plan = record.plan()?;
        match record.phase.clone() {
            CutoverPhase::Approved => {
                owner
                    .begin_preparation(expected, plan)
                    .map_err(native_error)?;
                #[cfg(test)]
                test_boundary("root-cutover-native-prepared", record.operation.as_slice())?;
            }
            CutoverPhase::Retiring { proof } => {
                let retired = retirement(record, pin, &proof)?;
                owner
                    .begin_preparation(expected, plan)
                    .map_err(native_error)?;
                owner.commit_replacement(&retired).map_err(native_error)?;
                let selected = owner
                    .access()
                    .map_err(db_error)?
                    .current(expected.application())
                    .map_err(native_error)?;
                if selected != association.expected(&record.successor, self.family()?)? {
                    return Err(Error::Internal);
                }
                #[cfg(test)]
                test_boundary("root-cutover-native-retired", record.operation.as_slice())?;
                let tx = transaction(&self.db)?;
                {
                    let mut history = tx.open_table(RETIRED_ROOTS).map_err(db_error)?;
                    if history.len().map_err(db_error)? >= MAX_OPERATIONS {
                        return Err(Error::Capacity);
                    }
                    let key = archive_key(account, fenced.revision);
                    if history
                        .insert(key.as_slice(), encode(&fenced, MAX_ROOT)?.as_slice())
                        .map_err(db_error)?
                        .is_some()
                    {
                        return Err(Error::Internal);
                    }
                }
                save_root(&tx, &record.successor)?;
                self.finish_root_candidate(
                    &tx,
                    account,
                    record.request.preparation,
                    record.operation,
                    true,
                )?;
                association.active = None;
                save(&tx, association)?;
                record.phase = CutoverPhase::Committed { proof };
                save_cutover(&tx, record)?;
                #[cfg(test)]
                test_boundary(
                    "root-cutover-host-before-commit",
                    record.operation.as_slice(),
                )?;
                tx.commit().map_err(db_error)?;
                #[cfg(test)]
                test_boundary("root-cutover-host-committed", record.operation.as_slice())?;
            }
            CutoverPhase::Closing { receipt } => {
                let closed = pin
                    .verify_closed_account_preparation(&plan, &receipt)
                    .map_err(db_error)?;
                match owner.preparation(plan.operation()) {
                    Ok((application, _, original)) => {
                        if application != expected.application() || original != &plan {
                            return Err(Error::Internal);
                        }
                    }
                    // The authenticated host approval can precede native intent.
                    // Retain that exact original plan before applying closure,
                    // so absence cannot leave old native authority admissible.
                    Err(sdk::DurableError::Absent) => {
                        owner
                            .begin_preparation(expected, plan.clone())
                            .map_err(native_error)?;
                        #[cfg(test)]
                        test_boundary(
                            "root-cutover-closure-native-prepared",
                            record.operation.as_slice(),
                        )?;
                    }
                    Err(error) => return Err(native_error(error)),
                }
                owner.close_preparation(&closed).map_err(native_error)?;
                #[cfg(test)]
                test_boundary("root-cutover-native-closed", record.operation.as_slice())?;
                let tx = transaction(&self.db)?;
                self.finish_root_candidate(
                    &tx,
                    account,
                    record.request.preparation,
                    record.operation,
                    false,
                )?;
                association.active = None;
                save(&tx, association)?;
                record.phase = CutoverPhase::Closed { receipt };
                save_cutover(&tx, record)?;
                #[cfg(test)]
                test_boundary(
                    "root-cutover-close-before-commit",
                    record.operation.as_slice(),
                )?;
                tx.commit().map_err(db_error)?;
                #[cfg(test)]
                test_boundary("root-cutover-closed", record.operation.as_slice())?;
            }
            CutoverPhase::Committed { .. } | CutoverPhase::Closed { .. } => {
                return Err(Error::Internal)
            }
        }
        record.result(self.family()?)
    }
    /// Retained old issuer metadata, never a current account selection.
    pub fn retired_account_root(
        &mut self,
        account: &Account,
        revision: u64,
    ) -> Result<RootInfo, Error> {
        self.action(|store| {
            store.admits_authority_association(account)?;
            let tx = store.db.begin_read().map_err(db_error)?;
            let table = tx.open_table(RETIRED_ROOTS).map_err(db_error)?;
            let key = archive_key(account, revision);
            let row = table
                .get(key.as_slice())
                .map_err(db_error)?
                .ok_or(Error::Conflict("Original retired root is absent"))?;
            let root: Root = decode(row.value(), MAX_ROOT)?;
            let info = root.info(store.family()?)?;
            if root.application != account.application_id
                || root.revision != revision
                || !info.suspended
            {
                return Err(Error::Internal);
            }
            Ok(info)
        })
    }
}
