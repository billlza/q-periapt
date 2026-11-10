// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Candidate selection is committed only by the original account-root coordinator.
use super::*;
impl Store {
    pub(in super::super) fn cutover_candidate(
        &self,
        account: &Account,
        preparation: [u8; 32],
        enrollment: [u8; 32],
        roster: Checkpoint,
    ) -> Result<Root, Error> {
        let record = self.root_preparation_record(account, preparation)?;
        record.admits_successor(&self.root(account)?, self.family()?)?;
        if record.enrollment != Some(enrollment)
            || record.candidate.members.len() != 1
            || record.candidate.roster.as_ref().map(|r| r.checkpoint) != Some(roster)
        {
            return Err(Error::Conflict(
                "Original candidate enrollment or roster differs",
            ));
        }
        let op = self.operation(account, enrollment)?;
        if op.root_preparation != Some(preparation) || !matches!(op.phase, Phase::Issued { .. }) {
            return Err(Error::Conflict(
                "Candidate requires its original issued enrollment",
            ));
        }
        record
            .candidate
            .admits_authority(&op.invitation, self.family()?)?;
        Ok(record.candidate)
    }
    pub(in super::super) fn hold_root_candidate(
        &self,
        tx: &redb::WriteTransaction,
        account: &Account,
        preparation: [u8; 32],
        operation: [u8; 32],
    ) -> Result<(), Error> {
        let mut record = self.root_preparation_record(account, preparation)?;
        if record.closed || record.selected || record.cutover.is_some() {
            return Err(Error::Conflict("Candidate already has an original cutover"));
        }
        record.cutover = Some(operation);
        record.check(account, preparation)?;
        save(tx, &record)
    }
    pub(in super::super) fn finish_root_candidate(
        &self,
        tx: &redb::WriteTransaction,
        account: &Account,
        preparation: [u8; 32],
        operation: [u8; 32],
        selected: bool,
    ) -> Result<(), Error> {
        let mut record = self.root_preparation_record(account, preparation)?;
        if record.cutover != Some(operation) || record.selected || record.closed {
            return Err(Error::Internal);
        }
        record.selected = selected;
        record.closed = !selected;
        record.check(account, preparation)?;
        save(tx, &record)
    }
}
