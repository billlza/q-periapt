// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The original enrollment commits authorization before reconciling child backups.
use super::*;
use crate::AccountRootJournalTransition;
impl Owners {
    fn transition(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<(), DurableError> {
        self.read()?;
        if &self.state.proposal == transition.next_proposal() {
            let original = self.state.history.last().ok_or(DurableError::Conflict)?;
            if !transition.is_original_retry(original)? {
                return Err(DurableError::Conflict);
            }
        } else {
            if self.state.receipt.is_some() {
                return Err(DurableError::Conflict);
            }
            let marker = transition.marker(&self.state.proposal)?;
            let active = self
                .enrollment
                .active
                .as_ref()
                .ok_or(DurableError::Closed)?;
            let snapshot = read_snapshot(&active.database, &active.key, self.enrollment.binding)?;
            validate(
                &self.enrollment,
                &snapshot.image,
                &self.pin,
                transition.next_proposal(),
            )?;
            if self.journal.is_none() {
                self.fence_journal()?;
            }
            self.journal
                .as_mut()
                .ok_or(DurableError::Closed)?
                .validate_transition(transition)?;
            let mut next = self.state.clone();
            next.proposal = transition.next_proposal().clone();
            next.history.push(marker);
            save(&self.enrollment, Some(&self.state), &next, "handoff")?;
            self.state = next;
        }
        self.fence_journal()
    }
}
impl AccountRootEnrollmentRecovery {
    /// Retain the independently approved transition in the original enrollment
    /// before changing its journal fence. Original enrollment bytes and journal
    /// image/pending intent are preserved. Failure consumes all local owners and
    /// can follow either commit; recover this same transition without old traffic.
    pub fn transition_after_noncommit(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)
            .and_then(|owners| owners.transition(transition));
        if let Err(error) = result {
            self.close();
            return Err(error);
        }
        self.status()
    }
    /// Reconcile one original transition using the existing independently retained
    /// enrollment. A missing parent or journal is never replaced. A parent already
    /// committed to the next proposal reconstructs its authorized child history,
    /// including when an older journal backup removed a completed child transition.
    pub fn resume_transition(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        let binding = paths.binding(&key, &intent)?;
        let database = open_private_database(&paths.configuration)?;
        let snapshot = read_snapshot(&database, &key, binding)?;
        if snapshot.retirement.is_some() {
            return Err(DurableError::Conflict);
        }
        let state = *snapshot.root_replacement.ok_or(DurableError::Absent)?;
        let enrollment = DeviceEnrollment {
            active: Some(Active { database, key }),
            paths,
            intent,
            binding,
            account_authority: None,
        };
        let mut owners = Owners {
            enrollment,
            pin,
            state,
            journal: None,
        };
        owners.transition(transition)?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
