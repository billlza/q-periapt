// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The original enrollment commits authorization before reconciling child backups.
use super::*;
use crate::AccountRootJournalTransition;
impl Owners {
    fn prepared_transition(
        &mut self,
        transition: &AccountRootJournalTransition,
        managed_initial: bool,
    ) -> Result<Option<State>, DurableError> {
        self.read()?;
        if &self.state.proposal == transition.next_proposal() {
            if managed_initial && self.state.history.is_empty() {
                return Ok(None);
            }
            let original = self.state.history.last().ok_or(DurableError::Conflict)?;
            if !transition.is_original_retry(original)? {
                return Err(DurableError::Conflict);
            }
            Ok(None)
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
            Ok(Some(next))
        }
    }
    fn transition(
        &mut self,
        transition: &AccountRootJournalTransition,
        managed_initial: bool,
    ) -> Result<(), DurableError> {
        if let Some(next) = self.prepared_transition(transition, managed_initial)? {
            save(&self.enrollment, Some(&self.state), &next, "handoff")?;
            self.state = next;
        }
        self.fence_journal()
    }
}
impl AccountRootEnrollmentRecovery {
    // A live managed controller uses the existing child lease to refuse an
    // incompatible head before changing its independent registry intent.
    pub(in crate::enrollment) fn validate_managed_transition(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<(), DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)
            .and_then(|owners| owners.prepared_transition(transition, true).map(|_| ()));
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Retain the independently approved transition in the original enrollment
    /// before changing its journal fence. Original enrollment bytes and journal
    /// image/pending intent are preserved. Failure consumes all local owners and
    /// can follow either commit; recover this same transition without old traffic.
    pub fn transition_after_noncommit(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        self.transition_inner(transition, false)
    }
    pub(in crate::enrollment) fn apply_managed_transition(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        self.transition_inner(transition, true)
    }
    fn transition_inner(
        &mut self,
        transition: &AccountRootJournalTransition,
        managed_initial: bool,
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)
            .and_then(|owners| owners.transition(transition, managed_initial));
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
        Self::open_transition(paths, intent, pin, transition, false)
    }
    pub(in crate::enrollment) fn resume_managed_transition(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        Self::open_transition(paths, intent, pin, transition, true)
    }
    fn open_transition(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
        allow_initial: bool,
    ) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        let binding = paths.binding(&key, &intent)?;
        let database = open_private_database(&paths.configuration)?;
        let enrollment = DeviceEnrollment {
            active: Some(Active { database, key }),
            paths,
            intent,
            binding,
            account_authority: None,
        };
        Self::transition_owner(enrollment, pin, transition, allow_initial)
    }
    pub(in crate::enrollment) fn prepare_managed_transition(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        Self::transition_owner(enrollment, pin, transition, true)
    }
    fn transition_owner(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
        allow_initial: bool,
    ) -> Result<Self, DurableError> {
        let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
        if snapshot.retirement.is_some() {
            return Err(DurableError::Conflict);
        }
        // Only the managed caller may admit an initial fence: its registry has
        // already retained original non-commit and the exact next approved plan.
        // Replaying that initial fence has no predecessor journal history. No
        // storage error is converted to absence or to creation of a new parent.
        let state = match snapshot.root_replacement {
            None if allow_initial => {
                return Self::prepare(enrollment, pin, transition.next_proposal().clone())
            }
            Some(state)
                if allow_initial
                    && state.proposal == *transition.next_proposal()
                    && state.history.is_empty() =>
            {
                return Self::prepare(enrollment, pin, transition.next_proposal().clone())
            }
            Some(state) => *state,
            None => return Err(DurableError::Absent),
        };
        let mut owners = Owners {
            enrollment,
            pin,
            state,
            journal: None,
        };
        owners.transition(transition, allow_initial)?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
