// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The original enrollment commits authorization before reconciling child backups.
use super::*;
use crate::AccountRootJournalTransition;

enum TransitionState {
    Initial,
    Retained(Box<State>),
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    async fn prepared_transition(
        &mut self,
        transition: &AccountRootJournalTransition,
        managed_initial: bool,
    ) -> Result<Option<State>, DurableError> {
        self.read()?;
        if self.transferred.is_some() {
            return Err(DurableError::Suspended);
        }
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
                self.fence_journal().await?;
            }
            self.journal
                .as_mut()
                .ok_or(DurableError::Closed)?
                .validate_transition(transition)?;
            let mut next = self.state.clone();
            next.proposal = transition.next_proposal().clone();
            next.history.push(marker);
            next.child = Some(
                self.journal
                    .as_mut()
                    .ok_or(DurableError::Closed)?
                    .transition_checkpoint(transition)?,
            );
            Ok(Some(next))
        }
    }
    async fn transition(
        &mut self,
        transition: &AccountRootJournalTransition,
        managed_initial: bool,
    ) -> Result<(), DurableError> {
        if let Some(next) = self
            .prepared_transition(transition, managed_initial)
            .await?
        {
            save(&self.enrollment, Some(&self.state), &next, "handoff")?;
            self.state = next;
        }
        self.fence_journal().await
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl AccountRootEnrollmentRecovery {
    // A live managed controller uses the existing child lease to refuse an
    // incompatible head before changing its independent registry intent.
    pub(in crate::enrollment) async fn validate_managed_transition(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<(), DurableError> {
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        owners.prepared_transition(transition, true).await?;
        self.active = Some(owners);
        Ok(())
    }
    /// Retain the independently approved transition in the original enrollment
    /// before changing its journal fence. Original enrollment bytes and journal
    /// image/pending intent are preserved. Failure consumes all local owners and
    /// can follow either commit; recover this same transition without old traffic.
    pub async fn transition_after_noncommit(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        self.transition_inner(transition, false).await
    }
    pub(in crate::enrollment) async fn apply_managed_transition(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        self.transition_inner(transition, true).await
    }
    async fn transition_inner(
        &mut self,
        transition: &AccountRootJournalTransition,
        managed_initial: bool,
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        owners.transition(transition, managed_initial).await?;
        self.active = Some(owners);
        self.status()
    }
    /// Reconcile one original transition using the existing independently retained
    /// enrollment. A missing parent or journal is never replaced. A parent already
    /// committed to the next proposal reconstructs its authorized child history,
    /// including when an older journal backup removed a completed child transition.
    pub async fn resume_transition(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        Self::open_transition(paths, intent, pin, transition, false).await
    }
    async fn open_transition(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
        allow_initial: bool,
    ) -> Result<Self, DurableError> {
        let enrollment = DeviceEnrollment::open_original_storage(paths, intent).await?;
        Self::transition_owner(enrollment, pin, transition, allow_initial).await
    }
    pub(in crate::enrollment) async fn prepare_managed_transition(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        Self::transition_owner(enrollment, pin, transition, true).await
    }
    async fn transition_owner(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
        allow_initial: bool,
    ) -> Result<Self, DurableError> {
        let state = match Self::read_transition_state(&enrollment, transition, allow_initial)? {
            TransitionState::Initial => {
                return Self::prepare_initial_transition(enrollment, pin, transition).await
            }
            TransitionState::Retained(state) => state,
        };
        Self::resume_transition_state(enrollment, pin, state, transition, allow_initial).await
    }

    // Conversely, retries of a retained transition must not reserve the initial
    // preparation frame while reconciling the existing child journal.
    #[inline(never)]
    async fn prepare_initial_transition(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        Self::prepare(enrollment, pin, transition.next_proposal().clone()).await
    }

    // The retained-transition path has its own validation and state-copy frame.
    // Initial preparation must not reserve it while recovering the child journal.
    #[inline(never)]
    async fn resume_transition_state(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        state: Box<State>,
        transition: &AccountRootJournalTransition,
        allow_initial: bool,
    ) -> Result<Self, DurableError> {
        let mut owners = Owners {
            enrollment,
            pin,
            state: *state,
            journal: None,
            transferred: None,
        };
        owners.transition(transition, allow_initial).await?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }

    // Finish decoding and drop the full enrollment/retirement snapshot before
    // child recovery performs another signature verification. Keeping this frame
    // separate bounds nested stack use on default foreign caller threads.
    #[inline(never)]
    fn read_transition_state(
        enrollment: &DeviceEnrollment,
        transition: &AccountRootJournalTransition,
        allow_initial: bool,
    ) -> Result<TransitionState, DurableError> {
        let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
        if snapshot.retirement.is_some() {
            return Err(DurableError::Conflict);
        }
        // Only the managed caller may admit an initial fence: its registry has
        // already retained original non-commit and the exact next approved plan.
        // Replaying that initial fence has no predecessor journal history. No
        // storage error is converted to absence or to creation of a new parent.
        match snapshot.root_replacement {
            None if allow_initial => Ok(TransitionState::Initial),
            Some(state)
                if allow_initial
                    && state.proposal == *transition.next_proposal()
                    && state.history.is_empty() =>
            {
                Ok(TransitionState::Initial)
            }
            Some(state) => Ok(TransitionState::Retained(state)),
            None => Err(DurableError::Absent),
        }
    }
}
