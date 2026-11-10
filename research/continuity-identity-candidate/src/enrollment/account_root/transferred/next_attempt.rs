// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Publish the exact next parent expectation before changing its child fence.
use super::*;
use crate::TransferredAccountRootJournalTransition;

fn matches_plan(
    state: &State,
    plan: &TransferredAccountRootJournalPlan,
) -> Result<bool, DurableError> {
    Ok(state.proposal == *plan.proposal()
        && state.authority.as_ref() == Some(&plan.binding()?)
        && &state.attempts == plan.attempts()
        && state.history.is_empty()
        && state.child.is_some())
}

// Keep decoding the complete parent out of the child/signature verification frame.
#[inline(never)]
fn retained_state(
    enrollment: &DeviceEnrollment,
    transition: &TransferredAccountRootJournalTransition,
) -> Result<(Box<State>, VerifiedDevice, bool), DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
    if snapshot.retirement.is_some() {
        return Err(DurableError::Conflict);
    }
    let state = snapshot.root_replacement.ok_or(DurableError::Absent)?;
    let already_next = matches_plan(&state, transition.next_plan())?;
    let plan = if already_next {
        transition.next_plan()
    } else {
        transition.previous_plan()
    };
    if !matches_plan(&state, plan)? {
        return Err(DurableError::Conflict);
    }
    if let Some(receipt) = &state.receipt {
        plan.verify(receipt)?;
        if !already_next && receipt != transition.closed() {
            return Err(DurableError::Conflict);
        }
    }
    let original = validate(
        enrollment,
        &snapshot.image,
        plan.witness_pin()?,
        plan.proposal(),
    )?;
    let Phase::Accepted { admission, .. } = &snapshot.image.phase else {
        return Err(DurableError::Suspended);
    };
    plan.check_parent(&original, admission.journal, admission.policy)?;
    check_selection(plan, snapshot.witness_handoff.as_ref())?;
    Ok((state, original, already_next))
}

struct PreparedTransition {
    state: Box<State>,
    child: crate::durable::RootAttemptPreparation,
    already_next: bool,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl PreparedTransition {
    async fn preflight(
        enrollment: &DeviceEnrollment,
        transition: &TransferredAccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        let (state, original, already_next) = retained_state(enrollment, transition)?;
        let child = AccountRootJournalRecovery::prepare_transferred_transition(
            enrollment.paths.installation.files()[1],
            enrollment.key().await?,
            &original,
            state.journal,
            transition,
        )?;
        let expected = if already_next {
            child.checkpoint()
        } else {
            child.previous_checkpoint()
        };
        if state.child != Some(expected) || (!already_next && child.already_next()) {
            return Err(DurableError::Conflict);
        }
        Ok(Self {
            state,
            child,
            already_next,
        })
    }
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl AccountRootEnrollmentRecovery {
    // Read-only preflight for the existing managed registry controller. Holding
    // the enrollment excludes another managed activation; the child lease is
    // retained throughout validation and no intent is published here.
    // Do not reserve the next-attempt preflight frame on the original foreign-caller path.
    #[inline(never)]
    pub(in crate::enrollment) async fn check_transferred_transition(
        enrollment: &DeviceEnrollment,
        transition: &TransferredAccountRootJournalTransition,
    ) -> Result<(), DurableError> {
        PreparedTransition::preflight(enrollment, transition).await?;
        Ok(())
    }

    /// Reconcile the independently approved next target after authentic permanent
    /// non-commit. Retains the original enrollment, journal, pending work, selection
    /// and every exact signed closure. Parent publication precedes child publication.
    /// Missing or conflicting stores fail; errors may follow either durable commit.
    pub async fn resume_transferred_transition(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        transition: &TransferredAccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        let enrollment = DeviceEnrollment::open_original_storage(paths, intent).await?;
        Self::prepare_transferred_transition(enrollment, transition).await
    }

    pub(in crate::enrollment) async fn prepare_transferred_transition(
        enrollment: DeviceEnrollment,
        transition: &TransferredAccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        let PreparedTransition {
            state,
            child,
            already_next,
        } = PreparedTransition::preflight(&enrollment, transition).await?;
        let plan = transition.next_plan();
        let next = if already_next {
            *state
        } else {
            let mut next = (*state).clone();
            next.proposal = plan.proposal().clone();
            next.authority = Some(plan.binding()?);
            next.attempts = plan.attempts().clone();
            next.receipt = None;
            next.child = Some(child.checkpoint());
            let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
            if next.encode(&active.key, enrollment.binding)?.len() + CURRENT_RECEIPT_BYTES
                > MAX_BYTES
            {
                return Err(DurableError::Capacity);
            }
            save(&enrollment, Some(&state), &next, "transferred-handoff")?;
            next
        };
        let journal = child.commit()?;
        let mut owners = Owners {
            journal: Some(journal),
            enrollment,
            pin: plan.witness_pin()?.clone(),
            state: next,
            transferred: Some(Box::new(plan.clone())),
        };
        owners.read()?;
        owners.reconcile_current_outcome()?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
