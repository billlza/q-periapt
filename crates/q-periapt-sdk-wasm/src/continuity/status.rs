// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
/// Original durable progress. Only activation under current authority releases a service.
#[wasm_bindgen(js_name = QPeriaptContinuityPhase)]
pub enum Phase {
    /// Original intent, before releasing a signed request.
    Preparing = 1,
    /// Original request committed; remote registration may have happened.
    Requested = 2,
    /// Original grant/journal accepted; prepare the original children.
    Accepted = 3,
    /// Activation started; retry activation, never child creation.
    Activating = 4,
    /// Original service has operated; reopen through current authorized activation.
    Active = 5,
    /// Original roster change awaits journal reconciliation.
    Refreshing = 6,
    /// Historical roster result exists without sufficient current traffic authority.
    RosterResolved = 7,
}
/// Immutable authenticated progress snapshot, not a lease or authorization token.
#[wasm_bindgen(js_name = QPeriaptContinuityStatus)]
pub struct Status {
    pub(super) inner: engine::EnrollmentStatus,
}
#[wasm_bindgen(js_class = QPeriaptContinuityStatus)]
impl Status {
    /// Exact original enrollment stage, including unresolved roster states.
    pub fn phase(&self) -> Phase {
        use engine::EnrollmentStatus as E;
        match self.inner {
            E::Preparing => Phase::Preparing,
            E::Requested => Phase::Requested,
            E::Accepted(_) => Phase::Accepted,
            E::Activating(_) => Phase::Activating,
            E::Active(_) => Phase::Active,
            E::Refreshing { .. } => Phase::Refreshing,
            E::RosterResolved(_) => Phase::RosterResolved,
        }
    }
    /// Original journal when one has been allocated; absent only before grant acceptance.
    pub fn journal(&self) -> Option<Vec<u8>> {
        use engine::EnrollmentStatus as E;
        match self.inner {
            E::Preparing | E::Requested => None,
            E::Accepted(id)
            | E::Activating(id)
            | E::Active(id)
            | E::Refreshing { journal: id, .. } => Some(id.as_bytes().to_vec()),
            E::RosterResolved(value) => Some(value.journal.as_bytes().to_vec()),
        }
    }
    /// Retained original roster expectations/results, only in a roster recovery stage.
    pub fn roster_refresh(&self) -> Option<Refresh> {
        match self.inner {
            engine::EnrollmentStatus::Refreshing { previous, next, .. } => Some(Refresh {
                previous,
                target: next,
                observed: None,
                outcome: None,
                observed_at: None,
            }),
            engine::EnrollmentStatus::RosterResolved(value) => Some(Refresh {
                previous: value.previous,
                target: value.target,
                observed: Some(value.observed),
                outcome: Some(value.outcome),
                observed_at: Some(value.observed_at),
            }),
            engine::EnrollmentStatus::Preparing
            | engine::EnrollmentStatus::Requested
            | engine::EnrollmentStatus::Accepted(_)
            | engine::EnrollmentStatus::Activating(_)
            | engine::EnrollmentStatus::Active(_) => None,
        }
    }
}
/// Historical roster disposition, never an automatic reauthorization.
#[wasm_bindgen(js_name = QPeriaptContinuityRosterOutcome)]
pub enum RosterOutcome {
    /// Original target was observed committed.
    Committed = 1,
    /// Original target expired while the journal remained below it.
    ExpiredUncommitted = 2,
    /// Different bytes at the target version exclude original adoption.
    SupersededUncommitted = 3,
    /// A later head supersedes the target; past adoption is unknown.
    SupersededUnknown = 4,
}
/// Immutable signed-checkpoint expectation; does not authenticate itself.
#[wasm_bindgen(js_name = QPeriaptContinuityCheckpoint)]
pub struct Checkpoint {
    inner: engine::RosterCheckpoint,
}
#[wasm_bindgen(js_class = QPeriaptContinuityCheckpoint)]
impl Checkpoint {
    /// Original checkpoint version.
    pub fn version(&self) -> u64 {
        self.inner.version()
    }
    /// Original checkpoint digest.
    pub fn digest(&self) -> Vec<u8> {
        self.inner.digest().to_vec()
    }
}
/// Original roster recovery metadata without guessing an unknown commit result.
#[wasm_bindgen(js_name = QPeriaptContinuityRosterRefresh)]
pub struct Refresh {
    previous: engine::RosterCheckpoint,
    target: engine::RosterCheckpoint,
    observed: Option<engine::RosterCheckpoint>,
    outcome: Option<engine::RosterRefreshOutcome>,
    observed_at: Option<u64>,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRosterRefresh)]
impl Refresh {
    /// Original expected predecessor.
    pub fn previous(&self) -> Checkpoint {
        Checkpoint {
            inner: self.previous,
        }
    }
    /// Original independently approved target.
    pub fn target(&self) -> Checkpoint {
        Checkpoint { inner: self.target }
    }
    /// Actual retained observation, absent while resolution is pending.
    pub fn observed(&self) -> Option<Checkpoint> {
        self.observed.map(|inner| Checkpoint { inner })
    }
    /// Trusted observation time; absent while resolution is pending.
    pub fn observed_at(&self) -> Option<u64> {
        self.observed_at
    }
    /// Retained outcome; absence means unresolved, never uncommitted.
    pub fn outcome(&self) -> Option<RosterOutcome> {
        self.outcome.map(|outcome| match outcome {
            engine::RosterRefreshOutcome::Committed => RosterOutcome::Committed,
            engine::RosterRefreshOutcome::ExpiredUncommitted => RosterOutcome::ExpiredUncommitted,
            engine::RosterRefreshOutcome::SupersededUncommitted => {
                RosterOutcome::SupersededUncommitted
            }
            engine::RosterRefreshOutcome::SupersededUnknown => RosterOutcome::SupersededUnknown,
        })
    }
}
