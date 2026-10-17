// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact original roster outcomes; unknown supersession is not no commit.
use super::*;

#[repr(C)]
pub struct RosterResolution {
    pub outcome: u32,
    pub reserved: u32,
    pub journal: [u8; 32],
    pub previous: Checkpoint,
    pub target: Checkpoint,
    pub observed: Checkpoint,
    pub observed_at: u64,
}
impl RosterResolution {
    fn observed(value: p::RosterRefreshResolution) -> Self {
        Self {
            outcome: match value.outcome {
                p::RosterRefreshOutcome::Committed => 1,
                p::RosterRefreshOutcome::ExpiredUncommitted => 2,
                p::RosterRefreshOutcome::SupersededUncommitted => 3,
                p::RosterRefreshOutcome::SupersededUnknown => 4,
            },
            reserved: 0,
            journal: *value.journal.as_bytes(),
            previous: Checkpoint::observed(value.previous),
            target: Checkpoint::observed(value.target),
            observed: Checkpoint::observed(value.observed),
            observed_at: value.observed_at,
        }
    }
}

/// Resolve only the original retained predecessor/target pair. Loads signed P0
/// history without a live SDK runtime, TLS environment or private signer.
/// No owner transfer occurs; a failed call may have persisted the original result.
/// # Safety
/// Input records are aligned, immutable and readable for the call. Result and
/// diagnostic are distinct aligned writable records, disjoint from all inputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_resolve_roster_refresh(
    handle: u64,
    previous: *const Checkpoint,
    target: *const Checkpoint,
    resolution: *mut RosterResolution,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(resolution)?;
        if previous.is_null() || !previous.is_aligned() || target.is_null() || !target.is_aligned()
        {
            return Err(Failure::argument());
        }
        // SAFETY: copied from the validated caller input records before admission.
        let (previous, target) = unsafe { ((*previous).native()?, (*target).native()?) };
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let result = owner.enrollment.resolve_roster_refresh(
                previous,
                target,
                &original,
                owner::now().map_err(Failure::configuration)?,
            )?;
            Ok(RosterResolution::observed(result))
        })?;
        // SAFETY: success is published only after native readback and invocation checks.
        unsafe { put(resolution, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
