// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::account_authority::tests::{
    fault_database, restore_registry_snapshot, snapshot_registry,
};
use std::sync::atomic::Ordering;

pub(super) struct Case {
    pub(super) s: Scenario,
    pub(super) next: Next,
    pub(super) phase: u8,
    pub(super) closed: bool,
    pub(super) wire: Option<Vec<u8>>,
}
impl Case {
    pub(super) fn new(work: Work, phase: u8, closed: bool) -> Self {
        let mut s = Scenario::new(work, true);
        let next = Next::new(&mut s, "next-target", 211, 186);
        if phase >= 1 {
            assert_eq!(
                s.registry
                    .begin_transferred_preparation(
                        s.recovery.expected,
                        next.plan.clone(),
                        &s.t.history
                    )
                    .expect("original approved next intent"),
                State::Preparing
            );
        }
        if phase >= 2 {
            assert_eq!(
                s.registry
                    .bind_transferred_preparation(
                        next.plan.operation(),
                        &s.t.frozen,
                        next.approval.clone()
                    )
                    .expect("original approved next freeze"),
                State::Pending
            );
        }
        let wire = if phase == 2 {
            Some(next.decide(&mut s, closed))
        } else {
            None
        };
        Self {
            s,
            next,
            phase,
            closed,
            wire,
        }
    }
    pub(super) fn expected(&self) -> State {
        *[
            State::Preparing,
            State::Pending,
            if self.closed {
                State::Closed
            } else {
                State::Committed
            },
        ]
        .get(usize::from(self.phase))
        .expect("bounded owned test stage")
    }
    pub(super) fn apply(&mut self) -> Result<State, DurableError> {
        Step {
            history: &self.s.t.history,
            frozen: &self.s.t.frozen,
            plan: &self.next.plan,
            approval: &self.next.approval,
            phase: self.phase,
            wire: self.wire.as_deref(),
        }
        .apply(&mut self.s.registry, self.s.recovery.expected)
    }
}
pub(super) struct Step<'a> {
    pub(super) history: &'a AnchorHandoffHistory,
    pub(super) frozen: &'a AnchorFrozenAccount,
    pub(super) plan: &'a AnchorTransferredAccountReplacementPlan,
    pub(super) approval: &'a AnchorTransferredAccountReplacementApproval,
    pub(super) phase: u8,
    pub(super) wire: Option<&'a [u8]>,
}
impl Step<'_> {
    pub(super) fn apply(
        &self,
        registry: &mut AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
    ) -> Result<State, DurableError> {
        match self.phase {
            0 => registry.begin_transferred_preparation(expected, self.plan.clone(), self.history),
            1 => registry.bind_transferred_preparation(
                self.plan.operation(),
                self.frozen,
                self.approval.clone(),
            ),
            2 => registry.retain_transferred_account_decision(
                self.plan.operation(),
                self.wire.ok_or(DurableError::Corrupt)?,
            ),
            _ => Err(DurableError::Corrupt),
        }
    }
}
type Rows = Vec<(String, Vec<u8>)>;
pub(super) fn original_rows(t: &Transferred) -> [Rows; 2] {
    [
        (&t.f.original.paths.configuration as &Path, TABLE),
        (t.f.original.paths.installation.files()[1], JOURNAL),
    ]
    .map(|(path, table)| {
        let db = open_private_database(path).expect("same original protected storage");
        let tx = db.begin_read().expect("original read");
        tx.open_table(table)
            .expect("original table")
            .iter()
            .expect("original rows")
            .map(|r| {
                let (k, v) = r.expect("row");
                (k.value().to_string(), v.value().to_vec())
            })
            .collect()
    })
}
#[test]
fn transferred_next_attempt_all_registry_sync_boundaries_keep_closed_history_and_original_state() {
    for work in [
        Work::Credential(1),
        Work::Roster(1),
        Work::Cancellation(true),
    ] {
        for (phase, closed) in [(0, false), (1, false), (2, false), (2, true)] {
            let mut c = Case::new(work, phase, closed);
            let original = original_rows(&c.s.t);
            let baseline = snapshot_registry(&c.s.registry);
            let path = c.s.recovery.path.clone();
            let (_, count) = fault_database(&mut c.s.registry, &path, false);
            count.store(0, Ordering::SeqCst);
            assert_eq!(
                c.apply().expect("calibrate original transaction"),
                c.expected()
            );
            let barriers = count.load(Ordering::SeqCst);
            assert!((1..=8).contains(&barriers));
            c.s.registry.close();
            for after in [false, true] {
                for cut in 1..=barriers {
                    restore_registry_snapshot(&path, &baseline);
                    c.s.reopen();
                    let (remaining, observed) = fault_database(&mut c.s.registry, &path, after);
                    let access = c.s.registry.access().expect("original lease");
                    observed.store(0, Ordering::SeqCst);
                    remaining.store(cut, Ordering::SeqCst);
                    crate::durable::tests::assert_sync_failure(c.apply(), after);
                    assert!(matches!(c.s.registry.access(), Err(DurableError::Closed)));
                    assert!(matches!(
                        access.current(c.s.recovery.expected.application()),
                        Err(DurableError::Closed)
                    ));
                    c.s.reopen();
                    c.s.assert_old();
                    assert_eq!(
                        c.apply().expect("exact same approved attempt retry"),
                        c.expected()
                    );
                    c.s.reopen();
                    c.s.assert_old();
                    assert_eq!(
                        c.s.registry
                            .transferred_preparation(c.next.plan.operation())
                            .expect("exact target")
                            .2,
                        &c.next.plan
                    );
                    if let Some(wire) = &c.wire {
                        assert_eq!(
                            c.s.registry
                                .transferred_account_decision(c.next.plan.operation())
                                .expect("exact terminal bytes")
                                .as_bytes(),
                            wire
                        );
                    }
                    assert!(
                        original_rows(&c.s.t) == original,
                        "registry recovery never changes original parent/journal/pending/fences"
                    );
                    c.s.registry.close();
                    eprintln!("TRANSFERRED_NEXT_SYNC work={work:?} phase={phase} closed={closed} after={after} cut={cut} calibrated={barriers} exact_old_closed=true exact_next=true original_rows=true");
                }
            }
        }
    }
}
