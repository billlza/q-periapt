// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{durable::tests::fault_database_path, WitnessJournalAdoption};
use std::sync::atomic::{AtomicUsize, Ordering};

struct SyncCase {
    f: Fixture,
    approval: Approval,
    proposal: PolicyProposal,
    before: (Vec<u8>, Option<Vec<u8>>),
    next: Transfer,
    parent_bytes: Vec<u8>,
    child_bytes: Vec<u8>,
}
impl SyncCase {
    fn new(adopt: bool) -> Self {
        let (f, approval, proposal) = pending_case();
        let before = journal(&f);
        let first = first_transfer(&f);
        let mut next = next_transfer(&f, &first, 154, 78);
        next.plan = next
            .plan
            .clone()
            .continue_from(&first.plan, &first.control)
            .expect("same explicit adopted predecessor");
        next.set_time(156);
        if adopt {
            open(&f.c)
                .prepare_witness_handoff(f.c.policy.historical(), next.plan.clone(), || Ok(155))
                .expect("second prepared selection");
        }
        let parent_bytes = fs::read(&f.c.paths.configuration).expect("closed parent baseline");
        let child_bytes =
            fs::read(f.c.paths.installation.files()[1]).expect("closed child baseline");
        Self {
            f,
            approval,
            proposal,
            before,
            next,
            parent_bytes,
            child_bytes,
        }
    }
    fn reset(&self) {
        fs::write(&self.f.c.paths.configuration, &self.parent_bytes)
            .expect("restore owned baseline parent");
        fs::write(self.f.c.paths.installation.files()[1], &self.child_bytes)
            .expect("restore owned baseline child");
    }
    fn recover(&self) {
        let mut owner = self.next.adopt_parent(&self.f.c, 155);
        assert_eq!(
            owner
                .witness_handoff_status(self.f.c.policy.historical(), self.next.plan.clone())
                .expect("same exact successor decision"),
            WitnessJournalAdoptionState::Adopted
        );
        let mut client = self.next.client(&mut owner, &self.f.c);
        let subject = AnchorSubject::for_device(self.f.id, &self.f.original, &self.f.c.policy)
            .expect("original subject");
        assert_eq!(
            client
                .exchange(
                    subject,
                    AnchorOperation::policy_renewal_status(&self.proposal)
                )
                .expect("recovered current witness through actual TCP")
                .policy_renewal_state(&self.proposal)
                .expect("same original operation"),
            State::Prepared
        );
        owner.close();
        assert_eq!(
            journal(&self.f),
            self.before,
            "fault/retry cannot reseal or drop original P"
        );
    }
    fn finish(&self) {
        complete_original(
            &self.f,
            &self.approval,
            self.proposal,
            &self.before,
            &self.next,
            156,
        );
    }
    fn parent(
        &self,
        owner: &mut DeviceEnrollment,
        adopt: bool,
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        if adopt {
            owner.adopt_witness_handoff(
                self.f.c.policy.historical(),
                self.next.plan.clone(),
                &self.next.receipt,
            )
        } else {
            owner.prepare_witness_handoff(
                self.f.c.policy.historical(),
                self.next.plan.clone(),
                || Ok(155),
            )
        }
    }
    fn child(
        &self,
        adopt: bool,
        after: bool,
        cut: usize,
    ) -> (
        Result<WitnessJournalAdoption, DurableError>,
        Arc<AtomicUsize>,
    ) {
        let (db, remaining, count, _) =
            fault_database_path(self.f.c.paths.installation.files()[1], after);
        let key = JournalKey::open(&self.f.c.paths.wrapping).expect("original key");
        if adopt {
            let mut owner =
                WitnessJournalAdoption::resume_in_database(db, key, self.next.plan.clone())
                    .expect("original prepared successor");
            count.store(0, Ordering::SeqCst);
            remaining.store(cut, Ordering::SeqCst);
            let result = owner.adopt_authorization(&self.next.receipt);
            if result.is_err() {
                assert!(matches!(owner.status(), Err(DurableError::Closed)));
            }
            (result.map(|_| owner), count)
        } else {
            count.store(0, Ordering::SeqCst);
            remaining.store(cut, Ordering::SeqCst);
            (
                WitnessJournalAdoption::prepare_in_database(
                    db,
                    key,
                    self.next.plan.clone(),
                    || Ok(155),
                ),
                count,
            )
        }
    }
}

#[test]
fn enrollment_witness_successor_parent_sync_faults_reconcile_exact_child_commit() {
    for adopt in [false, true] {
        let c = SyncCase::new(adopt);
        let (mut owner, _, count) = faulty(&c.f.c, false);
        count.store(0, Ordering::SeqCst);
        c.parent(&mut owner, adopt)
            .expect("calibrate parent publication");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        owner.close();
        let close_syncs = count.load(Ordering::SeqCst) - barriers;
        for after in [false, true] {
            for cut in 1..=barriers {
                c.reset();
                let (mut owner, remaining, _) = faulty(&c.f.c, after);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(c.parent(&mut owner, adopt), after);
                assert!(matches!(owner.status(), Err(DurableError::Closed)));
                c.recover();
            }
        }
        c.finish();
        eprintln!("SUCCESSOR_PARENT_SYNC adopt={adopt} barriers={barriers} faults={} close_syncs={close_syncs}", 2 * barriers);
    }
}

#[test]
fn enrollment_witness_successor_child_sync_faults_preserve_predecessor_and_original_p() {
    for adopt in [false, true] {
        let c = SyncCase::new(adopt);
        let (result, count) = c.child(adopt, false, 0);
        let mut owner = result.expect("calibrate original child transaction");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        owner.close();
        let close_syncs = count.load(Ordering::SeqCst) - barriers;
        for after in [false, true] {
            for cut in 1..=barriers {
                c.reset();
                let (result, _) = c.child(adopt, after, cut);
                assert_sync_failure(result, after);
                c.recover();
            }
        }
        c.finish();
        eprintln!("SUCCESSOR_CHILD_SYNC adopt={adopt} barriers={barriers} faults={} close_syncs={close_syncs}", 2 * barriers);
    }
}
