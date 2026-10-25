// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::Ordering;

fn invoke(
    owner: &mut DeviceEnrollment,
    f: &Fixture,
    adopt: bool,
) -> Result<WitnessJournalAdoptionState, DurableError> {
    if adopt {
        owner.adopt_witness_handoff(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            &f.transfer.receipt,
        )
    } else {
        owner.prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || Ok(180))
    }
}
#[test]
fn enrollment_witness_selection_parent_sync_faults_preserve_child_commit_and_exact_retry() {
    for adopt in [false, true] {
        let f = Fixture::new();
        if adopt {
            let mut owner = open(&f.c);
            owner
                .prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || {
                    Ok(180)
                })
                .expect("first preparation");
            owner.close();
        }
        let parent = fs::read(&f.c.paths.configuration).expect("closed original parent");
        let child = fs::read(f.c.paths.installation.files()[1]).expect("closed original child");
        let signer = fs::read(&f.c.paths.signer).expect("original signer");
        let (mut owner, _, count) = faulty(&f.c, false);
        count.store(0, Ordering::SeqCst);
        invoke(&mut owner, &f, adopt).expect("calibrate parent transaction only");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        owner.close();
        let close_syncs = count.load(Ordering::SeqCst) - barriers;
        for after in [false, true] {
            for cut in 1..=barriers {
                fs::write(&f.c.paths.configuration, &parent).expect("restore closed owned parent");
                fs::write(f.c.paths.installation.files()[1], &child)
                    .expect("restore closed owned child");
                let (mut owner, remaining, _) = faulty(&f.c, after);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(invoke(&mut owner, &f, adopt), after);
                assert!(matches!(owner.status(), Err(DurableError::Closed)));
                let mut recovered = f.transfer.adopt_parent(&f.c, 180);
                assert_eq!(
                    recovered
                        .witness_handoff_status(f.c.policy.historical(), f.transfer.plan.clone())
                        .expect("same committed selection"),
                    WitnessJournalAdoptionState::Adopted
                );
                recovered.close();
                assert_eq!(fs::read(&f.c.paths.signer).expect("same signer"), signer);
                assert_eq!(f.transfer.requests.load(Ordering::SeqCst), 0);
            }
        }
        eprintln!("ENROLLMENT_WITNESS_PARENT_SYNC adopt={adopt} transaction_syncs={barriers} faults={} close_syncs={close_syncs}", 2 * barriers);
    }
}
