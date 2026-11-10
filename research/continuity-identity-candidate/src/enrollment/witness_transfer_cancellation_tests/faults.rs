// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{WitnessJournalAdoption, WitnessJournalAdoptionState};

fn reserve(
    owner: &mut DeviceEnrollment,
    f: &Fixture,
    transfer: &Transfer,
) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
    owner.prepare_witnessed_credential_cancellation_with_witness_plan(
        f.c.policy.historical(),
        transfer.plan.clone(),
        290,
    )
}
fn reserve_child(
    owner: &mut WitnessJournalAdoption,
    f: &Fixture,
    g: &crate::VerifiedCredentialRenewal,
) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
    owner.reserve_credential_cancellation(
        &f.original,
        f.c.policy.historical(),
        f.id,
        crate::durable::CredentialCancellationTarget {
            grant: g.historical(),
            continuation: None,
            adopts: false,
            completed: None,
            independent: None,
        },
    )
}

#[test]
fn transferred_cancellation_parent_sync_failure_closes_owner_and_preserves_exact_child() {
    let (f, _, transfer) = staged_transfer();
    let parent = fs::read(&f.c.paths.configuration).expect("closed original parent");
    let child = fs::read(f.c.paths.installation.files()[1]).expect("closed original child");
    let original = disk(&f).0;
    let (mut owner, _, count) = faulty(&f.c, false);
    count.store(0, Ordering::SeqCst);
    let expected = reserve(&mut owner, &f, &transfer).expect("calibrate only parent transaction");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    owner.close();
    let close_syncs = count.load(Ordering::SeqCst) - barriers;
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(&f.c.paths.configuration, &parent).expect("restore owned closed parent");
            fs::write(f.c.paths.installation.files()[1], &child)
                .expect("restore owned closed child");
            let (mut owner, remaining, _) = faulty(&f.c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(reserve(&mut owner, &f, &transfer), after);
            assert!(matches!(owner.status(), Err(DurableError::Closed)));
            assert!(disk(&f).0 == original);
            let mut recovered = open(&f.c);
            assert_eq!(
                reserve(&mut recovered, &f, &transfer).expect("original retry"),
                expected
            );
            recovered.close();
            assert!(disk(&f).0 == original);
        }
    }
    assert_eq!(transfer.requests.load(Ordering::SeqCst), 0);
    eprintln!(
        "TRANSFER_CANCEL_PARENT_SYNC barriers={barriers} faults={} close_syncs={close_syncs}",
        2 * barriers
    );
}

#[test]
fn transferred_cancellation_child_sync_failure_preserves_selection_and_original_image() {
    let (f, g, transfer) = staged_transfer();
    let path = f.c.paths.installation.files()[1];
    let image = disk(&f).0;
    // Readback opens/closes redb and can change allocator housekeeping. Freeze
    // the exact closed bytes only after that observation, for both calibration
    // and every injected attempt.
    let raw = fs::read(path).expect("closed original journal after readback");
    let (db, _, count, _) = fault_database_path(path, false);
    let mut owner = WitnessJournalAdoption::resume_in_database(
        db,
        JournalKey::open(&f.c.paths.wrapping).expect("key"),
        transfer.plan.clone(),
    )
    .expect("same selected journal");
    count.store(0, Ordering::SeqCst);
    let expected = reserve_child(&mut owner, &f, &g).expect("calibrate child transaction");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    owner.close();
    let close_syncs = count.load(Ordering::SeqCst) - barriers;
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(path, &raw).expect("restore only owned closed fixture journal");
            let (db, remaining, observed, _) = fault_database_path(path, after);
            let mut owner = WitnessJournalAdoption::resume_in_database(
                db,
                JournalKey::open(&f.c.paths.wrapping).expect("key"),
                transfer.plan.clone(),
            )
            .expect("selected journal");
            remaining.store(cut, Ordering::SeqCst);
            observed.store(0, Ordering::SeqCst);
            let result = reserve_child(&mut owner, &f, &g);
            eprintln!("TRANSFER_CANCEL_CHILD_CUT calibrated={barriers} after={after} cut={cut} observed={} remaining={} returned_error={}",
                observed.load(Ordering::SeqCst), remaining.load(Ordering::SeqCst), result.is_err());
            assert_sync_failure(result, after);
            assert!(matches!(owner.status(), Err(DurableError::Closed)));
            assert!(disk(&f).0 == image);
            let mut recovered = WitnessJournalAdoption::resume_original(
                path,
                JournalKey::open(&f.c.paths.wrapping).expect("key"),
                transfer.plan.clone(),
            )
            .expect("same original recovery");
            assert_eq!(
                recovered.status().expect("persistent selection"),
                WitnessJournalAdoptionState::Adopted
            );
            assert_eq!(
                reserve_child(&mut recovered, &f, &g).expect("same reservation"),
                expected
            );
            recovered.close();
            assert!(disk(&f).0 == image);
        }
    }
    assert_eq!(transfer.requests.load(Ordering::SeqCst), 0);
    eprintln!(
        "TRANSFER_CANCEL_CHILD_SYNC barriers={barriers} faults={} close_syncs={close_syncs}",
        2 * barriers
    );
}
