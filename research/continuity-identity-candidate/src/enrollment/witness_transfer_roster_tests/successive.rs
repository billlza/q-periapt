// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AnchorOperation;

#[test]
fn enrollment_witness_successive_r_preserves_original_or_renewed_policy_and_three_stages() {
    for adopted in [false, true] {
        for progress in [0, 1, 2] {
            let c = case(adopted);
            let p = prepare_original(&c);
            let sealed = journal(&c.f);
            witness_prepare(&c, p);
            let subject =
                AnchorSubject::for_device(c.f.id, &c.f.original, &c.f.c.policy).expect("subject");
            let first = Transfer::new(
                &mut c.f.carrier.store.lock().expect("A"),
                &c.f.c,
                &c.f.original,
                &c.previous,
                c.policy.historical(),
                subject,
                151,
            );
            first.adopt_parent(&c.f.c, 152).close();
            first.set_time(153);
            if progress > 0 {
                let mut owner = open(&c.f.c);
                let mut carrier = first.client(&mut owner, &c.f.c);
                assert_eq!(
                    carrier
                        .exchange(subject, AnchorOperation::commit_roster_refresh(&p))
                        .expect("B applies original R")
                        .roster_refresh_state(&p)
                        .expect("same R"),
                    RState::Applied
                );
                if progress == 2 {
                    assert_eq!(
                        DeviceJournal::recover_roster_refresh(
                            c.f.c.paths.installation.files()[1],
                            JournalKey::open(&c.f.c.paths.wrapping).expect("original key"),
                            &c.f.original,
                            c.f.c.policy.historical(),
                            c.f.id,
                            p,
                            &mut carrier
                        )
                        .expect("original target installed with pending"),
                        RState::Applied
                    );
                    assert_eq!(journal(&c.f), (target_image(&sealed), sealed.1.clone()));
                }
                owner.close();
            }
            let before = journal(&c.f);
            let current = if progress > 0 { &c.target } else { &c.previous };
            let second = first.successor(
                &c.f.c,
                &c.f.original,
                current,
                c.policy.historical(),
                subject,
                (154, 97),
            );
            second.set_time(156);
            second.adopt_parent(&c.f.c, 155).close();
            assert_eq!(
                journal(&c.f),
                before,
                "second selection must preserve exact R"
            );
            second.reopen_target();
            let mut owner = open(&c.f.c);
            let mut carrier = second.client(&mut owner, &c.f.c);
            assert_eq!(
                owner
                    .commit_witnessed_roster_refresh(
                        &p,
                        c.f.c.policy.historical(),
                        &c.policy,
                        156,
                        &mut carrier
                    )
                    .expect("original R and parent ACK"),
                RState::Applied
            );
            owner.close();
            check_terminal(&c, p, false, true);
            assert_eq!(journal(&c.f), (target_image(&sealed), None));
            let mut owner = open(&c.f.c);
            let carrier = second.client(&mut owner, &c.f.c);
            let mut active = if adopted {
                owner.activate_witnessed_policy_renewal(
                    c.f.c.policy.historical(),
                    &c.policy,
                    156,
                    carrier,
                )
            } else {
                owner.activate(&c.policy, 156, Some(carrier))
            }
            .expect("same admitted installation");
            let (service, signer, device) = active.parts().expect("owners");
            signer.check_device(device).expect("original signer");
            assert_eq!(device.roster().checkpoint(), p.scope().target);
            assert_eq!(
                service
                    .stores()
                    .expect("original journal")
                    .0
                    .identity()
                    .expect("id"),
                c.f.id
            );
            active.close();
            eprintln!("SUCCESSIVE_R adopted_p={adopted} stage={progress} original_target=true parent_ack=true");
        }
    }
}

#[test]
fn enrollment_witness_successive_r_closes_original_target_after_expiry() {
    for adopted in [false, true] {
        let c = case(adopted);
        let p = prepare_original(&c);
        let saved = journal(&c.f);
        witness_prepare(&c, p);
        let subject =
            AnchorSubject::for_device(c.f.id, &c.f.original, &c.f.c.policy).expect("subject");
        let first = Transfer::new(
            &mut c.f.carrier.store.lock().expect("A"),
            &c.f.c,
            &c.f.original,
            &c.previous,
            c.policy.historical(),
            subject,
            151,
        );
        first.adopt_parent(&c.f.c, 152).close();
        let second = first.successor(
            &c.f.c,
            &c.f.original,
            &c.previous,
            c.policy.historical(),
            subject,
            (154, 97),
        );
        second.adopt_parent(&c.f.c, 155).close();
        second.set_time(301);
        second
            .target
            .lock()
            .expect("C")
            .transferred_control(&second.control)
            .expect("exact current authorization")
            .close_roster_refresh(p, &c.previous, &c.target, c.policy.historical())
            .expect("historical original close");
        second.reopen_target();
        let mut owner = open(&c.f.c);
        let mut carrier = second.client(&mut owner, &c.f.c);
        assert_eq!(
            owner
                .close_witnessed_roster_refresh(&p, c.f.c.policy.historical(), &mut carrier)
                .expect("original close and parent ACK"),
            RState::Closed
        );
        owner.close();
        assert_eq!(journal(&c.f), (saved.0, None));
        check_terminal(&c, p, true, true);
    }
}
