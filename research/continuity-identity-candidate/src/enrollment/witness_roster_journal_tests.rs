// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real original R journal targets; witness history never becomes an operational owner.
use super::*;
use crate::{
    AnchorRosterRefreshProposal as RProposal, AnchorRosterRefreshState as RState, RosterRefreshId,
    RosterRefreshMaterials,
};
type JournalSnapshot = (Vec<u8>, Option<Vec<u8>>);
struct Case {
    f: Fixture,
    policy: VerifiedSessionPolicy,
    previous: VerifiedDevice,
    target: VerifiedDevice,
}
fn case(adopted: bool) -> Case {
    let f = fixture();
    let mut owner = open(&f.c);
    let client = owner
        .anchor_client(
            &f.c.policy,
            150,
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("original client");
    let mut active = owner
        .activate(&f.c.policy, 150, Some(client))
        .expect("original owner");
    let (service, _, device) = active.parts().expect("original owners");
    service
        .stores()
        .expect("stores")
        .0
        .generate_prekey(
            &f.c.policy,
            device,
            PrekeyId::from_trusted_state([117; 32]).expect("prekey ID"),
            LeafKind::OneTimePq,
            Validity::new(100, 160).expect("validity"),
            150,
        )
        .expect("real existing SDK prekey");
    active.close();
    let policy = if adopted {
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        approve_witness(&f, &a, p);
        applied_at(&f, &a, p, 150);
        a.target
    } else {
        policy(&f.c, 1, 200, 150)
    };
    let mut owner = open(&f.c);
    let certificate = match owner.image().expect("configuration").phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("accepted"),
    }
    .expect("original certificate");
    owner.close();
    let roster =
        f.c.root
            .issue_roster(
                2,
                interval(),
                &[f.c.root.roster_entry(&certificate).expect("original C")],
            )
            .expect("signed R2");
    let target = AccountPin::new(
        f.original.account_id(),
        f.c.intent.root.clone(),
        roster.checkpoint(),
        policy.family(),
    )
    .expect("root-approved pin")
    .verify_device(&certificate, roster.as_bytes(), 150)
    .expect("same C0, target R2");
    let previous = f.original.clone();
    Case {
        f,
        policy,
        previous,
        target,
    }
}
fn active(c: &Case) -> EnrolledDevice {
    if c.policy.checkpoint() == c.f.c.policy.checkpoint() {
        let mut owner = open(&c.f.c);
        let client = owner
            .anchor_client(
                &c.policy,
                150,
                c.f.pin.clone(),
                Box::new(c.f.carrier.clone()),
                Duration::from_secs(3),
            )
            .expect("P0 client");
        owner
            .activate(&c.policy, 150, Some(client))
            .expect("P0 owner")
    } else {
        activate(&c.f, &c.policy, 150).expect("original independently renewed P owner")
    }
}
fn materials(c: &Case) -> RosterRefreshMaterials<'_> {
    RosterRefreshMaterials {
        original: &c.f.original,
        original_policy: c.f.c.policy.historical(),
        policy: &c.policy,
        target: &c.target,
    }
}
fn prepared(c: &Case) -> RProposal {
    let mut owner = active(c);
    let p = owner
        .parts()
        .expect("owners")
        .0
        .stores()
        .expect("stores")
        .0
        .prepare_roster_refresh(
            RosterRefreshId::generate().expect("operation"),
            &materials(c),
            150,
        )
        .expect("seal original R target");
    owner.close();
    p
}
fn inspect(c: &Case) -> Result<Option<RProposal>, DurableError> {
    DeviceJournal::inspect_roster_refresh_preparation(
        c.f.c.paths.installation.files()[1],
        JournalKey::open(&c.f.c.paths.wrapping).expect("key"),
        &c.f.original,
        c.f.c.policy.historical(),
        c.f.id,
    )
}
fn target_image(saved: &JournalSnapshot) -> Vec<u8> {
    let pending = saved.1.as_ref().expect("original R pending");
    assert_eq!(pending.get(..8), Some(b"QPWINT07".as_slice()));
    pending
        .get(341..pending.len() - 32)
        .expect("original exact sealed R target")
        .to_vec()
}
fn witness_prepare(c: &Case, p: RProposal) {
    assert_eq!(
        c.f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_roster_refresh(p, &c.previous, &c.target, &c.policy, 150)
            .expect("independent exact approval"),
        RState::Prepared
    );
}
fn exchange(c: &Case, p: RProposal, op: crate::AnchorOperation) -> Result<RState, DurableError> {
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    let reply = client.exchange(p.subject(), op)?;
    Ok(reply.roster_refresh_state(&p)?)
}
fn recover(c: &Case, p: RProposal) -> Result<RState, DurableError> {
    let mut owner = open(&c.f.c);
    let mut client = policy_client(&c.f, &mut owner);
    DeviceJournal::recover_roster_refresh(
        c.f.c.paths.installation.files()[1],
        owner.key()?,
        &c.f.original,
        c.f.c.policy.historical(),
        c.f.id,
        p,
        &mut client,
    )
}
#[test]
fn actual_original_roster_target_survives_lost_commit_reply_and_expired_recovery() {
    for adopted in [false, true] {
        let c = case(adopted);
        let before = journal(&c.f);
        let p = prepared(&c);
        let saved = journal(&c.f);
        assert_eq!(saved.0, before.0);
        assert_eq!(inspect(&c).expect("original preparation"), Some(p));
        assert_eq!(journal(&c.f), saved);
        assert_eq!(
            DeviceJournal::assert_roster_target_preserves_assets(
                &JournalKey::open(&c.f.c.paths.wrapping).expect("key"),
                &c.f.original,
                &before.0,
                &target_image(&saved),
                p.scope()
            ),
            1,
            "actual prekey preserved"
        );
        witness_prepare(&c, p);
        *c.f.carrier.cut.lock().expect("lost reply") = Some((16, true));
        assert!(exchange(&c, p, crate::AnchorOperation::commit_roster_refresh(&p)).is_err());
        assert_eq!(journal(&c.f), saved);
        c.f.carrier.clock.store(401, Ordering::SeqCst);
        c.policy.close();
        c.f.c.policy.close();
        let start = c.f.carrier.requests.lock().expect("calls").len();
        assert_eq!(
            recover(&c, p).expect("exact historical Applied"),
            RState::Applied
        );
        let after = journal(&c.f);
        assert_eq!(after, (target_image(&saved), saved.1.clone()));
        assert_eq!(
            inspect(&c).expect("same proposal after installation"),
            Some(p)
        );
        assert_eq!(recover(&c, p).expect("exact retry"), RState::Applied);
        assert_eq!(journal(&c.f), after);
        assert_eq!(
            c.f.carrier.requests.lock().expect("calls").get(start..),
            Some([17, 17].as_slice()),
            "only fresh status; no commit or ACK"
        );
        assert!(
            DeviceJournal::inspect_policy_renewal_preparation(
                c.f.c.paths.installation.files()[1],
                JournalKey::open(&c.f.c.paths.wrapping).expect("key"),
                &c.f.original,
                c.f.c.policy.historical(),
                c.f.id
            )
            .is_err(),
            "R intent cannot become P"
        );
        let mut owner = open(&c.f.c);
        let client = policy_client(&c.f, &mut owner);
        assert!(
            DeviceJournal::open_anchored_retained(
                c.f.c.paths.installation.files()[1],
                owner.key().expect("key"),
                &c.f.original,
                c.f.c.policy.historical(),
                c.f.id,
                client
            )
            .is_err(),
            "ordinary open cannot consume an R terminal"
        );
    }
}
#[test]
fn prepared_closed_unavailable_and_substituted_roster_evidence_never_install_a_target() {
    for state in 0..3 {
        let c = case(true);
        let p = prepared(&c);
        let saved = journal(&c.f);
        let expected = match state {
            0 => RState::Unavailable,
            1 => {
                witness_prepare(&c, p);
                RState::Prepared
            }
            _ => {
                witness_prepare(&c, p);
                assert_eq!(
                    exchange(&c, p, crate::AnchorOperation::close_roster_refresh(&p))
                        .expect("close"),
                    RState::Closed
                );
                RState::Closed
            }
        };
        c.f.carrier.clock.store(401, Ordering::SeqCst);
        c.policy.close();
        assert_eq!(recover(&c, p).expect("historical exact state"), expected);
        assert_eq!(journal(&c.f), saved);
        let mut wrong = p.to_bytes();
        *wrong.last_mut().expect("target digest") ^= 1;
        let wrong = RProposal::from_trusted_state(&wrong).expect("another canonical proposal");
        let calls = c.f.carrier.requests.lock().expect("calls").len();
        assert!(recover(&c, wrong).is_err());
        assert_eq!(c.f.carrier.requests.lock().expect("calls").len(), calls);
        assert_eq!(journal(&c.f), saved);
    }
}
#[test]
fn unavailable_reply_preserves_original_roster_pending_and_can_retry_same_status() {
    let c = case(true);
    let p = prepared(&c);
    let saved = journal(&c.f);
    witness_prepare(&c, p);
    assert_eq!(
        exchange(&c, p, crate::AnchorOperation::commit_roster_refresh(&p)).expect("commit"),
        RState::Applied
    );
    for after in [false, true] {
        *c.f.carrier.cut.lock().expect("cut") = Some((17, after));
        assert!(recover(&c, p).is_err());
        assert_eq!(journal(&c.f), saved);
    }
    assert_eq!(
        recover(&c, p).expect("fresh original status"),
        RState::Applied
    );
    assert_eq!(journal(&c.f), (target_image(&saved), saved.1));
}

#[test]
fn an_authentic_local_roster_target_is_not_witness_applied_evidence() {
    for closed in [false, true] {
        let c = case(true);
        let p = prepared(&c);
        let saved = journal(&c.f);
        witness_prepare(&c, p);
        if closed {
            exchange(&c, p, crate::AnchorOperation::close_roster_refresh(&p))
                .expect("close exact R");
        }
        // Test-only replay of the authentic sealed target; never a production repair path.
        let db =
            open_private_database(c.f.c.paths.installation.files()[1]).expect("original journal");
        let tx = transaction(&db).expect("test transaction");
        tx.open_table(JOURNAL)
            .expect("table")
            .insert("image", target_image(&saved).as_slice())
            .expect("authentic target fixture");
        tx.commit().expect("fixture commit");
        drop(db);
        let before = journal(&c.f);
        assert!(
            matches!(recover(&c, p), Err(DurableError::Conflict)),
            "local target cannot invent Applied from Prepared/Closed"
        );
        assert_eq!(journal(&c.f), before);
    }
}
#[test]
fn preparing_roster_rejects_unchanged_roster_and_unadopted_authentic_policy_without_mutation() {
    for wrong_policy in [false, true] {
        let c = case(true);
        let before = journal(&c.f);
        let mut owner = active(&c);
        let other = policy(&c.f.c, 3, 350, 150);
        let mut m = materials(&c);
        if wrong_policy {
            m.policy = &other;
        } else {
            m.target = &c.previous;
        }
        let journal = owner.parts().expect("owners").0.stores().expect("stores").0;
        assert!(journal
            .prepare_roster_refresh(RosterRefreshId::generate().expect("ID"), &m, 150)
            .is_err());
        assert!(journal.identity().is_err(), "error closes journal");
        owner.close();
        assert_eq!(super::super::super::journal(&c.f), before);
        assert_eq!(inspect(&c).expect("no local target"), None);
    }
}
fn applied_pending() -> (Case, RProposal, JournalSnapshot) {
    let c = case(true);
    let p = prepared(&c);
    let saved = journal(&c.f);
    witness_prepare(&c, p);
    exchange(&c, p, crate::AnchorOperation::commit_roster_refresh(&p))
        .expect("original witness commit");
    (c, p, saved)
}
#[test]
fn roster_journal_sync_faults_keep_original_target_and_intent_at_every_boundary() {
    use crate::durable::tests::{
        assert_sync_failure, fault_database_path, fault_existing_journal, observe_bound_preparation,
    };
    let c = case(true);
    let _before = super::super::super::journal(&c.f);
    let mut owner = active(&c);
    let journal = owner.parts().expect("owners").0.stores().expect("stores").0;
    let (_, count) = fault_existing_journal(journal, c.f.c.paths.installation.files()[1], false);
    let committed = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&committed);
    let counter = Arc::clone(&count);
    observe_bound_preparation(move || seen.store(counter.load(Ordering::SeqCst), Ordering::SeqCst));
    journal
        .prepare_roster_refresh(
            RosterRefreshId::generate().expect("ID"),
            &materials(&c),
            150,
        )
        .expect("calibrate reservation");
    let commit_barriers = committed.load(Ordering::SeqCst);
    let total_barriers = count.load(Ordering::SeqCst);
    assert!(commit_barriers > 0 && commit_barriers <= total_barriers && total_barriers <= 16);
    owner.close();
    let (mut prep_faults, mut close_faults, mut apply_faults) = (0, 0, 0);
    for after in [false, true] {
        for cut in 1..=total_barriers {
            let c = case(true);
            let before = super::super::super::journal(&c.f);
            let mut owner = active(&c);
            let journal = owner.parts().expect("owners").0.stores().expect("stores").0;
            let (remaining, _) =
                fault_existing_journal(journal, c.f.c.paths.installation.files()[1], after);
            remaining.store(cut, Ordering::SeqCst);
            let operation = RosterRefreshId::generate().expect("original ID");
            let result = journal.prepare_roster_refresh(operation, &materials(&c), 150);
            assert!(journal.identity().is_err());
            owner.close();
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            let returned = if cut <= commit_barriers {
                assert_sync_failure(result, after);
                prep_faults += 1;
                None
            } else {
                close_faults += 1;
                Some(result.expect("durable reservation survives later Drop housekeeping error"))
            };
            assert_eq!(super::super::super::journal(&c.f).0, before.0);
            let p = match inspect(&c).expect("reopen original preparation") {
                Some(p) => {
                    if let Some(returned) = returned {
                        assert_eq!(p, returned);
                    }
                    p
                }
                None => {
                    assert!(returned.is_none());
                    let mut owner = active(&c);
                    let p = owner
                        .parts()
                        .expect("owners")
                        .0
                        .stores()
                        .expect("stores")
                        .0
                        .prepare_roster_refresh(operation, &materials(&c), 150)
                        .expect("unsent absence can reserve original operation");
                    owner.close();
                    p
                }
            };
            assert_eq!(p.scope().operation, operation);
            let saved = super::super::super::journal(&c.f);
            assert_eq!(inspect(&c).expect("exact retained descriptor"), Some(p));
            assert_eq!(super::super::super::journal(&c.f), saved);
            witness_prepare(&c, p);
            exchange(&c, p, crate::AnchorOperation::commit_roster_refresh(&p))
                .expect("exact original witness commit");
            c.f.carrier.clock.store(401, Ordering::SeqCst);
            c.policy.close();
            assert_eq!(
                recover(&c, p).expect("expired original recovery"),
                RState::Applied
            );
            assert_eq!(
                super::super::super::journal(&c.f),
                (target_image(&saved), saved.1)
            );
        }
    }
    let (c, p, _) = applied_pending();
    let (db, _, count, _) = fault_database_path(c.f.c.paths.installation.files()[1], false);
    let mut owner = open(&c.f.c);
    let key = owner.key().expect("key");
    let mut client = policy_client(&c.f, &mut owner);
    DeviceJournal::recover_roster_refresh_in_database(
        &db,
        &key,
        &c.f.original,
        c.f.c.policy.historical(),
        c.f.id,
        p,
        &mut client,
    )
    .expect("calibrate actual target installation");
    let barriers = count.load(Ordering::SeqCst);
    assert!((1..=16).contains(&barriers));
    drop(db);
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let (c, p, saved) = applied_pending();
            let (db, remaining, _, _) =
                fault_database_path(c.f.c.paths.installation.files()[1], after);
            remaining.store(cut, Ordering::SeqCst);
            let mut owner = open(&c.f.c);
            let key = owner.key().expect("key");
            let mut client = policy_client(&c.f, &mut owner);
            assert_sync_failure(
                DeviceJournal::recover_roster_refresh_in_database(
                    &db,
                    &key,
                    &c.f.original,
                    c.f.c.policy.historical(),
                    c.f.id,
                    p,
                    &mut client,
                ),
                after,
            );
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            drop(db);
            owner.close();
            let observed = super::super::super::journal(&c.f);
            assert_eq!(observed.1, saved.1);
            assert!(observed.0 == saved.0 || observed.0 == target_image(&saved));
            c.f.carrier.clock.store(401, Ordering::SeqCst);
            c.policy.close();
            assert_eq!(
                recover(&c, p).expect("same original after unknown installation"),
                RState::Applied
            );
            assert_eq!(
                super::super::super::journal(&c.f),
                (target_image(&saved), saved.1)
            );
            apply_faults += 1;
        }
    }
    eprintln!("ROSTER_JOURNAL_SYNC prepare_faults={prep_faults} post_commit_close_faults={close_faults} apply_faults={apply_faults} exact_target=true retained_pending=true no_reseal=true");
}

#[test]
fn a_fresh_root_roster_can_be_prepared_from_the_actual_expired_predecessor() {
    let mut c = case(true);
    let mut owner = open(&c.f.c);
    let certificate = match owner.image().expect("original enrollment").phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("accepted"),
    }
    .expect("original certificate");
    owner.close();
    let issue = |version, until| {
        let roster =
            c.f.c
                .root
                .issue_roster(
                    version,
                    Validity::new(100, until).expect("root interval"),
                    &[c.f.c.root.roster_entry(&certificate).expect("same C0")],
                )
                .expect("independent roster");
        AccountPin::new(
            c.f.original.account_id(),
            c.f.c.intent.root.clone(),
            roster.checkpoint(),
            c.policy.family(),
        )
        .expect("root pin")
        .verify_device(&certificate, roster.as_bytes(), 150)
        .expect("verified root snapshot")
    };
    let previous = issue(2, 152);
    let next = issue(3, 200);
    let mut owner = active(&c);
    owner
        .parts()
        .expect("owners")
        .0
        .stores()
        .expect("stores")
        .0
        .install_roster(previous.roster(), 150)
        .expect("actual R2, before its expiry");
    owner.close();
    let subject =
        crate::AnchorSubject::for_device(c.f.id, &c.f.original, c.f.c.policy.historical())
            .expect("original subject");
    c.f.carrier
        .store
        .lock()
        .expect("witness")
        .update_roster_authority(
            subject,
            c.previous.roster().checkpoint(),
            &previous,
            &c.policy,
            150,
        )
        .expect("complete existing standalone R2 before entering atomic-R format");
    c.f.carrier.clock.store(155, Ordering::SeqCst);
    assert!(
        activate(&c.f, &c.policy, 155).is_err(),
        "expired actual R2 does not release an owner"
    );
    c.previous = previous;
    c.target = next;
    let mut owner = open(&c.f.c);
    let image = owner.image().expect("durable original P completion");
    let completion = owner
        .policy_enrollment_completion(&image, c.f.c.policy.historical())
        .expect("historical completion")
        .expect("P1");
    let client = policy_client(&c.f, &mut owner);
    let mut journal = DeviceJournal::open_anchored_retained(
        c.f.c.paths.installation.files()[1],
        owner.key().expect("key"),
        &c.f.original,
        c.f.c.policy.historical(),
        c.f.id,
        client,
    )
    .expect("metadata owner without live old roster");
    journal
        .retain_enrollment_policy_completion(completion)
        .expect("original P completion only");
    let p = journal
        .prepare_roster_refresh(
            RosterRefreshId::generate().expect("R3 operation"),
            &materials(&c),
            155,
        )
        .expect("root-approved fresh target from actual expired R2");
    owner.close();
    assert_eq!(p.scope().previous, c.previous.roster().checkpoint());
    assert_eq!(p.scope().target, c.target.roster().checkpoint());
    c.f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_roster_refresh(p, &c.previous, &c.target, &c.policy, 155)
        .expect("witness admits exact fresh target, not expired predecessor");
    assert_eq!(
        exchange(&c, p, crate::AnchorOperation::commit_roster_refresh(&p)).expect("atomic R3"),
        RState::Applied
    );
    assert_eq!(recover(&c, p).expect("same R3 target"), RState::Applied);
    assert!(
        super::super::super::journal(&c.f).1.is_some(),
        "enrollment still must own terminal and ACK"
    );
}

#[path = "witness_roster_enrollment_tests.rs"]
mod enrollment;
