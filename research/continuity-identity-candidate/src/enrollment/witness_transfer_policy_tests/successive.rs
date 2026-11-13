// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{EnrolledDevice, LeafKind, PrekeyId, WitnessJournalAdoptionState};
#[path = "successive/process.rs"]
mod process;
#[path = "successive/sync.rs"]
mod sync;
#[path = "successive/validation.rs"]
mod validation;

fn retained_prekey() -> PrekeyId {
    PrekeyId::from_trusted_state([94; 32]).expect("original secret prekey identity")
}
fn original_with_prekey() -> Fixture {
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
        .expect("original operating witness");
    let mut active = owner
        .activate(&f.c.policy, 150, Some(client))
        .expect("original operational installation");
    let (service, _, device) = active.parts().expect("original owners");
    let journal = service.stores().expect("original children").0;
    let leaf = journal
        .generate_prekey(
            &f.c.policy,
            device,
            retained_prekey(),
            LeafKind::OneTimePq,
            Validity::new(150, 160).expect("original credential interval"),
            150,
        )
        .expect("generate and persist a real secret PQ prekey before P");
    fs::write(
        f.c.paths
            .configuration
            .parent()
            .expect("owned root")
            .join("retained-prekey-public"),
        leaf.public_key(),
    )
    .expect("independent public comparison");
    assert_eq!(
        journal
            .prekey_leaf(&f.c.policy, device, retained_prekey(), 150)
            .expect("actually available before P")
            .public_key(),
        leaf.public_key()
    );
    fs::write(
        f.c.paths
            .configuration
            .parent()
            .expect("owned root")
            .join("retained-prekey-digest"),
        journal.test_retained_prekey_digest(retained_prekey()),
    )
    .expect("retain only a comparison digest");
    active.close();
    f
}
fn check_retained_prekey(
    f: &Fixture,
    active: &mut EnrolledDevice,
    policy: &VerifiedSessionPolicy,
    now: u64,
) {
    let expected = fs::read(
        f.c.paths
            .configuration
            .parent()
            .expect("owned root")
            .join("retained-prekey-digest"),
    )
    .expect("independent full original prekey record digest");
    let (service, _, device) = active.parts().expect("recovered owners");
    let journal = service.stores().expect("original children").0;
    assert_eq!(journal.identity().expect("same journal"), f.id);
    assert_eq!(
        journal
            .test_retained_prekey_digest(retained_prekey())
            .as_slice(),
        expected
    );
    // P adoption preserves the old sealed record, not permission to republish
    // through the ordinary original-policy inventory API under either P0 or P1.
    assert!(matches!(
        journal.prekey_leaf(policy, device, retained_prekey(), now),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        journal.prekey_leaf(&f.c.policy, device, retained_prekey(), now),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        journal
            .test_retained_prekey_digest(retained_prekey())
            .as_slice(),
        expected
    );
}
fn pending_case() -> (Fixture, Approval, PolicyProposal) {
    let f = original_with_prekey();
    let a = approval(&f);
    stage(&f, &a);
    let p = prepare(&f, &a);
    approve_witness(&f, &a, p);
    (f, a, p)
}
fn first_transfer(f: &Fixture) -> Transfer {
    let subject =
        AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
    let first = Transfer::new(
        &mut f.carrier.store.lock().expect("A"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        151,
    );
    first.adopt_parent(&f.c, 152).close();
    first
}
fn next_transfer(f: &Fixture, source: &Transfer, now: u64, id: u8) -> Transfer {
    let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("same subject");
    Transfer::with_decision(
        &mut source.target.lock().expect("current source"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        (now, id),
    )
}
fn complete_original(
    f: &Fixture,
    a: &Approval,
    p: PolicyProposal,
    before: &(Vec<u8>, Option<Vec<u8>>),
    transfer: &Transfer,
    now: u64,
) {
    let mut owner = open(&f.c);
    let mut client = transfer.client(&mut owner, &f.c);
    assert_eq!(
        owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                now,
                &mut client
            )
            .expect("exact original P completion"),
        State::Applied
    );
    owner.close();
    assert_eq!(journal(f), (target(before), None));
    let mut owner = open(&f.c);
    let client = transfer.client(&mut owner, &f.c);
    let mut active = owner
        .activate_witnessed_policy_renewal(f.c.policy.historical(), &a.target, now, client)
        .expect("release same installation");
    check_retained_prekey(f, &mut active, &a.target, now);
    active.close();
}

#[test]
fn enrollment_witness_successive_selection_finishes_original_p_without_resealing() {
    for progress in [0, 1, 2] {
        let f = original_with_prekey();
        let a = approval(&f);
        stage(&f, &a);
        let p = prepare(&f, &a);
        approve_witness(&f, &a, p);
        let sealed = journal(&f);
        let signer = fs::read(&f.c.paths.signer).expect("original protected signer");
        let key = fs::read(&f.c.paths.wrapping).expect("original storage key");
        let subject =
            AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
        if progress > 0 {
            let mut owner = open(&f.c);
            let mut client = policy_client(&f, &mut owner);
            assert_eq!(
                client
                    .exchange(subject, AnchorOperation::commit_policy_renewal(&p))
                    .expect("source applies original P")
                    .policy_renewal_state(&p)
                    .expect("same operation"),
                State::Applied
            );
            if progress == 2 {
                assert_eq!(
                    DeviceJournal::recover_policy_renewal(
                        f.c.paths.installation.files()[1],
                        JournalKey::open(&f.c.paths.wrapping).expect("same key"),
                        &f.original,
                        f.c.policy.historical(),
                        f.id,
                        p,
                        &mut client,
                    )
                    .expect("original sealed target installed with pending retained"),
                    State::Applied
                );
            }
            owner.close();
        }
        let before = journal(&f);
        let current_policy = if progress > 0 {
            a.target.historical()
        } else {
            f.c.policy.historical()
        };
        let first = Transfer::new(
            &mut f.carrier.store.lock().expect("A source"),
            &f.c,
            &f.original,
            &f.original,
            current_policy,
            subject,
            151,
        );
        first.adopt_parent(&f.c, 152).close();
        assert_eq!(journal(&f), before);
        let mut second = Transfer::with_decision(
            &mut first.target.lock().expect("real B source"),
            &f.c,
            &f.original,
            &f.original,
            current_policy,
            subject,
            (154, 78),
        );
        second.plan = second
            .plan
            .clone()
            .continue_from(&first.plan, &first.control)
            .expect("explicit independently retained adopted predecessor");
        second.set_time(156);
        let mut owner = open(&f.c);
        owner
            .prepare_witness_handoff(f.c.policy.historical(), second.plan.clone(), || Ok(155))
            .expect("second preparation must retain the original selected journal");
        owner
            .adopt_witness_handoff(
                f.c.policy.historical(),
                second.plan.clone(),
                &second.receipt,
            )
            .expect("same parent and child adopt C");
        assert_eq!(
            journal(&f),
            before,
            "second selection cannot reseal or clear pending work"
        );
        owner.close();
        let mut owner = open(&f.c);
        assert_eq!(
            owner
                .witness_handoff_status(f.c.policy.historical(), second.plan.clone())
                .expect("cold second selection"),
            WitnessJournalAdoptionState::Adopted
        );
        let mut client = second.client(&mut owner, &f.c);
        assert_eq!(
            owner
                .commit_witnessed_policy_renewal(
                    &p,
                    f.c.policy.historical(),
                    &a.target,
                    156,
                    &mut client
                )
                .expect("same original P and parent terminal/ACK through C"),
            State::Applied
        );
        owner.close();
        assert_eq!(journal(&f), (target(&sealed), None));
        let mut owner = open(&f.c);
        let client = second.client(&mut owner, &f.c);
        let mut active = owner
            .activate_witnessed_policy_renewal(f.c.policy.historical(), &a.target, 156, client)
            .expect("original installation releases under new policy and current witness");
        check_retained_prekey(&f, &mut active, &a.target, 156);
        active.close();
        assert_eq!(
            fs::read(&f.c.paths.signer).expect("retained signer"),
            signer
        );
        assert_eq!(fs::read(&f.c.paths.wrapping).expect("retained key"), key);
    }
}

#[test]
fn enrollment_witness_successive_selection_reaches_eight_with_original_pending_p() {
    let (f, a, p) = pending_case();
    let before = journal(&f);
    let signer = fs::read(&f.c.paths.signer).expect("original signer");
    let key = fs::read(&f.c.paths.wrapping).expect("original key");
    let mut transfers = vec![first_transfer(&f)];
    for hop in 2u8..=8 {
        // The original fixture credential expires at160. Keep this capacity
        // exercise inside its admission interval; expiry refusal is checked below.
        let now = 151 + u64::from(hop - 1);
        let previous = transfers.last().expect("selected predecessor");
        let mut next = next_transfer(&f, previous, now, 75 + hop);
        next.plan = next
            .plan
            .clone()
            .continue_from(&previous.plan, &previous.control)
            .expect("strict complete-history successor");
        next.set_time(now + 1);
        next.adopt_parent(&f.c, now + 1).close();
        assert_eq!(journal(&f), before, "hop {hop} cannot alter original P");
        next.reopen_target();
        let mut owner = open(&f.c);
        let mut client = next.client(&mut owner, &f.c);
        let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy)
            .expect("same logical subject");
        assert_eq!(
            client
                .exchange(subject, AnchorOperation::policy_renewal_status(&p))
                .expect("current witness over actual TCP")
                .policy_renewal_state(&p)
                .expect("same original operation"),
            State::Prepared
        );
        owner.close();
        transfers.push(next);
    }
    let last = transfers.last().expect("eighth adopted target");
    let wire = {
        let db =
            open_private_database(f.c.paths.installation.files()[1]).expect("original journal");
        let read = db.begin_read().expect("read");
        let table = read
            .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                "continuity_device_candidate_v21",
            ))
            .expect("original table");
        let row = table
            .get("witness-handoff")
            .expect("lookup")
            .expect("same current row");
        row.value().to_vec()
    };
    assert!(wire.starts_with(b"QPWJAH02"));
    assert!(wire.len() > 16 * 1024 && wire.len() <= 8 * 16 * 1024);
    assert!(
        last.plan
            .clone()
            .continue_from(&last.plan, &last.control)
            .is_err(),
        "cannot rebase an existing chain"
    );
    complete_original(&f, &a, p, &before, last, 159);
    last.set_time(174);
    let mut expired = open(&f.c);
    let client = last.client(&mut expired, &f.c);
    assert!(
        matches!(
            expired.activate_witnessed_policy_renewal(
                f.c.policy.historical(),
                &a.target,
                174,
                client
            ),
            Err(DurableError::Protocol(Error::Validity))
        ),
        "eight historical selections cannot extend the original credential"
    );
    // Activation consumes the owner even when admission fails. Historical
    // selection remains observable without granting a running installation.
    let mut retained = open(&f.c);
    assert_eq!(
        retained
            .witness_handoff_status(f.c.policy.historical(), last.plan.clone())
            .expect("historical selection after expiry"),
        WitnessJournalAdoptionState::Adopted
    );
    retained.close();
    assert_eq!(journal(&f), (target(&before), None));
    assert_eq!(fs::read(&f.c.paths.signer).expect("same signer"), signer);
    assert_eq!(fs::read(&f.c.paths.wrapping).expect("same key"), key);
    eprintln!(
        "SUCCESSIVE_CLIENT_EIGHT metadata_bytes={} original_p_completed=true",
        wire.len()
    );
}

#[test]
fn enrollment_witness_successive_selection_can_skip_unselected_intermediate_witness() {
    let (f, a, p) = pending_case();
    let before = journal(&f);
    let first = first_transfer(&f);
    let middle = next_transfer(&f, &first, 154, 78);
    let mut last = next_transfer(&f, &middle, 157, 79);
    last.plan = last
        .plan
        .clone()
        .continue_from(&first.plan, &first.control)
        .expect("full verified history extends last locally selected B, not unselected C");
    last.set_time(159);
    last.adopt_parent(&f.c, 158).close();
    assert_eq!(journal(&f), before);
    let mut owner = open(&f.c);
    assert!(owner
        .witness_handoff_status(f.c.policy.historical(), middle.plan.clone())
        .is_err());
    complete_original(&f, &a, p, &before, &last, 159);
}
