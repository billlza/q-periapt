// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_client_next_mac_valid_parent_history_tamper_rejects() {
    for changed in ["prefix", "signature", "checkpoint"] {
        let mut s = Scenario::new(Work::Policy(2), true);
        let next = Next::new(&mut s, "next-target", 211, 186);
        let transition = TransferredAccountRootJournalTransition::verify(
            s.t.plan(),
            fresh_plan(&s, &next),
            &s.closed,
        )
        .expect("approved next");
        let mut owner = open(&s, &transition).expect("exact next fences");
        let o = owner.active.as_ref().expect("restricted owner");
        let active = o.enrollment.active.as_ref().expect("parent lease");
        let mut state = o.state.clone();
        match changed {
            "prefix" => state.attempts = crate::durable::root_attempts::Attempts::default(),
            "checkpoint" => state.child.as_mut().expect("bound child")[0] ^= 1,
            "signature" => {
                let mut bytes = Vec::new();
                state
                    .attempts
                    .encode(&mut bytes)
                    .expect("exact attempt prefix");
                *bytes.last_mut().expect("signed closure") ^= 1;
                state.attempts =
                    crate::durable::root_attempts::Attempts::decode(&mut Decoder::new(&bytes))
                        .expect("untrusted signature remains syntactically valid");
            }
            _ => unreachable!(),
        }
        let damaged = state
            .encode(&active.key, o.enrollment.binding)
            .expect("valid storage MAC is not protocol approval");
        owner.close();
        let backup = fs::read(&s.t.f.original.paths.configuration).expect("exact owned parent");
        let db = open_private_database(&s.t.f.original.paths.configuration)
            .expect("owned fixture database");
        let tx = transaction(&db).expect("transaction");
        tx.open_table(TABLE)
            .expect("table")
            .insert(ROW, damaged.as_slice())
            .expect("deliberate corruption");
        tx.commit().expect("committed damaged parent");
        drop(db);
        assert!(
            open(&s, &transition).is_err(),
            "MAC-valid {changed} must not be accepted"
        );
        fs::write(&s.t.f.original.paths.configuration, backup).expect("restore exact parent");
        open(&s, &transition).expect("original exact retry").close();
    }
}

#[test]
fn transferred_client_next_child_sync_faults_preserve_exact_original_intent() {
    let mut s = Scenario::new(Work::Cancellation(true), true);
    let next = Next::new(&mut s, "next-target", 211, 186);
    let transition = TransferredAccountRootJournalTransition::verify(
        s.t.plan(),
        fresh_plan(&s, &next),
        &s.closed,
    )
    .expect("next approved transition");
    let path = s.t.f.original.paths.installation.files()[1];
    let child = fs::read(path).expect("original journal");
    let rows = journal_rows(&s.t);
    let identity =
        JournalIdentity::from_trusted_state(s.t.f.original.genesis.subject().journal_parts().0)
            .expect("original journal ID");
    let apply = |after, cut| {
        let prepared = AccountRootJournalRecovery::prepare_transferred_transition(
            path,
            JournalKey::open(&s.t.f.original.paths.wrapping).expect("same key"),
            &s.t.f.original.device,
            identity,
            &transition,
        )
        .expect("same child preflight");
        let (prepared, remaining, count) = prepared.fault_sync(path, after);
        count.store(0, Ordering::SeqCst);
        remaining.store(cut, Ordering::SeqCst);
        (prepared.commit(), count)
    };
    let (owner, count) = apply(false, usize::MAX);
    let mut owner = owner.expect("calibrate child commit");
    let barriers = count.load(Ordering::SeqCst);
    owner.close();
    let close_syncs = count.load(Ordering::SeqCst) - barriers;
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(path, &child).expect("restore exact original child");
            let (result, _) = apply(after, cut);
            crate::durable::tests::assert_sync_failure(result.map(|_| ()), after);
            AccountRootJournalRecovery::resume_transferred_transition(
                path,
                JournalKey::open(&s.t.f.original.paths.wrapping).expect("same key"),
                &s.t.f.original.device,
                identity,
                &transition,
            )
            .expect("same exact child retry")
            .close();
            assert!(journal_rows(&s.t) == rows);
        }
    }
    eprintln!("TRANSFERRED_CLIENT_NEXT_CHILD_SYNC barriers={barriers} close_syncs={close_syncs} faults={}", 2 * barriers);
}

#[test]
fn transferred_client_next_joint_backups_and_mac_valid_child_closure_tamper_refuse() {
    let mut s = Scenario::new(Work::Policy(1), true);
    let old_parent = fs::read(&s.t.f.original.paths.configuration).expect("old parent");
    let old_child = fs::read(s.t.f.original.paths.installation.files()[1]).expect("old child");
    let next = Next::new(&mut s, "next-target", 211, 186);
    let transition = TransferredAccountRootJournalTransition::verify(
        s.t.plan(),
        fresh_plan(&s, &next),
        &s.closed,
    )
    .expect("next transition");
    open(&s, &transition).expect("parent then child").close();
    let parent_path = &s.t.f.original.paths.configuration;
    let child_path = s.t.f.original.paths.installation.files()[1];
    let parent = fs::read(parent_path).expect("new parent");
    let child = fs::read(child_path).expect("new child");
    fs::write(parent_path, old_parent).expect("owned old parent backup");
    assert!(
        open(&s, &transition).is_err(),
        "child cannot precede independent parent publication"
    );
    fs::write(parent_path, &parent).expect("restore new parent");
    fs::write(child_path, old_child).expect("owned exact earlier child");
    open(&s, &transition)
        .expect("retained next parent repairs exact old child")
        .close();
    let db = open_private_database(child_path).expect("original child");
    let tx = transaction(&db).expect("transaction");
    {
        let mut table = tx.open_table(JOURNAL).expect("journal table");
        let wire = table
            .get("account-root-fence")
            .expect("get")
            .expect("fence")
            .value()
            .to_vec();
        let positions = wire
            .windows(s.closed.len())
            .enumerate()
            .filter_map(|(i, w)| (w == s.closed).then_some(i))
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 1);
        let mut body = wire.get(..wire.len() - 32).expect("bounded body").to_vec();
        *body
            .get_mut(*positions.first().expect("one closure") + s.closed.len() - 1)
            .expect("signature byte") ^= 1;
        let key = JournalKey::open(&s.t.f.original.paths.wrapping).expect("same owned key");
        let damaged = crate::durable::tests::authenticate_account_root_fence(&key, &body);
        table
            .insert("account-root-fence", damaged.as_slice())
            .expect("deliberate valid-MAC damage");
    }
    tx.commit().expect("commit damaged fixture");
    drop(db);
    assert!(
        open(&s, &transition).is_err(),
        "MAC-valid signed-prefix tamper cannot replace host trust"
    );
    fs::write(child_path, child).expect("restore exact child");
    open(&s, &transition).expect("original exact retry").close();
}

#[test]
fn transferred_client_next_parent_sync_faults_reconcile_exact_selected_attempt() {
    let mut s = Scenario::new(Work::Credential(1), true);
    let next = Next::new(&mut s, "next-target", 211, 186);
    let transition = TransferredAccountRootJournalTransition::verify(
        s.t.plan(),
        fresh_plan(&s, &next),
        &s.closed,
    )
    .expect("next approved transition");
    let parent = fs::read(&s.t.f.original.paths.configuration).expect("quiescent original parent");
    let child =
        fs::read(s.t.f.original.paths.installation.files()[1]).expect("quiescent original child");
    let rows = journal_rows(&s.t);
    let apply = |after, cut| {
        let mut enrollment = DeviceEnrollment::open_original_storage(
            s.t.f.original.paths.clone(),
            s.t.f.original.intent.clone(),
        )
        .expect("original signer-free parent");
        let (remaining, count) = fault_parent(&mut enrollment, after);
        count.store(0, Ordering::SeqCst);
        remaining.store(cut, Ordering::SeqCst);
        let result =
            AccountRootEnrollmentRecovery::prepare_transferred_transition(enrollment, &transition);
        (result, count)
    };
    let (owner, count) = apply(false, usize::MAX);
    let mut owner = owner.expect("calibrate actual parent commit");
    let barriers = count.load(Ordering::SeqCst);
    owner.close();
    let close_syncs = count.load(Ordering::SeqCst) - barriers;
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(&s.t.f.original.paths.configuration, &parent)
                .expect("restore original parent");
            fs::write(s.t.f.original.paths.installation.files()[1], &child)
                .expect("restore original child");
            let (result, _) = apply(after, cut);
            crate::durable::tests::assert_sync_failure(result.map(|_| ()), after);
            let mut owner =
                open(&s, &transition).expect("same next attempt after uncertain commit");
            assert_eq!(
                owner.status().expect("same restricted next"),
                AccountRootEnrollmentState::IntentRetained
            );
            owner.close();
            assert!(journal_rows(&s.t) == rows);
        }
    }
    eprintln!("TRANSFERRED_CLIENT_NEXT_PARENT_SYNC barriers={barriers} close_syncs={close_syncs} faults={}", 2 * barriers);
}
