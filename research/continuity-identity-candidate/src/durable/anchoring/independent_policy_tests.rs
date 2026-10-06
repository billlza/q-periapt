// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::credential_preparation::{disk, request_operation};
use super::*;
use crate::{
    AnchorPolicyRenewalProposal as Proposal, AnchorPolicyRenewalState as State,
    HistoricalSessionPolicy, PolicyRenewalId, PolicyRenewalMaterials, PolicyRenewalScope,
    PolicyRenewalStatement, RootSigningKey, VerifiedPolicyRenewal,
};

struct Approval {
    original: HistoricalSessionPolicy,
    target: VerifiedSessionPolicy,
    approved: VerifiedPolicyRenewal,
}
impl Approval {
    fn materials<'a>(&'a self, c: &'a Case) -> PolicyRenewalMaterials<'a> {
        PolicyRenewalMaterials {
            original: &self.original,
            previous: &self.original,
            target: &self.target,
            original_device: c.peer.initiator_device(),
            current_device: c.peer.initiator_device(),
        }
    }
}
fn approval(c: &Case) -> Approval {
    let (issuer, _, _, runtime) = crate::tests::session_policy_fixture_with_budget(
        &[PrekeyQuality::OneTimeBoth],
        AnchorRequirement::required(&c.pin),
        crate::ApplicationSendBudget::new(1024).expect("budget"),
    );
    let original = c
        .peer
        .initiator
        .current_policy()
        .expect("original policy")
        .historical()
        .clone();
    let issued = issuer
        .issue_session_policy(
            &runtime,
            crate::SessionPolicyParameters::new(
                2,
                crate::Validity::new(100, 300).expect("target validity"),
                crate::AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                AnchorRequirement::required(&c.pin),
                crate::ApplicationSendBudget::new(1024).expect("budget"),
            )
            .expect("parameters"),
        )
        .expect("target policy");
    let target = crate::PolicyPin::new(
        issuer.policy_family().expect("family"),
        issuer.public_key().expect("key"),
        issued.checkpoint(),
    )
    .expect("target pin")
    .verify(issued.as_bytes(), runtime, 150)
    .expect("target runtime");
    let device = c.peer.initiator_device();
    let scope = PolicyRenewalScope {
        operation: PolicyRenewalId::generate().expect("P ID"),
        journal: c.identity,
        original_owner: bootstrap::storage_owner(device),
        original_credential: device.credential_digest(),
        current_credential: device.credential_digest(),
        current_roster: device.roster().checkpoint(),
        original_policy: original.checkpoint(),
        previous_policy: original.checkpoint(),
        previous_authorization: None,
    };
    let materials = PolicyRenewalMaterials {
        original: &original,
        previous: &original,
        target: &target,
        original_device: device,
        current_device: device,
    };
    let request = PolicyRenewalStatement::new(&scope, &materials, 150).expect("exact P request");
    let account = RootSigningKey::deterministic([90; 32], [91; 32]).expect("original account root");
    let approved = VerifiedPolicyRenewal::verify(
        &account
            .approve_policy_renewal(&request)
            .expect("account approval"),
        &issuer
            .approve_policy_renewal(&request)
            .expect("policy approval"),
        &scope,
        &materials,
        150,
    )
    .expect("two verified approvals");
    Approval {
        original,
        target,
        approved,
    }
}
fn prepare(c: &mut Case, a: &Approval) -> Result<Proposal, DurableError> {
    let materials = PolicyRenewalMaterials {
        original: &a.original,
        previous: &a.original,
        target: &a.target,
        original_device: c.peer.initiator_device(),
        current_device: c.peer.initiator_device(),
    };
    c.journal
        .prepare_policy_renewal(&a.approved, &materials, 150)
}
fn inspect(c: &Case, a: &Approval) -> Result<Option<Proposal>, DurableError> {
    DeviceJournal::inspect_policy_renewal_preparation(
        &c.path.join("state.redb"),
        JournalKey::open(&c.path.join("key")).expect("original key"),
        c.peer.initiator_device(),
        &a.original,
        c.identity,
    )
}
fn recover(c: &Case, a: &Approval, p: Proposal) -> Result<State, DurableError> {
    DeviceJournal::recover_policy_renewal(
        &c.path.join("state.redb"),
        JournalKey::open(&c.path.join("key")).expect("original key"),
        c.peer.initiator_device(),
        &a.original,
        c.identity,
        p,
        &mut client(&c.pin, &c.server, true),
    )
}
fn witness_prepare(c: &Case, a: &Approval, p: Proposal) {
    assert_eq!(
        c.server
            .lock()
            .expect("witness")
            .store
            .prepare_policy_renewal(p, &a.approved, &a.materials(c), 150)
            .expect("independent witness preparation"),
        State::Prepared
    );
}
fn witness_command(c: &Case, p: Proposal, operation: AnchorOperation) -> State {
    client(&c.pin, &c.server, true)
        .exchange(c.subject, operation)
        .expect("fresh real witness result")
        .policy_renewal_state(&p)
        .expect("exact original P")
}
fn sealed_target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let intent = saved.1.as_ref().expect("retained intent");
    assert_eq!(intent.get(..8), Some(b"QPWINT06".as_slice()));
    intent
        .get(220..intent.len().checked_sub(32).expect("MAC"))
        .expect("sealed P target")
        .to_vec()
}
fn assert_only_status(c: &Case, p: Proposal, start: usize) {
    let s = c.server.lock().expect("server");
    assert!(s
        .requests
        .get(start..)
        .expect("new requests")
        .iter()
        .all(|wire| request_operation(wire) == AnchorOperation::policy_renewal_status(&p)));
}
#[test]
fn exact_sealed_policy_target_survives_restart_expiry_and_lost_commit_reply() {
    let mut c = case();
    let a = approval(&c);
    c.journal
        .generate_prekey(
            c.peer.initiator.current_policy().expect("P0"),
            c.peer.initiator_device(),
            crate::PrekeyId::from_trusted_state([11; 32]).expect("prekey ID"),
            crate::LeafKind::OneTimePq,
            crate::Validity::new(100, 190).expect("validity"),
            150,
        )
        .expect("real retained prekey");
    let before = c.journal.image().expect("original image");
    let p = prepare(&mut c, &a).expect("reserve exact P");
    assert!(c.journal.active.is_none());
    assert!(
        matches!(reopen(&c), Err(DurableError::Suspended)),
        "live original owner must not replay a P transaction"
    );
    let pending = disk(&c);
    let target = sealed_target(&pending);
    assert_eq!(image_hash(&pending.0), p.expected_head().digest());
    assert_eq!(image_hash(&target), p.target_head().digest());
    assert_eq!(inspect(&c, &a).expect("metadata"), Some(p));
    assert_eq!(
        recover(&c, &a, p).expect("not yet witness prepared"),
        State::Unavailable
    );
    assert_eq!(disk(&c), pending);
    witness_prepare(&c, &a, p);
    assert_eq!(
        recover(&c, &a, p).expect("prepared is not applied"),
        State::Prepared
    );
    assert_eq!(disk(&c), pending);
    {
        let mut s = c.server.lock().expect("server");
        s.fail = Some((s.requests.len() + 1, true));
    }
    assert!(client(&c.pin, &c.server, true)
        .exchange(c.subject, AnchorOperation::commit_policy_renewal(&p))
        .is_err());
    {
        let mut s = c.server.lock().expect("server");
        s.fail = None;
        s.now = 301;
    }
    a.target.close();
    c.peer.initiator.current_policy().expect("P0").close();
    let start = c.server.lock().expect("server").requests.len();
    assert_eq!(
        recover(&c, &a, p).expect("historical exact apply"),
        State::Applied
    );
    assert_only_status(&c, p, start);
    let after = disk(&c);
    assert_eq!(after.0, target);
    assert_eq!(after.1, pending.1, "original pending cannot be retired yet");
    assert_eq!(
        inspect(&c, &a).expect("same metadata after installation"),
        Some(p)
    );
    assert_eq!(
        recover(&c, &a, p).expect("idempotent original query"),
        State::Applied
    );
    assert_eq!(disk(&c), after);
    let key = JournalKey::open(&c.path.join("key")).expect("wrapping");
    let installed = unseal(
        &key,
        bootstrap::storage_owner(c.peer.initiator_device()),
        &after.0,
    )
    .expect("authenticated target");
    assert_eq!(
        (
            installed.id,
            installed.owner,
            installed.local_account,
            installed.protection,
            installed.next_fanout
        ),
        (
            before.id,
            before.owner,
            before.local_account,
            before.protection,
            before.next_fanout
        )
    );
    assert_eq!(installed.revision, before.revision + 1);
    let mut unchanged = 0;
    for (id, record) in &before.records {
        if record.kind != RecordKind::Roster {
            let actual = installed.records.get(id).expect("original retained record");
            assert!(actual.payload == record.payload, "retained payload changed");
            assert_eq!(actual.context, record.context);
            assert!(actual.keys == record.keys, "retained key metadata changed");
            assert!(
                actual.prekeys == record.prekeys,
                "retained prekey metadata changed"
            );
            unchanged += 1;
        }
    }
    assert_eq!(unchanged, 1);
    assert!(
        reopen(&c).is_err(),
        "historical application is not an operational owner"
    );
    assert!(
        super::credential_preparation::inspect(&c).is_err(),
        "P cannot become a G proposal"
    );
}
#[test]
fn closed_policy_target_keeps_original_image_and_pending_without_inventing_completion() {
    let mut c = case();
    let a = approval(&c);
    let p = prepare(&mut c, &a).expect("prepare");
    let before = disk(&c);
    witness_prepare(&c, &a, p);
    assert_eq!(
        witness_command(&c, p, AnchorOperation::close_policy_renewal(&p)),
        State::Closed
    );
    c.server.lock().expect("server").now = 301;
    a.target.close();
    let start = c.server.lock().expect("server").requests.len();
    assert_eq!(
        recover(&c, &a, p).expect("closed exact original"),
        State::Closed
    );
    assert_eq!(disk(&c), before);
    assert_only_status(&c, p, start);
    assert!(reopen(&c).is_err());
}
#[test]
fn missing_or_substituted_policy_evidence_preserves_pending_and_dispatch_scope() {
    for after in [false, true] {
        let mut c = case();
        let a = approval(&c);
        let p = prepare(&mut c, &a).expect("prepare");
        witness_prepare(&c, &a, p);
        assert_eq!(
            witness_command(&c, p, AnchorOperation::commit_policy_renewal(&p)),
            State::Applied
        );
        let before = disk(&c);
        {
            let mut s = c.server.lock().expect("server");
            s.fail = Some((s.requests.len() + 1, after));
        }
        assert!(recover(&c, &a, p).is_err());
        assert_eq!(disk(&c), before, "missing status cannot install target");
        c.server.lock().expect("server").fail = None;
        let mut bytes = p.to_bytes();
        *bytes.get_mut(8 + 32 + 96).expect("operation") ^= 1;
        let wrong = Proposal::from_trusted_state(&bytes).expect("different typed expectation");
        let calls = c.server.lock().expect("server").requests.len();
        assert!(recover(&c, &a, wrong).is_err());
        assert_eq!(
            calls,
            c.server.lock().expect("server").requests.len(),
            "wrong original rejected before dispatch"
        );
        assert_eq!(disk(&c), before);
        assert_eq!(
            recover(&c, &a, p).expect("exact original retry"),
            State::Applied
        );
        assert_eq!(disk(&c).0, sealed_target(&before));
        assert_eq!(disk(&c).1, before.1);
    }
}
#[test]
fn policy_preparation_never_relabels_an_existing_credential_intent() {
    let mut c = case();
    let a = approval(&c);
    let g = super::credential_preparation::grant(&c);
    let gp = super::credential_preparation::prepare(&mut c, &g).expect("real credential intent");
    let before = disk(&c);
    assert!(inspect(&c, &a).is_err());
    assert_eq!(
        super::credential_preparation::inspect(&c).expect("original G remains"),
        Some(gp)
    );
    assert_eq!(disk(&c), before);
}

fn fault_owner(
    c: &mut Case,
    after: bool,
) -> (
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let attached = c
        .journal
        .active
        .as_mut()
        .expect("original active journal")
        .anchor
        .take();
    c.journal.close();
    let (mut journal, remaining, count, _) =
        crate::durable::tests::fault_store(&c.path, c.peer.initiator_device(), after);
    journal
        .active
        .as_mut()
        .expect("same faulted original journal")
        .anchor = attached;
    c.journal = journal;
    (remaining, count)
}
#[test]
fn policy_journal_sync_failures_preserve_original_pending_and_exact_recovery_target() {
    use std::sync::atomic::Ordering;
    let mut calibration = case();
    let a = approval(&calibration);
    let (_, count) = fault_owner(&mut calibration, false);
    let persisted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let measured = Arc::clone(&persisted);
    let preparation_count = Arc::clone(&count);
    write_intent::tests::on_bound_preparation(move || {
        measured.store(preparation_count.load(Ordering::SeqCst), Ordering::SeqCst);
    });
    prepare(&mut calibration, &a).expect("calibrate prepare");
    let prepare_barriers = persisted.load(Ordering::SeqCst);
    let including_close = count.load(Ordering::SeqCst);
    assert!((1..=8).contains(&prepare_barriers));
    assert!(including_close > prepare_barriers && including_close <= 16);
    let mut prep_faults = 0;
    let mut close_faults = 0;
    for after in [false, true] {
        for cut in 1..=including_close {
            let mut c = case();
            let a = approval(&c);
            let original = c.journal.image().expect("original");
            let calls = c.server.lock().expect("server").requests.len();
            let (remaining, _) = fault_owner(&mut c, after);
            remaining.store(cut, Ordering::SeqCst);
            let result = prepare(&mut c, &a);
            let returned = if cut <= prepare_barriers {
                crate::durable::tests::assert_sync_failure(result, after);
                prep_faults += 1;
                None
            } else {
                // The intent transaction and readback already completed. These
                // are redb Drop housekeeping syncs, not another intent commit.
                // A successful public result must still name the exact durable
                // intent on a real reopen, despite this later close fault.
                close_faults += 1;
                Some(result.expect("earlier immediate commit remains durable"))
            };
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            assert!(c.journal.active.is_none());
            let disk_before = disk(&c);
            assert_eq!(
                image_hash(&disk_before.0),
                original.digest,
                "preparation must not change current image"
            );
            let observed = inspect(&c, &a).expect("authenticate retained metadata");
            if let Some(returned) = returned {
                assert_eq!(
                    observed,
                    Some(returned),
                    "returned proposal must already be durable"
                );
            }
            assert_eq!(disk(&c), disk_before);
            let server = c.server.lock().expect("server");
            assert!(server
                .requests
                .get(calls..)
                .expect("calls")
                .iter()
                .all(|wire| request_operation(wire) == AnchorOperation::query()));
            drop(server);
            if let Some(p) = observed {
                assert_eq!(p.operation(), a.approved.scope().operation);
                assert_eq!(p.statement(), a.approved.statement_digest());
                assert_eq!(p.expected_head().digest(), original.digest);
                assert_eq!(
                    p.target_head().digest(),
                    image_hash(&sealed_target(&disk_before))
                );
                assert_eq!(inspect(&c, &a).expect("exact original again"), Some(p));
                assert!(reopen(&c).is_err());
            } else {
                assert!(disk_before.1.is_none());
                assert!(reopen(&c).is_ok());
            }
        }
    }
    let mut c = case();
    let a = approval(&c);
    let p = prepare(&mut c, &a).expect("prepare");
    witness_prepare(&c, &a, p);
    witness_command(&c, p, AnchorOperation::commit_policy_renewal(&p));
    let (db, _, count, _) =
        crate::durable::tests::fault_database_path(&c.path.join("state.redb"), false);
    let key = JournalKey::open(&c.path.join("key")).expect("key");
    assert_eq!(
        write_intent::recover_policy_renewal(
            &db,
            &key,
            c.peer.initiator_device(),
            &a.original,
            c.identity,
            p,
            &mut client(&c.pin, &c.server, true)
        )
        .expect("calibrate actual apply"),
        State::Applied
    );
    let apply_barriers = count.load(Ordering::SeqCst);
    assert!((1..=8).contains(&apply_barriers));
    drop(db);
    let mut apply_faults = 0;
    for after in [false, true] {
        for cut in 1..=apply_barriers {
            let mut c = case();
            let a = approval(&c);
            let p = prepare(&mut c, &a).expect("prepare");
            let original = disk(&c);
            let target = sealed_target(&original);
            witness_prepare(&c, &a, p);
            witness_command(&c, p, AnchorOperation::commit_policy_renewal(&p));
            let (db, remaining, _, _) =
                crate::durable::tests::fault_database_path(&c.path.join("state.redb"), after);
            let key = JournalKey::open(&c.path.join("key")).expect("key");
            remaining.store(cut, Ordering::SeqCst);
            let result = write_intent::recover_policy_renewal(
                &db,
                &key,
                c.peer.initiator_device(),
                &a.original,
                c.identity,
                p,
                &mut client(&c.pin, &c.server, true),
            );
            crate::durable::tests::assert_sync_failure(result, after);
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            drop(db);
            let disk_after = disk(&c);
            assert!(disk_after.0 == original.0 || disk_after.0 == target);
            assert_eq!(disk_after.1, original.1);
            assert_eq!(
                recover(&c, &a, p).expect("fresh exact original retry"),
                State::Applied
            );
            assert_eq!(disk(&c), (target, original.1));
            apply_faults += 1;
        }
    }
    eprintln!("INDEPENDENT_POLICY_JOURNAL_SYNC prepare_faults={prep_faults} post_commit_close_faults={close_faults} apply_faults={apply_faults} exact_target=true original_pending=true no_reseal=true");
}
#[test]
fn matching_local_target_never_replaces_exact_witness_applied_evidence() {
    for closed in [false, true] {
        let mut c = case();
        let a = approval(&c);
        let p = prepare(&mut c, &a).expect("prepare");
        let original = disk(&c);
        let target = sealed_target(&original);
        witness_prepare(&c, &a, p);
        if closed {
            assert_eq!(
                witness_command(&c, p, AnchorOperation::close_policy_renewal(&p)),
                State::Closed
            );
        }
        // Fixture-only replay of an authentic target while the independent witness
        // has not applied it. This is not a recovery procedure.
        let db = open_private_database(&c.path.join("state.redb")).expect("fixture database");
        let tx = transaction(&db).expect("fixture transaction");
        {
            let mut table = tx.open_table(TABLE).expect("table");
            table
                .insert("image", target.as_slice())
                .expect("replay exact authenticated target");
        }
        tx.commit().expect("fixture durability");
        drop(db);
        assert!(matches!(recover(&c, &a, p), Err(DurableError::Conflict)));
        assert_eq!(disk(&c), (target, original.1));
        assert!(reopen(&c).is_err());
    }
}
