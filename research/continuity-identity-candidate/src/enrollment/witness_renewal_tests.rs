// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorCredentialRenewalProposal as Proposal, AnchorStore, CredentialRenewalStatus,
    DeviceJournal, Validity,
};
use std::{
    io,
    sync::{atomic::AtomicU64, Mutex},
    time::Instant,
};
#[path = "witness_policy_transaction_tests.rs"]
mod policy_transaction;
const JOURNAL: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_device_candidate_v21");
type ReplyHook = Option<(u8, Box<dyn FnOnce() + Send>)>;
#[derive(Clone)]
struct Carrier {
    store: Arc<Mutex<AnchorStore>>,
    clock: Arc<AtomicU64>,
    cut: Arc<Mutex<Option<(u8, bool)>>>,
    requests: Arc<Mutex<Vec<u8>>>,
    after_reply: Arc<Mutex<ReplyHook>>,
}
impl AnchorTransport for Carrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let opcode = *request
            .get(4 + 8 + 32 + 96 + 32 + 32)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.requests
            .lock()
            .map_err(|_| io::Error::other("request lock"))?
            .push(opcode);
        let cut = {
            let mut cut = self.cut.lock().map_err(|_| io::Error::other("cut lock"))?;
            if cut.is_some_and(|(op, _)| op == opcode) {
                cut.take()
            } else {
                None
            }
        };
        if cut == Some((opcode, false)) {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        let reply = self
            .store
            .lock()
            .map_err(|_| io::Error::other("store lock"))?
            .handle(request, self.clock.load(Ordering::SeqCst))
            .map_err(io::Error::other)?;
        let hook = {
            let mut hook = self
                .after_reply
                .lock()
                .map_err(|_| io::Error::other("reply hook lock"))?;
            if hook.as_ref().is_some_and(|(op, _)| *op == opcode) {
                hook.take()
            } else {
                None
            }
        };
        if let Some((_, hook)) = hook {
            hook();
        }
        if cut == Some((opcode, true)) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(reply)
    }
}
struct Fixture {
    _witness_dir: Arc<tempfile::TempDir>,
    c: Case,
    pin: AnchorPin,
    carrier: Carrier,
    original: VerifiedDevice,
    id: JournalIdentity,
}
fn client(f: &Fixture, owner: &mut DeviceEnrollment, at: u64) -> AnchorClient {
    owner
        .credential_renewal_anchor_client(
            &f.c.policy,
            at,
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("historical original client")
}
fn fixture() -> Fixture {
    fixture_with_policy_expiry(None)
}
fn fixture_with_policy_expiry(policy_until: Option<u64>) -> Fixture {
    let dir = directory();
    let root = dir.path().canonicalize().expect("witness directory");
    let store = AnchorStore::provision(
        &root.join("witness.redb"),
        JournalKey::provision(&root.join("witness.key")).expect("key"),
        crate::AnchorSigningKey::deterministic([226; 32], [227; 32]).expect("test signer"),
        crate::AnchorIdentity::generate().expect("id"),
    )
    .expect("store");
    let pin = store.pin().expect("pin");
    let carrier = Carrier {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(AtomicU64::new(150)),
        cut: Arc::new(Mutex::new(None)),
        requests: Arc::new(Mutex::new(Vec::new())),
        after_reply: Arc::new(Mutex::new(None)),
    };
    fixture_on_witness(Arc::new(dir), pin, carrier, policy_until)
}
fn fixture_on_witness(
    dir: Arc<tempfile::TempDir>,
    pin: AnchorPin,
    carrier: Carrier,
    policy_until: Option<u64>,
) -> Fixture {
    let mut c = case_with_anchor(crate::AnchorRequirement::required(&pin));
    if let Some(until) = policy_until {
        c.policy = super::policy_continuation::policy(&c, 1, until, 150);
    }
    c.intent.description.validity = Validity::new(100, 160).expect("C0");
    let (mut owner, _, id) = accepted(&c);
    let image = owner.image().expect("image");
    let original = owner.admitted(&image, &c.policy, 150).expect("original");
    let genesis = match owner.prepare(&c.policy, 150).expect("prepare") {
        InstallationPreparation::RequiresEnrollment(g) => Ok(g),
        _ => Err("required witness"),
    }
    .expect("genesis");
    carrier
        .store
        .lock()
        .expect("store")
        .enroll(&genesis, &original, &c.policy, 150)
        .expect("independent admission");
    let anchor = owner
        .anchor_client(
            &c.policy,
            150,
            pin.clone(),
            Box::new(carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("client");
    owner
        .activate(&c.policy, 150, Some(anchor))
        .expect("original active")
        .close();
    Fixture {
        _witness_dir: dir,
        c,
        pin,
        carrier,
        original,
        id,
    }
}
fn grant(
    f: &Fixture,
    previous: &VerifiedDevice,
    version: u64,
    until: u64,
) -> crate::VerifiedCredentialRenewal {
    renewal::grant(&f.c, &f.original, previous, version, until)
}
fn prepare(f: &Fixture, proof: &crate::VerifiedCredentialRenewal, at: u64) -> Proposal {
    f.carrier.clock.store(at, Ordering::SeqCst);
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .stage_credential_renewal(proof, proof.operation(), &f.c.policy, at)
            .expect("stage"),
        renewal::pending(proof)
    );
    let anchor = client(f, &mut owner, at);
    let proposal = owner
        .prepare_witnessed_credential_renewal(&f.c.policy, at, anchor)
        .expect("exact preparation");
    let anchor = client(f, &mut owner, at);
    assert_eq!(
        owner
            .prepare_witnessed_credential_renewal(&f.c.policy, at, anchor)
            .expect("retry exact"),
        proposal
    );
    f.carrier
        .store
        .lock()
        .expect("store")
        .prepare_credential_renewal(proposal, proof, &f.c.policy, at)
        .expect("independent approval");
    proposal
}

#[test]
fn witness_store_keeps_policy_t1_across_g2_ack_restart_and_policy_expiry() {
    use crate::{
        AnchorCredentialRenewalState as State, AnchorHead, AnchorOperation, AnchorOutcome,
        AnchorSubject, PolicyContinuationMaterials,
    };
    let f = fixture_with_policy_expiry(Some(160));
    let g1 = grant(&f, &f.original, 2, 180);
    let p1 = super::policy_continuation::policy(&f.c, 2, 190, 170);
    let scope = super::policy_continuation::scope(&f.c, &g1, f.id);
    let t1 = super::policy_continuation::joint(&f.c, &g1, &scope, &f.c.policy, &p1);
    let materials = PolicyContinuationMaterials {
        original: f.c.policy.historical(),
        previous: f.c.policy.historical(),
        target: &p1,
        credential: &g1,
    };
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    let subject =
        AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
    let mut exchange = |operation, now| {
        f.carrier.clock.store(now, Ordering::SeqCst);
        anchor
            .exchange(subject, operation)
            .expect("fresh signed witness observation")
    };
    let before = exchange(AnchorOperation::query(), 170).observed_head();
    // This is a witness-store component test with explicit opaque head
    // expectations. It does not qualify a sealed journal target or owner release.
    let target = AnchorHead::from_trusted_state(before.fence(), before.revision() + 1, [81; 32])
        .expect("store-only target");
    let first = Proposal::from_journal(
        f.pin.binding(),
        subject,
        g1.operation(),
        g1.statement_digest(),
        before,
        target,
    )
    .expect("G1 proposal")
    .with_policy_continuation(&t1)
    .expect("exact G1/T1 proposal");
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .prepare_policy_continuation(first, &t1, &materials, 170)
            .expect("independent dual approval"),
        State::Prepared
    );
    assert_eq!(
        exchange(AnchorOperation::commit_credential_renewal(&first), 170)
            .credential_renewal_state(&first)
            .expect("exact Apply"),
        State::Applied
    );
    assert_eq!(
        exchange(AnchorOperation::acknowledge_credential_renewal(&first), 170)
            .credential_renewal_state(&first)
            .expect("ACK"),
        State::Acknowledged
    );
    let g2 = grant(&f, g1.successor_device(), 3, 195);
    let target2 = AnchorHead::from_trusted_state(target.fence(), target.revision() + 1, [82; 32])
        .expect("second store-only target");
    let second = Proposal::from_journal(
        f.pin.binding(),
        subject,
        g2.operation(),
        g2.statement_digest(),
        target,
        target2,
    )
    .expect("G2 proposal")
    .with_retained_policy_continuation(&t1.historical())
    .expect("G2 preserves T1");
    assert!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .prepare_credential_renewal(second, &g2, &f.c.policy, 170)
            .is_err(),
        "P0 cannot authorize another write after T1"
    );
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .prepare_continued_credential_renewal(second, &g2, f.c.policy.historical(), &p1, 170)
            .expect("G2 under current T1/P1"),
        State::Prepared
    );
    assert_eq!(
        exchange(AnchorOperation::commit_credential_renewal(&second), 170)
            .credential_renewal_state(&second)
            .expect("G2 Apply"),
        State::Applied
    );
    assert_eq!(
        exchange(
            AnchorOperation::acknowledge_credential_renewal(&second),
            170
        )
        .credential_renewal_state(&second)
        .expect("G2 ACK"),
        State::Acknowledged
    );
    let advance = AnchorOperation::advance(target2, [83; 32]).expect("ordinary next head");
    let advanced = exchange(advance, 175)
        .applied_head()
        .expect("ordinary update retains T");
    {
        let mut store = f.carrier.store.lock().expect("store");
        store.close();
        let dir = f
            ._witness_dir
            .path()
            .canonicalize()
            .expect("original canonical witness path");
        *store = AnchorStore::open(
            &dir.join("witness.redb"),
            JournalKey::open(&dir.join("witness.key")).expect("original wrapping"),
            crate::AnchorSigningKey::deterministic([226; 32], [227; 32]).expect("original signer"),
            f.pin.identity(),
        )
        .expect("same independent witness storage");
    }
    let current = g2.successor_device().authority_binding();
    for (g, t, expected) in [
        (
            g2.statement_digest(),
            t1.statement_digest(),
            AnchorOutcome::AuthorityCurrent,
        ),
        (
            g1.statement_digest(),
            t1.statement_digest(),
            AnchorOutcome::AuthorityDenied,
        ),
        (
            g2.statement_digest(),
            g2.statement_digest(),
            AnchorOutcome::AuthorityDenied,
        ),
    ] {
        let op = AnchorOperation::admit_continuation(current, g, t).expect("exact admission");
        assert_eq!(op.to_bytes().len(), 97);
        assert_eq!(
            AnchorOperation::from_trusted_state(&op.to_bytes()).expect("canonical operation"),
            op
        );
        let reply = exchange(op, 175);
        assert_eq!(reply.observed_head(), advanced);
        assert_eq!(reply.outcome(), expected);
    }
    assert_eq!(
        exchange(
            AnchorOperation::admit_authority(current).expect("old account-only request"),
            175
        )
        .outcome(),
        AnchorOutcome::AuthorityDenied
    );
    // Closing T2 consumes both attempted versions, but does not adopt T2 or
    // erase T1. A distinct later G must still work under T1/P1.
    let p2 = super::policy_continuation::policy(&f.c, 3, 195, 170);
    let g3 = grant(&f, g2.successor_device(), 4, 199);
    let mut scope3 = super::policy_continuation::scope(&f.c, &g3, f.id);
    scope3.previous_policy = p1.checkpoint();
    scope3.previous_authorization = Some(t1.statement_digest());
    let t2 = super::policy_continuation::joint(&f.c, &g3, &scope3, &p1, &p2);
    let closed_target =
        AnchorHead::from_trusted_state(advanced.fence(), advanced.revision() + 1, [84; 32])
            .expect("closed target expectation");
    let third = Proposal::from_journal(
        f.pin.binding(),
        subject,
        g3.operation(),
        g3.statement_digest(),
        advanced,
        closed_target,
    )
    .expect("G3")
    .with_policy_continuation(&t2)
    .expect("T2");
    let second_policy = PolicyContinuationMaterials {
        original: f.c.policy.historical(),
        previous: p1.historical(),
        target: &p2,
        credential: &g3,
    };
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .prepare_policy_continuation(third, &t2, &second_policy, 175)
            .expect("T2 preparation"),
        State::Prepared
    );
    assert_eq!(
        exchange(AnchorOperation::close_credential_renewal(&third), 175)
            .credential_renewal_state(&third)
            .expect("close T2"),
        State::Closed
    );
    assert_eq!(
        exchange(AnchorOperation::acknowledge_credential_renewal(&third), 175)
            .credential_renewal_state(&third)
            .expect("ACK closed T2"),
        State::Acknowledged
    );
    assert!(
        matches!(
            f.carrier
                .store
                .lock()
                .expect("store")
                .prepare_policy_continuation(third, &t2, &second_policy, 175),
            Err(DurableError::Protocol(Error::Retired))
        ),
        "the original closed G3/T2 is retired, not a new attempt"
    );
    let g4 = grant(&f, g2.successor_device(), 5, 199);
    let next_head =
        AnchorHead::from_trusted_state(advanced.fence(), advanced.revision() + 1, [85; 32])
            .expect("later G-only target");
    let fourth = Proposal::from_journal(
        f.pin.binding(),
        subject,
        g4.operation(),
        g4.statement_digest(),
        advanced,
        next_head,
    )
    .expect("independent G4")
    .with_retained_policy_continuation(&t1.historical())
    .expect("still T1");
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .prepare_continued_credential_renewal(fourth, &g4, f.c.policy.historical(), &p1, 175)
            .expect("new G4 despite higher closed-policy floor"),
        State::Prepared
    );
    assert_eq!(
        exchange(AnchorOperation::commit_credential_renewal(&fourth), 175)
            .credential_renewal_state(&fourth)
            .expect("Apply G4"),
        State::Applied
    );
    assert_eq!(
        exchange(
            AnchorOperation::acknowledge_credential_renewal(&fourth),
            175
        )
        .credential_renewal_state(&fourth)
        .expect("ACK G4"),
        State::Acknowledged
    );
    let current = g4.successor_device().authority_binding();
    assert_eq!(
        exchange(
            AnchorOperation::admit_continuation(
                current,
                g4.statement_digest(),
                t1.statement_digest()
            )
            .expect("G4/T1 current"),
            175
        )
        .outcome(),
        AnchorOutcome::AuthorityCurrent
    );
    let g5 = grant(&f, g4.successor_device(), 6, 200);
    let mut scope5 = super::policy_continuation::scope(&f.c, &g5, f.id);
    scope5.previous_policy = p1.checkpoint();
    scope5.previous_authorization = Some(t1.statement_digest());
    let replayed_version = super::policy_continuation::joint(&f.c, &g5, &scope5, &p1, &p2);
    let fifth = Proposal::from_journal(
        f.pin.binding(),
        subject,
        g5.operation(),
        g5.statement_digest(),
        next_head,
        AnchorHead::from_trusted_state(next_head.fence(), next_head.revision() + 1, [86; 32])
            .expect("new target"),
    )
    .expect("new G5")
    .with_policy_continuation(&replayed_version)
    .expect("new valid approval of retired P2 version");
    let replayed_materials = PolicyContinuationMaterials {
        credential: &g5,
        ..second_policy
    };
    assert!(
        matches!(
            f.carrier
                .store
                .lock()
                .expect("store")
                .prepare_policy_continuation(fifth, &replayed_version, &replayed_materials, 175),
            Err(DurableError::Conflict)
        ),
        "a newer G cannot reset the independently retired policy version"
    );
    g4.successor_device()
        .roster()
        .authorize_device(g4.successor_device(), 191)
        .expect("latest credential remains live after P1 expiry");
    assert_eq!(
        exchange(
            AnchorOperation::admit_continuation(
                current,
                g4.statement_digest(),
                t1.statement_digest()
            )
            .expect("same current G4/T1"),
            191
        )
        .outcome(),
        AnchorOutcome::AuthorityDenied
    );
    assert_eq!(
        exchange(AnchorOperation::query(), 191).observed_head(),
        next_head,
        "historical observation does not extend T validity"
    );
}

#[test]
fn adopted_policy_roster_refresh_refuses_live_p0_and_preserves_p1_for_next_g() {
    use crate::{
        AnchorCredentialRenewalState as State, AnchorHead, AnchorOperation, AnchorSubject,
        PolicyContinuationMaterials,
    };
    let f = fixture_with_policy_expiry(Some(180));
    let g = grant(&f, &f.original, 2, 185);
    let p1 = super::policy_continuation::policy(&f.c, 2, 190, 170);
    let t = super::policy_continuation::joint(
        &f.c,
        &g,
        &super::policy_continuation::scope(&f.c, &g, f.id),
        &f.c.policy,
        &p1,
    );
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    let subject =
        AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
    f.carrier.clock.store(170, Ordering::SeqCst);
    let before = anchor
        .exchange(subject, AnchorOperation::query())
        .expect("observed head")
        .observed_head();
    let target = AnchorHead::from_trusted_state(before.fence(), before.revision() + 1, [84; 32])
        .expect("opaque component target");
    let proposal = Proposal::from_journal(
        f.pin.binding(),
        subject,
        g.operation(),
        g.statement_digest(),
        before,
        target,
    )
    .expect("original G")
    .with_policy_continuation(&t)
    .expect("exact T");
    let materials = PolicyContinuationMaterials {
        original: f.c.policy.historical(),
        previous: f.c.policy.historical(),
        target: &p1,
        credential: &g,
    };
    f.carrier
        .store
        .lock()
        .expect("store")
        .prepare_policy_continuation(proposal, &t, &materials, 170)
        .expect("prepare T1");
    assert_eq!(
        anchor
            .exchange(
                subject,
                AnchorOperation::commit_credential_renewal(&proposal)
            )
            .expect("Apply")
            .credential_renewal_state(&proposal)
            .expect("exact Apply"),
        State::Applied
    );
    anchor
        .exchange(
            subject,
            AnchorOperation::acknowledge_credential_renewal(&proposal),
        )
        .expect("ACK");
    let certificate =
        f.c.root
            .issue_device(
                g.successor_device().description.clone(),
                g.successor_device().key.clone(),
            )
            .expect("same C1");
    let roster =
        f.c.root
            .issue_roster(
                3,
                Validity::new(100, 200).expect("roster interval"),
                &[f.c.root.roster_entry(&certificate).expect("member")],
            )
            .expect("new R3");
    let pin = AccountPin::new(
        f.original.account_id(),
        f.c.root.public_key().expect("root"),
        roster.checkpoint(),
        f.c.policy.family(),
    )
    .expect("independent R3");
    let refreshed = pin
        .verify_device(&certificate, roster.as_bytes(), 170)
        .expect("current C1/R3");
    f.c.policy
        .check_device(&refreshed, 170)
        .expect("P0 is still individually live");
    assert!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .update_roster_authority(
                subject,
                g.successor_device().roster().checkpoint(),
                &refreshed,
                &f.c.policy,
                170
            )
            .is_err(),
        "superseded live P0 must not rewrite the adopted P1 validity"
    );
    f.carrier
        .store
        .lock()
        .expect("store")
        .update_roster_authority(
            subject,
            g.successor_device().roster().checkpoint(),
            &refreshed,
            &p1,
            170,
        )
        .expect("current P1 roster refresh");
    let g2 = grant(&f, &refreshed, 4, 195);
    let next = Proposal::from_journal(
        f.pin.binding(),
        subject,
        g2.operation(),
        g2.statement_digest(),
        target,
        AnchorHead::from_trusted_state(target.fence(), target.revision() + 1, [85; 32])
            .expect("next opaque target"),
    )
    .expect("next G")
    .with_retained_policy_continuation(&t.historical())
    .expect("retain T1");
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("store")
            .prepare_continued_credential_renewal(next, &g2, f.c.policy.historical(), &p1, 170)
            .expect("refreshed P1 predecessor remains valid"),
        State::Prepared
    );
}
fn disk(f: &Fixture) -> (Vec<u8>, Option<Vec<u8>>) {
    let db = open_private_database(f.c.paths.installation.files()[1]).expect("journal");
    let read = db.begin_read().expect("read");
    let table = read.open_table(JOURNAL).expect("table");
    let image = table
        .get("image")
        .expect("image")
        .expect("present")
        .value()
        .to_vec();
    let pending = table
        .get("pending")
        .expect("pending")
        .map(|v| v.value().to_vec());
    (image, pending)
}
fn activate(f: &Fixture, at: u64) -> Result<EnrolledDevice, DurableError> {
    let mut owner = open(&f.c);
    let anchor = client(f, &mut owner, at);
    owner.activate(&f.c.policy, at, Some(anchor))
}
fn historical(f: &Fixture) -> crate::HistoricalSessionPolicy {
    let (authority, issued, _, _) = crate::tests::session_policy_fixture_with_anchor(
        &[PrekeyQuality::OneTimeBoth],
        crate::AnchorRequirement::required(&f.pin),
    );
    assert_eq!(issued.checkpoint(), f.c.policy.checkpoint());
    crate::PolicyPin::new(
        f.c.policy.family(),
        authority.public_key().expect("independent root"),
        f.c.policy.checkpoint(),
    )
    .expect("exact independent pin")
    .verify_historical(issued.as_bytes())
    .expect("signed historical metadata")
}
#[test]
fn preparation_configuration_sync_failures_recover_exact_bytes_after_policy_expiry_without_dispatch(
) {
    let staged = || {
        let f = fixture();
        let proof = grant(&f, &f.original, 2, 190);
        open(&f.c)
            .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, 150)
            .expect("stage only");
        (f, proof)
    };
    let (f, _) = staged();
    let (mut owner, _, count) = faulty(&f.c, false);
    let anchor = client(&f, &mut owner, 150);
    count.store(0, Ordering::SeqCst);
    owner
        .prepare_witnessed_credential_renewal(&f.c.policy, 150, anchor)
        .expect("calibrate");
    let syncs = count.load(Ordering::SeqCst);
    owner.close();
    assert!((1..=4).contains(&syncs));
    let mut cuts = 0;
    for after in [false, true] {
        for cut in 1..=syncs {
            let (f, proof) = staged();
            let historical = historical(&f);
            let (mut owner, remaining, _) = faulty(&f.c, after);
            let anchor = client(&f, &mut owner, 150);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.prepare_witnessed_credential_renewal(&f.c.policy, 150, anchor),
                after,
            );
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            assert!(owner.active.is_none());
            let saved = disk(&f);
            assert!(saved.1.is_some());
            let exact = DeviceJournal::inspect_credential_renewal_preparation(
                f.c.paths.installation.files()[1],
                JournalKey::open(&f.c.paths.wrapping).expect("key"),
                &f.original,
                &historical,
                f.id,
            )
            .expect("authenticated durable proposal")
            .expect("present despite config failure");
            f.c.policy.close();
            f.c.policy.runtime.close();
            assert!(historical.validity().until() <= 250);
            let requests = f.carrier.requests.lock().expect("requests").len();
            let mut owner = open(&f.c);
            for _ in 0..2 {
                assert_eq!(
                    owner
                        .recover_witnessed_credential_renewal_preparation(&historical, 250)
                        .expect("historical preparation"),
                    Some(exact)
                );
                assert_eq!(
                    owner.credential_renewal_status().expect("same pending"),
                    renewal::pending(&proof)
                );
            }
            owner.close();
            assert_eq!(
                disk(&f),
                saved,
                "recovery must never reseal or remove the original intent"
            );
            assert_eq!(f.carrier.requests.lock().expect("requests").len(), requests);
            cuts += 1;
        }
    }
    eprintln!("witness preparation configuration cuts={cuts}");
}
#[test]
fn missing_preparation_is_pending_but_missing_intent_under_retained_coordination_is_conflict() {
    let f = fixture();
    let proof = grant(&f, &f.original, 2, 190);
    let historical = historical(&f);
    let mut owner = open(&f.c);
    owner
        .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, 150)
        .expect("stage");
    let saved = disk(&f);
    assert!(saved.1.is_none());
    let requests = f.carrier.requests.lock().expect("requests").len();
    assert_eq!(
        owner
            .recover_witnessed_credential_renewal_preparation(&historical, 250)
            .expect("no proposal"),
        None
    );
    assert_eq!(
        owner.credential_renewal_status().expect("pending"),
        renewal::pending(&proof)
    );
    assert_eq!(disk(&f), saved);
    assert_eq!(f.carrier.requests.lock().expect("requests").len(), requests);
    let anchor = client(&f, &mut owner, 150);
    owner
        .prepare_witnessed_credential_renewal(&f.c.policy, 150, anchor)
        .expect("prepare");
    owner.close();
    // Opening redb changes its own recovery metadata. Compare the authenticated
    // enrollment record, whose bytes must remain untouched on this refusal.
    let configuration = || {
        let db = open_private_database(&f.c.paths.configuration).expect("configuration");
        let read = db.begin_read().expect("read");
        let table = read.open_table(TABLE).expect("table");
        let value = table.get("enrollment").expect("record").expect("present");
        value.value().to_vec()
    };
    let original_configuration = configuration();
    {
        let db = open_private_database(f.c.paths.installation.files()[1]).expect("journal");
        let write = db.begin_write().expect("write");
        write
            .open_table(JOURNAL)
            .expect("table")
            .remove("pending")
            .expect("remove fixture intent");
        write.commit().expect("commit fixture corruption");
    }
    let saved = disk(&f);
    let mut owner = open(&f.c);
    assert!(matches!(
        owner.recover_witnessed_credential_renewal_preparation(&historical, 250),
        Err(DurableError::Conflict)
    ));
    assert!(owner.active.is_none());
    assert_eq!(disk(&f), saved);
    assert_eq!(configuration(), original_configuration);
}
#[test]
fn historical_recovery_does_not_authorize_new_commit_when_only_current_policy_is_invalid() {
    for boundary in ["expiry", "policy-close", "runtime-close"] {
        let f = fixture();
        let proof = grant(&f, &f.original, 2, 400);
        let proposal = prepare(&f, &proof, 150);
        let at = match boundary {
            "expiry" => 250,
            "policy-close" => {
                f.c.policy.close();
                150
            }
            "runtime-close" => {
                f.c.policy.runtime.close();
                150
            }
            _ => unreachable!("fixed cases"),
        };
        assert!(proof.successor_device().description.validity.until() > at);
        let saved = disk(&f);
        let requests = f.carrier.requests.lock().expect("requests").len();
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, at);
        assert_eq!(
            owner
                .recover_witnessed_credential_renewal_preparation(f.c.policy.historical(), at)
                .expect("history still recoverable"),
            Some(proposal)
        );
        assert!(owner
            .commit_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                at,
                &mut anchor
            )
            .is_err());
        assert!(owner.active.is_none());
        assert!(
            !f.carrier
                .requests
                .lock()
                .expect("requests")
                .get(requests..)
                .expect("retained request prefix")
                .contains(&5),
            "new Commit escaped {boundary}"
        );
        assert_eq!(disk(&f), saved);
        assert!(activate(&f, at).is_err());
    }
}
#[test]
fn original_required_enrollment_commits_twice_without_resealing_a_completed_target() {
    let f = fixture();
    let signer = fs::read(&f.c.paths.signer).expect("original signer");
    let first = grant(&f, &f.original, 2, 190);
    let p = prepare(&f, &first, 170);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                first.operation(),
                first.statement_digest(),
                &f.c.policy,
                170,
                &mut anchor
            )
            .expect("commit"),
        renewal::committed(&first)
    );
    owner.close();
    assert_eq!(
        DeviceJournal::inspect_credential_renewal_preparation(
            f.c.paths.installation.files()[1],
            JournalKey::open(&f.c.paths.wrapping).expect("key"),
            &f.original,
            &f.c.policy,
            f.id
        )
        .expect("no pending"),
        None
    );
    let state = disk(&f);
    assert!(state.1.is_none());
    assert_eq!(
        crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2", &state.0),
        p.target_head().digest()
    );
    activate(&f, 170).expect("C1 current owner").close();
    assert_eq!(
        disk(&f),
        state,
        "activation must not erase the retained receipt by resealing"
    );
    let next = grant(&f, first.successor_device(), 3, 220);
    let p2 = prepare(&f, &next, 180);
    assert_eq!(p2.expected_head(), p.target_head());
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 180);
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                next.operation(),
                next.statement_digest(),
                &f.c.policy,
                180,
                &mut anchor
            )
            .expect("second commit"),
        renewal::committed(&next)
    );
    owner.close();
    activate(&f, 180).expect("C2 current owner").close();
    assert_eq!(fs::read(&f.c.paths.signer).expect("same signer"), signer);
}
#[test]
fn early_closed_target_preserves_live_predecessor_and_rejects_reused_version() {
    for prior in [false, true] {
        let f = fixture();
        let first = grant(&f, &f.original, 2, 190);
        let (previous, version, at) = if prior {
            prepare(&f, &first, 170);
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 170);
            owner
                .commit_witnessed_credential_renewal(
                    first.operation(),
                    first.statement_digest(),
                    &f.c.policy,
                    170,
                    &mut anchor,
                )
                .expect("first");
            (first.successor_device(), 3, 175)
        } else {
            (&f.original, 2, 150)
        };
        let proof = grant(&f, previous, version, 220);
        let original_image = disk(&f).0;
        prepare(&f, &proof, at);
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, at);
        let closed = CredentialRenewalStatus::Closed {
            operation: proof.operation(),
            statement: proof.statement_digest(),
            target: proof.successor_device().roster().checkpoint(),
        };
        assert_eq!(
            owner
                .close_witnessed_credential_renewal(
                    proof.operation(),
                    proof.statement_digest(),
                    &f.c.policy,
                    at,
                    &mut anchor
                )
                .expect("closed"),
            closed
        );
        owner.close();
        assert_eq!(disk(&f), (original_image, None));
        activate(&f, at).expect("still-live predecessor").close();
        if prior {
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, at);
            assert_eq!(
                owner
                    .stage_credential_renewal(&first, first.operation(), &f.c.policy, at)
                    .expect("exact T1 stage retry"),
                renewal::committed(&first)
            );
            assert_eq!(
                owner
                    .reconcile_witnessed_credential_renewal(
                        first.operation(),
                        first.statement_digest(),
                        &f.c.policy,
                        at,
                        &mut anchor
                    )
                    .expect("exact T1 reconciliation"),
                renewal::committed(&first)
            );
            assert_eq!(
                owner
                    .credential_renewal_status()
                    .expect("latest remains T2"),
                closed
            );
        }

        assert!(open(&f.c)
            .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, at)
            .is_err());
        let next = grant(&f, previous, version + 1, 240);
        prepare(&f, &next, at);
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, at);
        owner
            .commit_witnessed_credential_renewal(
                next.operation(),
                next.statement_digest(),
                &f.c.policy,
                at,
                &mut anchor,
            )
            .expect("higher target");
    }
}
#[test]
fn lost_commit_status_and_ack_replies_recover_original_terminal_after_expiry() {
    for opcode in [5, 6, 8] {
        for after in [false, true] {
            let f = fixture();
            let proof = grant(&f, &f.original, 2, 190);
            prepare(&f, &proof, 170);
            *f.carrier.cut.lock().expect("cut") = Some((opcode, after));
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 170);
            assert!(owner
                .commit_witnessed_credential_renewal(
                    proof.operation(),
                    proof.statement_digest(),
                    &f.c.policy,
                    170,
                    &mut anchor
                )
                .is_err());
            assert!(owner.active.is_none());
            f.carrier.clock.store(250, Ordering::SeqCst);
            f.c.policy.close();
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 250);
            let status = owner
                .reconcile_witnessed_credential_renewal(
                    proof.operation(),
                    proof.statement_digest(),
                    &f.c.policy,
                    250,
                    &mut anchor,
                )
                .expect("historical recovery");
            if opcode == 5 && !after {
                assert_eq!(status, renewal::pending(&proof));
                assert!(disk(&f).1.is_some());
                assert!(matches!(
                    owner
                        .close_witnessed_credential_renewal(
                            proof.operation(),
                            proof.statement_digest(),
                            &f.c.policy,
                            250,
                            &mut anchor
                        )
                        .expect("close after expiry"),
                    CredentialRenewalStatus::Closed { .. }
                ));
            } else {
                assert_eq!(status, renewal::committed(&proof));
            }
            owner.close();
            assert!(disk(&f).1.is_none());
            assert!(activate(&f, 250).is_err());
        }
    }
}

#[test]
fn every_terminal_and_retirement_configuration_sync_cut_retains_original_outcome() {
    let mut injected = 0;
    for closed in [false, true] {
        let f = fixture();
        let proof = grant(&f, &f.original, 2, 190);
        prepare(&f, &proof, 150);
        let (mut owner, _, count) = faulty(&f.c, false);
        let mut anchor = client(&f, &mut owner, 150);
        count.store(0, Ordering::SeqCst);
        let run = |owner: &mut DeviceEnrollment,
                   f: &Fixture,
                   proof: &crate::VerifiedCredentialRenewal,
                   anchor: &mut AnchorClient| {
            if closed {
                owner.close_witnessed_credential_renewal(
                    proof.operation(),
                    proof.statement_digest(),
                    &f.c.policy,
                    150,
                    anchor,
                )
            } else {
                owner.commit_witnessed_credential_renewal(
                    proof.operation(),
                    proof.statement_digest(),
                    &f.c.policy,
                    150,
                    anchor,
                )
            }
        };
        run(&mut owner, &f, &proof, &mut anchor).expect("calibrate");
        let syncs = count.load(Ordering::SeqCst);
        owner.close();
        assert!((2..=12).contains(&syncs));
        for after in [false, true] {
            for cut in 1..=syncs {
                let f = fixture();
                let proof = grant(&f, &f.original, 2, 190);
                let proposal = prepare(&f, &proof, 150);
                let (mut owner, remaining, _) = faulty(&f.c, after);
                let mut anchor = client(&f, &mut owner, 150);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(run(&mut owner, &f, &proof, &mut anchor), after);
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                assert!(owner.active.is_none());
                f.carrier.clock.store(250, Ordering::SeqCst);
                f.c.policy.close();
                let mut owner = open(&f.c);
                let mut anchor = client(&f, &mut owner, 250);
                let actual = owner
                    .reconcile_witnessed_credential_renewal(
                        proof.operation(),
                        proof.statement_digest(),
                        &f.c.policy,
                        250,
                        &mut anchor,
                    )
                    .expect("original exact recovery");
                let expected = if closed {
                    CredentialRenewalStatus::Closed {
                        operation: proof.operation(),
                        statement: proof.statement_digest(),
                        target: proof.successor_device().roster().checkpoint(),
                    }
                } else {
                    renewal::committed(&proof)
                };
                assert_eq!(actual, expected);
                owner.close();
                let saved = disk(&f);
                assert!(saved.1.is_none());
                assert_eq!(
                    crate::crypto::digest(
                        b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2",
                        &saved.0
                    ),
                    if closed {
                        proposal.expected_head().digest()
                    } else {
                        proposal.target_head().digest()
                    }
                );
                assert!(activate(&f, 250).is_err());
                injected += 1;
            }
        }
        eprintln!("witness enrollment config closed={closed} measured syncs={syncs}");
    }
    eprintln!("witness enrollment config injected cuts={injected}");
}

#[test]
fn enrollment_crash_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_WITNESS_ENROLLMENT_CHILD") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let f = fixture();
    let proof = grant(&f, &f.original, 2, 190);
    use crate::durable::WitnessedCredentialIntent;
    let mode = std::env::var("QPERIAPT_WITNESS_ENROLLMENT_CLOSED").expect("mode");
    let proposal = if mode == "2" {
        open(&f.c)
            .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, 150)
            .expect("stage");
        let cancellation = open(&f.c)
            .prepare_witnessed_credential_cancellation(&f.c.policy, 150)
            .expect("reserve");
        f.carrier
            .store
            .lock()
            .expect("witness")
            .close_unprepared_credential_renewal(cancellation, &proof, &f.c.policy)
            .expect("independent close");
        WitnessedCredentialIntent::Cancellation(cancellation)
    } else {
        WitnessedCredentialIntent::Proposal(prepare(&f, &proof, 150))
    };
    fs::write(
        root.join("enrollment-path"),
        f.c.paths
            .configuration
            .parent()
            .expect("path")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .expect("client path");
    fs::write(
        root.join("witness-path"),
        f._witness_dir
            .path()
            .canonicalize()
            .expect("path")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .expect("witness path");
    fs::write(root.join("witness-id"), f.pin.identity().as_bytes()).expect("witness identity");
    fs::write(root.join("trusted-root"), f.c.intent.root.encode()).expect("account root");
    fs::write(
        root.join("proposal"),
        match proposal {
            WitnessedCredentialIntent::Proposal(p) => p.to_bytes(),
            WitnessedCredentialIntent::Cancellation(c) => c.to_bytes(),
        },
    )
    .expect("proposal");
    let (authority, issued, _, _) = crate::tests::session_policy_fixture_with_anchor(
        &[PrekeyQuality::OneTimeBoth],
        crate::AnchorRequirement::required(&f.pin),
    );
    assert_eq!(issued.checkpoint(), f.c.policy.checkpoint());
    fs::write(
        root.join("trusted-policy-root"),
        authority.public_key().expect("policy root").encode(),
    )
    .expect("root");
    fs::write(root.join("protocol-policy"), issued.as_bytes()).expect("original signed policy");
    fs::write(root.join("trusted-family"), f.c.policy.family()).expect("family");
    let checkpoint = issued.checkpoint();
    let mut exact_policy = checkpoint.version().to_be_bytes().to_vec();
    exact_policy.extend_from_slice(&checkpoint.digest());
    fs::write(root.join("trusted-policy-checkpoint"), exact_policy).expect("independent exact pin");

    let checkpoint = proof.successor_device().roster().checkpoint();
    let mut bytes = checkpoint.version().to_be_bytes().to_vec();
    bytes.extend_from_slice(&checkpoint.digest());
    fs::write(root.join("target-checkpoint"), bytes).expect("target");
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    if mode == "2" {
        owner
            .reconcile_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                150,
                &mut anchor,
            )
            .expect("cancellation closure");
    } else if mode == "1" {
        owner
            .close_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                150,
                &mut anchor,
            )
            .expect("close");
    } else {
        owner
            .commit_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                150,
                &mut anchor,
            )
            .expect("commit");
    }
    Err("requested process cut was not reached")
}
#[test]
fn real_process_kills_recover_original_enrollment_at_each_cross_store_boundary() {
    use crate::durable::tests::ChildGuard;
    use std::process::{Command, Stdio};
    let mut cuts = 0;
    for mode in ["0", "1", "2"] {
        let closed = mode != "0";
        for stage in [
            "witness-observed",
            "witness-terminal",
            "witness-retired",
            "witness-complete",
        ] {
            let folder = directory();
            let root = folder.path().canonicalize().expect("owned root");
            let log = fs::File::create(root.join("child.log")).expect("log");
            let mut child = ChildGuard(
                Command::new(std::env::current_exe().expect("binary"))
                    .args([
                        "--exact",
                        "enrollment::tests::witness_renewal::enrollment_crash_child",
                        "--nocapture",
                    ])
                    .env("TMPDIR", &root)
                    .env("QPERIAPT_WITNESS_ENROLLMENT_CHILD", &root)
                    .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", &root)
                    .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", stage)
                    .env("QPERIAPT_WITNESS_ENROLLMENT_CLOSED", mode)
                    .stdout(Stdio::from(log.try_clone().expect("log clone")))
                    .stderr(Stdio::from(log))
                    .spawn()
                    .expect("child"),
            );
            let deadline = Instant::now() + Duration::from_secs(40);
            while !root.join("renewal-ready").exists() {
                assert!(
                    child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                    "child did not reach {stage}: {}",
                    fs::read_to_string(root.join("child.log")).expect("log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().expect("actual kill");
            assert!(!child.0.wait().expect("reap").success());
            let client_path =
                PathBuf::from(fs::read_to_string(root.join("enrollment-path")).expect("path"));
            let witness_path =
                PathBuf::from(fs::read_to_string(root.join("witness-path")).expect("path"));
            assert!(client_path.starts_with(&root) && witness_path.starts_with(&root));
            let identity = crate::AnchorIdentity::from_trusted_state(
                fs::read(root.join("witness-id"))
                    .expect("identity")
                    .try_into()
                    .expect("width"),
            )
            .expect("identity");
            let store = AnchorStore::open(
                &witness_path.join("witness.redb"),
                JournalKey::open(&witness_path.join("witness.key")).expect("key"),
                crate::AnchorSigningKey::deterministic([226; 32], [227; 32]).expect("same signer"),
                identity,
            )
            .expect("same witness");
            let pin = store.pin().expect("pin");
            // Reconstruct only signed historical metadata. No SDK runtime is
            // opened and no past verification time is substituted after restart.
            let expected = fs::read(root.join("trusted-policy-checkpoint")).expect("pin");
            let mut d = Decoder::new(&expected);
            let checkpoint = crate::PolicyCheckpoint::from_trusted_state(
                d.u64().expect("version"),
                d.array().expect("digest"),
            )
            .expect("checkpoint");
            d.finish().expect("complete pin");
            let policy_pin = crate::PolicyPin::new(
                fs::read(root.join("trusted-family"))
                    .expect("family")
                    .try_into()
                    .expect("width"),
                PublicKey::decode(&fs::read(root.join("trusted-policy-root")).expect("root"))
                    .expect("public"),
                checkpoint,
            )
            .expect("independent policy pin");
            let policy = policy_pin
                .verify_historical(&fs::read(root.join("protocol-policy")).expect("wire"))
                .expect("historical metadata only");
            assert!(policy.validity().until() <= 250);
            let intent = EnrollmentIntent::new(
                PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root"))
                    .expect("root"),
                DeviceDescription::new(
                    [7; 16],
                    1,
                    policy.family(),
                    Validity::new(100, 160).expect("C0"),
                )
                .expect("intent"),
            );
            let transport = Carrier {
                store: Arc::new(Mutex::new(store)),
                clock: Arc::new(AtomicU64::new(250)),
                cut: Arc::new(Mutex::new(None)),
                requests: Arc::new(Mutex::new(Vec::new())),
                after_reply: Arc::new(Mutex::new(None)),
            };
            let wire = fs::read(root.join("proposal")).expect("original intent");
            let proposal = if mode == "2" {
                crate::durable::WitnessedCredentialIntent::Cancellation(
                    crate::AnchorCredentialRenewalCancellation::from_trusted_state(&wire)
                        .expect("cancellation"),
                )
            } else {
                crate::durable::WitnessedCredentialIntent::Proposal(
                    Proposal::from_trusted_state(&wire).expect("proposal"),
                )
            };
            let bytes = fs::read(root.join("target-checkpoint")).expect("target");
            let mut d = Decoder::new(&bytes);
            let target = RosterCheckpoint::from_trusted_state(
                d.u64().expect("version"),
                d.array().expect("digest"),
            )
            .expect("target");
            d.finish().expect("complete");
            let mut owner =
                DeviceEnrollment::open(paths(&client_path), intent).expect("original owner");
            let mut anchor = owner
                .credential_renewal_anchor_client(
                    &policy,
                    250,
                    pin,
                    Box::new(transport),
                    Duration::from_secs(3),
                )
                .expect("historical client");
            assert_eq!(
                owner
                    .reconcile_witnessed_credential_renewal(
                        proposal.operation(),
                        proposal.statement(),
                        &policy,
                        250,
                        &mut anchor
                    )
                    .expect("terminal recovery"),
                if closed {
                    CredentialRenewalStatus::Closed {
                        operation: proposal.operation(),
                        statement: proposal.statement(),
                        target,
                    }
                } else {
                    CredentialRenewalStatus::Committed {
                        operation: proposal.operation(),
                        statement: proposal.statement(),
                        target,
                    }
                }
            );
            owner.close();
            // HistoricalSessionPolicy cannot be passed to activate (compile-fail doctest).
            cuts += 1;
        }
    }
    assert_eq!(cuts, 12);
    eprintln!("witness enrollment real process cuts={cuts}");
}

#[test]
fn retired_terminal_unavailable_never_erases_a_different_pending_after_client_rollback() {
    let f = fixture();
    let first = grant(&f, &f.original, 2, 190);
    let p1 = prepare(&f, &first, 150);
    *f.carrier.cut.lock().expect("cut") = Some((8, false));
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    assert!(owner
        .close_witnessed_credential_renewal(
            first.operation(),
            first.statement_digest(),
            &f.c.policy,
            150,
            &mut anchor
        )
        .is_err());
    let terminal_config = fs::read(&f.c.paths.configuration).expect("durable Terminal backup");
    let terminal_journal =
        fs::read(f.c.paths.installation.files()[1]).expect("original pending backup");
    let first_image = disk(&f).0;
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    assert!(matches!(
        owner
            .reconcile_witnessed_credential_renewal(
                first.operation(),
                first.statement_digest(),
                &f.c.policy,
                150,
                &mut anchor
            )
            .expect("finish T1"),
        CredentialRenewalStatus::Closed { .. }
    ));
    owner.close();
    let second = grant(&f, &f.original, 3, 200);
    let p2 = prepare(&f, &second, 150);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    for operation in [
        crate::AnchorOperation::close_credential_renewal(&p2),
        crate::AnchorOperation::acknowledge_credential_renewal(&p2),
    ] {
        anchor
            .exchange(p2.subject(), operation)
            .expect("independent later control flow");
    }
    owner.close();
    let t2 = disk(&f);
    assert_eq!(t2.0, first_image);
    fs::write(&f.c.paths.configuration, &terminal_config).expect("rollback original config");
    let before = f.carrier.requests.lock().expect("requests").len();
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    assert!(matches!(
        owner.reconcile_witnessed_credential_renewal(
            first.operation(),
            first.statement_digest(),
            &f.c.policy,
            150,
            &mut anchor
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        f.carrier.requests.lock().expect("requests").len(),
        before,
        "reject mismatched pending before ACK"
    );
    assert_eq!(disk(&f), t2, "never erase T2 under T1 Terminal");
    fs::write(f.c.paths.installation.files()[1], &terminal_journal)
        .expect("restore original exact T1 journal backup");
    f.carrier.clock.store(250, Ordering::SeqCst);
    f.c.policy.close();
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 250);
    let reply = anchor
        .exchange(
            p1.subject(),
            crate::AnchorOperation::credential_renewal_status(&p1),
        )
        .expect("fresh exact observation");
    assert_eq!(
        reply.credential_renewal_state(&p1).expect("typed"),
        crate::AnchorCredentialRenewalState::Unavailable
    );
    assert!(matches!(
        owner
            .reconcile_witnessed_credential_renewal(
                first.operation(),
                first.statement_digest(),
                &f.c.policy,
                250,
                &mut anchor
            )
            .expect("known terminal permits metadata finish"),
        CredentialRenewalStatus::Closed { .. }
    ));
    owner.close();
    assert_eq!(disk(&f), (first_image, None));
    assert!(activate(&f, 250).is_err());
}

#[test]
fn unavailable_without_durable_terminal_stays_pending_and_does_not_infer_no_commit() {
    let f = fixture();
    let proof = grant(&f, &f.original, 2, 190);
    let p = prepare(&f, &proof, 150);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    for operation in [
        crate::AnchorOperation::commit_credential_renewal(&p),
        crate::AnchorOperation::acknowledge_credential_renewal(&p),
    ] {
        anchor
            .exchange(p.subject(), operation)
            .expect("external control flow");
    }
    let saved = disk(&f);
    f.carrier.clock.store(250, Ordering::SeqCst);
    f.c.policy.close();
    assert_eq!(
        owner
            .reconcile_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                250,
                &mut anchor
            )
            .expect("unknown observation"),
        renewal::pending(&proof)
    );
    assert_eq!(disk(&f), saved);
    assert!(owner.activate(&f.c.policy, 250, Some(anchor)).is_err());
}

#[test]
fn every_pending_retirement_sync_cut_preserves_terminal_image_and_retries_without_an_advance() {
    let setup = |closed: bool| {
        let f = fixture();
        let proof = grant(&f, &f.original, 2, 190);
        let proposal = prepare(&f, &proof, 150);
        *f.carrier.cut.lock().expect("cut") = Some((8, false));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 150);
        let result = if closed {
            owner.close_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                150,
                &mut anchor,
            )
        } else {
            owner.commit_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                150,
                &mut anchor,
            )
        };
        assert!(matches!(result, Err(DurableError::Anchor(_))));
        (f, proof, proposal)
    };
    let mut injected = 0;
    for closed in [false, true] {
        let (f, _, proposal) = setup(closed);
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 150);
        let terminal = owner
            .persisted_witness_terminal(&f.c.policy, 150, proposal)
            .expect("authenticated terminal");
        let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
        let (db, _, count, _) = fault_database_path(f.c.paths.installation.files()[1], false);
        count.store(0, Ordering::SeqCst);
        DeviceJournal::retire_witnessed_credential_intent_in_database(
            &db,
            &key,
            &f.original,
            &f.c.policy,
            f.id,
            &terminal,
            &mut anchor,
        )
        .expect("calibration");
        let syncs = count.load(Ordering::SeqCst);
        assert!((1..=8).contains(&syncs));
        count.store(0, Ordering::SeqCst);
        DeviceJournal::retire_witnessed_credential_intent_in_database(
            &db,
            &key,
            &f.original,
            &f.c.policy,
            f.id,
            &terminal,
            &mut anchor,
        )
        .expect("absent pending retry");
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "absent pending must not commit again"
        );
        drop(db);
        owner.close();
        for after in [false, true] {
            for cut in 1..=syncs {
                let (f, proof, proposal) = setup(closed);
                let saved = disk(&f);
                let mut owner = open(&f.c);
                let mut anchor = client(&f, &mut owner, 150);
                let terminal = owner
                    .persisted_witness_terminal(&f.c.policy, 150, proposal)
                    .expect("durable terminal");
                let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
                let lease = DeviceInstallation::open_bound(
                    f.c.paths.installation.clone(),
                    &key,
                    &f.original,
                    &f.c.policy,
                )
                .expect("original lease");
                let (db, remaining, _, _) =
                    fault_database_path(f.c.paths.installation.files()[1], after);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(
                    DeviceJournal::retire_witnessed_credential_intent_in_database(
                        &db,
                        &key,
                        &f.original,
                        &f.c.policy,
                        f.id,
                        &terminal,
                        &mut anchor,
                    ),
                    after,
                );
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                drop(db);
                drop(lease);
                owner.close();
                let after_fault = disk(&f);
                assert_eq!(after_fault.0, saved.0);
                assert!(after_fault.1.is_none() || after_fault.1 == saved.1);
                f.carrier.clock.store(250, Ordering::SeqCst);
                f.c.policy.close();
                let mut owner = open(&f.c);
                let mut anchor = client(&f, &mut owner, 250);
                let status = owner
                    .reconcile_witnessed_credential_renewal(
                        proof.operation(),
                        proof.statement_digest(),
                        &f.c.policy,
                        250,
                        &mut anchor,
                    )
                    .expect("finish after uncertain deletion");
                assert_eq!(
                    status,
                    if closed {
                        CredentialRenewalStatus::Closed {
                            operation: proof.operation(),
                            statement: proof.statement_digest(),
                            target: proof.successor_device().roster().checkpoint(),
                        }
                    } else {
                        renewal::committed(&proof)
                    }
                );
                owner.close();
                assert_eq!(disk(&f), (saved.0, None));
                injected += 1;
            }
        }
        eprintln!("witness intent retirement closed={closed} measured syncs={syncs}");
    }
    eprintln!("witness intent retirement injected cuts={injected}");
}

#[path = "witness_cancellation_tests.rs"]
mod cancellation;

#[test]
fn opaque_witness_target_never_replaces_the_exact_renewal_receipt() {
    use crate::{AnchorOperation, AnchorOutcome, AnchorRequest};
    let f = fixture();
    let b = grant(&f, &f.original, 2, 190);
    let original_certificate =
        f.c.root
            .issue_device(f.original.description.clone(), f.original.key.clone())
            .expect("same original certificate body");
    let a = crate::durable::tests::grant(
        &f.c.root,
        &original_certificate,
        &f.original,
        190,
        2,
        [211; 32],
        f.c.policy.checkpoint().digest(),
    );
    assert_ne!(a.operation(), b.operation());
    assert_ne!(a.statement_digest(), b.statement_digest());
    assert_eq!(
        a.successor_device().credential_digest(),
        b.successor_device().credential_digest()
    );
    assert_eq!(
        a.successor_device().roster().checkpoint(),
        b.successor_device().roster().checkpoint()
    );
    assert_eq!(
        a.successor_device().authority_binding(),
        b.successor_device().authority_binding()
    );

    // Honest journal code creates a real encrypted target containing grant B.
    // Do not invoke the helper that would independently approve B at the witness.
    let mut owner = open(&f.c);
    owner
        .stage_credential_renewal(&b, b.operation(), &f.c.policy, 170)
        .expect("stage B");
    f.carrier.clock.store(170, Ordering::SeqCst);
    let anchor = client(&f, &mut owner, 170);
    let proposal_b = owner
        .prepare_witnessed_credential_renewal(&f.c.policy, 170, anchor)
        .expect("real sealed target B");
    let signer_id = owner.identity().expect("original signer identity");
    owner.close();
    let before = disk(&f);
    assert!(
        before.1.is_some(),
        "original target B must remain durably pending"
    );

    // The public proposal decoder authenticates no target semantics. Model a
    // holder of the original signing key choosing a target during approval.
    let mut metadata = proposal_b.to_bytes();
    metadata
        .get_mut(136..168)
        .expect("proposal operation field")
        .copy_from_slice(a.operation().as_bytes());
    metadata
        .get_mut(168..200)
        .expect("proposal statement field")
        .copy_from_slice(&a.statement_digest());
    let proposal_a = Proposal::from_trusted_state(&metadata).expect("canonical public proposal A");
    assert_eq!(proposal_a.operation(), a.operation());
    assert_eq!(proposal_a.statement(), a.statement_digest());
    assert_eq!(proposal_a.expected_head(), proposal_b.expected_head());
    assert_eq!(proposal_a.target_head(), proposal_b.target_head());
    assert_ne!(proposal_a.binding(), proposal_b.binding());
    let signer = DeviceSigningKey::open(
        &f.c.paths.signer,
        &JournalKey::open(&f.c.paths.wrapping).expect("original wrapping owner"),
        signer_id,
    )
    .expect("original device signer");
    let exchange = |operation| {
        // All request construction and verification APIs below are public.
        let request = AnchorRequest::new(&f.pin, proposal_a.subject(), operation, &signer)
            .expect("fresh signed request");
        let reply = f
            .carrier
            .store
            .lock()
            .expect("actual witness")
            .handle(request.as_bytes(), 170)
            .expect("durable witness result");
        f.pin
            .verify_reply(&request, &reply)
            .expect("independent authenticated fresh reply")
    };
    assert_eq!(
        exchange(AnchorOperation::commit_credential_renewal(&proposal_a)).outcome(),
        AnchorOutcome::CredentialUnavailable,
        "device signer alone cannot prepare A"
    );
    f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_credential_renewal(proposal_a, &a, &f.c.policy, 170)
        .expect("trusted control plane explicitly approves A with opaque target B");
    assert_eq!(
        exchange(AnchorOperation::commit_credential_renewal(&proposal_b)).outcome(),
        AnchorOutcome::CredentialUnavailable,
        "B never independently approved"
    );
    let committed = exchange(AnchorOperation::commit_credential_renewal(&proposal_a));
    assert_eq!(committed.outcome(), AnchorOutcome::CredentialApplied);
    assert_eq!(committed.observed_head(), proposal_b.target_head());
    assert_eq!(
        exchange(AnchorOperation::credential_renewal_status(&proposal_b)).outcome(),
        AnchorOutcome::CredentialUnavailable
    );
    let admitted = exchange(
        AnchorOperation::admit_authority(b.successor_device().authority_binding())
            .expect("authority"),
    );
    assert_eq!(admitted.outcome(), AnchorOutcome::AuthorityCurrent);
    assert_eq!(admitted.observed_head(), proposal_b.target_head());

    // Existing exact intent recovery does not equate that projection with B's
    // own transaction receipt. Preserve this negative result in the experiment.
    assert!(
        matches!(activate(&f, 170), Err(DurableError::Suspended)),
        "unapproved B released owner"
    );
    assert_eq!(
        disk(&f),
        before,
        "rejected B recovery changed pending target bytes"
    );
    assert_eq!(
        exchange(AnchorOperation::acknowledge_credential_renewal(&proposal_a)).outcome(),
        AnchorOutcome::CredentialAcknowledged
    );
    let admitted = exchange(
        AnchorOperation::admit_authority(b.successor_device().authority_binding())
            .expect("authority"),
    );
    assert_eq!(admitted.outcome(), AnchorOutcome::AuthorityCurrent);
    assert_eq!(admitted.observed_head(), proposal_b.target_head());
    assert_eq!(
        exchange(AnchorOperation::credential_renewal_status(&proposal_b)).outcome(),
        AnchorOutcome::CredentialUnavailable
    );
    assert!(
        matches!(activate(&f, 170), Err(DurableError::Suspended)),
        "unapproved B released owner after A ACK"
    );
    assert_eq!(disk(&f), before);
}
