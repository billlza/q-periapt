// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Witness-store component tests. Proposal target digests are explicit public
//! expectations, not a claim that journal/enrollment coordination is implemented.
use super::*;
use crate::{
    AccountPin, AllowedPrekeyModes, AnchorIdentity, AnchorRequirement, ApplicationSendBudget,
    DeviceDescription, DeviceSigningKey, HistoricalSessionPolicy, PolicyPin, PolicyRenewalId,
    PolicyRenewalScope, PolicyRenewalStatement, PolicySigningKey, RootSigningKey,
    SessionPolicyParameters, SigningKeyId,
};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, sync::Arc};

pub(in crate::anchor::store) struct Case {
    pub(in crate::anchor::store) _dir: tempfile::TempDir,
    pub(in crate::anchor::store) server: PathBuf,
    pub(in crate::anchor::store) store: AnchorStore,
    pub(in crate::anchor::store) pin: AnchorPin,
    pub(in crate::anchor::store) account: RootSigningKey,
    pub(in crate::anchor::store) issuer: PolicySigningKey,
    pub(in crate::anchor::store) signer: DeviceSigningKey,
    pub(in crate::anchor::store) runtime: Arc<q_periapt_sdk::Runtime>,
    pub(in crate::anchor::store) device: VerifiedDevice,
    pub(in crate::anchor::store) certificate: Vec<u8>,
    pub(in crate::anchor::store) original: HistoricalSessionPolicy,
    pub(in crate::anchor::store) target: VerifiedSessionPolicy,
    pub(in crate::anchor::store) subject: AnchorSubject,
    pub(in crate::anchor::store) initial: AnchorHead,
}
impl Case {
    pub(in crate::anchor::store) fn new() -> Self {
        let dir = crate::durable::tests::directory();
        let server = dir
            .path()
            .canonicalize()
            .expect("canonical private directory");
        let wrap = JournalKey::provision(&server.join("wrapping")).expect("wrap");
        let signing = AnchorSigningKey::provision(
            &server.join("signer"),
            &wrap,
            SigningKeyId::from_trusted_state([63; 32]).expect("ID"),
        )
        .expect("key");
        let identity = AnchorIdentity::generate().expect("identity");
        fs::write(server.join("instance"), identity.as_bytes()).expect("retain pin");
        let mut store =
            AnchorStore::provision(&server.join("anchor.redb"), wrap, signing, identity)
                .expect("store");
        let pin = store.pin().expect("pin");
        let (_, _, _, runtime) =
            crate::tests::session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
        let issuer = PolicySigningKey::generate().expect("issuer");
        let p0 = policy(&issuer, &runtime, &pin, 1, 160, 150);
        let target = policy(&issuer, &runtime, &pin, 2, 260, 170);
        let account = RootSigningKey::generate().expect("account");
        let signer = DeviceSigningKey::generate().expect("device");
        let certificate = account
            .issue_device(
                DeviceDescription::new(
                    [3; 16],
                    1,
                    p0.family(),
                    Validity::new(100, 400).expect("validity"),
                )
                .expect("desc"),
                signer.public_key().expect("public"),
            )
            .expect("certificate");
        let roster = account
            .issue_roster(
                1,
                Validity::new(100, 400).expect("roster time"),
                &[account.roster_entry(&certificate).expect("entry")],
            )
            .expect("roster");
        let device = AccountPin::new(
            account.account_id().expect("account"),
            account.public_key().expect("root"),
            roster.checkpoint(),
            p0.family(),
        )
        .expect("pin")
        .verify_device(&certificate, roster.as_bytes(), 150)
        .expect("device");
        let client = server.join("client");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&client)
            .expect("private client directory");
        let mut journal = crate::DeviceJournal::provision_anchored(
            &client.join("journal.redb"),
            JournalKey::provision(&client.join("key")).expect("journal wrapping"),
            &device,
            &p0,
            crate::JournalIdentity::generate().expect("original journal ID"),
            150,
        )
        .expect("required-witness journal genesis");
        let genesis = journal
            .anchor_genesis(&device, &p0)
            .expect("actual empty original journal");
        store
            .enroll(&genesis, &device, &p0, 150)
            .expect("independent enrollment");
        let initial = AnchorHead::from_trusted_state(1, 1, genesis.image_digest()).expect("head");
        journal.close();
        Self {
            _dir: dir,
            server,
            store,
            pin,
            account,
            issuer,
            signer,
            runtime,
            device,
            certificate,
            original: p0.historical().clone(),
            target,
            subject: genesis.subject(),
            initial,
        }
    }
    fn materials<'a>(
        &'a self,
        previous: &'a HistoricalSessionPolicy,
        target: &'a VerifiedSessionPolicy,
    ) -> PolicyRenewalMaterials<'a> {
        PolicyRenewalMaterials {
            original: &self.original,
            previous,
            target,
            original_device: &self.device,
            current_device: &self.device,
        }
    }
    pub(in crate::anchor::store) fn approval(
        &self,
        previous: &HistoricalSessionPolicy,
        previous_authorization: Option<[u8; 32]>,
        target: &VerifiedSessionPolicy,
    ) -> VerifiedPolicyRenewal {
        let scope = PolicyRenewalScope {
            operation: PolicyRenewalId::generate().expect("operation"),
            journal: crate::JournalIdentity::from_trusted_state(self.subject.journal)
                .expect("journal"),
            original_owner: self.subject.owner,
            original_credential: self.device.credential_digest(),
            current_credential: self.device.credential_digest(),
            current_roster: self.device.roster().checkpoint(),
            original_policy: self.original.checkpoint(),
            previous_policy: previous.checkpoint(),
            previous_authorization,
        };
        let materials = self.materials(previous, target);
        let s = PolicyRenewalStatement::new(&scope, &materials, 170).expect("statement");
        VerifiedPolicyRenewal::verify(
            &self
                .account
                .approve_policy_renewal(&s)
                .expect("root approval"),
            &self
                .issuer
                .approve_policy_renewal(&s)
                .expect("policy approval"),
            &scope,
            &materials,
            170,
        )
        .expect("two roots")
    }
    pub(in crate::anchor::store) fn proposal(
        &self,
        approval: &VerifiedPolicyRenewal,
        expected: AnchorHead,
        digest: u8,
    ) -> Proposal {
        let p = Proposal {
            witness: self.pin.binding(),
            subject: self.subject,
            operation: approval.scope().operation,
            statement: approval.statement_digest(),
            expected,
            target: AnchorHead::from_trusted_state(
                expected.fence(),
                expected.revision() + 1,
                [digest; 32],
            )
            .expect("explicit store-only target"),
        };
        Proposal::from_trusted_state(&p.to_bytes()).expect("canonical")
    }
    pub(in crate::anchor::store) fn reopen(&mut self) {
        self.store.close();
        self.store = open_witness(&self.server);
    }
    pub(in crate::anchor::store) fn exchange(
        &mut self,
        p: &Proposal,
        op: AnchorOperation,
        now: u64,
    ) -> State {
        let request = AnchorRequest::new(&self.pin, self.subject, op, &self.signer)
            .expect("signed fresh request");
        let wire = self
            .store
            .handle(request.as_bytes(), now)
            .expect("actual witness response");
        let reply = self
            .pin
            .verify_reply(&request, &wire)
            .expect("fresh witness signature");
        assert!(
            reply.applied_head().is_err(),
            "ordinary advance is not P authority"
        );
        reply.policy_renewal_state(p).expect("exact P result")
    }
    pub(in crate::anchor::store) fn fingerprint(&mut self) -> (u64, [u8; 32]) {
        let i = self.store.image().expect("state");
        (i.revision, i.digest)
    }
    pub(in crate::anchor::store) fn prepare(
        &mut self,
        p: Proposal,
        a: &VerifiedPolicyRenewal,
    ) -> Result<State, DurableError> {
        let m = PolicyRenewalMaterials {
            original: &self.original,
            previous: &self.original,
            target: &self.target,
            original_device: &self.device,
            current_device: &self.device,
        };
        self.store.prepare_policy_renewal(p, a, &m, 170)
    }
    pub(in crate::anchor::store) fn admission(
        &mut self,
        op: AnchorOperation,
        now: u64,
    ) -> AnchorOutcome {
        let request =
            AnchorRequest::new(&self.pin, self.subject, op, &self.signer).expect("request");
        let wire = self.store.handle(request.as_bytes(), now).expect("reply");
        self.pin
            .verify_reply(&request, &wire)
            .expect("signed response")
            .outcome()
    }
}
pub(in crate::anchor::store) fn policy(
    issuer: &PolicySigningKey,
    runtime: &Arc<q_periapt_sdk::Runtime>,
    pin: &AnchorPin,
    version: u64,
    until: u64,
    now: u64,
) -> VerifiedSessionPolicy {
    let wire = issuer
        .issue_session_policy(
            runtime,
            SessionPolicyParameters::new(
                version,
                Validity::new(100, until).expect("time"),
                AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                AnchorRequirement::required(pin),
                ApplicationSendBudget::new(3).expect("budget"),
            )
            .expect("parameters"),
        )
        .expect("signed policy");
    PolicyPin::new(
        issuer.policy_family().expect("family"),
        issuer.public_key().expect("key"),
        wire.checkpoint(),
    )
    .expect("independent pin")
    .verify(wire.as_bytes(), Arc::clone(runtime), now)
    .expect("live policy")
}
#[test]
fn independent_policy_applies_without_any_credential_grant_and_preserves_exact_history() {
    let mut c = Case::new();
    let a = c.approval(&c.original, None, &c.target);
    let p = c.proposal(&a, c.initial, 71);
    let original = c.fingerprint();
    assert_eq!(
        c.exchange(&p, AnchorOperation::policy_renewal_status(&p), 170),
        State::Unavailable
    );
    assert_eq!(c.fingerprint(), original, "unknown history is read only");
    assert_eq!(c.prepare(p, &a).expect("prepare"), State::Prepared);
    let prepared = c.fingerprint();
    assert_eq!(c.prepare(p, &a).expect("exact prepare"), State::Prepared);
    assert_eq!(c.fingerprint(), prepared);
    c.reopen();
    assert_eq!(
        c.exchange(&p, AnchorOperation::policy_renewal_status(&p), 170),
        State::Prepared
    );
    let admit =
        AnchorOperation::admit_policy_renewal(c.device.authority_binding(), a.statement_digest())
            .expect("admit");
    assert_eq!(c.admission(admit, 170), AnchorOutcome::AuthorityDenied);
    assert_eq!(
        c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170),
        State::Applied
    );
    let applied = c.fingerprint();
    c.reopen();
    assert_eq!(
        c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 300),
        State::Applied
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::close_policy_renewal(&p), 300),
        State::Applied
    );
    assert_eq!(c.fingerprint(), applied);
    let image = c.store.image().expect("state");
    let entry = image
        .entries
        .get(&c.subject.id(&c.pin.binding()))
        .expect("subject");
    assert_eq!(entry.head, p.target_head());
    assert_eq!(entry.credential_owner, c.subject.owner);
    assert_eq!(entry.authority, c.device.authority_binding());
    assert_eq!(entry.renewal_floor, 0);
    assert!(entry.credential_authorization.is_none() && entry.policy_authorization.is_none());
    assert_eq!(
        c.admission(admit, 200),
        AnchorOutcome::AuthorityDenied,
        "ACK required"
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 300),
        State::Acknowledged
    );
    c.reopen();
    assert_eq!(
        c.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 300),
        State::Acknowledged
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::policy_renewal_status(&p), 300),
        State::Unavailable
    );
    assert_eq!(c.admission(admit, 300), AnchorOutcome::AuthorityDenied);
    assert_eq!(c.admission(admit, 200), AnchorOutcome::AuthorityCurrent);
    assert_eq!(
        c.admission(
            AnchorOperation::admit_authority(c.device.authority_binding()).expect("old admission"),
            200
        ),
        AnchorOutcome::AuthorityDenied
    );
    assert!(matches!(
        c.prepare(p, &a),
        Err(DurableError::Protocol(Error::Retired))
    ));
}
#[test]
fn independent_policy_closed_target_cannot_revive_and_later_policy_preserves_its_predecessor() {
    let mut c = Case::new();
    let a = c.approval(&c.original, None, &c.target);
    let p = c.proposal(&a, c.initial, 72);
    let m = HistoricalPolicyRenewalMaterials {
        original: &c.original,
        previous: &c.original,
        target: c.target.historical(),
        original_device: &c.device,
        current_device: &c.device,
    };
    assert_eq!(
        c.store
            .close_policy_renewal(p, &a.historical(), &m)
            .expect("close before preparation"),
        State::Closed
    );
    assert_eq!(c.prepare(p, &a).expect("closed exact"), State::Closed);
    assert_eq!(
        c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170),
        State::Closed
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 170),
        State::Acknowledged
    );
    c.reopen();
    assert!(matches!(
        c.prepare(p, &a),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let p2 = policy(&c.issuer, &c.runtime, &c.pin, 3, 350, 170);
    let next = c.approval(&c.original, None, &p2);
    let proposal = c.proposal(&next, c.initial, 73);
    let m = PolicyRenewalMaterials {
        original: &c.original,
        previous: &c.original,
        target: &p2,
        original_device: &c.device,
        current_device: &c.device,
    };
    assert_eq!(
        c.store
            .prepare_policy_renewal(proposal, &next, &m, 170)
            .expect("new approved target, original still predecessor"),
        State::Prepared
    );
    assert_eq!(
        c.exchange(
            &proposal,
            AnchorOperation::commit_policy_renewal(&proposal),
            170
        ),
        State::Applied
    );
    assert_eq!(
        c.exchange(
            &proposal,
            AnchorOperation::acknowledge_policy_renewal(&proposal),
            170
        ),
        State::Acknowledged
    );
    c.reopen();
    let p3 = policy(&c.issuer, &c.runtime, &c.pin, 4, 380, 170);
    let third = c.approval(p2.historical(), Some(next.statement_digest()), &p3);
    let q = c.proposal(&third, proposal.target_head(), 74);
    let m = PolicyRenewalMaterials {
        original: &c.original,
        previous: p2.historical(),
        target: &p3,
        original_device: &c.device,
        current_device: &c.device,
    };
    assert_eq!(
        c.store
            .prepare_policy_renewal(q, &third, &m, 170)
            .expect("exact adopted predecessor"),
        State::Prepared
    );
    assert_eq!(
        c.exchange(&q, AnchorOperation::commit_policy_renewal(&q), 170),
        State::Applied
    );
}
#[test]
fn independent_policy_preparation_blocks_ordinary_writes_and_refuses_expired_commit() {
    let mut c = Case::new();
    let a = c.approval(&c.original, None, &c.target);
    let p = c.proposal(&a, c.initial, 75);
    c.prepare(p, &a).expect("prepare");
    let before = c.fingerprint();
    for op in [
        AnchorOperation::advance(c.initial, [76; 32]).expect("advance"),
        AnchorOperation::fence_writer(c.initial).expect("fence"),
        AnchorOperation::acknowledge_policy_renewal(&p),
    ] {
        let rq = AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("rq");
        assert!(c.store.handle(rq.as_bytes(), 170).is_err());
        assert_eq!(c.fingerprint(), before);
    }
    let rq = AnchorRequest::new(
        &c.pin,
        c.subject,
        AnchorOperation::commit_policy_renewal(&p),
        &c.signer,
    )
    .expect("rq");
    assert!(matches!(
        c.store.handle(rq.as_bytes(), 260),
        Err(AnchorError::Rejected(Error::Validity))
    ));
    assert_eq!(c.fingerprint(), before);
    assert_eq!(
        c.exchange(&p, AnchorOperation::policy_renewal_status(&p), 300),
        State::Prepared
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::close_policy_renewal(&p), 300),
        State::Closed
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 300),
        State::Closed
    );
}
#[test]
fn independent_policy_rejects_substituted_proposal_and_legacy_credential_identity() {
    let mut c = Case::new();
    let a = c.approval(&c.original, None, &c.target);
    let p = c.proposal(&a, c.initial, 77);
    let before = c.fingerprint();
    let mut changed = p;
    changed.statement = [78; 32];
    assert!(c.prepare(changed, &a).is_err());
    let mut changed = p;
    changed.operation = PolicyRenewalId::generate().expect("other operation");
    assert!(c.prepare(changed, &a).is_err());
    let mut changed = p;
    changed.witness = [79; 32];
    assert!(c.prepare(changed, &a).is_err());
    assert_eq!(c.fingerprint(), before);
    c.prepare(p, &a).expect("original");
    let before = c.fingerprint();
    let changed = c.proposal(&a, c.initial, 80);
    assert!(c.prepare(changed, &a).is_err());
    assert_eq!(c.fingerprint(), before);
    let g = crate::AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.subject,
        crate::CredentialRenewalId::from_trusted_state(*a.scope().operation.as_bytes())
            .expect("same bytes different type"),
        a.statement_digest(),
        c.initial,
        p.target_head(),
    )
    .expect("legacy metadata");
    assert_ne!(g.binding(), p.binding());
    assert!(Proposal::from_trusted_state(&g.to_bytes()).is_err());
    assert!(crate::AnchorCredentialRenewalProposal::from_trusted_state(&p.to_bytes()).is_err());
    let rq = AnchorRequest::new(
        &c.pin,
        c.subject,
        AnchorOperation::commit_credential_renewal(&g),
        &c.signer,
    )
    .expect("legacy rq");
    let wire = c
        .store
        .handle(rq.as_bytes(), 170)
        .expect("honest unavailable");
    let response = c.pin.verify_reply(&rq, &wire).expect("signed");
    assert_eq!(response.outcome(), AnchorOutcome::CredentialUnavailable);
    assert!(response.policy_renewal_state(&p).is_err());
    assert_eq!(c.fingerprint(), before);
    let rq = AnchorRequest::new(
        &c.pin,
        c.subject,
        AnchorOperation::policy_renewal_status(&p),
        &c.signer,
    )
    .expect("rq");
    let wire = c.store.handle(rq.as_bytes(), 170).expect("reply");
    let response = c.pin.verify_reply(&rq, &wire).expect("signed");
    assert!(response.credential_renewal_state(&g).is_err());
    assert!(
        c.pin.verify_reply(&rq, &wire).is_err(),
        "attempt consumed exactly once"
    );
}
#[test]
fn independent_policy_public_encoding_is_bounded_and_canonical() {
    let c = Case::new();
    let a = c.approval(&c.original, None, &c.target);
    let p = c.proposal(&a, c.initial, 81);
    let wire = p.to_bytes();
    assert_eq!(wire.len(), 296);
    for n in 0..wire.len() {
        assert!(Proposal::from_trusted_state(wire.get(..n).expect("prefix")).is_err())
    }
    let mut longer = wire.clone();
    longer.push(0);
    assert!(Proposal::from_trusted_state(&longer).is_err());
    for op in [
        AnchorOperation::commit_policy_renewal(&p),
        AnchorOperation::policy_renewal_status(&p),
        AnchorOperation::close_policy_renewal(&p),
        AnchorOperation::acknowledge_policy_renewal(&p),
        AnchorOperation::admit_policy_renewal(c.device.authority_binding(), p.statement())
            .expect("admit"),
    ] {
        let wire = op.to_bytes();
        assert_eq!(wire.len(), 97);
        assert_eq!(
            AnchorOperation::from_trusted_state(&wire).expect("roundtrip"),
            op
        );
        for n in 0..wire.len() {
            assert!(AnchorOperation::from_trusted_state(wire.get(..n).expect("prefix")).is_err())
        }
        let mut dirty = wire.clone();
        *dirty.last_mut().expect("tail") = 1;
        assert!(AnchorOperation::from_trusted_state(&dirty).is_err());
    }
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Prepare,
    CloseUnprepared,
    Commit,
    ClosePrepared,
    AcknowledgeApplied,
    AcknowledgeClosed,
}
#[derive(Debug)]
enum MutationFailure {
    Durable(DurableError),
    Request(AnchorError),
}
impl Mutation {
    fn setup(self, c: &mut Case, p: Proposal, a: &VerifiedPolicyRenewal) {
        if !matches!(self, Self::Prepare | Self::CloseUnprepared) {
            c.prepare(p, a).expect("original prepared state");
        }
        match self {
            Self::AcknowledgeApplied => {
                assert_eq!(
                    c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170),
                    State::Applied
                );
            }
            Self::AcknowledgeClosed => {
                assert_eq!(
                    c.exchange(&p, AnchorOperation::close_policy_renewal(&p), 170),
                    State::Closed
                );
            }
            _ => {}
        }
    }
    fn run(
        self,
        c: &mut Case,
        p: Proposal,
        a: &VerifiedPolicyRenewal,
    ) -> Result<State, MutationFailure> {
        let op = match self {
            Self::Prepare => return c.prepare(p, a).map_err(MutationFailure::Durable),
            Self::CloseUnprepared => {
                let m = HistoricalPolicyRenewalMaterials {
                    original: &c.original,
                    previous: &c.original,
                    target: c.target.historical(),
                    original_device: &c.device,
                    current_device: &c.device,
                };
                return c
                    .store
                    .close_policy_renewal(p, &a.historical(), &m)
                    .map_err(MutationFailure::Durable);
            }
            Self::Commit => AnchorOperation::commit_policy_renewal(&p),
            Self::ClosePrepared => AnchorOperation::close_policy_renewal(&p),
            Self::AcknowledgeApplied | Self::AcknowledgeClosed => {
                AnchorOperation::acknowledge_policy_renewal(&p)
            }
        };
        let rq = AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("fresh attempt");
        let wire = c
            .store
            .handle(rq.as_bytes(), 170)
            .map_err(MutationFailure::Request)?;
        Ok(c.pin
            .verify_reply(&rq, &wire)
            .expect("real witness signature")
            .policy_renewal_state(&p)
            .expect("exact proposal"))
    }
    fn expected(self) -> State {
        match self {
            Self::Prepare => State::Prepared,
            Self::CloseUnprepared | Self::ClosePrepared => State::Closed,
            Self::Commit => State::Applied,
            Self::AcknowledgeApplied | Self::AcknowledgeClosed => State::Acknowledged,
        }
    }
}
pub(in crate::anchor::store) fn fault(
    c: &mut Case,
    after: bool,
) -> (
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    c.store.close();
    let (db, remaining, count, _) =
        crate::durable::tests::fault_database_path(&c.server.join("anchor.redb"), after);
    let wrapping = JournalKey::open(&c.server.join("wrapping")).expect("original wrap");
    let signer = AnchorSigningKey::open(
        &c.server.join("signer"),
        &wrapping,
        SigningKeyId::from_trusted_state([63; 32]).expect("signer ID"),
    )
    .expect("original signer");
    c.store = AnchorStore {
        active: Some(Active {
            db,
            wrapping,
            signer,
            pin: c.pin.clone(),
        }),
    };
    (remaining, count)
}
#[test]
fn independent_policy_every_sync_failure_recovers_original_prepare_commit_close_and_ack() {
    use std::sync::atomic::Ordering;
    let mut faults = 0;
    for mutation in [
        Mutation::Prepare,
        Mutation::CloseUnprepared,
        Mutation::Commit,
        Mutation::ClosePrepared,
        Mutation::AcknowledgeApplied,
        Mutation::AcknowledgeClosed,
    ] {
        let mut calibration = Case::new();
        let a = calibration.approval(&calibration.original, None, &calibration.target);
        let p = calibration.proposal(&a, calibration.initial, 90);
        mutation.setup(&mut calibration, p, &a);
        let (_, count) = fault(&mut calibration, false);
        assert_eq!(
            mutation.run(&mut calibration, p, &a).expect("calibration"),
            mutation.expected()
        );
        let barriers = count.load(Ordering::SeqCst);
        assert!(
            (1..=8).contains(&barriers),
            "unexpected sync boundary count: {barriers}"
        );
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut c = Case::new();
                let a = c.approval(&c.original, None, &c.target);
                let p = c.proposal(&a, c.initial, 91);
                mutation.setup(&mut c, p, &a);
                let (remaining, _) = fault(&mut c, after);
                remaining.store(cut, Ordering::SeqCst);
                assert!(
                    matches!(
                        mutation.run(&mut c, p, &a),
                        Err(MutationFailure::Durable(DurableError::CommitUncertain(_))
                            | MutationFailure::Request(AnchorError::Storage(
                                DurableError::CommitUncertain(_)
                            )))
                    ),
                    "{mutation:?} after={after} cut={cut}"
                );
                assert_eq!(remaining.load(Ordering::SeqCst), 0);
                assert!(
                    c.store.active.is_none(),
                    "uncertain commit must close store"
                );
                c.reopen();
                assert_eq!(
                    mutation
                        .run(&mut c, p, &a)
                        .expect("same original after uncertainty"),
                    mutation.expected()
                );
                let stable = c.fingerprint();
                assert_eq!(
                    mutation.run(&mut c, p, &a).expect("exact idempotent retry"),
                    mutation.expected()
                );
                assert_eq!(
                    c.fingerprint(),
                    stable,
                    "retry wrote a second witness transition"
                );
                faults += 1;
            }
        }
    }
    eprintln!("INDEPENDENT_POLICY_WITNESS_SYNC mutations=6 before_after_faults={faults} original_retry=true no_second_transition=true");
}

fn open_witness(server: &std::path::Path) -> AnchorStore {
    let key = JournalKey::open(&server.join("wrapping")).expect("original wrap");
    let signer = AnchorSigningKey::open(
        &server.join("signer"),
        &key,
        SigningKeyId::from_trusted_state([63; 32]).expect("original signer ID"),
    )
    .expect("original signer");
    let identity = AnchorIdentity::from_trusted_state(
        fs::read(server.join("instance"))
            .expect("retained instance")
            .try_into()
            .expect("identity width"),
    )
    .expect("same instance");
    AnchorStore::open(&server.join("anchor.redb"), key, signer, identity)
        .expect("reopen original witness")
}

#[test]
fn independent_policy_request_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_INDEPENDENT_POLICY_SERVER_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let mut store = open_witness(&path);
    let wire = fs::read(path.join("request.bin")).expect("original signed request");
    let reply = store.handle(&wire, 170).expect("original command");
    fs::write(path.join("returned-reply"), reply).expect("released acknowledgement");
}
#[test]
fn independent_policy_process_loss_after_commit_preserves_each_exact_terminal_and_ack() {
    use std::{
        process::{Command as Process, Stdio},
        time::{Duration, Instant},
    };
    type RequestConstructor = fn(&Proposal) -> AnchorOperation;
    let requests: [(Mutation, RequestConstructor); 4] = [
        (Mutation::Commit, AnchorOperation::commit_policy_renewal),
        (
            Mutation::ClosePrepared,
            AnchorOperation::close_policy_renewal,
        ),
        (
            Mutation::AcknowledgeApplied,
            AnchorOperation::acknowledge_policy_renewal,
        ),
        (
            Mutation::AcknowledgeClosed,
            AnchorOperation::acknowledge_policy_renewal,
        ),
    ];
    for (mutation, command) in requests {
        let mut c = Case::new();
        let a = c.approval(&c.original, None, &c.target);
        let p = c.proposal(&a, c.initial, 92);
        mutation.setup(&mut c, p, &a);
        let revision = c.fingerprint().0 + 1;
        let op = command(&p);
        let rq =
            AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("original signed attempt");
        fs::write(c.server.join("request.bin"), rq.as_bytes()).expect("retain original request");
        c.store.close();
        let log = fs::File::create(c.server.join("child.log")).expect("log");
        let mut child = crate::durable::tests::ChildGuard(
            Process::new(std::env::current_exe().expect("current test binary"))
                .args([
                    "--exact",
                    "anchor::store::policy_renewal::tests::independent_policy_request_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_INDEPENDENT_POLICY_SERVER_DIR", &c.server)
                .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
                .env("QPERIAPT_ANCHOR_CRASH_REVISION", revision.to_string())
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned witness process"),
        );
        let until = Instant::now() + Duration::from_secs(20);
        while !c.server.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child state").is_none() && Instant::now() < until,
                "witness cut not reached: {mutation:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !c.server.join("returned-reply").exists(),
            "signed acknowledgement escaped before cut"
        );
        child.0.kill().expect("kill owned witness");
        assert!(!child.0.wait().expect("reap child").success());
        c.reopen();
        assert_eq!(
            c.fingerprint().0,
            revision,
            "transaction committed before process loss"
        );
        assert_eq!(
            mutation
                .run(&mut c, p, &a)
                .expect("original fresh-attempt recovery"),
            mutation.expected()
        );
        assert_eq!(
            c.fingerprint().0,
            revision,
            "retry performed a second transaction"
        );
    }
    eprintln!("INDEPENDENT_POLICY_WITNESS_PROCESS cuts=4 commit_close_and_both_acks=true no_reply_escaped=true exact_original_retry=true");
}

#[test]
fn independent_policy_roster_refresh_preserves_current_p_and_rejects_stale_authority() {
    let mut c = Case::new();
    let a = c.approval(&c.original, None, &c.target);
    let p = c.proposal(&a, c.initial, 95);
    c.prepare(p, &a).expect("prepare");
    assert_eq!(
        c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170),
        State::Applied
    );
    let roster = c
        .account
        .issue_roster(
            2,
            Validity::new(100, 400).expect("interval"),
            &[c.account.roster_entry(&c.certificate).expect("same member")],
        )
        .expect("new signed roster");
    let next = AccountPin::new(
        c.account.account_id().expect("account"),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        c.original.family(),
    )
    .expect("independent next pin")
    .verify_device(&c.certificate, roster.as_bytes(), 170)
    .expect("current same credential");
    assert!(matches!(
        c.store.update_roster_authority(
            c.subject,
            c.device.roster().checkpoint(),
            &next,
            &c.target,
            170
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        c.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 170),
        State::Acknowledged
    );
    assert_eq!(
        c.store
            .update_roster_authority(
                c.subject,
                c.device.roster().checkpoint(),
                &next,
                &c.target,
                170
            )
            .expect("adopt real newer roster"),
        roster.checkpoint()
    );
    c.reopen();
    assert_eq!(
        c.admission(
            AnchorOperation::admit_policy_renewal(
                c.device.authority_binding(),
                a.statement_digest()
            )
            .expect("old"),
            170
        ),
        AnchorOutcome::AuthorityDenied
    );
    assert_eq!(
        c.admission(
            AnchorOperation::admit_policy_renewal(next.authority_binding(), a.statement_digest())
                .expect("new"),
            170
        ),
        AnchorOutcome::AuthorityCurrent
    );
    let p2 = policy(&c.issuer, &c.runtime, &c.pin, 3, 350, 170);
    let mut scope = a.scope().clone();
    scope.operation = PolicyRenewalId::generate().expect("new P operation");
    scope.previous_policy = c.target.checkpoint();
    scope.previous_authorization = Some(a.statement_digest());
    scope.current_roster = roster.checkpoint();
    let materials = PolicyRenewalMaterials {
        original: &c.original,
        previous: c.target.historical(),
        target: &p2,
        original_device: &c.device,
        current_device: &next,
    };
    let statement = PolicyRenewalStatement::new(&scope, &materials, 170)
        .expect("unchanged credential, actual roster");
    let next_approval = VerifiedPolicyRenewal::verify(
        &c.account
            .approve_policy_renewal(&statement)
            .expect("account"),
        &c.issuer.approve_policy_renewal(&statement).expect("policy"),
        &scope,
        &materials,
        170,
    )
    .expect("independent approval");
    let proposal = c.proposal(&next_approval, p.target_head(), 96);
    assert_eq!(
        c.store
            .prepare_policy_renewal(proposal, &next_approval, &materials, 170)
            .expect("new P at actual roster"),
        State::Prepared
    );
    assert_eq!(
        c.exchange(
            &proposal,
            AnchorOperation::commit_policy_renewal(&proposal),
            170
        ),
        State::Applied
    );
}
