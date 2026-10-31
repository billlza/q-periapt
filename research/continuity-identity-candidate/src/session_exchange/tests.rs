// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountPin, BootstrapBundle, BootstrapMaterials, BootstrapRequirements, DeviceDescription,
    DeviceEnrollment, DirectoryExpectation, EnrollmentIntent, EnrollmentPaths, ExpectedDevice,
    InstallationPaths, JournalKey, LeafKind, PrekeyPublicationKey, PrekeyPublicationPlan,
    PrekeyPublicationRun, PrekeyQuality, RootSigningKey, VerifiedEnrollmentRequest,
    VerifiedSessionPolicy,
};
use std::{collections::BTreeMap, path::Path};
mod account;
mod control;
mod delivery;

struct Device {
    _dir: tempfile::TempDir,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    certificate: Vec<u8>,
    roster: Vec<u8>,
    pin: AccountPin,
    account: [u8; 32],
    owner: EnrolledDevice,
}
impl Device {
    fn new(policy: &VerifiedSessionPolicy) -> Self {
        Self::account(policy, 1)
            .pop()
            .expect("one registered device")
    }
    fn account(policy: &VerifiedSessionPolicy, count: u8) -> Vec<Self> {
        let root = RootSigningKey::generate().expect("account root");
        let mut staged = Vec::new();
        for index in 0..count {
            let dir = crate::durable::tests::directory();
            let base = dir.path().canonicalize().expect("path");
            let paths = paths(&base);
            drop(JournalKey::provision(&base.join("key")).expect("wrapping key"));
            let intent = EnrollmentIntent::new(
                root.public_key().expect("public root"),
                DeviceDescription::new(
                    [7 + index; 16],
                    1,
                    policy.family(),
                    crate::tests::interval(),
                )
                .expect("intent"),
            );
            let mut pending =
                DeviceEnrollment::provision(paths.clone(), intent.clone()).expect("provision");
            let request = pending.request(150).expect("request");
            let request =
                VerifiedEnrollmentRequest::verify(&request, &intent, 150).expect("verify request");
            let certificate = root.issue_enrollment(&request, 150).expect("issue");
            staged.push((dir, paths, intent, certificate, pending));
        }
        let entries = staged
            .iter()
            .map(|(_, _, _, certificate, _)| root.roster_entry(certificate).expect("entry"))
            .collect::<Vec<_>>();
        let roster = root
            .issue_roster(1, crate::tests::interval(), &entries)
            .expect("complete roster");
        staged
            .into_iter()
            .map(|(dir, paths, intent, certificate, mut pending)| {
                let pin = AccountPin::new(
                    root.account_id().expect("account"),
                    root.public_key().expect("root"),
                    roster.checkpoint(),
                    policy.family(),
                )
                .expect("pin");
                pending
                    .accept(&certificate, roster.as_bytes(), &pin, policy, 150)
                    .expect("accept");
                pending.prepare(policy, 150).expect("prepare");
                let owner = pending.activate(policy, 150, None).expect("activate");
                Self {
                    _dir: dir,
                    paths,
                    intent,
                    certificate,
                    roster: roster.as_bytes().to_vec(),
                    pin,
                    account: root.account_id().expect("account"),
                    owner,
                }
            })
            .collect()
    }
    fn reopen(&mut self, policy: &VerifiedSessionPolicy) {
        self.owner.close();
        self.owner = DeviceEnrollment::open(self.paths.clone(), self.intent.clone())
            .expect("same enrollment")
            .activate(policy, 150, None)
            .expect("same installation");
    }
}
fn paths(base: &Path) -> EnrollmentPaths {
    EnrollmentPaths::new(
        &base.join("key"),
        &base.join("signer"),
        &base.join("enrollment"),
        InstallationPaths::new(
            &base.join("installation"),
            &base.join("journal"),
            &base.join("archives"),
        )
        .expect("children"),
    )
    .expect("paths")
}
struct Pair {
    a: Device,
    b: Device,
    policy: Arc<VerifiedSessionPolicy>,
    bundle: BootstrapBundle,
}
impl Pair {
    fn new() -> Self {
        let (_, issued, pin, runtime) =
            crate::tests::session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
        let policy = Arc::new(pin.verify(issued.as_bytes(), runtime, 150).expect("policy"));
        let a = Device::new(&policy);
        let mut b = Device::new(&policy);
        let bundle = bundle(&a, &mut b, &policy);
        Self {
            a,
            b,
            policy,
            bundle,
        }
    }
    fn required(&self) -> BootstrapRequirements<'_> {
        BootstrapRequirements {
            initiator: ExpectedDevice::new(&self.a.pin, [7; 16], 1).expect("a"),
            responder: ExpectedDevice::new(&self.b.pin, [7; 16], 1).expect("b"),
            quality: PrekeyQuality::OneTimeBoth,
            directory: DirectoryExpectation::from_trusted_state([77; 32]).expect("directory"),
        }
    }
    fn peers(&mut self) -> (BootstrapPeer, BootstrapPeer) {
        let a = Arc::new(
            self.bundle
                .verify(Arc::clone(&self.policy), self.required(), 150)
                .expect("a bundle"),
        );
        let b = Arc::new(
            self.bundle
                .verify(Arc::clone(&self.policy), self.required(), 150)
                .expect("b bundle"),
        );
        (
            self.a
                .owner
                .parts()
                .expect("a")
                .0
                .admit_peer(a, BootstrapRole::Initiator, 150)
                .expect("a peer"),
            self.b
                .owner
                .parts()
                .expect("b")
                .0
                .admit_peer(b, BootstrapRole::Responder, 150)
                .expect("b peer"),
        )
    }
    fn reopened(&mut self, id: [u8; 32]) -> (Session, Session) {
        let a = self
            .bundle
            .request_reopen(
                Arc::clone(&self.policy),
                self.required(),
                BootstrapRole::Initiator,
                id,
                150,
            )
            .expect("a request");
        let b = self
            .bundle
            .request_reopen(
                Arc::clone(&self.policy),
                self.required(),
                BootstrapRole::Responder,
                id,
                150,
            )
            .expect("b request");
        (
            Session::from_reopened(
                &self
                    .a
                    .owner
                    .parts()
                    .expect("a")
                    .0
                    .reopen_peer(a, 150)
                    .expect("a reopen"),
            ),
            Session::from_reopened(
                &self
                    .b
                    .owner
                    .parts()
                    .expect("b")
                    .0
                    .reopen_peer(b, 150)
                    .expect("b reopen"),
            ),
        )
    }
}
#[derive(Default)]
struct Effects {
    entries: BTreeMap<MessageId, Vec<u8>>,
    calls: usize,
    fail: bool,
}
impl Consumer for Effects {
    fn commit(&mut self, _: [u8; 32], delivery: &CommittedPlaintext) -> io::Result<()> {
        self.calls += 1;
        if let Some(old) = self.entries.get(&delivery.message_id()) {
            assert_eq!(old, delivery.as_bytes());
        } else {
            self.entries
                .insert(delivery.message_id(), delivery.as_bytes().to_vec());
        }
        if self.fail {
            return Err(io::Error::other("effect outcome unknown"));
        }
        Ok(())
    }
}
struct Carrier<'a> {
    owner: &'a mut EnrolledDevice,
    peer: &'a BootstrapPeer,
    effects: &'a mut Effects,
    corrupt: bool,
    lose: bool,
    requests: Vec<Vec<u8>>,
}
impl Transport for Carrier<'_> {
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: Instant,
        cancel: &Cancellation,
    ) -> io::Result<Vec<u8>> {
        self.requests.push(request.to_vec());
        let mut reply = self
            .owner
            .serve_session_exchange(
                self.peer,
                request,
                self.effects,
                &Run { deadline, cancel },
                || Ok(150),
            )
            .map_err(io::Error::other)?;
        if codec::open(request).expect("frame").0 == FINAL {
            if self.lose {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if self.corrupt {
                *reply.last_mut().expect("proof") ^= 1;
            }
        }
        Ok(reply)
    }
}
fn run(cancel: &Cancellation) -> Run<'_> {
    Run::new(cancel, Duration::from_secs(30)).expect("run")
}

#[test]
fn confirmed_bootstrap_reopens_and_delivers_in_both_directions_without_duplicate_effects() {
    let mut pair = Pair::new();
    let (a, b) = pair.peers();
    let cancel = Cancellation::default();
    let mut effects = Effects::default();
    let mut carrier = Carrier {
        owner: &mut pair.b.owner,
        peer: &b,
        effects: &mut effects,
        corrupt: false,
        lose: false,
        requests: vec![],
    };
    let session = pair
        .a
        .owner
        .establish_session(
            &a,
            InitiationId::generate().expect("id"),
            &mut carrier,
            &run(&cancel),
            || Ok(150),
        )
        .expect("establish");
    let id = pair
        .a
        .owner
        .next_session_message_id(&session, 150)
        .expect("message id");
    assert_eq!(
        pair.a
            .owner
            .deliver_session_message(
                &session,
                Submission {
                    message: id,
                    plaintext: b"original",
                    associated_data: b"bound"
                },
                &mut carrier,
                &run(&cancel),
                || Ok(150)
            )
            .expect("delivery"),
        Consumption::Confirmed
    );
    let duplicate = carrier.requests.last().expect("message").clone();
    drop(carrier);
    pair.b
        .owner
        .serve_session_exchange(&b, &duplicate, &mut effects, &run(&cancel), || Ok(150))
        .expect("duplicate");
    assert_eq!(effects.calls, 1);
    pair.a.reopen(&pair.policy);
    pair.b.reopen(&pair.policy);
    let (a_session, b_session) = pair.reopened(session.id());
    struct Reverse<'a> {
        owner: &'a mut EnrolledDevice,
        session: &'a Session,
        effects: &'a mut Effects,
    }
    impl Transport for Reverse<'_> {
        fn exchange(
            &mut self,
            wire: &[u8],
            deadline: Instant,
            cancel: &Cancellation,
        ) -> io::Result<Vec<u8>> {
            self.owner
                .serve_session_message(
                    self.session,
                    wire,
                    self.effects,
                    &Run { deadline, cancel },
                    || Ok(150),
                )
                .map_err(io::Error::other)
        }
    }
    let mut reverse_effects = Effects::default();
    let id = pair
        .b
        .owner
        .next_session_message_id(&b_session, 150)
        .expect("reverse id");
    let mut reverse = Reverse {
        owner: &mut pair.a.owner,
        session: &a_session,
        effects: &mut reverse_effects,
    };
    assert_eq!(
        pair.b
            .owner
            .deliver_session_message(
                &b_session,
                Submission {
                    message: id,
                    plaintext: b"reverse",
                    associated_data: b""
                },
                &mut reverse,
                &run(&cancel),
                || Ok(150)
            )
            .expect("reverse"),
        Consumption::Confirmed
    );
    assert_eq!(reverse_effects.calls, 1);
}

#[test]
fn tampered_ready_proof_closes_owner_and_exact_retry_recovers_committed_original() {
    for lose in [false, true] {
        let mut pair = Pair::new();
        let (a, b) = pair.peers();
        let cancel = Cancellation::default();
        let mut effects = Effects::default();
        let id = InitiationId::generate().expect("id");
        let mut carrier = Carrier {
            owner: &mut pair.b.owner,
            peer: &b,
            effects: &mut effects,
            corrupt: !lose,
            lose,
            requests: vec![],
        };
        let error = pair
            .a
            .owner
            .establish_session(&a, id, &mut carrier, &run(&cancel), || Ok(150))
            .err()
            .expect("reject");
        if lose {
            assert!(matches!(error, Error::Transport(_)));
        } else {
            assert!(matches!(
                error,
                Error::Durable(DurableError::Protocol(crate::Error::Authentication))
            ));
        }
        assert!(pair.a.owner.parts().is_err());
        let original = carrier.requests;
        pair.a.reopen(&pair.policy);
        let (a, b) = pair.peers();
        let mut retry = Carrier {
            owner: &mut pair.b.owner,
            peer: &b,
            effects: &mut effects,
            corrupt: false,
            lose: false,
            requests: vec![],
        };
        pair.a
            .owner
            .establish_session(&a, id, &mut retry, &run(&cancel), || Ok(150))
            .expect("exact recovery");
        assert_eq!(original, retry.requests);
        assert_eq!(effects.calls, 0);
    }
}

#[test]
fn cancelled_admission_dispatches_nothing_and_closes_owner() {
    let mut pair = Pair::new();
    let (a, b) = pair.peers();
    let cancel = Cancellation::default();
    cancel.cancel();
    let mut effects = Effects::default();
    let mut carrier = Carrier {
        owner: &mut pair.b.owner,
        peer: &b,
        effects: &mut effects,
        corrupt: false,
        lose: false,
        requests: vec![],
    };
    assert!(matches!(
        pair.a.owner.establish_session(
            &a,
            InitiationId::generate().expect("id"),
            &mut carrier,
            &run(&cancel),
            || Ok(150)
        ),
        Err(Error::Cancelled)
    ));
    assert!(carrier.requests.is_empty());
    assert!(pair.a.owner.parts().is_err());
}

#[test]
fn carrier_versions_and_unbounded_frames_are_rejected() {
    let mut frame = frame(INITIAL, b"x").expect("frame");
    for tag in [b"QPCNET01", b"QPCNET02"] {
        frame.get_mut(..8).expect("magic").copy_from_slice(tag);
        assert!(codec::open(&frame).is_err());
    }
    assert!(codec::open(&vec![0; crate::contract::MAX_CONNECTION_FRAME_BYTES + 1]).is_err());
    assert!(codec::split(&[0, 10, 1]).is_err());
}

#[test]
fn unknown_effect_and_lost_ack_recover_the_same_message_without_double_effect() {
    for lose_ack in [false, true] {
        let mut pair = Pair::new();
        let (a, b) = pair.peers();
        let cancel = Cancellation::default();
        let mut effects = Effects::default();
        let mut carrier = Carrier {
            owner: &mut pair.b.owner,
            peer: &b,
            effects: &mut effects,
            corrupt: false,
            lose: false,
            requests: vec![],
        };
        let session = pair
            .a
            .owner
            .establish_session(
                &a,
                InitiationId::generate().expect("id"),
                &mut carrier,
                &run(&cancel),
                || Ok(150),
            )
            .expect("establish");
        drop(carrier);
        let message = pair
            .a
            .owner
            .next_session_message_id(&session, 150)
            .expect("message");
        effects.fail = !lose_ack;
        struct Cut<'a> {
            inner: Carrier<'a>,
            lose: bool,
        }
        impl Transport for Cut<'_> {
            fn exchange(
                &mut self,
                wire: &[u8],
                deadline: Instant,
                cancel: &Cancellation,
            ) -> io::Result<Vec<u8>> {
                let reply = self.inner.exchange(wire, deadline, cancel)?;
                if self.lose {
                    Err(io::ErrorKind::UnexpectedEof.into())
                } else {
                    Ok(reply)
                }
            }
        }
        let mut cut = Cut {
            inner: Carrier {
                owner: &mut pair.b.owner,
                peer: &b,
                effects: &mut effects,
                corrupt: false,
                lose: false,
                requests: vec![],
            },
            lose: lose_ack,
        };
        let input = || Submission {
            message,
            plaintext: b"one original operation",
            associated_data: b"bound",
        };
        assert!(matches!(
            pair.a.owner.deliver_session_message(
                &session,
                input(),
                &mut cut,
                &run(&cancel),
                || Ok(150)
            ),
            Err(Error::Transport(_))
        ));
        let original = cut.inner.requests;
        assert_eq!(original.len(), 1);
        assert!(pair.a.owner.parts().is_err());
        if !lose_ack {
            assert!(pair.b.owner.parts().is_err());
        }
        assert_eq!(effects.entries.len(), 1);
        assert_eq!(effects.calls, 1);
        pair.a.reopen(&pair.policy);
        pair.b.reopen(&pair.policy);
        let (session, _) = pair.reopened(session.id());
        assert_eq!(
            pair.a
                .owner
                .session_message_status(&session, message)
                .expect("original status"),
            MessageStatus::Committed
        );
        effects.fail = false;
        let mut retry = Carrier {
            owner: &mut pair.b.owner,
            peer: &b,
            effects: &mut effects,
            corrupt: false,
            lose: false,
            requests: vec![],
        };
        assert_eq!(
            pair.a
                .owner
                .deliver_session_message(&session, input(), &mut retry, &run(&cancel), || Ok(150))
                .expect("recover"),
            Consumption::Confirmed
        );
        assert_eq!(original, retry.requests);
        drop(retry);
        assert_eq!(effects.entries.len(), 1);
        assert_eq!(effects.calls, if lose_ack { 1 } else { 2 });
        assert_eq!(
            pair.a
                .owner
                .session_message_status(&session, message)
                .expect("confirmed ID"),
            MessageStatus::Acknowledged
        );
    }
}

#[test]
fn replayed_valid_prefix_is_pending_not_fabricated_message_consumption() {
    let mut pair = Pair::new();
    let (a, b) = pair.peers();
    let cancel = Cancellation::default();
    let mut effects = Effects::default();
    let mut carrier = Carrier {
        owner: &mut pair.b.owner,
        peer: &b,
        effects: &mut effects,
        corrupt: false,
        lose: false,
        requests: vec![],
    };
    let session = pair
        .a
        .owner
        .establish_session(
            &a,
            InitiationId::generate().expect("id"),
            &mut carrier,
            &run(&cancel),
            || Ok(150),
        )
        .expect("establish");
    drop(carrier);
    let old = pair
        .b
        .owner
        .parts()
        .expect("b")
        .0
        .stores()
        .expect("stores")
        .0
        .message_acknowledgement_for_epoch(b.context(), session.id(), 0, 150)
        .expect("original empty prefix");
    struct Replay(Vec<u8>);
    impl Transport for Replay {
        fn exchange(&mut self, _: &[u8], _: Instant, _: &Cancellation) -> io::Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }
    let message = pair
        .a
        .owner
        .next_session_message_id(&session, 150)
        .expect("id");
    let input = || Submission {
        message,
        plaintext: b"not delivered by replay",
        associated_data: b"",
    };
    assert_eq!(
        pair.a
            .owner
            .deliver_session_message(
                &session,
                input(),
                &mut Replay(frame(ACK, &old).expect("ack")),
                &run(&cancel),
                || Ok(150)
            )
            .expect("authenticated prefix"),
        Consumption::PrefixPending
    );
    assert_eq!(
        pair.a
            .owner
            .session_message_status(&session, message)
            .expect("not consumed"),
        MessageStatus::Committed
    );
    assert!(effects.entries.is_empty());
    let mut real = Carrier {
        owner: &mut pair.b.owner,
        peer: &b,
        effects: &mut effects,
        corrupt: false,
        lose: false,
        requests: vec![],
    };
    assert_eq!(
        pair.a
            .owner
            .deliver_session_message(&session, input(), &mut real, &run(&cancel), || Ok(150))
            .expect("real delivery"),
        Consumption::Confirmed
    );
    assert_eq!(effects.calls, 1);
}

#[test]
fn wrong_owner_and_closed_policy_do_not_release_new_frames() {
    for close_policy in [false, true] {
        let mut pair = Pair::new();
        let (a, b) = pair.peers();
        let cancel = Cancellation::default();
        let mut effects = Effects::default();
        let mut carrier = Carrier {
            owner: &mut pair.b.owner,
            peer: &b,
            effects: &mut effects,
            corrupt: false,
            lose: false,
            requests: vec![],
        };
        let session = pair
            .a
            .owner
            .establish_session(
                &a,
                InitiationId::generate().expect("id"),
                &mut carrier,
                &run(&cancel),
                || Ok(150),
            )
            .expect("establish");
        drop(carrier);
        let message = pair
            .a
            .owner
            .next_session_message_id(&session, 150)
            .expect("id");
        if close_policy {
            pair.policy.close();
        }
        struct NoDispatch;
        impl Transport for NoDispatch {
            fn exchange(&mut self, _: &[u8], _: Instant, _: &Cancellation) -> io::Result<Vec<u8>> {
                unreachable!("invalid authority dispatched")
            }
        }
        let owner = if close_policy {
            &mut pair.a.owner
        } else {
            &mut pair.b.owner
        };
        assert!(owner
            .deliver_session_message(
                &session,
                Submission {
                    message,
                    plaintext: b"refuse",
                    associated_data: b""
                },
                &mut NoDispatch,
                &run(&cancel),
                || Ok(150)
            )
            .is_err());
        assert!(owner.parts().is_err());
    }
}

fn bundle(a: &Device, b: &mut Device, policy: &Arc<VerifiedSessionPolicy>) -> BootstrapBundle {
    let plan = PrekeyPublicationPlan::new(
        [77; 32],
        crate::tests::interval(),
        &[
            LeafKind::SignedClassical,
            LeafKind::LastResortPq,
            LeafKind::OneTimeClassical,
            LeafKind::OneTimePq,
        ]
        .map(|kind| PrekeyPublicationKey::generate(kind, crate::tests::interval())),
    )
    .expect("plan");
    let publication_id = b
        .owner
        .next_prekey_publication_id()
        .expect("publication id");
    let cancel = Cancellation::default();
    let publication = b
        .owner
        .prepare_prekey_publication(
            publication_id,
            &plan,
            policy,
            PrekeyPublicationRun {
                cancel: &cancel,
                deadline: Instant::now() + Duration::from_secs(30),
            },
            || Ok(150),
        )
        .expect("publish");
    let manifest = publication.manifest();
    let device = b
        .pin
        .verify_device(&b.certificate, &b.roster, 150)
        .expect("responder");
    let verified = device
        .verify_manifest(manifest.as_bytes(), 150)
        .expect("manifest");
    let proof_for = |kind| {
        (0..manifest.leaf_count())
            .map(|i| manifest.proof(i).expect("proof"))
            .find(|proof| {
                verified
                    .verify_leaf(proof, 150)
                    .expect("verified leaf")
                    .kind()
                    == kind
            })
            .expect("required role")
            .encode()
            .expect("proof bytes")
    };
    let signed = proof_for(LeafKind::SignedClassical);
    let pq = proof_for(LeafKind::LastResortPq);
    let otc = proof_for(LeafKind::OneTimeClassical);
    let otp = proof_for(LeafKind::OneTimePq);
    let bundle = BootstrapBundle::from_materials(
        PrekeyQuality::OneTimeBoth,
        BootstrapMaterials {
            initiator_credential: &a.certificate,
            initiator_roster: &a.roster,
            responder_credential: &b.certificate,
            responder_roster: &b.roster,
            responder_manifest: manifest.as_bytes(),
            signed_classical: &signed,
            last_resort_pq: &pq,
            one_time_classical: Some(&otc),
            one_time_pq: Some(&otp),
        },
    )
    .expect("bundle");

    bundle
}
