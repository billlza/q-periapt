// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    tests::{interval, session_policy_fixture_with_budget},
    AccountPin, AnchorRequirement, ApplicationSendBudget, ClassicalChoice, DeviceDescription,
    DirectoryExpectation, LeafKind, ManifestContext, PqChoice, PrekeyLeaf, RootSigningKey,
};
use q_periapt_sdk::HybridKey;

mod lifecycle;
mod process;
mod roles;
mod witness;

fn canonical(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path()
        .canonicalize()
        .expect("canonical private directory")
}

struct Fixture {
    local: Arc<VerifiedDevice>,
    local_signer: DeviceSigningKey,
    peers: Vec<Arc<VerifiedDevice>>,
    peer_signers: Vec<DeviceSigningKey>,
    contexts: Vec<Arc<BootstrapContext>>,
    keys: Vec<HybridKey>,
    root: RootSigningKey,
    certificates: Vec<Vec<u8>>,
}
struct Enrollment {
    root: RootSigningKey,
    signers: Vec<DeviceSigningKey>,
    devices: Vec<Arc<VerifiedDevice>>,
    certificates: Vec<Vec<u8>>,
}
fn enrollment(seed: u8, count: u8, family: [u8; 32]) -> Enrollment {
    let root = RootSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("root");
    let mut signers = Vec::new();
    let mut certificates = Vec::new();
    for index in 0..count {
        let signer =
            DeviceSigningKey::deterministic([seed + 2 + index * 2; 32], [seed + 3 + index * 2; 32])
                .expect("device");
        certificates.push(
            root.issue_device(
                DeviceDescription::new([seed + index; 16], 1, family, interval())
                    .expect("description"),
                signer.public_key().expect("public"),
            )
            .expect("certificate"),
        );
        signers.push(signer);
    }
    let entries: Vec<_> = certificates
        .iter()
        .map(|c| root.roster_entry(c).expect("entry"))
        .collect();
    let roster = root.issue_roster(1, interval(), &entries).expect("roster");
    let pin = AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root public"),
        roster.checkpoint(),
        family,
    )
    .expect("pin");
    let devices = certificates
        .iter()
        .map(|c| {
            Arc::new(
                pin.verify_device(c, roster.as_bytes(), 150)
                    .expect("enrolled"),
            )
        })
        .collect();
    Enrollment {
        root,
        signers,
        devices,
        certificates,
    }
}
fn fixture(
    budget: u16,
    same_account: bool,
    public: Option<Vec<[u8; q_periapt_sdk::PUBLIC_KEY_LEN]>>,
) -> Fixture {
    fixture_with_anchor(
        budget,
        same_account,
        public,
        AnchorRequirement::local_only(),
    )
}
fn fixture_with_anchor(
    budget: u16,
    same_account: bool,
    public: Option<Vec<[u8; q_periapt_sdk::PUBLIC_KEY_LEN]>>,
    anchor: AnchorRequirement,
) -> Fixture {
    let (_, issued, pin, runtime) = session_policy_fixture_with_budget(
        &[PrekeyQuality::ReusableBoth],
        anchor,
        ApplicationSendBudget::new(budget).expect("budget"),
    );
    let policy = Arc::new(
        pin.verify(issued.as_bytes(), Arc::clone(&runtime), 150)
            .expect("policy"),
    );
    let Enrollment {
        root,
        signers: mut peer_signers,
        devices: mut peers,
        mut certificates,
    } = enrollment(40, if same_account { 3 } else { 2 }, policy.family());
    let (local_signer, local) = if same_account {
        certificates.remove(0);
        (peer_signers.remove(0), peers.remove(0))
    } else {
        let Enrollment {
            mut signers,
            mut devices,
            ..
        } = enrollment(20, 1, policy.family());
        (signers.remove(0), devices.remove(0))
    };
    let mut contexts = Vec::new();
    let mut keys = Vec::new();
    for (index, (signer, peer)) in peer_signers.iter().zip(&peers).enumerate() {
        let key = runtime.generate_key().expect("prekey owner");
        let bytes = match &public {
            Some(keys) => *keys.get(index).expect("restored public"),
            None => key.public_key().expect("public").to_bytes(),
        };
        let (pq, classical) = bytes.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        let leaves = [
            PrekeyLeaf::new(LeafKind::SignedClassical, classical, interval()).expect("classical"),
            PrekeyLeaf::new(LeafKind::LastResortPq, pq, interval()).expect("PQ"),
        ];
        let manifest = signer
            .issue_manifest(
                peer,
                ManifestContext::new(
                    1,
                    runtime.trusted_state().digest(),
                    crate::bootstrap_suite_digest(),
                    [99; 32],
                    interval(),
                )
                .expect("manifest context"),
                &leaves,
            )
            .expect("manifest");
        let verified = peer
            .verify_manifest(manifest.as_bytes(), 150)
            .expect("verified manifest");
        let proofs: Vec<_> = (0..manifest.leaf_count())
            .map(|index| {
                let proof = manifest.proof(index).expect("proof");
                (
                    verified
                        .verify_leaf(&proof, 150)
                        .expect("authenticated leaf")
                        .kind(),
                    proof,
                )
            })
            .collect();
        let classical = &proofs
            .iter()
            .find(|(kind, _)| *kind == LeafKind::SignedClassical)
            .expect("classical role")
            .1;
        let pq = &proofs
            .iter()
            .find(|(kind, _)| *kind == LeafKind::LastResortPq)
            .expect("PQ role")
            .1;
        let selection = Arc::new(
            verified
                .select_prekeys(
                    classical,
                    pq,
                    ClassicalChoice::SignedOnly,
                    PqChoice::LastResort,
                    150,
                )
                .expect("selection"),
        );
        contexts.push(Arc::new(
            BootstrapContext::new(
                Arc::clone(&policy),
                Arc::clone(&local),
                Arc::clone(peer),
                selection,
                DirectoryExpectation::from_trusted_state([99; 32]).expect("directory"),
                150,
            )
            .expect("context"),
        ));
        keys.push(key);
    }
    Fixture {
        local,
        local_signer,
        peers,
        peer_signers,
        contexts,
        keys,
        root,
        certificates,
    }
}
struct Network {
    f: Fixture,
    sender: DeviceJournal,
    receivers: Vec<DeviceJournal>,
    sessions: Vec<[u8; 32]>,
    sender_path: std::path::PathBuf,
    _sender_dir: tempfile::TempDir,
    receiver_dirs: Vec<tempfile::TempDir>,
}
impl Network {
    fn new(budget: u16, same_account: bool) -> Self {
        let f = fixture(budget, same_account, None);
        Self::with_fixture(f, |path, device, _| new_store(path, device))
    }
    fn with_fixture(
        f: Fixture,
        mut provision: impl FnMut(
            &Path,
            &VerifiedDevice,
            &crate::VerifiedSessionPolicy,
        ) -> DeviceJournal,
    ) -> Self {
        let sender_dir = directory();
        let sender_path = canonical(&sender_dir);
        let mut sender = provision(
            &sender_path,
            &f.local,
            f.contexts.first().expect("context").policy(),
        );
        let mut receivers = Vec::new();
        let mut sessions = Vec::new();
        let mut receiver_dirs = Vec::new();
        for (((context, device), signer), key) in f
            .contexts
            .iter()
            .zip(&f.peers)
            .zip(&f.peer_signers)
            .zip(&f.keys)
        {
            let dir = directory();
            let mut receiver = provision(&canonical(&dir), device, context.policy());
            let request = InitiationId::generate().expect("request");
            let initial = sender
                .initiate(Arc::clone(context), request, &f.local_signer, 150)
                .expect("initial");
            let reply = receiver
                .respond(
                    Arc::clone(context),
                    &initial,
                    signer,
                    PqKeySource::from_key(key),
                    TraditionalKeySource::from_key(key),
                    150,
                )
                .expect("reply");
            let final_wire = sender
                .accept_reply(Arc::clone(context), request, &reply, 150)
                .expect("final");
            let session = final_wire.session_id();
            receiver
                .finish(
                    Arc::clone(context),
                    &initial,
                    final_wire.final_message(),
                    150,
                )
                .expect("finish");
            assert_eq!(
                sender
                    .activate_initiator_messages(Arc::clone(context), request, 150)
                    .expect("sender messages"),
                session
            );
            assert_eq!(
                receiver
                    .activate_responder_messages(Arc::clone(context), &initial, 150)
                    .expect("peer messages"),
                session
            );
            receivers.push(receiver);
            sessions.push(session);
            receiver_dirs.push(dir);
        }
        Self {
            f,
            sender,
            receivers,
            sessions,
            sender_path,
            _sender_dir: sender_dir,
            receiver_dirs,
        }
    }
    fn send(&mut self, id: FanoutId, plaintext: &[u8]) -> Result<Vec<FanoutMember>, DurableError> {
        let targets = targets(&self.f, &self.sessions);
        self.sender.send_account_message(
            FanoutInput {
                id,
                account: self.f.peers.first().expect("peer").account_id(),
                targets: &targets,
                plaintext,
                associated_data: b"account-message",
            },
            150,
        )
    }
    fn check_delivery(&mut self, results: &[FanoutMember], plaintext: &[u8]) {
        assert_eq!(results.len(), self.receivers.len());
        for (index, member) in results.iter().enumerate() {
            assert_eq!(
                member.device,
                self.f.peers.get(index).expect("peer").device_id()
            );
            let wire = committed_wire(member);
            let delivered = self
                .receivers
                .get_mut(index)
                .expect("receiver")
                .receive_message(
                    self.f.contexts.get(index).expect("context"),
                    *self.sessions.get(index).expect("session"),
                    wire,
                    b"account-message",
                    150,
                )
                .expect("peer receives");
            assert_eq!(delivered.as_bytes(), plaintext);
            assert_eq!(delivered.message_id(), member.message);
        }
    }
    fn reopen(&mut self) {
        self.sender.close();
        self.sender = reopen(&self.sender_path, &self.f.local);
    }
}
fn targets<'a>(f: &'a Fixture, sessions: &'a [[u8; 32]]) -> Vec<FanoutTarget<'a>> {
    f.contexts
        .iter()
        .zip(sessions)
        .map(|(context, session)| FanoutTarget {
            context,
            session: *session,
        })
        .collect()
}
fn committed_wire(member: &FanoutMember) -> &Vec<u8> {
    match &member.output {
        FanoutOutput::Committed(wire) => Ok(wire),
        _ => Err("expected a committed member, got a terminal or suspended outcome"),
    }
    .expect("exact committed wire")
}
fn wires(results: &[FanoutMember]) -> Vec<Vec<u8>> {
    results
        .iter()
        .map(|member| committed_wire(member).clone())
        .collect()
}

#[test]
fn account_fanout_is_complete_exact_and_durable_for_peer_and_own_accounts() {
    for same_account in [false, true] {
        let mut n = Network::new(4, same_account);
        let id = n.sender.next_fanout_id().expect("next ID");
        assert_eq!(
            n.sender.fanout_status(id).expect("absent"),
            FanoutStatus::Absent
        );
        let results = n.send(id, b"all required devices").expect("aggregate");
        n.check_delivery(&results, b"all required devices");
        assert_eq!(
            n.sender.fanout_status(id).expect("state"),
            FanoutStatus::Committed
        );
        let saved = wires(&results);
        assert_eq!(
            wires(&n.send(id, b"all required devices").expect("exact retry")),
            saved
        );
        assert!(matches!(
            n.send(id, b"replacement"),
            Err(DurableError::Conflict)
        ));
        n.reopen();
        assert_eq!(
            wires(&n.send(id, b"all required devices").expect("restart")),
            saved
        );
        for session in &n.sessions {
            assert_eq!(
                state(&mut n.sender, session)
                    .traffic(0)
                    .expect("traffic")
                    .sent,
                1
            );
        }
        let targets = targets(&n.f, &n.sessions);
        assert!(matches!(
            n.sender.retire_fanout(id, &targets),
            Err(DurableError::Suspended)
        ));
        for (index, member) in results.iter().enumerate() {
            n.receivers
                .get_mut(index)
                .expect("receiver")
                .consume_message(
                    n.f.contexts.get(index).expect("context"),
                    *n.sessions.get(index).expect("session"),
                    member.message,
                    150,
                )
                .expect("consume");
            let ack = n
                .receivers
                .get_mut(index)
                .expect("receiver")
                .message_acknowledgement(
                    n.f.contexts.get(index).expect("context"),
                    *n.sessions.get(index).expect("session"),
                    150,
                )
                .expect("authenticated ACK");
            n.sender
                .accept_message_acknowledgement(
                    n.f.contexts.get(index).expect("context"),
                    *n.sessions.get(index).expect("session"),
                    &ack,
                    150,
                )
                .expect("ack");
        }
        let replay = n
            .sender
            .resume_account_message(id, &targets, 150)
            .expect("all explicit outcomes");
        assert!(replay
            .iter()
            .all(|m| matches!(m.output, FanoutOutput::Acknowledged)));
        n.sender
            .retire_fanout(id, &targets)
            .expect("retire terminal metadata");
        n.reopen();
        assert_eq!(
            n.sender.fanout_status(id).expect("retired"),
            FanoutStatus::Retired
        );
        assert!(matches!(
            n.send(id, b"all required devices"),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert_ne!(n.sender.next_fanout_id().expect("monotonic ID"), id);
        assert_eq!(n.receiver_dirs.len(), 2);
    }
}

#[test]
fn account_fanout_refuses_omitted_duplicate_wrong_session_and_expired_inputs_before_reservation() {
    let mut n = Network::new(4, false);
    let id = n.sender.next_fanout_id().expect("ID");
    let before = n.sender.image().expect("image").revision;
    for mode in 0..4 {
        let mut selected = targets(&n.f, &n.sessions);
        match mode {
            0 => {
                selected.pop();
            }
            1 => {
                *selected.get_mut(1).expect("second target") = FanoutTarget {
                    context: selected.first().expect("first target").context,
                    session: selected.first().expect("first target").session,
                };
            }
            2 => {
                selected.get_mut(1).expect("second target").session =
                    selected.first().expect("first target").session;
            }
            _ => {}
        }
        let result = n.sender.send_account_message(
            FanoutInput {
                id,
                account: n.f.peers.first().expect("peer").account_id(),
                targets: &selected,
                plaintext: b"required set",
                associated_data: b"account-message",
            },
            if mode == 3 { 201 } else { 150 },
        );
        match mode {
            0 => assert!(matches!(
                result,
                Err(DurableError::Protocol(Error::PolicyDenied))
            )),
            1 | 2 => assert!(matches!(result, Err(DurableError::Conflict))),
            _ => assert!(matches!(
                result,
                Err(DurableError::Protocol(Error::Validity))
            )),
        }
        assert_eq!(n.sender.image().expect("unchanged").revision, before);
        assert_eq!(
            n.sender.fanout_status(id).expect("absent"),
            FanoutStatus::Absent
        );
    }
    n.send(id, b"required set")
        .expect("original complete set remains available");
}

#[test]
fn account_fanout_preflight_prevents_the_unary_loop_partial_release_counterexample() {
    let mut n = Network::new(1, false);
    let last = n
        .sender
        .next_message_id(
            n.f.contexts.get(1).expect("context"),
            *n.sessions.get(1).expect("session"),
            150,
        )
        .expect("last slot");
    n.sender
        .send_message(
            n.f.contexts.get(1).expect("context"),
            *n.sessions.get(1).expect("session"),
            last,
            b"already spent",
            b"account-message",
            150,
        )
        .expect("spend last peer budget");
    let id = n.sender.next_fanout_id().expect("aggregate ID");
    let before = n.sender.image().expect("image").revision;
    assert!(matches!(
        n.send(id, b"must reach every device"),
        Err(DurableError::Protocol(Error::RekeyRequired))
    ));
    assert_eq!(n.sender.image().expect("unchanged").revision, before);
    assert_eq!(
        state(&mut n.sender, n.sessions.first().expect("session"))
            .traffic(0)
            .expect("traffic")
            .sent,
        0
    );
    // A loop around the existing unary API has different semantics: it really
    // exposes the first plaintext before discovering the second recipient's failure.
    let first = n
        .sender
        .next_message_id(
            n.f.contexts.first().expect("context"),
            *n.sessions.first().expect("session"),
            150,
        )
        .expect("first slot");
    let wire = n
        .sender
        .send_message(
            n.f.contexts.first().expect("context"),
            *n.sessions.first().expect("session"),
            first,
            b"unsafe unary prefix",
            b"account-message",
            150,
        )
        .expect("unary prefix");
    assert_eq!(
        n.receivers
            .get_mut(0)
            .expect("receiver")
            .receive_message(
                n.f.contexts.first().expect("context"),
                *n.sessions.first().expect("session"),
                &wire,
                b"account-message",
                150
            )
            .expect("actual prefix disclosure")
            .as_bytes(),
        b"unsafe unary prefix"
    );
    assert!(matches!(
        n.sender.next_message_id(
            n.f.contexts.get(1).expect("context"),
            *n.sessions.get(1).expect("session"),
            150
        ),
        Err(DurableError::Protocol(Error::RekeyRequired))
    ));
}

#[test]
fn account_fanout_roster_changes_never_silently_change_the_retained_recipient_set() {
    for revoke in [false, true] {
        let mut n = Network::new(4, false);
        let id = n.sender.next_fanout_id().expect("ID");
        n.send(id, b"frozen recipients").expect("committed");
        let entries: Vec<_> =
            n.f.certificates
                .iter()
                .take(if revoke { 1 } else { 2 })
                .map(|c| n.f.root.roster_entry(c).expect("entry"))
                .collect();
        let issued =
            n.f.root
                .issue_roster(2, interval(), &entries)
                .expect("updated roster");
        let pin = AccountPin::new(
            n.f.root.account_id().expect("account"),
            n.f.root.public_key().expect("public"),
            issued.checkpoint(),
            n.f.contexts.first().expect("context").policy().family(),
        )
        .expect("pin");
        let roster = pin
            .verify_roster(issued.as_bytes(), 150)
            .expect("authenticated head");
        n.sender.install_roster(&roster, 150).expect("durable head");
        n.reopen();
        let before = n.sender.image().expect("image").revision;
        let targets = targets(&n.f, &n.sessions);
        let result = n.sender.resume_account_message(id, &targets, 150);
        let expected = if revoke {
            Error::Scope
        } else {
            Error::Checkpoint
        };
        assert!(matches!(result, Err(DurableError::Protocol(error)) if error == expected));
        assert_eq!(n.sender.image().expect("unchanged").revision, before);
        assert_eq!(
            n.sender.fanout_status(id).expect("not reset"),
            FanoutStatus::Committed
        );
    }
}

#[test]
fn account_fanout_sync_faults_reconcile_all_members_together_at_every_measured_barrier() {
    let mut n = Network::new(4, false);
    let id = n.sender.next_fanout_id().expect("ID");
    n.sender.close();
    let original = &n.sender_path;
    let copy = || {
        let dir = directory();
        for name in ["state.redb", "key", "store-id"] {
            fs::copy(original.join(name), dir.path().join(name)).expect("isolated crash snapshot");
        }
        dir
    };
    let normal_dir = copy();
    let selected = targets(&n.f, &n.sessions);
    let submit = |journal: &mut DeviceJournal| {
        journal.send_account_message(
            FanoutInput {
                id,
                account: n.f.peers.first().expect("peer").account_id(),
                targets: &selected,
                plaintext: b"all or none across actual sync cuts",
                associated_data: b"account-message",
            },
            150,
        )
    };
    let (mut normal, _, count, _) = fault_store(&canonical(&normal_dir), &n.f.local, false);
    count.store(0, Ordering::SeqCst);
    let expected = wires(&submit(&mut normal).expect("baseline"));
    let barriers = count.load(Ordering::SeqCst);
    assert!((8..=24).contains(&barriers), "actual barriers={barriers}");
    normal.close();
    let mut observed = BTreeSet::new();
    for cut in 1..=barriers {
        for after in [false, true] {
            let dir = copy();
            let (mut journal, fail, _, _) = fault_store(&canonical(&dir), &n.f.local, after);
            fail.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(submit(&mut journal), after);
            assert!(journal.active.is_none());
            journal = reopen(&canonical(&dir), &n.f.local);
            let phase = journal.fanout_status(id).expect("reconciled phase");
            assert_ne!(phase, FanoutStatus::Retired);
            observed.insert(format!("{phase:?}"));
            for (context, session) in n.f.contexts.iter().zip(&n.sessions) {
                let message = MessageId::for_epoch(session, 1, 0, 0).expect("exact member ID");
                let status = journal
                    .message_status(context, *session, message)
                    .expect("member phase");
                assert_eq!(
                    status,
                    match phase {
                        FanoutStatus::Absent => Ok(MessageStatus::Absent),
                        FanoutStatus::Reserved => Ok(MessageStatus::Reserved),
                        FanoutStatus::Committed => Ok(MessageStatus::Committed),
                        FanoutStatus::Retired => Err("batch was never retired"),
                    }
                    .expect("exact member phase")
                );
                if phase == FanoutStatus::Reserved {
                    assert!(matches!(
                        journal.resume_message(context, *session, message, 150),
                        Err(DurableError::Suspended)
                    ));
                    assert!(matches!(
                        journal.send_message(
                            context,
                            *session,
                            message,
                            b"all or none across actual sync cuts",
                            b"account-message",
                            150
                        ),
                        Err(DurableError::Suspended)
                    ));
                    assert!(matches!(
                        journal.next_message_id(context, *session, 150),
                        Err(DurableError::Suspended)
                    ));
                }
            }
            assert_eq!(
                wires(&submit(&mut journal).expect("exact aggregate recovery")),
                expected
            );
            for (context, session) in n.f.contexts.iter().zip(&n.sessions) {
                let progress = journal
                    .application_send_progress(context, *session)
                    .expect("spending");
                assert_eq!(
                    (progress.committed, progress.reserved, progress.remaining),
                    (1, false, 3)
                );
            }
        }
    }
    assert!(observed.contains("Reserved") && observed.contains("Committed"));
    eprintln!(
        "ACCOUNT_FANOUT_SYNC_RECOVERY barriers={barriers} faults={} phases={observed:?}",
        barriers * 2
    );
}

#[test]
fn account_fanout_capacity_and_id_scope_preserve_earlier_committed_work() {
    let mut n = Network::new(64, false);
    let first = n.sender.next_fanout_id().expect("ID");
    assert_eq!(
        n.sender.next_fanout_id().expect("same unreserved slot"),
        first
    );
    let mut original = None;
    for _ in 0..16 {
        let id = n.sender.next_fanout_id().expect("next batch");
        let sent = n
            .send(id, b"bounded retained aggregate")
            .expect("admitted batch");
        if id == first {
            original = Some(wires(&sent));
        }
    }
    let next = n.sender.next_fanout_id().expect("full-capacity next ID");
    let before = n.sender.image().expect("image").revision;
    assert!(matches!(
        n.send(next, b"cannot evict a batch"),
        Err(DurableError::Capacity)
    ));
    assert_eq!(n.sender.image().expect("unchanged").revision, before);
    assert_eq!(
        n.sender.fanout_status(next).expect("not reserved"),
        FanoutStatus::Absent
    );
    let mut selected = targets(&n.f, &n.sessions);
    selected.reverse();
    let replay = n
        .sender
        .resume_account_message(first, &selected, 150)
        .expect("order-independent exact membership");
    assert_eq!(wires(&replay), original.expect("first batch"));
    n.check_delivery(&replay, b"bounded retained aggregate");
    let mut other = Network::new(64, false);
    let revision = other.sender.image().expect("other image").revision;
    assert!(matches!(
        other.send(first, b"bounded retained aggregate"),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        other
            .sender
            .image()
            .expect("unchanged other journal")
            .revision,
        revision
    );
}
