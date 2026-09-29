// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture_with_anchor, Fixture},
    durable::tests::directory,
    AnchorIdentity, AnchorPin, AnchorRequest, AnchorRequirement, AnchorSigningKey, AnchorStore,
    AnchorTransport, InitiatorOperation, PrekeyQuality,
};
use redb::ReadableDatabase;
use std::{
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

struct Server {
    now: u64,
    store: AnchorStore,
    requests: Vec<Vec<u8>>,
    replies: Vec<Vec<u8>>,
    fail: Option<(usize, bool)>,
    substitute: Option<Vec<u8>>,
}
struct Carrier(Arc<Mutex<Server>>);
impl AnchorTransport for Carrier {
    fn exchange(&mut self, request: &[u8], _: Instant) -> io::Result<Vec<u8>> {
        let mut server = self.0.lock().expect("server lock");
        server.requests.push(request.to_vec());
        let attempt = server.requests.len();
        if let Some(reply) = &server.substitute {
            return Ok(reply.clone());
        }
        if server.fail == Some((attempt, false)) {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        let now = server.now;
        let reply = server
            .store
            .handle(request, now)
            .map_err(io::Error::other)?;
        server.replies.push(reply.clone());
        if server.fail == Some((attempt, true)) {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        Ok(reply)
    }
}
struct Case {
    peer: Fixture,
    server: Arc<Mutex<Server>>,
    pin: AnchorPin,
    journal: DeviceJournal,
    identity: JournalIdentity,
    subject: AnchorSubject,
    path: PathBuf,
    _folder: tempfile::TempDir,
}
fn client(pin: &AnchorPin, server: &Arc<Mutex<Server>>, initiator: bool) -> AnchorClient {
    let seed = if initiator { 92 } else { 96 };
    AnchorClient::new(
        pin.clone(),
        DeviceSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("same test credential"),
        Box::new(Carrier(Arc::clone(server))),
        Duration::from_secs(10),
    )
    .expect("client")
}
fn case() -> Case {
    let folder = directory();
    let path = folder.path().canonicalize().expect("path");
    let wrapping = JournalKey::provision(&path.join("witness-key")).expect("wrapping");
    let signer = AnchorSigningKey::generate().expect("witness signer");
    let store = AnchorStore::provision(
        &path.join("witness.redb"),
        wrapping,
        signer,
        AnchorIdentity::generate().expect("witness identity"),
    )
    .expect("store");
    let pin = store.pin().expect("pin");
    let peer = fixture_with_anchor(
        PrekeyQuality::OneTimeBoth,
        AnchorRequirement::required(&pin),
    );
    let key = JournalKey::provision(&path.join("key")).expect("journal key");
    let mut journal = DeviceJournal::provision_anchored(
        &path.join("state.redb"),
        key,
        peer.initiator_device(),
        peer.initiator.policy(),
        150,
    )
    .expect("required journal");
    let genesis = journal
        .anchor_genesis(peer.initiator_device(), peer.initiator.policy())
        .expect("genesis");
    let identity = journal.identity().expect("identity");
    let server = Arc::new(Mutex::new(Server {
        now: 150,
        store,
        requests: Vec::new(),
        replies: Vec::new(),
        fail: None,
        substitute: None,
    }));
    server
        .lock()
        .expect("server")
        .store
        .enroll(
            &genesis,
            peer.initiator_device(),
            peer.initiator.policy(),
            150,
        )
        .expect("trusted enrollment");
    journal
        .activate_anchor(
            peer.initiator_device(),
            peer.initiator.policy(),
            client(&pin, &server, true),
        )
        .expect("activate");
    Case {
        peer,
        server,
        pin,
        journal,
        identity,
        subject: genesis.subject(),
        path,
        _folder: folder,
    }
}
fn reopen(c: &Case) -> Result<DeviceJournal, DurableError> {
    DeviceJournal::open_anchored(
        &c.path.join("state.redb"),
        JournalKey::open(&c.path.join("key")).expect("key"),
        c.peer.initiator_device(),
        c.peer.initiator.policy(),
        c.identity,
        client(&c.pin, &c.server, true),
    )
}
fn request_id() -> InitiationId {
    InitiationId::from_trusted_state([51; 32]).expect("request")
}
fn initiate(c: &mut Case) -> Result<Vec<u8>, DurableError> {
    c.journal.initiate(
        Arc::clone(&c.peer.initiator),
        request_id(),
        &c.peer.signer_i,
        150,
    )
}

#[test]
fn required_policy_has_no_volatile_or_local_journal_bypass() {
    let mut c = case();
    assert!(matches!(
        InitiatorOperation::start(Arc::clone(&c.peer.initiator), &c.peer.signer_i, 150),
        Err(Error::PolicyDenied)
    ));
    let (pq, classical) = c.peer.sources();
    assert!(matches!(
        ResponderOperation::new(Arc::clone(&c.peer.responder)).respond(
            &[],
            &c.peer.signer_r,
            pq,
            classical,
            150
        ),
        Err(Error::PolicyDenied)
    ));
    let key = JournalKey::provision(&c.path.join("local-key")).expect("local key");
    let mut local =
        DeviceJournal::provision(&c.path.join("local.redb"), key, c.peer.initiator_device())
            .expect("local journal");
    assert!(matches!(
        local.initiate(
            Arc::clone(&c.peer.initiator),
            request_id(),
            &c.peer.signer_i,
            150
        ),
        Err(DurableError::AnchorRequired)
    ));
    c.journal.close();
    assert!(matches!(
        DeviceJournal::open(
            &c.path.join("state.redb"),
            JournalKey::open(&c.path.join("key")).expect("key"),
            c.peer.initiator_device(),
            c.identity
        ),
        Err(DurableError::AnchorRequired)
    ));
    let other = AnchorPin::new(
        AnchorIdentity::generate().expect("different instance"),
        c.pin.public_key().clone(),
    );
    assert!(matches!(
        DeviceJournal::open_anchored(
            &c.path.join("state.redb"),
            JournalKey::open(&c.path.join("key")).expect("key"),
            c.peer.initiator_device(),
            c.peer.initiator.policy(),
            c.identity,
            client(&other, &c.server, true)
        ),
        Err(DurableError::Conflict)
    ));
    c.journal = reopen(&c).expect("matching owner");
    let initial = initiate(&mut c).expect("anchored initial");
    assert_eq!(
        c.journal
            .resume_initial(Arc::clone(&c.peer.initiator), request_id(), 150)
            .expect("same flight"),
        initial
    );
}

#[test]
fn both_real_journals_complete_handshake_under_required_witness_policy() {
    let mut c = case();
    let (policy, device, _) = c.peer.responder.inventory_inputs();
    let key = JournalKey::provision(&c.path.join("responder-key")).expect("key");
    let mut responder =
        DeviceJournal::provision_anchored(&c.path.join("responder.redb"), key, device, policy, 150)
            .expect("responder");
    let genesis = responder.anchor_genesis(device, policy).expect("genesis");
    let responder_identity = responder.identity().expect("independent identity");
    c.server
        .lock()
        .expect("server")
        .store
        .enroll(&genesis, device, policy, 150)
        .expect("enrollment");
    responder
        .activate_anchor(device, policy, client(&c.pin, &c.server, false))
        .expect("activation");
    let initial = initiate(&mut c).expect("initial");
    let (pq, classical) = c.peer.sources();
    let reply = responder
        .respond(
            Arc::clone(&c.peer.responder),
            &initial,
            &c.peer.signer_r,
            pq,
            classical,
            150,
        )
        .expect("reply");
    let result = c
        .journal
        .accept_reply(Arc::clone(&c.peer.initiator), request_id(), &reply, 150)
        .expect("final");
    assert_eq!(
        responder
            .finish(
                Arc::clone(&c.peer.responder),
                &initial,
                result.final_message(),
                150
            )
            .expect("responder completed"),
        result.session_id()
    );
    c.journal.close();
    c.journal = reopen(&c).expect("restart");
    assert_eq!(
        c.journal
            .resume_reply(Arc::clone(&c.peer.initiator), request_id(), 150)
            .expect("exact final")
            .final_message(),
        result.final_message()
    );
    let session = result.session_id();
    assert_eq!(
        c.journal
            .activate_initiator_messages(Arc::clone(&c.peer.initiator), request_id(), 150)
            .expect("message chains"),
        session
    );
    assert_eq!(
        responder
            .activate_responder_messages(Arc::clone(&c.peer.responder), &initial, 150)
            .expect("peer chains"),
        session
    );
    let id = c
        .journal
        .next_message_id(&c.peer.initiator, session, 150)
        .expect("message id");
    let wire = c
        .journal
        .send_message(
            &c.peer.initiator,
            session,
            id,
            b"anchored message",
            b"application",
            150,
        )
        .expect("anchored send");
    assert_eq!(
        responder
            .receive_message(&c.peer.responder, session, &wire, b"application", 150)
            .expect("anchored receive")
            .as_bytes(),
        b"anchored message"
    );
    // Cached output still needs a fresh release query, after image admission.
    {
        let mut server = c.server.lock().expect("server");
        server.fail = Some((server.requests.len() + 2, false));
    }
    assert!(matches!(
        c.journal
            .resume_message(&c.peer.initiator, session, id, 150),
        Err(DurableError::Anchor(_))
    ));
    assert!(c.journal.active.is_none());
    c.server.lock().expect("server").fail = None;
    c.journal = reopen(&c).expect("recover current witness head");
    assert_eq!(
        c.journal
            .resume_message(&c.peer.initiator, session, id, 150)
            .expect("same committed outbox"),
        wire
    );
    {
        let mut server = c.server.lock().expect("server");
        server.fail = Some((server.requests.len() + 2, false));
    }
    assert!(matches!(
        responder.receive_message(&c.peer.responder, session, &wire, b"application", 150),
        Err(DurableError::Anchor(_))
    ));
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    let open_responder = || {
        DeviceJournal::open_anchored(
            &c.path.join("responder.redb"),
            JournalKey::open(&c.path.join("responder-key")).expect("key"),
            c.peer.local_device(),
            c.peer.responder.policy(),
            responder_identity,
            client(&c.pin, &c.server, false),
        )
        .expect("reopen anchored responder")
    };
    responder = open_responder();
    assert_eq!(
        responder
            .consume_message(&c.peer.responder, session, id, 150)
            .expect("consume"),
        1
    );
    let ack = responder
        .message_acknowledgement(&c.peer.responder, session, 150)
        .expect("ack");
    {
        let mut server = c.server.lock().expect("server");
        server.fail = Some((server.requests.len() + 2, false));
    }
    assert!(matches!(
        responder.message_acknowledgement(&c.peer.responder, session, 150),
        Err(DurableError::Anchor(_))
    ));
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    assert_eq!(
        responder
            .message_acknowledgement(&c.peer.responder, session, 150)
            .expect("same committed prefix"),
        ack
    );
    assert_eq!(
        c.journal
            .accept_message_acknowledgement(&c.peer.initiator, session, &ack, 150)
            .expect("anchored retirement"),
        1
    );
    assert_eq!(
        c.journal
            .message_status(&c.peer.initiator, session, id)
            .expect("retired status"),
        crate::MessageStatus::Acknowledged
    );
}

#[test]
fn restored_client_database_is_rejected_while_witness_remains_ahead() {
    let mut c = case();
    c.journal.close();
    let snapshot = c.path.join("genesis-snapshot.redb");
    fs::copy(c.path.join("state.redb"), &snapshot).expect("owned snapshot");
    c.journal = reopen(&c).expect("fresh current head");
    initiate(&mut c).expect("advance");
    c.journal.close();
    fs::copy(snapshot, c.path.join("state.redb")).expect("restore test-owned old image");
    assert!(matches!(reopen(&c), Err(DurableError::Anchor(_))));
}

#[test]
fn external_writer_fence_suspends_instead_of_adopting_new_authority() {
    let mut c = case();
    let image = c.journal.image().expect("current image");
    let head = AnchorHead::from_trusted_state(1, image.revision, image.digest).expect("head");
    let request = AnchorRequest::new(
        &c.pin,
        c.subject,
        AnchorOperation::fence_writer(head).expect("fence"),
        &c.peer.signer_i,
    )
    .expect("request");
    let wire = c
        .server
        .lock()
        .expect("server")
        .store
        .handle(request.as_bytes(), 150)
        .expect("fenced");
    assert_eq!(
        c.pin
            .verify_reply(&request, &wire)
            .expect("reply")
            .applied_head()
            .expect("applied")
            .fence(),
        2
    );
    assert!(matches!(initiate(&mut c), Err(DurableError::Anchor(_))));
    assert!(c.journal.active.is_none());
    assert!(matches!(reopen(&c), Err(DurableError::Anchor(_))));
}

#[test]
fn every_initial_exchange_loss_recovers_only_the_durable_exact_target() {
    let mut baseline = case();
    let before = baseline.server.lock().expect("server").requests.len();
    initiate(&mut baseline).expect("baseline");
    let count = baseline.server.lock().expect("server").requests.len() - before;
    assert_eq!(count, 12, "read, five advance/query pairs, release");
    for offset in 1..=count {
        for after in [false, true] {
            let mut c = case();
            {
                let mut server = c.server.lock().expect("server");
                server.fail = Some((server.requests.len() + offset, after));
            }
            assert!(
                matches!(initiate(&mut c), Err(DurableError::Anchor(_))),
                "offset {offset}, after {after}"
            );
            assert!(c.journal.active.is_none());
            // Inspect the real authenticated image and pending transaction without applying it.
            let db = open_private_database(&c.path.join("state.redb")).expect("readback");
            let key = JournalKey::open(&c.path.join("key")).expect("key");
            let owner = bootstrap::storage_owner(c.peer.initiator_device());
            let (image, pending) =
                write_intent::load_snapshot(&db, &key, owner).expect("authenticated snapshot");
            let tx = db.begin_read().expect("read");
            let table = tx.open_table(TABLE).expect("table");
            let target = table.get("pending").expect("pending lookup").map(|value| {
                let bytes = value.value();
                bytes
                    .get(156..bytes.len() - 32)
                    .expect("exact sealed target")
                    .to_vec()
            });
            assert_eq!(pending.is_some(), target.is_some());
            // The ordinary opener must not apply even a valid saved intent.
            assert!(matches!(
                write_intent::recover(&db, &key, owner, c.identity),
                Err(DurableError::AnchorRequired)
            ));
            let (unchanged, _) = write_intent::load_snapshot(&db, &key, owner).expect("unchanged");
            assert_eq!(unchanged.digest, image.digest);
            drop(table);
            drop(tx);
            drop(db);
            c.server.lock().expect("server").fail = None;
            c.journal = reopen(&c).expect("exact command reconciliation");
            if let Some(target) = target {
                let restored = c.journal.image().expect("recovered");
                assert_eq!(restored.digest, image_hash(&target));
                assert_eq!(restored.revision, image.revision + 1);
            }
            let initial = initiate(&mut c).expect("finish retained operation");
            assert_eq!(
                c.journal
                    .resume_initial(Arc::clone(&c.peer.initiator), request_id(), 150)
                    .expect("same result"),
                initial
            );
        }
    }
}

#[test]
fn captured_query_reply_cannot_reopen_or_release_a_required_journal() {
    let mut c = case();
    let captured = c
        .server
        .lock()
        .expect("server")
        .replies
        .first()
        .expect("activation reply")
        .clone();
    c.server.lock().expect("server").substitute = Some(captured);
    assert!(matches!(initiate(&mut c), Err(DurableError::Anchor(_))));
    assert!(c.journal.active.is_none());
    assert!(matches!(reopen(&c), Err(DurableError::Anchor(_))));
    c.server.lock().expect("server").substitute = None;
    c.journal = reopen(&c).expect("fresh signed challenge response");
    initiate(&mut c).expect("operation after independent reconciliation");
}

#[test]
fn each_local_commit_sync_failure_reconciles_against_the_real_witness() {
    use std::sync::atomic::Ordering;
    for after_sync in [false, true] {
        for cut in 1..=4 {
            let mut c = case();
            let attached = c.journal.active.as_mut().expect("active").anchor.take();
            c.journal.close();
            let (mut journal, remaining, _, _) =
                crate::durable::tests::fault_store(&c.path, c.peer.initiator_device(), after_sync);
            journal.active.as_mut().expect("active").anchor = attached;
            c.journal = journal;
            remaining.store(cut, Ordering::SeqCst);
            assert!(
                matches!(initiate(&mut c), Err(DurableError::CommitUncertain(_))),
                "sync {cut}, after {after_sync}"
            );
            assert!(c.journal.active.is_none());
            c.journal = reopen(&c).expect("reconcile exact local intent and witness command");
            let initial = initiate(&mut c).expect("retained computation");
            assert_eq!(
                c.journal
                    .resume_initial(Arc::clone(&c.peer.initiator), request_id(), 150)
                    .expect("one exact result"),
                initial
            );
        }
    }
}

#[test]
fn inactive_required_journal_cannot_create_prekeys_and_active_inventory_is_anchored() {
    let c = case();
    let (policy, device, _) = c.peer.responder.inventory_inputs();
    let key = JournalKey::provision(&c.path.join("inventory-key")).expect("key");
    let mut journal =
        DeviceJournal::provision_anchored(&c.path.join("inventory.redb"), key, device, policy, 150)
            .expect("inactive journal");
    let identity = journal.identity().expect("identity");
    let genesis = journal.anchor_genesis(device, policy).expect("genesis");
    c.server
        .lock()
        .expect("server")
        .store
        .enroll(&genesis, device, policy, 150)
        .expect("enrollment");
    let request = PrekeyId::from_trusted_state([67; 32]).expect("request");
    assert!(matches!(
        journal.generate_prekey(
            policy,
            device,
            request,
            crate::LeafKind::OneTimePq,
            crate::tests::interval(),
            150
        ),
        Err(DurableError::AnchorRequired)
    ));
    assert!(journal.active.is_none());
    journal = DeviceJournal::open_anchored(
        &c.path.join("inventory.redb"),
        JournalKey::open(&c.path.join("inventory-key")).expect("key"),
        device,
        policy,
        identity,
        client(&c.pin, &c.server, false),
    )
    .expect("activate on reopen");
    let leaf = journal
        .generate_prekey(
            policy,
            device,
            request,
            crate::LeafKind::OneTimePq,
            crate::tests::interval(),
            150,
        )
        .expect("anchored public prekey");
    assert_eq!(
        journal
            .prekey_leaf(policy, device, request, 150)
            .expect("public readback")
            .key_fingerprint(),
        leaf.key_fingerprint()
    );
    journal
        .retire_prekey(policy, device, request)
        .expect("anchored retirement");
    assert!(matches!(
        journal.prekey_leaf(policy, device, request, 150),
        Err(DurableError::KeyRetired)
    ));
}

#[test]
fn expiry_allows_only_confirmation_of_an_already_committed_exact_intent() {
    for after in [false, true] {
        let mut c = case();
        {
            let mut server = c.server.lock().expect("server");
            server.fail = Some((server.requests.len() + 2, after));
        }
        assert!(matches!(initiate(&mut c), Err(DurableError::Anchor(_))));
        {
            let mut server = c.server.lock().expect("server");
            server.fail = None;
            server.now = 250;
        }
        let recovered = reopen(&c);
        if after {
            c.journal = recovered.expect("read-only confirmation of exact committed command");
            assert_eq!(
                c.journal
                    .initiation_status(&c.peer.initiator, request_id())
                    .expect("reconciled status"),
                DurableStatus::InitialKeyReserved
            );
            assert!(matches!(
                c.journal.initiate(
                    Arc::clone(&c.peer.initiator),
                    request_id(),
                    &c.peer.signer_i,
                    250
                ),
                Err(DurableError::Protocol(Error::Validity))
            ));
        } else {
            assert!(
                matches!(recovered, Err(DurableError::Anchor(_))),
                "expiry cannot authorize an unperformed advance"
            );
        }
    }
}

#[test]
fn actual_tcp_carrier_verifies_real_witness_and_bounds_frames_and_total_deadline() {
    use std::net::TcpListener;
    for behavior in 0..4 {
        let c = case();
        let listener = TcpListener::bind("127.0.0.1:0").expect("test-owned loopback endpoint");
        listener.set_nonblocking(true).expect("bounded accept");
        let address = listener.local_addr().expect("address");
        let server = Arc::clone(&c.server);
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "client did not connect");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking accepted test socket");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("read deadline");
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .expect("write deadline");
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).expect("frame");
            assert_eq!(u32::from_be_bytes(prefix), 3674);
            let mut request = vec![0; 3674];
            stream.read_exact(&mut request).expect("request");
            let reply = server
                .lock()
                .expect("server")
                .store
                .handle(&request, 150)
                .expect("real witness");
            match behavior {
                0 => {
                    stream.write_all(&3659u32.to_be_bytes()).expect("length");
                    stream.write_all(&reply).expect("reply");
                }
                1 => stream
                    .write_all(&u32::MAX.to_be_bytes())
                    .expect("invalid oversized length"),
                2 => {
                    stream.write_all(&3659u32.to_be_bytes()).expect("length");
                    stream
                        .write_all(reply.get(..100).expect("partial reply range"))
                        .expect("partial");
                }
                3 => {
                    // No individual pause exceeds the total budget, but the complete prefix does.
                    for byte in 3659u32.to_be_bytes() {
                        std::thread::sleep(Duration::from_millis(100));
                        if let Err(error) = stream.write_all(&[byte]) {
                            assert!(matches!(
                                error.kind(),
                                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                            ));
                            break;
                        }
                    }
                }
                _ => unreachable!(),
            }
            Ok::<(), io::Error>(())
        });
        let mut client = AnchorClient::new(
            c.pin.clone(),
            DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("device"),
            Box::new(crate::AnchorTcpTransport::new(address)),
            if behavior == 3 {
                Duration::from_millis(300)
            } else {
                Duration::from_secs(3)
            },
        )
        .expect("client");
        let started = Instant::now();
        let result = client.exchange(c.subject, AnchorOperation::query());
        if behavior == 0 {
            assert_eq!(
                result
                    .expect("authenticated TCP reply")
                    .observed_head()
                    .revision(),
                1
            );
        } else {
            assert!(
                matches!(result, Err(AnchorClientError::Transport(_))),
                "behavior {behavior}"
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "bounded exchange"
        );
        thread
            .join()
            .expect("bounded server")
            .expect("server exchange");
    }
}
