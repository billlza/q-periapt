// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture_with_anchor_and_budget, Fixture},
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

struct ScopedCarrier {
    inner: Carrier,
    deadline: Instant,
    late_reply: bool,
}
impl AnchorTransport for ScopedCarrier {
    fn constrain_deadline(&self, _: Instant) -> io::Result<Instant> {
        Ok(self.deadline)
    }
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        let reply = self.inner.exchange(request, deadline)?;
        if self.late_reply {
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
        }
        Ok(reply)
    }
}

#[test]
fn enclosing_witness_deadline_does_not_refresh_between_signed_queries() {
    let c = case();
    let deadline = Instant::now() + Duration::from_secs(2);
    let count = c.server.lock().expect("server").requests.len();
    let mut client = AnchorClient::new(
        c.pin.clone(),
        DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("device signer"),
        Box::new(ScopedCarrier {
            inner: Carrier(Arc::clone(&c.server)),
            deadline,
            late_reply: false,
        }),
        Duration::from_secs(10),
    )
    .expect("scoped client");
    client
        .exchange(c.subject, AnchorOperation::query())
        .expect("first authenticated query");
    assert_eq!(c.server.lock().expect("server").requests.len(), count + 1);
    std::thread::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    );
    assert!(
        matches!(client.exchange(c.subject, AnchorOperation::query()),
        Err(crate::AnchorClientError::Transport(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert_eq!(
        c.server.lock().expect("server").requests.len(),
        count + 1,
        "expired query was dispatched"
    );
}

#[test]
fn witness_transport_cannot_extend_attempt_or_admit_a_late_authentic_reply() {
    let c = case();
    let count = c.server.lock().expect("server").requests.len();
    let mut client = AnchorClient::new(
        c.pin.clone(),
        DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("device signer"),
        Box::new(ScopedCarrier {
            inner: Carrier(Arc::clone(&c.server)),
            deadline: Instant::now() + Duration::from_secs(30),
            late_reply: true,
        }),
        Duration::from_millis(500),
    )
    .expect("attempt client");
    let started = Instant::now();
    assert!(
        matches!(client.exchange(c.subject, AnchorOperation::query()),
        Err(crate::AnchorClientError::Transport(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "transport extended the caller's attempt"
    );
    assert_eq!(c.server.lock().expect("server").requests.len(), count + 1);
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
    case_with_budget(1024)
}
fn case_with_budget(budget: u16) -> Case {
    case_with_witness_signer(
        budget,
        AnchorSigningKey::generate().expect("witness signer"),
    )
}
fn case_with_witness_signer(budget: u16, signer: AnchorSigningKey) -> Case {
    let folder = directory();
    let path = folder.path().canonicalize().expect("path");
    let wrapping = JournalKey::provision(&path.join("witness-key")).expect("wrapping");
    let store = AnchorStore::provision(
        &path.join("witness.redb"),
        wrapping,
        signer,
        AnchorIdentity::generate().expect("witness identity"),
    )
    .expect("store");
    let pin = store.pin().expect("pin");
    let peer = fixture_with_anchor_and_budget(
        PrekeyQuality::OneTimeBoth,
        AnchorRequirement::required(&pin),
        crate::ApplicationSendBudget::new(budget).expect("signed fixture budget"),
    );
    let key = JournalKey::provision(&path.join("key")).expect("journal key");
    let mut journal = DeviceJournal::provision_anchored(
        &path.join("state.redb"),
        key,
        peer.initiator_device(),
        peer.initiator
            .current_policy()
            .expect("fixture policy owner"),
        crate::durable::tests::retain_new_identity(&path.join("store-id")),
        150,
    )
    .expect("required journal");
    let genesis = journal
        .anchor_genesis(
            peer.initiator_device(),
            peer.initiator
                .current_policy()
                .expect("fixture policy owner"),
        )
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
            peer.initiator
                .current_policy()
                .expect("fixture policy owner"),
            150,
        )
        .expect("trusted enrollment");
    journal
        .activate_anchor(
            peer.initiator_device(),
            peer.initiator
                .current_policy()
                .expect("fixture policy owner"),
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
        c.peer
            .initiator
            .current_policy()
            .expect("fixture policy owner"),
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
    let mut local = DeviceJournal::provision(
        &c.path.join("local.redb"),
        key,
        c.peer.initiator_device(),
        crate::durable::tests::retain_new_identity(&c.path.join("local-id")),
    )
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
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
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
    let mut c = case_with_budget(2);
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let key = JournalKey::provision(&c.path.join("responder-key")).expect("key");
    let mut responder = DeviceJournal::provision_anchored(
        &c.path.join("responder.redb"),
        key,
        device,
        policy,
        crate::durable::tests::retain_new_identity(&c.path.join("responder-id")),
        150,
    )
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
            c.peer
                .responder
                .current_policy()
                .expect("fixture policy owner"),
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
    let unresolved_id = c
        .journal
        .next_message_id(&c.peer.initiator, session, 150)
        .expect("old slot");
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 6, false));
    assert!(matches!(
        c.journal.send_message(
            &c.peer.initiator,
            session,
            unresolved_id,
            b"old delivery awaiting application resolution",
            b"application",
            150,
        ),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 6);
    assert!(c.journal.active.is_none());
    c.server.lock().expect("server").fail = None;
    c.journal = reopen(&c).expect("last slot committed before lost witness release");
    let spent = c
        .journal
        .application_send_progress(&c.peer.initiator, session)
        .expect("retained spending");
    assert_eq!(
        (spent.committed, spent.reserved, spent.remaining),
        (2, false, 0)
    );
    assert!(matches!(
        c.journal.next_message_id(&c.peer.initiator, session, 150),
        Err(DurableError::Protocol(Error::RekeyRequired))
    ));
    let unresolved = c
        .journal
        .resume_message(&c.peer.initiator, session, unresolved_id, 150)
        .expect("same last-slot outbox");
    responder
        .receive_message(&c.peer.responder, session, &unresolved, b"application", 150)
        .expect("retain unconsumed plaintext");
    // The idle-designated proposer can be requested without an application send.
    // Lose the final release query after both request transactions committed.
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 6, false));
    assert!(matches!(
        responder.prepare_rekey_request(&c.peer.responder, session, &c.peer.signer_r, 150),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 6);
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    assert_eq!(
        responder
            .rekey_request_status(&c.peer.responder, session)
            .expect("request phase"),
        crate::RekeyRequestStatus::Committed
    );
    let control_request = responder
        .prepare_rekey_request(&c.peer.responder, session, &c.peer.signer_r, 150)
        .expect("release the exact request after reconciliation");
    // Three exact persisted stages each advance/query the witness. Lose only
    // the final release query, after the signed offer is already committed.
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 8, false));
    assert!(matches!(
        c.journal
            .prepare_rekey_offer(&c.peer.initiator, session, &c.peer.signer_i, 150),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 8);
    assert!(c.journal.active.is_none());
    c.server.lock().expect("server").fail = None;
    c.journal = reopen(&c).expect("reconcile committed offer");
    assert_eq!(
        c.journal
            .rekey_offer_status(&c.peer.initiator, session)
            .expect("status"),
        crate::RekeyOfferStatus::Committed
    );
    let offer = c
        .journal
        .prepare_rekey_offer(&c.peer.initiator, session, &c.peer.signer_i, 150)
        .expect("exact offer release");
    assert_eq!(
        c.journal
            .respond_rekey_request(
                &c.peer.initiator,
                session,
                &control_request,
                &c.peer.signer_i,
                150
            )
            .expect("request joins the existing offer"),
        offer
    );
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 2, false));
    assert!(matches!(
        c.journal
            .prepare_rekey_offer(&c.peer.initiator, session, &c.peer.signer_i, 150),
        Err(DurableError::Anchor(_))
    ));
    assert!(c.journal.active.is_none());
    c.server.lock().expect("server").fail = None;
    c.journal = reopen(&c).expect("reopen current head");
    assert_eq!(
        c.journal
            .prepare_rekey_offer(&c.peer.initiator, session, &c.peer.signer_i, 150)
            .expect("same bytes after lost release"),
        offer
    );
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 8, false));
    assert!(matches!(
        responder.respond_rekey_offer(&c.peer.responder, session, &offer, &c.peer.signer_r, 150),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 8);
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    assert_eq!(
        responder
            .rekey_response_status(&c.peer.responder, session)
            .expect("pending response"),
        crate::RekeyResponseStatus::Committed
    );
    let response = responder
        .respond_rekey_offer(&c.peer.responder, session, &offer, &c.peer.signer_r, 150)
        .expect("exact response release");
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 2, false));
    assert!(matches!(
        responder.respond_rekey_offer(&c.peer.responder, session, &offer, &c.peer.signer_r, 150),
        Err(DurableError::Anchor(_))
    ));
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    assert_eq!(
        responder
            .respond_rekey_offer(&c.peer.responder, session, &offer, &c.peer.signer_r, 150)
            .expect("same response after lost release"),
        response
    );
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 6, false));
    assert!(matches!(
        c.journal.accept_rekey_response(
            &c.peer.initiator,
            session,
            &response,
            &c.peer.signer_i,
            150
        ),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 6);
    assert!(c.journal.active.is_none());
    c.server.lock().expect("server").fail = None;
    c.journal = reopen(&c).expect("recover final commit");
    let final_wire = c
        .journal
        .rekey_outbox(
            &c.peer.initiator,
            session,
            1,
            crate::RekeyFlight::Final,
            150,
        )
        .expect("committed final");
    let progress = c
        .journal
        .rekey_progress(&c.peer.initiator, session)
        .expect("half cutover");
    assert_eq!(
        (
            progress.sending_epoch,
            progress.receiving_epoch,
            progress.confirmed_epoch
        ),
        (1, 0, 0)
    );
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 6, false));
    assert!(matches!(
        responder.finish_rekey(
            &c.peer.responder,
            session,
            &final_wire,
            &c.peer.signer_r,
            150
        ),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 6);
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    let receipt = responder
        .rekey_outbox(
            &c.peer.responder,
            session,
            1,
            crate::RekeyFlight::Receipt,
            150,
        )
        .expect("committed receipt");
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 4, false));
    assert!(matches!(
        c.journal
            .accept_rekey_receipt(&c.peer.initiator, session, &receipt, 150),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 4);
    assert!(c.journal.active.is_none());
    c.server.lock().expect("server").fail = None;
    c.journal = reopen(&c).expect("recover receive cutover");
    let fresh = c
        .journal
        .application_send_progress(&c.peer.initiator, session)
        .expect("only committed receipt advances budget");
    assert_eq!(
        (fresh.confirmed_epoch, fresh.committed, fresh.remaining),
        (1, 0, 2)
    );
    assert_eq!(
        c.journal
            .accept_rekey_receipt(&c.peer.initiator, session, &receipt, 150)
            .expect("receipt replay"),
        1
    );
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 2, false));
    assert!(matches!(
        c.journal.rekey_outbox(
            &c.peer.initiator,
            session,
            1,
            crate::RekeyFlight::Final,
            150
        ),
        Err(DurableError::Anchor(_))
    ));
    assert!(c.journal.active.is_none());
    c.server.lock().expect("server").fail = None;
    c.journal = reopen(&c).expect("recover cached release");
    let id = c
        .journal
        .next_message_id(&c.peer.initiator, session, 150)
        .expect("new epoch ID");
    let wire = c
        .journal
        .send_message(
            &c.peer.initiator,
            session,
            id,
            b"anchored epoch one",
            b"application",
            150,
        )
        .expect("new anchored traffic");
    assert_eq!(
        responder
            .receive_message(&c.peer.responder, session, &wire, b"application", 150)
            .expect("actual new epoch receipt")
            .as_bytes(),
        b"anchored epoch one"
    );
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 4, false));
    assert!(matches!(
        responder.begin_closed_epoch_resolution(&c.peer.responder, session, 0, 150),
        Err(DurableError::Anchor(_))
    ));
    assert_eq!(c.server.lock().expect("server").requests.len(), start + 4);
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    let resolution = match responder
        .closed_epoch_resolution_status(&c.peer.responder, session, 0)
        .expect("committed frozen report")
    {
        crate::EpochResolutionStatus::Pending(id) => Some(id),
        _ => None,
    }
    .expect("expected frozen report");
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 2, false));
    assert!(matches!(
        responder.begin_closed_epoch_resolution(&c.peer.responder, session, 0, 150),
        Err(DurableError::Anchor(_))
    ));
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    let report = responder
        .begin_closed_epoch_resolution(&c.peer.responder, session, 0, 150)
        .expect("authorized exact report");
    assert_eq!(report.resolution_id(), resolution);
    assert_eq!(
        report
            .unconsumed_deliveries()
            .first()
            .expect("retained old secret")
            .as_bytes(),
        b"old delivery awaiting application resolution"
    );
    let start = c.server.lock().expect("server").requests.len();
    c.server.lock().expect("server").fail = Some((start + 4, false));
    assert!(matches!(
        responder.acknowledge_closed_epoch_resolution(
            &c.peer.responder,
            session,
            0,
            resolution,
            150
        ),
        Err(DurableError::Anchor(_))
    ));
    assert!(responder.active.is_none());
    c.server.lock().expect("server").fail = None;
    responder = open_responder();
    assert_eq!(
        responder
            .closed_epoch_resolution_status(&c.peer.responder, session, 0)
            .expect("exact accounted outcome"),
        crate::EpochResolutionStatus::Acknowledged(resolution)
    );
    responder
        .acknowledge_closed_epoch_resolution(&c.peer.responder, session, 0, resolution, 150)
        .expect("idempotent authorized recovery");
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
fn every_roster_witness_exchange_loss_recovers_exact_revocation() {
    let mut baseline = case();
    let revoked = rosters::tests::update(baseline.peer.initiator_device(), 90, 2, false);
    let before = baseline.server.lock().expect("server").requests.len();
    baseline
        .journal
        .install_roster(&revoked, 150)
        .expect("baseline update");
    let exchanges = baseline.server.lock().expect("server").requests.len() - before;
    assert_eq!(
        exchanges, 4,
        "admission, advance, committed-head query, release"
    );
    for offset in 1..=exchanges {
        for after in [false, true] {
            let mut c = case();
            let revoked = rosters::tests::update(c.peer.initiator_device(), 90, 2, false);
            {
                let mut server = c.server.lock().expect("server");
                server.fail = Some((server.requests.len() + offset, after));
            }
            assert!(
                matches!(
                    c.journal.install_roster(&revoked, 150),
                    Err(DurableError::Anchor(_))
                ),
                "exchange {offset}, after {after}"
            );
            assert!(c.journal.active.is_none());
            assert!(matches!(initiate(&mut c), Err(DurableError::Closed)));
            c.server.lock().expect("server").fail = None;
            c.journal = reopen(&c).expect("reconcile exact durable intent and witness head");
            let image = c.journal.image().expect("recovered head");
            if offset == 1 {
                assert_eq!(image.revision, 1, "admission loss precedes reservation");
            } else {
                assert_eq!(image.revision, 2);
                assert_eq!(
                    c.journal
                        .roster_checkpoint(c.peer.initiator_device().account_id())
                        .expect("durable revocation"),
                    revoked.checkpoint()
                );
                assert!(matches!(
                    initiate(&mut c),
                    Err(DurableError::Protocol(Error::Scope))
                ));
            }
            c.journal
                .install_roster(&revoked, 150)
                .expect("exact update retry");
            assert_eq!(c.journal.image().expect("one update").revision, 2);
            assert!(matches!(
                initiate(&mut c),
                Err(DurableError::Protocol(Error::Scope))
            ));
        }
    }
    eprintln!(
        "ROSTER_WITNESS_RECOVERY exchanges={exchanges} losses={}",
        exchanges * 2
    );
}

#[test]
fn restored_roster_snapshot_cannot_override_the_witness_revocation_head() {
    let mut c = case();
    c.journal.close();
    let snapshot = c.path.join("enrolled-roster-snapshot.redb");
    fs::copy(c.path.join("state.redb"), &snapshot).expect("owned initial snapshot");
    c.journal = reopen(&c).expect("current head");
    let revoked = rosters::tests::update(c.peer.initiator_device(), 90, 2, false);
    c.journal
        .install_roster(&revoked, 150)
        .expect("witness-backed revocation");
    c.journal.close();
    fs::copy(snapshot, c.path.join("state.redb")).expect("restore owned older image");
    assert!(matches!(reopen(&c), Err(DurableError::Anchor(_))));
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
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let key = JournalKey::provision(&c.path.join("inventory-key")).expect("key");
    let mut journal = DeviceJournal::provision_anchored(
        &c.path.join("inventory.redb"),
        key,
        device,
        policy,
        crate::durable::tests::retain_new_identity(&c.path.join("inventory-id")),
        150,
    )
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

fn cancellation_owner(
    c: &Case,
    initiator: bool,
) -> Result<BootstrapCancellationJournal, DurableError> {
    BootstrapCancellationJournal::open_anchored(
        &c.path.join("state.redb"),
        JournalKey::open(&c.path.join("key")).expect("key"),
        c.identity,
        client(&c.pin, &c.server, initiator),
    )
}

#[test]
fn bootstrap_cancellation_requires_original_witness_and_enrolled_signer() {
    let mut c = case();
    initiate(&mut c).expect("initial");
    let revision = c.journal.image().expect("image").revision;
    c.journal.close();
    assert!(matches!(
        BootstrapCancellationJournal::open(
            &c.path.join("state.redb"),
            JournalKey::open(&c.path.join("key")).expect("key"),
            c.identity
        ),
        Err(DurableError::AnchorRequired)
    ));
    assert!(matches!(
        cancellation_owner(&c, false),
        Err(DurableError::Anchor(_))
    ));
    let foreign = case();
    assert!(matches!(
        BootstrapCancellationJournal::open_anchored(
            &c.path.join("state.redb"),
            JournalKey::open(&c.path.join("key")).expect("key"),
            c.identity,
            client(&foreign.pin, &foreign.server, true)
        ),
        Err(DurableError::Conflict)
    ));
    c.peer.close_initiator_policy();
    let mut normal = reopen(&c).expect("reconcile original subject");
    assert_eq!(
        normal.image().expect("unchanged after refusals").revision,
        revision
    );
    normal.close();
    let mut owner = cancellation_owner(&c, true).expect("original subject without live policy");
    owner
        .cancel(
            c.peer.initiator.digest(),
            BootstrapOperationId::for_initiation(request_id()),
        )
        .expect("cancel after local close with live original witness");
    owner.close();
}

#[test]
fn bootstrap_cancellation_witness_failures_reconcile_exact_receipt() {
    // One read query, one exact advance, one post-commit query.
    for after in [false, true] {
        for offset in 1..=3 {
            let mut c = case();
            initiate(&mut c).expect("initial");
            let image = c.journal.image().expect("image");
            let op = initiator::operation_id(request_id());
            let expected =
                cancellation::metadata(&c.journal.active.as_ref().expect("active").key, &image, op)
                    .expect("original receipt")
                    .report;
            c.journal.close();
            let mut owner = cancellation_owner(&c, true).expect("cleanup owner");
            {
                let mut server = c.server.lock().expect("server");
                server.fail = Some((server.requests.len() + offset, after));
            }
            assert!(matches!(
                owner.cancel(
                    c.peer.initiator.digest(),
                    BootstrapOperationId::for_initiation(request_id())
                ),
                Err(DurableError::Anchor(_))
            ));
            assert!(matches!(owner.entries(), Err(DurableError::Closed)));
            c.server.lock().expect("server").fail = None;
            let mut owner = cancellation_owner(&c, true).expect("reconcile original command");
            let receipt = owner
                .cancel(
                    c.peer.initiator.digest(),
                    BootstrapOperationId::for_initiation(request_id()),
                )
                .expect("exact retry");
            assert_eq!(receipt.report, expected);
            owner.close();
        }
    }
}

#[test]
fn bootstrap_cancellation_expired_witness_only_reconciles_already_applied_intent() {
    for after in [false, true] {
        let mut c = case();
        initiate(&mut c).expect("initial");
        c.journal.close();
        let mut owner = cancellation_owner(&c, true).expect("owner");
        {
            let mut server = c.server.lock().expect("server");
            server.fail = Some((server.requests.len() + 2, after));
        }
        assert!(matches!(
            owner.cancel(
                c.peer.initiator.digest(),
                BootstrapOperationId::for_initiation(request_id())
            ),
            Err(DurableError::Anchor(_))
        ));
        {
            let mut server = c.server.lock().expect("server");
            server.fail = None;
            server.now = 250;
        }
        let result = cancellation_owner(&c, true);
        if after {
            let mut owner = result.expect("exact already applied cancellation");
            assert_eq!(
                owner
                    .cancel(
                        c.peer.initiator.digest(),
                        BootstrapOperationId::for_initiation(request_id())
                    )
                    .expect("existing immutable receipt")
                    .entry
                    .status,
                DurableStatus::BootstrapCancelled
            );
        } else {
            assert!(
                matches!(result, Err(DurableError::Anchor(_))),
                "cleanup must not bypass an expired unperformed advance"
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

fn retained_device_with_roster(
    device: &VerifiedDevice,
    version: u64,
    until: u64,
) -> VerifiedDevice {
    let root =
        crate::RootSigningKey::deterministic([90; 32], [91; 32]).expect("original account root");
    let certificate = root
        .issue_device(device.description.clone(), device.key.clone())
        .expect("unchanged credential");
    let roster = root
        .issue_roster(
            version,
            crate::Validity::new(100, until).expect("roster validity"),
            &[root.roster_entry(&certificate).expect("entry")],
        )
        .expect("signed roster");
    let pin = crate::AccountPin::new(
        device.account_id(),
        root.public_key().expect("public root"),
        roster.checkpoint(),
        device.description.family,
    )
    .expect("independent roster expectation");
    pin.verify_device(&certificate, roster.as_bytes(), 150)
        .expect("retained credential in current roster")
}

fn assert_expired_witness<T>(result: Result<T, DurableError>) {
    assert!(
        matches!(result, Err(DurableError::Anchor(error))
        if matches!(*error, AnchorClientError::Transport(ref error)
            if matches!(error.get_ref().and_then(|source| source.downcast_ref::<crate::AnchorError>()),
                Some(crate::AnchorError::Rejected(Error::Validity))))),
        "the actual native witness must reject expired write authority"
    );
}

#[test]
fn roster_authority_refresh_recovers_the_original_anchored_roster_write_and_outbox() {
    let mut c = case();
    let previous = retained_device_with_roster(c.peer.initiator_device(), 2, 160);
    let next = retained_device_with_roster(c.peer.initiator_device(), 3, 190);
    c.server
        .lock()
        .expect("server")
        .store
        .update_roster_authority(
            c.subject,
            c.peer.initiator_device().roster().checkpoint(),
            &previous,
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            150,
        )
        .expect("explicit shorter admission");
    c.journal
        .install_roster(previous.roster(), 150)
        .expect("same short client authority");
    let initial = initiate(&mut c).expect("actual committed initial outbox");
    let identity = c.journal.identity().expect("original journal");
    let head = client(&c.pin, &c.server, true)
        .exchange(c.subject, AnchorOperation::query())
        .expect("fresh original head")
        .observed_head();
    c.server.lock().expect("server").now = 160;
    assert!(matches!(
        c.journal
            .resume_initial(Arc::clone(&c.peer.initiator), request_id(), 160),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert_expired_witness(c.journal.install_roster(next.roster(), 160));
    assert!(
        c.journal.active.is_none(),
        "failed witness advance closes the original owner"
    );
    assert_expired_witness(reopen(&c));
    assert_eq!(
        client(&c.pin, &c.server, true)
            .exchange(c.subject, AnchorOperation::query())
            .expect("read-only after expiry")
            .observed_head(),
        head
    );
    c.server
        .lock()
        .expect("server")
        .store
        .update_roster_authority(
            c.subject,
            previous.roster().checkpoint(),
            &next,
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            160,
        )
        .expect("explicit original-subject renewal");
    assert_eq!(
        client(&c.pin, &c.server, true)
            .exchange(c.subject, AnchorOperation::query())
            .expect("renewal preserves the actual head")
            .observed_head(),
        head
    );
    c.journal = reopen(&c).expect("reconcile the original retained write intent");
    assert_eq!(c.journal.identity().expect("same journal"), identity);
    assert_eq!(
        c.journal
            .roster_checkpoint(next.account_id())
            .expect("original intended roster"),
        next.roster().checkpoint()
    );
    assert_eq!(
        c.journal
            .resume_initial(Arc::clone(&c.peer.initiator), request_id(), 160)
            .expect("same original outbox"),
        initial
    );
    let after = client(&c.pin, &c.server, true)
        .exchange(c.subject, AnchorOperation::query())
        .expect("fresh reconciled head")
        .observed_head();
    assert_eq!(after.revision(), head.revision() + 1);
    assert_eq!(after.fence(), head.fence());
    c.journal
        .install_roster(next.roster(), 160)
        .expect("same roster retry");
    assert_eq!(
        client(&c.pin, &c.server, true)
            .exchange(c.subject, AnchorOperation::query())
            .expect("no second commit")
            .observed_head(),
        after
    );
    let revoked = rosters::tests::update_with_validity(
        c.peer.initiator_device(),
        90,
        4,
        false,
        crate::Validity::new(100, 190).expect("revocation validity"),
    );
    c.server.lock().expect("server").now = 170;
    c.journal
        .install_roster(&revoked, 170)
        .expect("durable local revocation");
    c.server
        .lock()
        .expect("server")
        .store
        .update_roster_authority(
            c.subject,
            previous.roster().checkpoint(),
            &next,
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            170,
        )
        .expect("witness metadata readback is not current client authority");
    c.journal.close();
    c.journal = reopen(&c).expect("original journal can be inspected after revocation");
    assert!(matches!(
        c.journal
            .resume_initial(Arc::clone(&c.peer.initiator), request_id(), 170),
        Err(DurableError::Protocol(Error::Scope))
    ));
    eprintln!("ANCHOR_ROSTER_REFRESH_JOURNAL original_journal=true retained_intent=true original_outbox=true exactly_one_roster_commit=true revoked_replay_refused=true");
}

mod credential_preparation {
    use super::*;
    use crate::{
        AnchorCredentialRenewalProposal, CredentialRenewalId, RootSigningKey,
        VerifiedCredentialRenewal,
    };
    use std::sync::atomic::Ordering;

    pub(super) fn grant(c: &Case) -> VerifiedCredentialRenewal {
        let original = c.peer.initiator_device();
        let root = RootSigningKey::deterministic([90; 32], [91; 32]).expect("original root");
        let certificate = root
            .issue_device(original.description.clone(), original.key.clone())
            .expect("original body");
        crate::durable::rosters::tests::renewal::grant(
            &root,
            &certificate,
            original,
            300,
            2,
            [219; 32],
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner")
                .checkpoint()
                .digest(),
        )
    }
    pub(super) fn prepare(
        c: &mut Case,
        grant: &VerifiedCredentialRenewal,
    ) -> Result<AnchorCredentialRenewalProposal, DurableError> {
        c.journal.prepare_local_credential_renewal(
            c.peer.initiator_device(),
            grant,
            grant.operation(),
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            150,
        )
    }
    pub(super) fn inspect(
        c: &Case,
    ) -> Result<Option<AnchorCredentialRenewalProposal>, DurableError> {
        DeviceJournal::inspect_credential_renewal_preparation(
            &c.path.join("state.redb"),
            JournalKey::open(&c.path.join("key")).expect("key"),
            c.peer.initiator_device(),
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            c.identity,
        )
    }
    pub(super) fn disk(c: &Case) -> (Vec<u8>, Option<Vec<u8>>) {
        let db = open_private_database(&c.path.join("state.redb")).expect("original database");
        let read = db.begin_read().expect("read");
        let table = read.open_table(TABLE).expect("table");
        let image = table
            .get("image")
            .expect("image lookup")
            .expect("image")
            .value()
            .to_vec();
        let pending = table
            .get("pending")
            .expect("pending lookup")
            .map(|v| v.value().to_vec());
        (image, pending)
    }
    pub(super) fn request_operation(wire: &[u8]) -> AnchorOperation {
        // The real AnchorStore already verified each captured signature.
        let (body, _) = crate::crypto::open_envelope(wire).expect("request envelope");
        assert_eq!(body.len(), 297);
        assert_eq!(body.get(..8).expect("request tag"), b"QPANRQ01");
        AnchorOperation::from_trusted_state(body.get(200..).expect("request command"))
            .expect("complete command")
    }
    fn only_queries(c: &Case, start: usize) {
        let server = c.server.lock().expect("server");
        assert!(server
            .requests
            .get(start..)
            .expect("preparation requests")
            .iter()
            .all(|wire| request_operation(wire) == AnchorOperation::query()));
    }
    fn fault_owner(
        c: &mut Case,
        after: bool,
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let attached = c.journal.active.as_mut().expect("active").anchor.take();
        c.journal.close();
        let (mut journal, remaining, count, _) =
            crate::durable::tests::fault_store(&c.path, c.peer.initiator_device(), after);
        journal.active.as_mut().expect("active").anchor = attached;
        c.journal = journal;
        (remaining, count)
    }

    #[test]
    fn exact_preparation_survives_expiry_without_ordinary_replay_or_authority_change() {
        let mut c = case();
        let grant = grant(&c);
        let before = c.journal.image().expect("original");
        let start = c.server.lock().expect("server").requests.len();
        let proposal = prepare(&mut c, &grant).expect("prepare exact target");
        assert!(c.journal.active.is_none());
        assert_eq!(proposal.subject(), c.subject);
        assert_eq!(proposal.witness_binding(), c.pin.binding());
        assert_eq!(proposal.operation(), grant.operation());
        assert_eq!(proposal.statement(), grant.statement_digest());
        assert_eq!(
            proposal.expected_head(),
            before
                .protection
                .head(before.revision, before.digest)
                .expect("head")
        );
        assert_eq!(proposal.target_head().revision(), before.revision + 1);
        let saved = disk(&c);
        assert_eq!(image_hash(&saved.0), before.digest);
        assert_eq!(
            saved
                .1
                .as_ref()
                .expect("pending")
                .get(..8)
                .expect("intent tag"),
            b"QPWINT02"
        );
        assert_eq!(inspect(&c).expect("read original"), Some(proposal));
        let count = c.server.lock().expect("server").requests.len();
        assert!(matches!(reopen(&c), Err(DurableError::Suspended)));
        assert!(matches!(
            crate::BootstrapCancellationJournal::open_anchored(
                &c.path.join("state.redb"),
                JournalKey::open(&c.path.join("key")).expect("key"),
                c.identity,
                client(&c.pin, &c.server, true)
            ),
            Err(DurableError::Suspended)
        ));
        assert_eq!(
            c.server.lock().expect("server").requests.len(),
            count,
            "ordinary reopen dispatched work"
        );
        let old = client(&c.pin, &c.server, true)
            .exchange(
                c.subject,
                AnchorOperation::admit_authority(c.peer.initiator_device().authority_binding())
                    .expect("old authority"),
            )
            .expect("old still current");
        assert_eq!(old.outcome(), AnchorOutcome::AuthorityCurrent);
        let target = client(&c.pin, &c.server, true)
            .exchange(
                c.subject,
                AnchorOperation::admit_authority(grant.successor_device().authority_binding())
                    .expect("target authority"),
            )
            .expect("target query");
        assert_eq!(target.outcome(), AnchorOutcome::AuthorityDenied);
        assert_eq!(old.observed_head(), proposal.expected_head());
        assert_eq!(target.observed_head(), proposal.expected_head());
        // Both policy and credential are expired/closed. Metadata recovery must
        // remain available, while it never returns an operational owner.
        c.server.lock().expect("server").now = 301;
        c.peer
            .initiator
            .current_policy()
            .expect("fixture policy owner")
            .close();
        assert_eq!(inspect(&c).expect("historical metadata"), Some(proposal));
        assert!(matches!(reopen(&c), Err(DurableError::Suspended)));
        assert_eq!(disk(&c), saved, "recovery must never reseal a target");
        // The only preparation traffic before explicit admission probes was Query.
        let server = c.server.lock().expect("server");
        assert!(server
            .requests
            .get(start..count)
            .expect("preparation request interval")
            .iter()
            .all(|wire| request_operation(wire) == AnchorOperation::query()));
    }

    #[test]
    fn every_reservation_sync_cut_preserves_original_image_and_never_dispatches_advance() {
        let mut baseline = case();
        let grant = grant(&baseline);
        let (_, count) = fault_owner(&mut baseline, false);
        count.store(0, Ordering::SeqCst);
        let measured = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let readback = Arc::clone(&measured);
        let persisted_count = Arc::clone(&count);
        write_intent::tests::on_bound_preparation(move || {
            readback.store(persisted_count.load(Ordering::SeqCst), Ordering::SeqCst);
        });
        prepare(&mut baseline, &grant).expect("measured reservation");
        let barriers = measured.load(Ordering::SeqCst);
        eprintln!(
            "preparation reservation syncs: {barriers}; including database drop: {}",
            count.load(Ordering::SeqCst)
        );
        assert!((2..=16).contains(&barriers));
        let mut retained = 0;
        let mut absent = 0;
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut c = case();
                let grant = self::grant(&c);
                let before = c.journal.image().expect("original");
                let start = c.server.lock().expect("server").requests.len();
                let (remaining, _) = fault_owner(&mut c, after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(prepare(&mut c, &grant), after);
                assert!(c.journal.active.is_none());
                assert_eq!(image_hash(&disk(&c).0), before.digest);
                if let Some(proposal) = inspect(&c).expect("authenticated disposition") {
                    retained += 1;
                    assert_eq!(proposal.expected_head().digest(), before.digest);
                    assert_eq!(proposal.operation(), grant.operation());
                    assert!(matches!(reopen(&c), Err(DurableError::Suspended)));
                } else {
                    absent += 1;
                    c.journal = reopen(&c).expect("no local intent, original state");
                    c.journal.close();
                }
                only_queries(&c, start);
            }
        }
        assert!(
            retained > 0 && absent > 0,
            "both durability outcomes must be observed"
        );
    }

    #[test]
    fn preparation_rejects_wrong_operation_and_inspection_rejects_wrong_scope() {
        let mut c = case();
        let grant = grant(&c);
        assert!(matches!(
            c.journal.prepare_local_credential_renewal(
                c.peer.initiator_device(),
                &grant,
                CredentialRenewalId::from_trusted_state([220; 32]).expect("other operation"),
                c.peer
                    .initiator
                    .current_policy()
                    .expect("fixture policy owner"),
                150
            ),
            Err(DurableError::Conflict)
        ));
        assert!(c.journal.active.is_none());
        assert!(inspect(&c).expect("no local reservation").is_none());
        c.journal = reopen(&c).expect("unchanged");
        prepare(&mut c, &grant).expect("original operation");
        let saved = disk(&c);
        assert!(matches!(
            DeviceJournal::inspect_credential_renewal_preparation(
                &c.path.join("state.redb"),
                JournalKey::open(&c.path.join("key")).expect("key"),
                c.peer.initiator_device(),
                c.peer
                    .initiator
                    .current_policy()
                    .expect("fixture policy owner"),
                JournalIdentity::from_trusted_state([222; 32]).expect("other journal")
            ),
            Err(DurableError::Conflict)
        ));
        assert!(DeviceJournal::inspect_credential_renewal_preparation(
            &c.path.join("state.redb"),
            JournalKey::open(&c.path.join("key")).expect("key"),
            c.peer.local_device(),
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            c.identity
        )
        .is_err());
        assert!(DeviceJournal::inspect_credential_renewal_preparation(
            &c.path.join("state.redb"),
            JournalKey::provision(&c.path.join("wrong-key")).expect("other key"),
            c.peer.initiator_device(),
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner"),
            c.identity
        )
        .is_err());
        assert_eq!(disk(&c), saved);
    }

    #[test]
    fn canonical_proposal_rejects_truncation_zero_binding_and_nonadjacent_heads() {
        let mut c = case();
        let grant = grant(&c);
        let proposal = prepare(&mut c, &grant).expect("proposal");
        let bytes = proposal.to_bytes();
        assert_eq!(bytes.len(), 296);
        assert_eq!(
            AnchorCredentialRenewalProposal::from_trusted_state(&bytes).expect("canonical"),
            proposal
        );
        for length in 0..bytes.len() {
            assert!(AnchorCredentialRenewalProposal::from_trusted_state(
                bytes.get(..length).expect("truncated prefix")
            )
            .is_err());
        }
        for range in [
            0..8,
            8..40,
            136..168,
            168..200,
            248..256,
            256..264,
            264..296,
        ] {
            let mut changed = bytes.clone();
            changed.get_mut(range).expect("metadata field").fill(0);
            assert!(AnchorCredentialRenewalProposal::from_trusted_state(&changed).is_err());
        }
        let mut changed = bytes.clone();
        changed.extend_from_slice(&[0]);
        assert!(AnchorCredentialRenewalProposal::from_trusted_state(&changed).is_err());
        let mut changed = bytes.clone();
        changed
            .get_mut(256..264)
            .expect("target revision")
            .copy_from_slice(&(proposal.target_head().revision() + 1).to_be_bytes());
        assert!(AnchorCredentialRenewalProposal::from_trusted_state(&changed).is_err());
    }

    #[test]
    fn runtime_closure_after_reservation_withholds_fresh_result_and_keeps_exact_intent() {
        let mut c = case();
        let grant = grant(&c);
        let policy_owner = Arc::clone(&c.peer.initiator);
        write_intent::tests::on_bound_preparation(move || {
            policy_owner
                .current_policy()
                .expect("fixture policy owner")
                .close()
        });
        assert!(matches!(
            prepare(&mut c, &grant),
            Err(DurableError::Protocol(Error::Closed))
        ));
        assert!(c.journal.active.is_none());
        let original = inspect(&c)
            .expect("historical preparation")
            .expect("retained exact intent");
        assert_eq!(original.operation(), grant.operation());
        assert_eq!(original.statement(), grant.statement_digest());
        assert!(matches!(reopen(&c), Err(DurableError::Suspended)));
        assert_eq!(inspect(&c).expect("same preparation"), Some(original));
    }

    #[test]
    fn authenticated_marker_changes_cannot_rebind_the_sealed_target() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut c = case();
        let grant = grant(&c);
        let proposal = prepare(&mut c, &grant).expect("original preparation");
        let (image, pending) = disk(&c);
        let pending = pending.expect("retained wire");
        for index in [8, 40, 72, pending.len() - 33] {
            let mut changed = pending
                .get(..pending.len() - 32)
                .expect("authenticated body")
                .to_vec();
            *changed.get_mut(index).expect("changed field") ^= 1;
            let key = JournalKey::open(&c.path.join("key")).expect("key");
            let derived = key.write_intent_key().expect("auth key");
            let mut auth =
                <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes()).expect("MAC");
            auth.update(&changed);
            changed.extend_from_slice(&auth.finalize().into_bytes());
            {
                let db = open_private_database(&c.path.join("state.redb")).expect("db");
                let tx = transaction(&db).expect("transaction");
                tx.open_table(TABLE)
                    .expect("table")
                    .insert("pending", changed.as_slice())
                    .expect("authenticated adversarial fixture");
                tx.commit().expect("persist fixture");
            }
            assert!(
                inspect(&c).is_err(),
                "authenticated change at {index} accepted"
            );
            assert_eq!(disk(&c).0, image);
        }
        {
            let db = open_private_database(&c.path.join("state.redb")).expect("db");
            let tx = transaction(&db).expect("transaction");
            tx.open_table(TABLE)
                .expect("table")
                .insert("pending", pending.as_slice())
                .expect("restore original intent");
            tx.commit().expect("restore fixture");
        }
        assert_eq!(
            inspect(&c).expect("original still recoverable"),
            Some(proposal)
        );
    }

    #[test]
    fn local_only_policy_cannot_create_required_witness_preparation() {
        let c = case();
        let grant = grant(&c);
        let f = crate::bootstrap::tests::fixture(PrekeyQuality::OneTimeBoth);
        let folder = directory();
        let path = folder.path().canonicalize().expect("path");
        let mut journal = crate::durable::tests::new_store(&path, f.initiator_device());
        assert!(matches!(
            journal.prepare_local_credential_renewal(
                f.initiator_device(),
                &grant,
                grant.operation(),
                f.initiator.current_policy().expect("fixture policy owner"),
                150
            ),
            Err(DurableError::AnchorRequired)
        ));
        assert!(journal.active.is_none());
        let db = open_private_database(&path.join("state.redb")).expect("db");
        let key = JournalKey::open(&path.join("key")).expect("key");
        let (_, pending) =
            write_intent::load_snapshot(&db, &key, bootstrap::storage_owner(f.initiator_device()))
                .expect("original local image");
        assert!(pending.is_none());
    }

    #[test]
    fn preparation_crash_child() {
        let Some(coordination) = std::env::var_os("QPERIAPT_CREDENTIAL_PREPARATION_CHILD") else {
            return;
        };
        let coordination = PathBuf::from(coordination);
        let mut c = case();
        assert!(
            c.path.starts_with(&coordination),
            "test must own the entire child directory"
        );
        fs::write(
            coordination.join("state-path"),
            c.path.as_os_str().as_encoded_bytes(),
        )
        .expect("private path");
        fs::write(coordination.join("witness-id"), c.pin.identity().as_bytes())
            .expect("public pin ID");
        fs::write(
            coordination.join("witness-public"),
            c.pin.public_key().encode(),
        )
        .expect("public pin key");
        let grant = grant(&c);
        prepare(&mut c, &grant).expect("must be killed before return");
        fs::write(coordination.join("returned"), b"unexpected").expect("return marker");
        assert!(
            !coordination.join("returned").exists(),
            "crash hook did not stop the original preparation"
        );
    }

    #[test]
    fn process_kill_after_reservation_recovers_exact_target_without_resealing() {
        use crate::durable::tests::ChildGuard;
        use std::process::{Command, Stdio};
        let folder = directory();
        let root = folder.path().canonicalize().expect("owned parent");
        let log = fs::File::create(root.join("child.log")).expect("child log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::anchoring::tests::credential_preparation::preparation_crash_child",
                    "--nocapture",
                ])
                .env("TMPDIR", &root)
                .env("QPERIAPT_CREDENTIAL_PREPARATION_CHILD", &root)
                .env("QPERIAPT_JOURNAL_CRASH_DIR", &root)
                .env("QPERIAPT_WRITE_INTENT_CRASH_PHASE", "credential-renewal")
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "child failed before durable marker: {}",
                fs::read_to_string(root.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned").exists());
        child.0.kill().expect("kill original process");
        assert!(!child.0.wait().expect("reap").success());
        let path = PathBuf::from(fs::read_to_string(root.join("state-path")).expect("child path"));
        assert!(path.starts_with(&root));
        let pin = AnchorPin::new(
            AnchorIdentity::from_trusted_state(
                fs::read(root.join("witness-id"))
                    .expect("ID")
                    .try_into()
                    .expect("width"),
            )
            .expect("pin ID"),
            crate::PublicKey::decode(&fs::read(root.join("witness-public")).expect("key"))
                .expect("pin key"),
        );
        let f = fixture_with_anchor_and_budget(
            PrekeyQuality::OneTimeBoth,
            AnchorRequirement::required(&pin),
            crate::ApplicationSendBudget::new(1024).expect("budget"),
        );
        let identity = crate::durable::tests::identity(&path);
        let inspect = || {
            DeviceJournal::inspect_credential_renewal_preparation(
                &path.join("state.redb"),
                JournalKey::open(&path.join("key")).expect("key"),
                f.initiator_device(),
                f.initiator.current_policy().expect("fixture policy owner"),
                identity,
            )
            .expect("authenticated original")
            .expect("retained proposal")
        };
        let proposal = inspect();
        assert_eq!(
            proposal.target_head().digest(),
            image_hash(&fs::read(root.join("saved-target-image")).expect("sealed target"))
        );
        f.initiator
            .current_policy()
            .expect("fixture policy owner")
            .close();
        assert_eq!(inspect(), proposal);
        let db = open_private_database(&path.join("state.redb")).expect("db");
        let read = db.begin_read().expect("read");
        let table = read.open_table(TABLE).expect("table");
        assert_eq!(
            table
                .get("pending")
                .expect("lookup")
                .expect("pending")
                .value(),
            fs::read(root.join("saved-write-intent")).expect("original intent")
        );
        assert_eq!(
            image_hash(
                table
                    .get("image")
                    .expect("lookup")
                    .expect("old image")
                    .value()
            ),
            proposal.expected_head().digest()
        );
    }

    #[test]
    fn actual_sealed_journal_target_is_the_exact_joint_witness_commit_after_a_lost_reply() {
        for apply in [true, false] {
            let mut c = case();
            let grant = grant(&c);
            let p = prepare(&mut c, &grant).expect("actual protected journal preparation");
            let saved = disk(&c);
            {
                let db = open_private_database(&c.path.join("state.redb")).expect("original db");
                let key = JournalKey::open(&c.path.join("key")).expect("key");
                let owner = bootstrap::storage_owner(c.peer.initiator_device());
                let (old, intent) =
                    write_intent::load_snapshot(&db, &key, owner).expect("authenticated intent");
                let target = intent
                    .expect("original preparation")
                    .authenticated_target(&key, owner)
                    .expect("exact target");
                assert_eq!(p.expected_head().digest(), old.digest);
                assert_eq!(p.target_head().digest(), target.digest);
                assert_eq!(target.owner, old.owner);
                rosters::check_credential_renewal_intent(
                    &target,
                    write_intent::RenewalBinding {
                        operation: grant.operation(),
                        credential: grant.statement_digest(),
                        policy: None,
                    },
                )
                .expect("same root operation in sealed target");
            }
            {
                let mut server = c.server.lock().expect("server");
                assert_eq!(
                    server
                        .store
                        .prepare_credential_renewal(
                            p,
                            &grant,
                            c.peer
                                .initiator
                                .current_policy()
                                .expect("fixture policy owner"),
                            150
                        )
                        .expect("independent witness approval"),
                    crate::AnchorCredentialRenewalState::Prepared
                );
                server.fail = Some((server.requests.len() + 1, true));
            }
            let operation = if apply {
                AnchorOperation::commit_credential_renewal(&p)
            } else {
                AnchorOperation::close_credential_renewal(&p)
            };
            assert!(matches!(
                client(&c.pin, &c.server, true).exchange(c.subject, operation),
                Err(AnchorClientError::Transport(_))
            ));
            {
                let mut server = c.server.lock().expect("server");
                server.fail = None;
                server.now = 301;
            }
            c.peer
                .initiator
                .current_policy()
                .expect("fixture policy owner")
                .close();
            let reply = client(&c.pin, &c.server, true)
                .exchange(c.subject, AnchorOperation::credential_renewal_status(&p))
                .expect("fresh historical witness observation");
            assert_eq!(
                reply.credential_renewal_state(&p).expect("exact proposal"),
                if apply {
                    crate::AnchorCredentialRenewalState::Applied
                } else {
                    crate::AnchorCredentialRenewalState::Closed
                }
            );
            assert_eq!(
                reply.observed_head(),
                if apply {
                    p.target_head()
                } else {
                    p.expected_head()
                }
            );
            let count = c.server.lock().expect("server").requests.len();
            assert!(matches!(reopen(&c), Err(DurableError::Suspended)));
            assert_eq!(c.server.lock().expect("server").requests.len(), count);
            assert_eq!(inspect(&c).expect("retained original metadata"), Some(p));
            assert_eq!(
                disk(&c),
                saved,
                "generic reopen must neither apply nor discard joint state"
            );
        }
    }
}

#[path = "credential_recovery_tests.rs"]
mod credential_recovery;

#[path = "independent_policy_tests.rs"]
mod independent_policy;

#[test]
fn publication_lost_witness_replies_reconcile_every_original_advance_before_release() {
    use crate::{
        PrekeyPublicationError, PrekeyPublicationKey as K, PrekeyPublicationPlan,
        PrekeyPublicationRequest, PrekeyPublicationRun, PrekeyPublicationStatus,
    };
    let plan = PrekeyPublicationPlan::new(
        [99; 32],
        crate::tests::interval(),
        &[
            K::generate(crate::LeafKind::SignedClassical, crate::tests::interval()),
            K::generate(crate::LeafKind::OneTimeClassical, crate::tests::interval()),
            K::generate(crate::LeafKind::LastResortPq, crate::tests::interval()),
            K::generate(crate::LeafKind::OneTimePq, crate::tests::interval()),
        ],
    )
    .expect("complete publication");
    let prepare = |c: &mut Case, id| {
        c.journal.prepare_prekey_publication(
            PrekeyPublicationRequest {
                id,
                plan: &plan,
                policy: c.peer.initiator.current_policy().expect("policy"),
                device: c.peer.initiator_device(),
                signer: &c.peer.signer_i,
            },
            PrekeyPublicationRun {
                cancel: &crate::Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(30),
            },
            || Ok(150),
        )
    };
    let mut baseline = case();
    let id = baseline.journal.next_prekey_publication_id().expect("next");
    let start = baseline.server.lock().expect("server").requests.len();
    prepare(&mut baseline, id).expect("baseline");
    let server = baseline.server.lock().expect("server");
    let requests = server.requests.get(start..).expect("publication requests");
    let mut cuts: Vec<_> = requests
        .iter()
        .enumerate()
        .filter_map(|(i, wire)| {
            // Every captured request was already signature-verified by the real store.
            let (body, _) = crate::crypto::open_envelope(wire).expect("request");
            assert_eq!(body.len(), 297);
            let command =
                AnchorOperation::from_trusted_state(body.get(200..).expect("canonical command"))
                    .expect("command");
            command
                .to_bytes()
                .first()
                .is_some_and(|kind| *kind == 2)
                .then_some(i + 1)
        })
        .collect();
    assert_eq!(cuts.len(), 6, "intent, four members and signed artifact");
    cuts.push(requests.len()); // Current check immediately before public release.
    drop(server);
    for after in [false, true] {
        for cut in &cuts {
            let mut c = case();
            let id = c.journal.next_prekey_publication_id().expect("next");
            let start = c.server.lock().expect("server").requests.len();
            c.server.lock().expect("server").fail = Some((start + cut, after));
            assert!(
                matches!(
                    prepare(&mut c, id),
                    Err(PrekeyPublicationError::Durable(DurableError::Anchor(_)))
                ),
                "cut {cut} after {after}"
            );
            c.journal.close();
            c.server.lock().expect("server").fail = None;
            c.journal = reopen(&c).expect("reconcile same witness target");
            let prepared = matches!(
                c.journal
                    .prekey_publication_status(id)
                    .expect("original state"),
                PrekeyPublicationStatus::Prepared { .. }
            );
            let before = c.journal.image().expect("recovered target");
            let result = prepare(&mut c, id).expect("exact retry");
            assert_eq!(result.id(), id);
            if prepared {
                let after = c.journal.image().expect("unchanged prepared record");
                let original = before
                    .records
                    .values()
                    .find(|r| r.kind == RecordKind::Publication)
                    .expect("original publication");
                let retained = after
                    .records
                    .values()
                    .find(|r| r.kind == RecordKind::Publication)
                    .expect("retained publication");
                assert_eq!(original.payload, retained.payload, "cut {cut}");
                assert_eq!(before.revision, after.revision);
            }
        }
    }
    eprintln!("publication witness reply matrix: {} cases", cuts.len() * 2);
}
