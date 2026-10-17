// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real TLS delivery of one member, retaining the whole local account transaction.
use super::super::tls_identity::{tls_limits, Identity};
use super::*;
use crate::connection_transport::{
    AccountDelivered, AccountDeliveryOutcome, Actor, Cancellation, ConnectionEndpoint, Consumer,
    Consumption, Error as TransportError, Run, RunLimits, Served,
};
use crate::SessionArchiveStore;
use std::{
    io::{self, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    thread,
    time::{Duration, Instant},
};

const BODY: &[u8] = b"one durable account operation";
const AD: &[u8] = b"account-message";
fn limits() -> RunLimits {
    RunLimits {
        exchanges: 1,
        timeout: Duration::from_secs(10),
        connect_timeout: Duration::from_secs(1),
        outer_deadline: None,
    }
}
fn accept(listener: &TcpListener, deadline: Instant) -> io::Result<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "account test accept deadline",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
}
struct Attempt<'a> {
    index: usize,
    id: FanoutId,
    address: SocketAddr,
    selected: &'a [usize],
    body: &'a [u8],
    cancel: Cancellation,
    limits: RunLimits,
}
impl Attempt<'_> {
    fn new(index: usize, id: FanoutId, address: SocketAddr) -> Self {
        Self {
            index,
            id,
            address,
            selected: &[0, 1],
            body: BODY,
            cancel: Cancellation::default(),
            limits: limits(),
        }
    }
}
#[derive(Clone, Copy)]
enum Effect {
    Commit,
    FailBefore,
    UnknownAfter,
}
struct Application {
    path: std::path::PathBuf,
    mode: Effect,
    writes: usize,
    close_policy: Option<Arc<BootstrapContext>>,
}
impl Consumer for Application {
    fn commit(&mut self, session: [u8; 32], delivery: &CommittedPlaintext) -> io::Result<()> {
        let expected = [
            session.as_slice(),
            delivery.message_id().as_bytes(),
            delivery.as_bytes(),
        ]
        .concat();
        let path = self.path.join("account-effect");
        if path.exists() {
            return if fs::read(path)? == expected {
                Ok(())
            } else {
                Err(io::ErrorKind::InvalidData.into())
            };
        }
        if matches!(self.mode, Effect::FailBefore) {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&expected)?;
        file.sync_all()?;
        fs::File::open(&self.path)?.sync_all()?;
        self.writes += 1;
        if let Some(context) = self.close_policy.take() {
            context
                .current_policy()
                .expect("fixture policy owner")
                .close();
        }
        if matches!(self.mode, Effect::UnknownAfter) {
            return Err(io::Error::other("application commit result lost"));
        }
        Ok(())
    }
}
struct Transport {
    n: Network,
    archives: SessionArchiveStore,
    receiver_archives: Vec<SessionArchiveStore>,
    client: Identity,
    servers: Vec<Identity>,
}
impl Transport {
    fn new(same_account: bool) -> Self {
        Self::from_network(Network::new(8, same_account))
    }
    fn from_network(mut n: Network) -> Self {
        let mut archives = SessionArchiveStore::provision(
            &n.sender_path.join("archives.redb"),
            n.sender.identity().expect("sender ID"),
        )
        .expect("sender archives");
        let mut receiver_archives = Vec::new();
        for (index, (context, session)) in n.f.contexts.iter().zip(&n.sessions).enumerate() {
            let proof = n
                .sender
                .archive_session_closure(context, *session)
                .expect("sender archive");
            archives
                .retain(&n.sender, context, *session, &proof)
                .expect("retain sender archive");
            let receiver = n.receivers.get_mut(index).expect("receiver");
            let mut index_store = SessionArchiveStore::provision(
                &canonical(n.receiver_dirs.get(index).expect("directory")).join("archives.redb"),
                receiver.identity().expect("receiver ID"),
            )
            .expect("receiver archives");
            let proof = receiver
                .archive_session_closure(context, *session)
                .expect("receiver archive");
            index_store
                .retain(receiver, context, *session, &proof)
                .expect("retain receiver archive");
            receiver_archives.push(index_store);
        }
        let servers = n
            .sessions
            .iter()
            .map(|_| Identity::new("localhost"))
            .collect();
        Self {
            n,
            archives,
            receiver_archives,
            client: Identity::new("client.test"),
            servers,
        }
    }
    fn run(&mut self, attempt: Attempt<'_>) -> Result<AccountDelivered, TransportError> {
        let context = self
            .n
            .f
            .contexts
            .get(attempt.index)
            .expect("selected context");
        let endpoint = ConnectionEndpoint::client(
            context,
            self.client
                .credentials(self.servers.get(attempt.index).expect("TLS peer")),
            tls_limits(),
        )
        .expect("client endpoint");
        let selected: Vec<_> = attempt
            .selected
            .iter()
            .map(|index| FanoutTarget {
                context: self.n.f.contexts.get(*index).expect("target context"),
                session: *self.n.sessions.get(*index).expect("target session"),
            })
            .collect();
        endpoint.send_account_member(
            Actor {
                journal: &mut self.n.sender,
                archives: &mut self.archives,
                context,
                signer: &self.n.f.local_signer,
            },
            FanoutInput {
                id: attempt.id,
                account: self.n.f.peers.first().expect("account").account_id(),
                targets: &selected,
                plaintext: attempt.body,
                associated_data: AD,
            },
            *self
                .n
                .sessions
                .get(attempt.index)
                .expect("selected session"),
            Run {
                address: attempt.address,
                server_name: "localhost",
                limits: attempt.limits,
                cancel: &attempt.cancel,
            },
            || Ok(150),
        )
    }
    fn exchange(
        &mut self,
        index: usize,
        id: FanoutId,
        mode: Effect,
    ) -> (
        Result<AccountDelivered, TransportError>,
        Result<Served, TransportError>,
        usize,
    ) {
        let (result, mut served, writes) = self.exchange_sequence(index, id, vec![mode], None, 1);
        assert_eq!(served.len(), 1);
        (result, served.remove(0), writes)
    }
    fn exchange_sequence(
        &mut self,
        index: usize,
        id: FanoutId,
        modes: Vec<Effect>,
        close_policy: Option<Arc<BootstrapContext>>,
        attempts: u16,
    ) -> (
        Result<AccountDelivered, TransportError>,
        Vec<Result<Served, TransportError>>,
        usize,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        listener.set_nonblocking(true).expect("bounded accept");
        let address = listener.local_addr().expect("address");
        let mut receiver = self.n.receivers.remove(index);
        let mut archives = self.receiver_archives.remove(index);
        let signer = self.n.f.peer_signers.remove(index);
        let context = Arc::clone(self.n.f.contexts.get(index).expect("context"));
        let endpoint = ConnectionEndpoint::server(
            &context,
            self.servers
                .get(index)
                .expect("TLS peer")
                .credentials(&self.client),
            tls_limits(),
        )
        .expect("server endpoint");
        let mut application = Application {
            path: canonical(self.n.receiver_dirs.get(index).expect("directory")),
            mode: Effect::Commit,
            writes: 0,
            close_policy,
        };
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut results = Vec::new();
            for mode in modes {
                application.mode = mode;
                let result = accept(&listener, deadline)
                    .map_err(TransportError::Io)
                    .and_then(|stream| {
                        endpoint.serve(
                            stream,
                            Actor {
                                journal: &mut receiver,
                                archives: &mut archives,
                                context: &context,
                                signer: &signer,
                            },
                            &mut application,
                            limits(),
                            &Cancellation::default(),
                            || Ok(150),
                        )
                    });
                results.push(result);
            }
            (
                results,
                receiver,
                archives,
                signer,
                application.writes,
                listener,
            )
        });
        let mut attempt = Attempt::new(index, id, address);
        attempt.limits.exchanges = attempts;
        let result = self.run(attempt);
        let (served, receiver, archives, signer, writes, listener) =
            server.join().expect("server join");
        assert_no_connection(&listener);
        self.n.receivers.insert(index, receiver);
        self.receiver_archives.insert(index, archives);
        self.n.f.peer_signers.insert(index, signer);
        (result, served, writes)
    }
    fn reopen(&mut self) {
        self.archives.close();
        self.n.reopen();
        self.archives = SessionArchiveStore::open(
            &self.n.sender_path.join("archives.redb"),
            self.n.sender.identity().expect("same ID"),
        )
        .expect("exact original archive index");
    }
    fn status(&mut self, index: usize, message: MessageId) -> MessageStatus {
        self.n
            .sender
            .message_status(
                self.n.f.contexts.get(index).expect("context"),
                *self.n.sessions.get(index).expect("session"),
                message,
            )
            .expect("original message status")
    }
}
fn idle_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking observer");
    let address = listener.local_addr().expect("address");
    (listener, address)
}
fn assert_no_connection(listener: &TcpListener) {
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}
fn confirmed(result: Result<AccountDelivered, TransportError>) -> AccountDelivered {
    let result = result.expect("account member delivered");
    assert_eq!(
        result.outcome,
        AccountDeliveryOutcome::Consumption(Consumption::Confirmed)
    );
    result
}

#[test]
fn account_tls_commits_all_members_before_first_dispatch_and_reopens_exactly() {
    for mode in 0..3 {
        let mut t = match mode {
            0 => Transport::new(false),
            1 => Transport::new(true),
            _ => Transport::from_network(super::roles::mixed_roles()),
        };
        let id = t.n.sender.next_fanout_id().expect("original ID");
        let (first, served, writes) = t.exchange(0, id, Effect::Commit);
        let first = confirmed(first);
        assert_eq!(first.exchanges, 1);
        assert!(matches!(
            served,
            Ok(Served::Consumed {
                duplicate: false,
                ..
            })
        ));
        assert_eq!(writes, 1);
        let members = t.n.send(id, BODY).expect("same complete aggregate");
        assert_eq!(members.len(), 2);
        assert!(matches!(
            members.first().expect("first").output,
            FanoutOutput::Acknowledged
        ));
        let second = members.get(1).expect("second");
        assert!(matches!(second.output, FanoutOutput::Committed(_)));
        assert_eq!(t.status(1, second.message), MessageStatus::Committed);
        // The previous pairwise carrier cannot be used for this aggregate slot.
        assert!(matches!(
            t.n.sender.send_message(
                t.n.f.contexts.get(1).expect("context"),
                second.session,
                second.message,
                BODY,
                AD,
                150,
            ),
            Err(DurableError::Suspended)
        ));
        let context = t.n.f.contexts.first().expect("first context");
        let report =
            t.n.sender
                .begin_session_closure(context, first.session)
                .expect("close acknowledged member");
        super::super::closure::account(&t.n.sender_path, &report);
        t.n.sender
            .acknowledge_session_closure(context, first.session, report.report)
            .expect("accounted first session");
        t.reopen();
        let (delivered, served, writes) = t.exchange(1, id, Effect::Commit);
        let delivered = confirmed(delivered);
        assert_eq!(delivered.message, second.message);
        assert_eq!(writes, 1);
        assert!(matches!(
            served,
            Ok(Served::Consumed {
                duplicate: false,
                ..
            })
        ));
        let (listener, address) = idle_listener();
        assert_eq!(confirmed(t.run(Attempt::new(0, id, address))).exchanges, 0);
        assert_eq!(confirmed(t.run(Attempt::new(1, id, address))).exchanges, 0);
        assert_no_connection(&listener);
        for (index, message) in [first.message, second.message].into_iter().enumerate() {
            let expected = [
                t.n.sessions.get(index).expect("session").as_slice(),
                message.as_bytes(),
                BODY,
            ]
            .concat();
            assert_eq!(
                fs::read(
                    canonical(t.n.receiver_dirs.get(index).expect("directory"))
                        .join("account-effect")
                )
                .expect("independent effect readback"),
                expected
            );
        }
    }
}

#[test]
fn account_tls_reconnects_exactly_and_rechecks_other_member_policy_before_retry() {
    let mut t = Transport::new(false);
    let id = t.n.sender.next_fanout_id().expect("original aggregate");
    let (result, served, writes) =
        t.exchange_sequence(0, id, vec![Effect::UnknownAfter, Effect::Commit], None, 2);
    let delivered = confirmed(result);
    assert_eq!(delivered.exchanges, 2);
    assert_eq!(writes, 1);
    assert!(matches!(
        served.first(),
        Some(Err(TransportError::Application(_)))
    ));
    assert!(matches!(
        served.get(1),
        Some(Ok(Served::Consumed {
            duplicate: false,
            ..
        }))
    ));
    let mut t = Transport::from_network(super::roles::mixed_roles());
    let id = t.n.sender.next_fanout_id().expect("original aggregate");
    let other = Arc::clone(t.n.f.contexts.get(1).expect("other required member"));
    let (result, served, writes) =
        t.exchange_sequence(0, id, vec![Effect::UnknownAfter], Some(other), 2);
    assert!(matches!(
        result,
        Err(TransportError::Durable(DurableError::Protocol(
            Error::Closed
        )))
    ));
    assert_eq!(writes, 1);
    assert!(matches!(
        served.first(),
        Some(Err(TransportError::Application(_)))
    ));
    assert_eq!(served.len(), 1);
    // Selected peer authority remains valid: it was the OTHER context's close
    // that refused the second dispatch, not a selected-peer TLS failure.
    t.n.f
        .contexts
        .first()
        .expect("selected context")
        .check_session_identity(150)
        .expect("selected peer still authorized");
    assert_eq!(
        t.n.sender.fanout_status(id).expect("retained aggregate"),
        FanoutStatus::Committed
    );
}

#[test]
fn account_tls_refuses_incomplete_duplicate_wrong_peer_cancelled_and_expired_before_commit() {
    let mut t = Transport::new(false);
    let id = t.n.sender.next_fanout_id().expect("ID");
    let (listener, address) = idle_listener();
    for (case, (index, selected)) in [(0, &[0][..]), (0, &[0, 0][..]), (1, &[0][..])]
        .into_iter()
        .enumerate()
    {
        let mut attempt = Attempt::new(index, id, address);
        attempt.selected = selected;
        let result = t.run(attempt);
        if case == 0 {
            assert!(matches!(
                result,
                Err(TransportError::Durable(DurableError::Protocol(
                    Error::PolicyDenied
                )))
            ));
        } else {
            assert!(matches!(result, Err(TransportError::Binding)));
        }
        assert_eq!(
            t.n.sender.fanout_status(id).expect("no reservation"),
            FanoutStatus::Absent
        );
        assert_no_connection(&listener);
    }
    let attempt = Attempt::new(0, id, address);
    attempt.cancel.cancel();
    assert!(matches!(t.run(attempt), Err(TransportError::Cancelled)));
    let mut attempt = Attempt::new(0, id, address);
    attempt.limits.outer_deadline = Some(Instant::now());
    assert!(matches!(t.run(attempt), Err(TransportError::Deadline)));
    assert_eq!(
        t.n.sender.fanout_status(id).expect("no reservation"),
        FanoutStatus::Absent
    );
    assert_no_connection(&listener);
    t.n.send(id, BODY).expect("complete reservation");
    let mut attempt = Attempt::new(0, id, address);
    attempt.body = b"changed input";
    assert!(matches!(
        t.run(attempt),
        Err(TransportError::Durable(DurableError::Conflict))
    ));
    assert_eq!(
        t.n.sender.fanout_status(id).expect("retained aggregate"),
        FanoutStatus::Committed
    );
    assert_no_connection(&listener);
}

#[test]
fn account_tls_pending_prefix_and_duplicate_receipts_do_not_invent_consumption() {
    let mut t = Transport::new(false);
    let context = t.n.f.contexts.first().expect("first context");
    let session = *t.n.sessions.first().expect("first session");
    let gap =
        t.n.sender
            .next_message_id(context, session, 150)
            .expect("earlier ordinary slot");
    t.n.sender
        .send_message(
            context,
            session,
            gap,
            b"earlier undelivered effect",
            AD,
            150,
        )
        .expect("undelivered ordinary outbox");
    let id = t.n.sender.next_fanout_id().expect("account ID");
    let mut original = None;
    for duplicate in [false, true] {
        let (result, served, writes) = t.exchange(0, id, Effect::Commit);
        let delivered = result.expect("valid partial consumption proof");
        assert_eq!(
            delivered.outcome,
            AccountDeliveryOutcome::Consumption(Consumption::PrefixPending)
        );
        assert_eq!(delivered.exchanges, 1);
        assert_ne!(delivered.message, gap);
        assert_eq!(t.status(0, delivered.message), MessageStatus::Committed);
        assert!(
            matches!(served, Ok(Served::Consumed { duplicate: observed, .. }) if observed == duplicate)
        );
        assert_eq!(writes, usize::from(!duplicate));
        if let Some(message) = original {
            assert_eq!(message, delivered.message);
        } else {
            original = Some(delivered.message);
        }
    }
    assert_eq!(t.status(0, gap), MessageStatus::Committed);
    assert_eq!(
        t.n.sender.fanout_status(id).expect("original aggregate"),
        FanoutStatus::Committed
    );
}

#[test]
fn account_tls_application_failures_keep_all_ids_and_reconcile_durable_effects() {
    for mode in [Effect::FailBefore, Effect::UnknownAfter] {
        let mut t = Transport::new(false);
        let id = t.n.sender.next_fanout_id().expect("ID");
        let (result, served, writes) = t.exchange(0, id, mode);
        assert!(matches!(
            result,
            Err(TransportError::RetryExhausted { attempts: 1, .. })
        ));
        assert!(matches!(served, Err(TransportError::Application(_))));
        assert_eq!(writes, usize::from(matches!(mode, Effect::UnknownAfter)));
        let original = t.n.send(id, BODY).expect("original committed members");
        assert!(original
            .iter()
            .all(|member| matches!(member.output, FanoutOutput::Committed(_))));
        t.reopen();
        let (result, served, writes) = t.exchange(0, id, Effect::Commit);
        assert_eq!(
            confirmed(result).message,
            original.first().expect("first").message
        );
        assert!(matches!(
            served,
            Ok(Served::Consumed {
                duplicate: false,
                ..
            })
        ));
        assert_eq!(writes, usize::from(matches!(mode, Effect::FailBefore)));
        let (result, served, writes) = t.exchange(1, id, Effect::Commit);
        assert_eq!(
            confirmed(result).message,
            original.get(1).expect("second").message
        );
        assert!(matches!(
            served,
            Ok(Served::Consumed {
                duplicate: false,
                ..
            })
        ));
        assert_eq!(writes, 1);
    }
}

#[test]
fn account_tls_rechecks_the_complete_roster_before_later_member_dispatch() {
    let mut t = Transport::new(false);
    let id = t.n.sender.next_fanout_id().expect("ID");
    let (result, served, _) = t.exchange(0, id, Effect::Commit);
    confirmed(result);
    assert!(served.is_ok());
    let entry =
        t.n.f
            .root
            .roster_entry(t.n.f.certificates.first().expect("retained credential"))
            .expect("entry");
    let issued =
        t.n.f
            .root
            .issue_roster(2, interval(), &[entry])
            .expect("revoke second peer");
    let pin = AccountPin::new(
        t.n.f.root.account_id().expect("account"),
        t.n.f.root.public_key().expect("root"),
        issued.checkpoint(),
        t.n.f
            .contexts
            .first()
            .expect("context")
            .current_policy()
            .expect("fixture policy owner")
            .family(),
    )
    .expect("independent pin");
    let roster = pin
        .verify_roster(issued.as_bytes(), 150)
        .expect("verified update");
    t.n.sender
        .install_roster(&roster, 150)
        .expect("committed revocation");
    t.reopen();
    let (listener, address) = idle_listener();
    for index in [0, 1] {
        assert!(matches!(
            t.run(Attempt::new(index, id, address)),
            Err(TransportError::Durable(DurableError::Protocol(
                Error::Scope
            )))
        ));
        assert_no_connection(&listener);
    }
    assert_eq!(
        t.n.sender.fanout_status(id).expect("original aggregate"),
        FanoutStatus::Committed
    );
    assert!(!canonical(t.n.receiver_dirs.get(1).expect("second device"))
        .join("account-effect")
        .exists());
}

#[test]
fn account_tls_retained_unknown_and_retired_epoch_outcomes_never_claim_consumption() {
    let mut t = Transport::new(false);
    let id = t.n.sender.next_fanout_id().expect("original aggregate");
    let (delivered, served, _) = t.exchange(0, id, Effect::Commit);
    confirmed(delivered);
    assert!(matches!(served, Ok(Served::Consumed { .. })));
    super::lifecycle::rekey_second(&mut t.n, 1);
    let context = Arc::clone(t.n.f.contexts.get(1).expect("second context"));
    let session = *t.n.sessions.get(1).expect("second session");
    let report =
        t.n.sender
            .begin_closed_epoch_resolution(&context, session, 0, 150)
            .expect("frozen unknown outcome");
    let (listener, address) = idle_listener();
    let pending = t
        .run(Attempt::new(1, id, address))
        .expect("explicit accounting state");
    assert_eq!(
        (pending.outcome, pending.exchanges),
        (AccountDeliveryOutcome::ResolutionPending, 0)
    );
    assert_no_connection(&listener);
    super::lifecycle::account(&t.n.sender_path.join("account-resolution"), &report);
    t.n.sender
        .acknowledge_closed_epoch_resolution(&context, session, 0, report.resolution_id(), 150)
        .expect("durable host accounting");
    let unknown = t
        .run(Attempt::new(1, id, address))
        .expect("explicit unknown outcome");
    assert_eq!(
        (unknown.outcome, unknown.exchanges),
        (AccountDeliveryOutcome::DeliveryUnknown, 0)
    );
    assert_eq!(
        (unknown.session, unknown.message),
        (pending.session, pending.message)
    );
    let peer = t.n.receivers.get_mut(1).expect("second journal");
    let peer_report = peer
        .begin_closed_epoch_resolution(&context, session, 0, 150)
        .expect("unseen range report");
    super::lifecycle::account(
        &canonical(t.n.receiver_dirs.get(1).expect("peer directory")).join("account-resolution"),
        &peer_report,
    );
    peer.acknowledge_closed_epoch_resolution(
        &context,
        session,
        0,
        peer_report.resolution_id(),
        150,
    )
    .expect("peer accounting");
    for target in 2..=4 {
        super::lifecycle::rekey_second(&mut t.n, target);
    }
    t.reopen();
    let retired = t
        .run(Attempt::new(1, id, address))
        .expect("explicit retired history");
    assert_eq!(
        (retired.outcome, retired.exchanges),
        (AccountDeliveryOutcome::HistoryRetired, 0)
    );
    assert_eq!(
        (retired.session, retired.message),
        (pending.session, pending.message)
    );
    assert_no_connection(&listener);
    assert!(
        !canonical(t.n.receiver_dirs.get(1).expect("peer directory"))
            .join("account-effect")
            .exists()
    );
}

#[test]
fn account_tls_session_freeze_never_releases_wire_or_blocks_another_admitted_member() {
    let mut t = Transport::new(false);
    let id = t.n.sender.next_fanout_id().expect("original aggregate");
    let members = t.n.send(id, BODY).expect("all member outboxes committed");
    let second = members.get(1).expect("second member");
    let context = Arc::clone(t.n.f.contexts.get(1).expect("second context"));
    let report =
        t.n.sender
            .begin_session_closure(&context, second.session)
            .expect("freeze second session");
    let (listener, address) = idle_listener();
    let frozen = t
        .run(Attempt::new(1, id, address))
        .expect("explicit freeze outcome");
    assert_eq!(
        (frozen.outcome, frozen.exchanges),
        (AccountDeliveryOutcome::ResolutionPending, 0)
    );
    assert_eq!(frozen.message, second.message);
    assert_no_connection(&listener);
    super::super::closure::account(&t.n.sender_path, &report);
    t.n.sender
        .acknowledge_session_closure(&context, second.session, report.report)
        .expect("durably accounted closure");
    t.reopen();
    let unknown = t
        .run(Attempt::new(1, id, address))
        .expect("explicit terminal outcome");
    assert_eq!(
        (unknown.outcome, unknown.exchanges),
        (AccountDeliveryOutcome::DeliveryUnknown, 0)
    );
    assert_no_connection(&listener);
    assert!(
        !canonical(t.n.receiver_dirs.get(1).expect("second directory"))
            .join("account-effect")
            .exists()
    );
    let (delivered, served, writes) = t.exchange(0, id, Effect::Commit);
    assert_eq!(
        confirmed(delivered).message,
        members.first().expect("first").message
    );
    assert!(matches!(
        served,
        Ok(Served::Consumed {
            duplicate: false,
            ..
        })
    ));
    assert_eq!(writes, 1);
}
