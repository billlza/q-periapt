// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorClient, AnchorIdentity, AnchorPin, AnchorSigningKey, AnchorStore, AnchorTransport,
};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

struct Witness {
    store: AnchorStore,
    calls: usize,
    now: u64,
    fail: Option<(usize, bool)>,
}
struct Transport(Arc<Mutex<Witness>>);
impl AnchorTransport for Transport {
    fn exchange(&mut self, wire: &[u8], _: Instant) -> io::Result<Vec<u8>> {
        let mut witness = self.0.lock().expect("witness actor");
        witness.calls += 1;
        let attempt = witness.calls;
        if witness.fail == Some((attempt, false)) {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        let now = witness.now;
        let result = witness.store.handle(wire, now).map_err(io::Error::other)?;
        if witness.fail == Some((attempt, true)) {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        Ok(result)
    }
}
fn signer(device: &VerifiedDevice) -> DeviceSigningKey {
    let seed = match device.device_id() {
        id if id == [20; 16] => Ok(22),
        id if id == [40; 16] => Ok(42),
        id if id == [41; 16] => Ok(44),
        _ => Err("unexpected fixture device"),
    }
    .expect("known separately enrolled identity");
    DeviceSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("same test signing identity")
}
fn client(pin: &AnchorPin, witness: &Arc<Mutex<Witness>>, device: &VerifiedDevice) -> AnchorClient {
    AnchorClient::new(
        pin.clone(),
        signer(device),
        Box::new(Transport(Arc::clone(witness))),
        Duration::from_secs(10),
    )
    .expect("witness client")
}
struct Anchored {
    network: Network,
    witness: Arc<Mutex<Witness>>,
    pin: AnchorPin,
    _dir: tempfile::TempDir,
}
impl Anchored {
    fn new() -> Self {
        let dir = directory();
        let path = canonical(&dir);
        let store = AnchorStore::provision(
            &path.join("witness.redb"),
            JournalKey::provision(&path.join("key")).expect("witness wrapping"),
            AnchorSigningKey::generate().expect("witness signer"),
            AnchorIdentity::generate().expect("witness identity"),
        )
        .expect("real witness");
        let pin = store.pin().expect("independent pin");
        let witness = Arc::new(Mutex::new(Witness {
            store,
            calls: 0,
            now: 150,
            fail: None,
        }));
        let f = fixture_with_anchor(4, false, None, AnchorRequirement::required(&pin));
        let network = Network::with_fixture(f, |path, device, policy| {
            let mut journal = DeviceJournal::provision_anchored(
                &path.join("state.redb"),
                JournalKey::provision(&path.join("key")).expect("device key"),
                device,
                policy,
                150,
            )
            .expect("anchored device");
            fs::write(
                path.join("store-id"),
                journal.identity().expect("identity").as_bytes(),
            )
            .expect("independent identity");
            let genesis = journal.anchor_genesis(device, policy).expect("genesis");
            witness
                .lock()
                .expect("witness")
                .store
                .enroll(&genesis, device, policy, 150)
                .expect("trusted enrollment");
            journal
                .activate_anchor(device, policy, client(&pin, &witness, device))
                .expect("activate");
            journal
        });
        Self {
            network,
            witness,
            pin,
            _dir: dir,
        }
    }
    fn reopen_sender(&mut self) {
        let n = &mut self.network;
        n.sender.close();
        n.sender = DeviceJournal::open_anchored(
            &n.sender_path.join("state.redb"),
            JournalKey::open(&n.sender_path.join("key")).expect("key"),
            &n.f.local,
            n.f.contexts.first().expect("context").policy(),
            crate::durable::tests::identity(&n.sender_path),
            client(&self.pin, &self.witness, &n.f.local),
        )
        .expect("exact required-witness reconciliation");
    }
}

#[test]
fn account_fanout_every_witness_loss_keeps_the_complete_aggregate_and_exact_budget() {
    let mut baseline = Anchored::new();
    let id = baseline.network.sender.next_fanout_id().expect("ID");
    let before = baseline.witness.lock().expect("witness").calls;
    baseline
        .network
        .send(id, b"witness-bound complete set")
        .expect("baseline");
    let calls = baseline.witness.lock().expect("witness").calls - before;
    assert!((8..=20).contains(&calls), "measured witness calls={calls}");
    for offset in 1..=calls {
        for after in [false, true] {
            let mut c = Anchored::new();
            let id = c.network.sender.next_fanout_id().expect("ID");
            {
                let mut witness = c.witness.lock().expect("witness");
                witness.fail = Some((witness.calls + offset, after));
            }
            assert!(
                matches!(
                    c.network.send(id, b"witness-bound complete set"),
                    Err(DurableError::Anchor(_))
                ),
                "offset={offset}, after={after}"
            );
            assert!(c.network.sender.active.is_none());
            // Ordinary reopening cannot apply an outstanding anchored write or
            // downgrade the aggregate's required protection.
            let n = &c.network;
            let mut ordinary = DeviceJournal::open(
                &n.sender_path.join("state.redb"),
                JournalKey::open(&n.sender_path.join("key")).expect("key"),
                &n.f.local,
                crate::durable::tests::identity(&n.sender_path),
            );
            match &mut ordinary {
                Ok(journal) => {
                    assert!(matches!(
                        journal.fanout_status(id),
                        Err(DurableError::AnchorRequired)
                    ));
                    journal.close();
                }
                Err(error) => {
                    assert!(
                        matches!(error, DurableError::AnchorRequired),
                        "unexpected ordinary admission failure: {error}"
                    );
                }
            }
            drop(ordinary);
            c.witness.lock().expect("witness").fail = None;
            c.reopen_sender();
            let result = c
                .network
                .send(id, b"witness-bound complete set")
                .expect("whole recovery");
            c.network
                .check_delivery(&result, b"witness-bound complete set");
            let expected = wires(&result);
            c.reopen_sender();
            assert_eq!(
                wires(
                    &c.network
                        .send(id, b"witness-bound complete set")
                        .expect("exact retry")
                ),
                expected
            );
            for (context, session) in c.network.f.contexts.iter().zip(&c.network.sessions) {
                let progress = c
                    .network
                    .sender
                    .application_send_progress(context, *session)
                    .expect("budget");
                assert_eq!(
                    (progress.committed, progress.reserved, progress.remaining),
                    (1, false, 3)
                );
            }
        }
    }
    eprintln!(
        "ACCOUNT_FANOUT_WITNESS_RECOVERY calls={calls} before_after_losses={}",
        calls * 2
    );
}

fn reserve_with_loss(c: &mut Anchored, offset: usize) -> FanoutId {
    let id = c.network.sender.next_fanout_id().expect("ID");
    {
        let mut witness = c.witness.lock().expect("witness");
        witness.fail = Some((witness.calls + offset, true));
    }
    assert!(matches!(
        c.network.send(id, b"abandon anchored reservation"),
        Err(DurableError::Anchor(_))
    ));
    assert!(c.network.sender.active.is_none());
    c.witness.lock().expect("witness").fail = None;
    c.reopen_sender();
    id
}

fn indexed_cleanup(
    c: &Anchored,
    id: FanoutId,
) -> Result<(crate::SessionArchiveStore, crate::FanoutAbandonmentJournal), DurableError> {
    let path = &c.network.sender_path;
    let identity = crate::durable::tests::identity(path);
    let mut index = crate::SessionArchiveStore::open(&path.join("archives.redb"), identity)?;
    let owner = crate::FanoutAbandonmentJournal::open_anchored(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key"))?,
        identity,
        id,
        &mut index,
        client(&c.pin, &c.witness, &c.network.f.local),
    )?;
    Ok((index, owner))
}
fn retain_cleanup(c: &mut Anchored) {
    let mut index = archive::retain(&mut c.network);
    index.close();
    for context in &c.network.f.contexts {
        context.policy().close();
    }
    c.network.sender.close();
}
fn discover_reserved() -> (Anchored, FanoutId, usize) {
    for offset in 1..=12 {
        let mut c = Anchored::new();
        let id = reserve_with_loss(&mut c, offset);
        if c.network.sender.fanout_status(id).expect("phase") == FanoutStatus::Reserved {
            return (c, id, offset);
        }
    }
    unreachable!("no observed reservation boundary")
}
fn prepare_indexed(stage: u8, cut: usize) -> (Anchored, FanoutId, Option<FanoutAbandonmentId>) {
    let mut c = Anchored::new();
    let id = reserve_with_loss(&mut c, cut);
    assert_eq!(
        c.network.sender.fanout_status(id).expect("actual phase"),
        FanoutStatus::Reserved
    );
    retain_cleanup(&mut c);
    let report = if stage > 0 {
        let (_index, mut owner) = indexed_cleanup(&c, id).expect("original scope");
        let report = owner.begin().expect("freeze");
        abandonment::account(&c.network.sender_path, &report);
        if stage == 2 {
            owner
                .acknowledge(report.report)
                .expect("accounted terminal");
        }
        Some(report.report)
    } else {
        None
    };
    (c, id, report)
}
fn indexed_transition(
    c: &Anchored,
    id: FanoutId,
    stage: u8,
    report: Option<FanoutAbandonmentId>,
) -> Result<(), DurableError> {
    let (_index, mut owner) = indexed_cleanup(c, id)?;
    match stage {
        0 => owner.begin().map(|_| ()),
        1 => owner.acknowledge(report.expect("accounted receipt")),
        2 => owner.retire_metadata(),
        _ => unreachable!(),
    }
}

#[test]
fn archived_fanout_preserves_every_witness_loss_through_terminal_metadata_retirement() {
    let (_, _, cut) = discover_reserved();
    for stage in 0..3 {
        let (baseline, id, report) = prepare_indexed(stage, cut);
        let before = baseline.witness.lock().expect("witness").calls;
        indexed_transition(&baseline, id, stage, report).expect("measure open and transition");
        let calls = baseline.witness.lock().expect("witness").calls - before;
        assert_eq!(calls, 5, "measured original witness queries and advance");
        for after in [false, true] {
            for at in 1..=calls {
                let (c, id, report) = prepare_indexed(stage, cut);
                {
                    let mut witness = c.witness.lock().expect("witness");
                    witness.fail = Some((witness.calls + at, after));
                }
                assert!(
                    matches!(
                        indexed_transition(&c, id, stage, report),
                        Err(DurableError::Anchor(_))
                    ),
                    "stage={stage} at={at} after={after}"
                );
                c.witness.lock().expect("witness").fail = None;
                let reopened = indexed_cleanup(&c, id);
                if matches!(&reopened, Err(DurableError::Protocol(Error::Retired))) {
                    assert_eq!(stage, 2);
                    continue;
                }
                let (_index, mut owner) = reopened.expect("reconcile original sealed work");
                if stage == 0 {
                    let report = owner.begin().expect("whole frozen report");
                    assert_eq!(report.sessions.len(), c.network.sessions.len());
                    assert_eq!(owner.begin().expect("same immutable report"), report);
                } else if stage == 1 {
                    let report = report.expect("receipt");
                    owner.acknowledge(report).expect("exact ack");
                    assert_eq!(
                        owner.status().expect("state"),
                        FanoutStatus::Abandoned(report)
                    );
                } else {
                    owner.retire_metadata().expect("exact retirement");
                    assert_eq!(owner.status().expect("state"), FanoutStatus::Retired);
                }
            }
        }
        eprintln!("ARCHIVED_FANOUT_WITNESS stage={stage} measured_open_and_transition_calls={calls} before_after_losses={}",calls*2);
    }
}

#[test]
fn archived_fanout_expired_witness_only_confirms_already_applied_freeze() {
    let (_, _, cut) = discover_reserved();
    for after in [false, true] {
        let (c, id, _) = prepare_indexed(0, cut);
        let (mut index, mut owner) = indexed_cleanup(&c, id).expect("owner");
        {
            let mut witness = c.witness.lock().expect("witness");
            witness.fail = Some((witness.calls + 2, after));
        }
        assert!(matches!(owner.begin(), Err(DurableError::Anchor(_))));
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        index.close();
        {
            let mut witness = c.witness.lock().expect("witness");
            witness.fail = None;
            witness.now = 250;
        }
        let result = indexed_cleanup(&c, id);
        if after {
            let (_index, mut owner) = result.expect("already applied original freeze");
            let report = owner.begin().expect("read-only exact loss report");
            abandonment::account(&c.network.sender_path, &report);
            assert!(
                matches!(
                    owner.acknowledge(report.report),
                    Err(DurableError::Anchor(_))
                ),
                "expiry must not permit a fresh terminal advance"
            );
        } else {
            assert!(
                matches!(result, Err(DurableError::Anchor(_))),
                "expiry must not perform the pending freeze"
            );
        }
    }
}

#[test]
fn archived_fanout_retired_disposition_still_requires_fresh_original_witness() {
    let (_, _, cut) = discover_reserved();
    let (c, id, _) = prepare_indexed(2, cut);
    let (mut index, mut owner) = indexed_cleanup(&c, id).expect("terminal owner");
    let path = &c.network.sender_path;
    owner.retire_metadata().expect("retirement");
    owner.close();
    assert!(matches!(
        crate::FanoutAbandonmentJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            crate::durable::tests::identity(path),
            id,
            &mut index
        ),
        Err(DurableError::AnchorRequired)
    ));
    assert!(matches!(
        crate::FanoutAbandonmentJournal::open_anchored(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            crate::durable::tests::identity(path),
            id,
            &mut index,
            client(
                &c.pin,
                &c.witness,
                c.network.f.peers.first().expect("wrong enrolled signer")
            )
        ),
        Err(DurableError::Anchor(_))
    ));
    index.close();
    {
        let mut witness = c.witness.lock().expect("witness");
        witness.fail = Some((witness.calls + 1, false));
    }
    assert!(
        matches!(indexed_cleanup(&c, id), Err(DurableError::Anchor(_))),
        "local retirement alone is not an authoritative disposition"
    );
    c.witness.lock().expect("witness").fail = None;
    assert!(matches!(
        indexed_cleanup(&c, id),
        Err(DurableError::Protocol(Error::Retired))
    ));
}
#[test]
fn account_fanout_abandonment_every_witness_loss_preserves_exact_whole_report() {
    // Discover the actual boundary from authenticated readback; do not assume
    // a particular number/order of witness calls for the reservation transaction.
    let mut found = None;
    for offset in 1..=12 {
        let mut c = Anchored::new();
        let id = reserve_with_loss(&mut c, offset);
        if c.network.sender.fanout_status(id).expect("phase") == FanoutStatus::Reserved {
            found = Some((c, id, offset));
            break;
        }
    }
    let (mut baseline, id, reservation_cut) = found.expect("observed durable reservation boundary");
    let selected = targets(&baseline.network.f, &baseline.network.sessions);
    let before = baseline.witness.lock().expect("witness").calls;
    let report = baseline
        .network
        .sender
        .begin_fanout_abandonment(id, &selected)
        .expect("baseline freeze");
    let freeze_calls = baseline.witness.lock().expect("witness").calls - before;
    super::abandonment::account(&baseline.network.sender_path, &report);
    let before = baseline.witness.lock().expect("witness").calls;
    baseline
        .network
        .sender
        .acknowledge_fanout_abandonment(id, report.report, &selected)
        .expect("baseline terminal");
    let finish_calls = baseline.witness.lock().expect("witness").calls - before;
    for (finish, calls) in [(false, freeze_calls), (true, finish_calls)] {
        assert!((3..=12).contains(&calls), "measured calls={calls}");
        for offset in 1..=calls {
            for after in [false, true] {
                let mut c = Anchored::new();
                let id = reserve_with_loss(&mut c, reservation_cut);
                assert_eq!(
                    c.network.sender.fanout_status(id).expect("reserved"),
                    FanoutStatus::Reserved
                );
                let selected = targets(&c.network.f, &c.network.sessions);
                let frozen = if finish {
                    let report = c
                        .network
                        .sender
                        .begin_fanout_abandonment(id, &selected)
                        .expect("freeze");
                    super::abandonment::account(&c.network.sender_path, &report);
                    Some(report.report)
                } else {
                    None
                };
                {
                    let mut witness = c.witness.lock().expect("witness");
                    witness.fail = Some((witness.calls + offset, after));
                }
                let result = match frozen {
                    Some(report) => c
                        .network
                        .sender
                        .acknowledge_fanout_abandonment(id, report, &selected),
                    None => c
                        .network
                        .sender
                        .begin_fanout_abandonment(id, &selected)
                        .map(|_| ()),
                };
                assert!(
                    matches!(result, Err(DurableError::Anchor(_))),
                    "finish={finish} offset={offset} after={after}"
                );
                assert!(c.network.sender.active.is_none());
                let n = &c.network;
                match DeviceJournal::open(
                    &n.sender_path.join("state.redb"),
                    JournalKey::open(&n.sender_path.join("key")).expect("key"),
                    &n.f.local,
                    crate::durable::tests::identity(&n.sender_path),
                ) {
                    Ok(mut ordinary) => {
                        assert!(matches!(
                            ordinary.fanout_status(id),
                            Err(DurableError::AnchorRequired)
                        ));
                        ordinary.close();
                    }
                    Err(error) => assert!(matches!(error, DurableError::AnchorRequired), "{error}"),
                }
                c.witness.lock().expect("witness").fail = None;
                c.reopen_sender();
                let phase = c.network.sender.fanout_status(id).expect("reconciled");
                let expected = match phase {
                    FanoutStatus::Reserved if !finish => Ok(DurableStatus::Messages),
                    FanoutStatus::Abandoning(_) => Ok(DurableStatus::MessagesAbandoning),
                    FanoutStatus::Abandoned(saved) if Some(saved) == frozen => {
                        Ok(DurableStatus::MessagesAbandoned)
                    }
                    _ => Err("invalid whole-report phase"),
                }
                .expect("only adjacent commit outcomes");
                let image = c.network.sender.image().expect("image");
                for session in &c.network.sessions {
                    assert_eq!(
                        image
                            .records
                            .get(&record_id(session))
                            .expect("member")
                            .phase,
                        expected
                    );
                }
                let selected = targets(&c.network.f, &c.network.sessions);
                let report_id = match phase {
                    FanoutStatus::Abandoned(report) => report,
                    _ => {
                        let report = c
                            .network
                            .sender
                            .begin_fanout_abandonment(id, &selected)
                            .expect("recover exact report");
                        if let Some(saved) = frozen {
                            assert_eq!(saved, report.report);
                        } else {
                            super::abandonment::account(&c.network.sender_path, &report);
                        }
                        c.network
                            .sender
                            .acknowledge_fanout_abandonment(id, report.report, &selected)
                            .expect("complete");
                        report.report
                    }
                };
                c.reopen_sender();
                assert_eq!(
                    c.network.sender.fanout_status(id).expect("terminal"),
                    FanoutStatus::Abandoned(report_id)
                );
            }
        }
        eprintln!("FANOUT_ABANDONMENT_WITNESS finish={finish} calls={calls} before_after_losses={} reservation_cut={reservation_cut}", calls*2);
    }
}

#[test]
fn independent_session_closure_every_witness_loss_keeps_required_protection_and_exact_report() {
    for finish in [false, true] {
        let prepare = || {
            let mut c = Anchored::new();
            let id = c.network.sender.next_fanout_id().expect("ID");
            c.network
                .send(id, b"anchored unknown delivery")
                .expect("committed");
            let context = c.network.f.contexts.first().expect("context");
            let session = *c.network.sessions.first().expect("session");
            let frozen = if finish {
                let report = c
                    .network
                    .sender
                    .begin_session_closure(context, session)
                    .expect("freeze");
                super::super::closure::account(&c.network.sender_path, &report);
                Some(report.report)
            } else {
                None
            };
            (c, frozen)
        };
        let action =
            |c: &mut Anchored, frozen: Option<SessionClosureId>| -> Result<(), DurableError> {
                let n = &mut c.network;
                let context = n.f.contexts.first().expect("context");
                let session = *n.sessions.first().expect("session");
                match frozen {
                    Some(report) => n
                        .sender
                        .acknowledge_session_closure(context, session, report),
                    None => n.sender.begin_session_closure(context, session).map(|_| ()),
                }
            };
        let (mut baseline, frozen) = prepare();
        let before = baseline.witness.lock().expect("witness").calls;
        action(&mut baseline, frozen).expect("measure actual exchanges");
        let calls = baseline.witness.lock().expect("witness").calls - before;
        assert!((3..=12).contains(&calls));
        for offset in 1..=calls {
            for after in [false, true] {
                let (mut c, frozen) = prepare();
                {
                    let mut witness = c.witness.lock().expect("witness");
                    witness.fail = Some((witness.calls + offset, after));
                }
                assert!(
                    matches!(action(&mut c, frozen), Err(DurableError::Anchor(_))),
                    "finish={finish} offset={offset} after={after}"
                );
                assert!(c.network.sender.active.is_none());
                let n = &c.network;
                match DeviceJournal::open(
                    &n.sender_path.join("state.redb"),
                    JournalKey::open(&n.sender_path.join("key")).expect("key"),
                    &n.f.local,
                    crate::durable::tests::identity(&n.sender_path),
                ) {
                    Ok(mut ordinary) => {
                        assert!(matches!(
                            ordinary.session_closure_status(
                                n.f.contexts.first().expect("context"),
                                *n.sessions.first().expect("session")
                            ),
                            Err(DurableError::AnchorRequired)
                        ));
                        ordinary.close();
                    }
                    Err(error) => assert!(matches!(error, DurableError::AnchorRequired)),
                }
                c.witness.lock().expect("witness").fail = None;
                c.reopen_sender();
                let n = &mut c.network;
                let context = n.f.contexts.first().expect("context");
                let session = *n.sessions.first().expect("session");
                let phase = n
                    .sender
                    .session_closure_status(context, session)
                    .expect("reconciled");
                let report_id = match phase {
                    SessionClosureStatus::Closed(report) => {
                        assert_eq!(Some(report), frozen);
                        report
                    }
                    SessionClosureStatus::Open | SessionClosureStatus::Pending(_) => {
                        if finish {
                            assert!(matches!(phase, SessionClosureStatus::Pending(_)));
                        }
                        let report = n
                            .sender
                            .begin_session_closure(context, session)
                            .expect("exact frozen report");
                        if let Some(saved) = frozen {
                            assert_eq!(report.report, saved);
                        } else {
                            super::super::closure::account(&n.sender_path, &report);
                        }
                        n.sender
                            .acknowledge_session_closure(context, session, report.report)
                            .expect("finish");
                        report.report
                    }
                };
                assert_eq!(
                    n.sender
                        .session_closure_status(context, session)
                        .expect("terminal"),
                    SessionClosureStatus::Closed(report_id)
                );
                assert_eq!(
                    n.sender
                        .message_status(
                            context,
                            session,
                            MessageId::for_epoch(&session, 1, 0, 0).expect("original ID")
                        )
                        .expect("unknown"),
                    MessageStatus::DeliveryUnknown
                );
                let other_context = n.f.contexts.get(1).expect("other context");
                assert_eq!(
                    n.sender
                        .session_closure_status(
                            other_context,
                            *n.sessions.get(1).expect("other session")
                        )
                        .expect("unrelated"),
                    SessionClosureStatus::Open
                );
            }
        }
        eprintln!(
            "SESSION_CLOSURE_WITNESS finish={finish} calls={calls} before_after_losses={}",
            calls * 2
        );
    }
}

#[test]
fn archived_session_closure_preserves_every_witness_loss_and_refuses_expired_advancement() {
    use crate::{SessionClosureArchive, SessionClosureJournal, SessionClosureStatus};
    fn capture(c: &mut Anchored) -> SessionClosureArchive {
        let n = &mut c.network;
        let context = n.f.contexts.first().expect("context");
        let session = *n.sessions.first().expect("session");
        let id = n
            .sender
            .next_message_id(context, session, 150)
            .expect("slot");
        n.sender
            .send_message(
                context,
                session,
                id,
                b"archived unknown outcome",
                b"archive",
                150,
            )
            .expect("original send");
        let archive = n
            .sender
            .archive_session_closure(context, session)
            .expect("protected archive");
        context.policy().close();
        n.sender.close();
        SessionClosureArchive::from_bytes(archive.as_bytes()).expect("retained public bytes")
    }
    fn open(
        c: &Anchored,
        archive: &SessionClosureArchive,
    ) -> Result<SessionClosureJournal, DurableError> {
        let n = &c.network;
        SessionClosureJournal::open_anchored(
            &n.sender_path.join("state.redb"),
            JournalKey::open(&n.sender_path.join("key")).expect("original key"),
            crate::durable::tests::identity(&n.sender_path),
            archive,
            client(&c.pin, &c.witness, &n.f.local),
        )
    }
    for finish in [false, true] {
        let mut baseline = Anchored::new();
        let archive = capture(&mut baseline);
        let frozen = if finish {
            let mut owner = open(&baseline, &archive).expect("open");
            let report = owner.begin().expect("freeze");
            super::super::closure::account(&baseline.network.sender_path, &report);
            Some(report)
        } else {
            None
        };
        let before = baseline.witness.lock().expect("witness").calls;
        let mut owner = open(&baseline, &archive).expect("baseline open");
        if let Some(report) = &frozen {
            owner.acknowledge(report.report).expect("terminal");
        } else {
            owner.begin().expect("freeze");
        }
        let calls = baseline.witness.lock().expect("witness").calls - before;
        assert_eq!(calls, 5, "measured open plus transition witness exchanges");
        for offset in 1..=calls {
            for after in [false, true] {
                let mut c = Anchored::new();
                let archive = capture(&mut c);
                let frozen = if finish {
                    let mut owner = open(&c, &archive).expect("open");
                    let report = owner.begin().expect("freeze");
                    super::super::closure::account(&c.network.sender_path, &report);
                    Some(report)
                } else {
                    None
                };
                {
                    let mut w = c.witness.lock().expect("witness");
                    w.fail = Some((w.calls + offset, after));
                }
                let attempt = open(&c, &archive).and_then(|mut owner| {
                    if let Some(report) = &frozen {
                        owner.acknowledge(report.report)
                    } else {
                        owner.begin().map(|_| ())
                    }
                });
                assert!(
                    matches!(attempt, Err(DurableError::Anchor(_))),
                    "finish={finish}, offset={offset}, after={after}: {attempt:?}"
                );
                let n = &c.network;
                assert!(matches!(
                    SessionClosureJournal::open(
                        &n.sender_path.join("state.redb"),
                        JournalKey::open(&n.sender_path.join("key")).expect("key"),
                        crate::durable::tests::identity(&n.sender_path),
                        &archive
                    ),
                    Err(DurableError::AnchorRequired)
                ));
                c.witness.lock().expect("witness").fail = None;
                let mut owner = open(&c, &archive).expect("exact protected recovery");
                let report_id = match owner.status().expect("status") {
                    SessionClosureStatus::Closed(id) => {
                        assert_eq!(id, frozen.as_ref().expect("accounted").report);
                        id
                    }
                    SessionClosureStatus::Open | SessionClosureStatus::Pending(_) => {
                        let report = owner.begin().expect("same report");
                        if let Some(saved) = &frozen {
                            assert_eq!(&report, saved);
                        } else {
                            super::super::closure::account(&c.network.sender_path, &report);
                        }
                        owner.acknowledge(report.report).expect("terminal");
                        report.report
                    }
                };
                assert_eq!(
                    owner.status().expect("closed"),
                    SessionClosureStatus::Closed(report_id)
                );
            }
        }
        eprintln!(
            "ARCHIVED_SESSION_CLOSURE_WITNESS finish={finish} calls={calls} before_after_losses={}",
            calls * 2
        );
    }
    let mut c = Anchored::new();
    let archive = capture(&mut c);
    let n = &c.network;
    let calls = c.witness.lock().expect("witness").calls;
    let wrong_pin = AnchorPin::new(
        AnchorIdentity::generate().expect("other identity"),
        AnchorSigningKey::generate()
            .expect("other key")
            .public_key()
            .expect("public"),
    );
    for client in [
        client(&wrong_pin, &c.witness, &n.f.local),
        client(&c.pin, &c.witness, n.f.peers.first().expect("wrong device")),
    ] {
        assert!(matches!(
            SessionClosureJournal::open_anchored(
                &n.sender_path.join("state.redb"),
                JournalKey::open(&n.sender_path.join("key")).expect("key"),
                crate::durable::tests::identity(&n.sender_path),
                &archive,
                client
            ),
            Err(DurableError::Conflict)
        ));
    }
    assert_eq!(
        c.witness
            .lock()
            .expect("no request under substituted authority")
            .calls,
        calls
    );
    c.witness.lock().expect("witness").now = 1001;
    let mut owner = open(&c, &archive).expect("read-only witness query after expiry");
    assert_eq!(owner.status().expect("status"), SessionClosureStatus::Open);
    assert!(
        matches!(owner.begin(), Err(DurableError::Anchor(_))),
        "expired witness authorization cannot advance"
    );
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    drop(owner);
    assert!(
        matches!(open(&c, &archive), Err(DurableError::Anchor(_))),
        "pending command cannot bypass witness expiry on reopen"
    );
}
