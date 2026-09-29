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
        let result = witness.store.handle(wire, 150).map_err(io::Error::other)?;
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
