// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{FanoutAbandonment, FanoutAbandonmentId};
use std::os::unix::fs::OpenOptionsExt;

pub(super) fn account(path: &Path, report: &FanoutAbandonment) {
    // Debug here is intentionally the complete public metadata structure, not a
    // private State or partial ID receipt. Retain every report field before ACK.
    let bytes = format!("{report:#?}\n");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("abandonment-accounting"))
        .expect("private application record");
    file.write_all(bytes.as_bytes()).expect("complete report");
    file.sync_all().expect("durable accounting");
    fs::File::open(path)
        .expect("directory")
        .sync_all()
        .expect("durable name");
}
fn closed(n: &mut Network, id: FanoutId, report: FanoutAbandonmentId) {
    let selected = targets(&n.f, &n.sessions);
    assert_eq!(
        n.sender.fanout_status(id).expect("terminal"),
        FanoutStatus::Abandoned(report)
    );
    for (context, session) in n.f.contexts.iter().zip(&n.sessions) {
        let message = MessageId::for_epoch(session, 1, 0, 0).expect("original ID");
        assert_eq!(
            n.sender
                .message_status(context, *session, message)
                .expect("status"),
            MessageStatus::ReservationAbandoned
        );
        assert!(matches!(
            n.sender.next_message_id(context, *session, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            n.sender
                .send_message(context, *session, message, b"replacement", b"", 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            n.sender.message_acknowledgement(context, *session, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            n.sender
                .prepare_rekey_offer(context, *session, &n.f.local_signer, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        let image = n.sender.image().expect("image");
        let record = image.records.get(&record_id(session)).expect("tombstone");
        assert_eq!(record.phase, DurableStatus::MessagesAbandoned);
        assert!(State::decode(&record.payload).is_err());
        let retired =
            super::super::super::fanout::Retired::decode(&record.payload).expect("keyless grammar");
        let source = image.records.get(&retired.source).expect("source");
        let request = InitiationId::from_trusted_state(
            source
                .payload
                .get(..32)
                .expect("request")
                .try_into()
                .expect("width"),
        )
        .expect("request");
        assert!(matches!(
            n.sender.resume_initial(Arc::clone(context), request, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            n.sender.resume_reply(Arc::clone(context), request, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            n.sender
                .activate_initiator_messages(Arc::clone(context), request, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
    }
    assert!(matches!(
        n.sender.resume_account_message(id, &selected, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    n.sender
        .acknowledge_fanout_abandonment(id, report, &selected)
        .expect("idempotent ACK");
}
#[test]
fn account_fanout_abandonment_process_cuts_freeze_and_close_all_sessions() {
    for stage in ["fanout-abandoning", "fanout-abandoned"] {
        let mut n = Network::new(4, false);
        let id = process::reserved(&mut n, "fanout-computed");
        process::abandonment_cut(&mut n, stage);
        let selected = targets(&n.f, &n.sessions);
        let report_id = if stage == "fanout-abandoning" {
            let report = n
                .sender
                .begin_fanout_abandonment(id, &selected)
                .expect("same frozen report");
            assert_eq!(
                n.sender.fanout_status(id).expect("frozen"),
                FanoutStatus::Abandoning(report.report)
            );
            let before = n.sender.image().expect("image");
            for (context, session) in n.f.contexts.iter().zip(&n.sessions) {
                assert!(matches!(
                    n.sender.next_message_id(context, *session, 150),
                    Err(DurableError::Suspended)
                ));
                assert!(matches!(
                    n.sender.message_acknowledgement(context, *session, 150),
                    Err(DurableError::Suspended)
                ));
                assert!(matches!(
                    n.sender
                        .prepare_rekey_offer(context, *session, &n.f.local_signer, 150),
                    Err(DurableError::Suspended)
                ));
            }
            assert!(matches!(
                n.sender.acknowledge_fanout_abandonment(
                    id,
                    FanoutAbandonmentId::from_trusted_state([7; 32]).expect("wrong ID"),
                    &selected
                ),
                Err(DurableError::Conflict)
            ));
            assert!(matches!(
                n.sender
                    .begin_fanout_abandonment(id, selected.get(..1).expect("partial")),
                Err(DurableError::Conflict)
            ));
            assert_eq!(n.sender.image().expect("unchanged").digest, before.digest);
            // Any private-state mutation breaks the immutable report MAC.
            let mut changed = n.sender.image().expect("image");
            let record = changed
                .records
                .get_mut(&record_id(n.sessions.first().expect("session")))
                .expect("record");
            let mut state = State::decode(&record.payload).expect("state");
            state
                .traffic_mut(0)
                .expect("traffic")
                .pending
                .as_mut()
                .expect("plan")
                .plaintext
                .push(1);
            record.payload = state.encode();
            assert!(validate_image(&changed).is_err());
            account(&n.sender_path, &report);
            n.sender
                .acknowledge_fanout_abandonment(id, report.report, &selected)
                .expect("accounted and closed");
            report.report
        } else {
            match n.sender.fanout_status(id).expect("terminal") {
                FanoutStatus::Abandoned(report) => Ok(report),
                _ => Err("not abandoned"),
            }
            .expect("whole terminal phase")
        };
        n.reopen();
        closed(&mut n, id, report_id);
        let selected = targets(&n.f, &n.sessions);
        n.sender
            .retire_fanout(id, &selected)
            .expect("retire batch metadata");
        n.reopen();
        assert_eq!(
            n.sender.fanout_status(id).expect("no reuse"),
            FanoutStatus::Retired
        );
        for (context, session) in n.f.contexts.iter().zip(&n.sessions) {
            assert!(matches!(
                n.sender.next_message_id(context, *session, 150),
                Err(DurableError::Protocol(Error::Retired))
            ));
        }
        // A genuinely new bootstrap can coexist with old terminal sources.
        let context = Arc::clone(n.f.contexts.first().expect("context"));
        let request = InitiationId::generate().expect("new request");
        let initial = n
            .sender
            .initiate(Arc::clone(&context), request, &n.f.local_signer, 150)
            .expect("fresh initial");
        let peer = n.receivers.first_mut().expect("peer");
        let peer_key = n.f.keys.first().expect("key");
        let reply = peer
            .respond(
                Arc::clone(&context),
                &initial,
                n.f.peer_signers.first().expect("signer"),
                PqKeySource::from_key(peer_key),
                TraditionalKeySource::from_key(peer_key),
                150,
            )
            .expect("fresh reply");
        let final_wire = n
            .sender
            .accept_reply(Arc::clone(&context), request, &reply, 150)
            .expect("new final");
        let session = final_wire.session_id();
        assert!(!n.sessions.contains(&session));
        peer.finish(
            Arc::clone(&context),
            &initial,
            final_wire.final_message(),
            150,
        )
        .expect("finish");
        n.sender
            .activate_initiator_messages(Arc::clone(&context), request, 150)
            .expect("fresh sender session");
        peer.activate_responder_messages(Arc::clone(&context), &initial, 150)
            .expect("fresh receiver session");
        let message = n
            .sender
            .next_message_id(&context, session, 150)
            .expect("new ID");
        let wire = n
            .sender
            .send_message(
                &context,
                session,
                message,
                b"new independent session",
                b"",
                150,
            )
            .expect("new send");
        assert_eq!(
            peer.receive_message(&context, session, &wire, b"", 150)
                .expect("actual fresh delivery")
                .as_bytes(),
            b"new independent session"
        );
        eprintln!(
            "FANOUT_ABANDONMENT_PROCESS cut={stage} all_sessions_terminal=true contender=Busy"
        );
    }
}
#[test]
fn account_fanout_abandonment_after_revocation_is_metadata_only_and_keeps_prior_unknowns() {
    let mut n = Network::new(4, false);
    let old = n.sender.next_fanout_id().expect("ID");
    let committed = n.send(old, b"earlier unknown send").expect("committed");
    // Both receivers send an unconsumed delivery so the report must account for loss.
    for ((context, session), receiver) in n.f.contexts.iter().zip(&n.sessions).zip(&mut n.receivers)
    {
        let id = receiver
            .next_message_id(context, *session, 150)
            .expect("peer ID");
        let wire = receiver
            .send_message(
                context,
                *session,
                id,
                b"private inbound text",
                b"private AD",
                150,
            )
            .expect("peer send");
        n.sender
            .receive_message(context, *session, &wire, b"private AD", 150)
            .expect("unconsumed inbox");
    }
    let id = process::reserved(&mut n, "fanout-computed");
    let entries: Vec<_> =
        n.f.certificates
            .iter()
            .take(1)
            .map(|c| n.f.root.roster_entry(c).expect("entry"))
            .collect();
    let issued =
        n.f.root
            .issue_roster(2, interval(), &entries)
            .expect("revoke");
    let pin = AccountPin::new(
        n.f.root.account_id().expect("account"),
        n.f.root.public_key().expect("public"),
        issued.checkpoint(),
        n.f.contexts.first().expect("context").policy().family(),
    )
    .expect("pin");
    n.sender
        .install_roster(
            &pin.verify_roster(issued.as_bytes(), 150).expect("verified"),
            150,
        )
        .expect("committed revocation");
    n.reopen();
    let selected = targets(&n.f, &n.sessions);
    assert!(n.sender.resume_account_message(id, &selected, 150).is_err());
    let before_size: usize = n
        .sender
        .image()
        .expect("image")
        .records
        .values()
        .map(|r| r.payload.len())
        .sum();
    let report = n
        .sender
        .begin_fanout_abandonment(id, &selected)
        .expect("cleanup despite revoked peer");
    let frozen_size: usize = n
        .sender
        .image()
        .expect("image")
        .records
        .values()
        .map(|r| r.payload.len())
        .sum();
    assert_eq!(
        before_size, frozen_size,
        "freeze uses pre-reserved image space"
    );
    assert_eq!(report.sessions.len(), 2);
    for session in &report.sessions {
        assert_eq!(
            session.reserved.plaintext_bytes,
            b"durable multi-device process cut".len()
        );
        let epoch = session.epochs.first().expect("epoch");
        assert_eq!(
            (epoch.sent, epoch.acknowledged_before, epoch.received),
            (1, 0, 1)
        );
        assert_eq!(epoch.unconfirmed.len(), 1);
        assert_eq!(epoch.deliveries.len(), 1);
        assert_eq!(
            epoch
                .deliveries
                .first()
                .expect("lost inbox")
                .plaintext_bytes,
            b"private inbound text".len()
        );
    }
    let debug = format!("{report:?}");
    assert!(
        !debug.contains("private inbound text")
            && !debug.contains("private AD")
            && !debug.contains("durable multi-device")
    );
    account(&n.sender_path, &report);
    n.sender
        .acknowledge_fanout_abandonment(id, report.report, &selected)
        .expect("terminal cleanup");
    for member in &committed {
        let context =
            n.f.contexts
                .iter()
                .find(|c| c.devices()[1].device_id() == member.device)
                .expect("context");
        assert_eq!(
            n.sender
                .message_status(context, member.session, member.message)
                .expect("unknown"),
            MessageStatus::DeliveryUnknown
        );
    }
    n.sender
        .retire_fanout(old, &selected)
        .expect("prior batch unknowns accounted");
    n.sender
        .retire_fanout(id, &selected)
        .expect("abandoned batch accounted");
    n.reopen();
    let terminal_size: usize = n
        .sender
        .image()
        .expect("image")
        .records
        .values()
        .map(|r| r.payload.len())
        .sum();
    assert!(terminal_size < frozen_size);
}

#[test]
fn account_fanout_unsafe_reservation_reset_reuses_the_actual_message_keystream() {
    let mut n = Network::new(4, false);
    let id = process::reserved(&mut n, "fanout-computed");
    let old =
        fs::read(n.sender_path.join("fanout-computed-wire")).expect("actual precommit ciphertext");
    assert!(matches!(
        n.send(id, b"different input"),
        Err(DurableError::Conflict)
    ));
    let original = b"durable multi-device process cut";
    let replacement = vec![b'X'; original.len()];
    // Isolated unsafe composition, never persisted or reachable through an API:
    // delete an uncertain plan then encrypt new input under its old message ID.
    let mut unsafe_state = state(&mut n.sender, n.sessions.first().expect("session"));
    let traffic = unsafe_state.traffic_mut(0).expect("traffic");
    let plan = traffic.pending.take().expect("real reserved plan");
    traffic.pending = Some(SendPlan {
        id: plan.id,
        fanout: None,
        plaintext: Zeroizing::new(replacement.clone()),
        ad: b"account-message".to_vec(),
    });
    let new = traffic
        .send(plan.id, &replacement, b"account-message")
        .expect("unsafe direct primitive");
    let old_body = old
        .get(MESSAGE_HEADER..MESSAGE_HEADER + original.len())
        .expect("ciphertext body");
    let new_body = new
        .get(MESSAGE_HEADER..MESSAGE_HEADER + original.len())
        .expect("replacement body");
    assert_eq!(
        old_body
            .iter()
            .zip(new_body)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>(),
        original
            .iter()
            .zip(&replacement)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>()
    );
    let selected = targets(&n.f, &n.sessions);
    let report = n
        .sender
        .begin_fanout_abandonment(id, &selected)
        .expect("safe irreversible freeze");
    account(&n.sender_path, &report);
    n.sender
        .acknowledge_fanout_abandonment(id, report.report, &selected)
        .expect("close instead of rewind");
    closed(&mut n, id, report.report);
    eprintln!("FANOUT_RESET_COUNTEREXAMPLE actual_precommit_ciphertext=true same_keystream=true shipping_replacement_refused=true");
}

#[test]
fn account_fanout_abandonment_sync_faults_reconcile_each_measured_barrier() {
    for finish in [false, true] {
        let mut n = Network::new(4, false);
        let id = process::reserved(&mut n, "fanout-computed");
        let selected = targets(&n.f, &n.sessions);
        let frozen = if finish {
            let report = n
                .sender
                .begin_fanout_abandonment(id, &selected)
                .expect("freeze baseline");
            account(&n.sender_path, &report);
            Some(report.report)
        } else {
            None
        };
        n.sender.close();
        let copy = || {
            let dir = directory();
            for name in ["state.redb", "key", "store-id"] {
                fs::copy(n.sender_path.join(name), dir.path().join(name))
                    .expect("isolated crash snapshot");
            }
            dir
        };
        let operation = |journal: &mut DeviceJournal| -> Result<(), DurableError> {
            match frozen {
                Some(report) => journal.acknowledge_fanout_abandonment(id, report, &selected),
                None => journal.begin_fanout_abandonment(id, &selected).map(|_| ()),
            }
        };
        let baseline = copy();
        let (mut journal, _, count, _) = fault_store(&canonical(&baseline), &n.f.local, false);
        count.store(0, Ordering::SeqCst);
        operation(&mut journal).expect("normal completion");
        let barriers = count.load(Ordering::SeqCst);
        assert!((3..=12).contains(&barriers), "measured barriers={barriers}");
        journal.close();
        let mut phases = BTreeSet::new();
        for cut in 1..=barriers {
            for after in [false, true] {
                let dir = copy();
                let path = canonical(&dir);
                let (mut journal, fail, _, _) = fault_store(&path, &n.f.local, after);
                fail.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(operation(&mut journal), after);
                assert!(journal.active.is_none());
                journal = reopen(&path, &n.f.local);
                let phase = journal.fanout_status(id).expect("reconciled phase");
                let expected = match phase {
                    FanoutStatus::Reserved if !finish => Ok(DurableStatus::Messages),
                    FanoutStatus::Abandoning(_) => Ok(DurableStatus::MessagesAbandoning),
                    FanoutStatus::Abandoned(saved) if Some(saved) == frozen => {
                        Ok(DurableStatus::MessagesAbandoned)
                    }
                    _ => Err("invalid abandonment outcome"),
                }
                .expect("only adjacent whole-image phases");
                phases.insert(expected as u8);
                let image = journal.image().expect("image");
                for session in &n.sessions {
                    assert_eq!(
                        image
                            .records
                            .get(&record_id(session))
                            .expect("member")
                            .phase,
                        expected
                    );
                }
                let report_id = match phase {
                    FanoutStatus::Abandoned(report) => report,
                    _ => {
                        let report = journal
                            .begin_fanout_abandonment(id, &selected)
                            .expect("recover frozen report");
                        assert_eq!(
                            journal
                                .begin_fanout_abandonment(id, &selected)
                                .expect("immutable retry"),
                            report
                        );
                        account(&path, &report);
                        journal
                            .acknowledge_fanout_abandonment(id, report.report, &selected)
                            .expect("complete exact accounting");
                        report.report
                    }
                };
                journal.close();
                journal = reopen(&path, &n.f.local);
                assert_eq!(
                    journal.fanout_status(id).expect("terminal"),
                    FanoutStatus::Abandoned(report_id)
                );
            }
        }
        assert_eq!(
            phases.len(),
            2,
            "observe both before and after commit outcomes"
        );
        eprintln!("FANOUT_ABANDONMENT_SYNC finish={finish} barriers={barriers} before_after_faults={} phases={phases:?}", barriers*2);
    }
}

#[test]
fn account_fanout_abandonment_does_not_need_an_extra_batch_slot_at_capacity() {
    let mut n = Network::new(32, false);
    for _ in 0..15 {
        let id = n.sender.next_fanout_id().expect("ID");
        n.send(id, b"retain prior unacknowledged fanout")
            .expect("prior batch");
    }
    let id = process::reserved(&mut n, "fanout-computed");
    assert_eq!(
        n.sender
            .image()
            .expect("image")
            .records
            .values()
            .filter(|r| r.kind == RecordKind::Fanout)
            .count(),
        16
    );
    let selected = targets(&n.f, &n.sessions);
    let report = n
        .sender
        .begin_fanout_abandonment(id, &selected)
        .expect("freeze at batch capacity");
    assert!(report
        .sessions
        .iter()
        .all(|s| s.epochs.first().is_some_and(|e| e.unconfirmed.len() == 15)));
    account(&n.sender_path, &report);
    n.sender
        .acknowledge_fanout_abandonment(id, report.report, &selected)
        .expect("close at capacity");
    n.sender
        .retire_fanout(id, &selected)
        .expect("free metadata slot");
    assert_eq!(
        n.sender.fanout_status(id).expect("retired"),
        FanoutStatus::Retired
    );
}
