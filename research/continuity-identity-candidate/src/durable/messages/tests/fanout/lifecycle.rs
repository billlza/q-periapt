// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::fs::OpenOptionsExt;

fn rekey_second(n: &mut Network, target: u64) {
    let context = n.f.contexts.get(1).expect("second context");
    let session = *n.sessions.get(1).expect("second session");
    let peer = n.receivers.get_mut(1).expect("second peer");
    let peer_signer = n.f.peer_signers.get(1).expect("second signer");
    let (proposer, responder, signing_a, signing_b) = if target % 2 == 1 {
        (&mut n.sender, peer, &n.f.local_signer, peer_signer)
    } else {
        (peer, &mut n.sender, peer_signer, &n.f.local_signer)
    };
    let offer = proposer
        .prepare_rekey_offer(context, session, signing_a, 150)
        .expect("offer");
    let response = responder
        .respond_rekey_offer(context, session, &offer, signing_b, 150)
        .expect("response");
    let final_wire = proposer
        .accept_rekey_response(context, session, &response, signing_a, 150)
        .expect("final");
    let receipt = responder
        .finish_rekey(context, session, &final_wire, signing_b, 150)
        .expect("receipt");
    assert_eq!(
        proposer
            .accept_rekey_receipt(context, session, &receipt, 150)
            .expect("confirmed"),
        target
    );
}

// This scenario has no plaintext deliveries or skipped keys. Persist every
// report field that it does contain before acknowledging host accounting.
fn account(path: &Path, report: &ClosedEpochResolution) {
    assert!(report.unconsumed_deliveries().is_empty());
    assert!(report.skipped_indices().is_empty());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("new private application record");
    file.write_all(b"TESTACC1").expect("record kind");
    file.write_all(report.resolution_id().as_bytes())
        .expect("exact report ID");
    for value in [
        report.epoch(),
        report.acknowledged_before(),
        report.sent_count(),
        report.consumed_before(),
        report.observed_receive_count(),
        report.peer_sent_count(),
        report
            .unconfirmed_messages()
            .len()
            .try_into()
            .expect("bounded count"),
    ] {
        file.write_all(&value.to_be_bytes())
            .expect("accounting counts");
    }
    for item in report.unconfirmed_messages() {
        file.write_all(item.message_id().as_bytes())
            .expect("unknown ID");
        file.write_all(item.ciphertext_digest())
            .expect("exact ciphertext");
    }
    file.sync_all().expect("durable application accounting");
    fs::File::open(path.parent().expect("private parent"))
        .expect("directory")
        .sync_all()
        .expect("durable directory entry");
}

#[test]
fn account_fanout_partial_ack_resolution_and_retired_history_never_invent_delivery() {
    let mut n = Network::new(4, false);
    let id = n.sender.next_fanout_id().expect("ID");
    let result = n
        .send(id, b"one recipient remains unknown")
        .expect("committed aggregate");
    let first = result.first().expect("first member");
    let context = n.f.contexts.first().expect("first context");
    let receiver = n.receivers.first_mut().expect("first peer");
    receiver
        .receive_message(
            context,
            first.session,
            committed_wire(first),
            b"account-message",
            150,
        )
        .expect("first delivery");
    receiver
        .consume_message(context, first.session, first.message, 150)
        .expect("first consumption");
    let ack = receiver
        .message_acknowledgement(context, first.session, 150)
        .expect("first ACK");
    n.sender
        .accept_message_acknowledgement(context, first.session, &ack, 150)
        .expect("first acknowledged");
    let selected = targets(&n.f, &n.sessions);
    let partial = n
        .sender
        .resume_account_message(id, &selected, 150)
        .expect("complete local outcome list");
    assert!(matches!(
        partial.first().expect("first").output,
        FanoutOutput::Acknowledged
    ));
    assert!(matches!(
        partial.get(1).expect("second").output,
        FanoutOutput::Committed(_)
    ));
    assert!(matches!(
        n.sender.retire_fanout(id, &selected),
        Err(DurableError::Suspended)
    ));
    rekey_second(&mut n, 1);
    let context = n.f.contexts.get(1).expect("second context");
    let session = *n.sessions.get(1).expect("second session");
    let report = n
        .sender
        .begin_closed_epoch_resolution(context, session, 0, 150)
        .expect("freeze unknown outcome");
    assert_eq!(report.unconfirmed_messages().len(), 1);
    assert_eq!(report.acknowledged_before(), 0);
    assert_eq!(
        report
            .unconfirmed_messages()
            .first()
            .expect("unknown")
            .message_id(),
        result.get(1).expect("second").message
    );
    let selected = targets(&n.f, &n.sessions);
    let frozen = n
        .sender
        .resume_account_message(id, &selected, 150)
        .expect("frozen member is explicit");
    assert!(matches!(
        frozen.get(1).expect("second").output,
        FanoutOutput::ResolutionPending
    ));
    assert!(matches!(
        n.sender.retire_fanout(id, &selected),
        Err(DurableError::Suspended)
    ));
    account(&n.sender_path.join("fanout-accounting"), &report);
    n.sender
        .acknowledge_closed_epoch_resolution(context, session, 0, report.resolution_id(), 150)
        .expect("accounted unknown");
    let unknown = n
        .sender
        .resume_account_message(id, &selected, 150)
        .expect("unknown is explicit");
    assert!(matches!(
        unknown.first().expect("first").output,
        FanoutOutput::Acknowledged
    ));
    assert!(matches!(
        unknown.get(1).expect("second").output,
        FanoutOutput::DeliveryUnknown
    ));
    let peer = n.receivers.get_mut(1).expect("second peer");
    let peer_report = peer
        .begin_closed_epoch_resolution(context, session, 0, 150)
        .expect("account for unseen old range");
    assert_eq!(
        (
            peer_report.observed_receive_count(),
            peer_report.peer_sent_count()
        ),
        (0, 1)
    );
    account(
        &canonical(n.receiver_dirs.get(1).expect("peer directory")).join("fanout-accounting"),
        &peer_report,
    );
    peer.acknowledge_closed_epoch_resolution(context, session, 0, peer_report.resolution_id(), 150)
        .expect("peer accounting");
    for target in 2..=4 {
        rekey_second(&mut n, target);
    }
    n.reopen();
    let selected = targets(&n.f, &n.sessions);
    let retired = n
        .sender
        .resume_account_message(id, &selected, 150)
        .expect("retired member retained as metadata");
    assert!(matches!(
        retired.first().expect("first").output,
        FanoutOutput::Acknowledged
    ));
    assert!(matches!(
        retired.get(1).expect("second").output,
        FanoutOutput::HistoryRetired
    ));
    n.sender
        .retire_fanout(id, &selected)
        .expect("all members have terminal accounting");
    assert_eq!(
        n.sender.fanout_status(id).expect("never reused"),
        FanoutStatus::Retired
    );
}
