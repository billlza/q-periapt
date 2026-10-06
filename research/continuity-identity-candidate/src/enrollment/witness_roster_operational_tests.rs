// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original pairwise state and fixed complete fanout across independent P and R.
use super::*;
#[path = "witness_peer_roster_tests.rs"]
mod peer_roster;
use crate::enrollment::tests::witness_renewal::policy_transaction::sessions::{
    bundle, endpoint, requirements, Endpoint,
};
use crate::{
    BootstrapBundle, BootstrapContext, BootstrapRole, FanoutInput, FanoutMember, FanoutOutput,
    FanoutTarget, InitiationId, SessionReopenRequest,
};

struct Link {
    bundle: BootstrapBundle,
    sender: Arc<BootstrapContext>,
    receiver: Arc<BootstrapContext>,
    session: [u8; 32],
}
fn connect(a: &mut Endpoint, b: &mut Endpoint) -> Link {
    let bundle = bundle(a, b);
    let sender = Arc::new(
        bundle
            .verify(
                Arc::new(policy(&a.f.c, 1, a.f.c.policy.validity().until(), 150)),
                requirements(a, b),
                150,
            )
            .expect("original sender context"),
    );
    let receiver = Arc::new(
        bundle
            .verify(
                Arc::new(policy(&b.f.c, 1, b.f.c.policy.validity().until(), 150)),
                requirements(a, b),
                150,
            )
            .expect("original receiver context"),
    );
    let initiation = InitiationId::generate().expect("original initiation");
    let (is, ik, _) = a.owner.parts().expect("original sender owners");
    let (rs, rk, _) = b.owner.parts().expect("original responder owners");
    let (ij, ia) = is.stores().expect("sender stores");
    let (rj, ra) = rs.stores().expect("receiver stores");
    let initial = ij
        .initiate(Arc::clone(&sender), initiation, ik, 150)
        .expect("actual initiate");
    let reply = rj
        .respond_from_inventory(Arc::clone(&receiver), &initial, rk, 150)
        .expect("actual prekeys");
    let final_msg = ij
        .accept_reply(Arc::clone(&sender), initiation, &reply, 150)
        .expect("actual accept");
    let session = final_msg.session_id();
    rj.finish(
        Arc::clone(&receiver),
        &initial,
        final_msg.final_message(),
        150,
    )
    .expect("confirm");
    ij.activate_initiator_messages(Arc::clone(&sender), initiation, 150)
        .expect("sender state");
    rj.activate_responder_messages(Arc::clone(&receiver), &initial, 150)
        .expect("receiver state");
    let archive = ij
        .archive_session_closure(&sender, session)
        .expect("original sender archive");
    ia.retain(ij, &sender, session, &archive).expect("retain");
    let archive = rj
        .archive_session_closure(&receiver, session)
        .expect("original receiver archive");
    ra.retain(rj, &receiver, session, &archive).expect("retain");
    Link {
        bundle,
        sender,
        receiver,
        session,
    }
}
fn requests(
    link: &Link,
    a: &Endpoint,
    b: &Endpoint,
    now: u64,
) -> (SessionReopenRequest, SessionReopenRequest) {
    (
        link.bundle
            .request_historical_reopen(
                Arc::new(a.f.c.policy.historical().clone()),
                requirements(a, b),
                BootstrapRole::Initiator,
                link.session,
                now,
            )
            .expect("original sender request"),
        link.bundle
            .request_historical_reopen(
                Arc::new(b.f.c.policy.historical().clone()),
                requirements(a, b),
                BootstrapRole::Responder,
                link.session,
                now,
            )
            .expect("original receiver request"),
    )
}
fn adopt_policy(f: &Fixture, now: u64) -> Arc<VerifiedSessionPolicy> {
    let a = approved_at(f, &f.c.policy, 2, 159, now);
    let p = prepared_at(f, &a, &f.c.policy, now);
    applied_at(f, &a, p, now);
    Arc::new(a.target)
}
fn certificate(f: &Fixture) -> Vec<u8> {
    let mut owner = open(&f.c);
    match owner.image().expect("original image").phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("original accepted enrollment"),
    }
    .expect("original accepted enrollment")
}
fn roster_target(f: &Fixture, certificates: &[Vec<u8>], version: u64, now: u64) -> VerifiedDevice {
    let entries = certificates
        .iter()
        .map(|c| f.c.root.roster_entry(c).expect("root member"))
        .collect::<Vec<_>>();
    let roster =
        f.c.root
            .issue_roster(
                version,
                Validity::new(100, 400).expect("roster validity"),
                &entries,
            )
            .expect("root approves next roster");
    AccountPin::new(
        f.original.account_id(),
        f.c.intent.root.clone(),
        roster.checkpoint(),
        f.c.policy.family(),
    )
    .expect("independent new pin")
    .verify_device(&certificate(f), roster.as_bytes(), now)
    .expect("root-approved same credential")
}
fn refresh(
    f: &Fixture,
    p: &VerifiedSessionPolicy,
    target: &VerifiedDevice,
    now: u64,
    lost_ack: bool,
) -> RProposal {
    let mut owner = open(&f.c);
    let image = owner.image().expect("original");
    let previous = owner
        .original_device_metadata(&image)
        .expect("actual original predecessor");
    let client = policy_client(f, &mut owner);
    let proposal = owner
        .prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("original R"),
            f.c.policy.historical(),
            p,
            target,
            now,
            client,
        )
        .expect("real original R target");
    owner.close();
    let saved = journal(f);
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_roster_refresh(proposal, &previous, target, p, now)
            .expect("independent R approval"),
        RState::Prepared
    );
    let mut owner = open(&f.c);
    let mut client = policy_client(f, &mut owner);
    if lost_ack {
        *f.carrier.cut.lock().expect("cut") = Some((19, true));
    }
    let result = owner.commit_witnessed_roster_refresh(
        &proposal,
        f.c.policy.historical(),
        p,
        now,
        &mut client,
    );
    if lost_ack {
        assert!(result.is_err());
        assert!(owner.active.is_none());
        assert!(journal(f).1.is_some(), "unknown ACK preserves pending");
        let mut owner = open(&f.c);
        let mut client = policy_client(f, &mut owner);
        assert_eq!(
            owner
                .reconcile_witnessed_roster_refresh(&proposal, f.c.policy.historical(), &mut client)
                .expect("same terminal retry"),
            RState::Applied
        );
        owner.close();
    } else {
        assert_eq!(result.expect("R commit"), RState::Applied);
        owner.close();
    }
    assert_eq!(journal(f), (target_image(&saved), None));
    proposal
}
fn reopen(
    endpoint: &mut Endpoint,
    request: SessionReopenRequest,
    policy: &Arc<VerifiedSessionPolicy>,
    now: u64,
) -> crate::ReopenedPeer {
    let mut owner = open(&endpoint.f.c);
    let client = policy_client(&endpoint.f, &mut owner);
    let (active, peer) = owner
        .activate_witnessed_policy_renewed_session(request, Arc::clone(policy), now, client)
        .expect("same original session owner");
    endpoint.owner = active;
    peer
}
fn journal_of(e: &mut Endpoint) -> &mut DeviceJournal {
    e.owner
        .parts()
        .expect("owners")
        .0
        .stores()
        .expect("stores")
        .0
}
fn fanout_targets<'a>(
    contexts: &'a [Arc<BootstrapContext>],
    links: &[Link],
) -> Vec<FanoutTarget<'a>> {
    contexts
        .iter()
        .zip(links)
        .map(|(context, link)| FanoutTarget {
            context,
            session: link.session,
        })
        .collect()
}
fn committed(member: &FanoutMember) -> &[u8] {
    match &member.output {
        FanoutOutput::Committed(wire) => Ok(wire.as_slice()),
        _ => Err("expected exact committed member"),
    }
    .expect("committed member")
}

#[test]
fn original_pending_pq_offer_and_outbox_survive_policy_expiry_roster_commit_and_lost_ack() {
    let f = fixture_with_policy_expiry(Some(151));
    let peer = fixture_on_witness(
        Arc::clone(&f._witness_dir),
        f.pin.clone(),
        f.carrier.clone(),
        Some(151),
    );
    let mut a = endpoint(f);
    let mut b = endpoint(peer);
    let link = connect(&mut a, &mut b);
    let old = journal_of(&mut a)
        .next_message_id(&link.sender, link.session, 150)
        .expect("old ID");
    let old_wire = journal_of(&mut a)
        .send_message(
            &link.sender,
            link.session,
            old,
            b"before R",
            b"original",
            150,
        )
        .expect("old ciphertext");
    let (service, signer, _) = a.owner.parts().expect("original signing owner");
    let offer = service
        .stores()
        .expect("stores")
        .0
        .prepare_rekey_offer(&link.sender, link.session, signer, 150)
        .expect("reserved original PQ contribution");
    a.owner.close();
    b.owner.close();
    let pa = adopt_policy(&a.f, 155);
    let pb = adopt_policy(&b.f, 155);
    let ar = roster_target(&a.f, &[certificate(&a.f)], 2, 155);
    let br = roster_target(&b.f, &[certificate(&b.f)], 2, 155);
    refresh(&a.f, &pa, &ar, 155, true);
    refresh(&b.f, &pb, &br, 155, false);
    let (ri, rr) = requests(&link, &a, &b, 155);
    let pi = reopen(&mut a, ri, &pa, 155);
    let pr = reopen(&mut b, rr, &pb, 155);
    assert_eq!(
        a.owner
            .parts()
            .expect("actual local R")
            .2
            .roster()
            .checkpoint(),
        ar.roster().checkpoint()
    );
    assert_eq!(
        b.owner
            .parts()
            .expect("actual peer R")
            .2
            .roster()
            .checkpoint(),
        br.roster().checkpoint()
    );
    a.owner
        .parts()
        .expect("service")
        .0
        .admit_peer_roster(br.roster(), &pa, 155)
        .expect("independent remote R");
    b.owner
        .parts()
        .expect("service")
        .0
        .admit_peer_roster(ar.roster(), &pb, 155)
        .expect("independent remote R");
    assert_eq!(
        journal_of(&mut a)
            .resume_message(pi.context(), link.session, old, 155)
            .expect("same outbox"),
        old_wire
    );
    assert_eq!(
        journal_of(&mut b)
            .receive_message(pr.context(), link.session, &old_wire, b"original", 155)
            .expect("old ciphertext under current authority")
            .as_bytes(),
        b"before R"
    );
    let (is, ik, _) = a.owner.parts().expect("same original owners");
    let (rs, rk, _) = b.owner.parts().expect("same peer owners");
    let ij = is.stores().expect("stores").0;
    let rj = rs.stores().expect("stores").0;
    assert_eq!(
        ij.prepare_rekey_offer(pi.context(), link.session, ik, 155)
            .expect("original retained offer"),
        offer
    );
    let response = rj
        .respond_rekey_offer(pr.context(), link.session, &offer, rk, 155)
        .expect("same control flow");
    let final_msg = ij
        .accept_rekey_response(pi.context(), link.session, &response, ik, 155)
        .expect("final");
    let receipt = rj
        .finish_rekey(pr.context(), link.session, &final_msg, rk, 155)
        .expect("receipt");
    ij.accept_rekey_receipt(pi.context(), link.session, &receipt, 155)
        .expect("confirmed update");
    assert_eq!(
        ij.rekey_progress(pi.context(), link.session)
            .expect("epoch")
            .confirmed_epoch,
        1
    );
    assert_eq!(
        rj.rekey_progress(pr.context(), link.session)
            .expect("peer epoch")
            .confirmed_epoch,
        1
    );
    let id = ij
        .next_message_id(pi.context(), link.session, 155)
        .expect("new epoch ID");
    let wire = ij
        .send_message(
            pi.context(),
            link.session,
            id,
            b"after R and rekey",
            b"new",
            155,
        )
        .expect("forward");
    assert_eq!(
        rj.receive_message(pr.context(), link.session, &wire, b"new", 155)
            .expect("peer decrypt")
            .as_bytes(),
        b"after R and rekey"
    );
    let id = rj
        .next_message_id(pr.context(), link.session, 155)
        .expect("reverse ID");
    let wire = rj
        .send_message(pr.context(), link.session, id, b"reverse", b"new", 155)
        .expect("reverse");
    assert_eq!(
        ij.receive_message(pi.context(), link.session, &wire, b"new", 155)
            .expect("original decrypt")
            .as_bytes(),
        b"reverse"
    );
}

#[test]
fn two_recipient_committed_fanout_survives_sender_roster_update_and_keeps_partial_consumption() {
    restricted_fanout_recovery(None);
}
#[test]
fn restricted_committed_fanout_retirement_recovers_processed_and_unprocessed_witness_losses() {
    for after in [false, true] {
        restricted_fanout_recovery(Some(after));
    }
}
fn restricted_fanout_recovery(loss: Option<bool>) {
    let observe = journal;
    use crate::enrollment::tests::witness_renewal::policy_transaction::sessions::fanout::recipients;
    let mut a = endpoint(fixture_with_policy_expiry(Some(151)));
    let mut peers = recipients(&a.f);
    let links = peers
        .iter_mut()
        .map(|b| connect(&mut a, b))
        .collect::<Vec<_>>();
    assert_eq!(links.len(), 2);
    let original_contexts = links
        .iter()
        .map(|l| Arc::clone(&l.sender))
        .collect::<Vec<_>>();
    let batch = journal_of(&mut a).next_fanout_id().expect("original batch");
    let account = peers.first().expect("recipient").f.original.account_id();
    let sent = journal_of(&mut a)
        .send_account_message(
            FanoutInput {
                id: batch,
                account,
                targets: &fanout_targets(&original_contexts, &links),
                plaintext: b"complete original batch",
                associated_data: b"account",
            },
            150,
        )
        .expect("two-recipient commit");
    assert_eq!(sent.len(), 2);
    // Only the first recipient has consumed this operation. Its signed/MACed
    // consumption fact must stay distinct from the other retained ciphertext.
    let first = peers.first_mut().expect("first recipient");
    let link = links.first().expect("first link");
    let member = sent
        .iter()
        .find(|m| m.session == link.session)
        .expect("first original member");
    let delivery = journal_of(first)
        .receive_message(
            &link.receiver,
            link.session,
            committed(member),
            b"account",
            150,
        )
        .expect("actual first delivery");
    assert_eq!(delivery.as_bytes(), b"complete original batch");
    journal_of(first)
        .consume_message(&link.receiver, link.session, delivery.message_id(), 150)
        .expect("application consumption");
    let ack = journal_of(first)
        .message_acknowledgement(&link.receiver, link.session, 150)
        .expect("peer ACK");
    journal_of(&mut a)
        .accept_message_acknowledgement(&link.sender, link.session, &ack, 150)
        .expect("actual consumption fact");
    a.owner.close();
    for b in &mut peers {
        b.owner.close();
    }
    let pa = adopt_policy(&a.f, 155);
    let policies = peers
        .iter()
        .map(|b| adopt_policy(&b.f, 155))
        .collect::<Vec<_>>();
    let next = roster_target(&a.f, &[certificate(&a.f)], 2, 155);
    refresh(&a.f, &pa, &next, 155, true);
    let mut contexts = Vec::new();
    let mut receiver_contexts = Vec::new();
    for (index, ((b, link), policy)) in peers.iter_mut().zip(&links).zip(&policies).enumerate() {
        let (ri, rr) = requests(link, &a, b, 155);
        let pi = if index == 0 {
            reopen(&mut a, ri, &pa, 155)
        } else {
            a.owner
                .parts()
                .expect("same sender owner")
                .0
                .reopen_continued_peer(ri, Arc::clone(&pa), 155)
                .expect("second original session")
        };
        let pr = reopen(b, rr, policy, 155);
        contexts.push(Arc::clone(pi.context()));
        receiver_contexts.push(Arc::clone(pr.context()));
        b.owner
            .parts()
            .expect("service")
            .0
            .admit_peer_roster(next.roster(), policy, 155)
            .expect("new sender R");
    }
    let selected = fanout_targets(&contexts, &links);
    let resumed = journal_of(&mut a)
        .resume_account_message(batch, &selected, 155)
        .expect("original complete batch under sender R2");
    assert_eq!(resumed.len(), 2);
    for m in &resumed {
        let old = sent
            .iter()
            .find(|x| x.session == m.session)
            .expect("same original recipient");
        assert_eq!((m.device, m.message), (old.device, old.message));
        if m.session == links.first().expect("first link").session {
            assert!(matches!(m.output, FanoutOutput::Acknowledged));
        } else {
            assert_eq!(committed(m), committed(old));
        }
    }
    let second = peers.get_mut(1).expect("second");
    let link = links.get(1).expect("second link");
    let context = receiver_contexts.get(1).expect("second context");
    let pending = resumed
        .iter()
        .find(|m| m.session == link.session)
        .expect("same pending member");
    assert_eq!(
        journal_of(second)
            .receive_message(context, link.session, committed(pending), b"account", 155)
            .expect("second original decryption")
            .as_bytes(),
        b"complete original batch"
    );
    // The batch remains pinned to its original recipient roster. An externally
    // approved new recipient roster suspends this operation without changing IDs.
    for b in &mut peers {
        b.owner.close();
    }
    let certificates = peers.iter().map(|b| certificate(&b.f)).collect::<Vec<_>>();
    let remote = roster_target(&peers.first().expect("account").f, &certificates, 2, 155);
    a.owner
        .parts()
        .expect("service")
        .0
        .admit_peer_roster(remote.roster(), &pa, 155)
        .expect("independent current remote roster");
    let before = journal_of(&mut a).test_snapshot();
    assert!(matches!(
        journal_of(&mut a).resume_account_message(batch, &selected, 155),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    assert_eq!(
        journal_of(&mut a).test_snapshot().digest,
        before.digest,
        "suspension must not rewrite batch"
    );
    assert_eq!(
        journal_of(&mut a)
            .fanout_status(batch)
            .expect("actual batch"),
        crate::FanoutStatus::Committed
    );
    assert!(
        matches!(
            journal_of(&mut a).resume_message(
                contexts.get(1).expect("context"),
                link.session,
                pending.message,
                155
            ),
            Err(DurableError::Suspended)
        ),
        "no individual bypass of mandatory group release"
    );
    // Explicit closure is historical accounting, not a new send or an inferred ACK.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    a.owner.close();
    pa.runtime.close();
    let recovery = |f: &Fixture| {
        let mut enrollment = open(&f.c);
        let key = enrollment.key().expect("original wrapping key");
        let client = policy_client(f, &mut enrollment);
        enrollment.close();
        (
            crate::InstallationRecovery::open(f.c.paths.installation.clone(), key)
                .expect("original restricted discovery"),
            client,
        )
    };
    let expected = |states: &[crate::FanoutMemberState]| {
        let mut members = sent
            .iter()
            .map(|member| {
                let index = links
                    .iter()
                    .position(|link| link.session == member.session)
                    .expect("original member");
                crate::FanoutMemberStatus {
                    device: member.device,
                    session: member.session,
                    message: member.message,
                    state: *states
                        .get(index)
                        .expect("one result for every original member"),
                }
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.device);
        crate::FanoutReconciliation { batch, members }
    };
    use crate::FanoutMemberState::{Acknowledged, Committed, DeliveryUnknown, ResolutionPending};
    let inspect = |want: crate::FanoutReconciliation| {
        let (recovery, client) = recovery(&a.f);
        let mut account = recovery
            .open_account(batch, Some(client))
            .expect("complete original batch");
        let journal = account.journal().expect("restricted account owner");
        assert_eq!(
            journal.reconcile_members().expect("all member metadata"),
            want
        );
        assert!(
            matches!(journal.begin(), Err(DurableError::Conflict)),
            "a committed batch is never a reserved abandonment"
        );
        assert!(
            matches!(journal.retire_metadata(), Err(DurableError::Suspended)),
            "at least one original member still awaits accounting"
        );
        account.close();
    };
    let before = observe(&a.f);
    let (discovery, client) = recovery(&a.f);
    let mut account = discovery
        .open_account(batch, Some(client))
        .expect("original cleanup witness");
    *a.f.carrier.cut.lock().expect("loss") = Some((1, false));
    assert!(
        matches!(
            account.journal().expect("account").reconcile_members(),
            Err(DurableError::Anchor(_))
        ),
        "metadata result must not bypass the current witness head"
    );
    assert!(a.f.carrier.cut.lock().expect("consumed loss").is_none());
    account.close();
    assert_eq!(
        observe(&a.f),
        before,
        "failed metadata release cannot change the original batch"
    );
    inspect(expected(&[Acknowledged, Committed]));
    for (index, link) in links.iter().enumerate() {
        let (discovery, client) = recovery(&a.f);
        let mut session = discovery
            .open_session(link.session, Some(client))
            .expect("original restricted session");
        let report = session
            .stores()
            .expect("stores")
            .0
            .begin()
            .expect("freeze original session for accounting");
        let epoch = report
            .epochs
            .iter()
            .find(|e| e.epoch == 0)
            .expect("original epoch");
        assert_eq!(epoch.sent, 1);
        let member = sent
            .iter()
            .find(|m| m.session == link.session)
            .expect("original batch member");
        if index == 0 {
            assert_eq!(epoch.acknowledged_before, 1);
            assert!(epoch.unconfirmed.is_empty());
        } else {
            assert_eq!(epoch.acknowledged_before, 0);
            assert_eq!(epoch.unconfirmed.len(), 1);
            assert_eq!(
                epoch.unconfirmed.first().expect("unconfirmed").message_id(),
                member.message
            );
        }
        let bytes = format!("{report:#?}\n");
        let path =
            a.f.c
                .paths
                .configuration
                .with_file_name(format!("roster-fanout-accounting-{index}.txt"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("private host report");
        file.write_all(bytes.as_bytes())
            .expect("complete public metadata");
        file.sync_all().expect("durable host accounting");
        fs::File::open(path.parent().expect("parent"))
            .expect("directory")
            .sync_all()
            .expect("durable name");
        assert_eq!(fs::read(&path).expect("host readback"), bytes.as_bytes());
        session.close();
        inspect(expected(&if index == 0 {
            [Acknowledged, Committed]
        } else {
            [Acknowledged, ResolutionPending]
        }));
        let (discovery, client) = recovery(&a.f);
        let mut session = discovery
            .open_session(link.session, Some(client))
            .expect("reopen original frozen report");
        assert_eq!(
            session
                .stores()
                .expect("stores")
                .0
                .begin()
                .expect("same report"),
            report
        );
        session
            .stores()
            .expect("stores")
            .0
            .acknowledge(report.report)
            .expect("ack exact durably accounted outcome");
        session.close();
    }
    let (discovery, client) = recovery(&a.f);
    let mut account = discovery
        .open_account(batch, Some(client))
        .expect("original accounted batch");
    let journal = account.journal().expect("restricted journal");
    assert_eq!(
        journal.reconcile_members().expect("exact final results"),
        expected(&[Acknowledged, DeliveryUnknown])
    );
    if let Some(after) = loss {
        *a.f.carrier.cut.lock().expect("advance loss") = Some((2, after));
        assert!(matches!(
            journal.retire_metadata(),
            Err(DurableError::Anchor(_))
        ));
        assert!(a
            .f
            .carrier
            .cut
            .lock()
            .expect("consumed advance loss")
            .is_none());
        account.close();
        let interrupted = observe(&a.f);
        let original = peer_roster::original_pending_target(&interrupted);
        let (discovery, client) = recovery(&a.f);
        let mut recovered = discovery
            .open_account(batch, Some(client))
            .expect("exact original retirement recovery");
        let current = recovered.journal().expect("recovered account");
        assert_eq!(
            current.status().expect("actual recovered fact"),
            crate::FanoutStatus::Retired
        );
        current.retire_metadata().expect("same retirement");
        recovered.close();
        assert_eq!(
            observe(&a.f),
            (original, None),
            "retirement recovered the byte-exact sealed target"
        );
        eprintln!("RESTRICTED_FANOUT_ADVANCE_LOSS after={after} original_sealed_target=true");
        return;
    }
    journal
        .retire_metadata()
        .expect("all original outcomes accounted through restricted owner");
    journal
        .retire_metadata()
        .expect("same-owner duplicate retirement");
    assert_eq!(
        journal.status().expect("retained original ID"),
        crate::FanoutStatus::Retired
    );
    assert!(matches!(
        journal.reconcile_members(),
        Err(DurableError::Protocol(Error::Retired))
    ));
    account.close();
    let (discovery, client) = recovery(&a.f);
    assert!(
        matches!(
            discovery.open_account(batch, Some(client)),
            Err(DurableError::Protocol(Error::Retired))
        ),
        "fresh owner observes actual retired ID"
    );
    eprintln!("ROSTER_FANOUT_RESTRICTED_RECOVERY members=2 ack=1 unknown=1 current_remote_roster_changed=true complete_reports_synced=true");
}

struct UpdatedPair {
    a: Endpoint,
    b: Endpoint,
    link: Link,
    pa: Arc<VerifiedSessionPolicy>,
    pi: crate::ReopenedPeer,
    pr: crate::ReopenedPeer,
}
fn updated_pair() -> UpdatedPair {
    let f = fixture_with_policy_expiry(Some(151));
    let second = fixture_on_witness(
        Arc::clone(&f._witness_dir),
        f.pin.clone(),
        f.carrier.clone(),
        Some(151),
    );
    let mut a = endpoint(f);
    let mut b = endpoint(second);
    let link = connect(&mut a, &mut b);
    a.owner.close();
    b.owner.close();
    let pa = adopt_policy(&a.f, 155);
    let pb = adopt_policy(&b.f, 155);
    let ar = roster_target(&a.f, &[certificate(&a.f)], 2, 155);
    let br = roster_target(&b.f, &[certificate(&b.f)], 2, 155);
    refresh(&a.f, &pa, &ar, 155, false);
    refresh(&b.f, &pb, &br, 155, false);
    let (ri, rr) = requests(&link, &a, &b, 155);
    let pi = reopen(&mut a, ri, &pa, 155);
    let pr = reopen(&mut b, rr, &pb, 155);
    a.owner
        .parts()
        .expect("service")
        .0
        .admit_peer_roster(br.roster(), &pa, 155)
        .expect("current remote R");
    b.owner
        .parts()
        .expect("service")
        .0
        .admit_peer_roster(ar.roster(), &pb, 155)
        .expect("current remote R");
    UpdatedPair {
        a,
        b,
        link,
        pa,
        pi,
        pr,
    }
}
#[test]
fn current_roster_cache_release_requires_fresh_witness_runtime_and_peer_membership() {
    let mut scenarios = 0;
    for aggregate in [false, true] {
        for failure in 0..3 {
            let mut n = updated_pair();
            assert_eq!(
                n.pr.context().digest(),
                n.link.receiver.digest(),
                "original peer transcript retained"
            );
            let individual = journal_of(&mut n.a)
                .next_message_id(n.pi.context(), n.link.session, 155)
                .expect("individual ID");
            journal_of(&mut n.a)
                .send_message(
                    n.pi.context(),
                    n.link.session,
                    individual,
                    b"cached original",
                    b"fence",
                    155,
                )
                .expect("committed cache");
            let batch = journal_of(&mut n.a).next_fanout_id().expect("batch ID");
            let targets = [FanoutTarget {
                context: n.pi.context(),
                session: n.link.session,
            }];
            journal_of(&mut n.a)
                .send_account_message(
                    FanoutInput {
                        id: batch,
                        account: n.b.f.original.account_id(),
                        targets: &targets,
                        plaintext: b"cached group",
                        associated_data: b"fence",
                    },
                    155,
                )
                .expect("committed complete group");
            match failure {
                0 => n.a.f.carrier.clock.store(159, Ordering::SeqCst),
                1 => {
                    let runtime = Arc::clone(&n.pa.runtime);
                    *n.a.f.carrier.after_reply.lock().expect("hook") =
                        Some((15, Box::new(move || runtime.close())));
                }
                _ => {
                    let issued =
                        n.b.f
                            .c
                            .root
                            .issue_roster(3, interval(), &[])
                            .expect("actual root revokes peer");
                    let pin = AccountPin::new(
                        n.b.f.original.account_id(),
                        n.b.f.c.intent.root.clone(),
                        issued.checkpoint(),
                        n.pa.family(),
                    )
                    .expect("independent current pin");
                    let revoked = pin
                        .verify_roster(issued.as_bytes(), 155)
                        .expect("authentic revocation");
                    n.a.owner
                        .parts()
                        .expect("service")
                        .0
                        .admit_peer_roster(&revoked, &n.pa, 155)
                        .expect("commit actual peer revocation");
                }
            }
            let before = journal_of(&mut n.a).test_snapshot();
            let result = if aggregate {
                journal_of(&mut n.a)
                    .resume_account_message(batch, &targets, 155)
                    .map(|_| ())
            } else {
                journal_of(&mut n.a)
                    .resume_message(n.pi.context(), n.link.session, individual, 155)
                    .map(|_| ())
            };
            match failure {
                0 => assert!(
                    matches!(result,Err(DurableError::Anchor(e)) if matches!(*e,crate::AnchorClientError::AuthorityDenied)),
                    "witness expiry must deny cached release"
                ),
                1 => assert!(
                    matches!(
                        result,
                        Err(DurableError::Protocol(Error::Closed | Error::Runtime(_)))
                    ),
                    "runtime closed during signed reply must deny cached release: {result:?}"
                ),
                _ => assert!(
                    matches!(result, Err(DurableError::Protocol(Error::Scope))),
                    "actual current membership must deny cached release: {result:?}"
                ),
            }
            n.a.owner.close();
            n.b.owner.close();
            let mut owner = open(&n.a.f.c);
            let client = policy_client(&n.a.f, &mut owner);
            let mut retained = DeviceJournal::open_anchored_retained(
                n.a.f.c.paths.installation.files()[1],
                owner.key().expect("original key"),
                &n.a.f.original,
                n.a.f.c.policy.historical(),
                n.a.f.id,
                client,
            )
            .expect("historical head inspection");
            let after = retained.test_snapshot();
            assert_eq!(
                (after.revision, after.digest),
                (before.revision, before.digest),
                "denial must preserve cache and original state"
            );
            retained.close();
            scenarios += 1;
        }
    }
    assert_eq!(scenarios, 6);
    eprintln!("ROSTER_TRAFFIC_FENCES scenarios={scenarios} cached_individual_and_fanout=true fresh_witness=true runtime_recheck=true actual_revocation=true");
}
