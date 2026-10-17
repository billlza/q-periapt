// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "peer_retirement_process.rs"]
mod process;

fn adopt(
    c: &Case,
    sender: &mut DeviceJournal,
    retirement: &crate::AnchorRetiredAccount,
    now: u64,
) -> Result<(), DurableError> {
    let device = c.f.initiator_device();
    let policy = c.f.initiator.current_policy()?;
    let authority = crate::RetainedInstallationAuthority::active_installation(device, policy);
    sender.retire_peer_account(
        &crate::installation::PolicyScope {
            authority: &authority,
            original_policy: policy.historical(),
            original_device: device,
        },
        retirement,
        policy,
        now,
    )
}

fn reopen(c: &Case, identity: JournalIdentity) -> Result<DeviceJournal, DurableError> {
    let path = c.path.parent().expect("fixture parent").join("peer");
    let client = crate::AnchorClient::new(
        c.pin.clone(),
        DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("original sender signer"),
        Box::new(Carrier(Arc::clone(&c.witness))),
        Duration::from_secs(10),
    )?;
    DeviceJournal::open_anchored(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key"))?,
        c.f.initiator_device(),
        c.f.initiator.current_policy()?,
        identity,
        client,
    )
}

#[test]
fn peer_account_retirement_fences_cached_fresh_and_reopened_old_root_operations() {
    let mut c = case();
    let (mut sender, session) = c.connected_peer();
    let identity = sender.identity().expect("original sender journal");
    let id = sender
        .next_message_id(&c.f.initiator, session, 150)
        .expect("message id");
    let wire = sender
        .send_message(&c.f.initiator, session, id, b"original", b"root", 150)
        .expect("actual ciphertext");
    assert_eq!(
        c.journal
            .receive_message(&c.f.responder, session, &wire, b"root", 150)
            .expect("actual receive")
            .as_bytes(),
        b"original"
    );
    c.journal
        .consume_message(&c.f.responder, session, id, 150)
        .expect("remote consumption before retirement");
    let late_ack = c
        .journal
        .message_acknowledgement(&c.f.responder, session, 150)
        .expect("valid original acknowledgement held in transit");
    let inbound_id = c
        .journal
        .next_message_id(&c.f.responder, session, 150)
        .expect("original peer send identity");
    let late_inbound = c
        .journal
        .send_message(
            &c.f.responder,
            session,
            inbound_id,
            b"held in transit",
            b"root",
            150,
        )
        .expect("valid original peer ciphertext");
    let proposal = c.proposal(233);
    let receipt = c.receipt(&proposal);
    let observed = c
        .pin
        .verify_retired_account(&proposal, &receipt)
        .expect("verified retirement");
    // Verification is intentionally pure; adoption is an explicit owner mutation.
    assert_eq!(
        sender
            .resume_message(&c.f.initiator, session, id, 150)
            .expect("before adoption"),
        wire
    );
    adopt(&c, &mut sender, &observed, 150).expect("durable peer floor");
    let first_image = sender.image().expect("current own witness head");
    adopt(&c, &mut sender, &observed, 150).expect("exact retry");
    assert_eq!(
        sender.image().expect("same image").digest,
        first_image.digest
    );
    for _ in 0..2 {
        assert!(matches!(
            sender.receive_message(&c.f.initiator, session, &late_inbound, b"root", 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            sender.accept_message_acknowledgement(&c.f.initiator, session, &late_ack, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            sender.resume_message(&c.f.initiator, session, id, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            sender.next_message_id(&c.f.initiator, session, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            sender.initiate(
                Arc::clone(&c.f.initiator),
                crate::InitiationId::from_trusted_state([234; 32]).expect("fresh request"),
                &c.f.signer_i,
                150
            ),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            sender.install_roster(c.f.local_device().roster(), 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        let newer = crate::durable::rosters::tests::update(c.f.local_device(), 94, 2, true);
        assert!(matches!(
            sender.install_roster(&newer, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        sender.close();
        sender = reopen(&c, identity).expect("original current sender remains openable");
    }
    adopt(&c, &mut sender, &observed, 150).expect("same operation after restart");
    let report = sender
        .begin_session_closure(&c.f.initiator, session)
        .expect("historical loss accounting after peer retirement");
    assert_eq!(report.peer_account, proposal.previous_account());
    assert_eq!(report.session, session);
    assert!(report
        .epochs
        .iter()
        .any(|epoch| !epoch.unconfirmed.is_empty()));
    sender.close();
}

#[test]
fn peer_account_retirement_rejects_a_different_witness_and_expired_local_authority() {
    let mut c = case();
    let (mut sender, _) = c.connected_peer();
    let other = case();
    let foreign_proposal = other.proposal(235);
    let foreign_receipt = other.receipt(&foreign_proposal);
    let foreign = other
        .pin
        .verify_retired_account(&foreign_proposal, &foreign_receipt)
        .expect("real unrelated witness signature");
    let before = sender.image().expect("before refusal").digest;
    assert!(matches!(
        adopt(&c, &mut sender, &foreign, 150),
        Err(DurableError::Conflict)
    ));
    assert_eq!(sender.image().expect("no mutation").digest, before);
    let proposal = c.proposal(236);
    let receipt = c.receipt(&proposal);
    let observed = c
        .pin
        .verify_retired_account(&proposal, &receipt)
        .expect("original witness");
    adopt(&c, &mut sender, &observed, 150).expect("original authorized adoption");
    assert!(adopt(&c, &mut sender, &observed, 250).is_err());
    sender.close();
}

#[test]
fn peer_account_retirement_fences_committed_fanout_and_preserves_loss_report() {
    let mut c = case();
    let (mut sender, session) = c.connected_peer();
    let account = c.f.local_device().account_id();
    let targets = [crate::FanoutTarget {
        context: &c.f.initiator,
        session,
    }];
    let id = sender.next_fanout_id().expect("original batch id");
    let input = || crate::FanoutInput {
        id,
        account,
        targets: &targets,
        plaintext: b"original fanout",
        associated_data: b"peer retirement",
    };
    let committed = sender
        .send_account_message(input(), 150)
        .expect("actual committed fanout");
    assert_eq!(committed.len(), 1);
    let p = c.proposal(237);
    let receipt = c.receipt(&p);
    let observed = c
        .pin
        .verify_retired_account(&p, &receipt)
        .expect("retirement");
    adopt(&c, &mut sender, &observed, 150).expect("local peer floor");
    assert!(matches!(
        sender.send_account_message(input(), 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        sender.resume_account_message(id, &targets, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        sender.fanout_status(id).expect("historical metadata"),
        crate::FanoutStatus::Committed
    );
    let report = sender
        .begin_session_closure(&c.f.initiator, session)
        .expect("historical committed-member accounting");
    assert_eq!(report.peer_account, account);
    assert!(report
        .epochs
        .iter()
        .any(|epoch| !epoch.unconfirmed.is_empty()));
    sender.close();
}

#[test]
fn peer_account_retirement_backup_cannot_remove_the_senders_committed_floor() {
    let mut c = case();
    let (mut sender, _) = c.connected_peer();
    let identity = sender.identity().expect("original identity");
    let path = c.path.parent().expect("parent").join("peer/state.redb");
    sender.close();
    let before = fs::read(&path).expect("complete pre-adoption backup");
    sender = reopen(&c, identity).expect("original sender");
    let p = c.proposal(238);
    let receipt = c.receipt(&p);
    let observed = c
        .pin
        .verify_retired_account(&p, &receipt)
        .expect("retirement");
    adopt(&c, &mut sender, &observed, 150).expect("committed sender floor");
    sender.close();
    let committed = fs::read(&path).expect("complete committed image");
    fs::write(&path, before).expect("restore only this owned test backup");
    assert!(matches!(reopen(&c, identity), Err(DurableError::Anchor(_))));
    fs::write(&path, committed).expect("restore original committed bytes");
    sender = reopen(&c, identity).expect("same committed sender");
    adopt(&c, &mut sender, &observed, 150).expect("original retry after restored committed bytes");
    sender.close();
}

#[test]
fn peer_account_retirement_reconciles_every_pre_and_post_sync_failure() {
    let barriers = {
        let mut c = case();
        let (mut sender, _) = c.connected_peer();
        let p = c.proposal(239);
        let receipt = c.receipt(&p);
        let observed = c
            .pin
            .verify_retired_account(&p, &receipt)
            .expect("retirement");
        let path = c.path.parent().expect("parent").join("peer/state.redb");
        let (_, count) = crate::durable::tests::fault_existing_journal(&mut sender, &path, false);
        adopt(&c, &mut sender, &observed, 150).expect("measure actual adoption barriers");
        count.load(Ordering::SeqCst)
    };
    assert!((1..=16).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = case();
            let (mut sender, session) = c.connected_peer();
            let identity = sender.identity().expect("original identity");
            let p = c.proposal(240);
            let receipt = c.receipt(&p);
            let observed = c
                .pin
                .verify_retired_account(&p, &receipt)
                .expect("retirement");
            let path = c.path.parent().expect("parent").join("peer/state.redb");
            let (remaining, _) =
                crate::durable::tests::fault_existing_journal(&mut sender, &path, after);
            remaining.store(cut, Ordering::SeqCst);
            assert!(
                adopt(&c, &mut sender, &observed, 150).is_err(),
                "cut={cut} after={after}"
            );
            assert!(matches!(sender.identity(), Err(DurableError::Closed)));
            remaining.store(0, Ordering::SeqCst);
            drop(sender);
            let mut original = reopen(&c, identity).expect("reconcile exact retained write intent");
            adopt(&c, &mut original, &observed, 150).expect("retry original approved statement");
            assert!(matches!(
                original.next_message_id(&c.f.initiator, session, 150),
                Err(DurableError::Protocol(Error::Scope))
            ));
            original.close();
        }
    }
    eprintln!(
        "PEER_ACCOUNT_RETIREMENT_SYNC_FAULTS barriers={barriers} failures={}",
        barriers * 2
    );
}

#[test]
fn peer_account_retirement_is_available_through_the_original_device_service() {
    use crate::{DeviceInstallation, InstallationPaths, InstallationPreparation};
    use std::os::unix::fs::DirBuilderExt;
    let mut c = case();
    let path = c.path.parent().expect("parent").join("peer");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("private installation directory");
    let paths = InstallationPaths::new(
        &path.join("installation.redb"),
        &path.join("state.redb"),
        &path.join("archives.redb"),
    )
    .expect("original paths");
    let device = c.f.initiator_device();
    let policy = c.f.initiator.current_policy().expect("current policy");
    let key = JournalKey::provision(&path.join("key")).expect("original key");
    let mut installation = DeviceInstallation::provision(paths, &key, device, policy, 150)
        .expect("explicit installation intent");
    let prepared = installation
        .prepare(key, device, policy, 150)
        .expect("original children");
    let genesis = match prepared {
        InstallationPreparation::RequiresEnrollment(genesis) => Some(genesis),
        InstallationPreparation::Local => None,
    }
    .expect("fixture requires its witness");
    c.witness
        .lock()
        .expect("witness")
        .enroll(&genesis, device, policy, 150)
        .expect("independent witness enrollment");
    let client = crate::AnchorClient::new(
        c.pin.clone(),
        DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("original signer"),
        Box::new(Carrier(Arc::clone(&c.witness))),
        Duration::from_secs(10),
    )
    .expect("client");
    let mut service = installation
        .activate(
            JournalKey::open(&path.join("key")).expect("same key"),
            device,
            policy,
            150,
            Some(client),
        )
        .expect("current original service");
    let session = c.connect_peer(service.stores().expect("retained service").0);
    let p = c.proposal(241);
    let receipt = c.receipt(&p);
    let observed = c
        .pin
        .verify_retired_account(&p, &receipt)
        .expect("retirement");
    service
        .retire_peer_account(
            &observed,
            c.f.initiator.current_policy().expect("policy"),
            150,
        )
        .expect("public service adoption");
    assert!(matches!(
        service
            .stores()
            .expect("current sender")
            .0
            .next_message_id(&c.f.initiator, session, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        service.admit_peer_roster(
            c.f.local_device().roster(),
            c.f.initiator.current_policy().expect("policy"),
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    service.close();
}

#[test]
fn peer_account_retirement_rejects_malformed_authenticated_marker_and_conflicting_retry() {
    let mut c = case();
    let (mut sender, _) = c.connected_peer();
    let p = c.proposal(242);
    let receipt = c.receipt(&p);
    let observed = c
        .pin
        .verify_retired_account(&p, &receipt)
        .expect("retirement");
    adopt(&c, &mut sender, &observed, 150).expect("original adoption");
    for malformed in 0..4 {
        let mut image = sender.image().expect("authenticated original");
        let record = image
            .records
            .values_mut()
            .find(|r| r.payload.starts_with(b"QPRHST07"))
            .expect("peer marker");
        match malformed {
            0 => record
                .payload
                .get_mut(8..40)
                .expect("encoded operation")
                .fill(0),
            1 => record
                .payload
                .get_mut(72..104)
                .expect("encoded successor")
                .copy_from_slice(&p.previous_account()),
            2 => record
                .payload
                .get_mut(104..136)
                .expect("encoded witness")
                .fill(17),
            _ => {
                record.payload.truncate(135);
            }
        }
        assert!(crate::durable::rosters::validate_image(&image).is_err());
    }
    // An authenticated competing local decision cannot be overwritten by retry.
    let mut image = sender.image().expect("original image");
    image
        .records
        .values_mut()
        .find(|r| r.payload.starts_with(b"QPRHST07"))
        .expect("peer marker")
        .payload
        .get_mut(8..40)
        .expect("encoded operation")
        .fill(243);
    sender
        .persist(&mut image)
        .expect("trusted-state conflict fixture");
    assert!(matches!(
        adopt(&c, &mut sender, &observed, 150),
        Err(DurableError::Conflict)
    ));
    sender.close();
}
