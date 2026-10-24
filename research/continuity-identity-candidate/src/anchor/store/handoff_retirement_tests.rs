// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "handoff_retirement_recovery_tests.rs"]
mod recovery;

fn imported(c: &mut Case) -> (TargetFixture, AnchorHandoffTarget, Vec<u8>) {
    let f = TargetFixture::new(c);
    let mut target = f.provision();
    let acknowledgement = target
        .import_receipt()
        .expect("committed import")
        .as_bytes()
        .to_vec();
    (f, target, acknowledgement)
}

#[test]
fn retirement_is_irreversible_and_exact_after_old_signer_removal() {
    let mut c = case();
    let old = super::super::handoff::plan(&mut c, 231);
    c.store
        .freeze_handoff(&old, 150)
        .expect("previous operation");
    let cancelled = c
        .store
        .cancel_handoff(&old)
        .expect("retained older cancellation");
    let stale = c.store.image().expect("original live image");
    let (f, mut target, ack) = imported(&mut c);
    let receipt = c
        .store
        .retire_handoff(&f.approval, &ack, || Ok(150))
        .expect("retired source");
    assert_eq!(receipt.state(), AnchorHandoffState::Retired);
    assert!(
        open_envelope(receipt.as_bytes())
            .expect("signed envelope")
            .0
            .len()
            <= crate::contract::MAX_SIGNED_BODY_BYTES
    );
    f.approval
        .verify_retirement_receipt(&f.freeze, &ack, receipt.as_bytes())
        .expect("exact historical transfer");
    assert!(f
        .approval
        .verify_retirement_receipt(&f.freeze, &ack, &f.freeze)
        .is_err());
    assert!(f
        .approval
        .verify_retirement_receipt(&f.freeze, &ack, &ack)
        .is_err());
    assert!(matches!(
        c.store.cancel_handoff(&f.plan),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        c.store.freeze_handoff(&f.plan, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let query = request(&c, AnchorOperation::query());
    assert!(matches!(
        c.store.handle(query.as_bytes(), 150),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    assert_eq!(
        c.store
            .frozen_handoff_state(&f.plan)
            .expect("retained complete original")
            .as_bytes(),
        f.source
    );
    c.store
        .active
        .as_mut()
        .expect("owned source")
        .signer
        .close();
    let mut read_clock = false;
    assert_eq!(
        c.store
            .retire_handoff(&f.approval, &ack, || {
                read_clock = true;
                Err(std::io::Error::other("committed retry read clock"))
            })
            .expect("no signer needed")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert!(!read_clock);
    assert!(matches!(
        c.store.persist(&mut { stale }),
        Err(DurableError::Conflict)
    ));
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .observe_handoff(&f.plan)
            .expect("durable retired")
            .as_bytes(),
        receipt.as_bytes()
    );
    c.store.close();
    fs::remove_file(c.server.join("signer")).expect("remove only owned test signer");
    let observer = AnchorHandoffObserver::open(
        &c.server.join("anchor.redb"),
        JournalKey::open(&c.server.join("wrapping")).expect("original storage key"),
        c.pin.clone(),
    )
    .expect("historical observer without signer");
    assert_eq!(
        observer
            .observe(&f.plan)
            .expect("retained retirement")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert_eq!(
        observer
            .observe(&old)
            .expect("retained cancelled history")
            .as_bytes(),
        cancelled.as_bytes()
    );
    assert_eq!(
        observer
            .retained_source_state(&f.plan)
            .expect("unchanged original state")
            .as_bytes(),
        f.source
    );
    assert_eq!(
        target.status().expect("still inactive"),
        AnchorHandoffTargetState::ImportedInactive
    );
    assert!(target.close_cancelled(receipt.as_bytes()).is_err());
    assert_eq!(
        target.retained_source_state().expect("no data discarded"),
        f.source
    );
}

#[test]
fn retirement_rechecks_both_admission_intervals_at_commit_and_rejects_clock_failure() {
    // First-time denial, expiry after signing, clock rollback and clock I/O failure.
    for times in [[155, 155], [150, 155], [150, 149], [150, u64::MAX]] {
        let mut c = case();
        let (f, _target, ack) = imported(&mut c);
        let mut calls = 0;
        let outcome = c.store.retire_handoff(&f.approval, &ack, || {
            let time = *times.get(calls).expect("bounded clock reads");
            calls += 1;
            if time == u64::MAX {
                Err(std::io::Error::other("test clock unavailable"))
            } else {
                Ok(time)
            }
        });
        if times[1] == u64::MAX {
            assert!(matches!(outcome, Err(DurableError::Io(_))));
        } else {
            assert!(matches!(
                outcome,
                Err(DurableError::Protocol(Error::Validity))
            ));
        }
        assert_eq!(calls, if times[0] == 155 { 1 } else { 2 });
        c.store.close();
        c.store = reopen(&c.server);
        assert_eq!(
            c.store
                .observe_handoff(&f.plan)
                .expect("no premature retirement")
                .state(),
            AnchorHandoffState::Frozen
        );
        assert_eq!(
            c.store
                .frozen_handoff_state(&f.plan)
                .expect("unchanged image")
                .as_bytes(),
            f.source
        );
        c.store
            .cancel_handoff(&f.plan)
            .expect("still cancellable after denied commit");
    }
    let mut c = case();
    let f = TargetFixture::new(&mut c);
    let approval = AnchorHandoffTargetApproval::from_trusted_state(
        &f.plan,
        &c.pin,
        &f.pin,
        Validity::new(140, 170).expect("longer target interval"),
        [232; 32],
    )
    .expect("independent longer approval");
    let mut target = AnchorHandoffTarget::provision_import(
        &f.db_path(),
        f.key(),
        &f.signer(),
        approval.clone(),
        &f.source,
        &f.freeze,
        150,
    )
    .expect("import");
    let ack = target.import_receipt().expect("original ack");
    let mut now = 150;
    assert!(matches!(
        c.store.retire_handoff(&approval, ack.as_bytes(), || {
            let value = now;
            now = 160;
            Ok(value)
        }),
        Err(DurableError::Protocol(Error::Validity))
    ));
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .observe_handoff(&f.plan)
            .expect("source interval checked at commit")
            .state(),
        AnchorHandoffState::Frozen
    );
}

#[test]
fn retirement_rejects_changed_approval_or_ack_and_signing_failure_keeps_frozen() {
    let mut c = case();
    let (f, _target, ack) = imported(&mut c);
    let other = AnchorHandoffTargetApproval::from_trusted_state(
        &f.plan,
        &c.pin,
        &f.pin,
        Validity::new(145, 155).expect("validity"),
        [233; 32],
    )
    .expect("different operator decision");
    assert!(c.store.retire_handoff(&other, &ack, || Ok(150)).is_err());
    let mut corrupted = ack.clone();
    *corrupted.last_mut().expect("signature byte") ^= 1;
    for wire in [&corrupted, &f.freeze, &Vec::new()] {
        assert!(c
            .store
            .retire_handoff(&f.approval, wire, || Ok(150))
            .is_err());
    }
    c.store
        .active
        .as_mut()
        .expect("owned signer")
        .signer
        .close();
    assert!(matches!(
        c.store.retire_handoff(&f.approval, &ack, || Ok(150)),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(
        c.store
            .observe_handoff(&f.plan)
            .expect("still frozen")
            .state(),
        AnchorHandoffState::Frozen
    );
    c.store.close();
    c.store = reopen(&c.server);
    let receipt = c
        .store
        .retire_handoff(&f.approval, &ack, || Ok(150))
        .expect("one admitted retirement");
    assert!(matches!(
        c.store.retire_handoff(&other, &ack, || Ok(150)),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store.retire_handoff(&f.approval, &corrupted, || Ok(150)),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        c.store
            .observe_handoff(&f.plan)
            .expect("original exact result")
            .as_bytes(),
        receipt.as_bytes()
    );
}

#[test]
fn retirement_preserves_real_pending_credential_and_its_complete_original_state() {
    let mut c = credential_case();
    let grant = credential_grant_first(&c);
    let proposal = crate::AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        grant.operation(),
        grant.statement_digest(),
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [234; 32]).expect("target"),
    )
    .expect("original G");
    c.store
        .prepare_credential_renewal(
            proposal,
            &grant,
            c.peer.responder.current_policy().expect("policy"),
            170,
        )
        .expect("real pending G");
    let f = TargetFixture::new_at(&mut c, 175);
    let mut target = f.provision();
    let ack = target.import_receipt().expect("original complete import");
    c.store
        .retire_handoff(&f.approval, ack.as_bytes(), || Ok(175))
        .expect("retire with unresolved G");
    assert_eq!(
        c.store
            .frozen_handoff_state(&f.plan)
            .expect("all original records retained")
            .as_bytes(),
        f.source
    );
    assert_eq!(
        target.retained_source_state().expect("same inherited G"),
        f.source
    );
    assert!(matches!(
        c.store.close_credential_renewal(
            proposal,
            &grant,
            c.peer.responder.current_policy().expect("policy")
        ),
        Err(DurableError::Suspended)
    ));
}

#[test]
fn retirement_reopen_rejects_mac_valid_and_source_signed_mismatched_target_binding() {
    let mut c = case();
    let (f, _target, ack) = imported(&mut c);
    let receipt = c
        .store
        .retire_handoff(&f.approval, &ack, || Ok(150))
        .expect("retired");
    let owner = c.store.active.as_ref().expect("owned test source");
    let image = load(&owner.db, &owner.wrapping, &owner.pin).expect("retired image");
    let mut encoded = encode(&owner.wrapping, &owner.pin, &image).expect("original image");
    let mut body = open_envelope(receipt.as_bytes()).expect("body").0.to_vec();
    // Last commitment precedes the retained admission timestamp.
    let index = body.len().checked_sub(9).expect("commitment byte");
    *body.get_mut(index).expect("ack commitment") ^= 1;
    let changed = envelope(
        &body,
        &owner
            .signer
            .sign(Purpose::AnchorHandoffRetirement, &body)
            .expect("test valid source signature"),
    )
    .expect("modified certificate");
    assert_eq!(changed.len(), receipt.as_bytes().len());
    assert!(
        f.plan.verify_receipt(&changed).is_ok(),
        "source signature alone cannot establish target import identity"
    );
    assert!(f
        .approval
        .verify_retirement_receipt(&f.freeze, &ack, &changed)
        .is_err());
    let positions: Vec<_> = encoded
        .windows(receipt.as_bytes().len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == receipt.as_bytes()).then_some(at))
        .collect();
    assert_eq!(positions.len(), 1);
    let at = *positions.first().expect("unique original certificate");
    encoded
        .get_mut(at..at + changed.len())
        .expect("same-size replacement")
        .copy_from_slice(&changed);
    let end = encoded.len().checked_sub(32).expect("MAC");
    let mut mac = authenticator(&owner.wrapping).expect("test MAC key");
    mac.update(encoded.get(..end).expect("body"));
    encoded
        .get_mut(end..)
        .expect("tag")
        .copy_from_slice(&mac.finalize().into_bytes());
    let tx = transaction(&owner.db).expect("test corruption");
    tx.open_table(TABLE)
        .expect("table")
        .insert("image", encoded.as_slice())
        .expect("replace only owned test image");
    tx.commit().expect("test corruption committed");
    assert!(c.store.observe_handoff(&f.plan).is_err());
    assert!(c.store.active.is_none());
}
