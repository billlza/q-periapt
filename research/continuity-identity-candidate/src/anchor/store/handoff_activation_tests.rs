// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "handoff_activation_recovery_tests.rs"]
mod recovery;

fn retired(c: &mut Case, now: u64) -> (TargetFixture, AnchorHandoffTarget, Vec<u8>) {
    let f = TargetFixture::new_at(c, now);
    let mut target = f.provision();
    let ack = target.import_receipt().expect("committed import");
    let retirement = c
        .store
        .retire_handoff(&f.approval, ack.as_bytes(), || Ok(now))
        .expect("actual committed retirement");
    (f, target, retirement.as_bytes().to_vec())
}

pub(in crate::anchor::store) fn new_client(
    store: AnchorStore,
    pin: &AnchorPin,
) -> crate::anchor::store::policy_renewal::tests::Case {
    use crate::anchor::store::policy_renewal::tests::{policy, Case as PolicyCase};
    let mut c = PolicyCase::new();
    let original = policy(&c.issuer, &c.runtime, pin, 1, 160, 150);
    let current = policy(&c.issuer, &c.runtime, pin, 2, 260, 170);
    let client = c.server.join("activated-target-client");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&client)
        .expect("private client");
    let mut journal = DeviceJournal::provision_anchored(
        &client.join("journal.redb"),
        JournalKey::provision(&client.join("key")).expect("new client key"),
        &c.device,
        &original,
        crate::JournalIdentity::generate().expect("new client journal identity"),
        150,
    )
    .expect("real new journal");
    let genesis = journal
        .anchor_genesis(&c.device, &original)
        .expect("actual new genesis");
    c.store.close();
    c.store = store;
    c.pin = pin.clone();
    c.subject = genesis.subject();
    c.initial = AnchorHead::from_trusted_state(1, 1, genesis.image_digest()).expect("genesis head");
    c.original = original.historical().clone();
    c.target = current;
    c.store
        .enroll(&genesis, &c.device, &original, 150)
        .expect("independent current enrollment");
    c
}

#[test]
fn activation_serves_new_enrollment_without_adopting_or_changing_inherited_clients() {
    let mut c = case();
    let prior = super::super::handoff::plan(&mut c, 216);
    c.store.freeze_handoff(&prior, 150).expect("earlier freeze");
    c.store
        .cancel_handoff(&prior)
        .expect("earlier cancellation retained");
    let (f, mut target, retirement) = retired(&mut c, 150);
    let source = target.retained_source_state().expect("complete old state");
    let acknowledgement = target
        .import_receipt()
        .expect("original import")
        .as_bytes()
        .to_vec();
    let history = target
        .verify_source_retirement(&retirement)
        .expect("verified complete history");
    let (mut active, activation) = target
        .activate(&retirement, f.signer())
        .expect("durable activation");
    assert!(matches!(target.status(), Err(DurableError::Closed)));
    let verified = f
        .approval
        .verify_activation_receipt(
            &history,
            &f.freeze,
            &acknowledgement,
            &retirement,
            activation.as_bytes(),
        )
        .expect("independent original public pins and transaction");
    assert_eq!(
        verified.history_checkpoint(),
        activation.history_checkpoint()
    );
    assert!(f
        .approval
        .verify_activation_receipt(
            &history,
            &f.freeze,
            &acknowledgement,
            &f.freeze,
            activation.as_bytes()
        )
        .is_err());
    assert!(f.plan.verify_receipt(activation.as_bytes()).is_err());
    assert_eq!(
        active.pin().expect("new authority").binding(),
        f.pin.binding()
    );
    assert_eq!(
        active.namespace().expect("unchanged namespace"),
        c.pin.binding()
    );
    let request = AnchorRequest::new(
        &f.pin,
        c.genesis.subject(),
        AnchorOperation::query(),
        &c.peer.signer_r,
    )
    .expect("valid device signature under new witness");
    assert!(f.pin.verify_reply(&request, activation.as_bytes()).is_err());
    assert!(matches!(
        active.handle(request.as_bytes(), 150),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("old verified materials");
    assert!(matches!(
        active.enroll(&c.genesis, device, policy, 150),
        Err(DurableError::Suspended)
    ));
    let captured = active
        .handoff_source_state()
        .expect("complete public successor capture");
    assert_eq!(captured.pin().binding(), f.pin.binding());
    let next_signer = AnchorSigningKey::generate().expect("independent third key");
    let next_pin = AnchorPin::new(
        AnchorIdentity::generate().expect("third identity"),
        next_signer.public_key().expect("third public key"),
    );
    let next_plan = AnchorHandoffPlan::from_trusted_state(
        [225; 32],
        &captured,
        next_pin,
        Validity::new(140, 160).expect("next interval"),
        [226; 32],
    )
    .expect("exact prospective next plan");
    active
        .freeze_handoff(&next_plan, 150)
        .expect("independently approved current-source freeze");
    assert_eq!(
        active
            .frozen_handoff_state(&next_plan)
            .expect("same complete source")
            .as_bytes(),
        captured.as_bytes()
    );
    let cancelled = active
        .cancel_handoff(&next_plan)
        .expect("cancel before new enrollment");
    let mut next = new_client(active, &f.pin);
    let approval = next.approval(&next.original, None, &next.target);
    let p = next.proposal(&approval, next.initial, 222);
    next.prepare(p, &approval)
        .expect("new client's actual dual-approved P");
    next.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170);
    next.store.close();
    c.store.close();
    fs::remove_file(c.server.join("signer")).expect("remove only owned old key");
    let mut reopened = f.open();
    assert_eq!(
        reopened.status().expect("committed"),
        AnchorHandoffTargetState::Activated
    );
    assert_eq!(
        reopened
            .retained_source_state()
            .expect("old full snapshot after new work"),
        source
    );
    assert_eq!(
        reopened
            .activation_receipt()
            .expect("same certificate")
            .as_bytes(),
        activation.as_bytes()
    );
    let (restored, replay) = reopened
        .activate(&retirement, f.signer())
        .expect("same activation retry");
    assert_eq!(replay.as_bytes(), activation.as_bytes());
    next.store = restored;
    assert_eq!(
        next.store
            .observe_handoff(&next_plan)
            .expect("ordinary writes retain source history")
            .as_bytes(),
        cancelled.as_bytes()
    );
    assert_eq!(
        next.store.namespace().expect("original namespace"),
        c.pin.binding()
    );
    next.exchange(&p, AnchorOperation::policy_renewal_status(&p), 170);
    next.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 170);
    assert!(matches!(
        next.store.handle(request.as_bytes(), 170),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
}

#[test]
fn activation_requires_exact_retirement_and_target_key_and_never_revives_cancelled_import() {
    let mut c = case();
    let f = TargetFixture::new(&mut c);
    let mut target = f.provision();
    let ack = target.import_receipt().expect("original ack");
    for false_receipt in [&f.freeze, &ack.as_bytes().to_vec(), &Vec::new()] {
        assert!(target.activate(false_receipt, f.signer()).is_err());
        assert_eq!(
            target.status().expect("still inactive"),
            AnchorHandoffTargetState::ImportedInactive
        );
    }
    let cancelled = c
        .store
        .cancel_handoff(&f.plan)
        .expect("committed source cancel");
    target
        .close_cancelled(cancelled.as_bytes())
        .expect("target cancellation");
    assert!(matches!(
        target.activate(cancelled.as_bytes(), f.signer()),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let mut c = case();
    let (f, mut target, retirement) = retired(&mut c, 150);
    let ack = target.import_receipt().expect("retained import");
    let mut body = open_envelope(&retirement)
        .expect("retirement body")
        .0
        .to_vec();
    let timestamp = body.len().checked_sub(8).expect("admission timestamp");
    body.get_mut(timestamp..)
        .expect("timestamp bytes")
        .copy_from_slice(&151_u64.to_be_bytes());
    let alternate = envelope(
        &body,
        &c.store
            .active
            .as_ref()
            .expect("owned source signer")
            .signer
            .sign(Purpose::AnchorHandoffRetirement, &body)
            .expect("valid alternate source signature"),
    )
    .expect("alternate certificate");
    f.approval
        .verify_retirement_receipt(&f.freeze, ack.as_bytes(), &alternate)
        .expect("valid certificate, distinct from the committed decision");
    assert!(matches!(
        target.activate(
            &retirement,
            AnchorSigningKey::generate().expect("wrong key")
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let (mut active, receipt) = target
        .activate(&retirement, f.signer())
        .expect("original intended target");
    active.close();
    let mut target = f.open();
    let before = fs::read(f.db_path()).expect("committed bytes");
    assert!(matches!(
        target.activate(&alternate, f.signer()),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        target.verify_source_retirement(&alternate),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        target
            .verify_source_retirement(&retirement)
            .expect("exact committed history")
            .checkpoint(),
        receipt.history_checkpoint()
    );
    assert!(target.activate(&f.freeze, f.signer()).is_err());
    assert!(target.close_cancelled(&f.freeze).is_err());
    assert_eq!(
        target
            .activation_receipt()
            .expect("original activation")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert_eq!(fs::read(f.db_path()).expect("unchanged state"), before);
}

pub(in crate::anchor::store) fn retains_pending(
    store: &mut AnchorStore,
    root: &Path,
    source_pin: &AnchorPin,
    subject: AnchorSubject,
    signer: &DeviceSigningKey,
) {
    let f = TargetFixture::from_store(store, root, source_pin, 175, false);
    let mut target = f.provision();
    let ack = target.import_receipt().expect("complete import");
    let retirement = store
        .retire_handoff(&f.approval, ack.as_bytes(), || Ok(175))
        .expect("retirement with original pending work");
    let (mut active, activation) = target
        .activate(retirement.as_bytes(), f.signer())
        .expect("complete target state");
    let attempted = AnchorRequest::new(&f.pin, subject, AnchorOperation::query(), signer)
        .expect("new challenge and original device key");
    assert!(matches!(
        active.handle(attempted.as_bytes(), 175),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    active.close();
    let mut reopened = f.open();
    assert_eq!(
        reopened
            .retained_source_state()
            .expect("all original pending bytes"),
        f.source
    );
    assert_eq!(
        reopened
            .activation_receipt()
            .expect("retained exact activation")
            .as_bytes(),
        activation.as_bytes()
    );
}

#[test]
fn activation_preserves_real_pending_credential_without_promoting_its_old_request() {
    let mut c = credential_case();
    let grant = credential_grant_first(&c);
    let p = crate::AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        grant.operation(),
        grant.statement_digest(),
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [223; 32]).expect("target"),
    )
    .expect("original pending G");
    c.store
        .prepare_credential_renewal(
            p,
            &grant,
            c.peer.responder.current_policy().expect("policy"),
            170,
        )
        .expect("actual G preparation");
    retains_pending(
        &mut c.store,
        &c.server,
        &c.pin,
        c.genesis.subject(),
        &c.peer.signer_r,
    );
}

#[test]
fn inherited_write_guard_rejects_an_otherwise_valid_unapproved_advance() {
    let mut c = case();
    let (f, mut target, retirement) = retired(&mut c, 150);
    let (mut active, _) = target.activate(&retirement, f.signer()).expect("activated");
    let mut image = active.image().expect("original inherited state");
    let entry = image
        .entries
        .get_mut(&c.genesis.subject().id(&c.pin.binding()))
        .expect("original ID");
    let operation = AnchorOperation::advance(entry.head, [224; 32]).expect("shaped advance");
    entry.head = AnchorHead::from_trusted_state(1, 2, [224; 32]).expect("target head");
    entry.last = Some(command_id(&f.pin.binding(), entry.subject, operation));
    assert!(matches!(
        active.persist(&mut image),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(active.pin(), Err(DurableError::Closed)));
    let mut target = f.open();
    assert_eq!(
        target.retained_source_state().expect("no mutation escaped"),
        f.source
    );
    let (mut current, _) = target
        .activate(&retirement, f.signer())
        .expect("original current state");
    let restored = current.image().expect("complete original entries");
    assert_eq!(
        restored
            .entries
            .get(&c.genesis.subject().id(&c.pin.binding()))
            .expect("original entry")
            .head,
        initial(&c)
    );
}

#[test]
fn inherited_legacy_classification_cannot_bypass_adoption_or_close_the_current_owner() {
    let mut c = case();
    legacy_without_original_identity(&mut c);
    let (f, mut target, retirement) = retired(&mut c, 150);
    let (mut active, _) = target
        .activate(&retirement, f.signer())
        .expect("complete legacy state");
    let original = c
        .peer
        .responder
        .inventory_inputs()
        .expect("independent old proof")
        .1;
    assert!(matches!(
        active.retain_original_identity(c.genesis.subject(), original),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        active
            .pin()
            .expect("ordinary refusal does not close service")
            .binding(),
        f.pin.binding()
    );
    let image = active.image().expect("unchanged original classification");
    assert!(image
        .entries
        .values()
        .all(|entry| entry.original_identity.is_none()));
}
