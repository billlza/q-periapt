// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorRetiredCleanupProposal as Cleanup, AnchorRetiredCleanupState as CleanupState,
    AnchorRetiredSubject,
};
use std::{
    io,
    os::unix::fs::PermissionsExt,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

struct InventoryCase {
    c: Case,
    next: Fresh,
    replacement: Proposal,
    retired: AnchorRetiredSubject,
    path: PathBuf,
    key: PathBuf,
    backup: PathBuf,
    identity: crate::JournalIdentity,
}
impl InventoryCase {
    fn capture(&self, path: &Path) -> Result<Cleanup, DurableError> {
        DeviceJournal::retired_cleanup_proposal(
            path,
            JournalKey::open(&self.key)?,
            self.identity,
            self.retired,
        )
    }
    fn proposal(&self) -> Cleanup {
        self.capture(&self.path).expect("actual original inventory")
    }
}

fn control_client(store: &Arc<Mutex<AnchorStore>>, pin: &AnchorPin) -> crate::AnchorClient {
    crate::AnchorClient::new(
        pin.clone(),
        DeviceSigningKey::deterministic([96; 32], [97; 32]).expect("original signer"),
        Box::new(InterruptedAdvance {
            store: Arc::clone(store),
            pin: pin.clone(),
            after: false,
            intercepted: Arc::new(AtomicBool::new(false)),
        }),
        Duration::from_secs(5),
    )
    .expect("original signed control client")
}

fn retain_inventory(
    c: &mut Case,
    replacement: &Proposal,
    path: &Path,
    key: &Path,
    identity: crate::JournalIdentity,
) -> (AnchorRetiredSubject, Cleanup) {
    let subject = c.genesis.subject();
    let wire = c
        .store
        .retired_subject_receipt(replacement, subject)
        .expect("permanent retirement receipt");
    let retired = c
        .pin
        .verify_retired_subject(replacement, subject, &wire)
        .expect("verified retirement");
    c.peer
        .responder
        .current_policy()
        .expect("old policy")
        .close();
    let before = rows(path);
    let proposal = DeviceJournal::retired_cleanup_proposal(
        path,
        JournalKey::open(key).expect("original key"),
        identity,
        retired,
    )
    .expect("original inventory after policy closure");
    assert!(proposal.pending_intent_digest().is_some());
    assert_eq!(
        proposal.pending_intent_digest(),
        Some(digest(
            b"Q-PERIAPT-CONTINUITY-RETIRED-LOCAL-INTENT/v1",
            before.1.as_ref().expect("complete original pending wire")
        ))
    );
    c.store
        .retain_retired_cleanup(&proposal)
        .expect("independent inventory retention");
    let receipt = c.store.retired_cleanup_receipt(&proposal).expect("receipt");
    assert_eq!(
        c.pin
            .verify_retired_cleanup(retired, &proposal, &receipt)
            .expect("verified original inventory")
            .proposal(),
        &proposal
    );
    assert_eq!(
        rows(path),
        before,
        "historical capture must preserve both rows"
    );
    assert_eq!(
        c.store
            .retired_subject_observation(replacement, subject)
            .expect("frozen whole witness entry"),
        retired
    );
    (retired, proposal)
}
struct InterruptedAdvance {
    store: Arc<Mutex<AnchorStore>>,
    pin: AnchorPin,
    after: bool,
    intercepted: Arc<AtomicBool>,
}
impl crate::AnchorTransport for InterruptedAdvance {
    fn exchange(&mut self, wire: &[u8], _: Instant) -> io::Result<Vec<u8>> {
        let request = incoming(&self.pin, wire).map_err(io::Error::other)?;
        let advance = matches!(request.operation.0, Command::Advance(..));
        if advance && !self.after {
            self.intercepted.store(true, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "original advance unprocessed",
            ));
        }
        let reply = self
            .store
            .lock()
            .map_err(|_| io::Error::other("witness lock"))?
            .handle(wire, 150)
            .map_err(io::Error::other)?;
        if advance {
            self.intercepted.store(true, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "committed reply lost",
            ));
        }
        Ok(reply)
    }
}
fn rows(path: &Path) -> (Vec<u8>, Option<Vec<u8>>) {
    let db = open_private_database(path).expect("original closed journal");
    let read = db.begin_read().expect("read");
    let table = read
        .open_table(TableDefinition::<&str, &[u8]>::new(
            "continuity_device_candidate_v21",
        ))
        .expect("journal table");
    let image = table
        .get("image")
        .expect("lookup")
        .expect("image")
        .value()
        .to_vec();
    let pending = table
        .get("pending")
        .expect("lookup")
        .map(|p| p.value().to_vec());
    (image, pending)
}
fn fixture(interruption: Option<bool>) -> InventoryCase {
    let mut c = required_case();
    let next = fresh(&c, 2, 2, 210);
    let identity = c._journal.identity().expect("original ID");
    c._journal.close();
    let root = c.server.parent().expect("root");
    let path = root.join("client/state.redb");
    let key = root.join("client/key");
    let backup_dir = root.join("before-intent");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&backup_dir)
        .expect("private backup directory");
    let backup = backup_dir.join("state.redb");
    fs::copy(&path, &backup).expect("closed original snapshot");
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).expect("private backup");
    if let Some(after) = interruption {
        c.store.close();
        let store = Arc::new(Mutex::new(reopen(&c.server)));
        let intercepted = Arc::new(AtomicBool::new(false));
        let client = crate::AnchorClient::new(
            c.pin.clone(),
            DeviceSigningKey::deterministic([96; 32], [97; 32]).expect("original fixture key"),
            Box::new(InterruptedAdvance {
                store: Arc::clone(&store),
                pin: c.pin.clone(),
                after,
                intercepted: Arc::clone(&intercepted),
            }),
            Duration::from_secs(5),
        )
        .expect("signed original client");
        let (policy, device, _) = c.peer.responder.inventory_inputs().expect("original");
        let mut journal = DeviceJournal::open_anchored(
            &path,
            JournalKey::open(&key).expect("key"),
            device,
            policy,
            identity,
            client,
        )
        .expect("actual active journal");
        let devices = c.peer.initiator.devices();
        let remote = devices.first().expect("initiator").roster();
        assert_ne!(remote.account_id(), device.account_id());
        assert!(matches!(
            journal.install_roster(remote, 150),
            Err(DurableError::Anchor(_))
        ));
        assert!(intercepted.load(Ordering::SeqCst));
        assert!(matches!(journal.identity(), Err(DurableError::Closed)));
        c.store = Arc::into_inner(store)
            .expect("exclusive controller")
            .into_inner()
            .expect("controller");
    }
    let replacement = first_proposal(&mut c, &next);
    commit(&mut c, &replacement, &next, 150).expect("retire actual frozen head");
    let wire = c
        .store
        .retired_subject_receipt(&replacement, c.genesis.subject())
        .expect("retirement proof");
    let retired = c
        .pin
        .verify_retired_subject(&replacement, c.genesis.subject(), &wire)
        .expect("verified permanent fact");
    InventoryCase {
        c,
        next,
        replacement,
        retired,
        path,
        key,
        backup,
        identity,
    }
}

#[test]
fn independently_bound_inventory_refuses_backup_omitting_original_pending_record() {
    let mut f = fixture(Some(false));
    let original_rows = rows(&f.path);
    let p = f.proposal();
    let missing = f
        .capture(&f.backup)
        .expect("same frozen image, different local inventory");
    assert_eq!(p.stored_image_digest(), missing.stored_image_digest());
    assert!(p.pending_intent_digest().is_some());
    assert!(missing.pending_intent_digest().is_none());
    assert_ne!(p.binding(), missing.binding());
    assert_eq!(
        f.c.store
            .retired_cleanup_status(&p)
            .expect("no bound inventory"),
        CleanupState::Unavailable
    );
    let before = f.c.store.image().expect("before").revision;
    assert_eq!(
        f.c.store
            .retain_retired_cleanup(&p)
            .expect("independent binding"),
        CleanupState::Retained
    );
    f.c.store.close();
    f.c.store = reopen(&f.c.server);
    f.c.peer.responder.current_policy().expect("policy").close();
    let restored = Cleanup::from_trusted_state(&p.to_bytes()).expect("original retained proposal");
    assert_eq!(
        f.c.store
            .retain_retired_cleanup(&restored)
            .expect("same original retry"),
        CleanupState::Retained
    );
    assert_eq!(f.c.store.image().expect("one commit").revision, before + 1);
    assert!(matches!(
        f.c.store.retain_retired_cleanup(&missing),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        f.c.store.retired_cleanup_status(&missing),
        Err(DurableError::Conflict)
    ));
    assert_eq!(rows(&f.path), original_rows);
    assert_eq!(
        f.c.store
            .retired_subject_observation(&f.replacement, f.retired.subject())
            .expect("unchanged frozen entry"),
        f.retired
    );
    assert_retired(&mut f.c, AnchorOperation::query());
    assert_eq!(query(&mut f.c, &f.next).outcome(), AnchorOutcome::Current);
    eprintln!("RETIRED_CLEANUP_INVENTORY actual_uncommitted_intent=true older_backup_same_image=true changed_inventory_conflicts=true old_entry_unchanged=true");
}

#[test]
fn capture_finds_actual_sealed_committed_target_without_applying_it() {
    let mut f = fixture(Some(true));
    let before = rows(&f.path);
    let p = f.proposal();
    assert_ne!(p.stored_image_digest(), f.retired.observed_head().digest());
    assert!(p.pending_intent_digest().is_some());
    assert!(matches!(f.capture(&f.backup), Err(DurableError::Conflict)));
    assert_eq!(
        rows(&f.path),
        before,
        "capture cannot apply or erase the original target"
    );
    f.c.store
        .retain_retired_cleanup(&p)
        .expect("exact committed-target inventory");
    assert_eq!(
        f.c.store
            .retired_subject_observation(&f.replacement, f.retired.subject())
            .expect("frozen head"),
        f.retired
    );
}

#[test]
fn historical_inventory_preserves_real_credential_targets_at_all_three_cuts() {
    use crate::AnchorCredentialRenewalState as RenewalState;
    for stage in 0..3 {
        let mut c = required_case();
        let original = c
            .peer
            .responder
            .inventory_inputs()
            .expect("original")
            .1
            .clone();
        let identity = c._journal.identity().expect("original identity");
        let path = c.server.parent().expect("root").join("client/state.redb");
        let key = c.server.parent().expect("root").join("client/key");
        let grant = credential_grant(&c, &original, 2, 240);
        c.store.close();
        let store = Arc::new(Mutex::new(reopen(&c.server)));
        let policy = c.peer.responder.current_policy().expect("current policy");
        c._journal
            .activate_anchor(&original, policy, control_client(&store, &c.pin))
            .expect("original journal activation");
        let proposal = c
            ._journal
            .prepare_local_credential_renewal(&original, &grant, grant.operation(), policy, 150)
            .expect("real sealed G target");
        assert!(matches!(c._journal.identity(), Err(DurableError::Closed)));
        assert_eq!(
            store
                .lock()
                .expect("controller")
                .prepare_credential_renewal(proposal, &grant, policy, 150)
                .expect("independent G approval"),
            RenewalState::Prepared
        );
        let prepared_rows = rows(&path);
        if stage > 0 {
            let request = AnchorRequest::new(
                &c.pin,
                c.genesis.subject(),
                AnchorOperation::commit_credential_renewal(&proposal),
                &c.peer.signer_r,
            )
            .expect("original G commit");
            let wire = store
                .lock()
                .expect("controller")
                .handle(request.as_bytes(), 150)
                .expect("actual G transaction");
            assert_eq!(
                c.pin
                    .verify_reply(&request, &wire)
                    .expect("signed G commit")
                    .credential_renewal_state(&proposal)
                    .expect("exact G"),
                RenewalState::Applied
            );
        }
        if stage == 2 {
            assert_eq!(
                DeviceJournal::recover_credential_renewal(
                    &path,
                    JournalKey::open(&key).expect("original key"),
                    &original,
                    policy,
                    identity,
                    proposal,
                    &mut control_client(&store, &c.pin)
                )
                .expect("install exact already committed target"),
                RenewalState::Applied
            );
        }
        let before = rows(&path);
        assert_eq!(
            before.1, prepared_rows.1,
            "full G intent survives target installation"
        );
        assert_eq!(before.0 == prepared_rows.0, stage != 2);
        c.store = Arc::into_inner(store)
            .expect("exclusive controller")
            .into_inner()
            .expect("lock");
        let next = fresh(&c, 2, 3, 212);
        let checkpoint = if stage == 0 {
            original.roster().checkpoint()
        } else {
            grant.successor_device().roster().checkpoint()
        };
        let subject = c.genesis.subject();
        let replacement = prepare(&mut c, &next, subject, checkpoint);
        commit(&mut c, &replacement, &next, 150).expect("replace at G cut");
        let (retired, cleanup) = retain_inventory(&mut c, &replacement, &path, &key, identity);
        assert_eq!(
            cleanup.stored_image_digest() == retired.observed_head().digest(),
            stage != 1
        );
        assert_eq!(rows(&path), before, "do not apply, close or erase G");
        for op in [
            AnchorOperation::commit_credential_renewal(&proposal),
            AnchorOperation::credential_renewal_status(&proposal),
            AnchorOperation::close_credential_renewal(&proposal),
            AnchorOperation::acknowledge_credential_renewal(&proposal),
        ] {
            assert_retired(&mut c, op);
        }
        assert_eq!(
            c.store
                .retired_subject_observation(&replacement, subject)
                .expect("G stays frozen"),
            retired
        );
    }
    eprintln!("RETIRED_CLEANUP_BOUND_CREDENTIAL stages=3 prepared=true witness_applied=true local_target_with_pending=true original_wire_preserved=true");
}

#[test]
fn historical_inventory_keeps_target_free_cancellation_and_refuses_omitting_backup() {
    for closed_at_witness in [false, true] {
        let mut c = required_case();
        let original = c
            .peer
            .responder
            .inventory_inputs()
            .expect("original")
            .1
            .clone();
        let identity = c._journal.identity().expect("original identity");
        c._journal.close();
        let root = c.server.parent().expect("root");
        let path = root.join("client/state.redb");
        let key = root.join("client/key");
        let backup_dir = root.join("before-cancellation");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&backup_dir)
            .expect("private directory");
        let backup = backup_dir.join("state.redb");
        fs::copy(&path, &backup).expect("original image before intent");
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).expect("private copy");
        let original_rows = rows(&path);
        let grant = credential_grant(&c, &original, 2, 240);
        let policy = c.peer.responder.current_policy().expect("policy");
        let cancellation = DeviceJournal::reserve_enrollment_credential_cancellation(
            &path,
            JournalKey::open(&key).expect("key"),
            &original,
            policy.historical(),
            identity,
            grant.historical(),
            None,
        )
        .expect("actual target-free cancellation reservation");
        let before = rows(&path);
        assert_eq!(before.0, original_rows.0, "reservation has no target image");
        let pending = before.1.as_ref().expect("full cancellation intent");
        assert_eq!(pending.len(), 320);
        assert_eq!(pending.get(..8), Some(b"QPWINT03".as_slice()));
        assert_eq!(
            pending.get(40..288),
            Some(cancellation.to_bytes().as_slice())
        );
        if closed_at_witness {
            assert_eq!(
                c.store
                    .close_unprepared_credential_renewal(cancellation, &grant, policy)
                    .expect("independent original cancellation"),
                crate::AnchorCredentialCancellationState::Closed
            );
        }
        let next = fresh(&c, 2, 3, 212);
        let replacement = first_proposal(&mut c, &next);
        commit(&mut c, &replacement, &next, 150).expect("retire with cancellation retained");
        let (retired, cleanup) = retain_inventory(&mut c, &replacement, &path, &key, identity);
        assert_eq!(
            cleanup.stored_image_digest(),
            retired.observed_head().digest()
        );
        let missing = DeviceJournal::retired_cleanup_proposal(
            &backup,
            JournalKey::open(&key).expect("key"),
            identity,
            retired,
        )
        .expect("same frozen image without local cancellation");
        assert_eq!(missing.stored_image_digest(), cleanup.stored_image_digest());
        assert!(missing.pending_intent_digest().is_none());
        assert_ne!(missing.binding(), cleanup.binding());
        assert!(matches!(
            c.store.retain_retired_cleanup(&missing),
            Err(DurableError::Conflict)
        ));
        for op in [
            AnchorOperation::credential_cancellation_status(&cancellation),
            AnchorOperation::acknowledge_credential_cancellation(&cancellation),
        ] {
            assert_retired(&mut c, op);
        }
        assert_eq!(rows(&path), before, "no target invention or intent removal");
        assert_eq!(
            c.store
                .retired_subject_observation(&replacement, c.genesis.subject())
                .expect("cancellation metadata frozen"),
            retired
        );
    }
    eprintln!("RETIRED_CLEANUP_CANCELLATION states=2 locally_reserved=true witness_closed=true target_free=true missing_intent_backup_conflicts=true");
}

#[test]
fn historical_inventory_preserves_real_policy_targets_at_all_three_cuts() {
    use crate::{AnchorPolicyRenewalState as PolicyState, PolicyRenewalMaterials};
    for stage in 0..3 {
        let mut c = required_case();
        let original = c
            .peer
            .responder
            .inventory_inputs()
            .expect("original")
            .1
            .clone();
        let identity = c._journal.identity().expect("original identity");
        let path = c.server.parent().expect("root").join("client/state.redb");
        let key = c.server.parent().expect("root").join("client/key");
        let (issuer, _, _, runtime) = crate::tests::session_policy_fixture_with_budget(
            &[PrekeyQuality::OneTimeBoth],
            crate::AnchorRequirement::required(&c.pin),
            crate::ApplicationSendBudget::new(1024).expect("budget"),
        );
        let issued = issuer
            .issue_session_policy(
                &runtime,
                crate::SessionPolicyParameters::new(
                    2,
                    Validity::new(100, 300).expect("validity"),
                    crate::AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                    crate::AnchorRequirement::required(&c.pin),
                    crate::ApplicationSendBudget::new(1024).expect("budget"),
                )
                .expect("parameters"),
            )
            .expect("signed target policy");
        let target = crate::PolicyPin::new(
            issuer.policy_family().expect("family"),
            issuer.public_key().expect("policy key"),
            issued.checkpoint(),
        )
        .expect("independent policy pin")
        .verify(issued.as_bytes(), runtime, 150)
        .expect("verified target policy");
        let policy = c.peer.responder.current_policy().expect("original policy");
        let scope = crate::PolicyRenewalScope {
            operation: crate::PolicyRenewalId::generate().expect("P operation"),
            journal: identity,
            original_owner: crate::bootstrap::storage_owner(&original),
            original_credential: original.credential_digest(),
            current_credential: original.credential_digest(),
            current_roster: original.roster().checkpoint(),
            original_policy: policy.checkpoint(),
            previous_policy: policy.checkpoint(),
            previous_authorization: None,
        };
        let materials = PolicyRenewalMaterials {
            original: policy.historical(),
            previous: policy.historical(),
            target: &target,
            original_device: &original,
            current_device: &original,
        };
        let statement =
            crate::PolicyRenewalStatement::new(&scope, &materials, 150).expect("exact P statement");
        let root = crate::RootSigningKey::deterministic([94; 32], [95; 32])
            .expect("original account authority");
        let approval = crate::VerifiedPolicyRenewal::verify(
            &root
                .approve_policy_renewal(&statement)
                .expect("account approval"),
            &issuer
                .approve_policy_renewal(&statement)
                .expect("policy approval"),
            &scope,
            &materials,
            150,
        )
        .expect("independently authenticated P");
        c.store.close();
        let store = Arc::new(Mutex::new(reopen(&c.server)));
        c._journal
            .activate_anchor(&original, policy, control_client(&store, &c.pin))
            .expect("original journal activation");
        let proposal = c
            ._journal
            .prepare_policy_renewal(&approval, &materials, 150)
            .expect("actual sealed policy-only target");
        assert!(matches!(c._journal.identity(), Err(DurableError::Closed)));
        assert_eq!(
            store
                .lock()
                .expect("controller")
                .prepare_policy_renewal(proposal, &approval, &materials, 150)
                .expect("independent P preparation"),
            PolicyState::Prepared
        );
        let prepared_rows = rows(&path);
        if stage > 0 {
            assert_eq!(
                control_client(&store, &c.pin)
                    .exchange(
                        c.genesis.subject(),
                        AnchorOperation::commit_policy_renewal(&proposal)
                    )
                    .expect("actual witness P commit")
                    .policy_renewal_state(&proposal)
                    .expect("original P result"),
                PolicyState::Applied
            );
        }
        if stage == 2 {
            assert_eq!(
                DeviceJournal::recover_policy_renewal(
                    &path,
                    JournalKey::open(&key).expect("key"),
                    &original,
                    policy.historical(),
                    identity,
                    proposal,
                    &mut control_client(&store, &c.pin)
                )
                .expect("install exact authenticated P target"),
                PolicyState::Applied
            );
        }
        let before = rows(&path);
        assert_eq!(
            before.1, prepared_rows.1,
            "full P intent survives target installation"
        );
        assert_eq!(before.0 == prepared_rows.0, stage != 2);
        c.store = Arc::into_inner(store)
            .expect("exclusive controller")
            .into_inner()
            .expect("lock");
        let replacement_policy = if stage == 0 { policy } else { &target };
        let next = fresh_with_policy(&c, replacement_policy, 2, 2, 212);
        let proofs = [(
            c.genesis.subject(),
            original.roster().checkpoint(),
            replacement_policy.historical(),
        )];
        let replacement = c
            .store
            .device_replacement_proposal(
                &next.genesis,
                &next.device,
                replacement_policy,
                &proofs,
                150,
            )
            .expect("replace using current policy lineage");
        c.store
            .replace_device(
                &replacement,
                &next.genesis,
                &next.device,
                replacement_policy,
                &proofs,
                150,
            )
            .expect("permanent retirement at P cut");
        let (retired, cleanup) = retain_inventory(&mut c, &replacement, &path, &key, identity);
        target.close();
        assert_eq!(
            cleanup.stored_image_digest() == retired.observed_head().digest(),
            stage != 1
        );
        assert_eq!(rows(&path), before, "do not apply, close or erase P");
        for op in [
            AnchorOperation::commit_policy_renewal(&proposal),
            AnchorOperation::policy_renewal_status(&proposal),
            AnchorOperation::close_policy_renewal(&proposal),
            AnchorOperation::acknowledge_policy_renewal(&proposal),
        ] {
            assert_retired(&mut c, op);
        }
        assert_eq!(
            c.store
                .retired_subject_observation(&replacement, c.genesis.subject())
                .expect("P stays frozen"),
            retired
        );
    }
    eprintln!("RETIRED_CLEANUP_BOUND_POLICY stages=3 prepared=true witness_applied=true local_target_with_pending=true original_wire_preserved=true");
}

#[test]
fn capture_requires_original_key_identity_scope_and_exclusive_lease() {
    let f = fixture(Some(false));
    let other = fixture(None);
    assert!(DeviceJournal::retired_cleanup_proposal(
        &f.path,
        JournalKey::open(&other.key).expect("different key"),
        f.identity,
        f.retired
    )
    .is_err());
    assert!(DeviceJournal::retired_cleanup_proposal(
        &f.path,
        JournalKey::open(&f.key).expect("key"),
        other.identity,
        f.retired
    )
    .is_err());
    assert!(DeviceJournal::retired_cleanup_proposal(
        &f.path,
        JournalKey::open(&f.key).expect("key"),
        f.identity,
        other.retired
    )
    .is_err());
    let lease = open_private_database(&f.path).expect("original exclusive lease");
    assert!(matches!(f.capture(&f.path), Err(DurableError::Database(_))));
    drop(lease);
    f.capture(&f.path).expect("original lease released");
}

#[test]
fn canonical_inventory_and_signed_retention_are_separate_from_operating_receipts() {
    let mut f = fixture(None);
    let p = f.proposal();
    let bytes = p.to_bytes();
    assert_eq!(bytes.len(), 313);
    for length in 0..bytes.len() {
        assert!(Cleanup::from_trusted_state(bytes.get(..length).expect("prefix")).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Cleanup::from_trusted_state(&extra).is_err());
    let mut absent_alias = bytes.clone();
    *absent_alias.last_mut().expect("absent pending padding") = 1;
    assert!(Cleanup::from_trusted_state(&absent_alias).is_err());
    assert!(matches!(
        f.c.store.retired_cleanup_receipt(&p),
        Err(DurableError::Absent)
    ));
    f.c.store.retain_retired_cleanup(&p).expect("retained");
    let wire =
        f.c.store
            .retired_cleanup_receipt(&p)
            .expect("purpose19 proof");
    assert_eq!(wire.len(), 3690);
    let observed =
        f.c.pin
            .verify_retired_cleanup(f.retired, &p, &wire)
            .expect("exact pinned inventory");
    assert_eq!(observed.proposal(), &p);
    for length in 0..wire.len() {
        assert!(f
            .c
            .pin
            .verify_retired_cleanup(f.retired, &p, wire.get(..length).expect("wire prefix"))
            .is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(f
        .c
        .pin
        .verify_retired_cleanup(f.retired, &p, &trailing)
        .is_err());
    let other = fixture(None);
    assert!(other
        .c
        .pin
        .verify_retired_cleanup(f.retired, &p, &wire)
        .is_err());
    // A valid signature cannot substitute a different original inventory or
    // retirement, even if it was issued by the same witness key.
    for offset in [8, 40, 72, 168, 200, 248] {
        let mut changed = bytes.clone();
        *changed.get_mut(offset).expect("bound field") ^= 1;
        let signature =
            f.c.store
                .active
                .as_ref()
                .expect("signer")
                .signer
                .sign(Purpose::AnchorRetiredCleanup, &changed)
                .expect("valid signature on other inventory");
        assert!(matches!(
            f.c.pin.verify_retired_cleanup(
                f.retired,
                &p,
                &envelope(&changed, &signature).expect("signed other inventory")
            ),
            Err(Error::Scope)
        ));
    }
    let ordinary = request(&f.c, AnchorOperation::query());
    assert!(f.c.pin.verify_reply(&ordinary, &wire).is_err());
    assert!(f
        .c
        .pin
        .verify_retired_subject(&f.replacement, f.retired.subject(), &wire)
        .is_err());
    for index in [4 + 313, 4 + 313 + 3309] {
        let mut invalid = wire.clone();
        *invalid.get_mut(index).expect("signature component") ^= 1;
        assert!(f
            .c
            .pin
            .verify_retired_cleanup(f.retired, &p, &invalid)
            .is_err());
    }
    let body = open_envelope(&wire).expect("body").0;
    let signature =
        f.c.store
            .active
            .as_ref()
            .expect("signer")
            .signer
            .sign(Purpose::AnchorRetirement, body)
            .expect("wrong purpose");
    assert!(f
        .c
        .pin
        .verify_retired_cleanup(f.retired, &p, &envelope(body, &signature).expect("wire"))
        .is_err());
}

#[test]
fn witness_v12_preserves_old_entry_and_rejects_authenticated_inventory_corruption() {
    let mut f = fixture(Some(false));
    let p = f.proposal();
    f.c.store
        .retain_retired_cleanup(&p)
        .expect("bind inventory");
    let image = f.c.store.image().expect("state");
    let active = f.c.store.active.as_ref().expect("owner");
    let wire = encode(&active.wrapping, &active.pin, &image).expect("v12");
    assert_eq!(wire.get(..8), Some(b"QPANC012".as_slice()));
    decode(&active.wrapping, &active.pin, &wire).expect("v12 roundtrip");
    let body = wire.get(..wire.len() - 32).expect("body");
    // A valid storage MAC cannot admit another subject ID, a missing replacement
    // decision, or a different frozen state. These are corrupt stored relations,
    // not a legitimate absent cleanup inventory.
    for offset in [
        body.len() - 345,
        body.len() - 313 + 40,
        body.len() - 313 + 168,
    ] {
        let mut changed = body.to_vec();
        *changed.get_mut(offset).expect("bound field") ^= 1;
        let mut auth = authenticator(&active.wrapping).expect("test MAC");
        auth.update(&changed);
        changed.extend_from_slice(&auth.finalize().into_bytes());
        assert!(matches!(
            decode(&active.wrapping, &active.pin, &changed),
            Err(DurableError::Corrupt)
        ));
    }
}

#[test]
fn every_cleanup_binding_sync_failure_reconciles_only_the_first_inventory() {
    let mut calibration = fixture(None);
    let p = calibration.proposal();
    let (_, count) = with_fault_database(&mut calibration.c, false);
    count.store(0, Ordering::SeqCst);
    calibration
        .c
        .store
        .retain_retired_cleanup(&p)
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut f = fixture(Some(false));
            let p = f.proposal();
            let before = f.c.store.image().expect("before").revision;
            let (remaining, _) = with_fault_database(&mut f.c, after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(f.c.store.retain_retired_cleanup(&p), after);
            assert!(f.c.store.active.is_none());
            f.c.store = reopen(&f.c.server);
            f.c.store
                .retain_retired_cleanup(&p)
                .expect("exact original reconciliation");
            assert_eq!(f.c.store.image().expect("one binding").revision, before + 1);
            assert_eq!(
                f.c.store
                    .retired_subject_observation(&f.replacement, f.retired.subject())
                    .expect("same frozen state"),
                f.retired
            );
            assert_retired(&mut f.c, AnchorOperation::query());
            assert_eq!(query(&mut f.c, &f.next).outcome(), AnchorOutcome::Current);
        }
    }
    eprintln!(
        "RETIRED_CLEANUP_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn cleanup_binding_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_RETIRED_CLEANUP_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let p = Cleanup::from_trusted_state(
        &fs::read(path.join("cleanup.bin")).expect("original cleanup request"),
    )
    .expect("canonical request");
    let mut store = reopen(path);
    store
        .retain_retired_cleanup(&p)
        .expect("independent binding");
    fs::write(path.join("cleanup-returned"), b"retained").expect("return marker");
}
#[test]
fn process_loss_after_cleanup_binding_keeps_original_inventory_without_old_runtime() {
    let mut f = fixture(Some(false));
    let p = f.proposal();
    let before = f.c.store.image().expect("before").revision;
    fs::write(f.c.server.join("cleanup.bin"), p.to_bytes())
        .expect("independently retained original request");
    f.c.store.close();
    let log = fs::File::create_new(f.c.server.join("cleanup-child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "anchor::store::tests::replacement::cleanup::cleanup_binding_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_RETIRED_CLEANUP_DIR", &f.c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &f.c.server)
            .env("QPERIAPT_ANCHOR_CRASH_REVISION", (before + 1).to_string())
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !f.c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "cleanup child deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!f.c.server.join("cleanup-returned").exists());
    child.0.kill().expect("kill after commit");
    assert!(!child.0.wait().expect("reap").success());
    f.c.store = reopen(&f.c.server);
    f.c.peer.responder.current_policy().expect("policy").close();
    f.c.store
        .retain_retired_cleanup(&p)
        .expect("same cleanup identity after process loss");
    assert_eq!(f.c.store.image().expect("one binding").revision, before + 1);
    let wrong = f.capture(&f.backup).expect("older local inventory");
    assert!(matches!(
        f.c.store.retain_retired_cleanup(&wrong),
        Err(DurableError::Conflict)
    ));
    eprintln!("RETIRED_CLEANUP_PROCESS commit_before_return=true exact_inventory_recovered=true older_backup_refused=true no_current_policy=true");
}

#[test]
fn actual_bound_roster_inventory_survives_prepared_applied_and_locally_installed_targets() {
    for stage in 0..3 {
        let mut c = required_case();
        let original = c
            .peer
            .responder
            .inventory_inputs()
            .expect("original")
            .1
            .clone();
        let subject = c.genesis.subject();
        let identity = c._journal.identity().expect("journal ID");
        let path = c.server.parent().expect("root").join("client/state.redb");
        let key = c.server.parent().expect("root").join("client/key");
        let (refreshed, _) = signed_device(&original, original.description.clone(), 2, 96, &[]);
        c.store.close();
        let store = Arc::new(Mutex::new(reopen(&c.server)));
        let clients = || {
            crate::AnchorClient::new(
                c.pin.clone(),
                DeviceSigningKey::deterministic([96; 32], [97; 32]).expect("original signer"),
                Box::new(InterruptedAdvance {
                    store: Arc::clone(&store),
                    pin: c.pin.clone(),
                    after: false,
                    intercepted: Arc::new(AtomicBool::new(false)),
                }),
                Duration::from_secs(5),
            )
            .expect("signed control carrier")
        };
        let policy = c.peer.responder.current_policy().expect("current policy");
        c._journal
            .activate_anchor(&original, policy, clients())
            .expect("original journal activation");
        let r = c
            ._journal
            .prepare_roster_refresh(
                crate::RosterRefreshId::generate().expect("original R ID"),
                &crate::RosterRefreshMaterials {
                    original: &original,
                    original_policy: policy.historical(),
                    policy,
                    target: &refreshed,
                },
                150,
            )
            .expect("real authenticated sealed R target");
        assert!(matches!(c._journal.identity(), Err(DurableError::Closed)));
        assert_eq!(
            store
                .lock()
                .expect("controller")
                .prepare_roster_refresh(r, &original, &refreshed, policy, 150)
                .expect("independent R approval"),
            crate::AnchorRosterRefreshState::Prepared
        );
        if stage > 0 {
            let req = AnchorRequest::new(
                &c.pin,
                subject,
                AnchorOperation::commit_roster_refresh(&r),
                &c.peer.signer_r,
            )
            .expect("original commit");
            let reply = store
                .lock()
                .expect("controller")
                .handle(req.as_bytes(), 150)
                .expect("real R commit");
            assert_eq!(
                c.pin
                    .verify_reply(&req, &reply)
                    .expect("signed commit")
                    .roster_refresh_state(&r)
                    .expect("typed result"),
                crate::AnchorRosterRefreshState::Applied
            );
        }
        if stage == 2 {
            assert_eq!(
                DeviceJournal::recover_roster_refresh(
                    &path,
                    JournalKey::open(&key).expect("key"),
                    &original,
                    policy.historical(),
                    identity,
                    r,
                    &mut clients()
                )
                .expect("install only original sealed target"),
                crate::AnchorRosterRefreshState::Applied
            );
        }
        c.store = Arc::into_inner(store)
            .expect("controller after journal closure")
            .into_inner()
            .expect("lock");
        let before = rows(&path);
        assert!(before.1.is_some());
        let next = fresh(&c, 2, 3, 212);
        let checkpoint = if stage == 0 {
            original.roster().checkpoint()
        } else {
            refreshed.roster().checkpoint()
        };
        let p = prepare(&mut c, &next, subject, checkpoint);
        commit(&mut c, &p, &next, 150).expect("replace while R metadata retained");
        let wire = c
            .store
            .retired_subject_receipt(&p, subject)
            .expect("retirement");
        let retired = c
            .pin
            .verify_retired_subject(&p, subject, &wire)
            .expect("pinned retirement");
        c.peer
            .responder
            .current_policy()
            .expect("old policy")
            .close();
        let cleanup = DeviceJournal::retired_cleanup_proposal(
            &path,
            JournalKey::open(&key).expect("key"),
            identity,
            retired,
        )
        .expect("historical-only complete R inventory");
        assert!(cleanup.pending_intent_digest().is_some());
        assert_eq!(
            cleanup.stored_image_digest() == retired.observed_head().digest(),
            stage != 1
        );
        c.store
            .retain_retired_cleanup(&cleanup)
            .expect("first R inventory retained");
        assert_eq!(
            rows(&path),
            before,
            "capture/binding cannot mutate or retire R"
        );
        for op in [
            AnchorOperation::commit_roster_refresh(&r),
            AnchorOperation::roster_refresh_status(&r),
            AnchorOperation::close_roster_refresh(&r),
            AnchorOperation::acknowledge_roster_refresh(&r),
        ] {
            assert_retired(&mut c, op);
        }
        assert_eq!(
            c.store
                .retired_subject_observation(&p, subject)
                .expect("unchanged entire frozen witness entry"),
            retired
        );
    }
    eprintln!("RETIRED_CLEANUP_BOUND_ROSTER stages=3 prepared=true witness_applied=true local_target_with_pending=true no_new_GPR_transition=true");
}
