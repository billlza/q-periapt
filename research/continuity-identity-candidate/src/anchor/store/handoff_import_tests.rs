// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "handoff_history_integration_tests.rs"]
mod history;
#[path = "handoff_import_recovery_tests.rs"]
mod recovery;
#[path = "handoff_retirement_tests.rs"]
mod retirement;
#[path = "handoff_import_validation_tests.rs"]
mod validation;

struct TargetFixture {
    now: u64,
    directory: PathBuf,
    plan: AnchorHandoffPlan,
    approval: AnchorHandoffTargetApproval,
    pin: AnchorPin,
    source: Vec<u8>,
    freeze: Vec<u8>,
}
impl TargetFixture {
    fn new(c: &mut Case) -> Self {
        Self::new_at(c, 150)
    }
    fn new_at(c: &mut Case, now: u64) -> Self {
        Self::with_legacy_plan(c, now, false)
    }
    fn with_legacy_plan(c: &mut Case, now: u64, legacy: bool) -> Self {
        let directory = c
            .server
            .parent()
            .expect("canonical owned root")
            .join("target-import");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .expect("target private directory");
        let wrapping = JournalKey::provision(&directory.join("wrapping"))
            .expect("independent target wrapping key");
        let signer =
            AnchorSigningKey::provision(&directory.join("signer"), &wrapping, target_key_id())
                .expect("target signer");
        let pin = AnchorPin::new(
            AnchorIdentity::generate().expect("target identity"),
            signer.public_key().expect("target public key"),
        );
        assert_ne!(pin.binding(), c.pin.binding());
        let source = c
            .store
            .handoff_source_state()
            .expect("complete original source");
        let plan = AnchorHandoffPlan::from_trusted_state(
            [212; 32],
            &source,
            pin.clone(),
            Validity::new(now - 10, now + 10).expect("source admission"),
            [213; 32],
        )
        .expect("source operator approval");
        let plan = if legacy {
            let mut bytes = plan.to_bytes();
            bytes.truncate(bytes.len().checked_sub(72).expect("v2 history context"));
            bytes
                .get_mut(..8)
                .expect("plan tag")
                .copy_from_slice(b"QPAHPL01");
            AnchorHandoffPlan::restore_trusted_state(&bytes).expect("original v1 approved plan")
        } else {
            plan
        };
        let approval = AnchorHandoffTargetApproval::from_trusted_state(
            &plan,
            &c.pin,
            &pin,
            Validity::new(now - 5, now + 5).expect("independent target admission"),
            [214; 32],
        )
        .expect("target operator approval");
        let freeze = c
            .store
            .freeze_handoff(&plan, now)
            .expect("source freeze committed");
        fs::write(
            directory.join("source-pin"),
            [
                c.pin.identity().as_bytes().as_slice(),
                &c.pin.public_key().encode(),
            ]
            .concat(),
        )
        .expect("independent public source pin");
        fs::write(
            directory.join("target-pin"),
            [
                pin.identity().as_bytes().as_slice(),
                &pin.public_key().encode(),
            ]
            .concat(),
        )
        .expect("independent target pin");
        fs::write(directory.join("approval"), approval.to_bytes()).expect("retained target intent");
        fs::write(directory.join("source"), source.as_bytes()).expect("original source bytes");
        fs::write(directory.join("freeze"), freeze.as_bytes()).expect("original freeze receipt");
        Self {
            now,
            directory,
            plan,
            approval,
            pin,
            source: source.as_bytes().to_vec(),
            freeze: freeze.as_bytes().to_vec(),
        }
    }
    fn key(&self) -> JournalKey {
        JournalKey::open(&self.directory.join("wrapping")).expect("target key")
    }
    fn signer(&self) -> AnchorSigningKey {
        AnchorSigningKey::open(&self.directory.join("signer"), &self.key(), target_key_id())
            .expect("target signer")
    }
    fn db_path(&self) -> PathBuf {
        self.directory.join("import.redb")
    }
    fn provision(&self) -> AnchorHandoffTarget {
        AnchorHandoffTarget::provision_import(
            &self.db_path(),
            self.key(),
            &self.signer(),
            self.approval.clone(),
            &self.source,
            &self.freeze,
            self.now,
        )
        .expect("complete inactive import")
    }
    fn open(&self) -> AnchorHandoffTarget {
        AnchorHandoffTarget::open(&self.db_path(), self.key(), self.approval.clone())
            .expect("same exact import")
    }
}
fn target_key_id() -> SigningKeyId {
    SigningKeyId::from_trusted_state([215; 32]).expect("target key identity")
}

// Used also by the actual pending-P/R fixtures. This imports their entire source
// image, not a reconstruction of selected fields or an empty replacement store.
pub(super) fn import_pending_then_cancel(c: &mut Case) {
    // G was prepared at170, P/R at150. Keep trusted fixture time monotonic
    // and admit transfer independently of the original client's expired grant.
    let fixture = TargetFixture::new_at(c, 175);
    let mut target = fixture.provision();
    assert_eq!(
        target
            .retained_source_state()
            .expect("complete pending state"),
        fixture.source
    );
    let cancel = c
        .store
        .cancel_handoff(&fixture.plan)
        .expect("source cancellation");
    target
        .close_cancelled(cancel.as_bytes())
        .expect("exact imported cancellation");
    target.close();
    let mut target = fixture.open();
    assert_eq!(
        target.status().expect("terminal imported state"),
        AnchorHandoffTargetState::Cancelled
    );
    assert_eq!(
        target
            .retained_source_state()
            .expect("original retained state after closure"),
        fixture.source
    );
}

#[test]
fn independent_import_preserves_original_commands_and_reopens_without_either_private_signer() {
    let mut c = case();
    let advance = request(
        &c,
        AnchorOperation::advance(initial(&c), [216; 32]).expect("original advance"),
    );
    let head = apply_request(&mut c, &advance)
        .applied_head()
        .expect("retained original head");
    let f = TargetFixture::new(&mut c);
    let restored =
        AnchorHandoffTargetApproval::restore_trusted_state(&f.approval.to_bytes(), &c.pin, &f.pin)
            .expect("independent retained approval");
    assert_eq!(restored.to_bytes(), f.approval.to_bytes());
    let mut target = f.provision();
    let receipt = target.import_receipt().expect("committed acknowledgement");
    assert_eq!(
        f.approval
            .verify_import_receipt(&f.freeze, receipt.as_bytes())
            .expect("target dual signature")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert!(f.plan.verify_receipt(receipt.as_bytes()).is_err());
    assert_eq!(
        target.status().expect("inactive only"),
        AnchorHandoffTargetState::ImportedInactive
    );
    assert_eq!(
        target.retained_source_state().expect("complete export"),
        f.source
    );
    assert!(matches!(
        c.store.handle(advance.as_bytes(), 150),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    assert!(target.close_cancelled(&f.freeze).is_err());
    assert!(target.close_cancelled(receipt.as_bytes()).is_err());
    target.close();
    assert!(
        AnchorStore::open(&f.db_path(), f.key(), f.signer(), f.pin.identity()).is_err(),
        "inactive import cannot be opened as an ordinary witness"
    );
    assert!(
        AnchorHandoffTarget::provision_import(
            &f.db_path(),
            f.key(),
            &f.signer(),
            f.approval.clone(),
            &f.source,
            &f.freeze,
            150
        )
        .is_err(),
        "never replace original import"
    );
    let cancel = c
        .store
        .cancel_handoff(&f.plan)
        .expect("trusted source cancel");
    let query = request(&c, AnchorOperation::query());
    assert_eq!(apply_request(&mut c, &query).observed_head(), head);
    c.store.close();
    fs::remove_file(c.server.join("signer")).expect("remove only fixture old signer");
    fs::remove_file(f.directory.join("signer")).expect("remove only fixture target signer");
    let mut target = f.open();
    assert_eq!(
        target
            .import_receipt()
            .expect("retained historical import without signing")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert_eq!(
        target
            .close_cancelled(cancel.as_bytes())
            .expect("source cancellation without private signers"),
        AnchorHandoffTargetState::Cancelled
    );
    assert_eq!(
        target
            .close_cancelled(cancel.as_bytes())
            .expect("exact closure retry"),
        AnchorHandoffTargetState::Cancelled
    );
    assert!(matches!(
        target.import_receipt(),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert_eq!(
        target
            .cancellation_receipt()
            .expect("exact retained terminal bytes"),
        cancel.as_bytes()
    );
    assert_eq!(
        target
            .retained_source_state()
            .expect("retained original history"),
        f.source
    );
    target.close();
    let mut target = f.open();
    assert_eq!(
        target.status().expect("terminal on reopen"),
        AnchorHandoffTargetState::Cancelled
    );
}

#[test]
fn import_rejects_unapproved_pins_expiry_changed_content_and_wrong_signer_before_publication() {
    let mut c = case();
    let f = TargetFixture::new(&mut c);
    assert!(AnchorHandoffTargetApproval::from_trusted_state(
        &f.plan,
        &f.pin,
        &c.pin,
        Validity::new(140, 160).expect("interval"),
        [217; 32]
    )
    .is_err());
    let wrong = AnchorSigningKey::generate().expect("unapproved target key");
    assert!(matches!(
        AnchorHandoffTarget::provision_import(
            &f.db_path(),
            f.key(),
            &wrong,
            f.approval.clone(),
            &f.source,
            &f.freeze,
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    for now in [144, 155, 160] {
        assert!(matches!(
            AnchorHandoffTarget::provision_import(
                &f.db_path(),
                f.key(),
                &f.signer(),
                f.approval.clone(),
                &f.source,
                &f.freeze,
                now
            ),
            Err(DurableError::Protocol(Error::Validity))
        ));
        assert!(!f.db_path().exists());
    }
    let mut changed = f.source.clone();
    *changed.last_mut().expect("source tail") ^= 1;
    assert!(AnchorHandoffTarget::provision_import(
        &f.db_path(),
        f.key(),
        &f.signer(),
        f.approval.clone(),
        &changed,
        &f.freeze,
        150
    )
    .is_err());
    let mut bad_signature = f.freeze.clone();
    *bad_signature.last_mut().expect("signature") ^= 1;
    assert!(AnchorHandoffTarget::provision_import(
        &f.db_path(),
        f.key(),
        &f.signer(),
        f.approval.clone(),
        &f.source,
        &bad_signature,
        150
    )
    .is_err());
    assert!(!f.db_path().exists());
    let mut target = f.provision();
    let before = target.import_receipt().expect("original receipt");
    target.close();
    let changed = AnchorHandoffTargetApproval::from_trusted_state(
        &f.plan,
        &c.pin,
        &f.pin,
        Validity::new(145, 155).expect("same validity"),
        [218; 32],
    )
    .expect("different retained decision");
    assert!(matches!(
        AnchorHandoffTarget::open(&f.db_path(), f.key(), changed),
        Err(DurableError::Conflict)
    ));
    let mut target = f.open();
    assert_eq!(
        target
            .import_receipt()
            .expect("unchanged exact original")
            .as_bytes(),
        before.as_bytes()
    );
    target.close();
    assert!(AnchorHandoffTarget::open(
        &f.directory.join("absent.redb"),
        f.key(),
        f.approval.clone()
    )
    .is_err());
    assert!(!f.directory.join("absent.redb").exists());
}

#[test]
fn actual_pending_credential_is_imported_with_original_head_and_proposal() {
    let mut c = credential_case();
    let grant = credential_grant_first(&c);
    let proposal = crate::AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        grant.operation(),
        grant.statement_digest(),
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [219; 32]).expect("target"),
    )
    .expect("original G");
    let policy = c.peer.responder.current_policy().expect("policy");
    c.store
        .prepare_credential_renewal(proposal, &grant, policy, 170)
        .expect("actual pending G");
    import_pending_then_cancel(&mut c);
    let policy = c.peer.responder.current_policy().expect("same policy");
    assert_eq!(
        c.store
            .close_credential_renewal(proposal, &grant, policy)
            .expect("same original G after cancelled import"),
        crate::AnchorCredentialRenewalState::Closed
    );
}

#[test]
fn corrupted_import_is_rejected_on_reopen_instead_of_recovering_with_default_state() {
    let mut c = case();
    let f = TargetFixture::new(&mut c);
    let mut target = f.provision();
    target.close();
    let db = open_private_database(&f.db_path()).expect("fixture corruption lease");
    const IMPORT: TableDefinition<&str, &[u8]> =
        TableDefinition::new("continuity_anchor_handoff_import_v1");
    let tx = transaction(&db).expect("owned corruption transaction");
    {
        let mut table = tx.open_table(IMPORT).expect("import table");
        let mut raw = table
            .get("image")
            .expect("lookup")
            .expect("image")
            .value()
            .to_vec();
        *raw.last_mut().expect("MAC") ^= 1;
        table
            .insert("image", raw.as_slice())
            .expect("test corruption");
    }
    tx.commit().expect("corruption committed");
    drop(db);
    assert!(matches!(
        AnchorHandoffTarget::open(&f.db_path(), f.key(), f.approval.clone()),
        Err(DurableError::Authentication)
    ));
}
