// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original-installation account cleanup and admission before recovery writes.
use super::*;
use crate::{FanoutAbandonmentId, InstallationRecovery, InstalledAccountRecovery};

pub(super) struct Managed {
    pub(super) service: crate::DeviceService,
    pub(super) receivers: Vec<DeviceJournal>,
    pub(super) f: Fixture,
    pub(super) sessions: Vec<[u8; 32]>,
    pub(super) paths: crate::InstallationPaths,
    pub(super) key_path: std::path::PathBuf,
    pub(super) root: std::path::PathBuf,
    _directories: Vec<tempfile::TempDir>,
}
impl Managed {
    pub(super) fn new(same_account: bool) -> Self {
        Self::with_fixture(fixture(4, same_account, None), |_, _, _| {
            Err(DurableError::AnchorRequired)
        })
    }
    pub(super) fn with_fixture(
        f: Fixture,
        mut enroll: impl FnMut(
            &crate::AnchorGenesis,
            &VerifiedDevice,
            &crate::VerifiedSessionPolicy,
        ) -> Result<crate::AnchorClient, DurableError>,
    ) -> Self {
        let sender_dir = directory();
        let root = canonical(&sender_dir);
        let paths = crate::InstallationPaths::new(
            &root.join("installation.redb"),
            &root.join("journal.redb"),
            &root.join("archives.redb"),
        )
        .expect("paths");
        let key_path = root.join("key");
        let key = JournalKey::provision(&key_path).expect("explicit original key");
        let policy = f
            .contexts
            .first()
            .expect("context")
            .current_policy()
            .expect("fixture policy owner");
        let mut installation =
            crate::DeviceInstallation::provision(paths.clone(), &key, &f.local, policy, 150)
                .expect("original installation");
        let preparation = installation
            .prepare(
                JournalKey::open(&key_path).expect("key"),
                &f.local,
                policy,
                150,
            )
            .expect("prepare");
        let anchor = match preparation {
            crate::InstallationPreparation::Local => None,
            crate::InstallationPreparation::RequiresEnrollment(genesis) => {
                Some(enroll(&genesis, &f.local, policy).expect("required witness enrollment"))
            }
        };
        let required = anchor.is_some();
        let mut service = installation
            .activate(key, &f.local, policy, 150, anchor)
            .expect("activate");
        let mut receivers = Vec::new();
        let mut receiver_dirs = Vec::new();
        let mut sessions = Vec::new();
        for (((context, device), signer), key) in f
            .contexts
            .iter()
            .zip(&f.peers)
            .zip(&f.peer_signers)
            .zip(&f.keys)
        {
            let dir = directory();
            let path = canonical(&dir);
            let mut receiver = if required {
                let mut journal = DeviceJournal::provision_anchored(
                    &path.join("state.redb"),
                    JournalKey::provision(&path.join("key")).expect("receiver wrapping key"),
                    device,
                    context.current_policy().expect("fixture policy owner"),
                    crate::durable::tests::retain_new_identity(&path.join("store-id")),
                    150,
                )
                .expect("original protected receiver");
                let genesis = journal
                    .anchor_genesis(
                        device,
                        context.current_policy().expect("fixture policy owner"),
                    )
                    .expect("receiver genesis");
                let client = enroll(
                    &genesis,
                    device,
                    context.current_policy().expect("fixture policy owner"),
                )
                .expect("required receiver enrollment");
                journal
                    .activate_anchor(
                        device,
                        context.current_policy().expect("fixture policy owner"),
                        client,
                    )
                    .expect("receiver enrollment");
                journal
            } else {
                new_store(&path, device)
            };
            let admitted = service
                .admit_peer(Arc::clone(context), crate::BootstrapRole::Initiator, 150)
                .expect("independently verified fresh peer under the original service");
            let context = admitted.context();
            let (journal, archives) = service.stores().expect("one shared journal");
            let initiation = InitiationId::generate().expect("initiation");
            let initial = journal
                .initiate(Arc::clone(context), initiation, &f.local_signer, 150)
                .expect("initiate");
            let reply = receiver
                .respond(
                    Arc::clone(context),
                    &initial,
                    signer,
                    PqKeySource::from_key(key),
                    TraditionalKeySource::from_key(key),
                    150,
                )
                .expect("respond");
            let completed = journal
                .accept_reply(Arc::clone(context), initiation, &reply, 150)
                .expect("reply");
            let session = completed.session_id();
            receiver
                .finish(
                    Arc::clone(context),
                    &initial,
                    completed.final_message(),
                    150,
                )
                .expect("finish");
            journal
                .activate_initiator_messages(Arc::clone(context), initiation, 150)
                .expect("sender");
            receiver
                .activate_responder_messages(Arc::clone(context), &initial, 150)
                .expect("receiver");
            let archive = journal
                .archive_session_closure(context, session)
                .expect("archive");
            archives
                .retain(journal, context, session, &archive)
                .expect("retain exact archive");
            sessions.push(session);
            receivers.push(receiver);
            receiver_dirs.push(dir);
        }
        receiver_dirs.push(sender_dir);
        Self {
            service,
            receivers,
            f,
            sessions,
            paths,
            key_path,
            root,
            _directories: receiver_dirs,
        }
    }

    pub(super) fn discover(&self) -> Result<InstallationRecovery, DurableError> {
        InstallationRecovery::open(
            self.paths.clone(),
            JournalKey::open(&self.key_path).expect("original wrapping key"),
        )
    }
    fn cleanup(&self, id: FanoutId) -> Result<InstalledAccountRecovery, DurableError> {
        self.discover()?.open_account(id, None)
    }
    fn reserve_with_pending_write(&mut self) -> FanoutId {
        let selected = targets(&self.f, &self.sessions);
        let (journal, _) = self.service.stores().expect("original service");
        let id = journal.next_fanout_id().expect("retain before dispatch");
        journal.close();
        let (db, remaining, count, _) =
            crate::durable::tests::fault_database_path(&self.root.join("journal.redb"), false);
        let key = JournalKey::open(&self.key_path).expect("same key");
        let owner = bootstrap::storage_owner(&self.f.local);
        let image = load(&db, &key, owner).expect("original authenticated state");
        assert_eq!(image.protection, Protection::Local);
        *journal = DeviceJournal {
            active: Some(Active {
                db,
                key,
                owner,
                id: image.id,
                protection: image.protection,
                anchor: None,
                account_authority: None,
                enrollment_completion: None,
            }),
        };
        // The existing real redb fault backend interrupts after the reservation
        // intent is durable, before its aggregate image is installed. The test
        // independently verifies this pending state; no public result is faked.
        remaining.store(3, Ordering::SeqCst);
        crate::durable::tests::assert_sync_failure(
            journal.send_account_message(
                FanoutInput {
                    id,
                    account: self
                        .f
                        .peers
                        .first()
                        .expect("recipient account")
                        .account_id(),
                    targets: &selected,
                    plaintext: b"original reserved account input",
                    associated_data: b"installed recovery",
                },
                150,
            ),
            false,
        );
        assert_eq!(count.load(Ordering::SeqCst), 3);
        self.service.close();
        let (_, pending) = self.snapshot();
        assert!(
            pending.is_some(),
            "the actual reservation intent must survive"
        );
        id
    }
    pub(super) fn snapshot(&self) -> ([u8; 32], Option<[u8; 32]>) {
        let db = open_private_database(&self.root.join("journal.redb")).expect("released journal");
        let key = JournalKey::open(&self.key_path).expect("original key");
        let owner = bootstrap::storage_owner(&self.f.local);
        let (image, pending) =
            write_intent::load_snapshot(&db, &key, owner).expect("authenticated state");
        (
            image.digest,
            pending.map(|value| {
                value
                    .authenticated_target(&key, owner)
                    .expect("sealed intent")
                    .digest
            }),
        )
    }
    pub(super) fn installation_scope(&self, replacement: Option<&[u8]>) -> Vec<u8> {
        const TABLE: redb::TableDefinition<&str, &[u8]> =
            redb::TableDefinition::new("continuity_installation_v1");
        let db = open_private_database(&self.root.join("installation.redb"))
            .expect("released configuration");
        let tx = db.begin_write().expect("fixture transaction");
        let original = {
            let mut table = tx.open_table(TABLE).expect("original table");
            let original = table
                .get("installation")
                .expect("read")
                .expect("row")
                .value()
                .to_vec();
            if let Some(bytes) = replacement {
                table
                    .insert("installation", bytes)
                    .expect("fixture scope replacement");
            }
            original
        };
        tx.commit().expect("fixture commit");
        original
    }
}

#[test]
fn installed_account_cleanup_retains_complete_loss_and_original_store_ownership() {
    for same_account in [false, true] {
        let mut c = Managed::new(same_account);
        let selected = targets(&c.f, &c.sessions);
        let (journal, _) = c.service.stores().expect("original service");
        let prior = journal.next_fanout_id().expect("prior account operation");
        let unknown = journal
            .send_account_message(
                FanoutInput {
                    id: prior,
                    account: c.f.peers.first().expect("account").account_id(),
                    targets: &selected,
                    plaintext: b"older unconfirmed delivery",
                    associated_data: b"prior",
                },
                150,
            )
            .expect("prior ciphertext committed but not acknowledged");
        let id = c.reserve_with_pending_write();
        c.f.contexts
            .first()
            .expect("policy")
            .current_policy()
            .expect("fixture policy owner")
            .close();
        c.f.local_signer.close();
        let mut owner = c
            .cleanup(id)
            .expect("original metadata-only recovery after policy close");
        assert!(matches!(
            c.discover(),
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        for file in ["journal.redb", "archives.redb"] {
            assert!(matches!(
                open_private_database(&c.root.join(file)),
                Err(PrivateDatabaseError::Busy)
            ));
        }
        let journal = owner.journal().expect("restricted aggregate journal");
        assert_eq!(
            journal.status().expect("reconciled reservation"),
            FanoutStatus::Reserved
        );
        let report = journal.begin().expect("freeze complete original set");
        assert_eq!(report.batch, id);
        assert_eq!(report.sessions.len(), 2);
        for (session, original) in report.sessions.iter().zip(&unknown) {
            assert_eq!(session.device, original.device);
            assert_eq!(session.session, original.session);
            assert_eq!(
                session.reserved.plaintext_bytes,
                b"original reserved account input".len()
            );
            assert_eq!(
                session.reserved.associated_data_bytes,
                b"installed recovery".len()
            );
            let epoch = session.epochs.first().expect("complete earlier epoch");
            assert_eq!(session.epochs.len(), 1);
            assert_eq!(epoch.acknowledged_before, 0);
            assert_eq!(epoch.sent, 1);
            assert_eq!(epoch.unconfirmed.len(), 1);
            assert_eq!(
                epoch
                    .unconfirmed
                    .first()
                    .expect("original unknown")
                    .message_id(),
                original.message
            );
        }
        assert_eq!(journal.begin().expect("immutable report"), report);
        assert!(matches!(
            journal.acknowledge(
                FanoutAbandonmentId::from_trusted_state([7; 32]).expect("wrong report")
            ),
            Err(DurableError::Conflict)
        ));
        owner.close();
        assert!(matches!(owner.journal(), Err(DurableError::Closed)));
        let mut restored = c.cleanup(id).expect("same original frozen batch");
        let journal = restored.journal().expect("restricted journal");
        assert_eq!(journal.begin().expect("same whole report"), report);
        abandonment::account(&c.root, &report);
        journal
            .acknowledge(report.report)
            .expect("host retained all loss metadata");
        journal
            .acknowledge(report.report)
            .expect("exact acknowledgement is idempotent");
        assert_eq!(
            journal.status().expect("terminal aggregate"),
            FanoutStatus::Abandoned(report.report)
        );
        assert!(matches!(
            journal.begin(),
            Err(DurableError::Protocol(Error::Retired))
        ));
        restored.close();
        let mut terminal = c
            .cleanup(id)
            .expect("terminal member bindings still authenticate");
        let journal = terminal.journal().expect("terminal journal");
        assert_eq!(
            journal.status().expect("exact original report"),
            FanoutStatus::Abandoned(report.report)
        );
        journal
            .retire_metadata()
            .expect("explicit aggregate metadata retirement");
        journal
            .retire_metadata()
            .expect("known local retirement is idempotent");
        assert_eq!(
            journal.status().expect("retired metadata"),
            FanoutStatus::Retired
        );
        terminal.close();
        assert!(matches!(
            c.cleanup(id),
            Err(DurableError::Protocol(Error::Retired))
        ));
        c.discover()
            .expect("all original store leases released")
            .close();
    }
}

#[test]
fn installed_account_rejects_wrong_installation_before_resolving_pending_writes() {
    let mut c = Managed::new(false);
    let id = c.reserve_with_pending_write();
    let before = c.snapshot();
    let original = c.installation_scope(None);
    let mut changed = original.clone();
    let owner = changed
        .get_mut(40..72)
        .expect("retained installation owner");
    *owner.first_mut().expect("owner byte") ^= 1;
    c.installation_scope(Some(&changed));
    assert!(matches!(c.cleanup(id), Err(DurableError::Conflict)));
    assert_eq!(
        c.snapshot(),
        before,
        "scope refusal must precede recovery writes"
    );
    c.installation_scope(Some(&original));
    let mut restored = c
        .cleanup(id)
        .expect("original authority can reconcile exact intent");
    assert_eq!(
        restored
            .journal()
            .expect("journal")
            .status()
            .expect("reservation"),
        FanoutStatus::Reserved
    );
    restored.close();
    assert!(c.snapshot().1.is_none());
}

#[test]
fn installed_account_absence_is_bound_to_original_installation() {
    let mut c = Managed::new(false);
    let id = c
        .service
        .stores()
        .expect("service")
        .0
        .next_fanout_id()
        .expect("unreserved original ID");
    c.service.close();
    let before = c.snapshot();
    let original = c.installation_scope(None);
    let mut changed = original.clone();
    *changed.get_mut(40).expect("retained owner") ^= 1;
    c.installation_scope(Some(&changed));
    assert!(matches!(c.cleanup(id), Err(DurableError::Conflict)));
    assert_eq!(c.snapshot(), before);
    c.installation_scope(Some(&original));
    assert!(matches!(c.cleanup(id), Err(DurableError::Absent)));
    c.discover()
        .expect("failed selections release original leases")
        .close();
}

#[test]
fn installed_account_missing_member_archive_cannot_reconcile_a_subset() {
    const TABLE: redb::TableDefinition<&[u8; 32], &[u8]> =
        redb::TableDefinition::new("continuity_session_archives_v1");
    let mut c = Managed::new(false);
    let id = c.reserve_with_pending_write();
    let before = c.snapshot();
    let selected = c
        .sessions
        .last()
        .expect("second independently credentialed member");
    let removed = {
        let db = open_private_database(&c.root.join("archives.redb")).expect("released index");
        let tx = db.begin_write().expect("fixture loss");
        let bytes = tx
            .open_table(TABLE)
            .expect("index")
            .remove(selected)
            .expect("remove")
            .expect("original archive")
            .value()
            .to_vec();
        tx.commit().expect("observed missing row");
        bytes
    };
    assert!(matches!(c.cleanup(id), Err(DurableError::ArchiveRequired)));
    assert_eq!(
        c.snapshot(),
        before,
        "complete archive checks precede any recovery write"
    );
    {
        let db = open_private_database(&c.root.join("archives.redb"))
            .expect("failed owner released index");
        let tx = db.begin_write().expect("restore original fixture bytes");
        tx.open_table(TABLE)
            .expect("index")
            .insert(selected, removed.as_slice())
            .expect("exact original archive");
        tx.commit().expect("fixture restore");
    }
    let mut restored = c.cleanup(id).expect("complete original archive set");
    assert_eq!(
        restored
            .journal()
            .expect("journal")
            .begin()
            .expect("complete report")
            .sessions
            .len(),
        2
    );
}
