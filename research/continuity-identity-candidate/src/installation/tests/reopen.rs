// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture_with_public_validity, AccountPin, BootstrapRole, MessageId,
    ReopenedSession, RootSigningKey, SessionReopenRequest, Validity, VerifiedRoster,
};

struct Local {
    _directory: tempfile::TempDir,
    root: PathBuf,
    f: Fixture,
    session: [u8; 32],
    service: DeviceService,
    _peer_directory: tempfile::TempDir,
    peer: DeviceJournal,
    original_id: MessageId,
    role: BootstrapRole,
}
impl Local {
    fn new(short_roster: bool) -> Self {
        Self::with_role(short_roster, BootstrapRole::Initiator)
    }
    fn with_role(short_roster: bool, role: BootstrapRole) -> Self {
        let short = Validity::new(100, 160).expect("advertisement");
        let f = fixture_with_public_validity(
            PrekeyQuality::OneTimeBoth,
            if short_roster {
                short
            } else {
                crate::tests::interval()
            },
            short,
        );
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        drop(JournalKey::provision(&root.join("key")).expect("key"));
        let device = f.initiator.device(role);
        let policy = f.initiator.policy();
        let mut owner =
            DeviceInstallation::provision(paths(&root), &key(&root), device, policy, 150)
                .expect("installation");
        owner
            .prepare(key(&root), device, policy, 150)
            .expect("prepare");
        let mut service = owner
            .activate(key(&root), device, policy, 150, None)
            .expect("activate");
        let peer_dir = directory();
        let peer_role = match role {
            BootstrapRole::Initiator => BootstrapRole::Responder,
            BootstrapRole::Responder => BootstrapRole::Initiator,
        };
        let mut peer = crate::durable::tests::new_store(
            &peer_dir.path().canonicalize().expect("peer path"),
            f.initiator.device(peer_role),
        );
        let (journal, archives) = service.stores().expect("stores");
        let (ji, jr) = match role {
            BootstrapRole::Initiator => (&mut *journal, &mut peer),
            BootstrapRole::Responder => (&mut peer, &mut *journal),
        };
        let request = InitiationId::generate().expect("bootstrap ID");
        let initial = ji
            .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
            .expect("initial");
        let (pq, classical) = f.sources();
        let reply = jr
            .respond(
                Arc::clone(&f.responder),
                &initial,
                &f.signer_r,
                pq,
                classical,
                150,
            )
            .expect("reply");
        let completed = ji
            .accept_reply(Arc::clone(&f.initiator), request, &reply, 150)
            .expect("final");
        let session = completed.session_id();
        jr.finish(
            Arc::clone(&f.responder),
            &initial,
            completed.final_message(),
            150,
        )
        .expect("confirmation");
        ji.activate_initiator_messages(Arc::clone(&f.initiator), request, 150)
            .expect("initiator messages");
        jr.activate_responder_messages(Arc::clone(&f.responder), &initial, 150)
            .expect("responder messages");
        let archive = journal
            .archive_session_closure(&f.initiator, session)
            .expect("archive");
        archives
            .retain(journal, &f.initiator, session, &archive)
            .expect("retained archive");
        let original_id = journal
            .next_message_id(&f.initiator, session, 150)
            .expect("original ID");
        journal
            .send_message(
                &f.initiator,
                session,
                original_id,
                b"unconfirmed original",
                b"recovery",
                150,
            )
            .expect("outbox");
        Self {
            _directory: dir,
            root,
            f,
            session,
            service,
            _peer_directory: peer_dir,
            peer,
            original_id,
            role,
        }
    }
    fn request(&self, session: [u8; 32], role: BootstrapRole, now: u64) -> SessionReopenRequest {
        self.f
            .bundle
            .request_reopen(
                self.f.policy_owner(BootstrapRole::Initiator),
                self.f.bundle_requirements(PrekeyQuality::OneTimeBoth),
                role,
                session,
                now,
            )
            .expect("historical snapshot; no operational authority")
    }
    fn reopen(&self) -> Result<ReopenedSession, DurableError> {
        DeviceInstallation::reopen_session(
            paths(&self.root),
            key(&self.root),
            self.request(self.session, self.role, 170),
            170,
            None,
        )
    }
    fn update(&mut self, role: BootstrapRole, keep: bool) {
        let device = self.f.initiator.device(role);
        let seed = match role {
            BootstrapRole::Initiator => 90,
            BootstrapRole::Responder => 94,
        };
        let roster = update(device, seed, keep);
        self.service
            .stores()
            .expect("stores")
            .0
            .install_roster(&roster, 150)
            .expect("independent current authority");
    }
}
fn update(device: &VerifiedDevice, seed: u8, keep: bool) -> VerifiedRoster {
    let root = RootSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("root");
    let certificate = root
        .issue_device(device.description.clone(), device.key.clone())
        .expect("credential");
    let members = if keep {
        vec![root.roster_entry(&certificate).expect("entry")]
    } else {
        Vec::new()
    };
    let roster = root
        .issue_roster(2, crate::tests::interval(), &members)
        .expect("roster");
    AccountPin::new(
        device.account_id(),
        root.public_key().expect("public"),
        roster.checkpoint(),
        device.description.family,
    )
    .expect("pin")
    .verify_roster(roster.as_bytes(), 150)
    .expect("verified")
}

#[test]
fn established_session_reopens_after_public_advertisement_expiry() {
    let mut c = Local::new(false);
    let original_context = c.f.initiator.digest();
    let (journal, _) = c.service.stores().expect("stores");
    let next = journal
        .next_message_id(&c.f.initiator, c.session, 170)
        .expect("existing session remains admitted after prekey expiry");
    let original_id = c.original_id;
    let original_wire = journal
        .resume_message(&c.f.initiator, c.session, original_id, 170)
        .expect("original durable outbox");
    c.service.close();
    assert!(matches!(
        c.f.bundle.verify(
            c.f.policy_owner(BootstrapRole::Initiator),
            c.f.bundle_requirements(PrekeyQuality::OneTimeBoth),
            170
        ),
        Err(Error::Validity)
    ));
    for _ in 0..2 {
        let reopened = c.reopen().expect("restore the same admitted session");
        assert_eq!(reopened.session_id(), c.session);
        assert_eq!(reopened.role(), BootstrapRole::Initiator);
        assert!(matches!(
            c.reopen(),
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        let (mut service, context) = reopened.into_parts();
        assert_eq!(context.digest(), original_context);
        let (journal, _) = service.stores().expect("same owned engines");
        assert_eq!(
            journal
                .next_message_id(&context, c.session, 170)
                .expect("same next slot"),
            next
        );
        assert_eq!(
            journal
                .resume_message(&context, c.session, original_id, 170)
                .expect("exact replay"),
            original_wire
        );
        assert!(matches!(
            journal.initiate(
                Arc::clone(&context),
                InitiationId::generate().expect("new ID"),
                &c.f.signer_i,
                170
            ),
            Err(DurableError::Protocol(Error::Validity))
        ));
        service.close();
        assert!(matches!(service.stores(), Err(DurableError::Closed)));
    }
}

#[test]
fn reopen_uses_current_rosters_without_changing_original_context() {
    let mut c = Local::new(true);
    c.update(BootstrapRole::Initiator, true);
    c.update(BootstrapRole::Responder, true);
    c.service.close();
    assert!(matches!(
        DeviceInstallation::open(
            paths(&c.root),
            &key(&c.root),
            c.f.initiator_device(),
            c.f.initiator.policy(),
            170
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let reopened = c
        .reopen()
        .expect("current durable authority admits old snapshot identity");
    let (mut service, context) = reopened.into_parts();
    assert_eq!(context.digest(), c.f.initiator.digest());
    service
        .stores()
        .expect("stores")
        .0
        .next_message_id(&context, c.session, 170)
        .expect("live session");
}

#[test]
fn reopen_cannot_revive_expired_or_revoked_current_membership() {
    for revoked in [
        None,
        Some(BootstrapRole::Initiator),
        Some(BootstrapRole::Responder),
    ] {
        let mut c = Local::new(true);
        if let Some(role) = revoked {
            c.update(BootstrapRole::Initiator, role != BootstrapRole::Initiator);
            c.update(BootstrapRole::Responder, role != BootstrapRole::Responder);
        }
        c.service.close();
        let error = c.reopen().err().expect("no restored owner");
        assert!(matches!(
            error,
            DurableError::Protocol(Error::Validity | Error::Scope)
        ));
        assert_eq!(
            open(&c.root, &c.f)
                .status()
                .expect("lease released on refusal"),
            InstallationStatus::Active
        );
    }
}

#[test]
fn reopen_rejects_wrong_session_role_key_and_missing_children() {
    let mut c = Local::new(false);
    c.service.close();
    for (session, role) in [
        ([79; 32], BootstrapRole::Initiator),
        (c.session, BootstrapRole::Responder),
    ] {
        assert!(DeviceInstallation::reopen_session(
            paths(&c.root),
            key(&c.root),
            c.request(session, role, 170),
            170,
            None
        )
        .is_err());
    }
    let other = JournalKey::provision(&c.root.join("other-key")).expect("different key");
    assert!(matches!(
        DeviceInstallation::reopen_session(
            paths(&c.root),
            other,
            c.request(c.session, BootstrapRole::Initiator, 170),
            170,
            None
        ),
        Err(DurableError::Conflict)
    ));
    for leaf in ["installation.redb", "state.redb", "archives.redb"] {
        let saved = c.root.join(format!("retained-{leaf}"));
        fs::rename(c.root.join(leaf), &saved).expect("retain missing child");
        assert!(c.reopen().is_err());
        assert!(
            !c.root.join(leaf).exists(),
            "restore must not create {leaf}"
        );
        fs::rename(saved, c.root.join(leaf)).expect("restore fixture");
    }
    c.reopen()
        .expect("failed attempts retain exact usable original state");
}

#[test]
fn reopen_rechecks_policy_runtime_time_and_session_closure() {
    for closed_runtime in [false, true] {
        let mut c = Local::new(false);
        let request = c.request(c.session, BootstrapRole::Initiator, 170);
        c.service.close();
        let policy = c.f.policy_owner(BootstrapRole::Initiator);
        if closed_runtime {
            policy.runtime.close();
        } else {
            policy.close();
        }
        assert!(DeviceInstallation::reopen_session(
            paths(&c.root),
            key(&c.root),
            request,
            170,
            None
        )
        .is_err());
    }
    let mut c = Local::new(false);
    let request = c.request(c.session, BootstrapRole::Initiator, 170);
    c.service.close();
    assert!(matches!(
        DeviceInstallation::reopen_session(paths(&c.root), key(&c.root), request, 200, None),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let (mut service, context) = c.reopen().expect("live time").into_parts();
    service
        .stores()
        .expect("stores")
        .0
        .begin_session_closure(&context, c.session)
        .expect("freeze session");
    service.close();
    assert!(matches!(c.reopen(), Err(DurableError::Suspended)));
}

#[test]
fn reopen_never_activates_creating_installation() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    drop(JournalKey::provision(&root.join("key")).expect("key"));
    let mut owner = create(&root, &f);
    owner.close();
    let request = f
        .bundle
        .request_reopen(
            f.policy_owner(BootstrapRole::Initiator),
            f.bundle_requirements(PrekeyQuality::OneTimeBoth),
            BootstrapRole::Initiator,
            [78; 32],
            150,
        )
        .expect("snapshot");
    assert!(matches!(
        DeviceInstallation::reopen_session(paths(&root), key(&root), request, 150, None),
        Err(DurableError::Conflict)
    ));
    assert!(!paths(&root).journal.exists() && !paths(&root).archives.exists());
    assert_eq!(
        open(&root, &f).status().expect("unchanged"),
        InstallationStatus::Creating
    );
}

#[test]
fn restored_owners_continue_exact_delivery_and_acknowledgement_in_both_roles() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let mut c = Local::with_role(false, role);
        let original_wire = c
            .service
            .stores()
            .expect("stores")
            .0
            .resume_message(&c.f.initiator, c.session, c.original_id, 150)
            .expect("original wire");
        c.service.close();
        let reopened = c.reopen().expect("restore original local role");
        assert_eq!(reopened.role(), role);
        let (mut service, context) = reopened.into_parts();
        let (journal, _) = service.stores().expect("stores");
        let wire = journal
            .resume_message(&context, c.session, c.original_id, 170)
            .expect("exact retained wire");
        assert_eq!(wire, original_wire);
        let plaintext = c
            .peer
            .receive_message(&c.f.responder, c.session, &wire, b"recovery", 170)
            .expect("peer authenticate");
        assert_eq!(plaintext.as_bytes(), b"unconfirmed original");
        c.peer
            .consume_message(&c.f.responder, c.session, plaintext.message_id(), 170)
            .expect("peer consume");
        let ack = c
            .peer
            .message_acknowledgement(&c.f.responder, c.session, 170)
            .expect("durable receipt");
        journal
            .accept_message_acknowledgement(&context, c.session, &ack, 170)
            .expect("receipt admitted");
        let id = journal
            .next_message_id(&context, c.session, 170)
            .expect("next durable slot");
        assert_ne!(id, c.original_id);
        let second = journal
            .send_message(&context, c.session, id, b"after restart", b"recovery", 170)
            .expect("fresh message after restart");
        assert_eq!(
            c.peer
                .receive_message(&c.f.responder, c.session, &second, b"recovery", 170)
                .expect("peer readback")
                .as_bytes(),
            b"after restart"
        );
    }
}

#[test]
fn reopened_session_requires_fresh_witness_at_every_release_boundary() {
    let c = Anchored::new();
    let (session, _) = super::recovery::anchored_session(&c);
    let request = || {
        c.peer
            .bundle
            .request_reopen(
                c.peer.policy_owner(BootstrapRole::Initiator),
                c.peer.bundle_requirements(PrekeyQuality::OneTimeBoth),
                BootstrapRole::Initiator,
                session,
                150,
            )
            .expect("same public identity")
    };
    assert!(matches!(
        DeviceInstallation::reopen_session(paths(&c.root), key(&c.root), request(), 150, None),
        Err(DurableError::AnchorRequired)
    ));
    let other = Anchored::new();
    assert!(matches!(
        DeviceInstallation::reopen_session(
            paths(&c.root),
            key(&c.root),
            request(),
            150,
            Some(other.client())
        ),
        Err(DurableError::Conflict)
    ));
    c.server.lock().expect("witness").calls = 0;
    drop(
        DeviceInstallation::reopen_session(
            paths(&c.root),
            key(&c.root),
            request(),
            150,
            Some(c.client()),
        )
        .expect("fresh witness"),
    );
    let calls = c.server.lock().expect("witness").calls;
    assert!((2..=8).contains(&calls), "observed witness checks: {calls}");
    for cut in 1..=calls {
        for after in [false, true] {
            {
                let mut server = c.server.lock().expect("witness");
                server.calls = 0;
                server.fail = Some((cut, after));
            }
            assert!(
                DeviceInstallation::reopen_session(
                    paths(&c.root),
                    key(&c.root),
                    request(),
                    150,
                    Some(c.client())
                )
                .is_err(),
                "lost witness exchange {cut} after={after}"
            );
            c.server.lock().expect("witness").fail = None;
            drop(
                DeviceInstallation::reopen_session(
                    paths(&c.root),
                    key(&c.root),
                    request(),
                    150,
                    Some(c.client()),
                )
                .expect("exact original state after lost query"),
            );
        }
    }
}

#[test]
fn reopen_requires_the_original_session_archive_even_when_index_is_valid() {
    let mut c = Local::new(false);
    c.service.close();
    let identity = open(&c.root, &c.f).identity().expect("original lineage");
    let index = paths(&c.root).archives;
    let saved = c.root.join("retained-original-index");
    fs::rename(&index, &saved).expect("retain index");
    drop(SessionArchiveStore::provision(&index, identity).expect("valid but empty index"));
    assert!(matches!(c.reopen(), Err(DurableError::Absent)));
    fs::rename(&index, c.root.join("empty-index")).expect("retain empty index");
    fs::rename(saved, index).expect("restore original index");
    c.reopen().expect("original matching archive");
}
