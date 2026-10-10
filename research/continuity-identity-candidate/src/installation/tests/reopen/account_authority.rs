// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityIdentity, AccountAuthorityStore, ApplicationAccountId, JournalAccountAuthority,
};

pub(super) fn registry(
    c: &Anchored,
    name: &str,
) -> (AccountAuthorityStore, JournalAccountAuthority) {
    let mut registry = AccountAuthorityStore::provision(
        &c.root.join(name),
        JournalKey::provision(&c.root.join(format!("{name}-key"))).expect("separate key"),
        AccountAuthorityIdentity::generate().expect("independent identity"),
        c.peer.initiator.current_policy().expect("policy").family(),
        c.pin.clone(),
    )
    .expect("independent registry");
    let local = registry
        .associate(
            ApplicationAccountId::from_trusted_state([201; 32]).expect("local application"),
            c.peer.initiator_device(),
        )
        .expect("independent local association");
    registry
        .associate(
            ApplicationAccountId::from_trusted_state([202; 32]).expect("peer application"),
            c.peer.local_device(),
        )
        .expect("independent peer association");
    let authority = JournalAccountAuthority::new(registry.access().expect("owner"), local)
        .expect("original live descriptor");
    (registry, authority)
}

fn request(c: &Anchored, session: [u8; 32]) -> SessionReopenRequest {
    c.peer
        .bundle
        .request_reopen(
            c.peer.policy_owner(BootstrapRole::Initiator),
            c.peer.bundle_requirements(PrekeyQuality::OneTimeBoth),
            BootstrapRole::Initiator,
            session,
            150,
        )
        .expect("original authenticated public session")
}

pub(super) fn bind(c: &Anchored, authority: JournalAccountAuthority) {
    let mut service = c
        .activate(open(&c.root, &c.peer))
        .expect("original service");
    service
        .stores()
        .expect("original stores")
        .0
        .adopt_account_authority(authority)
        .expect("explicit witnessed binding");
    service.close();
}

fn reopen(
    c: &Anchored,
    session: [u8; 32],
    authority: JournalAccountAuthority,
) -> Result<ReopenedSession, DurableError> {
    DeviceInstallation::reopen_session(
        paths(&c.root),
        key(&c.root),
        request(c, session),
        150,
        InstallationAdmission::managed(c.client(), authority),
    )
}

#[test]
fn managed_installation_initial_activation_and_exact_reopen_share_original_binding() {
    let c = Anchored::new();
    let owner = c.prepare();
    let (mut registry, authority) = registry(&c, "registry");
    let device = c.peer.initiator_device();
    let policy = c.peer.initiator.current_policy().expect("policy");
    let mut service = owner
        .activate(
            key(&c.root),
            device,
            policy,
            150,
            InstallationAdmission::managed(c.client(), authority.clone()),
        )
        .expect("genesis checked before initial managed activation");
    let identity = service
        .stores()
        .expect("stores")
        .0
        .identity()
        .expect("identity");
    service.close();
    assert!(matches!(
        c.activate(open(&c.root, &c.peer)),
        Err(DurableError::Conflict)
    ));
    let mut service = open(&c.root, &c.peer)
        .activate(
            key(&c.root),
            device,
            policy,
            150,
            InstallationAdmission::managed(c.client(), authority),
        )
        .expect("same original descriptor");
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("identity"),
        identity
    );
    registry.close();
    assert!(matches!(
        service
            .stores()
            .expect("exclusive owners")
            .0
            .check_installation_state(device, policy, false),
        Err(DurableError::Closed)
    ));
    service.close();
}

#[test]
fn managed_installation_session_reopen_does_not_adopt_an_unbound_journal() {
    let c = Anchored::new();
    let (session, _) = super::super::recovery::anchored_session(&c);
    let (_registry, authority) = registry(&c, "registry");
    assert!(matches!(
        reopen(&c, session, authority),
        Err(DurableError::Conflict)
    ));
    DeviceInstallation::reopen_session(
        paths(&c.root),
        key(&c.root),
        request(&c, session),
        150,
        Some(c.client()),
    )
    .expect("refused managed reopen leaves unbound original usable");
}

#[test]
fn managed_installation_reopen_refuses_missing_wrong_or_closed_registry_before_dispatch() {
    let c = Anchored::new();
    let (session, _) = super::super::recovery::anchored_session(&c);
    let (mut registry, authority) = registry(&c, "registry");
    bind(&c, authority.clone());
    let (_other, wrong) = self::registry(&c, "other");
    c.server.lock().expect("witness").calls = 0;
    assert!(matches!(
        DeviceInstallation::reopen_session(
            paths(&c.root),
            key(&c.root),
            request(&c, session),
            150,
            Some(c.client()),
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        reopen(&c, session, wrong),
        Err(DurableError::Conflict)
    ));
    assert_eq!(c.server.lock().expect("witness").calls, 0);
    reopen(&c, session, authority.clone()).expect("original remains recoverable");
    registry.close();
    c.server.lock().expect("witness").calls = 0;
    assert!(matches!(
        reopen(&c, session, authority),
        Err(DurableError::Closed)
    ));
    assert_eq!(c.server.lock().expect("witness").calls, 0);
}

#[test]
fn managed_installation_restores_exact_outbox_and_closes_cached_release_with_registry() {
    let c = Anchored::new();
    let (session, archive) = super::super::recovery::anchored_session(&c);
    let (mut registry, authority) = registry(&c, "registry");
    bind(&c, authority.clone());
    let (mut service, context) = reopen(&c, session, authority.clone())
        .expect("original session")
        .into_parts();
    let (journal, index) = service.stores().expect("original owners");
    index
        .require(journal, &context, session)
        .expect("same original archive");
    assert_eq!(
        journal
            .archive_session_closure(&context, session)
            .expect("archive")
            .as_bytes(),
        archive.as_bytes()
    );
    let id = journal
        .next_message_id(&context, session, 150)
        .expect("original session slot");
    let wire = journal
        .send_message(&context, session, id, b"managed original", b"recovery", 150)
        .expect("real committed outbox");
    service.close();
    let reopened = reopen(&c, session, authority).expect("exact reopen again");
    assert_eq!(reopened.session_id(), session);
    let (mut service, context) = reopened.into_parts();
    let journal = service.stores().expect("stores").0;
    assert_eq!(
        journal
            .resume_message(&context, session, id, 150)
            .expect("exact original wire"),
        wire
    );
    registry.close();
    assert!(matches!(
        journal.resume_message(&context, session, id, 150),
        Err(DurableError::Closed)
    ));
    service.close();
}

#[test]
fn managed_installation_closure_after_signed_witness_reply_withholds_reopened_owner() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    struct ClosingCarrier {
        inner: Carrier,
        registry: Arc<Mutex<AccountAuthorityStore>>,
        called: Arc<AtomicBool>,
    }
    impl crate::AnchorTransport for ClosingCarrier {
        fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
            let reply = self.inner.exchange(request, deadline)?;
            if !self.called.swap(true, Ordering::SeqCst) {
                self.registry.lock().expect("original registry").close();
            }
            Ok(reply)
        }
    }
    let c = Anchored::new();
    let (session, _) = super::super::recovery::anchored_session(&c);
    let (registry, authority) = registry(&c, "registry");
    bind(&c, authority.clone());
    let called = Arc::new(AtomicBool::new(false));
    let registry = Arc::new(Mutex::new(registry));
    let client = AnchorClient::new(
        c.pin.clone(),
        crate::DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("original signer"),
        Box::new(ClosingCarrier {
            inner: Carrier(Arc::clone(&c.server)),
            registry,
            called: Arc::clone(&called),
        }),
        Duration::from_secs(10),
    )
    .expect("original signed witness transport");
    assert!(matches!(
        DeviceInstallation::reopen_session(
            paths(&c.root),
            key(&c.root),
            request(&c, session),
            150,
            InstallationAdmission::managed(client, authority),
        ),
        Err(DurableError::Closed)
    ));
    assert!(
        called.load(Ordering::SeqCst),
        "actual signed witness reply preceded closure"
    );
}
