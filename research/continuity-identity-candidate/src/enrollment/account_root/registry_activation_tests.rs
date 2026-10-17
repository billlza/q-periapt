// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityIdentity, AccountAuthorityStore, ApplicationAccountId, JournalAccountAuthority,
};

fn registry(
    f: &Fixture,
    account: &Account,
    name: &str,
    id: u8,
) -> (AccountAuthorityStore, JournalAccountAuthority) {
    let root = f
        ._dir
        .path()
        .canonicalize()
        .expect("owned canonical fixture");
    let mut registry = AccountAuthorityStore::provision(
        &root.join(name),
        JournalKey::provision(&root.join(format!("{name}-key"))).expect("separate original key"),
        AccountAuthorityIdentity::generate().expect("original identity"),
        f.policy.family(),
        f.pin.clone(),
    )
    .expect("registry");
    let checkpoint = registry
        .associate(
            ApplicationAccountId::from_trusted_state([id; 32]).expect("application"),
            &account.device,
        )
        .expect("independent root association");
    let authority = JournalAccountAuthority::new(registry.access().expect("owner"), checkpoint)
        .expect("current original descriptor");
    (registry, authority)
}
fn activate(
    f: &Fixture,
    account: &Account,
    authority: JournalAccountAuthority,
) -> Result<EnrolledDevice, DurableError> {
    let mut enrollment = DeviceEnrollment::open(account.paths.clone(), account.intent.clone())?
        .with_account_authority(authority)?;
    let client = enrollment.anchor_client(
        &f.policy,
        150,
        f.pin.clone(),
        Box::new(Carrier(Arc::clone(&f.witness))),
        Duration::from_secs(3),
    )?;
    enrollment.activate(&f.policy, 150, Some(client))
}

#[test]
fn managed_enrollment_first_activation_binds_before_release_and_reopens_the_exact_original() {
    let f = fixture();
    f.witness
        .lock()
        .expect("witness")
        .enroll(&f.target.genesis, &f.target.device, &f.policy, 150)
        .expect("independent target enrollment");
    let (mut registry, authority) = registry(&f, &f.target, "target-registry", 82);
    let mut owner = activate(&f, &f.target, authority.clone())
        .expect("initial Creating installation with registry admission");
    let original = owner
        .parts()
        .expect("owner")
        .0
        .stores()
        .expect("service")
        .0
        .identity()
        .expect("original journal");
    owner
        .next_prekey_publication_id()
        .expect("controlled owner");
    owner.close();
    assert!(matches!(
        f.activate_account(&f.target),
        Err(DurableError::Conflict)
    ));
    let mut owner =
        activate(&f, &f.target, authority).expect("same independently retained descriptor");
    assert_eq!(
        owner
            .parts()
            .expect("owner")
            .0
            .stores()
            .expect("service")
            .0
            .identity()
            .expect("same journal"),
        original
    );
    owner.close();
    registry.close();
    eprintln!("MANAGED_ENROLLMENT_INITIAL creating=true binding_before_owner=true exact_reopen=true missing_registry_refused=true");
}

#[test]
fn managed_enrollment_rejects_another_registry_without_replacing_the_original_binding() {
    let f = fixture();
    let (mut first, authority) = registry(&f, &f.original, "first-registry", 83);
    let (mut other, wrong) = registry(&f, &f.original, "other-registry", 83);
    let mut owner = activate(&f, &f.original, authority.clone()).expect("original binding");
    owner.close();
    assert!(matches!(
        activate(&f, &f.original, wrong),
        Err(DurableError::Conflict)
    ));
    let mut owner =
        activate(&f, &f.original, authority.clone()).expect("original remains recoverable");
    first.close();
    assert!(matches!(
        owner
            .parts()
            .expect("original outer owner")
            .0
            .stores()
            .expect("original service")
            .0
            .adopt_account_authority(authority),
        Err(DurableError::Closed)
    ));
    assert!(matches!(
        owner.next_prekey_publication_id(),
        Err(DurableError::Closed)
    ));
    owner.close();
    other.close();
}

#[test]
fn managed_enrollment_replays_real_publication_and_refuses_cached_release_after_registry_close() {
    use crate::{
        Cancellation, LeafKind, PrekeyPublicationKey as Key, PrekeyPublicationPlan,
        PrekeyPublicationRun,
    };
    let f = fixture();
    let (mut registry, authority) = registry(&f, &f.original, "publication-registry", 84);
    let mut owner = activate(&f, &f.original, authority.clone()).expect("bound owner");
    let interval = Validity::new(100, 200).expect("signed interval");
    let plan = PrekeyPublicationPlan::new(
        [85; 32],
        interval,
        &[
            Key::generate(LeafKind::SignedClassical, interval),
            Key::generate(LeafKind::OneTimeClassical, interval),
            Key::generate(LeafKind::LastResortPq, interval),
            Key::generate(LeafKind::OneTimePq, interval),
        ],
    )
    .expect("actual key generation plan");
    let id = owner
        .next_prekey_publication_id()
        .expect("original publication identity");
    let cancel = Cancellation::default();
    let run = || PrekeyPublicationRun {
        cancel: &cancel,
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let first = owner
        .prepare_prekey_publication(id, &plan, &f.policy, run(), || Ok(150))
        .expect("real owned key and signature publication");
    owner.close();
    let mut owner = activate(&f, &f.original, authority).expect("same original managed owner");
    let retry = owner
        .prepare_prekey_publication(id, &plan, &f.policy, run(), || Ok(150))
        .expect("exact original publication");
    assert_eq!(first.as_bytes(), retry.as_bytes());
    registry.close();
    assert!(
        matches!(
            owner.prepare_prekey_publication(id, &plan, &f.policy, run(), || Ok(150)),
            Err(crate::PrekeyPublicationError::Durable(DurableError::Closed))
        ),
        "a cached artifact does not bypass its original registry lifetime"
    );
    owner.close();
}

#[test]
fn managed_enrollment_registry_closure_after_a_real_witness_reply_withholds_the_owner() {
    use std::sync::atomic::AtomicBool;
    struct ClosingCarrier {
        inner: Carrier,
        registry: Arc<Mutex<AccountAuthorityStore>>,
        called: Arc<AtomicBool>,
    }
    impl AnchorTransport for ClosingCarrier {
        fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
            let reply = self.inner.exchange(request, deadline)?;
            if !self.called.swap(true, Ordering::SeqCst) {
                self.registry.lock().expect("original registry").close();
            }
            Ok(reply)
        }
    }
    let f = fixture();
    let (registry, authority) = registry(&f, &f.original, "late-close-registry", 87);
    activate(&f, &f.original, authority.clone())
        .expect("already bound original journal")
        .close();
    let registry = Arc::new(Mutex::new(registry));
    let called = Arc::new(AtomicBool::new(false));
    let mut owner = DeviceEnrollment::open(f.original.paths.clone(), f.original.intent.clone())
        .expect("same original enrollment")
        .with_account_authority(authority)
        .expect("current original descriptor before I/O");
    let client = owner
        .anchor_client(
            &f.policy,
            150,
            f.pin.clone(),
            Box::new(ClosingCarrier {
                inner: Carrier(Arc::clone(&f.witness)),
                registry: Arc::clone(&registry),
                called: Arc::clone(&called),
            }),
            Duration::from_secs(3),
        )
        .expect("real signed witness client");
    assert!(matches!(
        owner.activate(&f.policy, 150, Some(client)),
        Err(DurableError::Closed)
    ));
    assert!(
        called.load(Ordering::SeqCst),
        "closure occurs after actual witness evaluation"
    );
}

fn initial_sync_cut(cut: usize, after: bool) -> usize {
    let f = fixture();
    f.witness
        .lock()
        .expect("witness")
        .enroll(&f.target.genesis, &f.target.device, &f.policy, 150)
        .expect("target enrollment");
    let (mut registry, authority) = registry(&f, &f.target, "fault-registry", 88);
    let mut enrollment = DeviceEnrollment::open(f.target.paths.clone(), f.target.intent.clone())
        .expect("original Creating configuration")
        .with_account_authority(authority.clone())
        .expect("original approved descriptor");
    let client = enrollment
        .anchor_client(
            &f.policy,
            150,
            f.pin.clone(),
            Box::new(Carrier(Arc::clone(&f.witness))),
            Duration::from_secs(3),
        )
        .expect("original client");
    let (remaining, count) = fault_parent(&mut enrollment, after);
    count.store(0, Ordering::SeqCst);
    remaining.store(cut, Ordering::SeqCst);
    let result = enrollment.activate(&f.policy, 150, Some(client));
    let barriers = count.load(Ordering::SeqCst);
    if cut == 0 {
        result.expect("calibrate actual parent commits").close();
    } else {
        crate::durable::tests::assert_sync_failure(result, after);
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
    }
    let mut recovered = activate(&f, &f.target, authority)
        .expect("same original descriptor reconciles uncertain activation");
    let identity = recovered
        .parts()
        .expect("owner")
        .0
        .stores()
        .expect("service")
        .0
        .identity()
        .expect("original identity");
    assert_eq!(
        crate::AnchorSubject::for_device(identity, &f.target.device, &f.policy)
            .expect("same scope"),
        f.target.genesis.subject()
    );
    recovered.close();
    assert!(matches!(
        f.activate_account(&f.target),
        Err(DurableError::Conflict)
    ));
    registry.close();
    barriers
}
#[test]
fn managed_enrollment_initial_sync_faults_recover_the_original_binding_without_an_early_owner() {
    let barriers = initial_sync_cut(0, false);
    assert!((2..=12).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            initial_sync_cut(cut, after);
        }
    }
    eprintln!("MANAGED_ENROLLMENT_INITIAL_SYNC barriers={barriers} faults={} original_identity=true required_registry_retained=true",barriers*2);
}

#[test]
fn managed_enrollment_ordinary_activation_refuses_a_registry_bound_journal_without_its_descriptor()
{
    let f = fixture();
    let root = f
        ._dir
        .path()
        .canonicalize()
        .expect("owned canonical fixture");
    let mut registry = AccountAuthorityStore::provision(
        &root.join("registry"),
        JournalKey::provision(&root.join("registry-key")).expect("original wrapping key"),
        AccountAuthorityIdentity::generate().expect("original identity"),
        f.policy.family(),
        f.pin.clone(),
    )
    .expect("registry");
    let expected = registry
        .associate(
            ApplicationAccountId::from_trusted_state([81; 32]).expect("application"),
            &f.original.device,
        )
        .expect("independent application association");
    let authority =
        JournalAccountAuthority::new(registry.access().expect("original owner"), expected)
            .expect("exact original admission");
    let mut current = f.activate();
    current
        .parts()
        .expect("controlled owner")
        .0
        .stores()
        .expect("original service")
        .0
        .adopt_account_authority(authority)
        .expect("real witnessed binding");
    current
        .next_prekey_publication_id()
        .expect("original owner remains usable");
    current.close();
    assert!(
        matches!(f.activate_account(&f.original), Err(DurableError::Conflict)),
        "ordinary activation must not bypass the required original registry"
    );
    registry.close();
    eprintln!("MANAGED_ENROLLMENT_BASELINE initial_owner=true witnessed_registry_binding=true ordinary_reopen=Conflict");
}
