// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::Fixture, CredentialRenewalAuthorization, CredentialRenewalMaterials,
    DeviceInstallation, DeviceService, InstallationPaths, InstallationPreparation,
};

pub(crate) fn grant(
    root: &RootSigningKey,
    origin: &[u8],
    previous: &VerifiedDevice,
    until: u64,
    version: u64,
    operation: [u8; 32],
    policy_digest: [u8; 32],
) -> VerifiedCredentialRenewal {
    let predecessor = root
        .issue_device(previous.description.clone(), previous.key.clone())
        .expect("same predecessor body");
    let mut description = previous.description.clone();
    description.validity =
        Validity::new(description.validity.from(), until).expect("extended interval");
    let successor = root
        .issue_device(description, previous.key.clone())
        .expect("same complete signing key");
    let roster = root
        .issue_roster(
            version,
            interval(),
            &[root.roster_entry(&successor).expect("member")],
        )
        .expect("target roster");
    let pin = AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root"),
        roster.checkpoint(),
        previous.description.family,
    )
    .expect("independent current pin");
    let authorization = CredentialRenewalAuthorization {
        operation: CredentialRenewalId::from_trusted_state(operation).expect("original operation"),
        previous: previous.roster().checkpoint(),
        policy_digest,
    };
    let issued = root
        .issue_credential_renewal(
            CredentialRenewalMaterials {
                original_credential: origin,
                previous_credential: &predecessor,
                successor_credential: &successor,
                previous_roster: previous.roster().as_bytes(),
                successor_roster: roster.as_bytes(),
            },
            &authorization,
            &pin,
            150,
        )
        .expect("explicit root continuation grant");
    VerifiedCredentialRenewal::verify(issued.as_bytes(), &pin, policy_digest, 150)
        .expect("independent grant verification")
}
fn paths(path: &Path) -> InstallationPaths {
    InstallationPaths::new(
        &path.join("installation.redb"),
        &path.join("state.redb"),
        &path.join("archives.redb"),
    )
    .expect("original paths")
}
fn create_service(path: &Path, f: &Fixture) -> DeviceService {
    let policy = f.initiator.policy();
    let device = f.initiator_device();
    let key = JournalKey::provision(&path.join("key")).expect("explicit first wrapping owner");
    let mut installation = DeviceInstallation::provision(paths(path), &key, device, policy, 150)
        .expect("original installation");
    assert!(matches!(
        installation
            .prepare(key, device, policy, 150)
            .expect("prepare"),
        InstallationPreparation::Local
    ));
    installation
        .activate(
            JournalKey::open(&path.join("key")).expect("original key"),
            device,
            policy,
            150,
            None,
        )
        .expect("original service")
}
fn reopen_service(path: &Path, f: &Fixture) -> DeviceService {
    let key = JournalKey::open(&path.join("key")).expect("original key");
    let policy = f.initiator.policy();
    let device = f.initiator_device();
    DeviceInstallation::open(paths(path), &key, device, policy, 150)
        .expect("original installation")
        .activate(key, device, policy, 150, None)
        .expect("original service")
}
fn peer(f: &Fixture) -> &VerifiedDevice {
    f.responder.device(crate::BootstrapRole::Responder)
}

#[test]
fn peer_renewal_is_atomic_exact_retry_preserves_owner_and_history_stays_constant() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let root = RootSigningKey::deterministic([94; 32], [95; 32]).expect("peer root");
    let original = root
        .issue_device(peer(&f).description.clone(), peer(&f).key.clone())
        .expect("original credential");
    let first = grant(
        &root,
        &original,
        peer(&f),
        300,
        2,
        [71; 32],
        f.initiator.policy().checkpoint().digest(),
    );
    let folder = directory();
    let path = folder.path().canonicalize().expect("path");
    let mut service = create_service(&path, &f);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(peer(&f).roster(), 150)
        .expect("original peer roster");
    let before = service
        .stores()
        .expect("stores")
        .0
        .image()
        .expect("original image");
    assert!(matches!(
        service
            .stores()
            .expect("stores")
            .0
            .install_roster(first.successor_device().roster(), 150),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    assert!(matches!(
        service.admit_peer_credential_renewal(
            &first,
            CredentialRenewalId::from_trusted_state([72; 32]).expect("other request"),
            f.initiator.policy(),
            150
        ),
        Err(DurableError::Conflict)
    ));
    let target = first.successor_device().roster().checkpoint();
    assert_eq!(
        service
            .admit_peer_credential_renewal(&first, first.operation(), f.initiator.policy(), 150)
            .expect("commit explicit grant"),
        target
    );
    let committed = service
        .stores()
        .expect("stores")
        .0
        .image()
        .expect("committed image");
    assert_eq!(committed.owner, before.owner);
    assert_eq!(committed.id, before.id);
    assert_eq!(committed.revision, before.revision + 1);
    let saved = get(&committed, &peer(&f).account_id()).expect("current authority");
    assert_eq!(saved.renewals.len(), 1);
    assert_eq!(
        saved
            .renewals
            .get(&peer(&f).device_id())
            .expect("original grant")
            .as_bytes(),
        first.as_bytes()
    );
    let payload_size = saved.record().expect("bounded encoding").payload.len();
    service.close();
    let mut service = reopen_service(&path, &f);
    assert_eq!(
        service
            .admit_peer_credential_renewal(&first, first.operation(), f.initiator.policy(), 150)
            .expect("original readback after reopen"),
        target
    );
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .image()
            .expect("readback")
            .revision,
        committed.revision
    );
    let other_operation = grant(
        &root,
        &original,
        peer(&f),
        300,
        2,
        [73; 32],
        f.initiator.policy().checkpoint().digest(),
    );
    assert!(matches!(
        service.admit_peer_credential_renewal(
            &other_operation,
            other_operation.operation(),
            f.initiator.policy(),
            150
        ),
        Err(DurableError::Conflict)
    ));
    let second = grant(
        &root,
        &original,
        first.successor_device(),
        400,
        3,
        [74; 32],
        f.initiator.policy().checkpoint().digest(),
    );
    service
        .admit_peer_credential_renewal(&second, second.operation(), f.initiator.policy(), 150)
        .expect("next exact predecessor");
    let image = service
        .stores()
        .expect("stores")
        .0
        .image()
        .expect("second image");
    let saved = get(&image, &peer(&f).account_id()).expect("same authority");
    assert_eq!(
        saved.renewals.len(),
        1,
        "one current grant, no appended renewal history"
    );
    assert_eq!(
        saved.record().expect("bounded encoding").payload.len(),
        payload_size
    );
    assert_eq!(
        saved
            .renewals
            .get(&peer(&f).device_id())
            .expect("new current grant")
            .statement_digest(),
        second.statement_digest()
    );
    let revoked = update(second.successor_device(), 94, 4, false);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(&revoked, 150)
        .expect("observed revocation");
    let late = grant(
        &root,
        &original,
        second.successor_device(),
        500,
        5,
        [75; 32],
        f.initiator.policy().checkpoint().digest(),
    );
    assert!(matches!(
        service.admit_peer_credential_renewal(&late, late.operation(), f.initiator.policy(), 150),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .roster_checkpoint(peer(&f).account_id())
            .expect("revoked head"),
        revoked.checkpoint()
    );
}

#[test]
fn peer_entry_cannot_replace_local_identity_or_cross_the_installation_policy() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let path = folder.path().canonicalize().expect("path");
    let mut service = create_service(&path, &f);
    let root = RootSigningKey::deterministic([90; 32], [91; 32]).expect("local root");
    let local = f.initiator_device();
    let mut other_origin = local.description.clone();
    other_origin.validity = Validity::new(100, 160).expect("another valid original credential");
    let original = root
        .issue_device(other_origin, local.key.clone())
        .expect("other origin");
    let renewal = grant(
        &root,
        &original,
        local,
        300,
        2,
        [81; 32],
        f.initiator.policy().checkpoint().digest(),
    );
    assert_ne!(
        renewal.original_storage_owner(),
        bootstrap::storage_owner(local)
    );
    assert!(matches!(
        service.admit_peer_credential_renewal(
            &renewal,
            renewal.operation(),
            f.initiator.policy(),
            150
        ),
        Err(DurableError::Conflict)
    ));
    let other = crate::bootstrap::tests::fixture_with_send_budget(
        PrekeyQuality::OneTimeBoth,
        crate::ApplicationSendBudget::new(17).expect("other policy"),
    );
    assert_eq!(
        other.initiator.policy().family(),
        f.initiator.policy().family()
    );
    assert_ne!(
        other.initiator.policy().checkpoint(),
        f.initiator.policy().checkpoint()
    );
    let root = RootSigningKey::deterministic([94; 32], [95; 32]).expect("peer root");
    let original = root
        .issue_device(peer(&f).description.clone(), peer(&f).key.clone())
        .expect("original");
    let renewal = grant(
        &root,
        &original,
        peer(&f),
        300,
        2,
        [82; 32],
        other.initiator.policy().checkpoint().digest(),
    );
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(peer(&f).roster(), 150)
        .expect("original peer");
    let before = service
        .stores()
        .expect("stores")
        .0
        .image()
        .expect("original image")
        .digest;
    assert!(matches!(
        service.admit_peer_credential_renewal(
            &renewal,
            renewal.operation(),
            other.initiator.policy(),
            150
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .image()
            .expect("unchanged image")
            .digest,
        before
    );
}

#[test]
fn every_peer_renewal_sync_cut_recovers_only_the_original_exact_operation() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let root = RootSigningKey::deterministic([94; 32], [95; 32]).expect("peer root");
    let original = root
        .issue_device(peer(&f).description.clone(), peer(&f).key.clone())
        .expect("original");
    let renewal = grant(
        &root,
        &original,
        peer(&f),
        300,
        2,
        [91; 32],
        f.initiator.policy().checkpoint().digest(),
    );
    let authority = crate::RetainedInstallationAuthority::active_installation(
        f.initiator_device(),
        f.initiator.policy(),
    );
    let setup = |path: &Path| {
        let mut journal = new_store(path, f.initiator_device());
        journal
            .install_roster(peer(&f).roster(), 150)
            .expect("initial peer");
        journal.close();
    };
    let baseline = directory();
    let path = baseline.path().canonicalize().expect("path");
    setup(&path);
    let (mut normal, _, count, _) = fault_store(&path, f.initiator_device(), false);
    count.store(0, Ordering::SeqCst);
    normal
        .install_peer_credential_renewal(
            &authority,
            &renewal,
            renewal.operation(),
            f.initiator.policy(),
            150,
        )
        .expect("baseline transition");
    let barriers = count.load(Ordering::SeqCst);
    assert!((4..=32).contains(&barriers));
    normal.close();
    let mut previous = 0;
    let mut committed = 0;
    for cut in 1..=barriers {
        for after in [false, true] {
            let folder = directory();
            let path = folder.path().canonicalize().expect("path");
            setup(&path);
            let (mut journal, remaining, _, _) = fault_store(&path, f.initiator_device(), after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                journal.install_peer_credential_renewal(
                    &authority,
                    &renewal,
                    renewal.operation(),
                    f.initiator.policy(),
                    150,
                ),
                after,
            );
            assert!(journal.active.is_none());
            let mut restored = reopen(&path, f.initiator_device());
            let image = restored.image().expect("original recovered image");
            let saved = get(&image, &peer(&f).account_id()).expect("atomic roster and grant");
            if saved.roster.checkpoint() == peer(&f).roster().checkpoint() {
                previous += 1;
                assert!(saved.renewals.is_empty());
            } else {
                committed += 1;
                assert_eq!(
                    saved.roster.checkpoint(),
                    renewal.successor_device().roster().checkpoint()
                );
                assert_eq!(
                    saved
                        .renewals
                        .get(&peer(&f).device_id())
                        .expect("committed original grant")
                        .statement_digest(),
                    renewal.statement_digest()
                );
            }
            restored
                .install_peer_credential_renewal(
                    &authority,
                    &renewal,
                    renewal.operation(),
                    f.initiator.policy(),
                    150,
                )
                .expect("original exact retry");
            let once = restored.image().expect("one completed transition");
            assert_eq!(once.revision, 3);
            assert_eq!(once.id, *identity(&path).as_bytes());
            assert_eq!(once.owner, bootstrap::storage_owner(f.initiator_device()));
        }
    }
    assert!(previous > 0 && committed > 0);
    eprintln!("PEER_RENEWAL_SYNC_RECOVERY barriers={barriers} faults={} previous={previous} committed={committed}", barriers * 2);
}
