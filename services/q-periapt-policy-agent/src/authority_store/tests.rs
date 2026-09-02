use std::cell::Cell;
use std::error::Error;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct FakeClock {
    now: Cell<Option<u64>>,
}

impl FakeClock {
    const fn new(now: u64) -> Self {
        Self {
            now: Cell::new(Some(now)),
        }
    }

    fn set(&self, now: u64) {
        self.now.set(Some(now));
    }

    fn fail(&self) {
        self.now.set(None);
    }
}

impl TrustedClockV2 for FakeClock {
    fn now_millis(&self) -> Result<u64, TrustedClockErrorV2> {
        self.now.get().ok_or(TrustedClockErrorV2)
    }
}

// Unix-only: it sets an owner-only directory mode, and `open_private_file`
// has no protected-store implementation on other platforms anyway.
#[cfg(unix)]
#[test]
fn a_failed_provision_leaves_the_path_retryable() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    // `open_private_file` requires an owner-only parent and refuses to
    // follow symlinks, so the directory needs the explicit mode and the
    // canonical path -- on macOS the temporary root is reached through
    // /var, a symlink to /private/var.
    let directory = tempfile::Builder::new()
        .prefix("q-periapt-authority-store-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let path = directory.path().canonicalize()?.join("authority.redb");

    // Fail initialization after the file has already been created, the way
    // unavailable entropy or a pre-epoch clock would.
    let broken = FakeClock::new(100);
    broken.fail();
    assert!(AuthorityStoreV2::provision_with_clock_for_test(
        &path,
        state_head(1, 1, 1, 1, 1)?,
        config(1, 1)?,
        limits(8, 4, 4)?,
        &broken,
    )
    .is_err());

    // The half-provisioned file must not survive. Creation is
    // O_CREAT|O_EXCL, so a leftover makes every later provision fail with
    // EEXIST while `open` rejects the store it finds -- one transient
    // failure would brick the path forever.
    assert!(
        !path.exists(),
        "a failed provision left its store file behind"
    );

    // And the path is genuinely reusable, not merely tidy.
    let working = FakeClock::new(100);
    let retried = AuthorityStoreV2::provision_with_clock_for_test(
        &path,
        state_head(1, 1, 1, 1, 1)?,
        config(1, 1)?,
        limits(8, 4, 4)?,
        &working,
    );
    assert!(retried.is_ok(), "retry failed: {:?}", retried.err());
    Ok(())
}

fn state_head(
    generation: u64,
    chain: u8,
    epoch: u64,
    digest: u8,
    fence: u8,
) -> TestResult<StateHeadV2> {
    Ok(StateHeadV2::new(
        StateRevisionV2::new(generation, [chain; 32], epoch, [digest; 32])?,
        StateFenceV2::from_bytes([fence; 32])?,
    ))
}

fn config(generation: u64, digest: u8) -> TestResult<DeploymentConfigRevisionV2> {
    Ok(DeploymentConfigRevisionV2::new(generation, [digest; 32])?)
}

fn limits(receipts: usize, capabilities: usize, keys: usize) -> TestResult<AuthorityLimitsV2> {
    Ok(AuthorityLimitsV2::new(
        receipts,
        capabilities,
        keys,
        10_000,
    )?)
}

fn create_file(path: &Path) -> TestResult<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?)
}

fn open_file(path: &Path) -> TestResult<File> {
    Ok(OpenOptions::new().read(true).write(true).open(path)?)
}

fn provision_test_store(
    path: &Path,
    clock: &FakeClock,
    configured_limits: AuthorityLimitsV2,
) -> TestResult<AuthorityStoreV2> {
    Ok(AuthorityStoreV2::provision_file(
        create_file(path)?,
        state_head(1, 1, 1, 1, 1)?,
        config(1, 1)?,
        configured_limits,
        clock,
    )?)
}

fn reopen(mut store: AuthorityStoreV2, path: &Path) -> TestResult<AuthorityStoreV2> {
    let expected_epoch = store.authority_epoch();
    let expected_image = store.durable_image_for_test()?;
    drop(store);
    let mut reopened = AuthorityStoreV2::open_file(open_file(path)?)?;
    assert_eq!(reopened.authority_epoch(), expected_epoch);
    assert_eq!(reopened.durable_image_for_test()?, expected_image);
    Ok(reopened)
}

fn operation(version: u64, byte: u8) -> TestResult<OperationIdV2> {
    Ok(OperationIdV2::new(version, [byte; 32])?)
}

fn current_intent(
    store: &mut AuthorityStoreV2,
    clock: &FakeClock,
    byte: u8,
    mutation: AuthorityMutationV2,
) -> TestResult<AuthorityIntentV2> {
    let snapshot = store.snapshot_with_clock(clock)?;
    Ok(AuthorityIntentV2::new(
        operation(snapshot.authority_version(), byte)?,
        snapshot.authority_version(),
        snapshot.config(),
        mutation,
    )?)
}

fn apply_current(
    store: &mut AuthorityStoreV2,
    clock: &FakeClock,
    byte: u8,
    mutation: AuthorityMutationV2,
) -> TestResult<AuthorityReceiptV2> {
    let intent = current_intent(store, clock, byte, mutation)?;
    Ok(store.apply_with_clock(clock, intent)?)
}

fn active_fence(store: &mut AuthorityStoreV2, clock: &FakeClock) -> TestResult<InstanceFenceV2> {
    store
        .snapshot_with_clock(clock)?
        .active_lease()
        .map(InstanceLeaseV2::fence)
        .ok_or_else(|| "expected active lease".into())
}

fn acquire(
    store: &mut AuthorityStoreV2,
    clock: &FakeClock,
    operation_byte: u8,
    instance_byte: u8,
) -> TestResult<InstanceFenceV2> {
    let expected_lease_generation = store.snapshot_with_clock(clock)?.lease_generation();
    let receipt = apply_current(
        store,
        clock,
        operation_byte,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation,
            instance_id: ProcessInstanceIdV2::from_bytes([instance_byte; 32])?,
        },
    )?;
    assert_eq!(receipt.disposition(), AuthorityDispositionV2::Applied);
    active_fence(store, clock)
}

fn register_one_key(
    store: &mut AuthorityStoreV2,
    clock: &FakeClock,
    instance_byte: u8,
    capability_byte: u8,
    key_byte: u8,
) -> TestResult<(InstanceFenceV2, CapabilityIdV2, AcceptedKeyIdV2)> {
    let fence = acquire(store, clock, 1, instance_byte)?;
    let capability_id = CapabilityIdV2::from_bytes([capability_byte; 32])?;
    assert_eq!(
        apply_current(
            store,
            clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id,
            },
        )?
        .disposition(),
        AuthorityDispositionV2::Applied
    );
    let key_id = AcceptedKeyIdV2::new(1, fence.generation(), [key_byte; 32])?;
    assert_eq!(
        apply_current(
            store,
            clock,
            3,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id,
                key_id,
            },
        )?
        .disposition(),
        AuthorityDispositionV2::Applied
    );
    Ok((fence, capability_id, key_id))
}

fn assert_all_operations_poisoned(
    store: &mut AuthorityStoreV2,
    clock: &FakeClock,
    intent: AuthorityIntentV2,
    locator: ReceiptLocatorV2,
) {
    assert_eq!(
        store.query(intent.operation_id()),
        Err(AuthorityStoreErrorV2::Poisoned)
    );
    assert_eq!(
        store.snapshot_with_clock(clock),
        Err(AuthorityStoreErrorV2::Poisoned)
    );
    assert_eq!(
        store.apply_with_clock(clock, intent),
        Err(AuthorityStoreErrorV2::Poisoned)
    );
    assert_eq!(
        store.acknowledge_receipt(locator),
        Err(AuthorityStoreErrorV2::Poisoned)
    );
}

fn reopen_and_assert_floor(
    store: AuthorityStoreV2,
    path: &Path,
    clock: &FakeClock,
    expected_floor: u64,
) -> TestResult<AuthorityStoreV2> {
    let mut reopened = reopen(store, path)?;
    clock.set(1);
    assert_eq!(
        reopened.snapshot_with_clock(clock)?.clock_floor_millis(),
        expected_floor
    );
    Ok(reopened)
}

fn assert_only_clock_floor_changed(
    before: &AuthorityRestoreV2,
    after: &AuthorityRestoreV2,
    expected_floor: u64,
) {
    let mut expected_meta = before.meta;
    expected_meta.clock_floor_millis = expected_floor;
    assert_eq!(after.meta, expected_meta);
    assert_eq!(after.receipts, before.receipts);
    assert_eq!(after.capabilities, before.capabilities);
    assert_eq!(after.keys, before.keys);
}

#[test]
fn all_eight_mutations_survive_normalized_restart_roundtrips() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority.redb");
    let clock = FakeClock::new(100);
    let mut store = provision_test_store(&path, &clock, limits(64, 16, 16)?)?;
    let authority_epoch = store.authority_epoch();

    let first_fence = acquire(&mut store, &clock, 1, 11)?;
    store = reopen(store, &path)?;
    assert_eq!(store.authority_epoch(), authority_epoch);
    let held = apply_current(
        &mut store,
        &clock,
        10,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: first_fence.generation(),
            instance_id: ProcessInstanceIdV2::from_bytes([99; 32])?,
        },
    )?;
    assert_eq!(
        held.disposition(),
        AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseHeld)
    );
    store = reopen(store, &path)?;

    clock.set(200);
    let renewed = apply_current(
        &mut store,
        &clock,
        2,
        AuthorityMutationV2::RenewLease { fence: first_fence },
    )?;
    assert_eq!(renewed.disposition(), AuthorityDispositionV2::Applied);
    store = reopen(store, &path)?;

    let capability_id = CapabilityIdV2::from_bytes([21; 32])?;
    let consumed = apply_current(
        &mut store,
        &clock,
        3,
        AuthorityMutationV2::ConsumeCapability {
            fence: first_fence,
            capability_id,
        },
    )?;
    assert_eq!(consumed.disposition(), AuthorityDispositionV2::Applied);
    store = reopen(store, &path)?;

    let key_id = AcceptedKeyIdV2::new(1, first_fence.generation(), [31; 32])?;
    let registered = apply_current(
        &mut store,
        &clock,
        4,
        AuthorityMutationV2::RegisterKey {
            fence: first_fence,
            capability_id,
            key_id,
        },
    )?;
    assert_eq!(registered.disposition(), AuthorityDispositionV2::Applied);
    store = reopen(store, &path)?;
    assert_eq!(store.snapshot_with_clock(&clock)?.active_key_count(), 1);

    let revoked = apply_current(
        &mut store,
        &clock,
        5,
        AuthorityMutationV2::RevokeKey {
            fence: first_fence,
            key_id,
        },
    )?;
    assert_eq!(revoked.disposition(), AuthorityDispositionV2::Applied);
    store = reopen(store, &path)?;
    assert_eq!(store.snapshot_with_clock(&clock)?.active_key_count(), 0);

    let released = apply_current(
        &mut store,
        &clock,
        6,
        AuthorityMutationV2::ReleaseLease { fence: first_fence },
    )?;
    assert_eq!(released.disposition(), AuthorityDispositionV2::Applied);
    store = reopen(store, &path)?;
    assert_eq!(store.snapshot_with_clock(&clock)?.retained_key_count(), 0);

    let second_fence = acquire(&mut store, &clock, 7, 12)?;
    let original_head = store.snapshot_with_clock(&clock)?.state_head();
    let next_head = state_head(2, 1, 2, 2, 2)?;
    let state_advance =
        StateAdvanceV2::new(StateTransitionKindV2::Advance, original_head, next_head)?;
    let advanced = apply_current(
        &mut store,
        &clock,
        8,
        AuthorityMutationV2::AdvanceState {
            fence: second_fence,
            advance: state_advance,
        },
    )?;
    assert_eq!(advanced.disposition(), AuthorityDispositionV2::Applied);
    store = reopen(store, &path)?;
    let after_state = store.snapshot_with_clock(&clock)?;
    assert_eq!(after_state.state_head(), next_head);
    assert_eq!(after_state.capability_count(), 0);
    assert_eq!(after_state.retained_key_count(), 0);

    let first_config = after_state.config();
    let second_config = config(2, 2)?;
    let config_advance = ConfigAdvanceV2::new(first_config, second_config)?;
    let configured = apply_current(
        &mut store,
        &clock,
        9,
        AuthorityMutationV2::AdvanceConfig {
            fence: second_fence,
            advance: config_advance,
        },
    )?;
    assert_eq!(configured.disposition(), AuthorityDispositionV2::Applied);
    store = reopen(store, &path)?;
    let final_snapshot = store.snapshot_with_clock(&clock)?;
    assert_eq!(final_snapshot.authority_version(), 11);
    assert_eq!(final_snapshot.config(), second_config);
    assert_eq!(final_snapshot.active_lease(), None);
    assert_eq!(final_snapshot.receipt_count(), 10);
    Ok(())
}

#[test]
fn active_missing_key_is_corrupt_but_historical_bindings_survive_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let clock = FakeClock::new(100);

    let active_path = directory.path().join("active-missing-key.redb");
    let mut active = provision_test_store(&active_path, &clock, limits(16, 4, 4)?)?;
    let (_, _, active_key_id) = register_one_key(&mut active, &clock, 11, 21, 31)?;
    drop(active);
    let database = Database::builder().create_file(open_file(&active_path)?)?;
    let transaction = database.begin_write()?;
    {
        let mut keys = transaction.open_table(KEY_TABLE)?;
        let encoded_key = encode_accepted_key_id(active_key_id);
        assert!(keys.remove(encoded_key.as_slice())?.is_some());
    }
    transaction.commit()?;
    drop(database);
    assert!(matches!(
        AuthorityStoreV2::open_file(open_file(&active_path)?),
        Err(AuthorityStoreErrorV2::CorruptStore)
    ));

    let release_path = directory.path().join("released-key-tombstone.redb");
    let mut released = provision_test_store(&release_path, &clock, limits(16, 4, 4)?)?;
    let (released_fence, _, _) = register_one_key(&mut released, &clock, 12, 22, 32)?;
    assert_eq!(
        apply_current(
            &mut released,
            &clock,
            4,
            AuthorityMutationV2::ReleaseLease {
                fence: released_fence,
            },
        )?
        .disposition(),
        AuthorityDispositionV2::Applied
    );
    released = reopen(released, &release_path)?;
    let released_snapshot = released.snapshot_with_clock(&clock)?;
    assert_eq!(released_snapshot.capability_count(), 1);
    assert_eq!(released_snapshot.retained_key_count(), 0);
    assert_eq!(released_snapshot.active_lease(), None);
    let _ = acquire(&mut released, &clock, 5, 13)?;
    released = reopen(released, &release_path)?;
    let reacquired_snapshot = released.snapshot_with_clock(&clock)?;
    assert_eq!(reacquired_snapshot.capability_count(), 1);
    assert_eq!(reacquired_snapshot.retained_key_count(), 0);

    let config_path = directory.path().join("old-config-key-tombstone.redb");
    let mut configured = provision_test_store(&config_path, &clock, limits(16, 4, 4)?)?;
    let (configured_fence, _, _) = register_one_key(&mut configured, &clock, 14, 24, 34)?;
    let next_config = config(2, 2)?;
    assert_eq!(
        apply_current(
            &mut configured,
            &clock,
            4,
            AuthorityMutationV2::AdvanceConfig {
                fence: configured_fence,
                advance: ConfigAdvanceV2::new(config(1, 1)?, next_config)?,
            },
        )?
        .disposition(),
        AuthorityDispositionV2::Applied
    );
    configured = reopen(configured, &config_path)?;
    let configured_snapshot = configured.snapshot_with_clock(&clock)?;
    assert_eq!(configured_snapshot.config(), next_config);
    assert_eq!(configured_snapshot.capability_count(), 1);
    assert_eq!(configured_snapshot.retained_key_count(), 0);
    assert_eq!(configured_snapshot.active_lease(), None);
    Ok(())
}

#[test]
fn all_rejection_tags_survive_normalized_restart_roundtrip() -> TestResult {
    const REJECTIONS: &[(u8, AuthorityRejectionV2)] = &[
        (1, AuthorityRejectionV2::ConfigurationMismatch),
        (2, AuthorityRejectionV2::LeaseHeld),
        (3, AuthorityRejectionV2::LeaseGenerationMismatch),
        (4, AuthorityRejectionV2::LeaseAbsent),
        (5, AuthorityRejectionV2::LeaseExpired),
        (6, AuthorityRejectionV2::FenceMismatch),
        (7, AuthorityRejectionV2::LeaseRenewalNotExtended),
        (8, AuthorityRejectionV2::MutationOverflow),
        (9, AuthorityRejectionV2::StateMismatch),
        (10, AuthorityRejectionV2::ConfigTransitionMismatch),
        (11, AuthorityRejectionV2::CapabilityReplay),
        (12, AuthorityRejectionV2::CapabilityUnknown),
        (13, AuthorityRejectionV2::CapabilityStale),
        (14, AuthorityRejectionV2::CapabilityAlreadyBound),
        (15, AuthorityRejectionV2::KeyAlreadyRegistered),
        (16, AuthorityRejectionV2::KeyStateGenerationMismatch),
        (17, AuthorityRejectionV2::KeyLeaseGenerationMismatch),
        (18, AuthorityRejectionV2::KeyUnknown),
        (19, AuthorityRejectionV2::KeyRevoked),
        (20, AuthorityRejectionV2::CapabilityCapacityExceeded),
        (21, AuthorityRejectionV2::KeyCapacityExceeded),
    ];

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("rejections.redb");
    let clock = FakeClock::new(100);
    let mut store = provision_test_store(&path, &clock, limits(32, 4, 4)?)?;
    let mut image = store.durable_image_for_test()?;
    image
        .receipts
        .try_reserve_exact(REJECTIONS.len())
        .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;

    for &(tag, rejection) in REJECTIONS {
        assert_eq!(encode_rejection(rejection), tag);
        assert_eq!(decode_rejection(tag)?, rejection);
        let expected_authority_version = u64::from(tag);
        let intent = AuthorityIntentV2::new(
            operation(expected_authority_version, tag)?,
            expected_authority_version,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([tag; 32])?,
            },
        )?;
        let receipt = AuthorityReceiptV2::restore(
            intent,
            AuthorityDispositionV2::Rejected(rejection),
            expected_authority_version + 1,
        )
        .map_err(map_restore)?;
        assert_eq!(decode_receipt(&encode_receipt(receipt)?)?, receipt);
        image.receipts.push((intent.operation_id(), receipt));
    }
    image.meta.authority_version = 22;
    image.receipts.sort_unstable_by_key(|(id, _)| *id);
    let next = AuthorityStateV2::restore(&image)
        .map_err(map_restore)?
        .durable_image()
        .map_err(map_restore)?;

    let transaction = store.begin_write()?;
    let loaded = store.load_matching(&transaction)?;
    store.persist_or_poison(&transaction, &loaded.image, &next)?;
    store.commit_or_poison(transaction)?;
    store = reopen(store, &path)?;
    for &(_, receipt) in &next.receipts {
        assert_eq!(
            store.query(receipt.intent().operation_id())?,
            AuthorityQueryResultV2::Found(Box::new(receipt))
        );
    }
    Ok(())
}

#[test]
fn replay_clock_floor_and_acknowledgement_are_durable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority.redb");
    let clock = FakeClock::new(100);
    let mut store = provision_test_store(&path, &clock, limits(8, 4, 4)?)?;
    let intent = current_intent(
        &mut store,
        &clock,
        1,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    let receipt = store.apply_with_clock(&clock, intent)?;
    clock.set(500);
    assert_eq!(store.apply_with_clock(&clock, intent)?, receipt);
    store = reopen(store, &path)?;
    clock.set(1);
    assert_eq!(store.snapshot_with_clock(&clock)?.clock_floor_millis(), 500);
    assert_eq!(
        store.query(intent.operation_id())?,
        AuthorityQueryResultV2::Found(Box::new(receipt))
    );

    let wrong = ReceiptLocatorV2::new(
        receipt.intent().operation_id(),
        receipt.resulting_authority_version() + 1,
    )?;
    assert_eq!(
        store.acknowledge_receipt(wrong),
        Err(AuthorityStoreErrorV2::ReceiptAcknowledgement(
            ReceiptAckErrorV2::ResultingVersionMismatch
        ))
    );
    assert_eq!(
        store.acknowledge_receipt(receipt.locator())?,
        ReceiptAckDispositionV2::Removed
    );
    store = reopen(store, &path)?;
    assert_eq!(
        store.query(intent.operation_id())?,
        AuthorityQueryResultV2::AbsentAtVersion {
            authority_version: receipt.resulting_authority_version()
        }
    );
    assert_eq!(
        store.acknowledge_receipt(receipt.locator())?,
        ReceiptAckDispositionV2::AlreadyAbsent
    );
    Ok(())
}

#[test]
fn clock_failure_and_receipt_bound_fail_closed_without_losing_floor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority.redb");
    let clock = FakeClock::new(100);
    let mut store = provision_test_store(&path, &clock, limits(1, 1, 1)?)?;
    let first = current_intent(
        &mut store,
        &clock,
        1,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    let receipt = store.apply_with_clock(&clock, first)?;
    let fence = active_fence(&mut store, &clock)?;
    clock.set(700);
    let second = AuthorityIntentV2::new(
        operation(2, 2)?,
        2,
        config(1, 1)?,
        AuthorityMutationV2::RenewLease { fence },
    )?;
    assert_eq!(
        store.apply_with_clock(&clock, second),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::ReceiptCapacityExceeded
        ))
    );
    store = reopen(store, &path)?;
    clock.set(1);
    assert_eq!(store.snapshot_with_clock(&clock)?.clock_floor_millis(), 700);

    clock.fail();
    assert_eq!(
        store.snapshot_with_clock(&clock),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::ClockUnavailable
        ))
    );
    assert_eq!(
        store.apply_with_clock(&clock, first),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::ClockUnavailable
        ))
    );
    assert_eq!(
        store.query(receipt.intent().operation_id())?,
        AuthorityQueryResultV2::Found(Box::new(receipt))
    );
    Ok(())
}

#[test]
fn every_non_receipt_error_persists_its_observed_clock_floor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("errors.redb");
    let clock = FakeClock::new(100);
    let mut store = provision_test_store(&path, &clock, limits(1, 2, 2)?)?;
    let first = AuthorityIntentV2::new(
        operation(1, 1)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    store.apply_with_clock(&clock, first)?;

    clock.set(200);
    let conflicting = AuthorityIntentV2::new(
        first.operation_id(),
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
        },
    )?;
    assert_eq!(
        store.apply_with_clock(&clock, conflicting),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::OperationConflict
        ))
    );
    store = reopen_and_assert_floor(store, &path, &clock, 200)?;

    clock.set(300);
    let stale = AuthorityIntentV2::new(
        operation(1, 2)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 1,
            instance_id: ProcessInstanceIdV2::from_bytes([13; 32])?,
        },
    )?;
    assert_eq!(
        store.apply_with_clock(&clock, stale),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::AuthorityVersionMismatch
        ))
    );
    store = reopen_and_assert_floor(store, &path, &clock, 300)?;

    clock.set(400);
    let full = AuthorityIntentV2::new(
        operation(2, 3)?,
        2,
        config(1, 1)?,
        AuthorityMutationV2::RenewLease {
            fence: active_fence(&mut store, &FakeClock::new(300))?,
        },
    )?;
    assert_eq!(
        store.apply_with_clock(&clock, full),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::ReceiptCapacityExceeded
        ))
    );
    store = reopen_and_assert_floor(store, &path, &clock, 400)?;

    let before_unavailable = store.durable_image_for_test()?;
    clock.fail();
    assert_eq!(
        store.snapshot_with_clock(&clock),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::ClockUnavailable
        ))
    );
    assert_eq!(
        store.apply_with_clock(&clock, first),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::ClockUnavailable
        ))
    );
    assert_eq!(store.durable_image_for_test()?, before_unavailable);

    let exhausted_path = directory.path().join("exhausted.redb");
    let exhausted_clock = FakeClock::new(100);
    let exhausted = provision_test_store(&exhausted_path, &exhausted_clock, limits(2, 2, 2)?)?;
    drop(exhausted);
    let database = Database::builder().create_file(open_file(&exhausted_path)?)?;
    let transaction = database.begin_write()?;
    {
        let mut meta = transaction.open_table(META_TABLE)?;
        meta.insert(META_AUTHORITY_VERSION, u64::MAX.to_be_bytes().as_slice())?;
    }
    transaction.commit()?;
    drop(database);
    let mut exhausted = AuthorityStoreV2::open_file(open_file(&exhausted_path)?)?;
    let exhausted_intent = AuthorityIntentV2::new(
        operation(u64::MAX, 4)?,
        u64::MAX,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([14; 32])?,
        },
    )?;
    exhausted_clock.set(500);
    assert_eq!(
        exhausted.apply_with_clock(&exhausted_clock, exhausted_intent),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::AuthorityVersionExhausted
        ))
    );
    let _ = reopen_and_assert_floor(exhausted, &exhausted_path, &exhausted_clock, 500)?;
    Ok(())
}

#[test]
fn every_reservation_allocation_failure_persists_floor_without_partial_effect() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("allocations.redb");
    let clock = FakeClock::new(100);
    let mut store = provision_test_store(&path, &clock, limits(16, 4, 4)?)?;
    let acquire_intent = AuthorityIntentV2::new(
        operation(1, 1)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;

    clock.set(1_000);
    store.fail_next_reservation_for_test(ReservationPointV2::Receipt);
    assert_eq!(
        store.apply_with_clock(&clock, acquire_intent),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::AllocationFailed
        ))
    );
    store = reopen_and_assert_floor(store, &path, &clock, 1_000)?;
    assert_eq!(
        store.query(acquire_intent.operation_id())?,
        AuthorityQueryResultV2::AbsentAtVersion {
            authority_version: 1
        }
    );

    clock.set(1_001);
    store.apply_with_clock(&clock, acquire_intent)?;
    let fence = active_fence(&mut store, &clock)?;
    let capability_id = CapabilityIdV2::from_bytes([21; 32])?;
    let consume_intent = AuthorityIntentV2::new(
        operation(2, 2)?,
        2,
        config(1, 1)?,
        AuthorityMutationV2::ConsumeCapability {
            fence,
            capability_id,
        },
    )?;
    clock.set(2_000);
    store.fail_next_reservation_for_test(ReservationPointV2::Capability);
    assert_eq!(
        store.apply_with_clock(&clock, consume_intent),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::AllocationFailed
        ))
    );
    store = reopen_and_assert_floor(store, &path, &clock, 2_000)?;
    let after_capability_failure = store.snapshot_with_clock(&FakeClock::new(2_000))?;
    assert_eq!(after_capability_failure.authority_version(), 2);
    assert_eq!(after_capability_failure.capability_count(), 0);

    clock.set(2_001);
    store.apply_with_clock(&clock, consume_intent)?;
    let key_id = AcceptedKeyIdV2::new(1, fence.generation(), [31; 32])?;
    let register_intent = AuthorityIntentV2::new(
        operation(3, 3)?,
        3,
        config(1, 1)?,
        AuthorityMutationV2::RegisterKey {
            fence,
            capability_id,
            key_id,
        },
    )?;
    clock.set(3_000);
    store.fail_next_reservation_for_test(ReservationPointV2::Key);
    assert_eq!(
        store.apply_with_clock(&clock, register_intent),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::AllocationFailed
        ))
    );
    store = reopen_and_assert_floor(store, &path, &clock, 3_000)?;
    let after_key_failure = store.snapshot_with_clock(&FakeClock::new(3_000))?;
    assert_eq!(after_key_failure.authority_version(), 3);
    assert_eq!(after_key_failure.capability_count(), 1);
    assert_eq!(after_key_failure.retained_key_count(), 0);
    assert_eq!(
        store.query(register_intent.operation_id())?,
        AuthorityQueryResultV2::AbsentAtVersion {
            authority_version: 3
        }
    );
    Ok(())
}

#[test]
fn precommit_export_and_encode_allocations_commit_only_the_observed_floor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("precommit-allocations.redb");
    let clock = FakeClock::new(100);
    let mut store = provision_test_store(&path, &clock, limits(16, 4, 4)?)?;

    let before_snapshot = store.durable_image_for_test()?;
    clock.set(500);
    store.fail_next_export_allocation_for_test();
    assert_eq!(
        store.snapshot_with_clock(&clock),
        Err(AuthorityStoreErrorV2::AllocationFailed)
    );
    let after_snapshot = store.durable_image_for_test()?;
    assert_only_clock_floor_changed(&before_snapshot, &after_snapshot, 500);
    store = reopen(store, &path)?;

    let acquire_intent = AuthorityIntentV2::new(
        operation(1, 1)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    let before_export = store.durable_image_for_test()?;
    clock.set(600);
    store.fail_next_export_allocation_for_test();
    assert_eq!(
        store.apply_with_clock(&clock, acquire_intent),
        Err(AuthorityStoreErrorV2::AllocationFailed)
    );
    let after_export = store.durable_image_for_test()?;
    assert_only_clock_floor_changed(&before_export, &after_export, 600);
    assert_eq!(
        store.query(acquire_intent.operation_id())?,
        AuthorityQueryResultV2::AbsentAtVersion {
            authority_version: 1
        }
    );
    store = reopen(store, &path)?;
    assert_eq!(
        store
            .apply_with_clock(&clock, acquire_intent)?
            .disposition(),
        AuthorityDispositionV2::Applied
    );

    let fence = active_fence(&mut store, &clock)?;
    let renew_intent = AuthorityIntentV2::new(
        operation(2, 2)?,
        2,
        config(1, 1)?,
        AuthorityMutationV2::RenewLease { fence },
    )?;
    let before_encode = store.durable_image_for_test()?;
    clock.set(700);
    store.fail_next_encode_allocation_for_test();
    assert_eq!(
        store.apply_with_clock(&clock, renew_intent),
        Err(AuthorityStoreErrorV2::AllocationFailed)
    );
    let after_encode = store.durable_image_for_test()?;
    assert_only_clock_floor_changed(&before_encode, &after_encode, 700);
    assert_eq!(
        store.query(renew_intent.operation_id())?,
        AuthorityQueryResultV2::AbsentAtVersion {
            authority_version: 2
        }
    );
    store = reopen(store, &path)?;
    assert_eq!(
        store.apply_with_clock(&clock, renew_intent)?.disposition(),
        AuthorityDispositionV2::Applied
    );
    Ok(())
}

#[test]
fn acknowledgement_partial_writes_are_explicitly_aborted_or_poisoned() -> TestResult {
    let directory = tempfile::tempdir()?;
    let clock = FakeClock::new(100);

    let retry_path = directory.path().join("ack-abort-retry.redb");
    let mut retry = provision_test_store(&retry_path, &clock, limits(8, 4, 4)?)?;
    let retry_intent = AuthorityIntentV2::new(
        operation(1, 1)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    let retry_receipt = retry.apply_with_clock(&clock, retry_intent)?;
    let before_retry = retry.durable_image_for_test()?;
    retry.fail_next_persist_allocation_after_meta_for_test();
    assert_eq!(
        retry.acknowledge_receipt(retry_receipt.locator()),
        Err(AuthorityStoreErrorV2::AllocationFailed)
    );
    assert_eq!(retry.durable_image_for_test()?, before_retry);
    assert_eq!(
        retry.query(retry_intent.operation_id())?,
        AuthorityQueryResultV2::Found(Box::new(retry_receipt))
    );
    retry = reopen(retry, &retry_path)?;
    assert_eq!(
        retry.acknowledge_receipt(retry_receipt.locator())?,
        ReceiptAckDispositionV2::Removed
    );

    let poisoned_path = directory.path().join("ack-abort-reported-failure.redb");
    let mut poisoned = provision_test_store(&poisoned_path, &clock, limits(8, 4, 4)?)?;
    let poisoned_intent = AuthorityIntentV2::new(
        operation(1, 2)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
        },
    )?;
    let poisoned_receipt = poisoned.apply_with_clock(&clock, poisoned_intent)?;
    let before_poison = poisoned.durable_image_for_test()?;
    poisoned.fail_next_persist_allocation_after_meta_for_test();
    poisoned.report_next_abort_failure_for_test();
    assert_eq!(
        poisoned.acknowledge_receipt(poisoned_receipt.locator()),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_all_operations_poisoned(
        &mut poisoned,
        &clock,
        poisoned_intent,
        poisoned_receipt.locator(),
    );
    drop(poisoned);
    // Test-only forensic inspection of a quarantined path; this is not permission to serve it.
    let mut reopened_poisoned = AuthorityStoreV2::open_file(open_file(&poisoned_path)?)?;
    assert_eq!(reopened_poisoned.durable_image_for_test()?, before_poison);
    Ok(())
}

#[test]
fn query_and_already_absent_never_hide_a_reported_abort_failure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let clock = FakeClock::new(100);

    let query_path = directory.path().join("query-abort-failure.redb");
    let mut query = provision_test_store(&query_path, &clock, limits(8, 4, 4)?)?;
    let operation_id = operation(1, 1)?;
    query.report_next_abort_failure_for_test();
    assert_eq!(
        query.query(operation_id),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_eq!(
        query.query(operation_id),
        Err(AuthorityStoreErrorV2::Poisoned)
    );

    let absent_path = directory.path().join("absent-abort-failure.redb");
    let mut absent = provision_test_store(&absent_path, &clock, limits(8, 4, 4)?)?;
    let locator = ReceiptLocatorV2::new(operation(1, 2)?, 2)?;
    absent.report_next_abort_failure_for_test();
    assert_eq!(
        absent.acknowledge_receipt(locator),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_eq!(
        absent.acknowledge_receipt(locator),
        Err(AuthorityStoreErrorV2::Poisoned)
    );
    Ok(())
}

#[test]
fn floor_only_commit_failures_and_internal_invariants_permanently_poison() -> TestResult {
    let directory = tempfile::tempdir()?;

    let abort_path = directory
        .path()
        .join("business-abort-reported-failure.redb");
    let abort_clock = FakeClock::new(100);
    let mut abort = provision_test_store(&abort_path, &abort_clock, limits(8, 4, 4)?)?;
    let abort_intent = AuthorityIntentV2::new(
        operation(1, 9)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([19; 32])?,
        },
    )?;
    let abort_locator = ReceiptLocatorV2::new(abort_intent.operation_id(), 2)?;
    let abort_before = abort.durable_image_for_test()?;
    abort_clock.set(450);
    abort.fail_next_encode_allocation_for_test();
    abort.report_next_abort_failure_for_test();
    assert_eq!(
        abort.apply_with_clock(&abort_clock, abort_intent),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_all_operations_poisoned(&mut abort, &abort_clock, abort_intent, abort_locator);
    drop(abort);
    // Every reopen below is test-only forensic old-or-new inspection, never service recovery.
    let mut reopened_abort = AuthorityStoreV2::open_file(open_file(&abort_path)?)?;
    assert_eq!(reopened_abort.durable_image_for_test()?, abort_before);

    let precommit_path = directory.path().join("floor-precommit.redb");
    let precommit_clock = FakeClock::new(100);
    let mut precommit = provision_test_store(&precommit_path, &precommit_clock, limits(8, 4, 4)?)?;
    let precommit_intent = AuthorityIntentV2::new(
        operation(1, 1)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    let precommit_locator = ReceiptLocatorV2::new(precommit_intent.operation_id(), 2)?;
    let precommit_before = precommit.durable_image_for_test()?;
    precommit_clock.set(500);
    precommit.fail_next_export_allocation_for_test();
    precommit.fail_before_next_commit_for_test();
    assert_eq!(
        precommit.apply_with_clock(&precommit_clock, precommit_intent),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_all_operations_poisoned(
        &mut precommit,
        &precommit_clock,
        precommit_intent,
        precommit_locator,
    );
    drop(precommit);
    let mut reopened_precommit = AuthorityStoreV2::open_file(open_file(&precommit_path)?)?;
    let precommit_after = reopened_precommit.durable_image_for_test()?;
    assert_only_clock_floor_changed(
        &precommit_before,
        &precommit_after,
        precommit_before.meta.clock_floor_millis,
    );

    let durable_path = directory.path().join("floor-post-durable.redb");
    let durable_clock = FakeClock::new(100);
    let mut durable = provision_test_store(&durable_path, &durable_clock, limits(8, 4, 4)?)?;
    let durable_intent = AuthorityIntentV2::new(
        operation(1, 2)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
        },
    )?;
    let durable_locator = ReceiptLocatorV2::new(durable_intent.operation_id(), 2)?;
    let durable_before = durable.durable_image_for_test()?;
    durable_clock.set(600);
    durable.fail_next_export_allocation_for_test();
    durable.fail_after_next_commit_for_test();
    assert_eq!(
        durable.apply_with_clock(&durable_clock, durable_intent),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_all_operations_poisoned(
        &mut durable,
        &durable_clock,
        durable_intent,
        durable_locator,
    );
    drop(durable);
    let mut reopened_durable = AuthorityStoreV2::open_file(open_file(&durable_path)?)?;
    let durable_after = reopened_durable.durable_image_for_test()?;
    assert_only_clock_floor_changed(&durable_before, &durable_after, 600);

    let invariant_path = directory.path().join("internal-invariant.redb");
    let invariant_clock = FakeClock::new(100);
    let mut invariant = provision_test_store(&invariant_path, &invariant_clock, limits(8, 4, 4)?)?;
    let invariant_intent = AuthorityIntentV2::new(
        operation(1, 3)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([13; 32])?,
        },
    )?;
    let invariant_locator = ReceiptLocatorV2::new(invariant_intent.operation_id(), 2)?;
    let invariant_before = invariant.durable_image_for_test()?;
    invariant_clock.set(700);
    invariant.fail_next_internal_invariant_for_test();
    assert_eq!(
        invariant.apply_with_clock(&invariant_clock, invariant_intent),
        Err(AuthorityStoreErrorV2::Authority(
            AuthorityErrorV2::InternalInvariant
        ))
    );
    assert_all_operations_poisoned(
        &mut invariant,
        &invariant_clock,
        invariant_intent,
        invariant_locator,
    );
    drop(invariant);
    let mut reopened_invariant = AuthorityStoreV2::open_file(open_file(&invariant_path)?)?;
    let invariant_after = reopened_invariant.durable_image_for_test()?;
    assert_only_clock_floor_changed(&invariant_before, &invariant_after, 700);
    Ok(())
}

#[test]
fn uncertain_commit_quarantines_path_and_forensics_observe_old_or_new_images() -> TestResult {
    let directory = tempfile::tempdir()?;
    let clock = FakeClock::new(100);
    let precommit_path = directory.path().join("precommit.redb");
    let mut precommit = provision_test_store(&precommit_path, &clock, limits(8, 4, 4)?)?;
    let precommit_intent = AuthorityIntentV2::new(
        operation(1, 1)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    let precommit_locator = ReceiptLocatorV2::new(precommit_intent.operation_id(), 2)?;
    precommit.fail_before_next_commit_for_test();
    assert_eq!(
        precommit.apply_with_clock(&clock, precommit_intent),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_all_operations_poisoned(&mut precommit, &clock, precommit_intent, precommit_locator);
    drop(precommit);
    // Test-only forensic inspection: Stage 2A1 cannot clear this path's quarantine.
    let mut reopened_precommit = AuthorityStoreV2::open_file(open_file(&precommit_path)?)?;
    let precommit_image = reopened_precommit.durable_image_for_test()?;
    assert_eq!(precommit_image.meta.authority_version, 1);
    assert!(precommit_image.receipts.is_empty());

    let durable_path = directory.path().join("durable.redb");
    let mut durable = provision_test_store(&durable_path, &clock, limits(8, 4, 4)?)?;
    let durable_intent = AuthorityIntentV2::new(
        operation(1, 2)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
        },
    )?;
    let durable_locator = ReceiptLocatorV2::new(durable_intent.operation_id(), 2)?;
    durable.fail_after_next_commit_for_test();
    assert_eq!(
        durable.apply_with_clock(&clock, durable_intent),
        Err(AuthorityStoreErrorV2::CommitUncertain)
    );
    assert_all_operations_poisoned(&mut durable, &clock, durable_intent, durable_locator);
    drop(durable);
    // Test-only forensic inspection: observing the new image is not safe reopen-and-serve.
    let mut reopened_durable = AuthorityStoreV2::open_file(open_file(&durable_path)?)?;
    let durable_image = reopened_durable.durable_image_for_test()?;
    let receipt = durable_image
        .receipts
        .iter()
        .find_map(|(operation_id, receipt)| {
            (*operation_id == durable_intent.operation_id()).then_some(*receipt)
        })
        .ok_or("forensic new image did not contain committed receipt")?;
    assert_eq!(receipt.intent(), durable_intent);
    assert_eq!(receipt.disposition(), AuthorityDispositionV2::Applied);
    assert_eq!(durable_image.meta.authority_version, 2);
    Ok(())
}

#[test]
fn v1_missing_and_corrupt_normalized_state_never_open_as_v2() -> TestResult {
    let directory = tempfile::tempdir()?;
    let missing_path = directory.path().join("missing.redb");
    assert!(matches!(
        AuthorityStoreV2::open(&missing_path),
        Err(AuthorityStoreErrorV2::InsecureOrMissingStore)
    ));

    let v1_path = directory.path().join("v1.redb");
    let database = Database::builder().create_file(create_file(&v1_path)?)?;
    let transaction = database.begin_write()?;
    let v1_meta: TableDefinition<&str, &[u8]> = TableDefinition::new("authority_meta_v1");
    {
        let mut table = transaction.open_table(v1_meta)?;
        table.insert("schema", [0u8, 1].as_slice())?;
    }
    transaction.commit()?;
    drop(database);
    match AuthorityStoreV2::open_file(open_file(&v1_path)?) {
        Err(AuthorityStoreErrorV2::UnsupportedSchema) => {}
        Err(error) => return Err(format!("unexpected V1 rejection: {error:?}").into()),
        Ok(_) => return Err("V1 database opened as V2".into()),
    }
    assert!(matches!(
        AuthorityStoreV2::provision(
            &v1_path,
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 4, 4)?,
        ),
        Err(AuthorityStoreErrorV2::InsecureOrMissingStore)
    ));

    let empty_path = directory.path().join("empty.redb");
    drop(create_file(&empty_path)?);
    assert!(matches!(
        AuthorityStoreV2::open_file(open_file(&empty_path)?),
        Err(AuthorityStoreErrorV2::UnsupportedSchema)
    ));
    assert_eq!(std::fs::metadata(&empty_path)?.len(), 0);

    let corrupt_path = directory.path().join("corrupt.redb");
    let clock = FakeClock::new(100);
    let store = provision_test_store(&corrupt_path, &clock, limits(8, 4, 4)?)?;
    drop(store);
    let database = Database::builder().create_file(open_file(&corrupt_path)?)?;
    let transaction = database.begin_write()?;
    {
        let mut meta = transaction.open_table(META_TABLE)?;
        meta.insert(META_CLOCK_FLOOR, [1u8; 7].as_slice())?;
    }
    transaction.commit()?;
    drop(database);
    match AuthorityStoreV2::open_file(open_file(&corrupt_path)?) {
        Err(AuthorityStoreErrorV2::CorruptStore) => {}
        Err(error) => return Err(format!("unexpected corruption result: {error:?}").into()),
        Ok(_) => return Err("corrupt database opened".into()),
    }

    let extra_path = directory.path().join("extra.redb");
    let store = provision_test_store(&extra_path, &clock, limits(8, 4, 4)?)?;
    drop(store);
    let database = Database::builder().create_file(open_file(&extra_path)?)?;
    let transaction = database.begin_write()?;
    let extra: TableDefinition<&[u8], &[u8]> = TableDefinition::new("unexpected_table");
    transaction.open_table(extra)?;
    transaction.commit()?;
    drop(database);
    assert!(matches!(
        AuthorityStoreV2::open_file(open_file(&extra_path)?),
        Err(AuthorityStoreErrorV2::CorruptStore)
    ));

    let multimap_path = directory.path().join("multimap.redb");
    let store = provision_test_store(&multimap_path, &clock, limits(8, 4, 4)?)?;
    drop(store);
    let database = Database::builder().create_file(open_file(&multimap_path)?)?;
    let transaction = database.begin_write()?;
    let multimap: redb::MultimapTableDefinition<&[u8], &[u8]> =
        redb::MultimapTableDefinition::new("unexpected_multimap");
    transaction.open_multimap_table(multimap)?;
    transaction.commit()?;
    drop(database);
    assert!(matches!(
        AuthorityStoreV2::open_file(open_file(&multimap_path)?),
        Err(AuthorityStoreErrorV2::CorruptStore)
    ));

    let missing_path = directory.path().join("missing-table.redb");
    let store = provision_test_store(&missing_path, &clock, limits(8, 4, 4)?)?;
    drop(store);
    let database = Database::builder().create_file(open_file(&missing_path)?)?;
    let transaction = database.begin_write()?;
    assert!(transaction.delete_table(RECEIPT_TABLE)?);
    transaction.commit()?;
    drop(database);
    assert!(matches!(
        AuthorityStoreV2::open_file(open_file(&missing_path)?),
        Err(AuthorityStoreErrorV2::CorruptStore)
    ));
    Ok(())
}

#[test]
fn database_lock_rejects_second_open_and_epoch_is_fresh() -> TestResult {
    let directory = tempfile::tempdir()?;
    let first_path = directory.path().join("first.redb");
    let second_path = directory.path().join("second.redb");
    let clock = FakeClock::new(100);
    let first = provision_test_store(&first_path, &clock, limits(8, 4, 4)?)?;
    assert!(matches!(
        AuthorityStoreV2::open_file(open_file(&first_path)?),
        Err(AuthorityStoreErrorV2::AlreadyOpen)
    ));
    assert!(matches!(
        AuthorityStoreV2::provision_file(
            open_file(&first_path)?,
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 4, 4)?,
            &clock,
        ),
        Err(AuthorityStoreErrorV2::AlreadyOpen)
    ));
    let second = provision_test_store(&second_path, &clock, limits(8, 4, 4)?)?;
    assert_ne!(first.authority_epoch(), second.authority_epoch());
    Ok(())
}

#[test]
fn closed_store_copy_can_open_and_is_explicitly_not_clone_defense() -> TestResult {
    let directory = tempfile::tempdir()?;
    let original_path = directory.path().join("original.redb");
    let copied_path = directory.path().join("copied.redb");
    let clock = FakeClock::new(100);
    let mut original = provision_test_store(&original_path, &clock, limits(8, 4, 4)?)?;
    let _ = acquire(&mut original, &clock, 1, 11)?;
    let epoch = original.authority_epoch();
    let image = original.durable_image_for_test()?;
    drop(original);

    std::fs::copy(&original_path, &copied_path)?;
    let mut copied = AuthorityStoreV2::open_file(open_file(&copied_path)?)?;
    assert_eq!(copied.authority_epoch(), epoch);
    assert_eq!(copied.durable_image_for_test()?, image);
    Ok(())
}

#[test]
fn codec_rejects_trailing_unknown_and_inconsistent_records() -> TestResult {
    assert_eq!(
        map_codec(CodecError::Allocation),
        AuthorityStoreErrorV2::AllocationFailed
    );
    let clock = FakeClock::new(100);
    let state = AuthorityStateV2::provision(
        state_head(1, 1, 1, 1, 1)?,
        config(1, 1)?,
        limits(8, 4, 4)?,
        &clock,
    )?;
    let mut image = state.durable_image().map_err(map_restore)?;
    image.meta.authority_version = 0;
    match AuthorityStateV2::restore(&image) {
        Err(AuthorityRestoreErrorV2::Invalid) => {}
        Err(error) => return Err(format!("unexpected restore result: {error:?}").into()),
        Ok(_) => return Err("invalid authority image restored".into()),
    }

    let mut linked = AuthorityStateV2::provision(
        state_head(1, 1, 1, 1, 1)?,
        config(1, 1)?,
        limits(8, 2, 2)?,
        &clock,
    )?;
    let acquire = AuthorityIntentV2::new(
        operation(1, 10)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    linked.apply(&clock, acquire)?;
    let fence = linked
        .snapshot(&clock)?
        .active_lease()
        .map(InstanceLeaseV2::fence)
        .ok_or("expected linked lease")?;
    let capability_id = CapabilityIdV2::from_bytes([21; 32])?;
    linked.apply(
        &clock,
        AuthorityIntentV2::new(
            operation(2, 11)?,
            2,
            config(1, 1)?,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id,
            },
        )?,
    )?;
    linked.apply(
        &clock,
        AuthorityIntentV2::new(
            operation(3, 12)?,
            3,
            config(1, 1)?,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id,
                key_id: AcceptedKeyIdV2::new(1, 1, [31; 32])?,
            },
        )?,
    )?;
    let mut broken_link = linked.durable_image().map_err(map_restore)?;
    let key = broken_link
        .keys
        .first_mut()
        .ok_or("expected linked key record")?;
    key.1.capability_id = CapabilityIdV2::from_bytes([99; 32])?;
    assert!(matches!(
        AuthorityStateV2::restore(&broken_link),
        Err(AuthorityRestoreErrorV2::Invalid)
    ));

    let mut bounded = AuthorityStateV2::provision(
        state_head(1, 1, 1, 1, 1)?,
        config(1, 1)?,
        limits(8, 1, 1)?,
        &clock,
    )?;
    bounded.apply(&clock, acquire)?;
    bounded.apply(
        &clock,
        AuthorityIntentV2::new(
            operation(2, 13)?,
            2,
            config(1, 1)?,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id,
            },
        )?,
    )?;
    let mut over_capacity = bounded.durable_image().map_err(map_restore)?;
    let record = over_capacity
        .capabilities
        .first()
        .map(|(_, record)| *record)
        .ok_or("expected bounded capability")?;
    over_capacity
        .capabilities
        .try_reserve_exact(1)
        .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;
    over_capacity
        .capabilities
        .push((CapabilityIdV2::from_bytes([22; 32])?, record));
    assert!(matches!(
        AuthorityStateV2::restore(&over_capacity),
        Err(AuthorityRestoreErrorV2::Invalid)
    ));

    let intent = AuthorityIntentV2::new(
        operation(1, 1)?,
        1,
        config(1, 1)?,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
        },
    )?;
    let mut state = AuthorityStateV2::provision(
        state_head(1, 1, 1, 1, 1)?,
        config(1, 1)?,
        limits(8, 4, 4)?,
        &clock,
    )?;
    let receipt = state.apply(&clock, intent)?;
    let encoded = encode_receipt(receipt)?;
    assert_eq!(decode_receipt(&encoded)?, receipt);
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(decode_receipt(&trailing), Err(AuthorityCodecError::Invalid));
    let mut unknown_rejection = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut unknown_rejection, RECEIPT_DOMAIN, STORE_SCHEMA_VERSION)
        .map_err(map_codec)?;
    encode_intent(&mut unknown_rejection, intent)?;
    unknown_rejection.byte(2).map_err(map_codec)?;
    unknown_rejection.byte(255).map_err(map_codec)?;
    unknown_rejection.u64(2).map_err(map_codec)?;
    assert_eq!(
        decode_receipt(&unknown_rejection.finish()),
        Err(AuthorityCodecError::Invalid)
    );
    Ok(())
}

#[test]
fn file_helpers_are_cross_platform_test_only() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path: PathBuf = directory.path().join("portable.redb");
    let clock = FakeClock::new(100);
    let store = provision_test_store(&path, &clock, limits(8, 4, 4)?)?;
    let epoch = store.authority_epoch();
    let reopened = reopen(store, &path)?;
    assert_eq!(reopened.authority_epoch(), epoch);
    Ok(())
}
