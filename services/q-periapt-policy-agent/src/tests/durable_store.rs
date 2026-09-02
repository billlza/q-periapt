//! Durable-store boundary: private files, redb crash recovery, and store refusal.

use super::*;

/// A failed `create` must not leave the `O_CREAT|O_EXCL` leaf behind: the next
/// attempt would get `EEXIST`, and the `create = false` path rejects the
/// zero-length leftover, so one transient failure would brick provisioning
/// permanently.
///
/// Ignored by default because it manipulates the process-wide `umask`, which
/// would make any sibling test that creates a private file flaky when the suite
/// runs in parallel. Run it deliberately:
///
/// ```text
/// cargo test -p q-periapt-policy-agent -- --ignored --test-threads=1
/// ```
///
/// Verified in both directions when the unlink was added: without it this fails
/// with `failed create left .../brick.redb behind`.
#[test]
#[ignore = "manipulates the process-wide umask; run with --test-threads=1"]
fn failed_private_file_create_leaves_no_leaf_behind() -> TestResult {
    use rustix::fs::Mode;
    use rustix::process::umask;

    let directory = TestDirectory::new()?;
    let path = directory.join("brick.redb");
    // umask 0o200 strips the owner-write bit, so O_CREAT yields mode 0400 and
    // the exact-mode check rejects it after the leaf already exists.
    let previous = umask(Mode::WUSR);
    let outcome = open_private_file(&path, true);
    umask(previous);
    assert!(
        matches!(outcome, Err(PrivateFileError)),
        "expected the exact-mode check to reject a 0400 leaf"
    );
    assert!(
        !path.exists(),
        "failed create left {path:?} behind; provisioning would be bricked"
    );
    // A retry under a sane umask must now succeed.
    drop(
        open_private_file(&path, true)
            .map_err(|_| io::Error::other("retry after a cleaned-up failure must succeed"))?,
    );
    Ok(())
}

#[test]
fn private_state_file_is_opened_beneath_an_owned_descriptor_boundary() -> TestResult {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = TestDirectory::new()?;
    let valid_path = directory.join("valid.redb");
    let mut valid = open_private_file(&valid_path, true)
        .map_err(|_| io::Error::other("failed to create private test state"))?;
    valid.write_all(&[1])?;
    valid.sync_all()?;
    drop(valid);
    drop(
        open_private_file(&valid_path, false)
            .map_err(|_| io::Error::other("failed to reopen private test state"))?,
    );

    let empty_path = directory.join("empty.redb");
    drop(
        open_private_file(&empty_path, true)
            .map_err(|_| io::Error::other("failed to create empty private test state"))?,
    );
    assert!(matches!(
        open_private_file(&empty_path, false),
        Err(PrivateFileError)
    ));
    assert_eq!(fs::metadata(&empty_path)?.len(), 0);

    assert!(matches!(
        open_private_file(Path::new("relative.redb"), true),
        Err(PrivateFileError)
    ));

    let nested = directory.join("nested");
    fs::create_dir(&nested)?;
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))?;
    assert!(matches!(
        open_private_file(&nested.join("..").join("traversal.redb"), true),
        Err(PrivateFileError)
    ));

    let insecure = directory.join("insecure");
    fs::create_dir(&insecure)?;
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        open_private_file(&insecure.join("state.redb"), true),
        Err(PrivateFileError)
    ));

    let real_parent = directory.join("real-parent");
    fs::create_dir(&real_parent)?;
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))?;
    let alias_parent = directory.join("alias-parent");
    symlink(&real_parent, &alias_parent)?;
    assert!(matches!(
        open_private_file(&alias_parent.join("state.redb"), true),
        Err(PrivateFileError)
    ));

    let target = directory.join("target.redb");
    let mut target_file = open_private_file(&target, true)
        .map_err(|_| io::Error::other("failed to create symlink target"))?;
    target_file.write_all(&[1])?;
    target_file.sync_all()?;
    drop(target_file);
    let alias_file = directory.join("alias.redb");
    symlink(&target, &alias_file)?;
    assert!(matches!(
        open_private_file(&alias_file, false),
        Err(PrivateFileError)
    ));

    let private_directory = OwnedPrivateDirectory::open(directory.path())
        .map_err(|_| io::Error::other("failed to pin private test directory"))?;
    assert!(private_directory.open_config_file("alias.redb", 1).is_err());

    let config_path = directory.join("config.bin");
    let mut config = open_private_file(&config_path, true)
        .map_err(|_| io::Error::other("failed to create private config"))?;
    config.write_all(&[1])?;
    config.sync_all()?;
    drop(config);
    let mut pinned_config = private_directory
        .open_config_file("config.bin", 1)
        .map_err(|_| io::Error::other("failed to open pinned private config"))?;
    let moved_config = directory.join("moved-config.bin");
    fs::rename(&config_path, &moved_config)?;
    let mut replacement = open_private_file(&config_path, true)
        .map_err(|_| io::Error::other("failed to create replacement config"))?;
    replacement.write_all(&[2])?;
    replacement.sync_all()?;
    drop(replacement);
    let mut original = [0u8; 1];
    pinned_config.read_exact(&mut original)?;
    assert_eq!(original, [1]);

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))?;
    assert!(private_directory.open_config_file("config.bin", 1).is_err());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_extended_acls_are_rejected_even_when_posix_modes_remain_private() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let file_directory = TestDirectory::new()?;
    let private_directory = OwnedPrivateDirectory::open(file_directory.path())
        .map_err(|_| io::Error::other("failed to pin ACL test directory"))?;
    let state_path = file_directory.join("state.redb");
    let mut state = open_private_file(&state_path, true)
        .map_err(|_| io::Error::other("failed to create ACL test state"))?;
    state.write_all(&[1])?;
    state.sync_all()?;
    drop(state);

    install_macos_test_acl(&state_path, "everyone allow read")?;
    assert_eq!(
        fs::metadata(&state_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert!(matches!(
        open_private_file(&state_path, false),
        Err(PrivateFileError)
    ));
    assert!(private_directory.open_config_file("state.redb", 1).is_err());

    let acl_directory = TestDirectory::new()?;
    install_macos_test_acl(acl_directory.path(), "everyone allow list,search")?;
    assert_eq!(
        fs::metadata(acl_directory.path())?.permissions().mode() & 0o777,
        0o700
    );
    assert!(matches!(
        OwnedPrivateDirectory::open(acl_directory.path()),
        Err(PrivateFileError)
    ));
    Ok(())
}

#[test]
fn witness_store_rejects_an_applied_receipt_ahead_of_its_head() -> TestResult {
    // A receipt saying Applied(H0 -> H1) beside a recorded head of H0 is a store
    // that holds proof it advanced past the head it reports. That is what a tear
    // between the receipt write and the head update looks like, and what a
    // rollback of the head alone looks like. Counting rows and checking that
    // each is filed under its own operation id both pass on it, because neither
    // ever compares a receipt against the head.
    //
    // It matters because the witness would then answer read_head() with H0 while
    // already having applied H0 -> H1. A second, different advance from H0 under
    // a fresh operation id is not a replay of anything, so nothing else would
    // stop it, and the lineage the witness exists to keep single would fork.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([43u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([44u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [7u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    // The advance the receipt claims was applied, one generation past the head
    // the store still records.
    let next = StateRevision::new(2, 2, [8u8; 32])?;
    let intent = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(TransitionKind::Advance, initial.revision(), next)?,
        initial.fence(),
        FenceToken::generate()?,
    )?;
    crate::witness::test_support::record_applied_receipt_ahead_of_head(&database, intent)
        .map_err(|_| io::Error::other("failed to stage the torn store"))?;

    let (witness_sk_again, _) = MlDsa65::generate([44u8; 32]);
    assert!(
        ReferenceWitnessServer::open(
            &database,
            client_vk,
            ZeroizingBytes::from_bytes(witness_sk_again),
            witness_vk,
            Duration::from_secs(2),
        )
        .is_err(),
        "a store holding an applied receipt ahead of its own head must be refused"
    );
    Ok(())
}

#[test]
fn witness_store_rejects_a_same_generation_head_that_forks_from_its_applied_receipt() -> TestResult
{
    // The strictly-greater-generation check catches a head left *behind* an
    // applied receipt. It says nothing about a head at the *same* generation
    // as the receipt that names a different digest or fence. Row counting and
    // per-key filing both pass on that store too, because neither compares a
    // receipt against the head -- yet `read_head` would then report one head
    // while `query_receipt` reports an applied advance to a different head at
    // the same generation. That is a forked lineage the witness must refuse at
    // open, not answer from.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([45u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([46u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [9u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    // An applied advance to generation 2 with digest [10], beside a recorded
    // head at generation 2 with digest [11] and an unrelated fence.
    let applied_next = StateRevision::new(2, 2, [10u8; 32])?;
    let intent = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(TransitionKind::Advance, initial.revision(), applied_next)?,
        initial.fence(),
        FenceToken::generate()?,
    )?;
    let forked_head = StateHead::new(
        StateRevision::new(2, 2, [11u8; 32])?,
        FenceToken::generate()?,
    );
    crate::witness::test_support::record_applied_receipt_with_forked_same_generation_head(
        &database,
        intent,
        forked_head,
    )
    .map_err(|_| io::Error::other("failed to stage the forked store"))?;

    let (witness_sk_again, _) = MlDsa65::generate([46u8; 32]);
    assert!(
        ReferenceWitnessServer::open(
            &database,
            client_vk,
            ZeroizingBytes::from_bytes(witness_sk_again),
            witness_vk,
            Duration::from_secs(2),
        )
        .is_err(),
        "a same-generation head that disagrees with its applied receipt must be refused"
    );
    Ok(())
}

#[test]
fn witness_store_rejects_a_semantically_damaged_database_at_open() -> TestResult {
    // redb's check_integrity proves only that its own structure is sound. A
    // recorded operation count that disagrees with the rows actually present is
    // worse than a late failure: capacity is enforced against that counter, so
    // an under-reporting store would let the explicit operation limit be
    // exceeded. It must be refused at open.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([41u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([42u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    crate::witness::test_support::desynchronize_operation_count(&database)
        .map_err(|_| io::Error::other("failed to stage the damaged store"))?;

    assert!(
        ReferenceWitnessServer::open(
            &database,
            client_vk,
            ZeroizingBytes::from_bytes(MlDsa65::generate([42u8; 32]).0),
            MlDsa65::generate([42u8; 32]).1,
            Duration::from_secs(2),
        )
        .is_err(),
        "a store whose operation count disagrees with its rows must be refused"
    );
    let _ = witness_vk;
    Ok(())
}

#[test]
fn witness_store_refuses_a_corrupted_primary_without_touching_it() -> TestResult {
    // Recovery is allowed to run on open, so this pins the property that makes
    // that safe: with two-phase commit, redb never falls back to the older
    // commit slot. A corrupted primary is refused outright, and the file is
    // left byte-identical for forensics rather than "repaired" into something
    // else.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([47u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([48u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [12u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    mark_redb_primary_slot_corrupted(&database)?;
    let before_open = fs::read(&database)?;
    let (witness_sk_again, _) = MlDsa65::generate([48u8; 32]);
    assert!(
        ReferenceWitnessServer::open(
            &database,
            client_vk,
            ZeroizingBytes::from_bytes(witness_sk_again),
            witness_vk,
            Duration::from_secs(2),
        )
        .is_err(),
        "a corrupted two-phase primary must be refused, not recovered from an older slot"
    );
    assert_eq!(
        fs::read(&database)?,
        before_open,
        "refusing must not modify the file"
    );
    Ok(())
}

#[test]
fn repository_refuses_a_corrupted_primary_without_touching_it() -> TestResult {
    let directory = TestDirectory::new()?;
    let path = directory.join("repository.redb");
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let (repository, _head) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    drop(repository);

    mark_redb_primary_slot_corrupted(&path)?;
    let before_open = fs::read(&path)?;
    assert!(
        matches!(
            StateRepository::open_existing(&path, migration.roots.clone()),
            Err(crate::repository::RepositoryError::CorruptStore)
        ),
        "a corrupted two-phase primary must be refused, not recovered from an older slot"
    );
    assert_eq!(
        fs::read(&path)?,
        before_open,
        "refusing must not modify the file"
    );
    Ok(())
}

#[test]
fn authority_store_refuses_a_corrupted_primary_without_touching_it() -> TestResult {
    // The authority store used to refuse recovery altogether, which also
    // refused every ordinary crash. What it actually needs to refuse is this.
    let directory = TestDirectory::new()?;
    let path = directory.join("authority.redb");
    let head = StateHeadV2::new(
        StateRevisionV2::new(1, [41u8; 32], 1, [43u8; 32])?,
        StateFenceV2::from_bytes([44u8; 32])?,
    );
    let config = DeploymentConfigRevisionV2::new(1, [45u8; 32])?;
    let store = crate::authority_store::AuthorityStoreV2::provision(
        &path,
        head,
        config,
        AuthorityLimitsV2::new(8, 4, 4, 10_000)?,
    )?;
    drop(store);

    mark_redb_primary_slot_corrupted(&path)?;
    let before_open = fs::read(&path)?;
    assert!(
        matches!(
            crate::authority_store::AuthorityStoreV2::open(&path),
            Err(crate::authority_store::AuthorityStoreErrorV2::CorruptStore)
        ),
        "a corrupted two-phase primary must be refused, not recovered from an older slot"
    );
    assert_eq!(
        fs::read(&path)?,
        before_open,
        "refusing must not modify the file"
    );
    Ok(())
}

#[test]
fn witness_store_reopens_after_a_real_crash_with_its_last_commit_intact() -> TestResult {
    // redb asks for its crash recovery after any unclean shutdown, and the
    // store lets it run (see WitnessStore::open). Only a real crash after a
    // real commit reaches that path -- a header flag flipped on a cleanly
    // closed file does not -- so the child process commits one advance through
    // the production path and exits without running destructors. The advance
    // must survive: recovery reconstructs allocator metadata, never committed
    // data.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([49u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([50u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [13u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::durable_store::witness_crash_after_commit_child")
        .env("Q_PERIAPT_TEST_WITNESS_CRASH", &database)
        .status()?;
    assert_eq!(status.code(), Some(86));
    assert_redb_file_left_unclean(&database)?;

    // The production open path recovers, and the advance the child committed
    // is what it recovers to.
    let head = crate::witness::test_support::open_head(&database)
        .map_err(|_| io::Error::other("a crashed witness store could not be reopened"))?;
    assert_eq!(head.revision(), StateRevision::new(2, 2, [14u8; 32])?);
    let (witness_sk_again, _) = MlDsa65::generate([50u8; 32]);
    ReferenceWitnessServer::open(
        &database,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk_again),
        witness_vk,
        Duration::from_secs(2),
    )
    .map_err(|_| io::Error::other("the witness server could not open the recovered store"))?;
    Ok(())
}

#[test]
fn witness_crash_after_commit_child() -> TestResult {
    let Some(path) = std::env::var_os("Q_PERIAPT_TEST_WITNESS_CRASH") else {
        return Ok(());
    };
    let path = PathBuf::from(path);
    let head = crate::witness::test_support::open_head(&path)?;
    let intent = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(
            TransitionKind::Advance,
            head.revision(),
            StateRevision::new(2, 2, [14u8; 32])?,
        )?,
        head.fence(),
        FenceToken::generate()?,
    )?;
    // Exits with 86 while the store is still open; returns only on failure.
    crate::witness::test_support::open_and_compare_then_exit(&path, intent, 86)?;
    Err(io::Error::other("the witness crash child did not exit").into())
}

#[test]
fn authority_store_reopens_after_a_real_crash_with_its_last_commit_intact() -> TestResult {
    // This store used to refuse redb's crash recovery and had no test that it
    // survives the one thing that triggers it: a crash after a commit. It did
    // not -- a crashed authority stayed down until an operator intervened, and
    // the service that grants every instance lease took every agent down with
    // it. Now the crash is recovered and the child's commit survives it.
    let directory = TestDirectory::new()?;
    let path = directory.join("authority.redb");
    let head = StateHeadV2::new(
        StateRevisionV2::new(1, [41u8; 32], 1, [43u8; 32])?,
        StateFenceV2::from_bytes([44u8; 32])?,
    );
    let config = DeploymentConfigRevisionV2::new(1, [45u8; 32])?;
    let mut store = crate::authority_store::AuthorityStoreV2::provision(
        &path,
        head,
        config,
        AuthorityLimitsV2::new(8, 4, 4, 10_000)?,
    )?;
    let before = store.snapshot()?;
    drop(store);

    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::durable_store::authority_crash_after_commit_child")
        .env("Q_PERIAPT_TEST_AUTHORITY_CRASH", &path)
        .status()?;
    assert_eq!(status.code(), Some(86));
    assert_redb_file_left_unclean(&path)?;

    let mut reopened = crate::authority_store::AuthorityStoreV2::open(&path)
        .map_err(|_| io::Error::other("a crashed authority store could not be reopened"))?;
    let after = reopened.snapshot()?;
    // The acquire the child committed survived, and nothing else moved.
    assert_eq!(after.lease_generation(), before.lease_generation() + 1);
    assert_eq!(after.state_head(), before.state_head());
    assert_eq!(after.config(), before.config());
    Ok(())
}

#[test]
fn authority_crash_after_commit_child() -> TestResult {
    let Some(path) = std::env::var_os("Q_PERIAPT_TEST_AUTHORITY_CRASH") else {
        return Ok(());
    };
    let mut store = crate::authority_store::AuthorityStoreV2::open(Path::new(&path))?;
    let snapshot = store.snapshot()?;
    let intent = AuthorityIntentV2::new(
        OperationIdV2::new(snapshot.authority_version(), [7u8; 32])?,
        snapshot.authority_version(),
        snapshot.config(),
        crate::authority::AuthorityMutationV2::AcquireLease {
            expected_lease_generation: snapshot.lease_generation(),
            instance_id: crate::authority::ProcessInstanceIdV2::from_bytes([9u8; 32])?,
        },
    )?;
    let receipt = store.apply(intent)?;
    assert!(matches!(
        receipt.disposition(),
        crate::authority::AuthorityDispositionV2::Applied
    ));
    std::process::exit(86);
}

#[test]
fn redb_lock_rejects_a_second_agent_repository_open() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("repository.redb");
    let (repository, _) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    assert!(matches!(
        StateRepository::open_existing(&path, migration.roots),
        Err(crate::RepositoryError::CorruptStore)
    ));
    drop(repository);
    Ok(())
}

#[test]
fn witness_store_refuses_an_unclean_file_from_a_non_two_phase_writer() -> TestResult {
    // Letting redb recover on open is safe only because every commit here is
    // two-phase, so redb can never fall back to the older commit slot. A file
    // marked unclean *without* the two-phase flag was last written by
    // something else, and redb would recover it through exactly the
    // slot-picking branch that argument excludes. It is refused before redb
    // sees it, and left byte-identical.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([53u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([54u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [15u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    mark_redb_file_unclean_without_two_phase(&database)?;
    let before_open = fs::read(&database)?;
    let (witness_sk_again, _) = MlDsa65::generate([54u8; 32]);
    assert!(
        ReferenceWitnessServer::open(
            &database,
            client_vk,
            ZeroizingBytes::from_bytes(witness_sk_again),
            witness_vk,
            Duration::from_secs(2),
        )
        .is_err(),
        "an unclean file from a non-two-phase writer must be refused, not recovered"
    );
    assert_eq!(
        fs::read(&database)?,
        before_open,
        "refusing must not modify the file"
    );
    Ok(())
}

#[test]
fn repository_refuses_an_unclean_file_from_a_non_two_phase_writer() -> TestResult {
    let directory = TestDirectory::new()?;
    let path = directory.join("repository.redb");
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let (repository, _head) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    drop(repository);

    mark_redb_file_unclean_without_two_phase(&path)?;
    let before_open = fs::read(&path)?;
    assert!(
        matches!(
            StateRepository::open_existing(&path, migration.roots.clone()),
            Err(crate::repository::RepositoryError::CorruptStore)
        ),
        "an unclean file from a non-two-phase writer must be refused, not recovered"
    );
    assert_eq!(
        fs::read(&path)?,
        before_open,
        "refusing must not modify the file"
    );
    Ok(())
}

#[test]
fn authority_store_refuses_an_unclean_file_from_a_non_two_phase_writer() -> TestResult {
    // This is the half of the authority store's former refuse-all-repair test
    // that is still worth keeping, now enforced for all three stores.
    let directory = TestDirectory::new()?;
    let path = directory.join("authority.redb");
    let head = StateHeadV2::new(
        StateRevisionV2::new(1, [41u8; 32], 1, [43u8; 32])?,
        StateFenceV2::from_bytes([44u8; 32])?,
    );
    let config = DeploymentConfigRevisionV2::new(1, [45u8; 32])?;
    let store = crate::authority_store::AuthorityStoreV2::provision(
        &path,
        head,
        config,
        AuthorityLimitsV2::new(8, 4, 4, 10_000)?,
    )?;
    drop(store);

    mark_redb_file_unclean_without_two_phase(&path)?;
    let before_open = fs::read(&path)?;
    assert!(
        matches!(
            crate::authority_store::AuthorityStoreV2::open(&path),
            Err(crate::authority_store::AuthorityStoreErrorV2::CorruptStore)
        ),
        "an unclean file from a non-two-phase writer must be refused, not recovered"
    );
    assert_eq!(
        fs::read(&path)?,
        before_open,
        "refusing must not modify the file"
    );
    Ok(())
}

/// A freshly provisioned agent store, for the lease-intent journal tests.
fn provisioned_agent_store(directory: &TestDirectory) -> TestResult<(PathBuf, MigrationMaterial)> {
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("agent.redb");
    let (repository, _) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    drop(repository);
    Ok((path, migration))
}

fn lease_operation(byte: u8) -> TestResult<OperationIdV2> {
    Ok(OperationIdV2::new(1, [byte; 32])?)
}

#[test]
fn journal_lease_intent_is_bounded_and_forgets_in_the_same_transaction() -> TestResult {
    let directory = TestDirectory::new()?;
    let (path, migration) = provisioned_agent_store(&directory)?;
    let repository = StateRepository::open_existing(&path, migration.roots.clone())?;
    let bound = u8::try_from(MAX_JOURNALED_LEASE_INTENTS)?;
    for byte in 1..=bound {
        repository.journal_lease_intent(lease_operation(byte)?, &[])?;
    }
    assert_eq!(
        repository.journaled_lease_intents()?.len(),
        usize::from(bound)
    );

    // One past the bound is refused with nothing to forget ...
    let overflow = lease_operation(bound + 1)?;
    assert_eq!(
        repository.journal_lease_intent(overflow, &[]),
        Err(RepositoryError::CapacityExceeded)
    );
    assert_eq!(
        repository.journaled_lease_intents()?.len(),
        usize::from(bound)
    );

    // ... and accepted when the same write forgets a settled row: the
    // deletion and the insertion are one transaction, so the row count never
    // exceeds the bound and the settled row is gone.
    let first = lease_operation(1)?;
    repository.journal_lease_intent(overflow, &[first])?;
    let journaled = repository.journaled_lease_intents()?;
    assert_eq!(journaled.len(), usize::from(bound));
    assert!(!journaled.contains(&first));
    assert!(journaled.contains(&overflow));

    // Forgetting is durable and indifferent to ids that are already gone.
    repository.forget_lease_intents(&[first, lease_operation(2)?])?;
    assert_eq!(
        repository.journaled_lease_intents()?.len(),
        usize::from(bound) - 1
    );
    drop(repository);
    let reopened = StateRepository::open_existing(&path, migration.roots)?;
    assert_eq!(
        reopened.journaled_lease_intents()?.len(),
        usize::from(bound) - 1
    );
    Ok(())
}

#[test]
fn a_store_provisioned_before_the_lease_journal_opens_and_journals() -> TestResult {
    // The journal table is additive. A store from before it existed has no
    // such table, opens all the same, reports an empty journal, and gets the
    // table from the first journal write -- which the agent's own acquire
    // performs at start.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 93)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(responder);
    initiator.release_instance_lease()?;
    drop(initiator);

    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    repository.drop_lease_journal_table_for_test()?;
    assert!(!repository.lease_journal_table_exists_for_test()?);
    drop(repository);

    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    assert!(!repository.lease_journal_table_exists_for_test()?);
    assert!(repository.journaled_lease_intents()?.is_empty());

    let restarted = PolicyAgent::new(
        repository,
        witness,
        initiator_authority.clone(),
        initiator_config,
    )?;
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 1);
    assert_eq!(
        restarted.reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::NoPendingTransition))
    );
    assert_eq!(restarted.journaled_lease_intents_for_test()?.len(), 1);
    assert_eq!(initiator_authority.receipt_count()?, 0);
    Ok(())
}

#[test]
fn a_lease_journal_beyond_its_bound_is_refused_at_open() -> TestResult {
    // Every row is well-formed; only the count is wrong. The bound is what the
    // service relies on to keep its in-memory bookkeeping finite, so a store
    // that breaks it is refused rather than trusted.
    let directory = TestDirectory::new()?;
    let (path, migration) = provisioned_agent_store(&directory)?;
    let repository = StateRepository::open_existing(&path, migration.roots.clone())?;
    let bound = u8::try_from(MAX_JOURNALED_LEASE_INTENTS)?;
    let mut keys = Vec::new();
    for byte in 1..=bound + 1 {
        keys.push(crate::authority_codec::encode_operation_id(
            lease_operation(byte)?,
        ));
    }
    let tag = [1u8];
    let rows: Vec<(&[u8], &[u8])> = keys
        .iter()
        .map(|key| (key.as_slice(), tag.as_slice()))
        .collect();
    repository.write_raw_lease_journal_rows_for_test(&rows)?;
    drop(repository);
    assert_eq!(
        StateRepository::open_existing(&path, migration.roots).err(),
        Some(RepositoryError::CorruptStore)
    );
    Ok(())
}

#[test]
fn a_malformed_lease_journal_row_is_refused_at_open() -> TestResult {
    // A key that is not a canonical operation id, or a value that is not the
    // one tag the journal writes, is a store nothing in this crate produced.
    let directory = TestDirectory::new()?;
    let (path, migration) = provisioned_agent_store(&directory)?;
    let repository = StateRepository::open_existing(&path, migration.roots.clone())?;
    let short_key = [0x5Au8; 39];
    let tag = [1u8];
    repository.write_raw_lease_journal_rows_for_test(&[(short_key.as_slice(), tag.as_slice())])?;
    drop(repository);
    assert_eq!(
        StateRepository::open_existing(&path, migration.roots.clone()).err(),
        Some(RepositoryError::CorruptStore)
    );

    let (path, migration) = {
        let policy = policy_material(20)?;
        let migration = migration_material(&policy.authenticated)?;
        let path = directory.join("agent-bad-tag.redb");
        let (repository, _) =
            StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
        drop(repository);
        (path, migration)
    };
    let repository = StateRepository::open_existing(&path, migration.roots.clone())?;
    let key = crate::authority_codec::encode_operation_id(lease_operation(1)?);
    let unknown_tag = [2u8];
    repository
        .write_raw_lease_journal_rows_for_test(&[(key.as_slice(), unknown_tag.as_slice())])?;
    drop(repository);
    assert_eq!(
        StateRepository::open_existing(&path, migration.roots).err(),
        Some(RepositoryError::CorruptStore)
    );
    Ok(())
}
