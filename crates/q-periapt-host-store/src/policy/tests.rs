use super::*;
use crate::filesystem::LockedFileBackend as FileBackend;
use q_periapt_backends::MlDsa65;
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;
use redb::StorageBackend;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn StdError>>;
struct Signed {
    policy: Vec<u8>,
    signature: Vec<u8>,
    root: Vec<u8>,
}
fn signed(version: u32, enabled: bool) -> Signed {
    signed_by(version, enabled, 91)
}
fn signed_by(version: u32, enabled: bool, seed: u8) -> Signed {
    let kems = if enabled {
        "\"ML-KEM-768\", \"X25519\""
    } else {
        "\"ML-KEM-1024\", \"X25519\""
    };
    let policy = format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [{kems}]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n").into_bytes();
    let (key, root) = MlDsa65::generate([seed; 32]);
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &key,
            &policy_signature_message(&policy),
            &[0; 32],
            &mut signature,
        )
        .expect("test signature");
    Signed {
        policy,
        signature,
        root: root.to_vec(),
    }
}
fn directory() -> io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("sdk-policy-store-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}
fn provision(path: &Path, document: &Signed) -> std::result::Result<PolicyStore, StoreError> {
    PolicyStore::provision(
        path,
        &document.policy,
        &document.signature,
        &document.root,
        Limits::default(),
    )
}

#[test]
fn max_version_exhaustion_is_durable_and_not_a_bootstrap_fallback() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("exhausted.redb");
    let initial = signed(u32::MAX - 1, true);
    let exhausted = signed(u32::MAX, true);
    let same_version_revocation = signed(u32::MAX, false);
    let lower = signed(1, false);
    let mut store = provision(&path, &initial)?;
    let previous = store.runtime()?;
    let current = store.replace_policy(
        previous.trusted_state(),
        &exhausted.policy,
        &exhausted.signature,
    )?;
    assert!(matches!(
        previous.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    let floor = current.trusted_state();
    let binding = current.policy_binding()?;
    assert_eq!(floor.version(), u32::MAX);
    assert!(current.is_enabled()?);

    // A different document at the same version is equivocation, including an
    // otherwise valid emergency-disable document. Lower versions are rollback.
    for rejected in [&same_version_revocation, &lower] {
        assert!(matches!(
            store.replace_policy(floor, &rejected.policy, &rejected.signature),
            Err(StoreError::Policy(q_periapt_sdk::Error::PolicyDenied))
        ));
        assert_eq!(store.runtime()?.policy_binding()?, binding);
        assert!(current.is_enabled()?);
    }
    store.close();
    assert!(matches!(
        current.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    assert!(matches!(
        PolicyStore::open_configured(
            &path,
            &lower.policy,
            &lower.signature,
            &initial.root,
            Limits::default()
        ),
        Err(StoreError::Policy(q_periapt_sdk::Error::PolicyDenied))
    ));

    let reopened = PolicyStore::open(&path, &initial.root, Limits::default())?;
    assert_eq!(reopened.runtime()?.trusted_state(), floor);
    assert!(reopened.runtime()?.is_enabled()?);
    drop(reopened);

    // A separately valid root/policy cannot select itself as the store's root.
    // Recovery will need its own previously provisioned authorization boundary.
    let (new_key, new_root) = MlDsa65::generate([92; 32]);
    let mut new_signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &new_key,
            &policy_signature_message(&lower.policy),
            &[0; 32],
            &mut new_signature,
        )
        .map_err(|error| io::Error::other(format!("new-root policy signature: {error:?}")))?;
    assert_ne!(new_root.as_slice(), initial.root.as_slice());
    assert!(!Runtime::from_signed_policy(
        &lower.policy,
        &new_signature,
        &new_root,
        None,
        Limits::default()
    )?
    .is_enabled()?);
    assert!(matches!(
        PolicyStore::open(&path, &new_root, Limits::default()),
        Err(StoreError::RootMismatch)
    ));
    let unchanged = PolicyStore::open(&path, &initial.root, Limits::default())?;
    assert_eq!(unchanged.runtime()?.policy_binding()?, binding);
    Ok(())
}

#[test]
fn borrowed_runtimes_cannot_prepare_updates_outside_the_durable_owner() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("policy.redb");
    let initial = signed(3, true);
    let revoked = signed(4, false);
    let enabled = signed(5, true);
    let mut store = provision(&path, &initial)?;
    let original = store.runtime()?;
    assert!(
        matches!(
            original.prepare_policy_update(&revoked.policy, &revoked.signature),
            Err(q_periapt_sdk::Error::UpdateOwnerRequired)
        ),
        "an operational store alias issued an in-memory update capability"
    );
    assert_eq!(store.runtime()?.trusted_state().version(), 3);
    assert!(original.is_enabled()?);
    let replacement = store.replace_policy(
        original.trusted_state(),
        &revoked.policy,
        &revoked.signature,
    )?;
    assert!(matches!(
        original.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    assert!(!replacement.is_enabled()?);
    assert!(matches!(
        replacement.prepare_policy_update(&enabled.policy, &enabled.signature),
        Err(q_periapt_sdk::Error::UpdateOwnerRequired)
    ));
    store.close();
    assert!(matches!(
        replacement.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    let mut reopened = PolicyStore::open(&path, &initial.root, Limits::default())?;
    let current = reopened.runtime()?;
    assert_eq!(current.trusted_state().version(), 4);
    assert!(!current.is_enabled()?);
    assert!(matches!(
        current.prepare_policy_update(&enabled.policy, &enabled.signature),
        Err(q_periapt_sdk::Error::UpdateOwnerRequired)
    ));
    let active =
        reopened.replace_policy(current.trusted_state(), &enabled.policy, &enabled.signature)?;
    assert!(active.is_enabled()?);
    drop(reopened);
    assert!(matches!(
        active.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    let final_store = PolicyStore::open(&path, &initial.root, Limits::default())?;
    assert_eq!(final_store.runtime()?.trusted_state().version(), 5);
    assert!(final_store.runtime()?.is_enabled()?);
    Ok(())
}

#[derive(Debug)]
struct GenesisResultLoss;
impl std::fmt::Display for GenesisResultLoss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected policy genesis result loss")
    }
}
impl StdError for GenesisResultLoss {}
thread_local! {
    static LOSE_GENESIS_RESULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
pub(super) fn after_provision_commit() -> std::result::Result<(), StoreError> {
    if LOSE_GENESIS_RESULT.with(|flag| flag.replace(false)) {
        Err(StoreError::CommitUncertain(redb::CommitError::Storage(
            redb::StorageError::Io(io::Error::other(GenesisResultLoss)),
        )))
    } else {
        Ok(())
    }
}
struct GenesisFailureGuard;
impl Drop for GenesisFailureGuard {
    fn drop(&mut self) {
        LOSE_GENESIS_RESULT.with(|flag| flag.set(false));
    }
}

#[test]
fn unknown_policy_genesis_result_preserves_the_actual_signed_sdk_runtime() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("policy.redb");
    let document = signed(3, true);
    let expected = Runtime::from_signed_policy(
        &document.policy,
        &document.signature,
        &document.root,
        None,
        Limits::default(),
    )?
    .trusted_state();
    LOSE_GENESIS_RESULT.with(|flag| {
        assert!(!flag.replace(true));
    });
    let guard = GenesisFailureGuard;
    let result = provision(&path, &document);
    assert!(
        matches!(result, Err(StoreError::CommitUncertain(redb::CommitError::Storage(
        redb::StorageError::Io(ref error)))) if error.get_ref().is_some_and(|cause| cause.is::<GenesisResultLoss>()))
    );
    assert!(
        !LOSE_GENESIS_RESULT.with(|flag| flag.get()),
        "exact post-commit failure was not exercised"
    );
    drop(guard);
    assert!(
        path.exists(),
        "a lost creation result erased a committed signed image"
    );
    let retained = std::fs::read(&path)?;
    assert!(matches!(
        provision(&path, &document),
        Err(StoreError::PrivateFile)
    ));
    assert_eq!(std::fs::read(&path)?, retained);
    let mut reopened = PolicyStore::open(&path, &document.root, Limits::default())?;
    let runtime = reopened.runtime()?;
    assert_eq!(runtime.trusted_state(), expected);
    let key = runtime.generate_key()?;
    key.public_key()?;
    reopened.close();
    assert!(matches!(
        runtime.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    assert!(matches!(
        key.public_key(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    Ok(())
}

#[test]
fn signed_update_revocation_recovery_and_close_preserve_owned_lifetimes() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("policy.redb");
    let initial = signed(1, true);
    let disabled = signed(2, false);
    let enabled = signed(3, true);
    let mut store = provision(&path, &initial)?;
    let runtime = store.runtime()?;
    let key = runtime.generate_key()?;
    let next = store.replace_policy(
        runtime.trusted_state(),
        &disabled.policy,
        &disabled.signature,
    )?;
    assert!(!next.is_enabled()?);
    assert!(matches!(
        runtime.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    assert!(matches!(
        key.public_key(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    drop(store);
    assert!(matches!(
        next.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    let mut reopened = PolicyStore::open(&path, &initial.root, Limits::default())?;
    let revoked = reopened.runtime()?;
    assert!(!revoked.is_enabled()?);
    assert_eq!(revoked.trusted_state().version(), 2);
    let recovered =
        reopened.replace_policy(revoked.trusted_state(), &enabled.policy, &enabled.signature)?;
    assert!(recovered.is_enabled()?);
    assert_eq!(recovered.trusted_state().version(), 3);
    assert!(matches!(
        revoked.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    reopened.close();
    reopened.close();
    assert!(matches!(reopened.runtime(), Err(StoreError::Closed)));
    assert!(matches!(
        recovered.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    Ok(())
}

#[test]
fn rollback_equivocation_bad_signatures_and_stale_callers_do_not_mutate_storage() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("policy.redb");
    let initial = signed(3, true);
    let mut store = provision(&path, &initial)?;
    let runtime = store.runtime()?;
    let expected = runtime.trusted_state();
    let lower = signed(2, true);
    let equivocation = signed(3, false);
    for invalid in [&initial, &lower, &equivocation] {
        assert!(matches!(
            store.replace_policy(expected, &invalid.policy, &invalid.signature),
            Err(StoreError::Policy(_))
        ));
        assert!(runtime.is_enabled()?);
    }
    let mut next = signed(4, true);
    *next.signature.first_mut().ok_or("empty fixture")? ^= 1;
    assert!(matches!(
        store.replace_policy(expected, &next.policy, &next.signature),
        Err(StoreError::Policy(_))
    ));
    let stale = TrustedPolicyState::new(1, [0; 32]).map_err(|_| "invalid test state")?;
    assert!(matches!(
        store.replace_policy(stale, &lower.policy, &lower.signature),
        Err(StoreError::Stale)
    ));
    drop(store);
    let store = PolicyStore::open(&path, &initial.root, Limits::default())?;
    assert_eq!(store.runtime()?.trusted_state(), expected);
    Ok(())
}

#[test]
fn private_directory_no_clobber_no_implicit_bootstrap_and_root_binding() -> Result<()> {
    let folder = directory()?;
    let root = folder.path().canonicalize()?;
    let path = root.join("policy.redb");
    let document = signed(1, true);
    assert!(matches!(
        PolicyStore::open(&path, &document.root, Limits::default()),
        Err(StoreError::PrivateFile)
    ));
    assert!(!path.exists());
    let store = provision(&path, &document)?;
    assert!(matches!(
        provision(&path, &document),
        Err(StoreError::PrivateFile)
    ));
    assert!(matches!(
        PolicyStore::open(&path, &document.root, Limits::default()),
        Err(StoreError::Busy)
    ));
    drop(store);
    let (_, wrong_root) = MlDsa65::generate([92; 32]);
    assert!(matches!(
        PolicyStore::open(&path, &wrong_root, Limits::default()),
        Err(StoreError::RootMismatch)
    ));
    symlink(&path, root.join("link.redb"))?;
    assert!(matches!(
        PolicyStore::open(&root.join("link.redb"), &document.root, Limits::default()),
        Err(StoreError::PrivateFile)
    ));
    std::fs::hard_link(&path, root.join("hard.redb"))?;
    assert!(matches!(
        PolicyStore::open(&path, &document.root, Limits::default()),
        Err(StoreError::PrivateFile)
    ));
    std::fs::remove_file(root.join("hard.redb"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        PolicyStore::open(&path, &document.root, Limits::default()),
        Err(StoreError::PrivateFile)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        PolicyStore::open(&path, &document.root, Limits::default()),
        Err(StoreError::PrivateFile)
    ));
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    assert!(PolicyStore::open(&path, &document.root, Limits::default())?
        .runtime()?
        .is_enabled()?);
    Ok(())
}

#[test]
fn corrupt_or_foreign_images_are_rejected_without_accepting_a_runtime() -> Result<()> {
    let document = signed(1, true);
    for alteration in [
        "state",
        "signature",
        "schema",
        "extra",
        "empty",
        "oversized",
    ] {
        let folder = directory()?;
        let path = folder.path().canonicalize()?.join("policy.redb");
        drop(provision(&path, &document)?);
        if alteration == "empty" || alteration == "oversized" {
            File::options()
                .write(true)
                .open(&path)?
                .set_len(if alteration == "empty" {
                    0
                } else {
                    MAX_DATABASE_BYTES + 1
                })?;
        } else {
            let file = open_private_file(&path, false).map_err(|_| "test private path")?;
            let db = database(file, false)?;
            let transaction = write_transaction(&db)?;
            {
                let mut table = transaction.open_table(TABLE)?;
                table.insert(alteration, b"invalid".as_slice())?;
            }
            transaction.commit()?;
        }
        assert!(
            PolicyStore::open(&path, &document.root, Limits::default()).is_err(),
            "{alteration}"
        );
    }
    Ok(())
}

struct SyncFailure {
    inner: FileBackend,
    armed: Arc<AtomicBool>,
    close_on_sync: Option<Arc<Runtime>>,
}
impl fmt::Debug for SyncFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncFailure").finish_non_exhaustive()
    }
}
impl StorageBackend for SyncFailure {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read(offset, out)
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn try_lock_range(
        &self,
        start: std::ops::Bound<u64>,
        end: std::ops::Bound<u64>,
    ) -> std::result::Result<bool, redb::BackendError> {
        self.inner.try_lock_range(start, end)
    }
    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
    fn sync_data(&self) -> io::Result<()> {
        if self.armed.swap(false, Ordering::SeqCst) {
            if let Some(runtime) = &self.close_on_sync {
                self.inner.sync_data()?;
                runtime.close();
                Ok(())
            } else {
                Err(io::Error::other("injected disk sync failure"))
            }
        } else {
            self.inner.sync_data()
        }
    }
}
#[test]
fn real_file_commit_failure_revokes_old_runtime_and_requires_reconciliation() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("policy.redb");
    let initial = signed(1, true);
    let next = signed(2, false);
    drop(provision(&path, &initial)?);
    let file = open_private_file(&path, false).map_err(|_| "test private path")?;
    let armed = Arc::new(AtomicBool::new(false));
    let database = Database::builder().create_with_backend(SyncFailure {
        inner: FileBackend::new(file)?,
        armed: Arc::clone(&armed),
        close_on_sync: None,
    })?;
    let owner = PolicyOwner::from_signed_policy(
        &initial.policy,
        &initial.signature,
        &initial.root,
        None,
        Limits::default(),
    )?;
    let runtime = owner.runtime()?;
    let mut store = PolicyStore {
        active: Some(Active {
            database,
            owner,
            root: initial.root.clone(),
            recovery: None,
        }),
    };
    armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.replace_policy(runtime.trusted_state(), &next.policy, &next.signature),
        Err(StoreError::CommitUncertain(_))
    ));
    assert!(matches!(
        runtime.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    assert!(matches!(store.runtime(), Err(StoreError::Closed)));
    // A failed commit is not an acknowledgement. Reconcile the exact requested
    // revocation before permitting any use, even if disk recovery found the old image.
    let mut recovered = PolicyStore::open(&path, &initial.root, Limits::default())?;
    let observed = recovered.runtime()?.trusted_state();
    if observed.version() == 1 {
        recovered.replace_policy(observed, &next.policy, &next.signature)?;
    }
    assert_eq!(recovered.runtime()?.trusted_state().version(), 2);
    assert!(!recovered.runtime()?.is_enabled()?);
    Ok(())
}

#[test]
fn persisted_update_survives_activation_failure_without_reviving_old_runtime() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("policy.redb");
    let initial = signed(1, true);
    let next = signed(2, false);
    drop(provision(&path, &initial)?);
    let owner = PolicyOwner::from_signed_policy(
        &initial.policy,
        &initial.signature,
        &initial.root,
        None,
        Limits::default(),
    )?;
    let runtime = owner.runtime()?;
    let armed = Arc::new(AtomicBool::new(false));
    let file = open_private_file(&path, false).map_err(|_| "test private path")?;
    let database = Database::builder().create_with_backend(SyncFailure {
        inner: FileBackend::new(file)?,
        armed: Arc::clone(&armed),
        close_on_sync: Some(Arc::clone(&runtime)),
    })?;
    let mut store = PolicyStore {
        active: Some(Active {
            database,
            owner,
            root: initial.root.clone(),
            recovery: None,
        }),
    };
    armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.replace_policy(runtime.trusted_state(), &next.policy, &next.signature),
        Err(StoreError::ActivationAfterCommit(
            q_periapt_sdk::Error::Closed
        ))
    ));
    assert!(matches!(store.runtime(), Err(StoreError::Closed)));
    assert!(matches!(
        runtime.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    let recovered = PolicyStore::open(&path, &initial.root, Limits::default())?;
    assert_eq!(recovered.runtime()?.trusted_state().version(), 2);
    assert!(!recovered.runtime()?.is_enabled()?);
    Ok(())
}

fn wait(mut child: Child) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("store child exceeded deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn process_lock_and_successful_commit_survive_abrupt_exit() -> Result<()> {
    const MODE: &str = "QPERIAPT_STORE_PROCESS_TEST";
    const PATH: &str = "QPERIAPT_STORE_PROCESS_PATH";
    let initial = signed(1, true);
    if let Ok(mode) = std::env::var(MODE) {
        let path = std::path::PathBuf::from(std::env::var_os(PATH).ok_or("child path missing")?);
        match mode.as_str() {
            "busy" => {
                assert!(matches!(
                    PolicyStore::open(&path, &initial.root, Limits::default()),
                    Err(StoreError::Busy)
                ));
                std::process::exit(41);
            }
            "commit" => {
                let next = signed(2, false);
                let mut store = PolicyStore::open(&path, &initial.root, Limits::default())?;
                let before = store.runtime()?.trusted_state();
                let runtime = store.replace_policy(before, &next.policy, &next.signature)?;
                assert!(!runtime.is_enabled()?);
                // Deliberately bypass Rust Drop and clean database shutdown.
                std::process::exit(42);
            }
            "panic" => {
                let next = signed(3, false);
                let mut store = PolicyStore::open(&path, &initial.root, Limits::default())?;
                let old = store.runtime()?;
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    store.replace_policy(old.trusted_state(), &next.policy, &next.signature)
                }));
                assert!(outcome.is_err(), "post-commit unwind did not run");
                assert!(matches!(store.runtime(), Err(StoreError::Closed)));
                assert!(matches!(
                    old.is_enabled(),
                    Err(q_periapt_sdk::Error::Closed)
                ));
                std::process::exit(43);
            }
            _ => return Err("unknown child mode".into()),
        }
    }
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("policy.redb");
    let store = provision(&path, &initial)?;
    let spawn = |mode: &str| -> io::Result<Child> {
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "policy::tests::process_lock_and_successful_commit_survive_abrupt_exit",
                "--nocapture",
            ])
            .env(MODE, mode)
            .env(PATH, &path)
            .stdin(Stdio::null())
            .spawn()
    };
    assert_eq!(wait(spawn("busy")?)?.code(), Some(41));
    drop(store);
    assert_eq!(wait(spawn("commit")?)?.code(), Some(42));
    let recovered = PolicyStore::open(&path, &initial.root, Limits::default())?;
    assert_eq!(recovered.runtime()?.trusted_state().version(), 2);
    assert!(!recovered.runtime()?.is_enabled()?);
    drop(recovered);
    assert_eq!(wait(spawn("panic")?)?.code(), Some(43));
    let recovered = PolicyStore::open(&path, &initial.root, Limits::default())?;
    assert_eq!(recovered.runtime()?.trusted_state().version(), 3);
    assert!(!recovered.runtime()?.is_enabled()?);
    Ok(())
}
pub(super) fn after_policy_commit() {
    if matches!(
        std::env::var("QPERIAPT_STORE_PROCESS_TEST").as_deref(),
        Ok("panic")
    ) {
        std::panic::resume_unwind(Box::new("injected normal-policy post-commit unwind"));
    }
}

fn recovery_signature(seed: u8, message: &[u8]) -> Result<Vec<u8>> {
    let (key, _) = MlDsa65::generate([seed; 32]);
    let mut out = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(&key, message, &[0; 32], &mut out)
        .map_err(|e| io::Error::other(format!("recovery fixture signature: {e:?}")))?;
    Ok(out)
}
fn recovery_trust(initial: &Signed) -> Result<(PolicyRecoveryTrust, Vec<u8>)> {
    let (_, recovery) = MlDsa65::generate([92; 32]);
    let trust = PolicyRecoveryTrust::new([50; 32], &initial.root, &recovery)?;
    let enrollment = recovery_signature(92, &trust.enrollment_message())?;
    Ok((trust, enrollment))
}
fn recovery_authorization(
    request: PolicyRecoveryRequest,
    incoming_seed: u8,
) -> Result<PolicyRecoveryAuthorization> {
    let approval = recovery_signature(92, &request.authorization_message())?;
    let possession = recovery_signature(incoming_seed, &request.possession_message())?;
    Ok(PolicyRecoveryAuthorization::new(
        request,
        &approval,
        &possession,
    )?)
}

#[test]
fn independent_authority_recovers_max_version_and_retains_original_receipts() -> Result<()> {
    let folder = directory()?;
    let path = folder.path().canonicalize()?.join("recoverable.redb");
    let initial = signed(u32::MAX, true);
    let (trust, enrollment) = recovery_trust(&initial)?;
    let mut store = PolicyStore::provision_recoverable(
        &path,
        &initial.policy,
        &initial.signature,
        &trust,
        &enrollment,
        Limits::default(),
    )?;
    let old = store.runtime()?;
    let old_binding = old.policy_binding()?;
    let old_key = old.generate_key()?;
    let disabled = signed_by(1, false, 93);
    let request = store.prepare_authority_recovery(
        [1; 32],
        &disabled.policy,
        &disabled.signature,
        &disabled.root,
    )?;
    assert_eq!(request.generation(), 1);
    assert_eq!(request.states().0.version(), u32::MAX);
    assert_eq!(request.states().1.version(), 1);
    assert_eq!(request.trust_binding(), trust.binding());
    let authorization = recovery_authorization(request, 93)?;
    let original = authorization.to_bytes();
    assert_eq!(
        store.recover_authority(&authorization, &disabled.policy, &disabled.signature)?,
        PolicyRecoveryOutcome::Applied
    );
    assert!(matches!(
        old.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    assert!(matches!(
        old_key.public_key(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    let current = store.runtime()?;
    assert!(!current.is_enabled()?);
    assert_ne!(current.policy_binding()?, old_binding);
    assert_eq!(
        store.recover_authority(&authorization, &disabled.policy, &disabled.signature)?,
        PolicyRecoveryOutcome::AlreadyApplied
    );
    let enabled = signed_by(2, true, 93);
    assert!(matches!(
        current.prepare_policy_update(&enabled.policy, &enabled.signature),
        Err(q_periapt_sdk::Error::UpdateOwnerRequired)
    ));
    let current =
        store.replace_policy(current.trusted_state(), &enabled.policy, &enabled.signature)?;
    assert!(current.is_enabled()?);
    assert_eq!(
        store.recover_authority(&authorization, &disabled.policy, &disabled.signature)?,
        PolicyRecoveryOutcome::AppliedThenAdvanced
    );
    let next = signed_by(1, true, 94);
    assert!(matches!(
        store.prepare_authority_recovery([1; 32], &next.policy, &next.signature, &next.root),
        Err(StoreError::RecoveryDenied)
    ));
    assert!(matches!(
        store.prepare_authority_recovery(
            [2; 32],
            &initial.policy,
            &initial.signature,
            &initial.root
        ),
        Err(StoreError::RecoveryDenied)
    ));
    let second_request =
        store.prepare_authority_recovery([2; 32], &next.policy, &next.signature, &next.root)?;
    // An independently signed inbound request still cannot revive a historical
    // root. Exercise the accepting boundary, not only the request builder.
    let mut reuse = second_request.to_bytes();
    reuse
        .get_mut(180..180 + ML_DSA_65_VK_LEN)
        .ok_or("root wire field")?
        .copy_from_slice(&initial.root);
    reuse
        .get_mut(180 + ML_DSA_65_VK_LEN..)
        .ok_or("state wire field")?
        .copy_from_slice(&old.trusted_state().encode());
    let reuse = recovery_authorization(PolicyRecoveryRequest::from_bytes(&reuse)?, 91)?;
    assert!(matches!(
        store.recover_authority(&reuse, &initial.policy, &initial.signature),
        Err(StoreError::RecoveryDenied)
    ));
    assert_eq!(store.runtime()?.trusted_state().version(), 2);
    let second = recovery_authorization(second_request, 94)?;
    assert_eq!(
        store.recover_authority(&second, &next.policy, &next.signature)?,
        PolicyRecoveryOutcome::Applied
    );
    assert_eq!(
        store.recover_authority(&authorization, &disabled.policy, &disabled.signature)?,
        PolicyRecoveryOutcome::AppliedThenAdvanced
    );
    drop(store);
    let restored = PolicyRecoveryAuthorization::from_bytes(&original)?;
    let (reopened, outcome) = PolicyStore::open_recovering(
        &path,
        &trust,
        &restored,
        &disabled.policy,
        &disabled.signature,
        Limits::default(),
    )?;
    assert_eq!(outcome, PolicyRecoveryOutcome::AppliedThenAdvanced);
    assert!(reopened.runtime()?.is_enabled()?);
    assert_eq!(reopened.runtime()?.trusted_state().version(), 1);
    drop(reopened);
    let advanced_again = signed_by(2, false, 94);
    let reconciled = PolicyStore::open_recoverable_configured(
        &path,
        &trust,
        &advanced_again.policy,
        &advanced_again.signature,
        Limits::default(),
    )?;
    assert!(!reconciled.runtime()?.is_enabled()?);
    assert_eq!(reconciled.runtime()?.trusted_state().version(), 2);
    drop(reconciled);
    assert!(matches!(
        PolicyStore::open_recoverable_configured(
            &path,
            &trust,
            &next.policy,
            &next.signature,
            Limits::default()
        ),
        Err(StoreError::Policy(q_periapt_sdk::Error::PolicyDenied))
    ));
    assert!(matches!(
        PolicyStore::open(&path, &next.root, Limits::default()),
        Err(StoreError::RecoveryRequired)
    ));
    let (_, recovery_root) = MlDsa65::generate([92; 32]);
    let foreign = PolicyRecoveryTrust::new([51; 32], &initial.root, &recovery_root)?;
    assert!(matches!(
        PolicyStore::open_recoverable(&path, &foreign, Limits::default()),
        Err(StoreError::RootMismatch)
    ));
    Ok(())
}

#[test]
fn recovery_requires_independent_roles_exact_predecessor_and_first_use_enrollment() -> Result<()> {
    let folder = directory()?;
    let root = folder.path().canonicalize()?;
    let initial = signed(1, true);
    let next = signed_by(1, false, 93);
    let (trust, enrollment) = recovery_trust(&initial)?;
    let path = root.join("recoverable.redb");
    let wrong_enrollment = recovery_signature(91, &trust.enrollment_message())?;
    assert!(matches!(
        PolicyStore::provision_recoverable(
            &path,
            &initial.policy,
            &initial.signature,
            &trust,
            &wrong_enrollment,
            Limits::default()
        ),
        Err(StoreError::RecoveryDenied)
    ));
    assert!(!path.exists());
    let mut store = PolicyStore::provision_recoverable(
        &path,
        &initial.policy,
        &initial.signature,
        &trust,
        &enrollment,
        Limits::default(),
    )?;
    let old = store.runtime()?;
    let binding = old.policy_binding()?;
    let request =
        store.prepare_authority_recovery([1; 32], &next.policy, &next.signature, &next.root)?;
    for (authority, incoming, swap_roles) in [(91, 93, false), (92, 91, false), (92, 93, true)] {
        let (a, p) = if swap_roles {
            (
                request.possession_message(),
                request.authorization_message(),
            )
        } else {
            (
                request.authorization_message(),
                request.possession_message(),
            )
        };
        let auth = PolicyRecoveryAuthorization::new(
            request.clone(),
            &recovery_signature(authority, &a)?,
            &recovery_signature(incoming, &p)?,
        )?;
        assert!(matches!(
            store.recover_authority(&auth, &next.policy, &next.signature),
            Err(StoreError::RecoveryDenied)
        ));
        assert_eq!(store.runtime()?.policy_binding()?, binding);
        assert!(old.is_enabled()?);
    }
    let auth = recovery_authorization(request, 93)?;
    let wrong_policy = signed_by(2, false, 93);
    assert!(matches!(
        store.recover_authority(&auth, &wrong_policy.policy, &wrong_policy.signature),
        Err(StoreError::RecoveryDenied)
    ));
    let advanced = signed(2, true);
    store.replace_policy(old.trusted_state(), &advanced.policy, &advanced.signature)?;
    assert!(matches!(
        store.recover_authority(&auth, &next.policy, &next.signature),
        Err(StoreError::Stale)
    ));
    assert!(store.runtime()?.is_enabled()?);
    drop(store);
    assert!(PolicyStore::open_recovering(
        &path,
        &trust,
        &auth,
        &next.policy,
        &next.signature,
        Limits::default()
    )
    .is_err());
    let ordinary = root.join("ordinary.redb");
    drop(provision(&ordinary, &initial)?);
    assert!(matches!(
        PolicyStore::open_recoverable(&ordinary, &trust, Limits::default()),
        Err(StoreError::RecoveryRequired)
    ));
    assert_eq!(
        PolicyStore::open(&ordinary, &initial.root, Limits::default())?
            .runtime()?
            .trusted_state()
            .version(),
        1
    );
    Ok(())
}

#[test]
fn authority_recovery_commit_failures_reconcile_original_authorization() -> Result<()> {
    for close_after_sync in [false, true] {
        let folder = directory()?;
        let path = folder.path().canonicalize()?.join("recoverable.redb");
        let initial = signed(u32::MAX, true);
        let next = signed_by(1, false, 93);
        let (trust, enrollment) = recovery_trust(&initial)?;
        let original = PolicyStore::provision_recoverable(
            &path,
            &initial.policy,
            &initial.signature,
            &trust,
            &enrollment,
            Limits::default(),
        )?;
        let recovery = original
            .active
            .as_ref()
            .ok_or("missing initial owner")?
            .recovery
            .clone();
        let auth = recovery_authorization(
            original.prepare_authority_recovery(
                [1; 32],
                &next.policy,
                &next.signature,
                &next.root,
            )?,
            93,
        )?;
        drop(original);
        let owner = PolicyOwner::from_signed_policy(
            &initial.policy,
            &initial.signature,
            &initial.root,
            None,
            Limits::default(),
        )?;
        let runtime = owner.runtime()?;
        let armed = Arc::new(AtomicBool::new(false));
        let database = Database::builder().create_with_backend(SyncFailure {
            inner: FileBackend::new(open_private_file(&path, false).map_err(|_| "private path")?)?,
            armed: Arc::clone(&armed),
            close_on_sync: close_after_sync.then(|| Arc::clone(&runtime)),
        })?;
        let mut store = PolicyStore {
            active: Some(Active {
                database,
                owner,
                root: initial.root.clone(),
                recovery,
            }),
        };
        armed.store(true, Ordering::SeqCst);
        let error = store.recover_authority(&auth, &next.policy, &next.signature);
        if close_after_sync {
            assert!(matches!(
                error,
                Err(StoreError::ActivationAfterCommit(
                    q_periapt_sdk::Error::Closed
                ))
            ));
        } else {
            assert!(matches!(error, Err(StoreError::CommitUncertain(_))));
        }
        assert!(matches!(
            runtime.is_enabled(),
            Err(q_periapt_sdk::Error::Closed)
        ));
        assert!(matches!(store.runtime(), Err(StoreError::Closed)));
        let (recovered, outcome) = PolicyStore::open_recovering(
            &path,
            &trust,
            &auth,
            &next.policy,
            &next.signature,
            Limits::default(),
        )?;
        if close_after_sync {
            assert_eq!(outcome, PolicyRecoveryOutcome::AlreadyApplied);
        } else {
            assert!(matches!(
                outcome,
                PolicyRecoveryOutcome::Applied | PolicyRecoveryOutcome::AlreadyApplied
            ));
        }
        assert_eq!(recovered.runtime()?.trusted_state().version(), 1);
        assert!(!recovered.runtime()?.is_enabled()?);
    }
    Ok(())
}

#[test]
fn recovered_authority_image_rejects_tampered_metadata() -> Result<()> {
    for field_name in [
        "recovery_trust",
        "recovery_enrollment",
        "recovery_history",
        "recovery_receipt",
        "root",
        "state",
    ] {
        let folder = directory()?;
        let path = folder.path().canonicalize()?.join("recovered.redb");
        let initial = signed(u32::MAX, true);
        let next = signed_by(1, false, 93);
        let (trust, enrollment) = recovery_trust(&initial)?;
        let mut store = PolicyStore::provision_recoverable(
            &path,
            &initial.policy,
            &initial.signature,
            &trust,
            &enrollment,
            Limits::default(),
        )?;
        let auth = recovery_authorization(
            store.prepare_authority_recovery([1; 32], &next.policy, &next.signature, &next.root)?,
            93,
        )?;
        store.recover_authority(&auth, &next.policy, &next.signature)?;
        let later = signed_by(1, false, 94);
        let second = recovery_authorization(
            store.prepare_authority_recovery(
                [2; 32],
                &later.policy,
                &later.signature,
                &later.root,
            )?,
            94,
        )?;
        store.recover_authority(&second, &later.policy, &later.signature)?;
        drop(store);
        let database = database(
            open_private_file(&path, false).map_err(|_| "private test path")?,
            false,
        )?;
        let transaction = write_transaction(&database)?;
        {
            let mut table = transaction.open_table(TABLE)?;
            let mut bytes = table
                .get(field_name)?
                .ok_or("missing metadata field")?
                .value()
                .to_vec();
            if field_name == "recovery_history" {
                // Alter a prior nonzero operation while keeping every root and
                // operation structurally unique. Only the signed history link
                // catches this change to the non-current entry.
                *bytes
                    .get_mut(96 + 32)
                    .ok_or("missing prior history entry")? ^= 1;
            } else {
                *bytes.last_mut().ok_or("empty metadata")? ^= 1;
            }
            table.insert(field_name, bytes.as_slice())?;
        }
        transaction.commit()?;
        drop(database);
        assert!(
            PolicyStore::open_recoverable(&path, &trust, Limits::default()).is_err(),
            "accepted modified {field_name}"
        );
    }
    Ok(())
}

pub(super) fn after_recovery_commit() {
    match std::env::var("QPERIAPT_RECOVERY_PROCESS_CUT").as_deref() {
        // The real redb commit returned; no new runtime has been activated yet.
        Ok("committed") => std::process::exit(72),
        Ok("panicked") => std::panic::resume_unwind(Box::new("injected post-commit unwind")),
        _ => {}
    }
}

#[test]
fn root_recovery_process_cuts_replay_original_authorization() -> Result<()> {
    const MODE: &str = "QPERIAPT_RECOVERY_PROCESS_CUT";
    const STORE_PATH: &str = "QPERIAPT_RECOVERY_PROCESS_PATH";
    let initial = signed(u32::MAX, true);
    let next = signed_by(1, false, 93);
    let (trust, enrollment) = recovery_trust(&initial)?;
    if let Ok(mode) = std::env::var(MODE) {
        let path =
            std::path::PathBuf::from(std::env::var_os(STORE_PATH).ok_or("missing child store")?);
        let wire = std::fs::read(path.with_extension("approval"))?;
        let auth = PolicyRecoveryAuthorization::from_bytes(&wire)?;
        let mut store = PolicyStore::open_recoverable(&path, &trust, Limits::default())?;
        if mode == "prepared" {
            assert_eq!(
                store
                    .prepare_authority_recovery([1; 32], &next.policy, &next.signature, &next.root)?
                    .to_bytes(),
                auth.request().to_bytes()
            );
            std::process::exit(71);
        }
        if mode == "panicked" {
            let old = store.runtime()?;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.recover_authority(&auth, &next.policy, &next.signature)
            }));
            assert!(outcome.is_err(), "post-commit unwind did not run");
            assert!(
                matches!(store.runtime(), Err(StoreError::Closed)),
                "unwound store remained active"
            );
            assert!(
                matches!(old.is_enabled(), Err(q_periapt_sdk::Error::Closed)),
                "unwind retained old permissions"
            );
            std::process::exit(73);
        }
        if mode != "committed" {
            return Err("unknown recovery cut".into());
        }
        store.recover_authority(&auth, &next.policy, &next.signature)?;
        return Err("post-commit process cut did not run".into());
    }
    for (mode, exit, expected) in [
        ("prepared", 71, PolicyRecoveryOutcome::Applied),
        ("committed", 72, PolicyRecoveryOutcome::AlreadyApplied),
        ("panicked", 73, PolicyRecoveryOutcome::AlreadyApplied),
    ] {
        let folder = directory()?;
        let path = folder.path().canonicalize()?.join("recovered.redb");
        let store = PolicyStore::provision_recoverable(
            &path,
            &initial.policy,
            &initial.signature,
            &trust,
            &enrollment,
            Limits::default(),
        )?;
        let auth = recovery_authorization(
            store.prepare_authority_recovery([1; 32], &next.policy, &next.signature, &next.root)?,
            93,
        )?;
        let wire = auth.to_bytes();
        std::fs::write(path.with_extension("approval"), &wire)?;
        drop(store);
        let child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "policy::tests::root_recovery_process_cuts_replay_original_authorization",
                "--nocapture",
            ])
            .env(MODE, mode)
            .env(STORE_PATH, &path)
            .stdin(Stdio::null())
            .spawn()?;
        assert_eq!(wait(child)?.code(), Some(exit));
        let restored = PolicyRecoveryAuthorization::from_bytes(&std::fs::read(
            path.with_extension("approval"),
        )?)?;
        assert_eq!(restored.to_bytes(), wire);
        let (reopened, outcome) = PolicyStore::open_recovering(
            &path,
            &trust,
            &restored,
            &next.policy,
            &next.signature,
            Limits::default(),
        )?;
        assert_eq!(outcome, expected);
        assert!(!reopened.runtime()?.is_enabled()?);
        assert_eq!(reopened.runtime()?.trusted_state().version(), 1);
    }
    Ok(())
}
