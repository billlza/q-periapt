use super::*;
use q_periapt_backends::MlDsa65;
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;
use redb::{backends::FileBackend, StorageBackend};
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
    let kems = if enabled {
        "\"ML-KEM-768\", \"X25519\""
    } else {
        "\"ML-KEM-1024\", \"X25519\""
    };
    let policy = format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [{kems}]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n").into_bytes();
    let (key, root) = MlDsa65::generate([91; 32]);
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
    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.inner.read(offset, len)
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn sync_data(&self, eventual: bool) -> io::Result<()> {
        if self.armed.swap(false, Ordering::SeqCst) {
            if let Some(runtime) = &self.close_on_sync {
                self.inner.sync_data(eventual)?;
                runtime.close();
                Ok(())
            } else {
                Err(io::Error::other("injected disk sync failure"))
            }
        } else {
            self.inner.sync_data(eventual)
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
    let runtime = Arc::new(Runtime::from_signed_policy(
        &initial.policy,
        &initial.signature,
        &initial.root,
        None,
        Limits::default(),
    )?);
    let mut store = PolicyStore {
        active: Some(Active {
            database,
            runtime: Arc::clone(&runtime),
            root: initial.root.clone(),
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
    let runtime = Arc::new(Runtime::from_signed_policy(
        &initial.policy,
        &initial.signature,
        &initial.root,
        None,
        Limits::default(),
    )?);
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
            runtime: Arc::clone(&runtime),
            root: initial.root.clone(),
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
    Ok(())
}
