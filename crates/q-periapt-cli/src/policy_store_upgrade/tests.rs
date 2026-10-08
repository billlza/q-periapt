use super::*;
use q_periapt_backends::MlDsa65;
use q_periapt_host_store::PolicyStore;
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;
use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};
type TestResult = std::result::Result<(), Box<dyn StdError>>;

struct Fixture {
    image: Image,
    state: TrustedPolicyState,
    root: Vec<u8>,
}
impl Fixture {
    fn new(version: u32, enabled: bool) -> Self {
        let kems = if enabled {
            "\"ML-KEM-768\", \"X25519\""
        } else {
            "\"ML-KEM-1024\", \"X25519\""
        };
        let policy = format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [{kems}]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n").into_bytes();
        let (key, root) = MlDsa65::generate([71; 32]);
        let root = root.to_vec();
        let mut signature = vec![0; ML_DSA_65_SIG_LEN];
        MlDsa65
            .sign(
                &key,
                &policy_signature_message(&policy),
                &[0; 32],
                &mut signature,
            )
            .expect("test signature");
        let runtime =
            Runtime::from_signed_policy(&policy, &signature, &root, None, Limits::default())
                .expect("fixture policy");
        let state = runtime.trusted_state();
        let image = Image::from([
            ("schema".into(), SCHEMA.to_vec()),
            ("root".into(), root.clone()),
            ("state".into(), state.encode().to_vec()),
            ("policy".into(), policy),
            ("signature".into(), signature),
        ]);
        Self { image, state, root }
    }
    fn write(&self, path: &Path) -> std::result::Result<(), Box<dyn StdError>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let db = redb_legacy::Database::builder()
            .create_with_backend(redb_legacy::backends::FileBackend::new(file)?)?;
        let mut tx = db.begin_write()?;
        tx.set_durability(redb_legacy::Durability::Immediate);
        tx.set_two_phase_commit(true);
        {
            let mut table =
                tx.open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(TABLE))?;
            for (name, bytes) in &self.image {
                table.insert(name.as_str(), bytes.as_slice())?;
            }
        }
        tx.commit()?;
        drop(db);
        Ok(())
    }
    fn trust_files(&self, dir: &Path) -> io::Result<(std::path::PathBuf, std::path::PathBuf)> {
        let root = dir.join("root.bin");
        let state = dir.join("state.bin");
        fs::write(&root, &self.root)?;
        fs::write(&state, self.state.encode())?;
        Ok((root, state))
    }
    fn verify(&self, path: &Path, enabled: bool) -> TestResult {
        let store = PolicyStore::open(path, &self.root, Limits::default())?;
        let runtime = store.runtime()?;
        assert_eq!(runtime.trusted_state(), self.state);
        assert_eq!(runtime.is_enabled()?, enabled);
        Ok(())
    }
}
fn directory() -> io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("policy-upgrade-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
}
fn copy(src: &Path, dst: &Path) -> io::Result<()> {
    fs::copy(src, dst)?;
    fs::set_permissions(dst, fs::Permissions::from_mode(0o600))
}

#[test]
fn actual_legacy_upgrade_and_current_retry_keep_max_floor_and_disabled_state() -> TestResult {
    for enabled in [true, false] {
        let dir = directory()?;
        let root = dir.path().canonicalize()?;
        let path = root.join("policy.redb");
        let fixture = Fixture::new(u32::MAX, enabled);
        fixture.write(&path)?;
        let identity = fs::metadata(&path)?;
        let before = fs::read(&path)?;
        assert!(PolicyStore::open(&path, &fixture.root, Limits::default()).is_err());
        assert_eq!(fs::read(&path)?, before);
        let (key, state) = fixture.trust_files(&root)?;
        let report = run(&path, &key, &state)?;
        assert_eq!(
            report.get("legacy_provider_used"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            report.get("policy_enabled"),
            Some(&serde_json::json!(enabled))
        );
        assert_eq!(fs::metadata(&path)?.ino(), identity.ino());
        fixture.verify(&path, enabled)?;
        let report = run(&path, &key, &state)?;
        assert_eq!(
            report.get("legacy_provider_used"),
            Some(&serde_json::json!(false))
        );
        fixture.verify(&path, enabled)?;
    }
    Ok(())
}

#[test]
fn incorrect_independent_trust_never_authorizes_conversion() -> TestResult {
    let dir = directory()?;
    let root = dir.path().canonicalize()?;
    let fixture = Fixture::new(7, true);
    let original = root.join("original.redb");
    fixture.write(&original)?;
    let (key, state) = fixture.trust_files(&root)?;
    let other = Fixture::new(8, true);
    for name in [
        "wrong-root",
        "wrong-state",
        "bad-signature",
        "unknown-field",
    ] {
        let path = root.join(name);
        copy(&original, &path)?;
        if name == "wrong-root" {
            fs::write(&key, vec![0; ML_DSA_65_VK_LEN])?;
        }
        if name == "wrong-state" {
            fs::write(&state, other.state.encode())?;
        }
        if matches!(name, "bad-signature" | "unknown-field") {
            let db = redb_legacy::Database::open(&path)?;
            let mut tx = db.begin_write()?;
            tx.set_durability(redb_legacy::Durability::Immediate);
            tx.set_two_phase_commit(true);
            {
                let mut table =
                    tx.open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(TABLE))?;
                if name == "bad-signature" {
                    table.insert("signature", vec![0; ML_DSA_65_SIG_LEN].as_slice())?;
                } else {
                    table.insert("unknown", b"data".as_slice())?;
                }
            }
            tx.commit()?;
            drop(db);
        }
        assert!(run(&path, &key, &state).is_err(), "{name}");
        let attempt = Attempt {
            backend: Box::new(admit(&path)?),
            failure: Mutex::new(None),
        };
        assert_eq!(slots(&attempt)?, [2, 2]);
        drop(attempt);
        fixture.trust_files(&root)?;
    }
    Ok(())
}

#[test]
fn private_path_and_exact_input_bounds_fail_before_replacement() -> TestResult {
    let dir = directory()?;
    let root = dir.path().canonicalize()?;
    let fixture = Fixture::new(2, true);
    let (key, state) = fixture.trust_files(&root)?;
    let missing = root.join("missing.redb");
    assert!(run(&missing, &key, &state).is_err());
    assert!(!missing.exists());
    let path = root.join("policy.redb");
    fixture.write(&path)?;
    let before = fs::read(&path)?;
    let link = root.join("link.redb");
    symlink(&path, &link)?;
    assert!(run(&link, &key, &state).is_err());
    let hard = root.join("hard.redb");
    fs::hard_link(&path, &hard)?;
    assert!(run(&path, &key, &state).is_err());
    fs::remove_file(&hard)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(run(&path, &key, &state).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    for length in [0, 35, 37] {
        fs::write(&state, vec![0; length])?;
        assert!(run(&path, &key, &state).is_err());
    }
    fixture.trust_files(&root)?;
    fs::write(&key, vec![0; ML_DSA_65_VK_LEN + 1])?;
    assert!(run(&path, &key, &state).is_err());
    assert_eq!(fs::read(&path)?, before);
    Ok(())
}

#[test]
fn corrupt_current_version_byte_is_refused_without_old_parser_or_writes() -> TestResult {
    let dir = directory()?;
    let root = dir.path().canonicalize()?;
    let fixture = Fixture::new(3, true);
    let path = root.join("policy.redb");
    fixture.write(&path)?;
    let (key, state) = fixture.trust_files(&root)?;
    run(&path, &key, &state)?;
    for offset in [64, 192] {
        let corrupt = root.join(format!("corrupt-{offset}.redb"));
        copy(&path, &corrupt)?;
        let mut file = OpenOptions::new().write(true).open(&corrupt)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&[2])?;
        drop(file);
        let before = fs::read(&corrupt)?;
        let error = run(&corrupt, &key, &state).expect_err("bad slot must be refused");
        assert!(error.to_string().contains("slot checksum mismatch"));
        assert_eq!(fs::read(&corrupt)?, before);
    }
    Ok(())
}

#[derive(Debug)]
struct InjectedIo;
impl fmt::Display for InjectedIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("injected migration I/O")
    }
}
impl StdError for InjectedIo {}
#[derive(Debug)]
struct Control {
    next: AtomicUsize,
    target: usize,
    after: bool,
    cut: bool,
    partial: bool,
    peer_path: Option<std::path::PathBuf>,
    hit: AtomicBool,
    events: Mutex<Vec<&'static str>>,
}
impl Control {
    fn boundary(&self, n: usize, after: bool) -> io::Result<()> {
        if self.target == n && self.after == after {
            self.hit.store(true, Ordering::SeqCst);
            if self.cut {
                std::process::exit(72);
            }
            return Err(io::Error::other(InjectedIo));
        }
        Ok(())
    }
    fn event<T>(
        &self,
        name: &'static str,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.events.lock().expect("event list").push(name);
        if let Some(path) = self.peer_path.as_ref() {
            if n == 1 || matches!(name, "sync" | "close") {
                probe_peers(path)?;
            }
        }
        self.boundary(n, false)?;
        let value = operation()?;
        self.boundary(n, true)?;
        Ok(value)
    }
}
#[derive(Debug)]
struct Instrumented {
    inner: LockedFileBackend,
    control: Arc<Control>,
}
impl StorageBackend for Instrumented {
    fn len(&self) -> io::Result<u64> {
        self.control.event("len", || self.inner.len())
    }
    fn read(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.control.event("read", || self.inner.read(o, b))
    }
    fn write(&self, o: u64, b: &[u8]) -> io::Result<()> {
        let partial = self.control.partial
            && self.control.target == self.control.next.load(Ordering::SeqCst) + 1;
        self.control.event("write", || {
            if partial {
                let prefix = b
                    .get(..b.len() / 2)
                    .ok_or_else(|| io::Error::other("partial-write fixture"))?;
                self.inner.write(o, prefix)?;
                self.control.hit.store(true, Ordering::SeqCst);
                return Err(io::Error::other(InjectedIo));
            }
            self.inner.write(o, b)
        })
    }
    fn set_len(&self, n: u64) -> io::Result<()> {
        self.control.event("resize", || self.inner.set_len(n))
    }
    fn sync_data(&self) -> io::Result<()> {
        self.control.event("sync", || self.inner.sync_data())
    }
    fn try_lock_range(
        &self,
        s: Bound<u64>,
        e: Bound<u64>,
    ) -> std::result::Result<bool, redb::BackendError> {
        self.inner.try_lock_range(s, e)
    }
    fn close(&self) -> io::Result<()> {
        self.control.event("close", || self.inner.close())
    }
}
fn attempt(
    path: &Path,
    target: usize,
    after: bool,
    cut: bool,
) -> Result<(Arc<Attempt>, Arc<Control>)> {
    let control = Arc::new(Control {
        next: AtomicUsize::new(0),
        target,
        after,
        cut,
        partial: false,
        peer_path: None,
        hit: AtomicBool::new(false),
        events: Mutex::new(Vec::new()),
    });
    let backend = Instrumented {
        inner: admit(path)?,
        control: Arc::clone(&control),
    };
    Ok((
        Arc::new(Attempt {
            backend: Box::new(backend),
            failure: Mutex::new(None),
        }),
        control,
    ))
}

fn wait_child(mut child: std::process::Child) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "migration test child timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn probe_peers(path: &Path) -> io::Result<()> {
    for engine in ["legacy", "current"] {
        let child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "policy_store_upgrade::tests::lease_peer_worker",
                "--nocapture",
            ])
            .env("QPERIAPT_MIGRATION_PEER_PATH", path)
            .env("QPERIAPT_MIGRATION_PEER_ENGINE", engine)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        if !wait_child(child)?.success() {
            return Err(io::Error::other(
                "independent lock competitor was not refused",
            ));
        }
    }
    Ok(())
}

#[test]
fn lease_peer_worker() -> TestResult {
    let Some(path) = std::env::var_os("QPERIAPT_MIGRATION_PEER_PATH") else {
        return Ok(());
    };
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    match std::env::var("QPERIAPT_MIGRATION_PEER_ENGINE")?.as_str() {
        "legacy" => assert!(matches!(
            redb_legacy::backends::FileBackend::new(file),
            Err(redb_legacy::DatabaseError::DatabaseAlreadyOpen)
        )),
        "current" => assert!(matches!(
            LockedFileBackend::new(file),
            Err(redb::DatabaseError::DatabaseAlreadyOpen)
        )),
        _ => return Err("unknown peer fixture".into()),
    }
    Ok(())
}

#[test]
fn independent_legacy_and_current_owners_are_fenced_until_final_close() -> TestResult {
    let dir = directory()?;
    let root = dir.path().canonicalize()?;
    let fixture = Fixture::new(12, true);
    let path = root.join("policy.redb");
    fixture.write(&path)?;
    let control = Arc::new(Control {
        next: AtomicUsize::new(0),
        target: 0,
        after: false,
        cut: false,
        partial: false,
        peer_path: Some(path.clone()),
        hit: AtomicBool::new(false),
        events: Mutex::new(Vec::new()),
    });
    let backend = Instrumented {
        inner: admit(&path)?,
        control: Arc::clone(&control),
    };
    let owner = Arc::new(Attempt {
        backend: Box::new(backend),
        failure: Mutex::new(None),
    });
    convert(owner, &fixture.root, fixture.state)?;
    fixture.verify(&path, true)?;
    let events = control.events.lock().expect("events");
    let probes = 1 + events
        .iter()
        .filter(|kind| matches!(**kind, "sync" | "close"))
        .count();
    assert!(probes > 5);
    eprintln!("MIGRATION_LEASE_HANDOFF_PASS peer_refusals={}", probes * 2);
    Ok(())
}

#[test]
fn partial_writes_fail_with_original_io_and_never_replace_the_inode() -> TestResult {
    let dir = directory()?;
    let root = dir.path().canonicalize()?;
    let fixture = Fixture::new(12, true);
    let original = root.join("original.redb");
    fixture.write(&original)?;
    let baseline = root.join("baseline.redb");
    copy(&original, &baseline)?;
    let (owner, control) = attempt(&baseline, 0, false, false)?;
    convert(owner, &fixture.root, fixture.state)?;
    let events = control.events.lock().expect("events").clone();
    let mut count = 0;
    for (i, _) in events
        .iter()
        .enumerate()
        .filter(|(_, kind)| **kind == "write")
    {
        let path = root.join(format!("partial-{i}.redb"));
        copy(&original, &path)?;
        let inode = fs::metadata(&path)?.ino();
        let control = Arc::new(Control {
            next: AtomicUsize::new(0),
            target: i + 1,
            after: true,
            cut: false,
            partial: true,
            peer_path: None,
            hit: AtomicBool::new(false),
            events: Mutex::new(Vec::new()),
        });
        let backend = Instrumented {
            inner: admit(&path)?,
            control: Arc::clone(&control),
        };
        let owner = Arc::new(Attempt {
            backend: Box::new(backend),
            failure: Mutex::new(None),
        });
        let error = convert(owner, &fixture.root, fixture.state)
            .expect_err("partial write cannot report success");
        assert!(control.hit.load(Ordering::SeqCst));
        assert!(
            contains_injected(&error),
            "partial write lost its typed error: {error}"
        );
        let metadata = fs::metadata(&path)?;
        assert_eq!(metadata.ino(), inode);
        assert!(metadata.len() >= 320);
        count += 1;
    }
    assert!(count > 0);
    // Torn writes can leave corrupt slots/pages. This tests truthful failure
    // and inode preservation, not automatic recovery from arbitrary corruption.
    eprintln!("MIGRATION_PARTIAL_WRITE_FAILURES_PASS count={count}");
    Ok(())
}
fn contains_injected(error: &(dyn StdError + 'static)) -> bool {
    if error.is::<InjectedIo>() {
        return true;
    }
    // io::Error::source() delegates to its stored error's source; get_ref()
    // exposes the stored typed error itself, including a leaf with no source.
    if error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
        .is_some_and(|inner| contains_injected(inner))
    {
        return true;
    }
    error.source().is_some_and(contains_injected)
}

#[test]
fn io_errors_across_both_providers_remain_typed_and_never_report_success() -> TestResult {
    let dir = directory()?;
    let root = dir.path().canonicalize()?;
    let fixture = Fixture::new(12, true);
    let original = root.join("original.redb");
    fixture.write(&original)?;
    let baseline = root.join("baseline.redb");
    copy(&original, &baseline)?;
    let (owner, control) = attempt(&baseline, 0, false, false)?;
    convert(owner, &fixture.root, fixture.state)?;
    let events = control.events.lock().expect("events").clone();
    assert!(
        events.contains(&"read")
            && events.contains(&"write")
            && events.contains(&"sync")
            && events.contains(&"close")
    );
    for (i, _) in events.iter().enumerate() {
        for after in [false, true] {
            let path = root.join(format!("error-{i}-{after}.redb"));
            copy(&original, &path)?;
            let (owner, control) = attempt(&path, i + 1, after, false)?;
            let error = convert(owner, &fixture.root, fixture.state)
                .expect_err("fault must not report success");
            assert!(
                control.hit.load(Ordering::SeqCst),
                "unreached fault {i}/{after}"
            );
            assert!(
                contains_injected(&error),
                "original typed I/O lost: {i}/{after}: {error}"
            );
            let (key, state) = fixture.trust_files(&root)?;
            run(&path, &key, &state)?;
            fixture.verify(&path, true)?;
        }
    }
    eprintln!(
        "MIGRATION_TYPED_IO_ERRORS_PASS boundaries={} faults={}",
        events.len(),
        events.len() * 2
    );
    Ok(())
}

#[test]
fn process_cut_worker() -> TestResult {
    let Some(path) = std::env::var_os("QPERIAPT_MIGRATION_CUT_PATH") else {
        return Ok(());
    };
    let target: usize = std::env::var("QPERIAPT_MIGRATION_CUT_TARGET")?.parse()?;
    let after = std::env::var("QPERIAPT_MIGRATION_CUT_AFTER")? == "true";
    let fixture = Fixture::new(12, true);
    let (owner, _) = attempt(Path::new(&path), target, after, true)?;
    convert(owner, &fixture.root, fixture.state)?;
    Err("requested process cut was not reached".into())
}

#[test]
fn process_cuts_across_conversion_and_current_close_recover_original_state() -> TestResult {
    if std::env::var_os("QPERIAPT_MIGRATION_CUT_PATH").is_some() {
        return Ok(());
    }
    let dir = directory()?;
    let root = dir.path().canonicalize()?;
    let fixture = Fixture::new(12, true);
    let original = root.join("original.redb");
    fixture.write(&original)?;
    let baseline = root.join("baseline.redb");
    copy(&original, &baseline)?;
    let (owner, control) = attempt(&baseline, 0, false, false)?;
    convert(owner, &fixture.root, fixture.state)?;
    let events = control.events.lock().expect("events").clone();
    for (i, kind) in events
        .iter()
        .enumerate()
        .filter(|(_, kind)| matches!(**kind, "write" | "resize" | "sync" | "close"))
    {
        for after in [false, true] {
            let path = root.join(format!("cut-{i}-{after}.redb"));
            copy(&original, &path)?;
            let mut child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "policy_store_upgrade::tests::process_cut_worker",
                    "--nocapture",
                ])
                .env("QPERIAPT_MIGRATION_CUT_PATH", &path)
                .env("QPERIAPT_MIGRATION_CUT_TARGET", (i + 1).to_string())
                .env("QPERIAPT_MIGRATION_CUT_AFTER", after.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(20);
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    return Err("process-cut child timed out".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(72), "{i}/{kind}/{after}");
            let (key, state) = fixture.trust_files(&root)?;
            run(&path, &key, &state)?;
            fixture.verify(&path, true)?;
        }
    }
    eprintln!(
        "MIGRATION_PROCESS_CUTS_PASS boundaries={} cuts={}",
        events
            .iter()
            .filter(|kind| matches!(**kind, "write" | "resize" | "sync" | "close"))
            .count(),
        events
            .iter()
            .filter(|kind| matches!(**kind, "write" | "resize" | "sync" | "close"))
            .count()
            * 2
    );
    Ok(())
}
