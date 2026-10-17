// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{DeviceSigningKey, SigningKeyId};
use std::io::Write;

pub(in crate::durable) fn after_key_publication() -> Result<(), DurableError> {
    at_checkpoint(Checkpoint::Published)?;
    let Some(path) = std::env::var_os("QPERIAPT_KEY_CREATE_FAILURE_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let mut ready = fs::File::create_new(path.join("ready.pending"))?;
    ready.write_all(b"complete wrapping file before owner return")?;
    ready.sync_all()?;
    fs::rename(path.join("ready.pending"), path.join("ready"))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("release-failure").exists() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "creator failure handoff").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::other("injected key creation sync failure").into())
}

#[test]
fn wrapping_key_create_failure_child() {
    let Some(path) = std::env::var_os("QPERIAPT_KEY_CREATE_FAILURE_DIR") else {
        return;
    };
    let path = Path::new(&path);
    assert!(
        matches!(JournalKey::provision(&path.join("wrapping")), Err(DurableError::Io(error))
        if error.kind() == io::ErrorKind::Other && error.to_string() == "injected key creation sync failure")
    );
}

#[test]
fn wrapping_key_creator_failure_preserves_a_key_already_used_by_a_concurrent_opener() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("private path");
    let log = fs::File::create_new(path.join("child.log")).expect("log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::tests::key_files::wrapping_key_create_failure_child",
                "--nocapture",
            ])
            .env("QPERIAPT_KEY_CREATE_FAILURE_DIR", &path)
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("creator"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "creator did not complete its write: {}",
            fs::read_to_string(path.join("child.log")).expect("log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let wrapping = JournalKey::open(&path.join("wrapping")).expect("concurrent complete-key owner");
    let signer_id =
        SigningKeyId::from_trusted_state([61; 32]).expect("independent signer identity");
    let signer = DeviceSigningKey::provision(&path.join("signer"), &wrapping, signer_id)
        .expect("durable dependent owner");
    let public = signer.public_key().expect("public");
    drop(signer);
    fs::write(path.join("release-failure"), b"release injected failure").expect("handoff");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.0.try_wait().expect("status") {
            assert!(
                status.success(),
                "{}",
                fs::read_to_string(path.join("child.log")).expect("log")
            );
            break;
        }
        assert!(Instant::now() < deadline, "creator teardown deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(wrapping);
    let restored = JournalKey::open(&path.join("wrapping"))
        .expect("creator failure must preserve the admitted immutable key");
    let signer = DeviceSigningKey::open(&path.join("signer"), &restored, signer_id)
        .expect("dependent signer remains recoverable");
    assert_eq!(signer.public_key().expect("public"), public);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::durable) enum Barrier {
    ProvisionPublication,
    OpenFile,
    OpenDirectory,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyncPoint {
    barrier: Barrier,
    after: bool,
}
#[derive(Debug)]
struct InjectedSyncFailure(SyncPoint);
impl std::fmt::Display for InjectedSyncFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "injected immutable-key sync failure: {:?}", self.0)
    }
}
impl std::error::Error for InjectedSyncFailure {}
struct SyncProbe {
    fault: Option<SyncPoint>,
    observed: Vec<SyncPoint>,
}
thread_local! {
    static SYNC_PROBE: std::cell::RefCell<Option<SyncProbe>> = const { std::cell::RefCell::new(None) };
}
pub(in crate::durable) fn at_sync(barrier: Barrier, after: bool) -> Result<(), DurableError> {
    let point = SyncPoint { barrier, after };
    SYNC_PROBE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(probe) = state.as_mut() else {
            return Ok(());
        };
        probe.observed.push(point);
        if probe.fault == Some(point) {
            Err(io::Error::other(InjectedSyncFailure(point)).into())
        } else {
            Ok(())
        }
    })
}
struct ProbeGuard;
impl ProbeGuard {
    fn arm(point: SyncPoint) -> Self {
        SYNC_PROBE.with(|probe| {
            assert!(probe.borrow().is_none());
            *probe.borrow_mut() = Some(SyncProbe {
                fault: Some(point),
                observed: Vec::new(),
            });
        });
        Self
    }
    fn observed(&self) -> Vec<SyncPoint> {
        SYNC_PROBE.with(|probe| {
            probe
                .borrow()
                .as_ref()
                .expect("active probe")
                .observed
                .clone()
        })
    }
}
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        SYNC_PROBE.with(|probe| {
            probe.borrow_mut().take();
        });
    }
}

#[derive(Clone, Copy, Debug)]
pub(in crate::durable) enum Checkpoint {
    Reserved,
    Header,
    Published,
    OpenRead,
    OpenFileSynced,
    OpenDirectorySynced,
}
pub(in crate::durable) fn at_checkpoint(point: Checkpoint) -> Result<(), DurableError> {
    let Some(path) = std::env::var_os("QPERIAPT_KEY_CRASH_DIR") else {
        return Ok(());
    };
    if std::env::var("QPERIAPT_KEY_CRASH_STAGE").ok().as_deref()
        != Some(format!("{point:?}").as_str())
    {
        return Ok(());
    }
    let path = Path::new(&path);
    let mut marker = fs::File::create_new(path.join("ready.pending"))?;
    marker.write_all(format!("{point:?}").as_bytes())?;
    marker.sync_all()?;
    fs::rename(path.join("ready.pending"), path.join("ready"))?;
    loop {
        std::thread::park();
    }
}

fn assert_dependent_signer(path: &Path, wrapping: &JournalKey, expected: &crate::PublicKey) {
    let signer = DeviceSigningKey::open(
        &path.join("signer"),
        wrapping,
        SigningKeyId::from_trusted_state([63; 32]).expect("retained ID"),
    )
    .expect("same protected signer");
    assert_eq!(&signer.public_key().expect("public"), expected);
    let message = b"immutable key recovery";
    let signature = signer
        .sign(crate::crypto::Purpose::Credential, message)
        .expect("signature");
    expected
        .verify(crate::crypto::Purpose::Credential, message, &signature)
        .expect("both components verify");
}
fn dependent_signer(path: &Path, wrapping: &JournalKey) -> crate::PublicKey {
    DeviceSigningKey::provision(
        &path.join("signer"),
        wrapping,
        SigningKeyId::from_trusted_state([63; 32]).expect("retained ID"),
    )
    .expect("protected dependent signer")
    .public_key()
    .expect("public")
}

#[test]
fn wrapping_key_sync_failures_withhold_the_owner_and_preserve_exact_recovery() {
    for barrier in [
        Barrier::ProvisionPublication,
        Barrier::OpenFile,
        Barrier::OpenDirectory,
    ] {
        for after in [false, true] {
            let dir = directory();
            let path = dir.path().canonicalize().expect("path");
            let public = if barrier != Barrier::ProvisionPublication {
                let key = JournalKey::provision(&path.join("wrapping")).expect("key");
                Some(dependent_signer(&path, &key))
            } else {
                None
            };
            let point = SyncPoint { barrier, after };
            let probe = ProbeGuard::arm(point);
            let result = if barrier == Barrier::ProvisionPublication {
                JournalKey::provision(&path.join("wrapping"))
            } else {
                JournalKey::open(&path.join("wrapping"))
            };
            assert!(matches!(result, Err(DurableError::Io(ref error))
                if error.get_ref().and_then(|inner| inner.downcast_ref::<InjectedSyncFailure>())
                    .is_some_and(|injected| injected.0 == point)));
            let observed = probe.observed();
            assert_eq!(observed.last(), Some(&point));
            assert_eq!(
                observed.len(),
                match (barrier, after) {
                    (Barrier::ProvisionPublication | Barrier::OpenFile, false) => 1,
                    (Barrier::ProvisionPublication | Barrier::OpenFile, true) => 2,
                    (Barrier::OpenDirectory, false) => 3,
                    (Barrier::OpenDirectory, true) => 4,
                }
            );
            drop(probe);
            if barrier == Barrier::ProvisionPublication && !after {
                assert!(!path.join("wrapping").exists());
                let key = JournalKey::provision(&path.join("wrapping"))
                    .expect("explicit first-use retry");
                let public = dependent_signer(&path, &key);
                assert_dependent_signer(&path, &key, &public);
                continue;
            }
            assert_eq!(
                fs::metadata(path.join("wrapping"))
                    .expect("retained file")
                    .len(),
                40
            );
            assert!(JournalKey::provision(&path.join("wrapping")).is_err());
            let key = JournalKey::open(&path.join("wrapping")).expect("reconciled original key");
            let public = public.unwrap_or_else(|| dependent_signer(&path, &key));
            assert_dependent_signer(&path, &key, &public);
        }
    }
}

#[test]
fn wrapping_key_missing_partial_linked_and_public_files_are_refused_without_replacement() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let file = path.join("wrapping");
    assert!(JournalKey::open(&file).is_err());
    assert!(!file.exists());
    let key = JournalKey::provision(&file).expect("key");
    let public = dependent_signer(&path, &key);
    drop(key);
    let alias = path.join("alias");
    fs::hard_link(&file, &alias).expect("owned alias fixture");
    assert!(matches!(
        JournalKey::open(&file),
        Err(DurableError::PrivateFile)
    ));
    assert!(matches!(
        JournalKey::open(&alias),
        Err(DurableError::PrivateFile)
    ));
    fs::remove_file(&alias).expect("remove only owned test alias");
    std::os::unix::fs::symlink(&file, &alias).expect("owned symlink fixture");
    assert!(matches!(
        JournalKey::open(&alias),
        Err(DurableError::PrivateFile)
    ));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("public mode fixture");
    assert!(matches!(
        JournalKey::open(&file),
        Err(DurableError::PrivateFile)
    ));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("restore fixture mode");
    assert_dependent_signer(
        &path,
        &JournalKey::open(&file).expect("same admitted key"),
        &public,
    );
    let bytes = zeroize::Zeroizing::new(fs::read(&file).expect("owned test fixture"));
    for length in [0, 8, 39, 41] {
        let mut variant = zeroize::Zeroizing::new(bytes.to_vec());
        variant.resize(length, 0);
        fs::write(&file, variant.as_slice()).expect("shape fixture");
        assert!(matches!(
            JournalKey::open(&file),
            Err(DurableError::PrivateFile)
        ));
        assert!(JournalKey::provision(&file).is_err());
        assert_eq!(
            fs::metadata(&file).expect("preserved shape").len(),
            length as u64
        );
    }
}

#[test]
fn wrapping_key_crash_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_KEY_CRASH_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let key = match std::env::var("QPERIAPT_KEY_CRASH_OPERATION")?.as_str() {
        "provision" => JournalKey::provision(&path.join("wrapping"))?,
        "open" => JournalKey::open(&path.join("wrapping"))?,
        _ => return Err("unexpected key owner test operation".into()),
    };
    drop(key);
    fs::write(path.join("owner-returned"), b"owner returned")?;
    Err("process cut did not prevent owner return".into())
}

#[test]
fn wrapping_key_process_cuts_keep_unpublished_absent_and_recover_exact_published_owners() {
    for point in [
        Checkpoint::Reserved,
        Checkpoint::Header,
        Checkpoint::Published,
        Checkpoint::OpenRead,
        Checkpoint::OpenFileSynced,
        Checkpoint::OpenDirectorySynced,
    ] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let opening = matches!(
            point,
            Checkpoint::OpenRead | Checkpoint::OpenFileSynced | Checkpoint::OpenDirectorySynced
        );
        let complete = !matches!(point, Checkpoint::Reserved | Checkpoint::Header);
        let mut public = if opening {
            let key = JournalKey::provision(&path.join("wrapping")).expect("key");
            Some(dependent_signer(&path, &key))
        } else {
            None
        };
        let log = fs::File::create_new(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::tests::key_files::wrapping_key_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_KEY_CRASH_DIR", &path)
                .env("QPERIAPT_KEY_CRASH_STAGE", format!("{point:?}"))
                .env(
                    "QPERIAPT_KEY_CRASH_OPERATION",
                    if opening { "open" } else { "provision" },
                )
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned creator/opener"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "key boundary {point:?} was not observed: {}",
                fs::read_to_string(path.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read_to_string(path.join("ready")).expect("stage"),
            format!("{point:?}")
        );
        assert!(!path.join("owner-returned").exists());
        // A concurrent immutable-file reader may admit complete bytes, provided
        // it performs its own durability barriers. Partial data cannot mint an owner.
        if complete {
            let key =
                JournalKey::open(&path.join("wrapping")).expect("independently reconciled owner");
            if let Some(expected) = &public {
                assert_dependent_signer(&path, &key, expected);
            } else {
                public = Some(dependent_signer(&path, &key));
            }
        } else {
            assert!(matches!(
                JournalKey::open(&path.join("wrapping")),
                Err(DurableError::PrivateFile)
            ));
        }
        child.0.kill().expect("kill exact boundary child");
        assert!(!child.0.wait().expect("reap").success());
        if let Some(public) = public {
            assert!(JournalKey::provision(&path.join("wrapping")).is_err());
            let key = JournalKey::open(&path.join("wrapping"))
                .expect("same immutable key after process loss");
            assert_dependent_signer(&path, &key, &public);
        } else {
            assert!(matches!(
                JournalKey::open(&path.join("wrapping")),
                Err(DurableError::PrivateFile)
            ));
            assert!(!path.join("wrapping").exists());
            let key =
                JournalKey::provision(&path.join("wrapping")).expect("explicit first-use retry");
            let public = dependent_signer(&path, &key);
            assert_dependent_signer(&path, &key, &public);
        }
        eprintln!("WRAPPING_KEY_PROCESS_CUT stage={point:?} complete={complete} original_owner_returned=false");
    }
}

#[test]
fn first_key_interrupted_header_does_not_publish_a_partial_identity() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::tests::key_files::wrapping_key_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_KEY_CRASH_DIR", &path)
            .env("QPERIAPT_KEY_CRASH_STAGE", "Header")
            .env("QPERIAPT_KEY_CRASH_OPERATION", "provision")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(child.0.try_wait().expect("status").is_none() && Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("kill");
    assert!(!child.0.wait().expect("reap").success());
    assert!(
        !path.join("wrapping").exists(),
        "initial incomplete key became the formal identity"
    );
    let key = JournalKey::provision(&path.join("wrapping")).expect("explicit first-use retry");
    let public = dependent_signer(&path, &key);
    assert_dependent_signer(
        &path,
        &JournalKey::open(&path.join("wrapping")).expect("recover"),
        &public,
    );
}
