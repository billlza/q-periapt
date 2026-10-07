use super::*;
use crate::filesystem::{open_private_database, provision_private_database};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const TABLE: TableDefinition<&str, u64> = TableDefinition::new("publication_test");
fn storage(e: impl Into<redb::Error>) -> PrivateDatabaseError {
    PrivateDatabaseError::Storage(Box::new(e.into()))
}
fn seed(db: &Database, value: u64) -> Result<(), PrivateDatabaseError> {
    let mut tx = db.begin_write().map_err(storage)?;
    tx.set_durability(Durability::Immediate).map_err(storage)?;
    tx.set_two_phase_commit(true);
    tx.open_table(TABLE)
        .map_err(storage)?
        .insert("genesis", value)
        .map_err(storage)?;
    tx.commit().map_err(storage)
}
fn value(db: &Database) -> u64 {
    let tx = db.begin_read().expect("read");
    let table = tx.open_table(TABLE).expect("schema");
    table.get("genesis").expect("lookup").expect("row").value()
}
fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory")
}
fn stage(root: &Path) -> std::path::PathBuf {
    let stages: Vec<_> = fs::read_dir(root)
        .expect("fixture entries")
        .map(|e| e.expect("entry").path())
        .filter(|p| {
            p.file_name()
                .expect("leaf")
                .to_string_lossy()
                .starts_with(".private-publication-")
        })
        .collect();
    assert_eq!(stages.len(), 1);
    stages.first().expect("one staging inode").clone()
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().expect("status").is_none() {
            self.0.kill().expect("kill");
            self.0.wait().expect("reap");
        }
    }
}
fn busy(path: &Path) {
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "filesystem::publication::database_tests::database_busy_child",
                "--nocapture",
            ])
            .env("QPERIAPT_DATABASE_PUBLICATION_BUSY", path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("contender"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.0.try_wait().expect("status") {
            assert!(status.success(), "contender must report Busy");
            break;
        }
        assert!(Instant::now() < deadline, "contender must not block");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn database_busy_child() {
    let Some(path) = std::env::var_os("QPERIAPT_DATABASE_PUBLICATION_BUSY") else {
        return;
    };
    assert!(matches!(
        open_private_database(Path::new(&path)),
        Err(PrivateDatabaseError::Busy)
    ));
}

#[test]
fn original_database_lock_survives_publication_and_all_plain_probe_drops() {
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    let path = root.join("configuration.redb");
    let db = provision_database_with(
        &path,
        |db| seed(db, 41),
        |staged| {
            busy(&root.join(&staged.name));
            assert!(!path.exists());
            let probe = staged.file()?;
            staged.publish_with(&probe, &mut |step, _, _, _| {
                if matches!(step, Step::Published | Step::DirectorySynced) {
                    busy(&path);
                }
                Ok(())
            })?;
            drop(probe);
            busy(&path);
            Ok(())
        },
    )
    .expect("same locked database");
    assert_eq!(value(&db), 41);
    busy(&path); // The helper's retained staging descriptor has now also dropped.
    drop(db);
    assert_eq!(
        value(&open_private_database(&path).expect("only after owner close")),
        41
    );
}

#[derive(Debug)]
struct PublicationFault(Step);
impl std::fmt::Display for PublicationFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database publication fault {:?}", self.0)
    }
}
impl std::error::Error for PublicationFault {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DatabaseSyncFault {
    index: usize,
    after: bool,
}
impl std::fmt::Display for DatabaseSyncFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database initialization sync fault {self:?}")
    }
}
impl std::error::Error for DatabaseSyncFault {}
struct Probe {
    count: usize,
    fault: Option<DatabaseSyncFault>,
}
thread_local! {
    static PROBE: std::cell::RefCell<Option<Probe>> = const { std::cell::RefCell::new(None) };
}
pub(in crate::filesystem) fn at_database_sync(after: bool) -> io::Result<()> {
    PROBE.with(|cell| {
        let mut state = cell.borrow_mut();
        let Some(probe) = state.as_mut() else {
            return Ok(());
        };
        if !after {
            probe.count += 1;
        }
        let point = DatabaseSyncFault {
            index: probe.count,
            after,
        };
        if probe.fault == Some(point) {
            probe.fault = None;
            Err(io::Error::other(point))
        } else {
            Ok(())
        }
    })
}
struct ProbeGuard;
impl ProbeGuard {
    fn arm(fault: Option<DatabaseSyncFault>) -> Self {
        PROBE.with(|cell| {
            assert!(cell.borrow().is_none());
            *cell.borrow_mut() = Some(Probe { count: 0, fault });
        });
        Self
    }
    fn count(&self) -> usize {
        PROBE.with(|cell| cell.borrow().as_ref().expect("armed").count)
    }
}
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        PROBE.with(|cell| {
            cell.borrow_mut().take();
        });
    }
}

#[test]
fn each_real_database_initialization_sync_fault_withholds_publication() {
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    let probe = ProbeGuard::arm(None);
    let db = provision_private_database(&root.join("calibration.redb"), |db| seed(db, 83))
        .expect("calibrate exact operation");
    let count = probe.count();
    drop(probe);
    drop(db);
    assert!(count > 0);
    for after in [false, true] {
        for index in 1..=count {
            let dir = directory();
            let root = dir.path().canonicalize().expect("path");
            let path = root.join("configuration.redb");
            let expected = DatabaseSyncFault { index, after };
            let probe = ProbeGuard::arm(Some(expected));
            let result = provision_private_database(&path, |db| seed(db, 83));
            let error = result.expect_err("injected sync must withhold owner");
            let error = match error {
                PrivateDatabaseError::Storage(error) => Ok(error),
                error => Err(error),
            }
            .expect("original storage error");
            let error = match *error {
                redb::Error::Io(error) => Ok(error),
                error => Err(error),
            }
            .expect("original I/O");
            let original = error
                .get_ref()
                .and_then(|e| e.downcast_ref::<DatabaseSyncFault>())
                .expect("exact fault identity");
            assert_eq!(*original, expected);
            drop(probe);
            assert!(!path.exists());
            let orphan = stage(&root);
            let before = fs::read(&orphan).expect("retained original staging");
            let db = provision_private_database(&path, |db| seed(db, 83))
                .expect("explicit first-use retry");
            assert_eq!(value(&db), 83);
            drop(db);
            assert_eq!(fs::read(orphan).expect("orphan unchanged"), before);
        }
    }
    eprintln!(
        "DATABASE_INITIALIZATION_SYNC count={count} before_after_faults={}",
        count * 2
    );
}

#[test]
fn database_publication_faults_retain_exact_errors_and_never_return_an_owner() {
    for cut in [
        Step::BeforeFileSync,
        Step::FileSynced,
        Step::BeforeRename,
        Step::Published,
        Step::BeforeDirectorySync,
        Step::DirectorySynced,
    ] {
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        let path = root.join("configuration.redb");
        let result = provision_database_with(
            &path,
            |db| seed(db, 52),
            |staged| {
                staged.publish_with(&staged.file()?, &mut |step, _, _, _| {
                    if step == cut {
                        Err(io::Error::other(PublicationFault(step)))
                    } else {
                        Ok(())
                    }
                })
            },
        );
        let error = result.expect_err("no owner may escape");
        let error = match error {
            PrivateDatabaseError::Io(error) => Ok(error),
            error => Err(error),
        }
        .expect("original publication I/O");
        let publication = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<PrivatePublicationError>())
            .expect("publication context");
        let original = publication
            .operation()
            .get_ref()
            .and_then(|e| e.downcast_ref::<PublicationFault>())
            .expect("exact injected error");
        assert_eq!(original.0, cut);
        assert!(publication.staging_name().is_some());
        if matches!(
            cut,
            Step::Published | Step::BeforeDirectorySync | Step::DirectorySynced
        ) {
            assert_eq!(
                value(&open_private_database(&path).expect("original committed database")),
                52
            );
            assert!(provision_private_database(&path, |db| seed(db, 90)).is_err());
            assert_eq!(value(&open_private_database(&path).expect("unchanged")), 52);
        } else {
            assert!(!path.exists());
            let orphan = stage(&root);
            let before = fs::read(&orphan).expect("orphan");
            drop(
                provision_private_database(&path, |db| seed(db, 90))
                    .expect("explicit first use retry"),
            );
            assert_eq!(
                value(&open_private_database(&path).expect("new initial image")),
                90
            );
            assert_eq!(fs::read(orphan).expect("orphan untouched"), before);
        }
        eprintln!("DATABASE_PUBLICATION_FAULT cut={cut:?} original_error_preserved=true owner_returned=false");
    }
}

#[test]
fn competing_database_creators_publish_one_original_owner() {
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    let barrier = std::sync::Barrier::new(2);
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = [61, 62]
            .into_iter()
            .map(|number| {
                let barrier = &barrier;
                let root = &root;
                scope.spawn(move || {
                    (
                        number,
                        provision_database_with(
                            &root.join("configuration.redb"),
                            |db| seed(db, number),
                            |staged| {
                                barrier.wait();
                                staged.publish()
                            },
                        ),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("creator"))
            .collect()
    });
    assert_eq!(results.iter().filter(|(_, r)| r.is_ok()).count(), 1);
    let mut winner = None;
    for (number, result) in results {
        match result {
            Ok(db) => {
                assert_eq!(value(&db), number);
                winner = Some((number, db));
            }
            Err(error) => {
                assert!(
                    matches!(&error, PrivateDatabaseError::Io(e)
                    if e.kind() == io::ErrorKind::AlreadyExists),
                    "unexpected failure: {error}"
                );
            }
        }
    }
    let (number, db) = winner.expect("one winner");
    busy(&root.join("configuration.redb"));
    drop(db);
    assert_eq!(
        value(&open_private_database(&root.join("configuration.redb")).expect("winner persisted")),
        number
    );
}

fn park_at(root: &Path, target: &str, step: &str) -> io::Result<()> {
    if target == step {
        fs::write(root.join("ready.pending"), step)?;
        fs::rename(root.join("ready.pending"), root.join("ready"))?;
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
#[test]
fn database_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_DATABASE_PUBLICATION_CUT") else {
        return;
    };
    let root = Path::new(&root);
    let target = std::env::var("QPERIAPT_DATABASE_PUBLICATION_STEP").expect("step");
    let _db = provision_database_with(
        &root.join("configuration.redb"),
        |db| {
            let mut tx = db.begin_write().map_err(storage)?;
            tx.set_durability(Durability::Immediate).map_err(storage)?;
            tx.set_two_phase_commit(true);
            tx.open_table(TABLE)
                .map_err(storage)?
                .insert("genesis", 73)
                .map_err(storage)?;
            park_at(root, &target, "before-commit").map_err(PrivateDatabaseError::Io)?;
            tx.commit().map_err(storage)?;
            park_at(root, &target, "after-commit").map_err(PrivateDatabaseError::Io)?;
            Ok::<_, PrivateDatabaseError>(())
        },
        |staged| {
            staged.publish_with(&staged.file()?, &mut |step, _, _, _| {
                park_at(root, &target, &format!("{step:?}"))
            })
        },
    )
    .expect("publish");
    fs::write(root.join("owner-returned"), b"owner").expect("release marker");
}
#[test]
fn database_process_cuts_preserve_exclusion_and_original_published_genesis() {
    for cut in [
        "before-commit",
        "after-commit",
        "FileSynced",
        "Published",
        "DirectorySynced",
    ] {
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        let path = root.join("configuration.redb");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "filesystem::publication::database_tests::database_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_DATABASE_PUBLICATION_CUT", &root)
                .env("QPERIAPT_DATABASE_PUBLICATION_STEP", cut)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("creator"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "missing cut {cut}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("owner-returned").exists());
        let published = matches!(cut, "Published" | "DirectorySynced");
        if published {
            busy(&path);
        } else {
            assert!(!path.exists());
            busy(&stage(&root));
        }
        child.0.kill().expect("kill original creator");
        assert!(!child.0.wait().expect("reap").success());
        if published {
            assert_eq!(
                value(&open_private_database(&path).expect("recover original committed image")),
                73
            );
            assert!(provision_private_database(&path, |db| seed(db, 99)).is_err());
        } else {
            assert!(!path.exists());
            let orphan = stage(&root);
            let before = fs::read(&orphan).expect("orphan");
            drop(
                provision_private_database(&path, |db| seed(db, 99))
                    .expect("explicit first use retry"),
            );
            assert_eq!(
                value(&open_private_database(&path).expect("new initial image")),
                99
            );
            assert_eq!(fs::read(orphan).expect("orphan never selected"), before);
        }
        eprintln!("DATABASE_PUBLICATION_PROCESS_CUT cut={cut} published={published} original_owner_returned=false");
    }
}
