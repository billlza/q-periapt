use super::*;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::{Child, Command, Stdio},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory")
}
fn stages(root: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(root)
        .expect("list owned fixture")
        .map(|entry| entry.expect("entry").path())
        .filter(|p| {
            p.file_name()
                .expect("leaf")
                .to_string_lossy()
                .starts_with(".private-publication-")
        })
        .collect()
}
#[derive(Debug)]
struct Injected(Step);
impl std::fmt::Display for Injected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "injected publication failure at {:?}", self.0)
    }
}
impl std::error::Error for Injected {}

#[test]
fn database_initialization_failure_never_publishes_partial_configuration() {
    use crate::filesystem::{provision_private_database, PrivateDatabaseError};
    let tmp = directory();
    let path = tmp
        .path()
        .canonicalize()
        .expect("path")
        .join("configuration.redb");
    let result = provision_private_database(&path, |db| {
        let _uncommitted = db
            .begin_write()
            .map_err(|e| PrivateDatabaseError::Storage(Box::new(e.into())))?;
        Err::<(), _>(PrivateDatabaseError::Io(io::Error::other(Injected(
            Step::Created,
        ))))
    });
    assert!(matches!(result, Err(PrivateDatabaseError::Io(ref error))
        if error.get_ref().and_then(|e| e.downcast_ref::<Injected>()).is_some()));
    assert!(
        !path.exists(),
        "failed initial transaction published a partial formal database"
    );
}

#[test]
fn every_publication_boundary_withholds_success_and_preserves_original_errors() {
    for target in [
        Step::Created,
        Step::Written,
        Step::BeforeFileSync,
        Step::FileSynced,
        Step::BeforeRename,
        Step::Published,
        Step::BeforeDirectorySync,
        Step::DirectorySynced,
    ] {
        let tmp = directory();
        let root = tmp.path().canonicalize().expect("path");
        let path = root.join("key");
        let error = publish_with(
            &path,
            b"complete original private image",
            |step, _, _, _| {
                if step == target {
                    Err(io::Error::other(Injected(step)))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("must withhold publication success");
        assert!(error
            .operation()
            .get_ref()
            .and_then(|e| e.downcast_ref::<Injected>())
            .is_some_and(|e| e.0 == target));
        assert!(error.staging_name().is_some());
        if matches!(
            target,
            Step::Published | Step::BeforeDirectorySync | Step::DirectorySynced
        ) {
            assert_eq!(
                fs::read(&path).expect("original retained"),
                b"complete original private image"
            );
            assert!(publish_private_bytes(&path, b"other").is_err());
            assert_eq!(
                fs::read(&path).expect("original retained"),
                b"complete original private image"
            );
        } else {
            assert!(!path.exists());
            assert_eq!(stages(&root).len(), 1);
            publish_private_bytes(&path, b"explicit first-use retry").expect("initial retry");
        }
        eprintln!("PRIVATE_PUBLICATION_FAULT step={target:?} exact_error=true destination_never_deleted=true");
    }
}

#[test]
fn concurrent_creators_have_one_winner_and_never_return_the_losing_image() {
    let tmp = directory();
    let root = tmp.path().canonicalize().expect("path");
    let barrier = Arc::new(Barrier::new(2));
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|image| {
                let barrier = &barrier;
                let root = &root;
                scope.spawn(move || {
                    (
                        image,
                        publish_with(&root.join("key"), image, |step, _, _, _| {
                            if step == Step::BeforeRename {
                                barrier.wait();
                            }
                            Ok(())
                        }),
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
    for (bytes, result) in results {
        match result {
            Ok(()) => assert_eq!(fs::read(root.join("key")).expect("winner"), bytes),
            Err(e) => {
                assert_eq!(e.operation().kind(), io::ErrorKind::AlreadyExists);
                assert!(e.staging_name().is_some());
            }
        }
    }
    assert_eq!(stages(&root).len(), 1);
}

#[test]
fn directory_sync_failure_and_losing_creator_preserve_a_concurrently_used_image() {
    let tmp = directory();
    let root = tmp.path().canonicalize().expect("path");
    let path = root.join("key");
    let error = publish_with(&path, b"original", |step, parent, _, _| {
        if step == Step::BeforeDirectorySync {
            let mut original = parent
                .open_state_file(OsStr::new("key"))
                .map_err(|_| admission())?;
            original.sync_all()?;
            parent.sync_entries().map_err(|_| admission())?;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut original, &mut bytes)?;
            fs::write(root.join("dependent"), bytes)?;
            let loser = publish_private_bytes(&path, b"loser").expect_err("NOREPLACE");
            assert_eq!(loser.operation().kind(), io::ErrorKind::AlreadyExists);
            return Err(io::Error::other(Injected(step)));
        }
        Ok(())
    })
    .expect_err("creator has no successful result");
    assert!(error.staging_name().is_some());
    assert_eq!(
        fs::read(path).expect("retained"),
        fs::read(root.join("dependent")).expect("dependent")
    );
    assert!(stages(&root).is_empty());
}

#[test]
fn existing_partial_symlink_and_hardlink_targets_are_never_replaced() {
    let tmp = directory();
    let root = tmp.path().canonicalize().expect("path");
    let original = root.join("original");
    fs::write(&original, b"original").expect("fixture");
    for name in ["partial", "symlink", "hardlink"] {
        let target = root.join(name);
        match name {
            "partial" => fs::write(&target, b"QPV").expect("partial"),
            "symlink" => std::os::unix::fs::symlink(&original, &target).expect("symlink"),
            _ => fs::hard_link(&original, &target).expect("hardlink"),
        }
        let before = fs::read(&target).expect("before");
        let error = publish_private_bytes(&target, b"replacement").expect_err("existing name");
        assert_eq!(error.operation().kind(), io::ErrorKind::AlreadyExists);
        assert!(error.staging_name().is_none());
        assert_eq!(fs::read(&target).expect("after"), before);
    }
    assert!(stages(&root).is_empty());
}

#[test]
fn substituted_or_linked_staging_inode_is_refused_without_deleting_any_replacement() {
    for linked in [false, true] {
        let tmp = directory();
        let root = tmp.path().canonicalize().expect("path");
        let error = publish_with(&root.join("key"), b"original", |step, _, leaf, _| {
            if step == Step::BeforeRename {
                if linked {
                    fs::hard_link(root.join(leaf), root.join("alias"))?;
                } else {
                    fs::rename(root.join(leaf), root.join("retained"))?;
                    let mut replacement = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(root.join(leaf))?;
                    replacement.write_all(b"replacement")?;
                }
            }
            Ok(())
        })
        .expect_err("changed inode");
        assert!(
            error.staging_name().is_some(),
            "staging correlation must remain observable"
        );
        assert!(!root.join("key").exists());
        assert_eq!(stages(&root).len(), 1);
        assert_eq!(
            fs::read(root.join(if linked { "alias" } else { "retained" })).expect("original"),
            b"original"
        );
        if !linked {
            assert_eq!(
                fs::read(stages(&root).first().expect("retained stage"))
                    .expect("replacement retained"),
                b"replacement"
            );
        }
    }
}

#[test]
fn publication_remains_beneath_the_original_pinned_parent() {
    let tmp = directory();
    let root = tmp.path().canonicalize().expect("path");
    let original = root.join("private");
    let moved = root.join("moved");
    fs::create_dir(&original).expect("directory");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).expect("mode");
    publish_with(&original.join("key"), b"original", |step, _, _, _| {
        if step == Step::BeforeRename {
            fs::rename(&original, &moved)?;
            fs::create_dir(&original)?;
            fs::set_permissions(&original, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    })
    .expect("pinned publication");
    assert!(!original.join("key").exists());
    assert_eq!(
        fs::read(moved.join("key")).expect("original parent"),
        b"original"
    );
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().expect("child status").is_none() {
            self.0.kill().expect("kill child");
            self.0.wait().expect("reap child");
        }
    }
}

#[test]
fn publication_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_PUBLICATION_CUT_DIRECTORY") else {
        return;
    };
    let root = Path::new(&root);
    let target = std::env::var("QPERIAPT_PUBLICATION_CUT_STEP").expect("step");
    publish_with(
        &root.join("key"),
        b"complete original private image",
        |step, _, _, file| {
            if format!("{step:?}") == target {
                if step == Step::Created {
                    // Model a short write interrupted before write_all can complete.
                    let mut file = file.try_clone()?;
                    file.write_all(b"partial")?;
                    file.sync_all()?;
                }
                fs::write(root.join("ready.pending"), &target)?;
                fs::rename(root.join("ready.pending"), root.join("ready"))?;
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        },
    )
    .expect("publish");
    fs::write(root.join("returned"), b"success").expect("result");
}

#[test]
fn actual_process_cuts_never_publish_partials_or_choose_orphans_on_retry() {
    for target in [
        Step::Created,
        Step::Written,
        Step::FileSynced,
        Step::Published,
        Step::DirectorySynced,
    ] {
        let tmp = directory();
        let root = tmp.path().canonicalize().expect("path");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "filesystem::publication::tests::publication_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_PUBLICATION_CUT_DIRECTORY", &root)
                .env("QPERIAPT_PUBLICATION_CUT_STEP", format!("{target:?}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "cut {target:?} not reached"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned").exists());
        child.0.kill().expect("kill at real syscall boundary");
        assert!(!child.0.wait().expect("reap").success());
        let published = matches!(target, Step::Published | Step::DirectorySynced);
        if published {
            assert!(stages(&root).is_empty());
            assert_eq!(
                fs::read(root.join("key")).expect("original"),
                b"complete original private image"
            );
            assert!(publish_private_bytes(&root.join("key"), b"other").is_err());
        } else {
            assert!(!root.join("key").exists());
            let before = stages(&root);
            assert_eq!(before.len(), 1);
            let orphan = fs::read(before.first().expect("one orphan")).expect("unpublished stage");
            publish_private_bytes(&root.join("key"), b"explicit new unpublished candidate")
                .expect("retry");
            assert_eq!(stages(&root), before);
            assert_eq!(
                fs::read(before.first().expect("one orphan")).expect("orphan untouched"),
                orphan
            );
            assert_eq!(
                fs::read(root.join("key")).expect("new initial image"),
                b"explicit new unpublished candidate"
            );
        }
        eprintln!("PRIVATE_PUBLICATION_PROCESS_CUT step={target:?} published={published} original_success_returned=false");
    }
}
