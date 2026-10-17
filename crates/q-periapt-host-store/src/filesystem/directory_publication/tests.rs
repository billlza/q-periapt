use super::*;
use crate::filesystem::publish_private_bytes;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
};

fn root() -> io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("private-tree-test-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
}
fn prepare(path: &Path) -> Result<(), PrivatePublicationError> {
    publish_private_bytes(
        &path.join("policy"),
        b"complete signed public configuration",
    )?;
    publish_private_bytes(&path.join("credential"), b"complete private fixture input")
}
fn complete(path: &Path) -> io::Result<()> {
    assert_eq!(
        fs::read(path.join("policy"))?,
        b"complete signed public configuration"
    );
    assert_eq!(
        fs::read(path.join("credential"))?,
        b"complete private fixture input"
    );
    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o700);
    Ok(())
}

#[test]
fn complete_tree_publishes_once_and_existing_tree_is_unchanged(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = root()?;
    let parent = temp.path().canonicalize()?;
    let target = parent.join("installation");
    publish_private_directory(&target, prepare)?;
    complete(&target)?;
    let mut called = false;
    let result = publish_private_directory(&target, |_| {
        called = true;
        Ok::<_, PrivatePublicationError>(())
    });
    assert_eq!(
        result.expect_err("existing destination").operation().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(!called);
    complete(&target)?;
    assert_eq!(fs::read_dir(&parent)?.count(), 1);
    Ok(())
}

#[test]
fn existing_file_empty_directory_and_symlink_never_become_first_use(
) -> Result<(), Box<dyn std::error::Error>> {
    for variant in 0..3 {
        let temp = root()?;
        let parent = temp.path().canonicalize()?;
        let target = parent.join("installation");
        match variant {
            0 => fs::write(&target, b"sentinel")?,
            1 => fs::create_dir(&target)?,
            _ => symlink("missing", &target)?,
        }
        let mut called = false;
        let error = publish_private_directory(&target, |_| {
            called = true;
            Ok::<_, PrivatePublicationError>(())
        })
        .expect_err("existing destination");
        assert_eq!(error.operation().kind(), io::ErrorKind::AlreadyExists);
        assert!(!called);
        assert_eq!(fs::read_dir(&parent)?.count(), 1);
        if variant == 0 {
            assert_eq!(fs::read(&target)?, b"sentinel");
        }
        if variant == 2 {
            assert_eq!(fs::read_link(&target)?, Path::new("missing"));
        }
    }
    Ok(())
}

#[test]
fn preparation_error_and_panic_leave_only_unpublished_staging(
) -> Result<(), Box<dyn std::error::Error>> {
    for panic in [false, true] {
        let temp = root()?;
        let parent = temp.path().canonicalize()?;
        let target = parent.join("installation");
        let result = std::panic::catch_unwind(|| {
            publish_private_directory(&target, |path| {
                publish_private_bytes(&path.join("policy"), b"partial private preparation")?;
                if panic {
                    std::panic::resume_unwind(Box::new("injected initializer unwind"));
                }
                Err::<(), _>(PrivatePublicationError::from(io::Error::other(
                    "injected initialization error",
                )))
            })
        });
        assert!(!target.exists());
        assert_eq!(fs::read_dir(&parent)?.count(), 1);
        let staging = fs::read_dir(&parent)?
            .next()
            .ok_or("missing staging")??
            .path();
        assert_eq!(
            fs::read(staging.join("policy"))?,
            b"partial private preparation"
        );
        if panic {
            let payload = result.expect_err("injected unwind must propagate");
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&"injected initializer unwind")
            );
        } else {
            assert!(result.expect("ordinary error").is_err());
        }
    }
    Ok(())
}

#[test]
fn every_publication_error_retains_original_error_and_complete_visible_tree(
) -> Result<(), Box<dyn std::error::Error>> {
    let steps = [
        Step::Created,
        Step::Initialized,
        Step::BeforeStagingSync,
        Step::StagingSynced,
        Step::BeforeRename,
        Step::Published,
        Step::BeforeParentSync,
        Step::ParentSynced,
    ];
    for (index, cut) in steps.into_iter().enumerate() {
        let temp = root()?;
        let parent = temp.path().canonicalize()?;
        let target = parent.join("installation");
        let error = publish_with(&target, prepare, |step, _| {
            if step == cut {
                Err(io::Error::from_raw_os_error(5))
            } else {
                Ok(())
            }
        })
        .expect_err("injected sync/publication cut");
        assert_eq!(error.operation().raw_os_error(), Some(5));
        assert!(error.staging_name().is_some());
        assert_eq!(target.exists(), index >= 5);
        assert_eq!(fs::read_dir(&parent)?.count(), 1);
        if index >= 5 {
            complete(&target)?;
        } else {
            let retained = parent.join(error.staging_name().ok_or("staging diagnostic")?);
            assert!(retained.is_dir());
            if index > 0 {
                complete(&retained)?;
            }
        }
    }
    Ok(())
}

#[test]
fn concurrent_publications_release_exactly_one_complete_directory(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = root()?;
    let parent = temp.path().canonicalize()?;
    let target = parent.join("installation");
    let (ready, admitted) = mpsc::channel();
    let mut tasks = Vec::new();
    let mut releases = Vec::new();
    for value in [b"first".as_slice(), b"second".as_slice()] {
        let destination = target.clone();
        let ready = ready.clone();
        let (release, proceed) = mpsc::channel();
        releases.push(release);
        tasks.push(std::thread::spawn(move || {
            publish_with(
                &destination,
                |path| publish_private_bytes(&path.join("value"), value),
                |step, _| {
                    if step == Step::BeforeRename {
                        ready.send(()).map_err(io::Error::other)?;
                        proceed
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .map_err(io::Error::other)?;
                    }
                    Ok(())
                },
            )
        }));
    }
    let both_admitted = (0..2).all(|_| {
        admitted
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok()
    });
    let released = releases
        .into_iter()
        .map(|release| release.send(()).is_ok())
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|t| t.join().expect("publication worker"))
        .collect::<Vec<_>>();
    assert!(both_admitted);
    assert!(released.into_iter().all(|sent| sent));
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r
                .as_ref()
                .is_err_and(|e| e.operation().kind() == io::ErrorKind::AlreadyExists))
            .count(),
        1
    );
    let bytes = fs::read(target.join("value"))?;
    assert!(bytes == b"first" || bytes == b"second");
    assert_eq!(fs::read_dir(&parent)?.count(), 2);
    Ok(())
}

#[test]
fn published_database_keeps_its_original_lease_and_reopens_its_committed_image(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::filesystem::{open_private_database, provision_private_database};
    use redb::ReadableDatabase;
    const TABLE: redb::TableDefinition<u64, u64> = redb::TableDefinition::new("first-install");
    let temp = root()?;
    let target = temp.path().canonicalize()?.join("installation");
    let database = publish_private_directory(&target, |staging| {
        prepare(staging)?;
        let database = provision_private_database(&staging.join("sdk.redb"), |database| {
            let mut transaction = database.begin_write()?;
            transaction.set_durability(redb::Durability::Immediate)?;
            transaction.set_two_phase_commit(true);
            {
                let mut table = transaction.open_table(TABLE)?;
                table.insert(7, 19)?;
            }
            transaction.commit()?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        Ok::<_, Box<dyn std::error::Error>>(database)
    })?;
    complete(&target)?;
    assert!(matches!(
        open_private_database(&target.join("sdk.redb")),
        Err(crate::filesystem::PrivateDatabaseError::Busy)
    ));
    assert_eq!(
        database
            .begin_read()?
            .open_table(TABLE)?
            .get(7)?
            .ok_or("missing value")?
            .value(),
        19
    );
    drop(database);
    let reopened = open_private_database(&target.join("sdk.redb"))?;
    assert_eq!(
        reopened
            .begin_read()?
            .open_table(TABLE)?
            .get(7)?
            .ok_or("missing value")?
            .value(),
        19
    );
    Ok(())
}

#[test]
fn directory_exit_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = std::env::var_os("QPERIAPT_DIRECTORY_EXIT_TARGET") else {
        return Ok(());
    };
    let cut = match std::env::var("QPERIAPT_DIRECTORY_EXIT_STEP")?.as_str() {
        "created" => Step::Created,
        "initialized" => Step::Initialized,
        "before-rename" => Step::BeforeRename,
        "published" => Step::Published,
        "before-parent-sync" => Step::BeforeParentSync,
        "parent-synced" => Step::ParentSynced,
        _ => return Err("unknown child cut".into()),
    };
    publish_with(Path::new(&target), prepare, |step, _| {
        if step == cut {
            // Immediate process exit deliberately bypasses Rust owner destructors.
            std::process::exit(79);
        }
        Ok(())
    })?;
    Err("child did not reach publication cut".into())
}

#[test]
fn process_exit_never_leaves_a_partial_formal_directory() -> Result<(), Box<dyn std::error::Error>>
{
    use std::{
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.0.try_wait().expect("child status").is_none() {
                self.0.kill().expect("stop owned child");
                self.0.wait().expect("reap owned child");
            }
        }
    }
    for (index, cut) in [
        "created",
        "initialized",
        "before-rename",
        "published",
        "before-parent-sync",
        "parent-synced",
    ]
    .into_iter()
    .enumerate()
    {
        let temp = root()?;
        let parent = temp.path().canonicalize()?;
        let target = parent.join("installation");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "filesystem::directory_publication::tests::directory_exit_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_DIRECTORY_EXIT_TARGET", &target)
                .env("QPERIAPT_DIRECTORY_EXIT_STEP", cut)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("publication child deadline expired".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(79));
        assert_eq!(target.exists(), index >= 3);
        if index >= 3 {
            complete(&target)?;
            assert!(publish_private_directory(&target, prepare).is_err());
            complete(&target)?;
        } else {
            // Explicit first-use retry creates a fresh complete tree. The orphan
            // remains private and is never selected, swept or promoted.
            assert_eq!(fs::read_dir(&parent)?.count(), 1);
            publish_private_directory(&target, prepare)?;
            complete(&target)?;
            assert_eq!(fs::read_dir(&parent)?.count(), 2);
        }
    }
    Ok(())
}

#[test]
fn stage_substitution_and_permission_change_are_refused() -> Result<(), Box<dyn std::error::Error>>
{
    for replace in [false, true] {
        let temp = root()?;
        let parent = temp.path().canonicalize()?;
        let target = parent.join("installation");
        let error = publish_with(&target, prepare, |step, stage| {
            if step == Step::BeforeRename {
                if replace {
                    fs::rename(&stage.path, parent.join("original-staging"))?;
                    fs::create_dir(&stage.path)?;
                    fs::set_permissions(&stage.path, fs::Permissions::from_mode(0o700))?;
                } else {
                    fs::set_permissions(&stage.path, fs::Permissions::from_mode(0o755))?;
                }
            }
            Ok(())
        })
        .expect_err("changed directory authority");
        assert_eq!(error.operation().kind(), io::ErrorKind::PermissionDenied);
        assert!(!target.exists());
        if replace {
            complete(&parent.join("original-staging"))?;
        }
    }
    Ok(())
}

#[test]
fn failed_publication_drops_the_unreleased_owner() -> Result<(), Box<dyn std::error::Error>> {
    struct Owner(Arc<AtomicBool>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let temp = root()?;
    let target = temp.path().canonicalize()?.join("installation");
    let dropped = Arc::new(AtomicBool::new(false));
    let result = publish_with(
        &target,
        |path| {
            prepare(path)?;
            Ok::<_, PrivatePublicationError>(Owner(Arc::clone(&dropped)))
        },
        |step, _| {
            if step == Step::Published {
                Err(io::Error::other("after publication"))
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert!(dropped.load(Ordering::SeqCst));
    complete(&target)?;
    Ok(())
}
