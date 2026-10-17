//! Native NTFS directory publication. Live child owners are deliberately retained and refused.
use super::*;
use crate::filesystem::{
    open_private_database, provision_private_database, publish_private_bytes,
    test_directory::directory, PrivateDatabaseError,
};
use redb::ReadableDatabase;
use std::{fs, sync::mpsc, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TABLE: redb::TableDefinition<u64, u64> = redb::TableDefinition::new("prepared");

#[path = "windows_process_tests.rs"]
mod process;

fn prepare(path: &Path) -> std::result::Result<(), PrivatePublicationError> {
    publish_private_bytes(&path.join("policy"), b"complete public fixture")?;
    publish_private_bytes(&path.join("credential"), b"complete private fixture")
}
fn complete(path: &Path) -> Result<()> {
    OwnedPrivateDirectory::open(path)?;
    assert_eq!(fs::read(path.join("policy"))?, b"complete public fixture");
    assert_eq!(
        fs::read(path.join("credential"))?,
        b"complete private fixture"
    );
    Ok(())
}
fn new_database(path: &Path) -> Result<redb::Database> {
    provision_private_database(path, |database| {
        let mut tx = database.begin_write()?;
        tx.set_durability(redb::Durability::Immediate)?;
        tx.set_two_phase_commit(true);
        tx.open_table(TABLE)?.insert(7, 19)?;
        tx.commit()?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
}

#[test]
fn windows_complete_tree_never_replaces_an_existing_name() -> Result<()> {
    let temporary = directory()?;
    let parent = temporary.path();
    let target = parent.join("installation");
    publish_private_directory(&target, prepare)?;
    complete(&target)?;
    for name in ["installation", "empty", "file", "link"] {
        let path = parent.join(name);
        match name {
            "empty" => fs::create_dir(&path)?,
            "file" => fs::write(&path, b"sentinel")?,
            "link" => std::os::windows::fs::symlink_dir("missing", &path)?,
            _ => {}
        }
        let mut called = false;
        let error = publish_private_directory(&path, |_| {
            called = true;
            Ok::<_, PrivatePublicationError>(())
        })
        .expect_err("destination is not first use");
        // A reparse name can be rejected at admission before the existence result.
        assert!(matches!(
            error.operation().kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
        ));
        assert!(!called);
    }
    complete(&target)?;
    assert_eq!(fs::read(parent.join("file"))?, b"sentinel");
    assert_eq!(fs::read_link(parent.join("link"))?, Path::new("missing"));
    assert_eq!(fs::read_dir(parent)?.count(), 4);
    Ok(())
}

#[test]
fn windows_directory_boundaries_preserve_error_and_prepared_tree() -> Result<()> {
    for cut in [
        Step::Created,
        Step::Initialized,
        Step::BeforeStagingSync,
        Step::StagingSynced,
        Step::BeforeRename,
        Step::Published,
        Step::BeforeParentSync,
        Step::ParentSynced,
    ] {
        let temporary = directory()?;
        let parent = temporary.path();
        let target = parent.join("installation");
        let error = publish_with(&target, prepare, |stage, _| {
            if stage == cut {
                Err(io::Error::other("directory boundary sentinel"))
            } else {
                Ok(())
            }
        })
        .expect_err("injected boundary cannot return success");
        assert_eq!(error.operation().to_string(), "directory boundary sentinel");
        let staged = parent.join(error.staging_name().ok_or("missing staging identity")?);
        let published = matches!(
            cut,
            Step::Published | Step::BeforeParentSync | Step::ParentSynced
        );
        assert_eq!(target.exists(), published);
        assert_eq!(staged.exists(), !published);
        assert_eq!(
            fs::read_dir(parent)?.count(),
            1,
            "failure cannot clean up names"
        );
        if cut == Step::Created {
            assert_eq!(fs::read_dir(staged)?.count(), 0);
        } else {
            complete(if published { &target } else { &staged })?;
        }
        eprintln!("WINDOWS_DIRECTORY_FAULT cut={cut:?} published={published} original_error=true no_returned_value=true");
    }
    Ok(())
}

#[test]
fn windows_directory_keeps_live_database_lease_and_refuses_rename() -> Result<()> {
    let temporary = directory()?;
    let parent = temporary.path();
    let target = parent.join("installation");
    let mut original = None;
    let result: Result<redb::Database> = publish_with(
        &target,
        |staging| {
            prepare(staging)?;
            original = Some(staging.to_owned());
            new_database(&staging.join("sdk.redb"))
        },
        |stage, staging| {
            if stage == Step::BeforeRename {
                assert!(
                    matches!(
                        open_private_database(&staging.path.join("sdk.redb")),
                        Err(PrivateDatabaseError::Busy)
                    ),
                    "publisher must not release the initializer's owner"
                );
            }
            Ok(())
        },
    );
    assert!(
        result.is_err(),
        "Windows cannot publish a directory with this live child handle"
    );
    assert!(!target.exists());
    let staged = original.ok_or("initializer did not run")?;
    complete(&staged)?;
    let database = open_private_database(&staged.join("sdk.redb"))?;
    assert_eq!(
        database
            .begin_read()?
            .open_table(TABLE)?
            .get(7)?
            .ok_or("missing row")?
            .value(),
        19
    );
    eprintln!("WINDOWS_DIRECTORY_LIVE_CHILD lock_retained_until_rename=true publication_refused=true original_image_preserved=true");
    Ok(())
}

#[test]
fn windows_concurrent_directory_publishers_choose_one_complete_tree() -> Result<()> {
    let temporary = directory()?;
    let target = temporary.path().join("installation");
    let (ready, observed) = mpsc::channel();
    std::thread::scope(|scope| -> Result<()> {
        let mut producers = Vec::new();
        let mut releases = Vec::new();
        for byte in [17u8, 29u8] {
            let ready = ready.clone();
            let target = &target;
            let (release, start) = mpsc::channel();
            releases.push(release);
            producers.push(scope.spawn(move || {
                publish_with(
                    target,
                    |staging| publish_private_bytes(&staging.join("winner"), &[byte]),
                    |stage, _| {
                        if stage == Step::Initialized {
                            ready.send(()).map_err(io::Error::other)?;
                            start
                                .recv_timeout(Duration::from_secs(10))
                                .map_err(io::Error::other)?;
                        }
                        Ok(())
                    },
                )
            }));
        }
        for _ in 0..2 {
            observed.recv_timeout(Duration::from_secs(10))?;
        }
        for release in releases {
            release.send(())?;
        }
        let results: Vec<_> = producers
            .into_iter()
            .map(|p| p.join().expect("publisher panic"))
            .collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
        Ok(())
    })?;
    let bytes = fs::read(target.join("winner"))?;
    assert!(bytes == [17] || bytes == [29]);
    assert_eq!(
        fs::read_dir(temporary.path())?.count(),
        2,
        "loser staging remains"
    );
    Ok(())
}

#[test]
fn windows_directory_delete_access_is_deferred_until_rename() -> Result<()> {
    use crate::filesystem::windows_native as native;
    let temporary = directory()?;
    let parent = OwnedPrivateDirectory::open(temporary.path())?;
    let name = OsStr::new("preparing");
    let original = ops::create_directory(&parent, name)?;
    let path = temporary.path().join(name);
    publish_private_bytes(&path.join("first"), b"prepared without delete access")?;
    let early_delete = native::open(&parent.descriptor, name, native::OpenKind::DirectoryRename)?;
    let blocked = publish_private_bytes(&path.join("second"), b"same original input");
    let observation = match &blocked {
        Ok(()) => "permitted",
        Err(error) => {
            assert_eq!(
                error.operation().raw_os_error(),
                Some(32),
                "unexpected control failure"
            );
            assert!(!path.join("second").exists());
            "sharing_violation"
        }
    };
    drop(early_delete);
    if blocked.is_err() {
        // Explicit fixture retry of a never-published byte image. The production
        // publisher has no retry, handle-closing fallback or cleanup branch.
        publish_private_bytes(&path.join("second"), b"same original input")?;
    }
    ops::rename_directory(&parent, name, OsStr::new("published"), &original)?;
    ops::same_directory(&parent, OsStr::new("published"), &original)?;
    assert_eq!(
        fs::read(temporary.path().join("published/second"))?,
        b"same original input"
    );
    eprintln!("WINDOWS_DIRECTORY_ACCESS early_delete={observation} no_delete_preparation=passed original_pin_retained=true late_rename=passed");
    Ok(())
}
