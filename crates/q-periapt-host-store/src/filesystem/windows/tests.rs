use super::*;
use crate::filesystem::test_directory::directory;
use crate::filesystem::{
    open_private_database, open_private_file, provision_private_database, publish_private_bytes,
    PrivateDatabaseError,
};
use redb::ReadableDatabase;
use std::{
    io::{Read, Write},
    os::windows::fs::OpenOptionsExt,
    process::Command,
    time::{Duration, Instant},
};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, WRITE_DAC,
};

#[test]
fn explicit_private_creation_and_no_replace_preserve_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = directory()?;
    let root = temporary.path();
    let state = root.join("state.bin");
    assert!(open_private_file(&state, false).is_err());
    let mut file = open_private_file(&state, true)?;
    file.write_all(b"original")?;
    file.sync_all()?;
    assert!(open_private_file(&state, true).is_err());
    let mut actual = Vec::new();
    open_private_file(&state, false)?.read_to_end(&mut actual)?;
    assert_eq!(actual, b"original");
    let image = root.join("image.bin");
    publish_private_bytes(&image, b"published")?;
    assert!(publish_private_bytes(&image, b"replacement").is_err());
    assert_eq!(std::fs::read(image)?, b"published");
    assert_eq!(std::fs::read(state)?, b"original");
    Ok(())
}

#[test]
fn hard_links_and_reparse_paths_are_refused() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = directory()?;
    let root = temporary.path();
    let state = root.join("state.bin");
    publish_private_bytes(&state, b"original")?;
    let alias = root.join("alias.bin");
    std::fs::hard_link(&state, &alias)?;
    assert!(open_private_file(&state, false).is_err());
    assert!(open_private_file(&alias, false).is_err());
    let plain = root.join("plain.bin");
    publish_private_bytes(&plain, b"single-link target")?;
    let link = root.join("linked.bin");
    std::os::windows::fs::symlink_file(&plain, &link)?;
    assert!(open_private_file(&link, false).is_err());
    let directory_alias = root.join("directory-link");
    std::os::windows::fs::symlink_dir(root, &directory_alias)?;
    assert!(open_private_file(&directory_alias.join("new.bin"), true).is_err());
    assert!(!root.join("new.bin").exists());
    assert_eq!(std::fs::read(state)?, b"original");
    Ok(())
}

#[test]
fn broad_file_and_directory_dacls_are_refused_without_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = directory()?;
    let root = temporary.path();
    let state = root.join("state.bin");
    publish_private_bytes(&state, b"original")?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
        .open(&state)?;
    crate::windows_acl::grant_everyone_read_for_test(&file)?;
    assert!(open_private_file(&state, false).is_err());
    assert_eq!(std::fs::read(&state)?, b"original");

    let parent = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    crate::windows_acl::grant_everyone_read_for_test(&parent)?;
    assert!(open_private_file(&root.join("new.bin"), true).is_err());
    assert!(!root.join("new.bin").exists());
    assert_eq!(std::fs::read(state)?, b"original");
    Ok(())
}

#[test]
fn leaf_aliases_streams_and_oversized_names_are_refused() {
    for name in [
        "",
        ".",
        "..",
        "file:stream",
        "folder/file",
        "folder\\file",
        "CON",
        "com1.bin",
        "COM¹.bin",
        "LPT³",
        "file?name",
        "new\nline",
        "trailing.",
        "trailing ",
    ] {
        assert!(native::leaf(OsStr::new(name)).is_err(), "{name}");
    }
    assert!(native::leaf(OsStr::new(&"a".repeat(256))).is_err());
    assert!(native::leaf(OsStr::new("state.redb")).is_ok());
}

#[test]
fn private_database_lock_child() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = std::env::var_os("QPC_PRIVATE_DATABASE_CHILD") {
        assert!(matches!(
            open_private_database(Path::new(&path)),
            Err(PrivateDatabaseError::Busy)
        ));
    }
    Ok(())
}

fn require_other_process_busy(path: &Path) -> io::Result<()> {
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "filesystem::windows::tests::private_database_lock_child",
            "--nocapture",
        ])
        .env("QPC_PRIVATE_DATABASE_CHILD", path)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("lock child failed: {status}")))
            };
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "lock child exceeded deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn published_database_retains_original_lock_and_committed_state(
) -> Result<(), Box<dyn std::error::Error>> {
    const TABLE: redb::TableDefinition<&str, u64> = redb::TableDefinition::new("state");
    let temporary = directory()?;
    let root = temporary.path();
    let path = root.join("state.redb");
    let database = provision_private_database::<PrivateDatabaseError>(&path, |db| {
        let result = (|| -> Result<(), redb::Error> {
            let mut tx = db.begin_write()?;
            tx.set_durability(redb::Durability::Immediate)?;
            tx.set_two_phase_commit(true);
            tx.open_table(TABLE)?.insert("genesis", 17)?;
            tx.commit()?;
            Ok(())
        })();
        result.map_err(|error| PrivateDatabaseError::Storage(Box::new(error)))
    })?;
    require_other_process_busy(&path)?;
    let probe = open_private_file(&path, false)?;
    drop(probe.try_clone()?);
    drop(probe);
    require_other_process_busy(&path)?;
    drop(database);
    let reopened = open_private_database(&path)?;
    let tx = reopened.begin_read()?;
    let table = tx.open_table(TABLE)?;
    assert_eq!(table.get("genesis")?.map(|row| row.value()), Some(17));
    Ok(())
}

#[test]
fn signed_policy_replacement_is_durable_and_aliases_remain_owner_bound(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::PolicyStore;
    use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
    use q_periapt_policy::policy_signature_message;
    use q_periapt_sdk::{Error, Limits};
    use q_periapt_sig::Signer;

    let temporary = directory()?;
    let folder = temporary.path();
    let path = folder.join("policy.redb");
    let (key, root) = MlDsa65::generate([91; 32]);
    let sign = |version, enabled| -> io::Result<(Vec<u8>, Vec<u8>)> {
        let kem = if enabled { "ML-KEM-768" } else { "ML-KEM-1024" };
        let policy = format!(
            "schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\n\
             default_profile = \"ContextBound\"\nallowed_kems = [\"{kem}\", \"X25519\"]\n\
             allowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n"
        )
        .into_bytes();
        let mut signature = vec![0; ML_DSA_65_SIG_LEN];
        MlDsa65
            .sign(
                &key,
                &policy_signature_message(&policy),
                &[0; 32],
                &mut signature,
            )
            .map_err(|error| io::Error::other(format!("fixture signing: {error}")))?;
        Ok((policy, signature))
    };
    let initial = sign(1, true)?;
    let revoked = sign(2, false)?;
    let mut store =
        PolicyStore::provision(&path, &initial.0, &initial.1, &root, Limits::default())?;
    let previous = store.runtime()?;
    assert!(previous.is_enabled()?);
    assert!(matches!(
        previous.prepare_policy_update(&revoked.0, &revoked.1),
        Err(Error::UpdateOwnerRequired)
    ));
    let current = store.replace_policy(previous.trusted_state(), &revoked.0, &revoked.1)?;
    assert!(matches!(previous.is_enabled(), Err(Error::Closed)));
    assert!(!current.is_enabled()?);
    let committed = current.trusted_state();
    store.close();
    assert!(matches!(current.is_enabled(), Err(Error::Closed)));
    let reopened =
        PolicyStore::open_configured(&path, &revoked.0, &revoked.1, &root, Limits::default())?;
    let restored = reopened.runtime()?;
    assert_eq!(restored.trusted_state(), committed);
    assert!(!restored.is_enabled()?);
    assert!(matches!(
        restored.prepare_policy_update(&initial.0, &initial.1),
        Err(Error::UpdateOwnerRequired)
    ));
    drop(reopened);
    assert!(matches!(restored.is_enabled(), Err(Error::Closed)));
    Ok(())
}

#[test]
fn retained_file_identity_requires_local_private_single_link_file(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = directory()?;
    let root = temporary.path();
    let path = root.join("identity.bin");
    publish_private_bytes(&path, b"original")?;
    let first = open_private_file(&path, false)?;
    let id = private_file_identity(&first)?;
    assert_eq!(id, private_file_identity(&first.try_clone()?)?);
    assert_eq!(
        id,
        private_file_identity(&open_private_file(&path, false)?)?
    );
    let substitute = root.join("substitute.bin");
    publish_private_bytes(&substitute, b"original")?;
    assert_ne!(
        id,
        private_file_identity(&open_private_file(&substitute, false)?)?
    );
    let alias = root.join("alias.bin");
    std::fs::hard_link(&path, &alias)?;
    assert!(
        private_file_identity(&first).is_err(),
        "identity must recheck link count"
    );
    std::fs::remove_file(&alias)?;
    assert_eq!(id, private_file_identity(&first)?);
    let mutable_acl = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
        .open(&path)?;
    crate::windows_acl::grant_everyone_read_for_test(&mutable_acl)?;
    assert!(
        private_file_identity(&first).is_err(),
        "identity must recheck private DACL"
    );
    let directory = OwnedPrivateDirectory::open(root)?;
    assert!(private_file_identity(&directory.descriptor).is_err());
    assert_eq!(std::fs::read(path)?, b"original");
    Ok(())
}
