//! Configuration reads use the original private directory and a read-only handle.
use super::*;
use crate::filesystem::{open_private_file, publish_private_bytes, test_directory::directory};
use std::{
    fs,
    io::{Read, Write},
    os::windows::fs::OpenOptionsExt,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, WRITE_DAC},
};

#[test]
fn configuration_reads_are_bounded_read_only_and_never_create(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = directory()?;
    let root = temporary.path();
    publish_private_bytes(&root.join("config"), b"configuration")?;
    let directory = OwnedPrivateDirectory::open(root)?;
    let mut file = directory.open_config_file("config", 13)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"configuration");
    assert!(
        file.write_all(b"change").is_err(),
        "returned handle must not grant write access"
    );
    assert!(file.try_clone()?.write_all(b"change").is_err());
    assert!(directory.open_config_file("config", 12).is_err());
    assert!(directory.open_config_file("config", 0).is_err());
    assert!(directory.open_config_file("missing", 64).is_err());
    assert!(!root.join("missing").exists());
    drop(open_private_file(&root.join("empty"), true)?);
    assert!(directory.open_config_file("empty", 64).is_err());
    assert_eq!(fs::read(root.join("config"))?, b"configuration");
    Ok(())
}

#[test]
fn configuration_refuses_links_nested_paths_and_changed_file_acl(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = directory()?;
    let root = temporary.path();
    let path = root.join("config");
    publish_private_bytes(&path, b"original")?;
    let directory = OwnedPrivateDirectory::open(root)?;
    let nested = native::create(&directory.descriptor, OsStr::new("nested"), true)?;
    drop(nested);
    publish_private_bytes(&root.join("nested/inside"), b"nested bytes")?;
    for name in [
        "nested",
        "nested/inside",
        "nested\\inside",
        ".",
        "..",
        "config.",
        "config ",
        "config:stream",
    ] {
        assert!(directory.open_config_file(name, 64).is_err(), "{name}");
    }
    let alias = root.join("alias");
    fs::hard_link(&path, &alias)?;
    assert!(directory.open_config_file("config", 64).is_err());
    assert!(directory.open_config_file("alias", 64).is_err());
    fs::remove_file(alias)?;
    std::os::windows::fs::symlink_file(&path, root.join("linked"))?;
    assert!(directory.open_config_file("linked", 64).is_err());
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
        .open(&path)?;
    crate::windows_acl::grant_everyone_read_for_test(&file)?;
    assert!(directory.open_config_file("config", 64).is_err());
    assert_eq!(fs::read(path)?, b"original");
    Ok(())
}

#[test]
fn configuration_keeps_pinned_parent_and_rechecks_its_acl() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = directory()?;
    let root = temporary.path();
    let parent = OwnedPrivateDirectory::open(root)?;
    let child = native::create(&parent.descriptor, OsStr::new("original"), true)?;
    drop(child);
    let original = root.join("original");
    publish_private_bytes(&original.join("config"), b"retained original")?;
    let pinned = OwnedPrivateDirectory::open(&original)?;
    let held = root.join("held");
    fs::rename(&original, &held)?;
    let replacement = native::create(&parent.descriptor, OsStr::new("original"), true)?;
    drop(replacement);
    publish_private_bytes(&original.join("config"), b"replacement")?;
    let mut bytes = Vec::new();
    pinned
        .open_config_file("config", 64)?
        .read_to_end(&mut bytes)?;
    assert_eq!(
        bytes, b"retained original",
        "never re-resolve the old parent pathname"
    );
    let mutable_acl = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&held)?;
    crate::windows_acl::grant_everyone_read_for_test(&mutable_acl)?;
    assert!(
        pinned.open_config_file("config", 64).is_err(),
        "revalidate the original directory DACL"
    );
    assert_eq!(fs::read(held.join("config"))?, b"retained original");
    assert_eq!(fs::read(original.join("config"))?, b"replacement");
    Ok(())
}
