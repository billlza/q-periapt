//! Read actual C application records through the independent native private-file boundary.
use super::{wait_for_c, OwnedChild, TestResult};
use q_periapt_host_store::filesystem::{
    publish_private_bytes, publish_private_directory, OwnedPrivateDirectory,
    PrivatePublicationError,
};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn directory(path: &Path) -> TestResult<()> {
    publish_private_directory(path, |_| Ok::<_, PrivatePublicationError>(()))?;
    Ok(())
}
fn run(root: &Path, path: &Path, label: &str, reject: bool) -> TestResult<()> {
    let client =
        PathBuf::from(std::env::var_os("QPC_EFFECT_CLIENT").ok_or("C effect client missing")?);
    let mut command = Command::new(client);
    if reject {
        command.arg("--reject");
    }
    let stdout = root.join(format!("effect-{label}.stdout"));
    let stderr = root.join(format!("effect-{label}.stderr"));
    let mut child = OwnedChild(
        command
            .arg(path)
            .stdout(Stdio::from(fs::File::create_new(&stdout)?))
            .stderr(Stdio::from(fs::File::create_new(&stderr)?))
            .spawn()?,
    );
    let status = wait_for_c(&mut child, label)?;
    let err = fs::read_to_string(stderr)?;
    assert_eq!(status.code(), Some(0), "effect {label}: {err}");
    assert!(err.is_empty(), "effect {label}: {err}");
    assert_eq!(
        fs::read_to_string(stdout)?,
        if reject {
            "effect-refusal: original directory and file boundary retained\n"
        } else {
            "effect-contract: two exact effects, duplicate idempotence, wrong payload and conflicting replay refused\n"
        }
    );
    eprintln!("WINDOWS_C_EFFECT case={label} original_boundary=true");
    Ok(())
}
pub(super) fn check(root: &Path) -> TestResult<()> {
    // Exercise actual UTF-8 caller paths through a wide-character process entry.
    let effects = root.join("effects-\u{6d4b}\u{8bd5}");
    directory(&effects)?;
    run(root, &effects, "commit", false)?;
    let retained = OwnedPrivateDirectory::open(&effects).map_err(io::Error::other)?;
    assert_eq!(fs::read_dir(&effects)?.count(), 2, "staging files remain");
    for (id, body) in [
        (2u8, b"persisted before process exit".as_slice()),
        (3u8, b"continued after pending recovery".as_slice()),
    ] {
        let name = format!("application-{id:02x}{}", "00".repeat(31));
        let mut file = retained
            .open_config_file(&name, 128)
            .map_err(io::Error::other)?;
        let mut data = Vec::new();
        (&mut file).take(129).read_to_end(&mut data)?;
        let mut expected = vec![0u8; 64];
        *expected.first_mut().ok_or("session width")? = 1;
        *expected.get_mut(32).ok_or("message width")? = id;
        expected.extend_from_slice(body);
        assert_eq!(data, expected, "native C record bytes");
    }
    drop(retained);
    let boundary = root.join("effect-boundary");
    directory(&boundary)?;
    let nested = boundary.join("nested");
    directory(&nested)?;
    let alias = root.join("effect-directory-alias");
    std::os::windows::fs::symlink_dir(&boundary, &alias)?;
    run(root, &alias, "directory-reparse", true)?;
    run(root, &alias.join("nested"), "ancestor-reparse", true)?;
    assert_eq!(fs::read_dir(&nested)?.count(), 0);
    assert_eq!(fs::read_dir(&boundary)?.count(), 1);
    let target = root.join("effect-original");
    // Exact valid bytes make a missing no-follow/single-link check observable:
    // merely comparing different bytes would refuse even an unsafe open.
    let mut original = vec![0u8; 64];
    *original.first_mut().ok_or("session width")? = 1;
    *original.get_mut(32).ok_or("message width")? = 2;
    original.extend_from_slice(b"persisted before process exit");
    publish_private_bytes(&target, &original)?;
    let name = format!("application-02{}", "00".repeat(31));
    let linked = root.join("effect-linked");
    directory(&linked)?;
    std::os::windows::fs::symlink_file(&target, linked.join(&name))?;
    run(root, &linked, "leaf-reparse", true)?;
    let hard = root.join("effect-hardlink");
    directory(&hard)?;
    fs::hard_link(&target, hard.join(&name))?;
    run(root, &hard, "hardlink", true)?;
    assert_eq!(fs::read(&target)?, original);
    assert_eq!(fs::read_dir(&linked)?.count(), 1);
    assert_eq!(fs::read_dir(&hard)?.count(), 1);
    let public = root.join("effect-public-acl");
    directory(&public)?;
    let mut child = OwnedChild(
        Command::new("icacls")
            .arg(&public)
            .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
            .stdout(Stdio::from(fs::File::create_new(
                root.join("effect-acl.stdout"),
            )?))
            .stderr(Stdio::from(fs::File::create_new(
                root.join("effect-acl.stderr"),
            )?))
            .spawn()?,
    );
    assert!(wait_for_c(&mut child, "public-acl-control")?.success());
    assert!(
        OwnedPrivateDirectory::open(&public).is_err(),
        "ACL control remained private"
    );
    run(root, &public, "public-acl", true)?;
    assert_eq!(fs::read_dir(&public)?.count(), 0);
    Ok(())
}
