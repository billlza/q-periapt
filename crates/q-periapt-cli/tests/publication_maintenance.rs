//! Native maintenance-package boundary: invoke the real executable and stores.
#![cfg(all(
    feature = "publication-maintenance",
    any(target_os = "macos", target_os = "linux")
))]

use q_periapt_host_store::filesystem::{
    publish_private_bytes, publish_private_directory, PrivatePublicationError,
};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn command(attempt: &Path, entries: usize) -> Output {
    // Installed qualification explicitly selects the extracted, pinned binary.
    // Ordinary Cargo integration tests use their own real Cargo-built executable.
    let binary = std::env::var_os("QPERIAPT_PUBLICATION_MAINTENANCE_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_qperiapt")));
    Command::new(binary)
        .arg("publication-reclaim")
        .arg(attempt)
        .args([
            "--max-entries",
            &entries.to_string(),
            "--max-depth",
            "8",
            "--max-bytes",
            "1024",
        ])
        .output()
        .expect("real maintenance process")
}
fn refused(output: Output, message: &str) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "failure must not emit a successful result"
    );
    assert!(String::from_utf8(output.stderr)
        .expect("error encoding")
        .contains(message));
}

#[test]
fn real_cli_reclaims_only_the_bound_inactive_attempt_and_replays_original_result() {
    let temp = tempfile::Builder::new()
        .prefix("qperiapt-publication-maintenance-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("owned private fixture");
    let root = temp.path().canonicalize().expect("absolute private root");
    let formal = root.join("formal");
    let value = b"original unpublished bytes";
    let mut control = None;
    let result = publish_private_directory::<(), PrivatePublicationError>(&formal, |payload| {
        publish_private_bytes(&payload.join("key"), value)?;
        let attempt = payload.parent().expect("original control").to_owned();
        refused(command(&attempt, 16), "active owner");
        control = Some(attempt);
        Err(io::Error::other("original fixture initialization failure").into())
    });
    let error = result.expect_err("unpublished fixture");
    assert_eq!(
        error.operation().to_string(),
        "original fixture initialization failure"
    );
    let control = control.expect("initializer observed");
    let record = fs::read(control.join("record")).expect("original record");
    assert!(!formal.exists());
    refused(command(&control, 1), "work budget exceeded");
    assert!(!control.join("cleanup.intent").exists());
    assert_eq!(
        fs::read(control.join("payload/key")).expect("intact payload"),
        value
    );
    let first = command(&control, 16);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&first.stdout).expect("actual result");
    assert_eq!(
        parsed,
        serde_json::json!({
            "schema_version": 1, "operation": "private-publication-reclaim/v2",
            "attempt": control.file_name().expect("name").to_str().expect("canonical nonce"),
            "outcome": "reclaimed", "entries": 2, "bytes": value.len(),
        })
    );
    assert!(!control.join("payload").exists());
    assert!(!formal.exists());
    let intent = fs::read(control.join("cleanup.intent")).expect("original intent");
    let receipt = fs::read(control.join("cleanup.done")).expect("original receipt");
    let retry = command(&control, 16);
    assert!(retry.status.success());
    assert_eq!(retry.stdout, first.stdout);
    assert_eq!(
        fs::read(control.join("record")).expect("same record"),
        record
    );
    assert_eq!(
        fs::read(control.join("cleanup.intent")).expect("same intent"),
        intent
    );
    assert_eq!(
        fs::read(control.join("cleanup.done")).expect("same receipt"),
        receipt
    );
    publish_private_bytes(&formal, value).expect("independent published fixture");
    refused(command(&formal, 16), "scope or record differs");
    assert_eq!(fs::read(&formal).expect("published bytes retained"), value);
    eprintln!("PUBLICATION_MAINTENANCE_CLI_COMPLETE");
}
