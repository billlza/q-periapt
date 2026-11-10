// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn directory() -> Result<PathBuf> {
    let temp = tempfile::tempdir()?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    let path = temp.keep().canonicalize()?;
    eprintln!("SDK authority private fixture retained: {}", path.display());
    Ok(path)
}
fn document(version: u32) -> Vec<u8> {
    format!("schema_version=1\npolicy_version={version}\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n").into_bytes()
}
fn prepared(path: &Path) -> Result<AuthorityStore> {
    let mut owner = AuthorityStore::provision(path, [1; 32])?;
    owner.prepare()?;
    Ok(owner)
}
#[test]
fn sdk_publications_keep_exact_original_bytes_and_never_jump_versions() -> Result<()> {
    let dir = directory()?;
    let path = dir.join("authority.redb");
    let mut owner = prepared(&path)?;
    let root = owner.authority()?.root;
    for request in [
        document(0),
        document(2),
        document(u32::MAX),
        b"schema_version=1".to_vec(),
    ] {
        assert!(owner.issue([2; 32], request).is_err());
        assert_eq!(owner.authority()?.allocated_version, 0);
    }
    let first = owner.issue([2; 32], document(1))?;
    assert_eq!(first.input.root, root);
    assert_eq!(first.input.document, document(1));
    assert_eq!(first.input.verify()?.trusted_state().version(), 1);
    assert_eq!(owner.issue([2; 32], document(1))?, first);
    assert!(owner.issue([2; 32], document(2)).is_err());
    assert!(owner.cancel([2; 32]).is_err());
    drop(owner);
    let mut owner = AuthorityStore::open(&path, [1; 32])?;
    assert_eq!(owner.result([2; 32])?, first);
    let second = owner.issue([3; 32], document(2))?;
    assert_eq!(second.version, 2);
    assert_eq!(second.input.root, first.input.root);
    assert_eq!(owner.result([2; 32])?, first);
    drop(owner);
    assert!(AuthorityStore::open(&path, [9; 32]).is_err());
    assert!(AuthorityStore::provision(&path, [1; 32]).is_err());
    Ok(())
}
#[test]
fn lost_sdk_private_files_preserve_public_history_and_refuse_new_signing() -> Result<()> {
    let dir = directory()?;
    let path = dir.join("authority.redb");
    let mut owner = prepared(&path)?;
    let first = owner.issue([2; 32], document(1))?;
    let (wrap, signer) = owner.paths(&owner.config()?)?;
    drop(owner);
    fs::rename(&signer, signer.with_extension("retained"))?;
    fs::rename(&wrap, wrap.with_extension("wrap.retained"))?;
    let mut owner = AuthorityStore::open(&path, [1; 32])?;
    assert_eq!(owner.result([2; 32])?, first);
    assert_eq!(owner.issue([2; 32], document(1))?, first);
    assert!(owner.issue([3; 32], document(2)).is_err());
    assert!(!wrap.exists() && !signer.exists());
    drop(owner);
    let mut owner = AuthorityStore::open(&path, [1; 32])?;
    assert_eq!(owner.result([2; 32])?, first);
    assert!(owner.prepare().is_err());
    assert!(!wrap.exists() && !signer.exists());
    Ok(())
}
#[test]
fn native_sdk_publication_bootstraps_the_separate_protocol_publisher() -> Result<()> {
    use crate::policy_publisher::{Anchor, BootstrapMode, Publisher, Request};
    let dir = directory()?;
    let mut sdk = prepared(&dir.join("sdk.redb"))?;
    let input = sdk.issue([2; 32], document(1))?.input;
    let mut protocol = Publisher::provision(&dir.join("protocol.redb"), [3; 32], input.clone())?;
    let authority = protocol.prepare()?;
    assert_eq!(authority.sdk_root, input.root);
    assert_ne!(
        authority.policy_root.get(..1952),
        Some(input.root.as_slice())
    );
    let publication = protocol.issue(
        [4; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: 100,
            valid_until: 200,
            send_budget: 10,
            anchor: Anchor::LocalOnly {},
        },
        150,
    )?;
    assert_eq!(publication.version, 1);
    Ok(())
}
#[test]
fn private_sdk_states_reject_unknown_fields_and_missing_cursor() -> Result<()> {
    for phase in ["Wrapping", "Signing"] {
        assert!(serde_json::from_value::<store::Phase>(
            serde_json::json!({"phase":phase,"root":"AQ"})
        )
        .is_err());
    }
    for phase in ["Pending", "Cancelled"] {
        assert!(serde_json::from_value::<store::State>(
            serde_json::json!({"phase":phase,"signature":"AQ"})
        )
        .is_err());
    }
    assert!(serde_json::from_value::<store::Cursor>(
        serde_json::json!({"phase":"Idle","operation":vec![9u8;32]})
    )
    .is_err());
    let dir = directory()?;
    let owner = prepared(&dir.join("sdk.redb"))?;
    let mut value = serde_json::to_value(owner.config()?)?;
    value.as_object_mut().ok_or("object")?.remove("cursor");
    assert!(serde_json::from_value::<store::Config>(value).is_err());
    Ok(())
}
fn kill(path: &Path, action: &str, stage: &str) -> Result<Vec<u8>> {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let marker = path.with_extension(format!("{stage}.marker"));
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "sdk_authority::tests::sdk_authority_child",
            "--nocapture",
        ])
        .env("QPERIAPT_SDK_AUTH_TEST_DATABASE", path)
        .env("QPERIAPT_SDK_AUTH_TEST_ACTION", action)
        .env("QPERIAPT_ISSUER_BARRIER", stage)
        .env("QPERIAPT_ISSUER_MARKER", &marker)
        .stdin(Stdio::null())
        .stdout(fs::File::create(
            path.with_extension(format!("{stage}.stdout")),
        )?)
        .stderr(fs::File::create(
            path.with_extension(format!("{stage}.stderr")),
        )?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() {
        if let Some(status) = child.try_wait()? {
            return Err(format!("SDK child exited before {stage}: {status}").into());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(format!("SDK child did not reach {stage}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill()?;
    let status = child.wait()?;
    assert_eq!(status.signal(), Some(9));
    Ok(fs::read(marker)?)
}
#[test]
fn sdk_root_creation_recovers_four_process_cuts_with_original_file_identity() -> Result<()> {
    for stage in [
        "sdk-wrapping-published",
        "sdk-signing-prepared",
        "sdk-signer-published",
        "sdk-ready-committed",
    ] {
        let dir = directory()?;
        let path = dir.join("sdk.redb");
        let owner = AuthorityStore::provision(&path, [1; 32])?;
        let signing_id = owner.config()?.signing_id;
        drop(owner);
        let marker = kill(&path, "prepare", stage)?;
        let mut owner = AuthorityStore::open(&path, [1; 32])?;
        assert_eq!(owner.config()?.signing_id, signing_id);
        let root = owner.prepare()?.root;
        if stage == "sdk-signer-published" || stage == "sdk-ready-committed" {
            assert_eq!(root, marker);
        }
        assert_eq!(owner.prepare()?.root, root);
        let first = owner.issue([2; 32], document(1))?;
        assert_eq!(first.input.root, root);
        first.input.verify()?;
    }
    Ok(())
}
#[test]
fn sdk_publication_recovers_three_process_cuts_without_retargeting_original() -> Result<()> {
    for stage in [
        "sdk-policy-intent-committed",
        "sdk-policy-signed-before-commit",
        "sdk-policy-result-committed",
    ] {
        let dir = directory()?;
        let path = dir.join("sdk.redb");
        let owner = prepared(&path)?;
        let root = owner.authority()?.root;
        drop(owner);
        let marker = kill(&path, "issue", stage)?;
        let mut owner = AuthorityStore::open(&path, [1; 32])?;
        assert_eq!(owner.authority()?.root, root);
        assert!(owner.issue([2; 32], document(2)).is_err());
        if stage != "sdk-policy-result-committed" {
            assert!(owner.result([2; 32]).is_err());
            assert!(owner.issue([3; 32], document(2)).is_err());
        }
        let issued = owner.issue([2; 32], document(1))?;
        if stage == "sdk-policy-result-committed" {
            assert_eq!(issued.input.signature, marker);
        }
        assert_eq!(issued.input.document, document(1));
        assert_eq!(owner.issue([2; 32], document(1))?, issued);
        drop(owner);
        assert_eq!(
            AuthorityStore::open(&path, [1; 32])?.result([2; 32])?,
            issued
        );
    }
    Ok(())
}
#[test]
fn cancelled_sdk_intent_keeps_its_operation_and_allocated_version() -> Result<()> {
    let dir = directory()?;
    let path = dir.join("sdk.redb");
    drop(prepared(&path)?);
    kill(&path, "issue", "sdk-policy-intent-committed")?;
    let mut owner = AuthorityStore::open(&path, [1; 32])?;
    assert!(owner.issue([3; 32], document(2)).is_err());
    owner.cancel([2; 32])?;
    owner.cancel([2; 32])?;
    assert!(owner.issue([2; 32], document(1)).is_err());
    assert!(owner.issue([3; 32], document(1)).is_err());
    assert_eq!(owner.authority()?.allocated_version, 1);
    assert_eq!(owner.issue([3; 32], document(2))?.version, 2);
    Ok(())
}
#[test]
fn sdk_authority_child() -> Result<()> {
    let Some(path) = std::env::var_os("QPERIAPT_SDK_AUTH_TEST_DATABASE") else {
        return Ok(());
    };
    let mut owner = AuthorityStore::open(Path::new(&path), [1; 32])?;
    match std::env::var("QPERIAPT_SDK_AUTH_TEST_ACTION")?.as_str() {
        "prepare" => {
            owner.prepare()?;
        }
        "issue" => {
            owner.issue([2; 32], document(1))?;
        }
        _ => return Err("unexpected SDK child action".into()),
    }
    Ok(())
}
