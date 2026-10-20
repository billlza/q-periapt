// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => eprintln!("inspect issuer child during cleanup: {error}"),
        }
        if let Err(error) = self.0.kill() {
            eprintln!("stop issuer child during cleanup: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("reap issuer child during cleanup: {error}");
        }
    }
}
pub(super) type ReapprovalInput = (
    [u8; 32],
    [u8; 32],
    Option<crate::enrollment::Checkpoint>,
    Vec<u8>,
);
pub(super) enum Work {
    Root,
    Issue([u8; 32]),
    Invite([u8; 32]),
    Upgrade,
    ReapprovalUpgrade,
    Reapprove(ReapprovalInput),
    ExtensionUpgrade,
    Extend(crate::enrollment::CredentialExtensionRequest),
    GrantUpgrade,
    Grant(Box<crate::credential_grant::CredentialGrantRequest>),
    CancelGrant(Box<crate::credential_grant::CredentialGrantRequest>),
}
pub(super) fn kill_at(path: &Path, boundary: &str, work: Work) -> Result<Vec<u8>> {
    let marker = path.join(format!("{boundary}.marker"));
    assert!(!marker.exists());
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "auth::enrollment_tests::crash::issuer_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("QPERIAPT_ISSUER_CHILD", path)
        .env("QPERIAPT_ISSUER_BARRIER", boundary)
        .env("QPERIAPT_ISSUER_MARKER", &marker)
        .stdout(Stdio::from(fs::File::create(
            path.join(format!("{boundary}.stdout")),
        )?))
        .stderr(Stdio::from(fs::File::create(
            path.join(format!("{boundary}.stderr")),
        )?));
    command
        .env_remove("QPERIAPT_ISSUER_OPERATION")
        .env_remove("QPERIAPT_ISSUER_REQUEST")
        .env_remove("QPERIAPT_ISSUER_UPGRADE")
        .env_remove("QPERIAPT_ISSUER_REAPPROVAL_UPGRADE")
        .env_remove("QPERIAPT_ISSUER_REAPPROVAL_INPUT")
        .env_remove("QPERIAPT_ISSUER_EXTENSION_UPGRADE")
        .env_remove("QPERIAPT_ISSUER_EXTENSION_INPUT")
        .env_remove("QPERIAPT_ISSUER_GRANT_UPGRADE")
        .env_remove("QPERIAPT_ISSUER_GRANT_INPUT")
        .env_remove("QPERIAPT_ISSUER_GRANT_CANCEL");
    let cancel_grant = matches!(&work, Work::CancelGrant(_));
    match work {
        Work::Root => {}
        Work::Issue(id) => {
            command.env("QPERIAPT_ISSUER_OPERATION", URL_SAFE_NO_PAD.encode(id));
        }
        Work::Invite(id) => {
            command.env("QPERIAPT_ISSUER_REQUEST", URL_SAFE_NO_PAD.encode(id));
        }
        Work::Upgrade => {
            command.env("QPERIAPT_ISSUER_UPGRADE", "1");
        }
        Work::ReapprovalUpgrade => {
            command.env("QPERIAPT_ISSUER_REAPPROVAL_UPGRADE", "1");
        }
        Work::Reapprove(input) => {
            let file = path.join("reapproval-input.json");
            fs::write(&file, serde_json::to_vec(&input)?)?;
            command.env("QPERIAPT_ISSUER_REAPPROVAL_INPUT", file);
        }
        Work::ExtensionUpgrade => {
            command.env("QPERIAPT_ISSUER_EXTENSION_UPGRADE", "1");
        }
        Work::Extend(input) => {
            let file = path.join("extension-input.json");
            fs::write(&file, serde_json::to_vec(&input)?)?;
            command.env("QPERIAPT_ISSUER_EXTENSION_INPUT", file);
        }
        Work::GrantUpgrade => {
            command.env("QPERIAPT_ISSUER_GRANT_UPGRADE", "1");
        }
        Work::Grant(input) | Work::CancelGrant(input) => {
            let file = path.join(format!("{boundary}.input.json"));
            fs::write(&file, serde_json::to_vec(&input)?)?;
            command.env("QPERIAPT_ISSUER_GRANT_INPUT", file);
            if cancel_grant {
                command.env("QPERIAPT_ISSUER_GRANT_CANCEL", "1");
            }
        }
    }
    let mut child = Worker(command.spawn()?);
    let limit = Instant::now() + Duration::from_secs(30);
    while !marker.exists() {
        if let Some(status) = child.0.try_wait()? {
            return Err(format!(
                "issuer child exited before {boundary}: {status}; inspect retained logs"
            )
            .into());
        }
        if Instant::now() >= limit {
            return Err(format!("issuer child did not reach {boundary}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.0.kill()?;
    let status = child.0.wait()?;
    assert_eq!(status.signal(), Some(9), "actual SIGKILL is required");
    Ok(fs::read(marker)?)
}

// Process entrypoint only. Without its exact child configuration, it performs no work.
#[test]
fn issuer_child() -> Result {
    let Some(path) = std::env::var_os("QPERIAPT_ISSUER_CHILD") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let mut store = Store::open(&path.join("accounts.redb"), ORIGIN)?;
    let account = store.account("alice")?.ok_or("original fixture account")?;
    if std::env::var_os("QPERIAPT_ISSUER_GRANT_UPGRADE").is_some() {
        store.enable_credential_grants()?;
    } else if let Some(file) = std::env::var_os("QPERIAPT_ISSUER_GRANT_INPUT") {
        let input = serde_json::from_slice(&fs::read(file)?)?;
        if std::env::var_os("QPERIAPT_ISSUER_GRANT_CANCEL").is_some() {
            store.cancel_credential_grant(&account, &input)?;
        } else {
            store.issue_credential_grant(&account, &input)?;
        }
    } else if std::env::var_os("QPERIAPT_ISSUER_EXTENSION_UPGRADE").is_some() {
        store.enable_enrollment_extensions()?;
    } else if let Some(file) = std::env::var_os("QPERIAPT_ISSUER_EXTENSION_INPUT") {
        let input = serde_json::from_slice(&fs::read(file)?)?;
        store.extend_enrollment_credential(&account, &input)?;
    } else if std::env::var_os("QPERIAPT_ISSUER_REAPPROVAL_UPGRADE").is_some() {
        store.enable_enrollment_reapproval()?;
    } else if let Some(file) = std::env::var_os("QPERIAPT_ISSUER_REAPPROVAL_INPUT") {
        let (previous, request_id, predecessor, request): ReapprovalInput =
            serde_json::from_slice(&fs::read(file)?)?;
        store.reapprove_enrollment(&account, previous, request_id, predecessor, &request)?;
    } else if std::env::var_os("QPERIAPT_ISSUER_UPGRADE").is_some() {
        store.enable_enrollment([42; 32])?;
    } else if let Some(id) = std::env::var_os("QPERIAPT_ISSUER_OPERATION") {
        let id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(id.to_str().ok_or("operation encoding")?)?
            .try_into()
            .map_err(|_| "operation length")?;
        store.issue_enrollment(&account, id)?;
    } else if let Some(id) = std::env::var_os("QPERIAPT_ISSUER_REQUEST") {
        let id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(id.to_str().ok_or("request encoding")?)?
            .try_into()
            .map_err(|_| "request length")?;
        store.invite_enrollment(&account, id)?;
    } else {
        store.prepare_enrollment_root(&account)?;
    }
    Err("configured boundary was not reached".into())
}

#[test]
fn schema_upgrade_kill_keeps_original_account_and_all_or_none_enrollment_tables() -> Result {
    for boundary in ["upgrade-before-commit", "upgrade-after-commit"] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let before = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
        drop(host);
        kill_at(&path, boundary, Work::Upgrade)?;
        let mut host = reopen(&path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            before
        );
        if boundary == "upgrade-before-commit" {
            let (session, _) = login(&mut host, &mut auth, "alice")?;
            assert!(host.prepare_enrollment_root(&session).is_err());
        }
        host.store.enable_enrollment([42; 32])?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        host.prepare_enrollment_root(&session)?;
    }
    Ok(())
}

#[test]
fn root_first_use_reconciles_four_real_process_kills_without_replacing_published_keys() -> Result {
    for boundary in [
        "root-wrapping-published",
        "root-signing-prepared",
        "root-signer-published",
        "root-ready-committed",
    ] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        host.store.enable_enrollment([42; 32])?;
        drop(host);
        let observed = kill_at(&path, boundary, Work::Root)?;
        let original_files: Vec<_> = fs::read_dir(&path)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|p| {
                matches!(
                    p.extension().and_then(|x| x.to_str()),
                    Some("wrap" | "signer")
                )
            })
            .map(|p| fs::read(&p).map(|b| (p, b)))
            .collect::<std::io::Result<_>>()?;
        let mut host = reopen(&path)?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        let root = host.prepare_enrollment_root(&session)?;
        if boundary.contains("signer-published") || boundary.contains("ready-committed") {
            assert_eq!(root.public_key, observed);
        }
        for (file, bytes) in original_files {
            assert!(fs::read(file)? == bytes, "a published original key changed");
        }
        assert!(root.roster.is_none());
    }
    Ok(())
}

#[test]
fn issuance_commit_before_and_after_kill_preserves_original_operation_and_exact_result() -> Result {
    for boundary in ["issue-before-commit", "issue-after-commit"] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        host.store.enable_enrollment([42; 32])?;
        host.prepare_enrollment_root(&session)?;
        let invitation = host.invite_enrollment(&session, crate::enrollment::random()?)?;
        let (paths, wire) = request(&path, &invitation)?;
        host.approve_enrollment(&session, invitation.operation, &wire)?;
        drop(host);
        let signed = kill_at(&path, boundary, Work::Issue(invitation.operation))?;
        let mut host = reopen(&path)?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        if boundary == "issue-before-commit" {
            assert!(matches!(
                host.enrollment_status(&session, invitation.operation)?,
                EnrollmentStatus::Approved { .. }
            ));
            assert!(host.enrollment_root(&session)?.roster.is_none());
        } else {
            assert!(
                matches!(host.enrollment_status(&session, invitation.operation)?, EnrollmentStatus::Issued { response, .. } if response == signed)
            );
        }
        let recovered = host.issue_enrollment(&session, invitation.operation)?;
        if boundary == "issue-after-commit" {
            assert_eq!(recovered, signed);
        }
        assert_eq!(
            host.issue_enrollment(&session, invitation.operation)?,
            recovered
        );
        let receipt: IssuedEnrollment = serde_json::from_slice(&recovered)?;
        assert_eq!(receipt.checkpoint.version, 1);
        verify(&host.enrollment_root(&session)?, &receipt)?;
        let mut device = sdk::DeviceEnrollment::open(paths, invitation.intent()?)?;
        assert_eq!(device.request(crate::enrollment::now()?)?, wire);
        device.close();
    }
    Ok(())
}

#[test]
fn invitation_creation_recovers_lost_operation_id_using_original_caller_identity() -> Result {
    for boundary in ["invitation-before-commit", "invitation-after-commit"] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        host.store.enable_enrollment([42; 32])?;
        host.prepare_enrollment_root(&session)?;
        let request_id = crate::enrollment::random()?;
        drop(host);
        let candidate: Invitation =
            serde_json::from_slice(&kill_at(&path, boundary, Work::Invite(request_id))?)?;
        let mut host = reopen(&path)?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        if boundary == "invitation-before-commit" {
            assert!(host
                .enrollment_status(&session, candidate.operation)
                .is_err());
        }
        let recovered = host.invite_enrollment(&session, request_id)?;
        if boundary == "invitation-after-commit" {
            assert_eq!(recovered, candidate);
        }
        assert_eq!(recovered.request_id, request_id);
        assert_eq!(host.invite_enrollment(&session, request_id)?, recovered);
        host.cancel_enrollment(&session, recovered.operation)?;
        assert!(host.invite_enrollment(&session, request_id).is_err());
    }
    Ok(())
}
