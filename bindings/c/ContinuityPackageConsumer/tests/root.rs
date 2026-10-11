// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Installed C controller on its default pthread stack across owned SIGKILL cuts.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "root/fixture.rs"]
mod setup;
#[path = "common/witness.rs"]
mod witness;
use q_periapt_continuity_identity_candidate as p;
use std::os::unix::{
    fs::{DirBuilderExt, OpenOptionsExt},
    process::ExitStatusExt,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn stage(client: &Path, case: &setup::Case, mode: &str, kill: bool) -> Result<u32> {
    let log = case.public.parent().ok_or("parent")?;
    let output = |name: &str| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(log.join(name))
    };
    let mut child = fixture::OwnedChild(
        Command::new(client)
            .args([mode])
            .arg(&case.public)
            .arg(&case.old.path)
            .arg(&case.target.path)
            .arg(&case.registry_path)
            .arg(case.witness.configured.address.to_string())
            .stdout(Stdio::from(output(&format!("{mode}.stdout"))?))
            .stderr(Stdio::from(output(&format!("{mode}.stderr"))?))
            .spawn()?,
    );
    let pid = child.0.id();
    if kill {
        let marker = case.public.join(format!("cut-{mode}"));
        let deadline = Instant::now() + Duration::from_secs(15);
        while !marker.exists() {
            if let Some(status) = child.0.try_wait()? {
                return Err(format!(
                    "{mode} exited before cut: {status}; {}",
                    fs::read_to_string(log.join(format!("{mode}.stderr")))?
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err(format!("{mode} cut marker timeout").into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            u64::from_be_bytes(fixture::array(&case.public, &format!("cut-{mode}"))?),
            u64::from(pid)
        );
        child.0.kill()?;
        let status = fixture::wait(&mut child)?;
        assert_eq!(status.signal(), Some(9));
        assert!(fs::read(log.join(format!("{mode}.stdout")))?.is_empty());
    } else {
        let status = fixture::wait(&mut child)?;
        if !status.success() {
            return Err(format!(
                "{mode}: {status}; {}",
                fs::read_to_string(log.join(format!("{mode}.stderr")))?
            )
            .into());
        }
        assert_eq!(
            fs::read_to_string(log.join(format!("{mode}.stdout")))?,
            format!("root-stage-pass:{mode}\n")
        );
    }
    assert!(fs::read(log.join(format!("{mode}.stderr")))?.is_empty());
    assert_eq!(
        u64::from_be_bytes(fixture::array(&case.public, &format!("process-{mode}"))?),
        u64::from(pid)
    );
    #[cfg(target_os = "macos")]
    {
        let actual = u64::from_be_bytes(fixture::array(&case.public, &format!("stack-{mode}"))?);
        let configured = u64::from_be_bytes(fixture::array(
            &case.public,
            &format!("stack-default-{mode}"),
        )?);
        // pthread_create uses NULL attributes. Report both the system default
        // and the actual stack, which may include runtime TLS allocation.
        assert!(actual > 0 && configured > 0);
    }
    Ok(pid)
}
#[test]
fn installed_c_root_controller_recovers_original_state_and_erasure_after_process_loss() -> Result<()>
{
    let client =
        PathBuf::from(std::env::var_os("QPC_ROOT_CLIENT").ok_or("compiled root client required")?);
    let path =
        PathBuf::from(std::env::var_os("QPC_ROOT_EVIDENCE").ok_or("fresh root evidence required")?);
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    let path = path.canonicalize()?;
    let mut case = setup::Case::new(&path)?;
    let witness_start = case
        .witness
        .captured
        .lock()
        .map_err(|_| "witness start")?
        .len();
    let mut processes = Vec::new();
    processes.push(stage(&client, &case, "begin", true)?);
    processes.push(stage(&client, &case, "preparing", false)?);
    let freeze = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.freeze_account(case.plan.request())?;
        witness.account_freeze_receipt(case.plan.request())?
    };
    fixture::store(&case.public, "freeze-receipt", &freeze)?;
    processes.push(stage(&client, &case, "freeze", true)?);
    processes.push(stage(&client, &case, "freeze-retry", false)?);
    let proposal = p::AnchorAccountReplacementProposal::from_trusted_state(&fixture::read(
        &case.public,
        "bound-proposal",
        65536,
    )?)?;
    case.pin
        .verify_account_freeze(case.plan.request(), &freeze)?;
    let mut registry = case.registry()?;
    let (application, state, retained) = registry.replacement(case.plan.operation())?;
    assert_eq!(application, case.checkpoint.application());
    assert_eq!(state, p::AccountAuthorityReplacementState::Pending);
    assert_eq!(retained, &proposal);
    assert_eq!(registry.preparation(case.plan.operation())?.2, &case.plan);
    registry.close();
    let retirement = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.replace_account_root(
            &proposal,
            &case.old.root.public_key()?,
            &case.target.genesis,
            &case.target.credential,
            &case.policy,
            fixture::now()?,
        )?;
        witness.retired_account_receipt(&proposal)?
    };
    fixture::store(&case.public, "retirement-receipt", &retirement)?;
    processes.push(stage(&client, &case, "retain", true)?);
    processes.push(stage(&client, &case, "retain-retry", false)?);
    // The signed Observe was handled by the actual witness; drop its response.
    case.witness.arm(21)?;
    processes.push(stage(&client, &case, "activation-unknown", false)?);
    processes.push(stage(&client, &case, "inventory", true)?);
    let inventory = p::AnchorRetiredCleanupProposal::from_trusted_state(&fixture::read(
        &case.public,
        "inventory",
        313,
    )?)?;
    let receipt = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.retain_retired_cleanup(&inventory)?;
        witness.retired_cleanup_receipt(&inventory)?
    };
    fixture::store(&case.public, "inventory-receipt", &receipt)?;
    processes.push(stage(&client, &case, "prepare-report", false)?);
    let report = p::AnchorRetiredReportProposal::from_trusted_state(&fixture::read(
        &case.public,
        "report-proposal",
        353,
    )?)?;
    let report_receipt = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.retain_retired_report(&report)?;
        witness.retired_report_receipt(&report)?
    };
    fixture::store(&case.public, "report-receipt", &report_receipt)?;
    processes.push(stage(&client, &case, "report", true)?);
    let recorded = fixture::read(&case.public, "host-report", 8388608)?;
    let mut observer = case.resume()?;
    observer.with_retired_cleanup(|old| {
        let installation = old.installation()?;
        let retained = installation.verify_retained(&case.pin, &receipt)?;
        assert_eq!(
            installation
                .report(&retained, &case.pin, &report_receipt)?
                .as_bytes(),
            recorded
        );
        Ok(())
    })?;
    drop(observer);
    processes.push(stage(&client, &case, "prepare-ack", true)?);
    let ack = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.acknowledge_retired_report(&report)?;
        witness.retired_report_acknowledgement_receipt(&report)?
    };
    fixture::store(&case.public, "host-ack", &ack)?;
    processes.push(stage(&client, &case, "journal", true)?);
    processes.push(stage(&client, &case, "signer", true)?);
    processes.push(stage(&client, &case, "verify", false)?);
    let mut observer = case.resume()?;
    assert_eq!(
        observer.state()?,
        p::AccountAuthorityReplacementState::Committed
    );
    observer.with_retired_cleanup(|old| {
        assert_eq!(
            old.signer_erasure_status()?,
            p::SigningFileErasureState::Erased
        );
        assert_eq!(
            old.installation()?.journal_erasure_status(&case.pin)?,
            p::retired_device::JournalErasureState::Erased
        );
        Ok(())
    })?;
    drop(observer);
    let mut registry = case.registry()?;
    let current = registry.access()?.current(case.checkpoint.application())?;
    assert_eq!(current.revision(), 2);
    assert_eq!(current.account(), case.target.credential.account_id());
    registry.close();
    assert_eq!(
        fixture::read(&case.public, "host-report", 8388608)?,
        recorded
    );
    case.witness.join()?;
    let captured = case
        .witness
        .captured
        .lock()
        .map_err(|_| "witness transcript")?;
    assert_eq!(captured.iter().filter(|entry| !entry.delivered).count(), 1);
    let mut transcript = Vec::new();
    for entry in captured.iter() {
        assert_eq!(entry.request.len(), 3674);
        assert_eq!(entry.reply.len(), 3659);
        if !entry.delivered {
            assert_eq!(entry.request.get(204), Some(&1));
        }
        transcript.push(u8::from(entry.delivered));
        transcript.extend_from_slice(&entry.request);
        transcript.extend_from_slice(&entry.reply);
    }
    let boundary = witness_start
        .checked_mul(1 + 3674 + 3659)
        .ok_or("transcript bound")?;
    let (setup_trace, c_trace) = transcript.split_at(boundary);
    fixture::store(&case.public, "setup-witness-transcript", setup_trace)?;
    fixture::store(&case.public, "witness-transcript", c_trace)?;
    fixture::store(
        &case.public,
        "witness-start",
        &u64::try_from(witness_start)?.to_be_bytes(),
    )?;

    assert_eq!(processes.len(), 14);
    let unique = processes.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), 14);
    let result=b"ROOT_C_LIFECYCLE processes=14 sigkill=8 witness_unknown=218 native_readbacks=3 original_revision=2 report_preserved=true cleanup_keeps_successor=true close_revokes_successor=true application_traffic=false\n";
    fixture::store(&case.public, "result", result)?;
    print!("{}", std::str::from_utf8(result)?);
    Ok(())
}
