// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;

fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}
fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[test]
fn original_cutover_child() -> Result<()> {
    if let Some(output) = std::env::var_os("QPERIAPT_ROOT_OPERATOR_CLI_OUTPUT") {
        return cli_fixture(Path::new(&output));
    }
    let Some(path) = std::env::var_os("QPERIAPT_ROOT_OPERATOR_TEST") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let mut owner = open(path)?;
    let plan: AccountRootPlan = load(&path.join("root-plan.json"))?;
    match std::env::var("QPERIAPT_ISSUER_BARRIER")?.as_str() {
        "witness-account-root-frozen" => {
            owner.freeze_account_root(&plan)?;
        }
        "witness-account-root-plan-closed" => {
            owner.close_account_root_plan(&plan)?;
        }
        "witness-account-root-closed" => {
            owner.close_account_root_replacement(&load(&path.join("root-decision.json"))?)?;
        }
        "witness-account-root-committed" => {
            owner.commit_account_root_replacement(
                &load(&path.join("root-trust.json"))?,
                &load(&path.join("root-request.json"))?,
                &plan,
                &load(&path.join("root-freeze.json"))?,
                &load(&path.join("root-decision.json"))?,
                crate::native_device::clock()?,
            )?;
        }
        _ => return Err("root boundary differs".into()),
    }
    Ok(())
}

fn cli_fixture(output: &Path) -> Result<()> {
    if !output.is_absolute() || output.exists() {
        return Err("fresh absolute CLI fixture output required".into());
    }
    let (f, mut owner) = Fixture::new()?;
    let plan = f.plan(&mut owner)?;
    let (unseen, unseen_request) = f.unseen()?;
    for (name, value) in [
        ("root-trust.json", serde_json::to_value(&f.trust)?),
        ("root-request.json", serde_json::to_value(&f.next.request)?),
        ("expected-plan.json", serde_json::to_value(&plan)?),
        ("old-trust.json", serde_json::to_value(&f.old.trust)?),
        ("old-request.json", serde_json::to_value(&f.old.request)?),
        ("unseen-trust.json", serde_json::to_value(&unseen)?),
        (
            "unseen-request.json",
            serde_json::to_value(&unseen_request)?,
        ),
        ("next-trust.json", serde_json::to_value(&f.next.trust)?),
    ] {
        save(&f.path.join(name), &value)?;
    }
    let pin = owner.pin()?;
    drop(owner);
    save(
        output,
        &serde_json::json!({"fixture":f.path,"host_identity":vec![91u8;32],"witness_pin":pin,
        "previous_account":f.old.trust.account.account,"successor_account":f.next.trust.account.account,"started_at":f.now}),
    )
}

#[test]
fn all_original_root_mutations_recover_after_process_loss() -> Result<()> {
    for stage in [
        "witness-account-root-frozen",
        "witness-account-root-committed",
        "witness-account-root-closed",
        "witness-account-root-plan-closed",
    ] {
        let (f, mut owner) = Fixture::new()?;
        let plan = f.plan(&mut owner)?;
        save(&f.path.join("root-plan.json"), &plan)?;
        save(&f.path.join("root-trust.json"), &f.trust)?;
        save(&f.path.join("root-request.json"), &f.next.request)?;
        let mut bound = None;
        if matches!(
            stage,
            "witness-account-root-committed" | "witness-account-root-closed"
        ) {
            let frozen = owner.freeze_account_root(&plan)?;
            let decision = owner.bind_account_root_replacement(
                &f.trust,
                &f.next.request,
                &plan,
                &frozen,
                f.now,
            )?;
            save(&f.path.join("root-freeze.json"), &frozen)?;
            save(&f.path.join("root-decision.json"), &decision)?;
            bound = Some(decision);
        }
        drop(owner);
        let marker = f.path.join("root-boundary");
        let log = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(f.path.join("root-child.log"))?;
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "witness::tests::account_root::process::original_cutover_child",
                "--nocapture",
            ])
            .env("QPERIAPT_ROOT_OPERATOR_TEST", &f.path)
            .env("QPERIAPT_ISSUER_BARRIER", stage)
            .env("QPERIAPT_ISSUER_MARKER", &marker)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            if let Some(status) = child.try_wait()? {
                return Err(format!("Root child exited before {stage}: {status}").into());
            }
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err(format!("Root boundary timed out: {stage}").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill()?;
        let status = child.wait()?;
        assert_eq!(status.signal(), Some(9));
        let mut owner = open(&f.path)?;
        match stage {
            "witness-account-root-frozen" => {
                let frozen = owner.freeze_account_root(&plan)?;
                let recovered = owner.bind_account_root_replacement(
                    &f.trust,
                    &f.next.request,
                    &plan,
                    &frozen,
                    f.now,
                )?;
                assert!(f.query_old(&mut owner).is_err());
                committed(
                    &f,
                    &recovered,
                    owner.commit_account_root_replacement(
                        &f.trust,
                        &f.next.request,
                        &plan,
                        &frozen,
                        &recovered,
                        f.now,
                    )?,
                )?;
            }
            "witness-account-root-committed" => {
                let original = bound.as_ref().ok_or("original decision")?;
                committed(
                    &f,
                    original,
                    owner.account_root_replacement_status(original)?,
                )?;
                assert!(f.query_old(&mut owner).is_err());
            }
            "witness-account-root-closed" => {
                let original = bound.as_ref().ok_or("original decision")?;
                let AccountRootOutcome::Closed { receipt, .. } =
                    owner.account_root_replacement_status(original)?
                else {
                    return Err("closed original decision".into());
                };
                f.old
                    .pin
                    .verify_closed_account_replacement(&decision(original)?, &receipt)?;
                assert!(f.query_old(&mut owner).is_err());
            }
            "witness-account-root-plan-closed" => {
                let AccountRootOutcome::Closed { receipt, .. } =
                    owner.close_account_root_plan(&plan)?
                else {
                    return Err("closed original plan".into());
                };
                f.old.pin.verify_closed_account_preparation(
                    &sdk::AnchorAccountReplacementPlan::from_trusted_state(&plan.plan)?,
                    &receipt,
                )?;
                assert!(owner.freeze_account_root(&plan).is_err());
            }
            _ => return Err("case".into()),
        }
    }
    Ok(())
}
