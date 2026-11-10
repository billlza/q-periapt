// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public original inputs from an authenticated host with one retained policy family.
use super::*;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

fn save(root: &Path, name: &str, value: &impl serde::Serialize) -> Result<()> {
    let file = root.join(name);
    if let Some(parent) = file.parent() {
        if parent != root && !parent.exists() {
            fs::DirBuilder::new().mode(0o700).create(parent)?;
        }
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)?;
    output.write_all(&serde_json::to_vec(value)?)?;
    output.sync_all()?;
    Ok(())
}

#[test]
fn original_root_registry_fixture_child() -> Result {
    let Some(output) = std::env::var_os("QPERIAPT_INDEPENDENT_ROOT_REGISTRY_FIXTURE") else {
        return Ok(());
    };
    let output = PathBuf::from(output);
    if !output.is_absolute() || output.exists() {
        return Err("fresh absolute root registry fixture output required".into());
    }
    let mut c = Case::new()?;
    let (old, old_request) = associate(&mut c)?;
    let first = Target::new(&mut c)?;
    c.host.approve_account_root(&c.token, &first.input)?;
    let frozen = witness(&c)?.freeze_account_root(&first.input.plan)?;
    let closed = witness(&c)?.close_account_root_plan(&first.input.plan)?;
    let AccountRootOutcome::Closed { receipt, .. } = &closed else {
        return Err("original closed plan".into());
    };
    let host_closed = c
        .host
        .close_account_root(&c.token, first.trust.operation, receipt)?;
    let next = Target::prepare(&mut c, Some(Prior::Frozen(&first, &frozen)))?;
    assert_eq!(old.account.family, first.root.family);
    assert_eq!(old.account.family, next.root.family);
    c.host.approve_account_root(&c.token, &next.input)?;
    let mut operator = witness(&c)?;
    let next_frozen = operator.freeze_account_root(&next.input.plan)?;
    let decision = operator.bind_account_root_replacement(
        &next.trust,
        &next.input.target,
        &next.input.plan,
        &next_frozen,
        now()?,
    )?;
    let retired = operator.commit_account_root_replacement(
        &next.trust,
        &next.input.target,
        &next.input.plan,
        &next_frozen,
        &decision,
        now()?,
    )?;
    let AccountRootOutcome::Committed { receipt, .. } = &retired else {
        return Err("original witness retirement".into());
    };
    let host_committed = c.host.commit_account_root(
        &c.token,
        next.trust.operation,
        &Retirement {
            decision: decision.clone(),
            receipt: receipt.clone(),
        },
    )?;
    assert_eq!(c.host.enrollment_root(&c.token)?, next.root);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let root = output.join("replan");
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    for (name, value) in [
        ("old-trust.json", serde_json::to_value(&old)?),
        ("old-request.json", serde_json::to_value(&old_request)?),
        ("root-trust.json", serde_json::to_value(&first.trust)?),
        (
            "root-request.json",
            serde_json::to_value(&first.input.target)?,
        ),
        (
            "plan/account-root-plan.json",
            serde_json::to_value(&first.input.plan)?,
        ),
        (
            "freeze-retry/account-root-freeze.json",
            serde_json::to_value(&frozen)?,
        ),
        (
            "original-plan-closed/account-root-plan-outcome.json",
            serde_json::to_value(&closed)?,
        ),
        ("new-root-trust.json", serde_json::to_value(&next.trust)?),
        (
            "new-root-request.json",
            serde_json::to_value(&next.input.target)?,
        ),
        (
            "replan-retry/account-root-plan.json",
            serde_json::to_value(&next.input.plan)?,
        ),
        (
            "same-frozen-root/account-root-freeze.json",
            serde_json::to_value(&next_frozen)?,
        ),
        (
            "new-bound-target/account-root-decision.json",
            serde_json::to_value(&decision)?,
        ),
        (
            "new-committed-target/account-root-outcome.json",
            serde_json::to_value(&retired)?,
        ),
        ("host-closed.json", serde_json::to_value(&host_closed)?),
        (
            "host-committed.json",
            serde_json::to_value(&host_committed)?,
        ),
        (
            "fixture.json",
            serde_json::json!({"schema":"qperiapt-original-root-registry-fixture/1","application":c.original.application,
            "family":old.account.family,"previous_account":old.account.account,"successor_account":next.root.account,
            "witness_pin":c.host.account_authority(&c.token)?.witness}),
        ),
    ] {
        save(&root, name, &value)?;
    }
    exact_closure(&output)?;
    save(
        &output,
        "RESULT.json",
        &serde_json::json!({"completed":true,"files":25,
        "scope":"Public inputs and signed outcomes from original software-Passkey host, native registry, native enrollments and witness in one policy family; no independent client owner claim"}),
    )?;
    Ok(())
}

fn exact_closure(output: &Path) -> Result<()> {
    let mut c = Case::new()?;
    let (old, old_request) = associate(&mut c)?;
    let target = Target::new(&mut c)?;
    c.host.approve_account_root(&c.token, &target.input)?;
    let mut operator = witness(&c)?;
    let frozen = operator.freeze_account_root(&target.input.plan)?;
    let decision = operator.bind_account_root_replacement(
        &target.trust,
        &target.input.target,
        &target.input.plan,
        &frozen,
        now()?,
    )?;
    let closed = operator.close_account_root_replacement(&decision)?;
    assert!(matches!(closed, AccountRootOutcome::Closed { .. }));
    assert_eq!(old.account.family, target.root.family);
    let root = output.join("close");
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    for (name, value) in [
        ("old-trust.json", serde_json::to_value(&old)?),
        ("old-request.json", serde_json::to_value(&old_request)?),
        ("root-trust.json", serde_json::to_value(&target.trust)?),
        (
            "root-request.json",
            serde_json::to_value(&target.input.target)?,
        ),
        (
            "plan/account-root-plan.json",
            serde_json::to_value(&target.input.plan)?,
        ),
        (
            "freeze-retry/account-root-freeze.json",
            serde_json::to_value(&frozen)?,
        ),
        (
            "bind/account-root-decision.json",
            serde_json::to_value(&decision)?,
        ),
        (
            "closed/account-root-outcome.json",
            serde_json::to_value(&closed)?,
        ),
        (
            "fixture.json",
            serde_json::json!({"schema":"qperiapt-original-root-registry-fixture/1",
            "application":c.original.application,"witness_pin":c.host.account_authority(&c.token)?.witness}),
        ),
    ] {
        save(&root, name, &value)?;
    }
    Ok(())
}
