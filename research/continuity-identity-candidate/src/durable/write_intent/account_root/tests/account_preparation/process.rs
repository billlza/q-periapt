// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
fn bytes32(path: &Path) -> [u8; 32] {
    fs::read(path)
        .expect("original retained fixture")
        .try_into()
        .expect("exact public field width")
}
#[test]
fn account_preparation_process_child() {
    let Some(base) = std::env::var_os("QPERIAPT_AUTHORITY_PREPARATION_DIR") else {
        return;
    };
    let base = Path::new(&base);
    let phase =
        std::env::var("QPERIAPT_AUTHORITY_PREPARATION_PHASE").expect("selected original mutation");
    let pin = crate::AnchorPin::new(
        crate::AnchorIdentity::from_trusted_state(bytes32(&base.join("witness-id")))
            .expect("original witness instance"),
        crate::PublicKey::decode(
            &fs::read(base.join("witness-public")).expect("original public witness key"),
        )
        .expect("original pinned key"),
    );
    let identity = AccountAuthorityIdentity::from_trusted_state(bytes32(&base.join("registry-id")))
        .expect("original registry identity");
    let plan = AnchorAccountReplacementPlan::from_trusted_state(
        &fs::read(base.join("original-plan")).expect("original approved plan"),
    )
    .expect("original plan bytes");
    let expected = AccountAuthorityCheckpoint::from_trusted_state(
        ApplicationAccountId::from_trusted_state([31; 32]).expect("original app"),
        1,
        plan.request().account(),
    )
    .expect("original checkpoint");
    let mut registry = AccountAuthorityStore::open(
        &base.join("authority.redb"),
        JournalKey::open(&base.join("authority-key")).expect("original key"),
        identity,
        bytes32(&base.join("family")),
        pin.clone(),
    )
    .expect("same original registry");
    let result = match phase.as_str() {
        "prepare" => registry
            .begin_preparation(expected, plan.clone())
            .map(|_| ()),
        "bind" => {
            let frozen = pin
                .verify_account_freeze(
                    plan.request(),
                    &fs::read(base.join("original-freeze")).expect("original signed freeze"),
                )
                .expect("authenticated original snapshot");
            registry
                .bind_preparation(plan.operation(), &frozen)
                .map(|_| ())
        }
        "commit" => {
            let proposal = registry
                .replacement(plan.operation())
                .expect("original bound proposal")
                .2;
            let retired = pin
                .verify_retired_account(
                    proposal,
                    &fs::read(base.join("original-retirement"))
                        .expect("original signed retirement"),
                )
                .expect("exact original retirement");
            registry.commit_replacement(&retired).map(|_| ())
        }
        _ => Err(DurableError::Protocol(Error::Scope)),
    };
    result.expect("selected original registry mutation must commit");
    fs::write(base.join("registry-returned"), phase).expect("owned return marker");
}
#[test]
fn account_preparation_process_loss_at_three_commits_keeps_original_intent_and_mapping() {
    for phase in ["prepare", "bind", "commit"] {
        let mut p = Prepared::new();
        let base = p.c.path.parent().expect("owned fixture root").to_path_buf();
        let plan_bytes = p.plan.to_bytes().expect("exact original plan");
        fs::write(base.join("original-plan"), &plan_bytes)
            .expect("retain original approval before child");
        fs::write(base.join("registry-id"), p.identity.as_bytes()).expect("retained identity");
        fs::write(base.join("witness-id"), p.c.pin.identity().as_bytes())
            .expect("retained witness instance");
        fs::write(base.join("witness-public"), p.c.pin.public_key().encode())
            .expect("retained public key");
        fs::write(base.join("family"), p.c.f.local_device().description.family)
            .expect("retained family");
        let frozen = if phase == "prepare" {
            None
        } else {
            p.registry
                .begin_preparation(p.expected, p.plan.clone())
                .expect("original local intent precedes witness");
            let frozen = p.frozen();
            let wire =
                p.c.witness
                    .lock()
                    .expect("original witness")
                    .account_freeze_receipt(p.plan.request())
                    .expect("original signed snapshot");
            fs::write(base.join("original-freeze"), wire).expect("retained original freeze proof");
            Some(frozen)
        };
        let retired = if phase == "commit" {
            p.registry
                .bind_preparation(
                    p.plan.operation(),
                    frozen.as_ref().expect("original freeze"),
                )
                .expect("original local binding");
            let proposal = p
                .registry
                .replacement(p.plan.operation())
                .expect("exact proposal")
                .2
                .clone();
            let wire = p.c.receipt(&proposal);
            fs::write(base.join("original-retirement"), &wire)
                .expect("retain exact signed retirement");
            Some(
                p.c.pin
                    .verify_retired_account(&proposal, &wire)
                    .expect("authenticated original witness decision"),
            )
        } else {
            None
        };
        p.registry.close();
        let log = fs::File::create_new(base.join("registry-child.log")).expect("owned child log");
        let mut child=crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("same actual test binary"))
            .args(["--exact","durable::write_intent::account_root::tests::account_preparation::process::account_preparation_process_child","--nocapture"])
            .env("QPERIAPT_AUTHORITY_PREPARATION_DIR",&base).env("QPERIAPT_AUTHORITY_PREPARATION_PHASE",phase)
            .stdout(Stdio::from(log.try_clone().expect("owned stdout"))).stderr(Stdio::from(log))
            .spawn().expect("owned original-registry child"));
        let deadline = Instant::now() + Duration::from_secs(25);
        while !base.join("registry-committed").exists() {
            assert!(
                child.0.try_wait().expect("owned child status").is_none()
                    && Instant::now() < deadline,
                "original registry did not reach selected durable commit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read(base.join("registry-committed")).expect("exact cut marker"),
            phase.as_bytes()
        );
        assert!(!base.join("registry-returned").exists());
        child
            .0
            .kill()
            .expect("kill owned child after database commit before API return");
        assert_eq!(child.0.wait().expect("reap owned child").signal(), Some(9));
        p.reopen();
        let (_, observed, retained) = p
            .registry
            .preparation(p.plan.operation())
            .expect("original operation survives child death");
        assert_eq!(retained.to_bytes().expect("same original plan"), plan_bytes);
        if phase == "prepare" {
            assert_eq!(observed, State::Preparing);
            p.query();
            assert_eq!(
                p.registry
                    .begin_preparation(p.expected, p.plan.clone())
                    .expect("exact original prepare retry"),
                State::Preparing
            );
        } else if phase == "bind" {
            assert_eq!(observed, State::Pending);
            assert_eq!(
                p.registry
                    .bind_preparation(p.plan.operation(), frozen.as_ref().expect("same freeze"))
                    .expect("exact original bind retry"),
                State::Pending
            );
        } else {
            assert_eq!(observed, State::Committed);
            assert_eq!(
                p.registry
                    .commit_replacement(retired.as_ref().expect("same retirement"))
                    .expect("exact original commit retry"),
                State::Committed
            );
        }
        let access = p.registry.access().expect("reopened original parent");
        if phase == "commit" {
            let current = access
                .current(p.expected.application())
                .expect("selected successor");
            assert_eq!(current.revision(), 2);
            assert_eq!(current.account(), p.c.next.account_id());
        } else {
            assert!(matches!(
                access.current(p.expected.application()),
                Err(DurableError::Suspended)
            ));
        }
        assert_eq!(
            access
                .current(p.other.application())
                .expect("unrelated original mapping"),
            p.other
        );
    }
    eprintln!("ACCOUNT_PREPARATION_PROCESS cuts=3 signal=SIGKILL after_database_commit_before_api_return=true original_plan=true exact_retry=true revision_once=true");
}
