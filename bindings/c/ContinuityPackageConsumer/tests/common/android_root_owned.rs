// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original and target Android identities, independently authorized account-root replacement.
use crate::{
    android_retirement::interrupted, android_roster_traffic as traffic, android_witness::witness,
    fixture, independent_inputs, issue_grant, p, run_foreign, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    cell::Cell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};
pub(crate) fn store(path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    Ok(publish_private_bytes(&path.join(name), bytes)?)
}
pub(crate) fn prepared(
    bytes: &[u8],
    device: &p::VerifiedDevice,
    policy: &p::VerifiedSessionPolicy,
) -> Result<p::AnchorGenesis> {
    assert_eq!(bytes.len(), 164);
    assert_eq!(bytes.get(..4).ok_or("protection")?, 2u32.to_be_bytes());
    let journal =
        p::JournalIdentity::from_trusted_state(bytes.get(4..36).ok_or("journal")?.try_into()?)?;
    let subject = p::AnchorSubject::from_trusted_state(bytes.get(36..132).ok_or("subject")?)?;
    assert_eq!(
        subject,
        p::AnchorSubject::for_device(journal, device, policy)?
    );
    Ok(p::AnchorGenesis::from_trusted_state(
        subject,
        bytes.get(132..).ok_or("genesis")?.try_into()?,
    )?)
}
#[test]
fn original_account_root_replacement() -> Result<()> {
    run_all(crate::android_root_alternatives::Variant::Original)
}
#[test]
fn transition_account_root_replacement() -> Result<()> {
    run_all(crate::android_root_alternatives::Variant::Transition)
}
#[test]
fn bound_transition_account_root_replacement() -> Result<()> {
    run_all(crate::android_root_alternatives::Variant::BoundTransition)
}
#[test]
fn adoption_account_root_replacement() -> Result<()> {
    run_all(crate::android_root_alternatives::Variant::Adoption)
}
#[test]
fn noncommit_account_root_replacement() -> Result<()> {
    run_all(crate::android_root_alternatives::Variant::Noncommit)
}
fn run_all(variant: crate::android_root_alternatives::Variant) -> Result<()> {
    let out = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("root cases")?);
    let driver = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("root driver")?);
    fs::DirBuilder::new().mode(0o700).create(&out)?;
    for profile in ["fixed", "recoverable"] {
        route(&out, &driver, profile, variant)?;
    }
    Ok(())
}
fn route(
    out: &Path,
    driver: &Path,
    profile: &str,
    variant: crate::android_root_alternatives::Variant,
) -> Result<()> {
    let base = out.join(format!("signed-{profile}"));
    let inputs = base.join("inputs");
    fs::DirBuilder::new().mode(0o700).create(&base)?;
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
    let mut witness = witness::Witness::start()?;
    let reference = fixture::setup_expiring_policy(Some(&witness.configured), 1800)?;
    let (old_root, old_intent, old_validity) = independent_inputs(&reference.initiator, &inputs)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let policy = fixture::protocol_policy(&inputs, &sdk)?;
    let pin = witness.configured.store.lock().map_err(|_| "pin")?.pin()?;
    store(&inputs, "witness-carrier", b"signed")?;
    store(&inputs, "witness-id", pin.identity().as_bytes())?;
    store(&inputs, "witness-public", &pin.public_key().encode())?;
    store(
        &inputs,
        "witness-address",
        witness.configured.address.to_string().as_bytes(),
    )?;
    store(
        &inputs,
        "authority-id",
        p::AccountAuthorityIdentity::generate()?.as_bytes(),
    )?;
    store(&inputs, "authority-application", &[161; 32])?;
    let calls = Cell::new(0u64);
    let run = |mode: &str, name: &str| -> Result<Vec<u8>> {
        let v = run_foreign(driver, profile, &inputs, &base, mode, name)?;
        calls.set(calls.get().checked_add(1).ok_or("root process census")?);
        Ok(v)
    };
    let cut = |mode: &str, name: &str| -> Result<Vec<u8>> {
        let v = interrupted(driver, profile, &inputs, &base, mode, name)?;
        calls.set(calls.get().checked_add(1).ok_or("root process census")?);
        Ok(v)
    };
    let request = run("policy-create", "original.request")?;
    let (old_certificate, old_roster) =
        issue_grant(&inputs, &old_root, &old_intent, old_validity, &request)?;
    let old_device = p::AccountPin::new(
        old_root.account_id()?,
        old_root.public_key()?,
        old_roster.checkpoint(),
        policy.family(),
    )?
    .verify_device(&old_certificate, old_roster.as_bytes(), fixture::now()?)?;
    let checkpoint = run("authority-create", "authority-created")?;
    store(&inputs, "authority-checkpoint", &checkpoint)?;
    let old = prepared(&run("policy-prepare", "prepared")?, &old_device, &policy)?;
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "old witness enrollment")?
        .enroll(&old, &old_device, &policy, fixture::now()?)?;
    assert_eq!(run("policy-activate", "activated.request")?, request);
    run("policy-identity", "original.identity")?;
    let case = traffic::Case {
        base: &base,
        inputs: &inputs,
        reference: &reference,
        witness: Some(&witness.configured),
    };
    let _old_traffic =
        traffic::Traffic::begin(&case, &old_root, &old_certificate, &old_roster, &run)?;
    store(&inputs, "root-route", variant.name().as_bytes())?;
    let target = crate::android_root_target::create(
        &reference.initiator,
        &inputs,
        &policy,
        "root-target",
        &run,
    )?;
    assert_ne!(old_root.account_id()?, target.root.account_id()?);
    assert_ne!(old.subject(), target.genesis.subject());
    let original_target = if variant == crate::android_root_alternatives::Variant::Original {
        None
    } else {
        Some(crate::android_root_target::create(
            &reference.initiator,
            &inputs,
            &policy,
            "root-original-target",
            &run,
        )?)
    };
    let planned = original_target.as_ref().unwrap_or(&target);
    if let Some(original) = original_target.as_ref() {
        assert_ne!(original.root.account_id()?, target.root.account_id()?);
        assert_ne!(original.genesis.subject(), target.genesis.subject());
    }
    let freeze_request = p::AnchorAccountFreezeRequest::from_trusted_state(
        p::AnchorAccountFreezeId::from_trusted_state([162; 32])?,
        old_root.public_key()?,
        &pin,
    )?;
    let plan = witness
        .configured
        .store
        .lock()
        .map_err(|_| "independent root plan")?
        .account_replacement_plan(
            p::AnchorAccountReplacementId::from_trusted_state([163; 32])?,
            freeze_request,
            &planned.genesis,
            &planned.device,
            &policy,
            fixture::now()?,
        )?;
    store(&inputs, "root-plan", &plan.to_bytes()?)?;
    assert_eq!(cut("root-begin-unknown", "root-begun")?, 1u32.to_be_bytes());
    assert_eq!(run("root-state", "root-preparing")?, 1u32.to_be_bytes());
    if variant == crate::android_root_alternatives::Variant::Noncommit {
        assert_eq!(
            run("root-cancel-preparing", "root-preparation-cancelled")?,
            302u32.to_be_bytes()
        );
    }
    let retained = crate::android_root_alternatives::prepare(
        crate::android_root_alternatives::Approval {
            inputs: &inputs,
            witness: &witness.configured,
            plan: &plan,
            old_root: &old_root,
            target: &target,
            policy: &policy,
            pin: &pin,
        },
        variant,
        &run,
        &cut,
    )?;
    assert_eq!(retained.len(), 72);
    assert_eq!(retained.get(..32).ok_or("application")?, [161; 32]);
    assert_eq!(retained.get(32..40).ok_or("revision")?, 2u64.to_be_bytes());
    assert_eq!(
        retained.get(40..).ok_or("new root")?,
        target.root.account_id()?
    );
    witness.arm(21)?;
    assert_eq!(
        run("root-activate-unknown", "root-activation-unknown")?,
        218u32.to_be_bytes()
    );
    assert_eq!(run("root-activate", "root-activated")?, [1]);
    crate::android_root_traffic::exercise(
        &case,
        &target.root,
        &target.certificate,
        &target.roster,
        &run,
    )?;
    if variant == crate::android_root_alternatives::Variant::Noncommit {
        assert_eq!(
            run("root-cancel-successor", "root-successor-cancelled")?,
            302u32.to_be_bytes()
        );
    }
    let inventory_bytes = run("root-inventory", "root-inventory")?;
    let inventory = p::AnchorRetiredCleanupProposal::from_trusted_state(&inventory_bytes)?;
    let inventory_receipt = {
        let mut store = witness.configured.store.lock().map_err(|_| "inventory")?;
        store.retain_retired_cleanup(&inventory)?;
        store.retired_cleanup_receipt(&inventory)?
    };
    store(&inputs, "root-inventory-receipt", &inventory_receipt)?;
    let report_bytes = run("root-prepare-report", "root-report-proposal")?;
    store(&inputs, "root-report-proposal", &report_bytes)?;
    let report = p::AnchorRetiredReportProposal::from_trusted_state(&report_bytes)?;
    assert_eq!(report.inventory(), &inventory);
    let report_receipt = {
        let mut store = witness.configured.store.lock().map_err(|_| "report")?;
        store.retain_retired_report(&report)?;
        store.retired_report_receipt(&report)?
    };
    store(&inputs, "root-report-receipt", &report_receipt)?;
    assert_eq!(
        cut("root-report-unknown", "root-report-unknown")?,
        report_bytes
    );
    let complete = run("root-report-reopen", "root-complete-report")?;
    assert!(complete.starts_with(b"QPRDMD01") || complete.starts_with(b"QPRDMD02"));
    assert_eq!(
        run("root-ack-tampered", "root-tampered-report")?,
        208u32.to_be_bytes()
    );
    assert_eq!(run("root-prepare-ack", "root-ack-proposal")?, report_bytes);
    let ack = {
        let mut store = witness
            .configured
            .store
            .lock()
            .map_err(|_| "host acknowledgement")?;
        store.acknowledge_retired_report(&report)?;
        store.retired_report_acknowledgement_receipt(&report)?
    };
    store(&inputs, "root-ack", &ack)?;
    assert_eq!(
        run("root-erase-wrong-purpose", "root-wrong-purpose")?,
        102u32.to_be_bytes()
    );
    assert_eq!(
        cut("root-journal-unknown", "root-journal-unknown")?,
        report_bytes
    );
    assert_eq!(
        cut("root-signer-unknown", "root-signer-unknown")?,
        report_bytes
    );
    assert_eq!(run("root-verify", "root-verified")?, complete);
    assert_eq!(
        run("root-close-revokes", "root-close-revoked")?,
        202u32.to_be_bytes()
    );
    let old_message = fixture::array::<32>(&inputs, "connection-message")?;
    let effect = fs::read(
        reference
            .responder
            .join(format!("application-{}", fixture::hex(&old_message))),
    )?;
    assert_eq!(effect, fs::read(base.join("roster-effect-before"))?);
    store(&base, "root-original-effect-after", &effect)?;
    assert_eq!(calls.get(), variant.processes());
    store(&base, "process-count", &calls.get().to_be_bytes())?;
    policy.close();
    sdk.close();
    witness.join()?;
    println!("qualified Android account-root {} {profile}: {} Java processes; {} process cuts; original report, new root traffic and controller-close revocation", variant.name(), variant.processes(), variant.cuts());
    Ok(())
}
