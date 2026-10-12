// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh Android-created identity, original uncertain send and independently authorized retirement.
use crate::{
    android_roster_traffic as traffic, android_witness::witness, fixture, independent_inputs,
    issue_grant, p, run_foreign, witness_tls_faults, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    cell::Cell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};

#[test]
fn original_android_retirement() -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("retirement cases")?);
    let driver = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("retirement driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    for profile in ["fixed", "recoverable"] {
        route(&output, &driver, profile, "signed")?;
    }
    Ok(())
}
fn route(out: &Path, driver: &Path, profile: &str, carrier: &str) -> Result<()> {
    let label = format!("{carrier}-{profile}");
    let base = out.join(&label);
    let inputs = base.join("inputs");
    fs::DirBuilder::new().mode(0o700).create(&base)?;
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
    let mut w = witness::Witness::start()?;
    let reference = fixture::setup_expiring_policy(Some(&w.configured), 1800)?;
    let (root, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let policy = fixture::protocol_policy(&inputs, &sdk)?;
    let pin = w
        .configured
        .store
        .lock()
        .map_err(|_| "witness pin")?
        .pin()?;
    for (name, bytes) in [
        ("witness-carrier", b"signed".to_vec()),
        ("witness-id", pin.identity().as_bytes().to_vec()),
        ("witness-public", pin.public_key().encode().to_vec()),
        (
            "witness-address",
            w.configured.address.to_string().into_bytes(),
        ),
        (
            "authority-id",
            p::AccountAuthorityIdentity::generate()?.as_bytes().to_vec(),
        ),
        ("authority-application", vec![141; 32]),
    ] {
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    let calls = Cell::new(0u64);
    let run = |mode: &str, name: &str| -> Result<Vec<u8>> {
        let result = run_foreign(driver, profile, &inputs, &base, mode, name)?;
        calls.set(calls.get().checked_add(1).ok_or("call census")?);
        Ok(result)
    };
    let request = run("policy-create", "original.request")?;
    let (certificate, original) = issue_grant(&inputs, &root, &intent, validity, &request)?;
    let registry = run("authority-create", "authority-created")?;
    publish_private_bytes(&inputs.join("authority-checkpoint"), &registry)?;
    let prepared = run("policy-prepare", "prepared")?;
    assert_eq!(prepared.len(), 164);
    assert_eq!(
        prepared.get(..4).ok_or("storage protection")?,
        2u32.to_be_bytes()
    );
    let journal =
        p::JournalIdentity::from_trusted_state(prepared.get(4..36).ok_or("journal")?.try_into()?)?;
    let subject = p::AnchorSubject::from_trusted_state(prepared.get(36..132).ok_or("subject")?)?;
    let genesis = p::AnchorGenesis::from_trusted_state(
        subject,
        prepared.get(132..).ok_or("genesis")?.try_into()?,
    )?;
    let previous_pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        original.checkpoint(),
        policy.family(),
    )?;
    let previous =
        previous_pin.verify_device(&certificate, original.as_bytes(), fixture::now()?)?;
    assert_eq!(
        subject,
        p::AnchorSubject::for_device(journal, &previous, policy.as_ref())?
    );
    w.configured.store.lock().map_err(|_| "witness")?.enroll(
        &genesis,
        &previous,
        &policy,
        fixture::now()?,
    )?;
    publish_private_bytes(&inputs.join("witness-subject"), &subject.to_bytes())?;
    let mut tls = if carrier == "tls" {
        let tls = witness_tls_faults::FaultWitness::start(
            Arc::clone(&w.configured.store),
            [
                inputs.as_path(),
                reference.initiator.as_path(),
                reference.responder.as_path(),
            ],
            w._directory.path().join("witness.redb"),
        )?;
        fs::write(inputs.join("witness-address"), tls.address.to_string())?;
        fs::write(inputs.join("witness-carrier"), b"tls")?;
        Some(tls)
    } else {
        None
    };
    assert_eq!(run("policy-activate", "activated.request")?, request);
    let identity = run("policy-identity", "original.identity")?;
    assert_eq!(
        identity.get(32..).ok_or("original journal")?,
        journal.as_bytes()
    );
    let traffic_case = traffic::Case {
        base: &base,
        inputs: &inputs,
        reference: &reference,
        witness: Some(&w.configured),
    };
    let _traffic = traffic::Traffic::begin(&traffic_case, &root, &certificate, &original, &run)?;
    let successor = crate::android_retirement_android::replace(
        &inputs,
        &base.join("successor"),
        driver,
        profile,
        crate::android_retirement_android::Scope {
            root: &root,
            previous: &previous,
            previous_subject: subject,
            policy: &policy,
            validity,
            witness: &w.configured,
        },
    )?;
    assert_ne!(
        fixture::array::<32>(&inputs, "successor-journal")?,
        *journal.as_bytes()
    );
    let cut = |mode: &str, name: &str| -> Result<Vec<u8>> {
        let value = interrupted(driver, profile, &inputs, &base, mode, name)?;
        calls.set(calls.get().checked_add(1).ok_or("call census")?);
        Ok(value)
    };
    let inventory_bytes = run("retired-owned-inventory", "retirement-inventory")?;
    let inventory = p::AnchorRetiredCleanupProposal::from_trusted_state(&inventory_bytes)?;
    assert_eq!(inventory_bytes.len(), 313);
    assert_eq!(
        run("retired-owned-cancelled", "retirement-cancelled")?,
        302u32.to_be_bytes()
    );
    {
        let mut controller = w
            .configured
            .store
            .lock()
            .map_err(|_| "inventory authority")?;
        controller.retain_retired_cleanup(&inventory)?;
        publish_private_bytes(
            &inputs.join("retirement-inventory-receipt"),
            &controller.retired_cleanup_receipt(&inventory)?,
        )?;
    }
    let proposal_bytes = run("retired-owned-prepare-report", "retirement-report-proposal")?;
    let proposal = p::AnchorRetiredReportProposal::from_trusted_state(&proposal_bytes)?;
    assert_eq!(proposal.inventory(), &inventory);
    publish_private_bytes(&inputs.join("retirement-report-proposal"), &proposal_bytes)?;
    {
        let mut controller = w.configured.store.lock().map_err(|_| "report authority")?;
        controller.retain_retired_report(&proposal)?;
        publish_private_bytes(
            &inputs.join("retirement-report-receipt"),
            &controller.retired_report_receipt(&proposal)?,
        )?;
    }
    assert_eq!(
        cut("retired-owned-report-unknown", "retirement-report-unknown")?,
        proposal.report_id()
    );
    let report = run("retired-owned-report-reopen", "retirement-report-reopened")?;
    assert_eq!(
        report.get(..32).ok_or("report identity")?,
        proposal.report_id()
    );
    assert_eq!(
        report.get(32..36).ok_or("report views")?,
        1u32.to_be_bytes()
    );
    let record = report.get(36..).ok_or("complete report")?;
    assert!(record.starts_with(b"QPRDMD01") || record.starts_with(b"QPRDMD02"));
    assert_eq!(
        record.get(8..321).ok_or("report inventory")?,
        inventory_bytes
    );
    publish_private_bytes(&base.join("retirement-complete-report"), record)?;
    // This is the real private-key MAC admission inside the original device, not
    // a public grammar/signature oracle: a same-length changed body must fail.
    assert_eq!(
        run("retired-owned-ack-tampered", "retirement-tampered-report")?,
        208u32.to_be_bytes()
    );
    assert_eq!(
        run("retired-owned-prepare-ack", "retirement-ack-proposal")?,
        proposal_bytes
    );
    {
        let mut controller = w
            .configured
            .store
            .lock()
            .map_err(|_| "host acknowledgement authority")?;
        controller.acknowledge_retired_report(&proposal)?;
        publish_private_bytes(
            &inputs.join("retirement-ack"),
            &controller.retired_report_acknowledgement_receipt(&proposal)?,
        )?;
    }
    assert_eq!(
        run(
            "retired-owned-erase-wrong-purpose",
            "retirement-wrong-purpose"
        )?,
        102u32.to_be_bytes()
    );
    assert_eq!(
        cut(
            "retired-owned-journal-unknown",
            "retirement-journal-unknown"
        )?,
        proposal.report_id()
    );
    assert_eq!(
        cut("retired-owned-signer-unknown", "retirement-signer-unknown")?,
        proposal.report_id()
    );
    assert_eq!(run("retired-owned-verify", "retirement-verified")?, record);
    assert_eq!(
        run(
            "retired-owned-operational-denied",
            "retirement-operational-denied"
        )?,
        215u32.to_be_bytes()
    );
    let message = fixture::array::<32>(&inputs, "connection-message")?;
    let effect = fs::read(
        reference
            .responder
            .join(format!("application-{}", fixture::hex(&message))),
    )?;
    assert_eq!(effect, fs::read(base.join("roster-effect-before"))?);
    publish_private_bytes(&base.join("retirement-effect-after"), &effect)?;
    assert_eq!(calls.get(), 21);
    publish_private_bytes(&base.join("process-count"), &calls.get().to_be_bytes())?;
    assert_eq!(successor.calls, 6);
    assert!(!successor.certificate.is_empty());
    assert_eq!(successor.roster.checkpoint().version(), 2);
    let next_base = base.join("successor");
    let next_inputs = next_base.join("inputs");
    let next_calls = Cell::new(successor.calls);
    let next_run = |mode: &str, name: &str| -> Result<Vec<u8>> {
        let result = run_foreign(driver, profile, &next_inputs, &next_base, mode, name)?;
        next_calls.set(next_calls.get().checked_add(1).ok_or("next calls")?);
        Ok(result)
    };
    crate::android_replacement_traffic::exercise(
        &traffic::Case {
            base: &next_base,
            inputs: &next_inputs,
            reference: &reference,
            witness: Some(&w.configured),
        },
        &root,
        &successor.certificate,
        &successor.roster,
        &next_run,
    )?;
    assert_eq!(next_calls.get(), 11);
    publish_private_bytes(
        &next_base.join("process-count"),
        &next_calls.get().to_be_bytes(),
    )?;
    let old_effect = fs::read(
        reference
            .responder
            .join(format!("application-{}", fixture::hex(&message))),
    )?;
    assert_eq!(old_effect, effect);
    publish_private_bytes(&base.join("retirement-effect-after-successor"), &old_effect)?;
    policy.close();
    sdk.close();
    if let Some(tls) = tls.as_mut() {
        tls.finish()?;
    }
    w.join()?;
    println!("qualified Android-owned retirement {label}: 32 Java processes; 3 actual process cuts; Android-owned successor traffic; original complete report and one peer effect");
    Ok(())
}

pub(crate) fn interrupted(
    driver: &Path,
    profile: &str,
    inputs: &Path,
    base: &Path,
    mode: &str,
    name: &str,
) -> Result<Vec<u8>> {
    let mut child = fixture::OwnedChild(
        Command::new(driver)
            .arg(mode)
            .arg(profile)
            .arg(inputs)
            .arg(base.join("installation"))
            .arg(base.join(name))
            .stdout(Stdio::from(fs::File::create(
                base.join(format!("{name}.stdout")),
            )?))
            .stderr(Stdio::from(fs::File::create(
                base.join(format!("{name}.stderr")),
            )?))
            .spawn()?,
    );
    let status = fixture::wait(&mut child)?;
    assert_eq!(
        status.code(),
        Some(77),
        "{}",
        String::from_utf8_lossy(&fs::read(base.join(format!("{name}.stderr")))?)
    );
    assert!(fs::read(base.join(format!("{name}.stdout")))?.is_empty());
    assert!(fs::read(base.join(format!("{name}.stderr")))?.is_empty());
    Ok(fs::read(base.join(name))?)
}
