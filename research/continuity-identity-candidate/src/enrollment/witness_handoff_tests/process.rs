// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::Instant,
};

pub(super) fn boundary(stage: &str, after: bool) {
    let Some(root) = std::env::var_os("QPERIAPT_ENROLLMENT_WITNESS_DIR") else {
        return;
    };
    let expected = format!("{stage}-{}", if after { "after" } else { "before" });
    if std::env::var("QPERIAPT_ENROLLMENT_WITNESS_CUT")
        .ok()
        .as_deref()
        != Some(expected.as_str())
    {
        return;
    }
    crate::durable::tests::publish_process_checkpoint(Path::new(&root), stage.as_bytes());
    loop {
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn publish(f: &Fixture, root: &Path) {
    f.transfer.publish_public_inputs(root);
    let d = &f.c.intent.description;
    let description = [
        d.id.as_slice(),
        d.generation.to_be_bytes().as_slice(),
        &d.family,
        d.validity.from().to_be_bytes().as_slice(),
        d.validity.until().to_be_bytes().as_slice(),
    ]
    .concat();
    fs::write(root.join("intent-description"), description).expect("independent public intent");
    fs::write(root.join("policy-family"), f.c.policy.family()).expect("independent family");
}
fn restore(
    root: &Path,
) -> (
    DeviceEnrollment,
    VerifiedSessionPolicy,
    WitnessJournalAdoptionPlan,
) {
    let read = |name| fs::read(root.join(name)).expect("original public input");
    let pin = |name| {
        let raw = read(name);
        let mut d = Decoder::new(&raw);
        let id = AnchorIdentity::from_trusted_state(d.array().expect("ID")).expect("identity");
        let key = PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("public key")).expect("key");
        d.finish().expect("complete pin");
        AnchorPin::new(id, key)
    };
    let origin = pin("origin-pin");
    let current = pin("current-pin");
    let history = AnchorHandoffHistory::restore_trusted_state(
        &read("history"),
        &origin,
        &current,
        read("checkpoint").try_into().expect("checkpoint"),
    )
    .expect("exact retained history");
    let target = AnchorHandoffTargetApproval::restore_trusted_state(
        &read("target-approval"),
        &origin,
        &current,
    )
    .expect("independent target approval");
    let activation = target
        .verify_activation_receipt(
            &read("freeze"),
            &read("ack"),
            &read("retired"),
            &read("activation"),
        )
        .expect("actual original activation");
    let checkpoint = read("policy-checkpoint");
    let mut d = Decoder::new(&checkpoint);
    let expected =
        PolicyCheckpoint::from_trusted_state(d.u64().expect("version"), d.array().expect("digest"))
            .expect("checkpoint");
    d.finish().expect("complete checkpoint");
    let policy = PolicyPin::new(
        read("policy-family").try_into().expect("family"),
        PublicKey::decode(&read("policy-root")).expect("policy root"),
        expected,
    )
    .expect("independent policy pin")
    .verify(&read("policy-wire"), crate::tests::sdk_runtime(), 150)
    .expect("same originally signed policy; no re-signing");
    let raw = read("intent-description");
    let mut d = Decoder::new(&raw);
    let id = d.array().expect("device ID");
    let generation = d.u64().expect("generation");
    let family = d.array().expect("family");
    let validity =
        Validity::new(d.u64().expect("from"), d.u64().expect("until")).expect("validity");
    d.finish().expect("complete description");
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&read("account-root")).expect("original account root"),
        DeviceDescription::new(id, generation, family, validity).expect("original description"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("same original parent");
    let image = owner.image().expect("original metadata");
    let original = owner
        .original_device_metadata(&image)
        .expect("original device");
    let materials = AnchorHandoffAdoptionMaterials {
        original_device: &original,
        current_device: &original,
        original_policy: policy.historical(),
        current_policy: policy.historical(),
        history: &history,
        activation: &activation,
    };
    let scope = AnchorHandoffAdoptionScope::from_trusted_state(&read("scope"))
        .expect("independently retained expected scope");
    let approved = HistoricalAnchorHandoffAdoption::from_approvals(
        &AnchorHandoffAdoptionApproval::from_bytes(&read("account-approval"))
            .expect("original account approval bytes"),
        &AnchorHandoffAdoptionApproval::from_bytes(&read("policy-approval"))
            .expect("original policy approval bytes"),
        &scope,
        &materials,
    )
    .expect("exact two-root consent");
    let plan =
        WitnessJournalAdoptionPlan::new(&approved, &materials).expect("original verified plan");
    (owner, policy, plan)
}
#[test]
fn enrollment_witness_selection_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_ENROLLMENT_WITNESS_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let cut = std::env::var("QPERIAPT_ENROLLMENT_WITNESS_CUT").expect("cut");
    let (mut owner, policy, plan) = restore(&root);
    if cut.contains("prepare") {
        owner
            .prepare_witness_handoff(policy.historical(), plan, || Ok(180))
            .expect("original preparation");
    } else {
        owner
            .adopt_witness_handoff(
                policy.historical(),
                plan,
                &fs::read(root.join("receipt")).expect("original receipt"),
            )
            .expect("original adoption");
    }
    fs::write(root.join("returned"), b"returned").expect("unexpected return marker");
}
#[test]
fn enrollment_witness_selection_sigkill_keeps_parent_and_child_publication_order() {
    use std::os::unix::process::ExitStatusExt;
    for cut in [
        "child-prepare-before",
        "child-prepare-after",
        "parent-prepare-before",
        "parent-prepare-after",
        "child-adopt-before",
        "child-adopt-after",
        "parent-adopt-before",
        "parent-adopt-after",
    ] {
        let f = Fixture::new();
        let root =
            f.c.paths
                .configuration
                .parent()
                .expect("original directory");
        if cut.contains("adopt") {
            open(&f.c)
                .prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || {
                    Ok(180)
                })
                .expect("original prepared phase");
        }
        publish(&f, root);
        let log = fs::File::create(root.join("child.log")).expect("child log");
        let mut child=crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact","enrollment::tests::witness_handoff::process::enrollment_witness_selection_process_child","--nocapture"])
            .env("QPERIAPT_ENROLLMENT_WITNESS_DIR",root).env("QPERIAPT_ENROLLMENT_WITNESS_CUT",cut)
            .env("QPERIAPT_WITNESS_ADOPTION_DIR",root).env("QPERIAPT_WITNESS_ADOPTION_CUT",cut.strip_prefix("child-").unwrap_or(""))
            .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log)).spawn().expect("owned child"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "missing cut {cut}: {}",
                fs::read_to_string(root.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned").exists());
        let pid = child.0.id();
        child.0.kill().expect("kill owned child");
        assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
        let mut owner = open(&f.c);
        owner
            .prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || Ok(180))
            .expect("same original preparation recovery");
        owner
            .adopt_witness_handoff(
                f.c.policy.historical(),
                f.transfer.plan.clone(),
                &f.transfer.receipt,
            )
            .expect("exact original adoption recovery");
        let client = owner
            .current_witness_anchor_client(
                f.c.policy.historical(),
                f.transfer.plan.clone(),
                f.carrier(),
                Duration::from_secs(3),
            )
            .expect("retained signer after process loss");
        let mut active = owner
            .activate(&f.c.policy, 190, Some(client))
            .expect("same original installation");
        let (service, _, device) = active.parts().expect("owners");
        let journal = service.stores().expect("original journal").0;
        assert_eq!(journal.identity().expect("ID"), f.identity);
        assert_eq!(
            journal
                .prekey_leaf(&f.c.policy, device, f.prekey, 190)
                .expect("original prekey")
                .public_key(),
            f.leaf.public_key()
        );
        active.close();
        eprintln!(
            "ENROLLMENT_WITNESS_KILLED cut={cut} child={pid} parent={}",
            std::process::id()
        );
    }
}
