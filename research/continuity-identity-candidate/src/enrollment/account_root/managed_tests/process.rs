// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::process::{Command, Stdio};

#[test]
fn managed_root_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_MANAGED_ROOT_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let wire = fs::read(path.join("managed-inputs")).expect("independently retained expectations");
    let mut decoder = Decoder::new(&wire);
    let registry_identity =
        AccountAuthorityIdentity::from_trusted_state(decoder.array().expect("registry identity"))
            .expect("original identity");
    let application =
        ApplicationAccountId::from_trusted_state(decoder.array().expect("application"))
            .expect("application");
    let revision = u64::from_be_bytes(decoder.array().expect("original revision"));
    let account = decoder.array().expect("original account");
    let witness = AnchorIdentity::from_trusted_state(decoder.array().expect("witness identity"))
        .expect("identity");
    let public = PublicKey::decode(
        decoder
            .take(PUBLIC_KEY_BYTES)
            .expect("witness public bytes"),
    )
    .expect("witness key");
    decoder.finish().expect("exact input");
    let pin = AnchorPin::new(witness, public);
    let plan = AnchorAccountReplacementPlan::from_trusted_state(
        &fs::read(path.join("managed-plan")).expect("same approved plan"),
    )
    .expect("plan");
    let (root, _, family, _) = plan.target().authority_transition();
    let intent = EnrollmentIntent::new(
        root.clone(),
        DeviceDescription::new(
            [7; 16],
            1,
            family,
            Validity::new(100, 200).expect("fixture validity"),
        )
        .expect("original fixture metadata"),
    );
    let base = path.parent().expect("owned fixture base");
    let registry = AccountAuthorityStore::open(
        &base.join("registry"),
        JournalKey::open(&base.join("registry-key")).expect("original key"),
        registry_identity,
        family,
        pin.clone(),
    )
    .expect("original registry");
    let expected = AccountAuthorityCheckpoint::from_trusted_state(application, revision, account)
        .expect("original checkpoint");
    let adoption = if std::env::var_os("QPERIAPT_MANAGED_ROOT_ADOPTION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        let approved = Proposal::from_trusted_state(
            &fs::read(path.join("managed-winner")).expect("independently approved winner"),
        )
        .expect("exact approved proposal");
        Some(
            crate::ManagedAccountRootAdoption::verify(
                &pin,
                &plan,
                approved,
                &fs::read(path.join("managed-noncommit")).expect("original non-commit"),
                &fs::read(path.join("managed-receipt")).expect("signed winner retirement"),
            )
            .expect("pinned approved adoption"),
        )
    } else {
        None
    };
    let transition = if std::env::var_os("QPERIAPT_MANAGED_ROOT_TRANSITION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        let next = AnchorAccountReplacementPlan::from_trusted_state(
            &fs::read(path.join("managed-next-plan")).expect("independent next approval"),
        )
        .expect("next plan");
        Some(
            crate::ManagedAccountRootTransition::verify(
                &pin,
                &plan,
                next,
                &fs::read(path.join("managed-noncommit")).expect("original non-commit"),
                &fs::read(path.join("managed-freeze")).expect("signed original freeze"),
            )
            .expect("pinned transition"),
        )
    } else {
        None
    };
    let mut managed = Managed::resume_original(registry, expected, plan, paths(&path), intent, pin)
        .expect("existing original preparation");
    if let Some(adoption) = adoption {
        managed
            .adopt_committed_winner(&adoption)
            .expect("ordered approved winner adoption");
        fs::write(path.join("returned"), b"returned").expect("API return marker");
        return;
    }
    if let Some(transition) = transition {
        managed
            .transition_after_noncommit(&transition)
            .expect("ordered registry and parent transition");
        fs::write(path.join("returned"), b"returned").expect("API return marker");
        return;
    }
    managed
        .bind_witness_freeze(&fs::read(path.join("managed-freeze")).expect("signed freeze"))
        .expect("bound original");
    managed
        .retain_witness_retirement(
            &fs::read(path.join("managed-receipt")).expect("signed retirement"),
        )
        .expect("original committed outcome");
    fs::write(path.join("returned"), b"returned").expect("API return marker");
}

pub(super) fn original_inputs(s: &Setup) -> &Path {
    let path =
        s.f.original
            .paths
            .wrapping
            .parent()
            .expect("original private directory");
    let mut public = s.identity.as_bytes().to_vec();
    public.extend_from_slice(s.expected.application().as_bytes());
    public.extend_from_slice(&s.expected.revision().to_be_bytes());
    public.extend_from_slice(&s.expected.account());
    public.extend_from_slice(s.f.pin.identity().as_bytes());
    public.extend_from_slice(&s.f.pin.public_key().encode());
    fs::write(path.join("managed-inputs"), public).expect("public registry and witness pins");
    fs::write(
        path.join("managed-plan"),
        s.plan.to_bytes().expect("original approval"),
    )
    .expect("retained approval");
    path
}

#[test]
fn managed_root_process_loss_preserves_original_operation_across_registry_parent_and_child() {
    for cut in [
        "managed-binding-after",
        "intent-before",
        "intent-after",
        "receipt-before",
        "receipt-after",
        "managed-retirement-after",
        "managed-registry-after",
    ] {
        let (s, registry, original) = Setup::new(200);
        let mut managed = s.begin(registry, original);
        let freeze = s.freeze();
        let frozen =
            s.f.pin
                .verify_account_freeze(s.plan.request(), &freeze)
                .expect("real signed freeze");
        let proposal = s
            .plan
            .bind(&frozen)
            .expect("independently approved original target");
        let receipt = s.f.receipt(&proposal);
        managed.close();
        let path = original_inputs(&s);
        fs::write(path.join("managed-freeze"), &freeze).expect("signed freeze");
        fs::write(path.join("managed-receipt"), &receipt).expect("signed retirement");
        let log = fs::File::create_new(path.join("managed-child.log")).expect("owned log");
        let mut child = crate::durable::tests::ChildGuard(
            Command::new(std::env::current_exe().expect("current test binary"))
                .args([
                    "--exact",
                    "enrollment::account_root::tests::managed::process::managed_root_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MANAGED_ROOT_DIR", path)
                .env("QPERIAPT_ROOT_PARENT_DIR", path)
                .env("QPERIAPT_ROOT_PARENT_CUT", cut)
                .stdout(Stdio::from(log.try_clone().expect("stdout")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "managed boundary not reached: {}",
                fs::read_to_string(path.join("managed-child.log")).expect("child log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists(), "kill precedes API return");
        child.0.kill().expect("kill only owned child");
        assert!(!child.0.wait().expect("reap owned child").success());
        let mut resumed = s.resume();
        let expected_state = if cut == "managed-registry-after" {
            State::Committed
        } else {
            State::Pending
        };
        assert_eq!(
            resumed.state().expect("actual original durable state"),
            expected_state
        );
        assert_eq!(
            resumed
                .bind_witness_freeze(&freeze)
                .expect("same freeze and proposal"),
            proposal
        );
        let checkpoint = resumed
            .retain_witness_retirement(&receipt)
            .expect("reconcile original outcome");
        assert_eq!(checkpoint.revision(), 2);
        assert_eq!(checkpoint.account(), s.f.target.device.account_id());
        let mut current = s
            .activate(&mut resumed, 150)
            .expect("fresh witness admission after recovery");
        current
            .next_prekey_publication_id()
            .expect("actual successor owner");
        resumed.close();
        assert!(matches!(
            current.next_prekey_publication_id(),
            Err(DurableError::Closed)
        ));
        current.close();
        s.f.assert_fenced();
        eprintln!("MANAGED_ROOT_PROCESS cut={cut} original_operation=true revision=2 successor_admitted=true old_fenced=true");
    }
}
