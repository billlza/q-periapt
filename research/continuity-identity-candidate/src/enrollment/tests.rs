// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "renewal_tests.rs"]
pub(super) mod renewal;
#[path = "roster_tests.rs"]
mod roster;
#[path = "witness_renewal_tests.rs"]
mod witness_renewal;
use crate::{
    durable::tests::{assert_sync_failure, directory, fault_database_path},
    tests::{interval, session_policy_fixture},
    LeafKind, PrekeyId, PrekeyQuality,
};
use std::{
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct Case {
    _directory: tempfile::TempDir,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    root: RootSigningKey,
    policy: VerifiedSessionPolicy,
}
fn paths(path: &Path) -> EnrollmentPaths {
    EnrollmentPaths::new(
        &path.join("wrap.key"),
        &path.join("signer.key"),
        &path.join("enrollment.redb"),
        InstallationPaths::new(
            &path.join("installation.redb"),
            &path.join("journal.redb"),
            &path.join("archives.redb"),
        )
        .expect("installation paths"),
    )
    .expect("paths")
}
fn case() -> Case {
    case_with_anchor(crate::AnchorRequirement::local_only())
}
fn case_with_anchor(anchor: crate::AnchorRequirement) -> Case {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let paths = paths(&path);
    drop(JournalKey::provision(&paths.wrapping).expect("explicit first key"));
    let (_issuer, issued, pin, runtime) =
        crate::tests::session_policy_fixture_with_anchor(&[PrekeyQuality::OneTimeBoth], anchor);
    let policy = pin.verify(issued.as_bytes(), runtime, 150).expect("policy");
    let root = RootSigningKey::generate().expect("account owner");
    let intent = EnrollmentIntent::new(
        root.public_key().expect("root"),
        DeviceDescription::new([7; 16], 1, policy.family(), interval()).expect("approved metadata"),
    );
    Case {
        _directory: dir,
        paths,
        intent,
        root,
        policy,
    }
}
fn create(c: &Case) -> DeviceEnrollment {
    DeviceEnrollment::provision(c.paths.clone(), c.intent.clone()).expect("new intent")
}
fn open(c: &Case) -> DeviceEnrollment {
    DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).expect("original intent")
}
fn response(c: &Case, wire: &[u8]) -> (Vec<u8>, crate::IssuedRoster, AccountPin) {
    let request =
        VerifiedEnrollmentRequest::verify(wire, &c.intent, 150).expect("proof of possession");
    let cert = c
        .root
        .issue_enrollment(&request, 150)
        .expect("explicit issuer grant");
    let roster = c
        .root
        .issue_roster(
            1,
            interval(),
            &[c.root.roster_entry(&cert).expect("member")],
        )
        .expect("roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent response pin");
    (cert, roster, pin)
}
fn accepted(c: &Case) -> (DeviceEnrollment, Vec<u8>, JournalIdentity) {
    let mut owner = create(c);
    let wire = owner.request(150).expect("durable request");
    let (cert, roster, pin) = response(c, &wire);
    let id = owner
        .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
        .expect("accept credential");
    (owner, wire, id)
}

#[test]
fn original_enrollment_restarts_through_request_acceptance_activation_and_real_prekey() {
    let c = case();
    assert!(DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err());
    assert!(!c.paths.configuration.exists() && !c.paths.signer.exists());
    let mut owner = create(&c);
    let original = owner.identity().expect("identity before signer");
    assert_eq!(owner.status().expect("state"), EnrollmentStatus::Preparing);
    assert!(!c.paths.signer.exists());
    assert!(
        DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err(),
        "lease"
    );
    owner.close();
    owner = open(&c);
    let request = owner.request(150).expect("first release");
    assert_eq!(
        VerifiedEnrollmentRequest::verify(&request, &c.intent, 150)
            .expect("request")
            .identity(),
        original
    );
    let key_bytes = fs::read(&c.paths.signer).expect("original encrypted key");
    owner.close();
    owner = open(&c);
    assert_eq!(owner.request(150).expect("exact retry"), request);
    let (cert, roster, pin) = response(&c, &request);
    let journal = owner
        .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
        .expect("accepted");
    assert_eq!(
        owner
            .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
            .expect("same acceptance"),
        journal
    );
    assert!(!c
        .paths
        .installation
        .files()
        .first()
        .expect("configuration")
        .exists());
    owner.close();
    owner = open(&c);
    assert_eq!(
        owner.status().expect("phase"),
        EnrollmentStatus::Accepted(journal)
    );
    assert!(matches!(
        owner.prepare(&c.policy, 150).expect("prepare"),
        InstallationPreparation::Local
    ));
    owner.close();
    owner = open(&c);
    let mut device = owner.activate(&c.policy, 150, None).expect("activate");
    let prekey = PrekeyId::from_trusted_state([55; 32]).expect("prekey identity");
    let (service, signer, identity) = device.parts().expect("controlled owners");
    signer.check_device(identity).expect("original signer");
    let public = service
        .stores()
        .expect("stores")
        .0
        .generate_prekey(
            &c.policy,
            identity,
            prekey,
            LeafKind::OneTimePq,
            interval(),
            150,
        )
        .expect("actual SDK key generation");
    assert!(
        DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err(),
        "active enrollment lease"
    );
    device.close();
    assert!(device.parts().is_err());
    let mut owner = open(&c);
    assert_eq!(
        owner.status().expect("phase"),
        EnrollmentStatus::Active(journal)
    );
    let mut device = owner
        .activate(&c.policy, 150, None)
        .expect("original active service");
    let (service, _, identity) = device.parts().expect("parts");
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("journal"),
        journal
    );
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .generate_prekey(
                &c.policy,
                identity,
                prekey,
                LeafKind::OneTimePq,
                interval(),
                150
            )
            .expect("original prekey")
            .public_key(),
        public.public_key()
    );
    assert_eq!(
        fs::read(&c.paths.signer).expect("unchanged signer"),
        key_bytes
    );
}

#[test]
fn proof_of_possession_binds_intent_purpose_and_both_signatures() {
    let c = case();
    let mut owner = create(&c);
    let wire = owner.request(150).expect("request");
    for offset in [
        0,
        4,
        12,
        44,
        76,
        92,
        100,
        116,
        148,
        4 + REQUEST_BODY,
        4 + REQUEST_BODY + q_periapt_backends::ML_DSA_65_SIG_LEN,
        wire.len() - 1,
    ] {
        let mut changed = wire.clone();
        *changed.get_mut(offset).expect("field") ^= 1;
        assert!(
            VerifiedEnrollmentRequest::verify(&changed, &c.intent, 150).is_err(),
            "field {offset}"
        );
    }
    let request = VerifiedEnrollmentRequest::verify(&wire, &c.intent, 150).expect("request");
    assert!(RootSigningKey::generate()
        .expect("other root")
        .issue_enrollment(&request, 150)
        .is_err());
    assert!(VerifiedEnrollmentRequest::verify(&wire, &c.intent, 200).is_err());
    let identity = owner.image().expect("image").identity;
    let signer = owner.signer(identity, false).expect("signer");
    let (body, _) = open_envelope(&wire).expect("body");
    let wrong = envelope(
        body,
        &signer
            .sign(Purpose::Credential, body)
            .expect("other purpose"),
    )
    .expect("envelope");
    assert!(VerifiedEnrollmentRequest::verify(&wrong, &c.intent, 150).is_err());
    let other = case();
    assert!(VerifiedEnrollmentRequest::verify(&wire, &other.intent, 150).is_err());
}

#[test]
fn acceptance_refuses_another_key_metadata_roster_or_policy_without_creating_children() {
    let c = case();
    let mut owner = create(&c);
    let wire = owner.request(150).expect("request");
    let (cert, roster, pin) = response(&c, &wire);
    let wrong = c
        .root
        .issue_device(
            c.intent.description.clone(),
            DeviceSigningKey::generate()
                .expect("wrong signer")
                .public_key()
                .expect("public"),
        )
        .expect("valid other certificate");
    let wrong_roster = c
        .root
        .issue_roster(
            1,
            interval(),
            &[c.root.roster_entry(&wrong).expect("member")],
        )
        .expect("roster");
    let wrong_pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        wrong_roster.checkpoint(),
        c.policy.family(),
    )
    .expect("pin");
    assert!(owner
        .accept(&wrong, wrong_roster.as_bytes(), &wrong_pin, &c.policy, 150)
        .is_err());
    owner = open(&c);
    assert_eq!(
        owner.status().expect("unchanged"),
        EnrollmentStatus::Requested
    );
    let empty = c.root.issue_roster(2, interval(), &[]).expect("revoked");
    assert!(owner
        .accept(&cert, empty.as_bytes(), &pin, &c.policy, 150)
        .is_err());
    owner = open(&c);
    let id = owner
        .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
        .expect("original response");
    let different = c
        .root
        .issue_roster(2, interval(), &[c.root.roster_entry(&cert).expect("entry")])
        .expect("different current roster");
    let different_pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        different.checkpoint(),
        c.policy.family(),
    )
    .expect("pin");
    assert!(owner
        .accept(&cert, different.as_bytes(), &different_pin, &c.policy, 150)
        .is_err());
    owner = open(&c);
    assert_eq!(
        owner.status().expect("retained acceptance"),
        EnrollmentStatus::Accepted(id)
    );
    assert!(!c
        .paths
        .installation
        .files()
        .first()
        .expect("configuration")
        .exists());
}

#[test]
fn partial_or_replaced_signer_never_triggers_replacement_generation() {
    for partial in [true, false] {
        let c = case();
        let mut owner = create(&c);
        let id = owner.identity().expect("id");
        if partial {
            fs::write(&c.paths.signer, []).expect("simulated unpublished partial creation");
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&c.paths.signer, fs::Permissions::from_mode(0o600)).expect("mode");
        } else {
            DeviceSigningKey::provision(
                &c.paths.signer,
                &JournalKey::open(&c.paths.wrapping).expect("key"),
                SigningKeyId::generate().expect("wrong identity"),
            )
            .expect("other owner");
        }
        let before = fs::read(&c.paths.signer).expect("bytes");
        assert!(owner.request(150).is_err());
        owner = open(&c);
        assert_eq!(owner.identity().expect("same original id"), id);
        assert!(owner.request(150).is_err());
        assert_eq!(fs::read(&c.paths.signer).expect("preserved"), before);
    }
}

#[test]
fn active_enrollment_never_recreates_missing_original_installation_or_children() {
    for ordinal in 0..3 {
        let c = case();
        let (mut owner, _, id) = accepted(&c);
        owner.prepare(&c.policy, 150).expect("prepare");
        owner
            .activate(&c.policy, 150, None)
            .expect("activate")
            .close();
        let path = c
            .paths
            .installation
            .files()
            .get(ordinal)
            .copied()
            .expect("path")
            .to_owned();
        fs::remove_file(&path).expect("simulate loss");
        let mut owner = open(&c);
        assert_eq!(
            owner.status().expect("active"),
            EnrollmentStatus::Active(id)
        );
        assert!(owner.activate(&c.policy, 150, None).is_err());
        assert!(!path.exists());
    }
}

fn faulty(c: &Case, after: bool) -> (DeviceEnrollment, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (database, remaining, count, _) = fault_database_path(&c.paths.configuration, after);
    let key = JournalKey::open(&c.paths.wrapping).expect("key");
    let binding = c.paths.binding(&key, &c.intent).expect("scope");
    (
        DeviceEnrollment {
            active: Some(Active { database, key }),
            paths: c.paths.clone(),
            intent: c.intent.clone(),
            binding,
        },
        remaining,
        count,
    )
}
#[test]
fn every_request_commit_sync_fault_withholds_output_and_recovers_original_key_and_request() {
    let c = case();
    create(&c).close();
    let (mut owner, _, count) = faulty(&c, false);
    owner.request(150).expect("calibration");
    let syncs = count.load(Ordering::SeqCst);
    assert!(syncs > 0);
    owner.close();
    for after in [false, true] {
        for cut in 1..=syncs {
            let c = case();
            let mut owner = create(&c);
            let id = owner.identity().expect("id");
            owner.close();
            let (mut owner, remaining, _) = faulty(&c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(owner.request(150), after);
            assert!(owner.active.is_none());
            let bytes = fs::read(&c.paths.signer).expect("original key survived failed request");
            let mut recovered = open(&c);
            let request = recovered.request(150).expect("reconcile");
            assert_eq!(
                VerifiedEnrollmentRequest::verify(&request, &c.intent, 150)
                    .expect("proof")
                    .identity(),
                id
            );
            recovered.close();
            assert_eq!(
                open(&c).request(150).expect("original committed request"),
                request
            );
            assert_eq!(fs::read(&c.paths.signer).expect("unchanged key"), bytes);
        }
    }
    eprintln!(
        "ENROLLMENT_REQUEST_SYNC syncs={syncs} injected_cases={}",
        syncs * 2
    );
}

thread_local! {
    static CLOSE_POLICY_AFTER_ACTIVE: std::cell::RefCell<Option<Arc<VerifiedSessionPolicy>>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn initial_boundary(stage: &str) {
    let Some(root) = std::env::var_os("QPERIAPT_ENROLLMENT_INITIAL_ROOT") else {
        return;
    };
    if std::env::var("QPERIAPT_ENROLLMENT_INITIAL_STAGE").expect("stage") != stage {
        return;
    }
    let root = Path::new(&root);
    fs::write(root.join("initial-ready.pending"), stage).expect("marker");
    fs::rename(
        root.join("initial-ready.pending"),
        root.join("initial-ready"),
    )
    .expect("marker publication");
    loop {
        std::thread::park();
    }
}

#[test]
fn unpublished_initial_enrollment_configuration_resumes_explicit_first_use() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for cut in ["before-commit", "after-commit"] {
        let c = case();
        let root = c.paths.configuration.parent().expect("root");
        fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "enrollment::tests::enrollment_process_cut_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_ENROLLMENT_CUT_ROOT", root)
                .env("QPERIAPT_ENROLLMENT_CUT_PHASE", "0")
                .env("QPERIAPT_ENROLLMENT_INITIAL_ROOT", root)
                .env("QPERIAPT_ENROLLMENT_INITIAL_STAGE", cut)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("creator"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("initial-ready").exists() {
            assert!(child.0.try_wait().expect("status").is_none() && Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!c.paths.configuration.exists());
        assert!(!c.paths.signer.exists());
        assert!(!c.paths.installation.files().iter().any(|p| p.exists()));
        child.0.kill().expect("kill initial creator");
        assert!(!child.0.wait().expect("reap").success());
        assert!(DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err());
        let mut owner = create(&c);
        let original = owner.identity().expect("newly published ID");
        let wire = owner.request(150).expect("first released request");
        assert_eq!(
            VerifiedEnrollmentRequest::verify(&wire, &c.intent, 150)
                .expect("proof")
                .identity(),
            original
        );
        let (certificate, roster, pin) = response(&c, &wire);
        let journal = owner
            .accept(&certificate, roster.as_bytes(), &pin, &c.policy, 150)
            .expect("response");
        owner.prepare(&c.policy, 150).expect("installation");
        let mut service = owner
            .activate(&c.policy, 150, None)
            .expect("active original published enrollment");
        assert_eq!(
            service
                .parts()
                .expect("parts")
                .0
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("journal"),
            journal
        );
        eprintln!("ENROLLMENT_INITIAL_PUBLICATION_CUT cut={cut} unpublished_children_absent=true explicit_intent_resumed=true");
    }
}

pub(super) fn after_roster_journal_commit() {
    roster::journal_boundary();
}

pub(super) fn after_commit(bytes: &[u8]) {
    if bytes.get(72) == Some(&4) {
        CLOSE_POLICY_AFTER_ACTIVE.with(|pending| {
            if let Some(policy) = pending.borrow_mut().take() {
                std::thread::spawn(move || policy.close())
                    .join()
                    .expect("concurrent policy close");
            }
        });
    }
    let Some(path) = std::env::var_os("QPERIAPT_ENROLLMENT_CUT_ROOT") else {
        return;
    };
    let phase: u8 = std::env::var("QPERIAPT_ENROLLMENT_CUT_PHASE")
        .expect("phase")
        .parse()
        .expect("number");
    if bytes.get(72) != Some(&phase) {
        return;
    }
    use std::io::Write;
    let root = Path::new(&path);
    let mut file = fs::File::create_new(root.join("committed.pending")).expect("barrier");
    file.write_all(&[phase]).expect("write");
    file.sync_all().expect("sync");
    fs::rename(root.join("committed.pending"), root.join("committed")).expect("publish");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "parent did not interrupt committed enrollment"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn acceptance_checks_live_policy_and_exact_authority_approved_description() {
    let c = case();
    let mut owner = create(&c);
    let wire = owner.request(150).expect("request");
    let req = VerifiedEnrollmentRequest::verify(&wire, &c.intent, 150).expect("request");
    let wrong = c
        .root
        .issue_device(
            DeviceDescription::new([8; 16], 1, c.policy.family(), interval())
                .expect("different device"),
            req.public_key().clone(),
        )
        .expect("certificate");
    let roster = c
        .root
        .issue_roster(
            1,
            interval(),
            &[c.root.roster_entry(&wrong).expect("entry")],
        )
        .expect("roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("pin");
    assert!(owner
        .accept(&wrong, roster.as_bytes(), &pin, &c.policy, 150)
        .is_err());
    owner = open(&c);
    let (cert, roster, pin) = response(&c, &wire);
    c.policy.close();
    assert!(owner
        .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
        .is_err());
    assert_eq!(
        open(&c).status().expect("original requested phase"),
        EnrollmentStatus::Requested
    );
}

#[test]
fn acceptance_and_activation_sync_faults_reconcile_the_original_journal_and_stage() {
    for activation in [false, true] {
        let setup = |c: &Case| {
            let mut owner = create(c);
            let wire = owner.request(150).expect("request");
            let (cert, roster, pin) = response(c, &wire);
            let id = if activation {
                let id = owner
                    .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
                    .expect("accepted");
                owner.prepare(&c.policy, 150).expect("prepared");
                Some(id)
            } else {
                None
            };
            owner.close();
            (wire, cert, roster, pin, id)
        };
        let c = case();
        let (_, cert, roster, pin, _) = setup(&c);
        let (mut owner, _, count) = faulty(&c, false);
        let syncs = if activation {
            let mut device = owner
                .activate(&c.policy, 150, None)
                .expect("calibrate activation");
            let count = count.load(Ordering::SeqCst);
            device.close();
            count
        } else {
            owner
                .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
                .expect("calibrate acceptance");
            let count = count.load(Ordering::SeqCst);
            owner.close();
            count
        };
        assert!(syncs > 0);
        for after in [false, true] {
            for cut in 1..=syncs {
                let c = case();
                let (wire, cert, roster, pin, original) = setup(&c);
                let (mut owner, remaining, _) = faulty(&c, after);
                remaining.store(cut, Ordering::SeqCst);
                if activation {
                    assert_sync_failure(owner.activate(&c.policy, 150, None), after);
                } else {
                    assert_sync_failure(
                        owner.accept(&cert, roster.as_bytes(), &pin, &c.policy, 150),
                        after,
                    );
                    assert!(owner.active.is_none());
                }
                let mut recovered = open(&c);
                assert_eq!(
                    recovered.request(150).expect("exact original request"),
                    wire
                );
                let before = recovered.status().expect("durable outcome");
                let id = recovered
                    .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
                    .expect("original acceptance");
                if let Some(expected) = original {
                    assert_eq!(id, expected);
                }
                if let EnrollmentStatus::Accepted(expected)
                | EnrollmentStatus::Activating(expected)
                | EnrollmentStatus::Active(expected) = before
                {
                    assert_eq!(id, expected);
                }
                if !activation {
                    recovered
                        .prepare(&c.policy, 150)
                        .expect("initial preparation");
                }
                let mut device = recovered
                    .activate(&c.policy, 150, None)
                    .expect("retry original activation");
                assert_eq!(
                    device
                        .parts()
                        .expect("parts")
                        .0
                        .stores()
                        .expect("stores")
                        .0
                        .identity()
                        .expect("journal"),
                    id
                );
            }
        }
        eprintln!(
            "ENROLLMENT_SYNC activation={activation} syncs={syncs} injected_cases={}",
            syncs * 2
        );
    }
}

#[test]
fn enrollment_process_cut_child() {
    let Some(root) = std::env::var_os("QPERIAPT_ENROLLMENT_CUT_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let paths = paths(root);
    let (_, issued, pin, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let policy = pin
        .verify(issued.as_bytes(), runtime, 150)
        .expect("current policy");
    let public = PublicKey::decode(&fs::read(root.join("trusted-root")).expect("independent root"))
        .expect("root");
    let intent = EnrollmentIntent::new(
        public.clone(),
        DeviceDescription::new([7; 16], 1, policy.family(), interval())
            .expect("approved description"),
    );
    let phase: u8 = std::env::var("QPERIAPT_ENROLLMENT_CUT_PHASE")
        .expect("phase")
        .parse()
        .expect("number");
    let mut owner = if phase == 0 {
        DeviceEnrollment::provision(paths, intent).expect("original enrollment creation")
    } else {
        DeviceEnrollment::open(paths, intent).expect("original enrollment")
    };
    if phase == 0 {
        return;
    }
    if phase == 1 {
        owner.request(150).expect("interrupted request");
    } else if phase == 2 {
        let checkpoint = RosterCheckpoint::from_trusted_state(
            1,
            fs::read(root.join("trusted-checkpoint"))
                .expect("checkpoint")
                .try_into()
                .expect("width"),
        )
        .expect("checkpoint");
        let pin = AccountPin::new(
            crate::identity::account_id(&public),
            public,
            checkpoint,
            policy.family(),
        )
        .expect("independent current pin");
        owner
            .accept(
                &fs::read(root.join("issued-certificate")).expect("certificate"),
                &fs::read(root.join("issued-roster")).expect("roster"),
                &pin,
                &policy,
                150,
            )
            .expect("interrupted acceptance");
    } else {
        owner
            .activate(&policy, 150, None)
            .expect("interrupted activation");
    }
}

#[test]
fn signer_publication_cuts_resume_the_original_preparing_enrollment() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for stage in ["generated", "published"] {
        let c = case();
        let root = c.paths.configuration.parent().expect("root");
        let mut owner = create(&c);
        let identity = owner.identity().expect("committed original identity");
        owner.close();
        fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
        let log = fs::File::create_new(root.join("signer-child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "enrollment::tests::enrollment_process_cut_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_ENROLLMENT_CUT_ROOT", root)
                .env("QPERIAPT_ENROLLMENT_CUT_PHASE", "1")
                .env("QPERIAPT_SIGNING_CRASH_DIR", root)
                .env("QPERIAPT_SIGNING_CRASH_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("request process"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "signer cut {stage} missing: {}",
                fs::read_to_string(root.join("signer-child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read_to_string(root.join("ready")).expect("marker"),
            stage
        );
        child.0.kill().expect("kill original requester");
        assert!(!child.0.wait().expect("reap").success());
        assert_eq!(c.paths.signer.exists(), stage == "published");
        let prior_public = fs::read(root.join("computed-public")).expect("diagnostic only");
        let mut resumed = open(&c);
        assert_eq!(
            resumed.status().expect("phase"),
            EnrollmentStatus::Preparing
        );
        assert_eq!(resumed.identity().expect("identity"), identity);
        let wire = resumed.request(150).expect("resume committed intent");
        let request = VerifiedEnrollmentRequest::verify(&wire, &c.intent, 150).expect("proof");
        assert_eq!(request.identity(), identity);
        assert_eq!(
            request.public_key().encode() == prior_public,
            stage == "published"
        );
        assert_eq!(resumed.request(150).expect("exact released retry"), wire);
        let (certificate, roster, pin) = response(&c, &wire);
        let journal = resumed
            .accept(&certificate, roster.as_bytes(), &pin, &c.policy, 150)
            .expect("authorized response");
        resumed
            .prepare(&c.policy, 150)
            .expect("original installation");
        let mut enrolled = resumed
            .activate(&c.policy, 150, None)
            .expect("active original enrollment");
        assert_eq!(
            enrolled
                .parts()
                .expect("parts")
                .0
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("journal"),
            journal
        );
        eprintln!("ENROLLMENT_SIGNER_PUBLICATION_CUT stage={stage} retained_identity=true published_key_reused={}", stage == "published");
    }
}

#[test]
fn process_cuts_after_each_enrollment_commit_resume_the_original_operation() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for phase in [0u8, 1, 2, 3, 4] {
        let c = case();
        let root = c.paths.configuration.parent().expect("root");
        fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("trusted root");
        let mut owner = (phase != 0).then(|| create(&c));
        let identity = owner
            .as_mut()
            .map(|owner| owner.identity().expect("original identity"));
        let mut original_request = None;
        let mut original_journal = None;
        if phase > 1 {
            let owner = owner.as_mut().expect("existing intent");
            let wire = owner.request(150).expect("request");
            let (cert, roster, pin) = response(&c, &wire);
            fs::write(root.join("issued-certificate"), &cert).expect("response");
            fs::write(root.join("issued-roster"), roster.as_bytes()).expect("roster");
            fs::write(
                root.join("trusted-checkpoint"),
                roster.checkpoint().digest(),
            )
            .expect("independent checkpoint");
            if phase > 2 {
                original_journal = Some(
                    owner
                        .accept(&cert, roster.as_bytes(), &pin, &c.policy, 150)
                        .expect("accepted"),
                );
                owner.prepare(&c.policy, 150).expect("prepared");
            }
            original_request = Some(wire);
        }
        if let Some(owner) = &mut owner {
            owner.close();
        }
        let log = fs::File::create_new(root.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "enrollment::tests::enrollment_process_cut_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_ENROLLMENT_CUT_ROOT", root)
                .env("QPERIAPT_ENROLLMENT_CUT_PHASE", phase.to_string())
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("committed").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "commit barrier failed: {}",
                fs::read_to_string(root.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            fs::read(root.join("committed")).expect("committed phase"),
            vec![phase]
        );
        child
            .0
            .kill()
            .expect("interrupt after commit before return");
        assert!(!child.0.wait().expect("reap").success());
        let mut recovered = open(&c);
        let recovered_id = recovered.identity().expect("same identity");
        if let Some(expected) = identity {
            assert_eq!(recovered_id, expected);
        }
        let status = recovered.status().expect("phase before retry");
        if phase == 0 {
            assert!(!c.paths.signer.exists());
        }
        let request = recovered.request(150).expect("original committed request");
        if let Some(before) = original_request {
            assert_eq!(request, before);
        }
        assert!(
            matches!(
                (phase, status),
                (0, EnrollmentStatus::Preparing)
                    | (1, EnrollmentStatus::Requested)
                    | (2, EnrollmentStatus::Accepted(_))
                    | (3, EnrollmentStatus::Activating(_))
                    | (4, EnrollmentStatus::Active(_))
            ),
            "wrong recovered phase: {status:?}"
        );
        if let EnrollmentStatus::Activating(id) | EnrollmentStatus::Active(id) = status {
            assert_eq!(Some(id), original_journal);
        }
        if phase > 2 {
            let mut service = recovered
                .activate(&c.policy, 150, None)
                .expect("original activation retry");
            assert_eq!(
                Some(
                    service
                        .parts()
                        .expect("parts")
                        .0
                        .stores()
                        .expect("stores")
                        .0
                        .identity()
                        .expect("journal")
                ),
                original_journal
            );
        }
        eprintln!(
            "ENROLLMENT_PROCESS_CUT phase={phase} recovered_phase_matches=true prior_request_compared={}", phase > 1
        );
    }
}

#[test]
fn policy_closed_at_final_enrollment_commit_withholds_service_but_retains_active_state() {
    let c = case();
    let (mut owner, _, id) = accepted(&c);
    owner.prepare(&c.policy, 150).expect("prepare");
    let key = fs::read(&c.paths.signer).expect("original signer");
    let policy = Arc::new(c.policy);
    CLOSE_POLICY_AFTER_ACTIVE.with(|pending| *pending.borrow_mut() = Some(Arc::clone(&policy)));
    assert!(
        matches!(
            owner.activate(&policy, 150, None),
            Err(DurableError::Protocol(Error::Closed))
        ),
        "final policy close must withhold operational owners"
    );
    let mut recovered = DeviceEnrollment::open(c.paths.clone(), c.intent.clone())
        .expect("original state inspection");
    assert_eq!(
        recovered.status().expect("committed state"),
        EnrollmentStatus::Active(id)
    );
    assert!(matches!(
        recovered.activate(&policy, 150, None),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(fs::read(&c.paths.signer).expect("preserved signer"), key);
}

struct NativeWitness(Arc<std::sync::Mutex<crate::AnchorStore>>);
impl AnchorTransport for NativeWitness {
    fn exchange(&mut self, request: &[u8], _: std::time::Instant) -> std::io::Result<Vec<u8>> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("witness poisoned"))?
            .handle(request, 150)
            .map_err(std::io::Error::other)
    }
}
#[test]
fn required_witness_enrollment_uses_original_genesis_and_never_falls_back() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("witness path");
    let store = crate::AnchorStore::provision(
        &path.join("witness.redb"),
        JournalKey::provision(&path.join("witness.key")).expect("independent witness key"),
        crate::AnchorSigningKey::generate().expect("independent signer"),
        crate::AnchorIdentity::generate().expect("witness id"),
    )
    .expect("witness");
    let pin = store.pin().expect("pin");
    let store = Arc::new(std::sync::Mutex::new(store));
    let c = case_with_anchor(crate::AnchorRequirement::required(&pin));
    let (mut owner, wire, id) = accepted(&c);
    let preparation = owner.prepare(&c.policy, 150).expect("original prepare");
    assert!(matches!(
        preparation,
        InstallationPreparation::RequiresEnrollment(_)
    ));
    if let InstallationPreparation::RequiresEnrollment(genesis) = preparation {
        assert_eq!(
            genesis.subject().to_bytes().get(..32),
            Some(id.as_bytes().as_slice())
        );
        assert!(matches!(
            owner.activate(&c.policy, 150, None),
            Err(DurableError::AnchorRequired)
        ));
        let mut owner = open(&c);
        assert_eq!(
            owner.status().expect("original activation intent"),
            EnrollmentStatus::Activating(id)
        );
        let (cert, roster, account) = response(&c, &wire);
        let device = account
            .verify_device(&cert, roster.as_bytes(), 150)
            .expect("independently verified original credential");
        store
            .lock()
            .expect("witness")
            .enroll(&genesis, &device, &c.policy, 150)
            .expect("explicit independent enrollment");
        let wrong = crate::AnchorPin::new(
            crate::AnchorIdentity::generate().expect("other id"),
            crate::AnchorSigningKey::generate()
                .expect("other signer")
                .public_key()
                .expect("public"),
        );
        assert!(owner
            .anchor_client(
                &c.policy,
                150,
                wrong,
                Box::new(NativeWitness(Arc::clone(&store))),
                Duration::from_secs(3)
            )
            .is_err());
        owner = open(&c);
        let client = owner
            .anchor_client(
                &c.policy,
                150,
                pin,
                Box::new(NativeWitness(Arc::clone(&store))),
                Duration::from_secs(3),
            )
            .expect("original client");
        let mut enrolled = owner
            .activate(&c.policy, 150, Some(client))
            .expect("activate original required-witness service");
        assert_eq!(
            enrolled
                .parts()
                .expect("parts")
                .0
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("journal"),
            id
        );
    }
}

#[test]
fn authenticated_enrollment_rejects_wrong_scope_key_and_modified_state_without_reset() {
    let c = case();
    let (mut owner, request, id) = accepted(&c);
    owner.close();
    let root = c.paths.configuration.parent().expect("root");
    let mut wrong = c.intent.clone();
    wrong.description.id = [8; 16];
    assert!(matches!(
        DeviceEnrollment::open(c.paths.clone(), wrong),
        Err(DurableError::Conflict)
    ));
    let shifted = EnrollmentPaths::new(
        &c.paths.wrapping,
        &c.paths.signer,
        &c.paths.configuration,
        InstallationPaths::new(
            &root.join("other-installation.redb"),
            &root.join("journal.redb"),
            &root.join("archives.redb"),
        )
        .expect("other paths"),
    )
    .expect("paths");
    assert!(matches!(
        DeviceEnrollment::open(shifted, c.intent.clone()),
        Err(DurableError::Conflict)
    ));
    assert!(!root.join("other-installation.redb").exists());
    let other = root.join("other-wrap.key");
    drop(JournalKey::provision(&other).expect("unrelated key"));
    let wrong_key = EnrollmentPaths::new(
        &other,
        &c.paths.signer,
        &c.paths.configuration,
        c.paths.installation.clone(),
    )
    .expect("other wrapping path");
    assert!(matches!(
        DeviceEnrollment::open(wrong_key, c.intent.clone()),
        Err(DurableError::Authentication)
    ));
    let db = open_private_database(&c.paths.configuration).expect("original test state");
    let original = {
        let tx = db.begin_read().expect("read");
        let table = tx.open_table(TABLE).expect("table");
        let row = table.get("enrollment").expect("read").expect("row");
        row.value().to_vec()
    };
    let mut corrupt = original.clone();
    *corrupt.last_mut().expect("MAC") ^= 1;
    write(&db, &corrupt).expect("inject persisted MAC corruption");
    drop(db);
    assert!(matches!(
        DeviceEnrollment::open(c.paths.clone(), c.intent.clone()),
        Err(DurableError::Authentication)
    ));
    assert!(DeviceEnrollment::provision(c.paths.clone(), c.intent.clone()).is_err());
    let db = open_private_database(&c.paths.configuration).expect("test repair only");
    write(&db, &original).expect("restore exact original test bytes");
    drop(db);
    let mut recovered = open(&c);
    assert_eq!(
        recovered.status().expect("same accepted state"),
        EnrollmentStatus::Accepted(id)
    );
    assert_eq!(recovered.request(150).expect("same request"), request);
}
