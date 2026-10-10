// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorAccountReplacementId, AnchorGenesis, AnchorIdentity, AnchorRequirement, AnchorSigningKey,
    AnchorStore, PrekeyQuality, Validity,
};
use std::os::unix::fs::DirBuilderExt;
use std::{
    fs, io,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Instant,
};

#[path = "process.rs"]
mod process;

pub(super) fn at_boundary(stage: &str, after: bool) {
    let Some(path) = std::env::var_os("QPERIAPT_ROOT_PARENT_DIR") else {
        return;
    };
    let Ok(cut) = std::env::var("QPERIAPT_ROOT_PARENT_CUT") else {
        return;
    };
    if cut != format!("{stage}-{}", if after { "after" } else { "before" }) {
        return;
    }
    fs::write(Path::new(&path).join("ready"), cut).expect("owned child boundary");
    loop {
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct Carrier(Arc<Mutex<AnchorStore>>);
impl AnchorTransport for Carrier {
    fn exchange(&mut self, bytes: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0
            .lock()
            .expect("witness")
            .handle(bytes, 150)
            .map_err(io::Error::other)
    }
}
struct Account {
    root: RootSigningKey,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    device: VerifiedDevice,
    genesis: AnchorGenesis,
}
struct Fixture {
    _dir: tempfile::TempDir,
    witness: Arc<Mutex<AnchorStore>>,
    pin: AnchorPin,
    policy: VerifiedSessionPolicy,
    original: Account,
    target: Account,
}
fn paths(path: &Path) -> EnrollmentPaths {
    EnrollmentPaths::new(
        &path.join("key"),
        &path.join("signer"),
        &path.join("enrollment"),
        InstallationPaths::new(
            &path.join("installation"),
            &path.join("journal"),
            &path.join("archives"),
        )
        .expect("installation paths"),
    )
    .expect("enrollment paths")
}
fn account(path: &Path, policy: &VerifiedSessionPolicy) -> Account {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .expect("private account");
    let paths = paths(path);
    JournalKey::provision(&paths.wrapping).expect("key");
    let root = RootSigningKey::generate().expect("root");
    let intent = EnrollmentIntent::new(
        root.public_key().expect("public root"),
        DeviceDescription::new(
            [7; 16],
            1,
            policy.family(),
            Validity::new(100, 200).expect("validity"),
        )
        .expect("intent"),
    );
    let mut owner =
        DeviceEnrollment::provision(paths.clone(), intent.clone()).expect("original enrollment");
    let wire = owner.request(150).expect("original request");
    let request = VerifiedEnrollmentRequest::verify(&wire, &intent, 150).expect("proof");
    let cert = root.issue_enrollment(&request, 150).expect("grant");
    let roster = root
        .issue_roster(
            1,
            Validity::new(100, 200).expect("validity"),
            &[root.roster_entry(&cert).expect("member")],
        )
        .expect("roster");
    let pin = AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root"),
        roster.checkpoint(),
        policy.family(),
    )
    .expect("pin");
    let device = pin
        .verify_device(&cert, roster.as_bytes(), 150)
        .expect("device");
    owner
        .accept(&cert, roster.as_bytes(), &pin, policy, 150)
        .expect("accept");
    let genesis = match owner.prepare(policy, 150).expect("prepare target") {
        InstallationPreparation::RequiresEnrollment(g) => Ok(g),
        _ => Err("local-only preparation"),
    }
    .expect("required witness");
    owner.close();
    Account {
        root,
        paths,
        intent,
        device,
        genesis,
    }
}
fn fixture() -> Fixture {
    let dir = crate::durable::tests::directory();
    let path = dir.path().canonicalize().expect("canonical parent");
    let mut store = AnchorStore::provision(
        &path.join("witness"),
        JournalKey::provision(&path.join("witness-key")).expect("key"),
        AnchorSigningKey::generate().expect("signer"),
        AnchorIdentity::generate().expect("identity"),
    )
    .expect("witness");
    let pin = store.pin().expect("pin");
    let (_, issued, policy_pin, runtime) = crate::tests::session_policy_fixture_with_anchor(
        &[PrekeyQuality::OneTimeBoth],
        AnchorRequirement::required(&pin),
    );
    let policy = policy_pin
        .verify(issued.as_bytes(), runtime, 150)
        .expect("policy");
    let original = account(&path.join("original"), &policy);
    let target = account(&path.join("target"), &policy);
    store
        .enroll(&original.genesis, &original.device, &policy, 150)
        .expect("old witness admission");
    let f = Fixture {
        _dir: dir,
        witness: Arc::new(Mutex::new(store)),
        pin,
        policy,
        original,
        target,
    };
    f.activate().close();
    f
}
impl Fixture {
    fn activate(&self) -> EnrolledDevice {
        self.activate_account(&self.original)
            .expect("original service")
    }
    fn activate_account(&self, account: &Account) -> Result<EnrolledDevice, DurableError> {
        let mut owner = DeviceEnrollment::open(account.paths.clone(), account.intent.clone())?;
        let anchor = owner.anchor_client(
            &self.policy,
            150,
            self.pin.clone(),
            Box::new(Carrier(Arc::clone(&self.witness))),
            Duration::from_secs(3),
        )?;
        owner.activate(&self.policy, 150, Some(anchor))
    }
    fn proposal(&self, id: u8) -> Proposal {
        self.witness
            .lock()
            .expect("witness")
            .account_root_replacement_proposal(
                AnchorAccountReplacementId::from_trusted_state([id; 32]).expect("id"),
                &self.original.root.public_key().expect("root"),
                &self.target.genesis,
                &self.target.device,
                &self.policy,
                150,
            )
            .expect("independently approved proposal")
    }
    fn receipt(&self, p: &Proposal) -> Vec<u8> {
        let mut store = self.witness.lock().expect("witness");
        store
            .replace_account_root(
                p,
                &self.original.root.public_key().expect("root"),
                &self.target.genesis,
                &self.target.device,
                &self.policy,
                150,
            )
            .expect("actual witness commit");
        store.retired_account_receipt(p).expect("purpose 22")
    }
    fn resume(&self, p: &Proposal) -> AccountRootEnrollmentRecovery {
        AccountRootEnrollmentRecovery::resume_original(
            self.original.paths.clone(),
            self.original.intent.clone(),
            self.pin.clone(),
            p.clone(),
        )
        .expect("original recovery")
    }
    fn assert_fenced(&self) {
        assert!(matches!(
            DeviceEnrollment::open(self.original.paths.clone(), self.original.intent.clone()),
            Err(DurableError::Suspended)
        ));
    }
}
fn parent_rows(db: &Database) -> (Vec<u8>, Option<Vec<u8>>) {
    let tx = db.begin_read().expect("parent snapshot");
    let table = tx.open_table(TABLE).expect("table");
    (
        table
            .get("enrollment")
            .expect("read")
            .expect("original")
            .value()
            .to_vec(),
        table.get(ROW).expect("read").map(|r| r.value().to_vec()),
    )
}

#[test]
fn account_root_enrollment_parent_survives_child_backup_restore_and_keeps_first_receipt() {
    let f = fixture();
    let p = f.proposal(221);
    let backup =
        fs::read(f.original.paths.installation.files()[1]).expect("quiescent child backup");
    let mut owner = f.activate();
    let id = owner
        .next_prekey_publication_id()
        .expect("real controlled owner operation");
    assert!(!id.as_bytes().iter().all(|b| *b == 0));
    let parent = parent_rows(
        &owner
            .active
            .as_ref()
            .expect("owner")
            .enrollment
            .active
            .as_ref()
            .expect("enrollment")
            .database,
    )
    .0;
    let mut recovery = owner
        .begin_account_root_replacement(f.pin.clone(), p.clone())
        .expect("parent then child fence");
    assert_eq!(
        recovery.status().expect("state"),
        AccountRootEnrollmentState::IntentRetained
    );
    assert_eq!(
        parent_rows(
            &recovery
                .active
                .as_ref()
                .expect("recovery")
                .enrollment
                .active
                .as_ref()
                .expect("parent")
                .database
        )
        .0,
        parent
    );
    recovery.close();
    f.assert_fenced();
    fs::write(f.original.paths.installation.files()[1], &backup).expect("restore only child");
    f.assert_fenced();
    let mut recovery = f.resume(&p);
    let receipt = f.receipt(&p);
    assert_eq!(
        recovery
            .retain_witness_retirement(&receipt)
            .expect("retain receipt"),
        AccountRootEnrollmentState::WitnessCommitted
    );
    let first = parent_rows(
        &recovery
            .active
            .as_ref()
            .expect("recovery")
            .enrollment
            .active
            .as_ref()
            .expect("parent")
            .database,
    );
    let resigned = f.receipt(&p);
    recovery
        .retain_witness_retirement(&resigned)
        .expect("same statement retry");
    assert_eq!(
        parent_rows(
            &recovery
                .active
                .as_ref()
                .expect("recovery")
                .enrollment
                .active
                .as_ref()
                .expect("parent")
                .database
        ),
        first
    );
    recovery.close();
    fs::write(f.original.paths.installation.files()[1], &backup)
        .expect("restore child again after commit");
    f.assert_fenced();
    let mut recovery = f.resume(&p);
    assert_eq!(
        recovery.status().expect("independent retained receipt"),
        AccountRootEnrollmentState::WitnessCommitted
    );
    assert_eq!(recovery.proposal().expect("exact operation"), p);
    recovery.close();
    f.assert_fenced();
}

#[test]
fn account_root_enrollment_conflicting_intent_and_bad_receipt_do_not_replace_parent() {
    let f = fixture();
    let p = f.proposal(222);
    let competing = f.proposal(223);
    f.activate()
        .begin_account_root_replacement(f.pin.clone(), p.clone())
        .expect("fence")
        .close();
    assert!(matches!(
        AccountRootEnrollmentRecovery::resume_original(
            f.original.paths.clone(),
            f.original.intent.clone(),
            f.pin.clone(),
            competing
        ),
        Err(DurableError::Conflict)
    ));
    let mut recovery = f.resume(&p);
    let mut receipt = f.receipt(&p);
    *receipt.last_mut().expect("signature") ^= 1;
    assert!(matches!(
        recovery.retain_witness_retirement(&receipt),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert!(recovery.active.is_none());
    let mut recovery = f.resume(&p);
    assert_eq!(
        recovery.status().expect("unacknowledged parent"),
        AccountRootEnrollmentState::IntentRetained
    );
    recovery.close();
    f.assert_fenced();
}

fn fault_parent(
    owner: &mut DeviceEnrollment,
    after: bool,
) -> (
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let active = owner.active.take().expect("parent");
    drop(active.database);
    let (database, remaining, count, _) =
        crate::durable::tests::fault_database_path(&owner.paths.configuration, after);
    owner.active = Some(Active {
        database,
        key: active.key,
    });
    (remaining, count)
}
#[test]
fn account_root_enrollment_sync_faults_recover_original_parent_intent() {
    let calibration = fixture();
    let p = calibration.proposal(224);
    let mut owner = calibration.activate();
    let (remaining, count) =
        fault_parent(&mut owner.active.as_mut().expect("owner").enrollment, false);
    remaining.store(usize::MAX, Ordering::SeqCst);
    count.store(0, Ordering::SeqCst);
    let mut recovery = owner
        .begin_account_root_replacement(calibration.pin.clone(), p)
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    recovery.close();
    assert!(barriers > 0);
    for after in [false, true] {
        for boundary in 1..=barriers {
            let f = fixture();
            let p = f.proposal(225);
            let mut owner = f.activate();
            let (remaining, count) =
                fault_parent(&mut owner.active.as_mut().expect("owner").enrollment, after);
            count.store(0, Ordering::SeqCst);
            remaining.store(boundary, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                owner.begin_account_root_replacement(f.pin.clone(), p.clone()),
                after,
            );
            let mut recovery = f.resume(&p);
            assert_eq!(recovery.proposal().expect("original"), p);
            recovery.close();
            f.assert_fenced();
        }
    }
    println!(
        "parent_intent_sync_barriers={barriers}; injected_faults={}",
        barriers * 2
    );
}

#[test]
fn account_root_enrollment_receipt_sync_faults_keep_exact_witness_decision() {
    let calibration = fixture();
    let p = calibration.proposal(226);
    let mut recovery = calibration
        .activate()
        .begin_account_root_replacement(calibration.pin.clone(), p.clone())
        .expect("fence");
    let receipt = calibration.receipt(&p);
    let (remaining, count) = fault_parent(
        &mut recovery.active.as_mut().expect("owner").enrollment,
        false,
    );
    remaining.store(usize::MAX, Ordering::SeqCst);
    count.store(0, Ordering::SeqCst);
    recovery
        .retain_witness_retirement(&receipt)
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    recovery.close();
    assert!(barriers > 0);
    for after in [false, true] {
        for boundary in 1..=barriers {
            let f = fixture();
            let p = f.proposal(227);
            let mut recovery = f
                .activate()
                .begin_account_root_replacement(f.pin.clone(), p.clone())
                .expect("fence");
            let receipt = f.receipt(&p);
            let (remaining, count) = fault_parent(
                &mut recovery.active.as_mut().expect("owner").enrollment,
                after,
            );
            count.store(0, Ordering::SeqCst);
            remaining.store(boundary, Ordering::SeqCst);
            let error = recovery
                .retain_witness_retirement(&receipt)
                .expect_err("fault surfaced");
            crate::durable::tests::assert_sync_failure::<()>(Err(error), after);
            assert!(recovery.active.is_none());
            let mut recovery = f.resume(&p);
            recovery
                .retain_witness_retirement(&receipt)
                .expect("exact retry");
            assert_eq!(
                recovery.status().expect("original commit"),
                AccountRootEnrollmentState::WitnessCommitted
            );
            recovery.close();
            f.assert_fenced();
        }
    }
    println!(
        "parent_receipt_sync_barriers={barriers}; injected_faults={}",
        barriers * 2
    );
}

#[test]
fn account_root_enrollment_authentication_image_and_schema_fail_closed() {
    for kind in ["mac", "image", "schema"] {
        let f = fixture();
        let p = f.proposal(229);
        let mut recovery = f.resume(&p);
        let owners = recovery.active.as_ref().expect("restricted owner");
        let parent = owners.enrollment.active.as_ref().expect("parent");
        let mut state = owners.state.clone();
        if kind == "image" {
            state.image[0] ^= 1;
        }
        let mut wire = state
            .encode(&parent.key, owners.enrollment.binding)
            .expect("fixture row");
        if kind == "mac" {
            *wire.last_mut().expect("MAC") ^= 1;
        }
        let tx = transaction(&parent.database).expect("fixture mutation");
        {
            let mut table = tx.open_table(TABLE).expect("parent table");
            table.insert(ROW, wire.as_slice()).expect("fixture marker");
            if kind == "schema" {
                table
                    .insert("unexpected", b"extra".as_slice())
                    .expect("extra row");
            }
        }
        tx.commit().expect("fixture commit");
        let error = recovery
            .status()
            .expect_err("corruption must refuse metadata");
        match kind {
            "mac" => assert!(matches!(error, DurableError::Authentication)),
            "image" => assert!(matches!(error, DurableError::Conflict)),
            "schema" => assert!(matches!(error, DurableError::Corrupt)),
            _ => unreachable!(),
        }
        assert!(recovery.active.is_none());
        assert!(AccountRootEnrollmentRecovery::resume_original(
            f.original.paths.clone(),
            f.original.intent.clone(),
            f.pin.clone(),
            p
        )
        .is_err());
        assert!(
            DeviceEnrollment::open(f.original.paths.clone(), f.original.intent.clone()).is_err()
        );
    }
}

#[test]
fn account_root_enrollment_missing_child_is_not_recreated_or_replaced() {
    let f = fixture();
    let p = f.proposal(230);
    f.activate()
        .begin_account_root_replacement(f.pin.clone(), p.clone())
        .expect("fence")
        .close();
    let path = f.original.paths.installation.files()[1];
    let held = path.with_extension("held");
    fs::rename(path, &held).expect("hide original quiescent fixture child");
    assert!(AccountRootEnrollmentRecovery::resume_original(
        f.original.paths.clone(),
        f.original.intent.clone(),
        f.pin.clone(),
        p.clone()
    )
    .is_err());
    assert!(!path.exists());
    f.assert_fenced();
    fs::rename(&held, path).expect("restore the exact original child");
    // Historical recovery does not reopen private signing material.
    fs::rename(
        &f.original.paths.signer,
        f.original.paths.signer.with_extension("held"),
    )
    .expect("hide original signer");
    let mut recovery = f.resume(&p);
    assert_eq!(recovery.proposal().expect("retained original operation"), p);
    recovery
        .retain_witness_retirement(&f.receipt(&p))
        .expect("original historical receipt");
    recovery.close();
    f.assert_fenced();
    assert!(!f.original.paths.signer.exists());
}

#[test]
fn account_root_enrollment_target_activation_requires_separate_current_witness_admission() {
    let f = fixture();
    let p = f.proposal(231);
    assert!(matches!(
        f.activate_account(&f.target),
        Err(DurableError::Anchor(_))
    ));
    let mut recovery = f
        .activate()
        .begin_account_root_replacement(f.pin.clone(), p.clone())
        .expect("original fence");
    assert!(matches!(
        f.activate_account(&f.target),
        Err(DurableError::Anchor(_))
    ));
    let receipt = f.receipt(&p);
    recovery
        .retain_witness_retirement(&receipt)
        .expect("original retirement");
    let mut target = f
        .activate_account(&f.target)
        .expect("separate current target admission");
    assert_eq!(
        target.parts().expect("actual target owners").2.account_id(),
        p.successor_account()
    );
    target.close();
    recovery.close();
    f.policy.close();
    let mut recovery = f.resume(&p);
    assert_eq!(
        recovery
            .status()
            .expect("historical parent after runtime close"),
        AccountRootEnrollmentState::WitnessCommitted
    );
    recovery.close();
    f.assert_fenced();
    assert!(f.activate_account(&f.target).is_err());
}
