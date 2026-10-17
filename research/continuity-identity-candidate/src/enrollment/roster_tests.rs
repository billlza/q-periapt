// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorClientError, AnchorOperation, AnchorOutcome, AnchorPin, AnchorRequest, AnchorStore,
    AnchorSubject, AnchorTransport, IssuedRoster, Validity,
};
use std::{
    io,
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};

struct Original {
    request: Vec<u8>,
    certificate: Vec<u8>,
    roster: IssuedRoster,
    journal: JournalIdentity,
}
fn roster(c: &Case, certificate: &[u8], version: u64, validity: Validity) -> IssuedRoster {
    c.root
        .issue_roster(
            version,
            validity,
            &[c.root.roster_entry(certificate).expect("member")],
        )
        .expect("signed roster")
}
fn pin(c: &Case, roster: &IssuedRoster) -> AccountPin {
    AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent roster pin")
}
fn prepared(c: &Case) -> (DeviceEnrollment, Original, InstallationPreparation) {
    let mut owner = create(c);
    let request = owner.request(150).expect("original request");
    let proof = VerifiedEnrollmentRequest::verify(&request, &c.intent, 150).expect("request proof");
    let certificate = c
        .root
        .issue_enrollment(&proof, 150)
        .expect("approved credential");
    let roster = roster(
        c,
        &certificate,
        1,
        Validity::new(100, 160).expect("short roster"),
    );
    let journal = owner
        .accept(
            &certificate,
            roster.as_bytes(),
            &pin(c, &roster),
            &c.policy,
            150,
        )
        .expect("accept short current roster");
    let preparation = owner
        .prepare(&c.policy, 150)
        .expect("prepare original children");
    (
        owner,
        Original {
            request,
            certificate,
            roster,
            journal,
        },
        preparation,
    )
}
fn local(c: &Case) -> Original {
    let (owner, original, preparation) = prepared(c);
    assert!(matches!(preparation, InstallationPreparation::Local));
    owner
        .activate(&c.policy, 150, None)
        .expect("initial active enrollment")
        .close();
    original
}
fn next_roster(c: &Case, original: &Original) -> IssuedRoster {
    roster(c, &original.certificate, 2, interval())
}
fn pending(original: &Original, next: &IssuedRoster) -> EnrollmentStatus {
    EnrollmentStatus::Refreshing {
        journal: original.journal,
        previous: original.roster.checkpoint(),
        next: next.checkpoint(),
    }
}
fn begin(c: &Case, original: &Original, next: &IssuedRoster) -> DeviceEnrollment {
    let mut owner = open(c);
    assert_eq!(
        owner
            .refresh_roster(
                original.roster.checkpoint(),
                next.as_bytes(),
                &pin(c, next),
                &c.policy,
                180
            )
            .expect("durable refresh intent"),
        pending(original, next)
    );
    owner
}
fn current(c: &Case) -> RosterCheckpoint {
    let mut owner = open(c);
    let image = owner.image().expect("authenticated configuration");
    match image.phase {
        Phase::Accepted { admission, .. } => Ok(admission.checkpoint),
        _ => Err("expected admitted phase"),
    }
    .expect("authenticated admitted phase")
}

#[test]
fn expired_roster_refresh_preserves_original_request_key_journal_and_real_prekey() {
    let c = case();
    let original = local(&c);
    let key_bytes = fs::read(&c.paths.signer).expect("original signer");
    assert!(matches!(
        open(&c).activate(&c.policy, 180, None),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let next = next_roster(&c, &original);
    let mut owner = begin(&c, &original, &next);
    assert_eq!(
        owner.request(180).expect("original request"),
        original.request
    );
    assert_eq!(
        owner
            .refresh_roster(
                original.roster.checkpoint(),
                next.as_bytes(),
                &pin(&c, &next),
                &c.policy,
                180
            )
            .expect("same pending target"),
        pending(&original, &next)
    );
    owner.close();
    let mut active = open(&c)
        .activate(&c.policy, 180, None)
        .expect("complete original refresh");
    let (service, signer, device) = active.parts().expect("retained owners");
    signer.check_device(device).expect("same signer");
    let journal = service.stores().expect("stores").0;
    assert_eq!(journal.identity().expect("identity"), original.journal);
    assert_eq!(
        journal
            .roster_checkpoint(device.account_id())
            .expect("head"),
        next.checkpoint()
    );
    let request = PrekeyId::from_trusted_state([61; 32]).expect("original operation");
    let leaf = journal
        .generate_prekey(
            &c.policy,
            device,
            request,
            LeafKind::OneTimePq,
            interval(),
            180,
        )
        .expect("actual SDK prekey under renewed roster");
    active.close();
    let mut owner = open(&c);
    assert_eq!(
        owner.status().expect("active"),
        EnrollmentStatus::Active(original.journal)
    );
    assert_eq!(
        owner
            .refresh_roster(
                original.roster.checkpoint(),
                next.as_bytes(),
                &pin(&c, &next),
                &c.policy,
                180
            )
            .expect("observe completed target"),
        EnrollmentStatus::Active(original.journal)
    );
    let mut active = owner
        .activate(&c.policy, 180, None)
        .expect("original active restart");
    let (service, _, device) = active.parts().expect("owners");
    let same = service
        .stores()
        .expect("stores")
        .0
        .generate_prekey(
            &c.policy,
            device,
            request,
            LeafKind::OneTimePq,
            interval(),
            180,
        )
        .expect("same original operation");
    assert_eq!(same.public_key(), leaf.public_key());
    assert_eq!(fs::read(&c.paths.signer).expect("signer bytes"), key_bytes);
}

#[test]
fn refresh_refuses_new_lineage_expired_intent_replacement_and_pending_target_substitution() {
    let c = case();
    let original = local(&c);
    let next = next_roster(&c, &original);
    let mut owner = begin(&c, &original, &next);
    let later = roster(&c, &original.certificate, 3, interval());
    assert!(matches!(
        owner.refresh_roster(
            original.roster.checkpoint(),
            later.as_bytes(),
            &pin(&c, &later),
            &c.policy,
            180
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(current(&c), next.checkpoint());
    let mut owner = open(&c);
    assert_eq!(
        owner.status().expect("retained pending target"),
        pending(&original, &next)
    );
    assert!(owner
        .refresh_roster(
            original.roster.checkpoint(),
            next.as_bytes(),
            &pin(&c, &next),
            &c.policy,
            200
        )
        .is_err());
    assert_eq!(current(&c), next.checkpoint());
    let c = case();
    let mut owner = create(&c);
    let wire = owner.request(150).expect("request");
    let (certificate, first, account) = response(&c, &wire);
    owner
        .accept(&certificate, first.as_bytes(), &account, &c.policy, 150)
        .expect("accepted, not active");
    let update = roster(&c, &certificate, 2, interval());
    assert!(matches!(
        owner.refresh_roster(
            first.checkpoint(),
            update.as_bytes(),
            &pin(&c, &update),
            &c.policy,
            150
        ),
        Err(DurableError::Protocol(Error::State))
    ));
    assert!(!c
        .paths
        .installation
        .files()
        .iter()
        .any(|path| path.exists()));
}

#[test]
fn a_newer_journal_revocation_cannot_be_replaced_by_a_pending_registration_refresh() {
    let c = case();
    let original = local(&c);
    let next = next_roster(&c, &original);
    begin(&c, &original, &next).close();
    let old = pin(&c, &original.roster)
        .verify_device(&original.certificate, original.roster.as_bytes(), 150)
        .expect("historical test device");
    let revoked = c
        .root
        .issue_roster(3, interval(), &[])
        .expect("independent revocation");
    let revocation = pin(&c, &revoked)
        .verify_roster(revoked.as_bytes(), 150)
        .expect("current revocation");
    let mut journal = crate::DeviceJournal::open(
        c.paths
            .installation
            .files()
            .get(1)
            .copied()
            .expect("journal path"),
        JournalKey::open(&c.paths.wrapping).expect("key"),
        &old,
        original.journal,
    )
    .expect("separate lower-level owner");
    journal
        .install_roster(&revocation, 150)
        .expect("commit concurrent revocation");
    journal.close();
    assert!(matches!(
        open(&c).activate(&c.policy, 180, None),
        Err(DurableError::Conflict)
    ));
    let mut owner = open(&c);
    assert_eq!(
        owner.status().expect("original pending identity"),
        pending(&original, &next)
    );
    assert!(owner
        .refresh_roster(
            revoked.checkpoint(),
            next.as_bytes(),
            &pin(&c, &next),
            &c.policy,
            180
        )
        .is_err());
    let mut journal = crate::DeviceJournal::open(
        c.paths
            .installation
            .files()
            .get(1)
            .copied()
            .expect("journal path"),
        JournalKey::open(&c.paths.wrapping).expect("key"),
        &old,
        original.journal,
    )
    .expect("original journal");
    assert_eq!(
        journal
            .roster_checkpoint(old.account_id())
            .expect("revocation retained"),
        revoked.checkpoint()
    );
    let reintroduced = roster(&c, &original.certificate, 4, interval());
    assert!(matches!(
        journal.install_roster(
            &pin(&c, &reintroduced)
                .verify_roster(reintroduced.as_bytes(), 180)
                .expect("signed but not automatically admissible"),
            180
        ),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
}

#[test]
fn each_refresh_intent_and_completion_sync_fault_recovers_exact_target_without_new_identity() {
    for completing in [false, true] {
        let c = case();
        let original = local(&c);
        let next = next_roster(&c, &original);
        if completing {
            begin(&c, &original, &next).close();
        }
        let (mut owner, _, count) = faulty(&c, false);
        count.store(0, Ordering::SeqCst);
        let syncs = if completing {
            let mut active = owner
                .activate(&c.policy, 180, None)
                .expect("calibrate completion");
            let observed = count.load(Ordering::SeqCst);
            active.close();
            observed
        } else {
            owner
                .refresh_roster(
                    original.roster.checkpoint(),
                    next.as_bytes(),
                    &pin(&c, &next),
                    &c.policy,
                    180,
                )
                .expect("calibrate intent");
            let observed = count.load(Ordering::SeqCst);
            owner.close();
            observed
        };
        // Dropping an already returned owner may sync redb's clean marker. It is
        // a separate boundary and cannot be injected as if it preceded return.
        eprintln!("ENROLLMENT_ROSTER_CALIBRATION completing={completing} operation_syncs={syncs} later_close_syncs={}", count.load(Ordering::SeqCst)-syncs);
        assert!(syncs > 0);
        for after in [false, true] {
            for cut in 1..=syncs {
                let c = case();
                let original = local(&c);
                let next = next_roster(&c, &original);
                if completing {
                    begin(&c, &original, &next).close();
                }
                let (mut owner, remaining, count) = faulty(&c, after);
                count.store(0, Ordering::SeqCst);
                remaining.store(cut, Ordering::SeqCst);
                if completing {
                    assert_sync_failure(owner.activate(&c.policy, 180, None).map(|_| ()), after);
                } else {
                    assert_sync_failure(
                        owner.refresh_roster(
                            original.roster.checkpoint(),
                            next.as_bytes(),
                            &pin(&c, &next),
                            &c.policy,
                            180,
                        ),
                        after,
                    );
                    assert!(owner.active.is_none());
                }
                let mut owner = open(&c);
                let phase = owner.status().expect("observed original phase");
                assert!(
                    matches!(phase, EnrollmentStatus::Active(id) | EnrollmentStatus::Refreshing {journal:id,..} if id==original.journal)
                );
                assert_eq!(
                    owner.request(180).expect("original request"),
                    original.request
                );
                owner
                    .refresh_roster(
                        original.roster.checkpoint(),
                        next.as_bytes(),
                        &pin(&c, &next),
                        &c.policy,
                        180,
                    )
                    .expect("reconcile original intent");
                let mut active = owner
                    .activate(&c.policy, 180, None)
                    .expect("complete original update");
                let (service, _, device) = active.parts().expect("owners");
                assert_eq!(
                    service
                        .stores()
                        .expect("stores")
                        .0
                        .roster_checkpoint(device.account_id())
                        .expect("durable target"),
                    next.checkpoint()
                );
            }
        }
        eprintln!(
            "ENROLLMENT_ROSTER_SYNC completing={completing} syncs={syncs} injected_cases={}",
            syncs * 2
        );
    }
}

#[derive(Clone)]
struct WitnessTransport {
    store: Arc<std::sync::Mutex<AnchorStore>>,
    clock: Arc<AtomicU64>,
}
impl AnchorTransport for WitnessTransport {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.store
            .lock()
            .map_err(|_| io::Error::other("witness poisoned"))?
            .handle(request, self.clock.load(Ordering::SeqCst))
            .map_err(io::Error::other)
    }
}
struct Witness {
    _directory: tempfile::TempDir,
    pin: AnchorPin,
    transport: WitnessTransport,
}
fn witness() -> Witness {
    let directory = directory();
    let path = directory.path().canonicalize().expect("private witness");
    let store = AnchorStore::provision(
        &path.join("witness.redb"),
        JournalKey::provision(&path.join("witness.key")).expect("key"),
        crate::AnchorSigningKey::generate().expect("signer"),
        crate::AnchorIdentity::generate().expect("identity"),
    )
    .expect("witness");
    let pin = store.pin().expect("pin");
    Witness {
        _directory: directory,
        pin,
        transport: WitnessTransport {
            store: Arc::new(std::sync::Mutex::new(store)),
            clock: Arc::new(AtomicU64::new(150)),
        },
    }
}
fn client(c: &Case, owner: &mut DeviceEnrollment, w: &Witness, at: u64) -> AnchorClient {
    owner
        .anchor_client(
            &c.policy,
            at,
            w.pin.clone(),
            Box::new(w.transport.clone()),
            Duration::from_secs(3),
        )
        .expect("original controlled witness client")
}
fn observe(c: &Case, w: &Witness, subject: AnchorSubject) -> (crate::AnchorHead, Option<[u8; 32]>) {
    let mut owner = open(c);
    let id = owner.identity().expect("identity");
    let signer = owner.signer(id, false).expect("controlled signer");
    let request =
        AnchorRequest::new(&w.pin, subject, AnchorOperation::query(), &signer).expect("query");
    let wire = w
        .transport
        .store
        .lock()
        .expect("store")
        .handle(request.as_bytes(), w.transport.clock.load(Ordering::SeqCst))
        .expect("historical query");
    let reply = w
        .pin
        .verify_reply(&request, &wire)
        .expect("signed observation");
    assert_eq!(reply.outcome(), AnchorOutcome::Current);
    (reply.observed_head(), reply.last_command_id())
}

#[test]
fn an_already_current_journal_does_not_substitute_for_current_witness_authority() {
    for at in [155, 180] {
        let w = witness();
        let c = case_with_anchor(crate::AnchorRequirement::required(&w.pin));
        let (mut owner, original, preparation) = prepared(&c);
        let genesis = match preparation {
            InstallationPreparation::RequiresEnrollment(genesis) => Ok(genesis),
            InstallationPreparation::Local => Err("required witness became local"),
        }
        .expect("required witness preparation");
        let subject = genesis.subject();
        let old = pin(&c, &original.roster)
            .verify_device(&original.certificate, original.roster.as_bytes(), 150)
            .expect("original admitted device");
        w.transport
            .store
            .lock()
            .expect("store")
            .enroll(&genesis, &old, &c.policy, 150)
            .expect("independent witness enrollment");
        let anchor = client(&c, &mut owner, &w, 150);
        let mut active = owner
            .activate(&c.policy, 150, Some(anchor))
            .expect("initial witnessed owner");
        let next = next_roster(&c, &original);
        let device = pin(&c, &next)
            .verify_device(&original.certificate, next.as_bytes(), at)
            .expect("new current authority");
        active
            .parts()
            .expect("parts")
            .0
            .stores()
            .expect("stores")
            .0
            .install_roster(device.roster(), 150)
            .expect("journal target while old witness still valid");
        active.close();
        w.transport.clock.store(at, Ordering::SeqCst);
        let before = observe(&c, &w, subject);
        let mut owner = open(&c);
        owner
            .refresh_roster(
                original.roster.checkpoint(),
                next.as_bytes(),
                &pin(&c, &next),
                &c.policy,
                at,
            )
            .expect("local intent only");
        let anchor = client(&c, &mut owner, &w, at);
        assert!(
            matches!(owner.activate(&c.policy, at, Some(anchor)), Err(DurableError::Anchor(error)) if matches!(*error, AnchorClientError::AuthorityDenied))
        );
        assert_eq!(
            observe(&c, &w, subject),
            before,
            "denial must not mutate journal or witness head"
        );
        assert_eq!(
            open(&c)
                .status()
                .expect("local durable phase is not a witness grant"),
            EnrollmentStatus::Active(original.journal)
        );
        w.transport
            .store
            .lock()
            .expect("store")
            .update_roster_authority(
                subject,
                original.roster.checkpoint(),
                &device,
                &c.policy,
                at,
            )
            .expect("explicit independent witness authority update");
        let mut owner = open(&c);
        let anchor = client(&c, &mut owner, &w, at);
        owner
            .activate(&c.policy, at, Some(anchor))
            .expect("same target after signed current authority confirmation")
            .close();
        assert_eq!(
            observe(&c, &w, subject),
            before,
            "same target must not advance twice"
        );
    }
}

pub(super) fn journal_boundary() {
    if std::env::var("QPERIAPT_ENROLLMENT_ROSTER_CUT").as_deref() != Ok("journal") {
        return;
    }
    let root = std::path::PathBuf::from(
        std::env::var_os("QPERIAPT_ENROLLMENT_CUT_ROOT").expect("cut root"),
    );
    use std::io::Write;
    let mut file = fs::File::create_new(root.join("journal-committed.pending")).expect("marker");
    file.write_all(b"journal").expect("marker write");
    file.sync_all().expect("marker sync");
    fs::rename(
        root.join("journal-committed.pending"),
        root.join("journal-committed"),
    )
    .expect("publish marker");
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        assert!(
            Instant::now() < deadline,
            "parent did not interrupt committed journal update"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn roster_refresh_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = std::env::var_os("QPERIAPT_ENROLLMENT_ROSTER_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let (_, issued, authority, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let policy = authority
        .verify(issued.as_bytes(), runtime, 180)
        .expect("live policy");
    let public = PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root"))
        .expect("public root");
    let intent = EnrollmentIntent::new(
        public.clone(),
        DeviceDescription::new([7; 16], 1, policy.family(), interval()).expect("intent"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    let cut = std::env::var("QPERIAPT_ENROLLMENT_ROSTER_CUT").expect("cut");
    if cut == "intent" {
        let previous = RosterCheckpoint::from_trusted_state(
            1,
            fs::read(root.join("trusted-previous"))
                .expect("previous")
                .try_into()
                .expect("width"),
        )
        .expect("previous checkpoint");
        let next = RosterCheckpoint::from_trusted_state(
            2,
            fs::read(root.join("trusted-next"))
                .expect("next")
                .try_into()
                .expect("width"),
        )
        .expect("next checkpoint");
        let pin = AccountPin::new(
            crate::identity::account_id(&public),
            public,
            next,
            policy.family(),
        )
        .expect("independent target pin");
        owner
            .refresh_roster(
                previous,
                &fs::read(root.join("next-roster")).expect("target roster"),
                &pin,
                &policy,
                180,
            )
            .expect("interrupted durable intent");
    } else {
        owner
            .activate(&policy, 180, None)
            .expect("interrupted completion");
    }
    Err("expected process cut was not reached".into())
}

#[test]
fn process_cuts_between_registration_and_journal_commits_resume_the_same_roster_update() {
    use crate::durable::tests::ChildGuard;
    use std::process::{Command, Stdio};
    for cut in ["intent", "journal", "active"] {
        let c = case();
        let original = local(&c);
        let next = next_roster(&c, &original);
        if cut != "intent" {
            begin(&c, &original, &next).close();
        }
        let root = c.paths.configuration.parent().expect("private root");
        for (name, bytes) in [
            ("trusted-root", c.intent.root.encode()),
            (
                "trusted-previous",
                original.roster.checkpoint().digest().to_vec(),
            ),
            ("trusted-next", next.checkpoint().digest().to_vec()),
            ("next-roster", next.as_bytes().to_vec()),
        ] {
            fs::write(root.join(name), bytes).expect("trusted public input");
        }
        let log = fs::File::create_new(root.join("roster-child.log")).expect("child log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "enrollment::tests::roster::roster_refresh_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_ENROLLMENT_ROSTER_ROOT", root)
                .env("QPERIAPT_ENROLLMENT_ROSTER_CUT", cut)
                .env("QPERIAPT_ENROLLMENT_CUT_ROOT", root)
                .env(
                    "QPERIAPT_ENROLLMENT_CUT_PHASE",
                    if cut == "intent" {
                        "5"
                    } else if cut == "active" {
                        "4"
                    } else {
                        "9"
                    },
                )
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("child"),
        );
        let marker = root.join(if cut == "journal" {
            "journal-committed"
        } else {
            "committed"
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "missing {cut} boundary: {}",
                fs::read_to_string(root.join("roster-child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        child.0.kill().expect("interrupt after actual commit");
        assert!(!child.0.wait().expect("reap").success());
        let mut owner = open(&c);
        assert_eq!(
            owner.status().expect("original durable phase"),
            if cut == "active" {
                EnrollmentStatus::Active(original.journal)
            } else {
                pending(&original, &next)
            }
        );
        assert_eq!(
            owner.request(180).expect("original request"),
            original.request
        );
        let mut active = owner
            .activate(&c.policy, 180, None)
            .expect("resume original update");
        let (service, _, device) = active.parts().expect("owners");
        let journal = service.stores().expect("stores").0;
        assert_eq!(journal.identity().expect("journal"), original.journal);
        assert_eq!(
            journal
                .roster_checkpoint(device.account_id())
                .expect("current target"),
            next.checkpoint()
        );
        eprintln!("ENROLLMENT_ROSTER_PROCESS_CUT cut={cut} original_journal=true exact_request=true target_reconciled=true");
    }
}

struct CutTransport {
    inner: WitnessTransport,
    opcode: u8,
    after_reply: bool,
    armed: Arc<std::sync::atomic::AtomicBool>,
    command: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
}
impl AnchorTransport for CutTransport {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        // Fixed public request framing: envelope length, tag, witness, subject,
        // command ID, challenge, then operation. No native private fields used.
        let cut = request.get(4 + 8 + 32 + 96 + 32 + 32) == Some(&self.opcode)
            && self.armed.swap(false, Ordering::SeqCst);
        if cut {
            *self
                .command
                .lock()
                .map_err(|_| io::Error::other("capture poisoned"))? = Some(
                request
                    .get(4 + 8 + 32 + 96..4 + 8 + 32 + 96 + 32)
                    .ok_or(io::ErrorKind::InvalidData)?
                    .try_into()
                    .map_err(|_| io::ErrorKind::InvalidData)?,
            );
            if !self.after_reply {
                return Err(io::ErrorKind::ConnectionReset.into());
            }
        }
        let reply = self.inner.exchange(request, deadline)?;
        if cut {
            Err(io::ErrorKind::UnexpectedEof.into())
        } else {
            Ok(reply)
        }
    }
}
fn witnessed(w: &Witness, c: &Case) -> (DeviceEnrollment, Original, AnchorSubject) {
    let (owner, original, preparation) = prepared(c);
    let genesis = match preparation {
        InstallationPreparation::RequiresEnrollment(genesis) => Ok(genesis),
        InstallationPreparation::Local => Err("required witness became local"),
    }
    .expect("witness genesis");
    let device = pin(c, &original.roster)
        .verify_device(&original.certificate, original.roster.as_bytes(), 150)
        .expect("independent original authority");
    let subject = genesis.subject();
    w.transport
        .store
        .lock()
        .expect("store")
        .enroll(&genesis, &device, &c.policy, 150)
        .expect("operator enrollment");
    (owner, original, subject)
}

#[test]
fn a_lost_signed_authority_confirmation_reopens_active_without_advancing_twice() {
    let w = witness();
    let c = case_with_anchor(crate::AnchorRequirement::required(&w.pin));
    let (mut owner, original, subject) = witnessed(&w, &c);
    let anchor = client(&c, &mut owner, &w, 150);
    owner
        .activate(&c.policy, 150, Some(anchor))
        .expect("initial owner")
        .close();
    let next = next_roster(&c, &original);
    let device = pin(&c, &next)
        .verify_device(&original.certificate, next.as_bytes(), 180)
        .expect("fresh device");
    w.transport.clock.store(180, Ordering::SeqCst);
    w.transport
        .store
        .lock()
        .expect("store")
        .update_roster_authority(
            subject,
            original.roster.checkpoint(),
            &device,
            &c.policy,
            180,
        )
        .expect("operator refresh");
    let mut owner = begin(&c, &original, &next);
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let command = Arc::new(std::sync::Mutex::new(None));
    let anchor = owner
        .anchor_client(
            &c.policy,
            180,
            w.pin.clone(),
            Box::new(CutTransport {
                inner: w.transport.clone(),
                opcode: 4,
                after_reply: true,
                armed: Arc::clone(&armed),
                command: Arc::clone(&command),
            }),
            Duration::from_secs(3),
        )
        .expect("bound client");
    assert!(
        matches!(owner.activate(&c.policy,180,Some(anchor)),Err(DurableError::Anchor(error)) if matches!(*error,AnchorClientError::Transport(ref error) if error.kind()==io::ErrorKind::UnexpectedEof))
    );
    assert!(!armed.load(Ordering::SeqCst));
    assert!(command.lock().expect("capture").is_some());
    assert_eq!(
        open(&c).status().expect("durable local phase"),
        EnrollmentStatus::Active(original.journal)
    );
    let before = observe(&c, &w, subject);
    let mut owner = open(&c);
    let anchor = client(&c, &mut owner, &w, 180);
    owner
        .activate(&c.policy, 180, Some(anchor))
        .expect("fresh signed confirmation after unknown response")
        .close();
    assert_eq!(
        observe(&c, &w, subject),
        before,
        "admission retries cannot mutate head or last applied command"
    );
}

#[test]
fn original_pending_revocation_is_reconciled_before_refresh_cas_and_cannot_resurrect_a_device() {
    let w = witness();
    let c = case_with_anchor(crate::AnchorRequirement::required(&w.pin));
    let (mut owner, original, subject) = witnessed(&w, &c);
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let command = Arc::new(std::sync::Mutex::new(None));
    let anchor = owner
        .anchor_client(
            &c.policy,
            150,
            w.pin.clone(),
            Box::new(CutTransport {
                inner: w.transport.clone(),
                opcode: 2,
                after_reply: false,
                armed: Arc::clone(&armed),
                command: Arc::clone(&command),
            }),
            Duration::from_secs(3),
        )
        .expect("cut client");
    let mut active = owner
        .activate(&c.policy, 150, Some(anchor))
        .expect("original owner");
    let revoked = c
        .root
        .issue_roster(2, interval(), &[])
        .expect("current revocation");
    let revoked_roster = pin(&c, &revoked)
        .verify_roster(revoked.as_bytes(), 150)
        .expect("signed revocation");
    assert!(
        matches!(active.parts().expect("parts").0.stores().expect("stores").0.install_roster(&revoked_roster,150),Err(DurableError::Anchor(error)) if matches!(*error,AnchorClientError::Transport(_)))
    );
    active.close();
    let original_command = command
        .lock()
        .expect("capture")
        .expect("pending original command");
    let before = observe(&c, &w, subject);
    let later = roster(&c, &original.certificate, 3, interval());
    let device = pin(&c, &later)
        .verify_device(&original.certificate, later.as_bytes(), 180)
        .expect("signed proposal is not a history bypass");
    let mut owner = open(&c);
    owner
        .refresh_roster(
            original.roster.checkpoint(),
            later.as_bytes(),
            &pin(&c, &later),
            &c.policy,
            180,
        )
        .expect("retained proposal only");
    owner.close();
    w.transport.clock.store(180, Ordering::SeqCst);
    w.transport
        .store
        .lock()
        .expect("store")
        .update_roster_authority(
            subject,
            original.roster.checkpoint(),
            &device,
            &c.policy,
            180,
        )
        .expect("independent witness authority; journal history remains authoritative");
    let mut owner = open(&c);
    let anchor = client(&c, &mut owner, &w, 180);
    assert!(matches!(
        owner.activate(&c.policy, 180, Some(anchor)),
        Err(DurableError::Conflict)
    ));
    let after = observe(&c, &w, subject);
    assert_eq!(after.0.fence(), before.0.fence());
    assert_eq!(after.0.revision(), before.0.revision() + 1);
    assert_eq!(
        after.1,
        Some(original_command),
        "recover the pending revocation, never reconstruct a different update"
    );
    let mut owner = open(&c);
    assert_eq!(
        owner
            .status()
            .expect("unchanged pending registration target"),
        EnrollmentStatus::Refreshing {
            journal: original.journal,
            previous: original.roster.checkpoint(),
            next: later.checkpoint()
        }
    );
    let anchor = client(&c, &mut owner, &w, 180);
    owner.close();
    let mut journal = crate::DeviceJournal::open_anchored(
        c.paths
            .installation
            .files()
            .get(1)
            .copied()
            .expect("journal path"),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        &device,
        &c.policy,
        original.journal,
        anchor,
    )
    .expect("read original recovered journal");
    assert_eq!(
        journal
            .roster_checkpoint(device.account_id())
            .expect("retained revocation"),
        revoked.checkpoint()
    );
    assert!(matches!(
        journal.install_roster(device.roster(), 180),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
}
