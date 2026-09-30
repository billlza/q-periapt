// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture_with_anchor_and_budget, Fixture},
    AnchorClient, AnchorIdentity, AnchorPin, AnchorRequirement, AnchorSigningKey, AnchorStore,
    AnchorTransport, ApplicationSendBudget, PublicKey,
};

pub(in crate::durable) fn genesis_boundary(stage: &str, id: &[u8; 32], digest: [u8; 32]) {
    let Some(path) = std::env::var_os("QPERIAPT_GENESIS_CUT_DIR") else {
        return;
    };
    let selected =
        std::env::var("QPERIAPT_GENESIS_CUT_STAGE").unwrap_or_else(|_| "after-commit".into());
    if selected != stage {
        return;
    }
    let path = Path::new(&path);
    let mut observed = fs::File::create_new(path.join("observed-id")).expect("public observation");
    observed.write_all(id).expect("observation");
    observed.sync_all().expect("observation sync");
    let mut image = fs::File::create_new(path.join("observed-digest")).expect("public digest");
    image.write_all(&digest).expect("digest");
    image.sync_all().expect("digest sync");
    let mut ready = fs::File::create_new(path.join("ready.pending")).expect("marker");
    ready.write_all(stage.as_bytes()).expect("marker");
    ready.sync_all().expect("marker sync");
    fs::rename(path.join("ready.pending"), path.join("ready"))
        .expect("publish complete boundary marker");
    loop {
        std::thread::park();
    }
}
pub(super) fn retain_identity(path: &Path, identity: JournalIdentity) {
    let mut file = fs::File::create_new(path).expect("new independent request");
    file.write_all(identity.as_bytes())
        .expect("retained identity");
    file.sync_all().expect("request durability");
    fs::File::open(path.parent().expect("identity directory"))
        .expect("directory")
        .sync_all()
        .expect("request name durability");
}
fn peer(path: &Path) -> Result<(Fixture, Option<AnchorPin>), Box<dyn std::error::Error>> {
    let pin = match fs::read(path.join("witness-pin")) {
        Ok(bytes) => Some(AnchorPin::new(
            AnchorIdentity::from_trusted_state(
                bytes.get(..32).ok_or("witness ID width")?.try_into()?,
            )?,
            PublicKey::decode(bytes.get(32..).ok_or("witness key width")?)?,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let f = fixture_with_anchor_and_budget(
        PrekeyQuality::OneTimeBoth,
        pin.as_ref()
            .map_or_else(AnchorRequirement::local_only, AnchorRequirement::required),
        ApplicationSendBudget::new(1024).expect("budget"),
    );
    Ok((f, pin))
}

#[test]
fn journal_genesis_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_GENESIS_CUT_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let (f, pin) = peer(path)?;
    let key = JournalKey::open(&path.join("key"))?;
    let journal = if pin.is_some() {
        DeviceJournal::provision_anchored(
            &path.join("state.redb"),
            key,
            f.local_device(),
            f.responder.policy(),
            identity(path),
            150,
        )?
    } else {
        DeviceJournal::provision(
            &path.join("state.redb"),
            key,
            f.local_device(),
            identity(path),
        )?
    };
    fs::write(path.join("returned-id"), journal.identity()?.as_bytes())?;
    Err("expected observed pre-return process cut".into())
}
#[test]
fn journal_genesis_busy_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_GENESIS_BUSY_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let (f, _) = peer(path)?;
    assert!(matches!(
        DeviceJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key"))?,
            f.local_device(),
            identity(path),
        ),
        Err(DurableError::Database(PrivateDatabaseError::Busy))
    ));
    Ok(())
}
fn cut_creation(path: &Path, stage: &str) {
    let log = fs::File::create_new(path.join("genesis-child.log")).expect("new log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::tests::provisioning::journal_genesis_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_GENESIS_CUT_DIR", path)
            .env("QPERIAPT_GENESIS_CUT_STAGE", stage)
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "genesis boundary not observed: {}",
            fs::read_to_string(path.join("genesis-child.log")).expect("log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(path.join("ready")).expect("stage"),
        stage
    );
    assert!(!path.join("returned-id").exists());
    for attempt in 0..3 {
        let name = path.join(format!("busy-{attempt}.log"));
        let log = fs::File::create_new(&name).expect("contender log");
        let mut contender = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::tests::provisioning::journal_genesis_busy_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_GENESIS_BUSY_DIR", path)
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("contender"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = contender.0.try_wait().expect("status") {
                assert!(
                    status.success(),
                    "{}",
                    fs::read_to_string(&name).expect("log")
                );
                break;
            }
            assert!(Instant::now() < deadline, "genesis lease contender blocked");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    child.0.kill().expect("kill at observed genesis boundary");
    assert!(!child.0.wait().expect("reap").success());
    assert_eq!(
        fs::read(path.join("observed-id")).expect("public identity"),
        identity(path).as_bytes(),
        "committed identity must equal the independently retained request before owner return"
    );
}
fn prepare(path: &Path) -> JournalIdentity {
    let expected =
        JournalIdentity::from_trusted_state([71; 32]).expect("independent creation request");
    retain_identity(&path.join("store-id"), expected);
    drop(JournalKey::provision(&path.join("key")).expect("wrapping key"));
    expected
}
fn assert_genesis(journal: &mut DeviceJournal, path: &Path, expected: JournalIdentity) {
    assert_eq!(journal.identity().expect("identity"), expected);
    let image = journal.image().expect("authenticated genesis");
    assert_eq!(image.revision, 1);
    assert_eq!(image.operation_count(), 0);
    assert_eq!(
        image.digest.as_slice(),
        fs::read(path.join("observed-digest")).expect("exact encrypted image")
    );
}

#[test]
fn journal_unknown_creation_reopens_using_the_identity_retained_before_the_call() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let expected = prepare(&path);
    cut_creation(&path, "after-commit");
    assert!(matches!(
        DeviceJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            f.local_device(),
            JournalIdentity::from_trusted_state([72; 32]).expect("other ID")
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        DeviceJournal::open(
            &path.join("state.redb"),
            JournalKey::provision(&path.join("other-key")).expect("other key"),
            f.local_device(),
            expected
        ),
        Err(DurableError::Authentication)
    ));
    assert!(matches!(
        DeviceJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            f.initiator_device(),
            expected
        ),
        Err(DurableError::Conflict)
    ));
    let mut reopened = reopen(&path, f.local_device());
    assert_genesis(&mut reopened, &path, expected);
    reopened.close();
    assert!(DeviceJournal::provision(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("key"),
        f.local_device(),
        expected
    )
    .is_err());
    let mut reopened = reopen(&path, f.local_device());
    assert_genesis(&mut reopened, &path, expected);
    // The recovered owner must support real authenticated work, not just an empty read.
    let mut initiator =
        InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initiator");
    let initial = initiator.initial_message(150).expect("initial").to_vec();
    let (pq, classical) = f.sources();
    let reply = reopened
        .respond(
            Arc::clone(&f.responder),
            &initial,
            &f.signer_r,
            pq,
            classical,
            150,
        )
        .expect("reply");
    let completed = initiator.finish(&reply, 150).expect("confirmation");
    assert_eq!(
        reopened
            .finish(
                Arc::clone(&f.responder),
                &initial,
                completed.final_message(),
                150
            )
            .expect("finish"),
        completed.pending_session().id()
    );
    assert_eq!(
        reopened.status(&f.responder, &initial).expect("status"),
        DurableStatus::Complete
    );
}

#[test]
fn journal_uncommitted_creation_is_not_repaired_or_reprovisioned() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let expected = prepare(&path);
    cut_creation(&path, "before-commit");
    assert!(matches!(
        DeviceJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            f.local_device(),
            expected
        ),
        Err(DurableError::Corrupt)
    ));
    let bytes = fs::read(path.join("state.redb")).expect("existing uncommitted file");
    assert!(DeviceJournal::provision(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("key"),
        f.local_device(),
        expected
    )
    .is_err());
    assert_eq!(
        fs::read(path.join("state.redb")).expect("preserved file"),
        bytes
    );
    assert!(DeviceJournal::open(
        &path.join("missing.redb"),
        JournalKey::open(&path.join("key")).expect("key"),
        f.local_device(),
        expected
    )
    .is_err());
    assert!(!path.join("missing.redb").exists());
}

struct Witness(Arc<std::sync::Mutex<AnchorStore>>);
impl AnchorTransport for Witness {
    fn exchange(&mut self, request: &[u8], _: Instant) -> io::Result<Vec<u8>> {
        self.0
            .lock()
            .expect("witness")
            .handle(request, 150)
            .map_err(io::Error::other)
    }
}
#[test]
fn journal_unknown_anchored_creation_preserves_exact_genesis_and_requires_enrollment() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let expected = prepare(&path);
    let witness = AnchorStore::provision(
        &path.join("witness.redb"),
        JournalKey::provision(&path.join("witness-key")).expect("witness key"),
        AnchorSigningKey::generate().expect("signer"),
        AnchorIdentity::generate().expect("witness ID"),
    )
    .expect("witness");
    let pin = witness.pin().expect("pin");
    let mut bytes = pin.identity().as_bytes().to_vec();
    bytes.extend_from_slice(&pin.public_key().encode());
    fs::write(path.join("witness-pin"), bytes).expect("independent test pin");
    let (f, _) = peer(&path).expect("independent fixture pin");
    cut_creation(&path, "after-commit");
    assert!(matches!(
        DeviceJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            f.local_device(),
            expected
        ),
        Err(DurableError::AnchorRequired)
    ));
    let recover = |id| {
        DeviceJournal::recover_anchor_genesis(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            f.local_device(),
            f.responder.policy(),
            id,
        )
    };
    assert!(matches!(
        recover(JournalIdentity::from_trusted_state([72; 32]).expect("other ID")),
        Err(DurableError::Conflict)
    ));
    let genesis = recover(expected).expect("retained required genesis");
    assert_eq!(
        genesis.image_digest().as_slice(),
        fs::read(path.join("observed-digest")).expect("digest")
    );
    assert_eq!(
        genesis.subject().to_bytes(),
        recover(expected)
            .expect("same exact genesis")
            .subject()
            .to_bytes()
    );
    let witness = Arc::new(std::sync::Mutex::new(witness));
    let client = || {
        AnchorClient::new(
            pin.clone(),
            DeviceSigningKey::deterministic([96; 32], [97; 32]).expect("original local credential"),
            Box::new(Witness(Arc::clone(&witness))),
            Duration::from_secs(10),
        )
        .expect("client")
    };
    // Public enrollment metadata cannot bypass fresh witness admission.
    let open = || {
        DeviceJournal::open_anchored(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            f.local_device(),
            f.responder.policy(),
            expected,
            client(),
        )
    };
    assert!(matches!(open(), Err(DurableError::Anchor(_))));
    witness
        .lock()
        .expect("witness")
        .enroll(&genesis, f.local_device(), f.responder.policy(), 150)
        .expect("explicit enrollment of original genesis");
    // Enrollment retry after an unknown result is exact and idempotent.
    witness
        .lock()
        .expect("witness")
        .enroll(
            &recover(expected).expect("original genesis"),
            f.local_device(),
            f.responder.policy(),
            150,
        )
        .expect("same enrollment");
    let mut journal = open().expect("original witness admission");
    assert_genesis(&mut journal, &path, expected);
    let request = crate::PrekeyId::from_trusted_state([76; 32]).expect("request");
    let leaf = journal
        .generate_prekey(
            f.responder.policy(),
            f.local_device(),
            request,
            crate::LeafKind::OneTimePq,
            crate::tests::interval(),
            150,
        )
        .expect("anchored durable work");
    journal.close();
    assert!(matches!(recover(expected), Err(DurableError::Conflict)));
    journal = DeviceJournal::open_anchored(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("original key"),
        f.local_device(),
        f.responder.policy(),
        expected,
        client(),
    )
    .expect("same subject reopen");
    assert_eq!(
        journal
            .prekey_leaf(f.responder.policy(), f.local_device(), request, 150)
            .expect("exact durable prekey")
            .key_fingerprint(),
        leaf.key_fingerprint()
    );
}
