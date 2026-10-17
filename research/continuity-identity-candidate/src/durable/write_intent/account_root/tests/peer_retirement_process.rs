// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual process loss around the existing sender journal/witness transaction.
use super::*;
use std::{
    io::Write,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Command, Stdio},
};

fn publish(path: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.join(format!("{name}.tmp"));
    let mut file = fs::File::create_new(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path.join(name))
}

// Untrusted test-only IPC. Real signed requests are evaluated by the parent's
// original AnchorStore; this is neither a fabricated reply nor a TCP/TLS test.
struct FileCarrier {
    path: PathBuf,
    sequence: u8,
}
impl crate::AnchorTransport for FileCarrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if self.sequence >= 32 || request.len() != 3674 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let sequence = self.sequence;
        self.sequence += 1;
        publish(&self.path, &format!("request-{sequence}"), request)?;
        let response = self.path.join(format!("response-{sequence}"));
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match fs::metadata(&response) {
                Ok(metadata) => {
                    if metadata.len() != 3659 {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    return fs::read(&response);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn peer_account_retirement_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_PEER_ROOT_PROCESS_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let witness = crate::AnchorIdentity::from_trusted_state(
        fs::read(path.join("witness-id"))
            .expect("original witness identity")
            .try_into()
            .expect("identity width"),
    )
    .expect("witness identity");
    let public = crate::PublicKey::decode(
        &fs::read(path.join("witness-public")).expect("original public pin"),
    )
    .expect("public key");
    let pin = AnchorPin::new(witness, public);
    let f = crate::bootstrap::tests::fixture_with_anchor_and_budget(
        crate::PrekeyQuality::OneTimeBoth,
        crate::AnchorRequirement::required(&pin),
        crate::ApplicationSendBudget::new(1024).expect("budget"),
    );
    let identity = JournalIdentity::from_trusted_state(
        fs::read(path.join("store-id"))
            .expect("original sender identity")
            .try_into()
            .expect("journal identity width"),
    )
    .expect("journal identity");
    let proposal = Proposal::from_trusted_state(
        &fs::read(path.join("proposal")).expect("retained approved proposal"),
    )
    .expect("proposal");
    let retired = pin
        .verify_retired_account(
            &proposal,
            &fs::read(path.join("receipt")).expect("original receipt"),
        )
        .expect("authenticated historical retirement");
    let client = crate::AnchorClient::new(
        pin,
        DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("sender signer"),
        Box::new(FileCarrier {
            path: path.into(),
            sequence: 0,
        }),
        Duration::from_secs(10),
    )
    .expect("bounded signed witness client");
    let device = f.initiator_device();
    let policy = f.initiator.current_policy().expect("current local policy");
    let mut journal = DeviceJournal::open_anchored(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("original key"),
        device,
        policy,
        identity,
        client,
    )
    .expect("original sender journal");
    if std::env::var("QPERIAPT_PEER_ROOT_PROCESS_CUT").expect("selected boundary")
        == "before-intent"
    {
        publish(path, "ready", b"before intent").expect("owned checkpoint");
        loop {
            std::thread::park();
        }
    }
    let authority = crate::RetainedInstallationAuthority::active_installation(device, policy);
    journal
        .retire_peer_account(
            &crate::installation::PolicyScope {
                authority: &authority,
                original_policy: policy.historical(),
                original_device: device,
            },
            &retired,
            policy,
            150,
        )
        .expect("explicit peer retirement");
    publish(path, "returned", b"returned").expect("actual API return marker");
}

fn sender_head(c: &Case, subject: crate::AnchorSubject) -> crate::AnchorHead {
    let request = crate::AnchorRequest::new(
        &c.pin,
        subject,
        crate::AnchorOperation::query(),
        &c.f.signer_i,
    )
    .expect("original signed sender query");
    let response = c
        .witness
        .lock()
        .expect("witness")
        .handle(request.as_bytes(), 150)
        .expect("current sender head");
    c.pin
        .verify_reply(&request, &response)
        .expect("authenticated current head")
        .observed_head()
}

#[test]
fn peer_account_retirement_process_loss_preserves_the_original_statement_at_four_boundaries() {
    for cut in ["before-intent", "intent", "witness", "image"] {
        let mut c = case();
        let (mut sender, session) = c.connected_peer();
        let identity = sender.identity().expect("original sender identity");
        let message = sender
            .next_message_id(&c.f.initiator, session, 150)
            .expect("original message");
        let wire = sender
            .send_message(
                &c.f.initiator,
                session,
                message,
                b"unconfirmed",
                b"root",
                150,
            )
            .expect("actual retained ciphertext");
        let subject = crate::AnchorSubject::for_device(
            identity,
            c.f.initiator_device(),
            c.f.initiator.current_policy().expect("policy"),
        )
        .expect("original sender subject");
        let before = sender_head(&c, subject);
        let proposal = c.proposal(244);
        let receipt = c.receipt(&proposal);
        let observed = c
            .pin
            .verify_retired_account(&proposal, &receipt)
            .expect("retirement");
        let path = c.path.parent().expect("parent").join("peer");
        for (name, bytes) in [
            ("witness-id", c.pin.identity().as_bytes().to_vec()),
            ("witness-public", c.pin.public_key().encode()),
            ("proposal", proposal.to_bytes().expect("original proposal")),
            ("receipt", receipt),
        ] {
            publish(&path, name, &bytes).expect("retain original public inputs");
        }
        sender.close();
        let log = fs::File::create_new(path.join("child.log")).expect("owned child log");
        let mut command = Command::new(std::env::current_exe().expect("original test binary"));
        command.args(["--exact", "durable::write_intent::account_root::tests::peer_retirement::process::peer_account_retirement_process_child", "--nocapture"])
            .env("QPERIAPT_PEER_ROOT_PROCESS_DIR", &path).env("QPERIAPT_PEER_ROOT_PROCESS_CUT", cut)
            .env("QPERIAPT_JOURNAL_CRASH_DIR", &path)
            .stdout(Stdio::from(log.try_clone().expect("stdout"))).stderr(Stdio::from(log));
        if cut == "intent" {
            command.env(
                "QPERIAPT_WRITE_INTENT_CRASH_PHASE",
                (DurableStatus::Roster as u8).to_string(),
            );
        }
        if cut == "image" {
            command.env(
                "QPERIAPT_JOURNAL_CRASH_PHASE",
                (DurableStatus::Roster as u8).to_string(),
            );
        }
        let mut child = crate::durable::tests::ChildGuard(command.spawn().expect("owned child"));
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut sequence = 0u8;
        while !path.join("ready").exists() {
            assert!(
                Instant::now() < deadline && child.0.try_wait().expect("child status").is_none(),
                "missing peer retirement checkpoint {cut}; log={}",
                fs::read_to_string(path.join("child.log")).expect("child log")
            );
            let request = path.join(format!("request-{sequence}"));
            if request.exists() {
                assert!(sequence < 32);
                let request = fs::read(request).expect("original signed request");
                assert_eq!(request.len(), 3674);
                let response = c
                    .witness
                    .lock()
                    .expect("original witness")
                    .handle(&request, 150)
                    .expect("evaluate real signed request");
                let current = sender_head(&c, subject);
                if cut == "witness" && current != before {
                    publish(&path, "withheld-signed-response", &response)
                        .expect("retain committed lost reply");
                    publish(&path, "ready", b"witness committed; reply not delivered")
                        .expect("checkpoint");
                    break;
                }
                publish(&path, &format!("response-{sequence}"), &response)
                    .expect("deliver original signed response");
                sequence += 1;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill only the owned child");
        assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
        assert_eq!(
            sender_head(&c, subject) == before,
            matches!(cut, "before-intent" | "intent")
        );
        sender = reopen(&c, identity).expect("recover exact original sealed intent");
        if cut == "before-intent" {
            assert_eq!(
                sender
                    .resume_message(&c.f.initiator, session, message, 150)
                    .expect("no durable floor claimed before intent"),
                wire
            );
        } else {
            assert!(matches!(
                sender.resume_message(&c.f.initiator, session, message, 150),
                Err(DurableError::Protocol(Error::Scope))
            ));
        }
        adopt(&c, &mut sender, &observed, 150).expect("same approved original statement");
        let committed = sender_head(&c, subject);
        adopt(&c, &mut sender, &observed, 150).expect("same statement exact retry");
        assert_eq!(sender_head(&c, subject), committed);
        let report = sender
            .begin_session_closure(&c.f.initiator, session)
            .expect("original unknown delivery accounting");
        assert_eq!(report.peer_account, proposal.previous_account());
        assert!(report
            .epochs
            .iter()
            .any(|epoch| !epoch.unconfirmed.is_empty()));
        sender.close();
    }
    eprintln!("PEER_ACCOUNT_RETIREMENT_PROCESS cuts=4 signal=SIGKILL signed_witness=true original_statement=true no_early_return=true unknown_delivery_preserved=true");
}
