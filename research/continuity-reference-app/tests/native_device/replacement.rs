// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real native and witness CLI, retained original files, and TCP activation.
use super::*;
use q_periapt_continuity_reference_app::{
    network,
    witness::{
        DevicePredecessorTrust, DeviceReplacementDecision, DeviceReplacementTrust,
        EnrollmentRequest, EnrollmentTrust, Pin, Witness,
    },
};
use std::{net::SocketAddr, process::Stdio, thread};

fn witness_args(path: &Path, command: &str, tail: &[&Path]) -> Vec<OsString> {
    let mut args = vec![
        command.into(),
        path.join("host.redb").into_os_string(),
        URL_SAFE_NO_PAD.encode([91; 32]).into(),
    ];
    args.extend(tail.iter().map(|p| p.as_os_str().to_os_string()));
    args
}
fn witness_call(path: &Path, command: &str, tail: &[&Path]) -> Result<serde_json::Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
        .args(witness_args(path, command, tail))
        .output()?;
    assert!(
        output.status.success(),
        "witness {command}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn trust(
    current: RootInfo,
    invitation: &Invitation,
    issued: &IssuedEnrollment,
    request: &EnrollmentRequest,
    policy: PolicyInput,
) -> Result<EnrollmentTrust> {
    // This controller independently approves the exact export from its own
    // newly enrolled test device. Production code receives these trusted fields
    // separately and never copies them from a remote preparation request.
    let journal = request.subject.get(..32).ok_or("subject")?.try_into()?;
    Ok(EnrollmentTrust {
        schema: "qperiapt-witness-enrollment-trust/1".into(),
        account: current,
        device: invitation.device,
        generation: invitation.generation,
        journal,
        genesis_head: request.head,
        certificate: issued.certificate.clone(),
        policy,
    })
}

struct HostServer {
    address: SocketAddr,
    stop: sdk::Cancellation,
    worker: Option<thread::JoinHandle<std::result::Result<(), String>>>,
}
impl HostServer {
    fn start(path: PathBuf) -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = sdk::Cancellation::default();
        let cancel = stop.clone();
        let worker = thread::spawn(move || -> std::result::Result<(), String> {
            let run =
                || -> Result<()> {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(async move {
                            let listener = tokio::net::TcpListener::from_std(listener)?;
                            network::serve(
                                listener,
                                network::Limits::default(),
                                cancel,
                                move |frame, run| {
                                    let response =
                                        (|| -> Result<_> {
                                            run.check()?;
                                            Witness::open(&path.join("host.redb"), [91; 32])?
                                                .handle(frame, run, clock()?)
                                        })();
                                    response.map_err(|e| std::io::Error::other(e.to_string()))
                                },
                            )
                            .await?;
                            Ok(())
                        })
                };
            run().map_err(|e| e.to_string())
        });
        Ok(Self {
            address,
            stop,
            worker: Some(worker),
        })
    }
    fn close(&mut self) -> Result<()> {
        self.stop.cancel();
        self.worker
            .take()
            .ok_or("server already stopped")?
            .join()
            .map_err(|_| "witness server panicked")?
            .map_err(Into::into)
    }
}
impl Drop for HostServer {
    fn drop(&mut self) {
        if self.worker.is_some() {
            if let Err(error) = self.close() {
                eprintln!("witness server cleanup: {error}");
            }
        }
    }
}

#[test]
fn replacement_cli_preserves_both_devices_and_recovers_lost_commit_output() -> Result<()> {
    let host = tempfile::tempdir()?.keep().canonicalize()?;
    fs::set_permissions(&host, fs::Permissions::from_mode(0o700))?;
    eprintln!(
        "Witness replacement CLI fixture retained: {}",
        host.display()
    );
    let pin: Pin = serde_json::from_value(witness_call(&host, "init", &[])?)?;
    let c = Case::open_with_anchor(1200, 2400, Some(&pin.as_sdk()?))?;
    c.accept()?;
    let original: EnrollmentRequest = serde_json::from_value(c.call(
        "prepare",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    )?)?;
    let (pins, materials) = c.publisher.export([65; 32])?;
    let policy = PolicyInput { pins, materials };
    let original_trust = trust(
        c.current.clone(),
        &c.invitation,
        &c.issued,
        &original,
        policy.clone(),
    )?;
    write(&c.path.join("original-trust.json"), &original_trust)?;
    write(&c.path.join("original-preparation.json"), &original)?;
    witness_call(
        &host,
        "enroll",
        &[
            &c.path.join("original-trust.json"),
            &c.path.join("original-preparation.json"),
        ],
    )?;
    let mut server = HostServer::start(host.clone())?;
    let mut original_activate = c.args(
        "activate",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    );
    original_activate.push(server.address.to_string().into());
    invoke(&original_activate, true)?;
    let original_status = c.call("status", &[])?;

    let fresh = c.path.join("replacement");
    private_dir(&fresh)?;
    private_dir(&fresh.join("device"))?;
    let mut invitation = c.invitation.clone();
    invitation.operation = [71; 32];
    invitation.request_id = [72; 32];
    invitation.generation = 2;
    invitation.predecessor = Some(c.issued.checkpoint);
    write(&fresh.join("invitation.json"), &invitation)?;
    invoke(
        &[
            "provision-key".into(),
            fresh.join("wrap.key").into_os_string(),
        ],
        true,
    )?;
    let args = |command: &str, tail: &[&Path]| {
        let mut values = vec![
            command.into(),
            fresh.join("device").into_os_string(),
            fresh.join("wrap.key").into_os_string(),
            fresh.join("invitation.json").into_os_string(),
        ];
        values.extend(tail.iter().map(|p| p.as_os_str().to_os_string()));
        values
    };
    invoke(&args("begin", &[]), true)?;
    invoke(&args("request", &[&fresh.join("request.bin")]), true)?;
    let request = sdk::VerifiedEnrollmentRequest::verify(
        &fs::read(fresh.join("request.bin"))?,
        &invitation.intent()?,
        clock()?,
    )?;
    let cert = c.root.issue_enrollment(&request, clock()?)?;
    assert_ne!(cert, c.issued.certificate);
    let roster = c.root.issue_roster(
        2,
        sdk::Validity::new(c.start, c.start + 2400)?,
        &[c.root.roster_entry(&cert)?],
    )?;
    let issued = IssuedEnrollment {
        operation: invitation.operation,
        root_revision: 1,
        certificate: cert,
        roster: roster.as_bytes().to_vec(),
        checkpoint: roster.checkpoint().into(),
    };
    let mut current = c.current.clone();
    current.roster = Some(RosterSnapshot {
        checkpoint: issued.checkpoint,
        bytes: issued.roster.clone(),
    });
    write(&fresh.join("issued.json"), &issued)?;
    write(&fresh.join("current.json"), &current)?;
    invoke(
        &args(
            "accept",
            &[
                &fresh.join("issued.json"),
                &fresh.join("current.json"),
                &c.path.join("policy-pins.json"),
                &c.path.join("policy-materials.json"),
            ],
        ),
        true,
    )?;
    let prepared: EnrollmentRequest = serde_json::from_slice(&invoke(
        &args(
            "prepare",
            &[
                &fresh.join("current.json"),
                &c.path.join("policy-pins.json"),
                &c.path.join("policy-materials.json"),
            ],
        ),
        true,
    )?)?;
    let fresh_status: serde_json::Value =
        serde_json::from_slice(&invoke(&args("status", &[]), true)?)?;
    assert_ne!(fresh_status["signing_id"], original_status["signing_id"]);
    assert_ne!(fresh_status["journal"], original_status["journal"]);
    assert_ne!(prepared.subject, original.subject);
    let approved = DeviceReplacementTrust {
        schema: "qperiapt-witness-device-replacement-trust/1".into(),
        successor: trust(current, &invitation, &issued, &prepared, policy.clone())?,
        predecessors: vec![DevicePredecessorTrust {
            subject: original.subject.clone(),
            checkpoint: c.issued.checkpoint,
            policy,
        }],
    };
    write(&fresh.join("trust.json"), &approved)?;
    write(&fresh.join("preparation.json"), &prepared)?;
    let output = fresh.join("decision");
    private_dir(&output)?;
    let decision: DeviceReplacementDecision = serde_json::from_value(witness_call(
        &host,
        "replacement-prepare",
        &[
            &fresh.join("trust.json"),
            &fresh.join("preparation.json"),
            &output,
        ],
    )?)?;
    let decision_file = output.join("device-replacement-decision.json");
    assert_eq!(
        serde_json::from_slice::<DeviceReplacementDecision>(&fs::read(&decision_file)?)?.proposal,
        decision.proposal
    );
    assert_eq!(
        witness_call(&host, "replacement-status", &[&decision_file])?["status"],
        "Unavailable"
    );
    let mut activate = args(
        "activate",
        &[
            &fresh.join("current.json"),
            &c.path.join("policy-pins.json"),
            &c.path.join("policy-materials.json"),
        ],
    );
    activate.push(server.address.to_string().into());
    invoke(&activate, false)?;
    let commit = witness_args(
        &host,
        "replacement-commit",
        &[
            &fresh.join("trust.json"),
            &fresh.join("preparation.json"),
            &decision_file,
        ],
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
        .args(&commit)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(child.stdout.take());
    let lost = child.wait_with_output()?;
    publish_private_bytes(&fresh.join("lost-commit.stderr"), &lost.stderr)?;
    assert!(!lost.status.success());
    assert!(String::from_utf8_lossy(&lost.stderr)
        .to_ascii_lowercase()
        .contains("broken pipe"));
    assert_eq!(
        witness_call(&host, "replacement-status", &[&decision_file])?["status"],
        "Committed"
    );
    invoke(&original_activate, false)?;
    invoke(&activate, true)?;
    assert_eq!(
        witness_call(
            &host,
            "replacement-commit",
            &[
                &fresh.join("trust.json"),
                &fresh.join("preparation.json"),
                &decision_file
            ]
        )?["status"],
        "Committed"
    );
    assert!(c.path.join("device").is_dir() && fresh.join("device").is_dir());
    server.close()?;
    let mut reopened = HostServer::start(host.clone())?;
    *activate.last_mut().ok_or("endpoint")? = reopened.address.to_string().into();
    *original_activate.last_mut().ok_or("endpoint")? = reopened.address.to_string().into();
    invoke(&activate, true)?;
    invoke(&original_activate, false)?;
    let retained_old = c.call("status", &[])?;
    let retained_new: serde_json::Value =
        serde_json::from_slice(&invoke(&args("status", &[]), true)?)?;
    for field in ["signing_id", "journal"] {
        assert_eq!(retained_old[field], original_status[field]);
        assert_eq!(retained_new[field], fresh_status[field]);
    }
    reopened.close()?;
    Ok(())
}
