// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Installed public enrollment, required-witness replacement and original host accounting.
use super::*;
use p::retired_device::{JournalErasureState, RecordMetadata, SessionState, ViewRole};

const OLD_PAYLOAD: &[u8] = b"retiring device effect before unavailable receipt";
// Use the existing foreign test application's exact accepted payload; every
// consumer still checks and durably records the complete session/message bytes.
const NEW_PAYLOAD: &[u8] = b"persisted before process exit";

fn traffic_log(path: &Path, mode: &str, stream: &str) -> Result<Vec<u8>> {
    // Empty stdout is expected before readiness, and successful stderr is empty.
    // Keep this log reader distinct from nonempty authenticated input records.
    let file = fs::File::open(path.join(format!("successor-traffic-{mode}.{stream}")))?;
    if !file.metadata()?.is_file() {
        return Err("foreign traffic log is not a file".into());
    }
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err("foreign traffic log exceeded bound".into());
    }
    Ok(bytes)
}

fn traffic(
    path: &Path,
    mode: &str,
    session: Option<[u8; 32]>,
    client: Option<&Path>,
    witness: &WitnessFixture,
) -> Result<(OwnedChild, SocketAddr)> {
    let (attempt, native_mode) = match (mode, session) {
        ("bootstrap", None) => (0, "retirement-traffic-bootstrap"),
        ("message", Some(_)) => (1, "retirement-traffic-application"),
        _ => return Err("replacement traffic invocation shape".into()),
    };
    let Some(client) = client else {
        return spawn(path, attempt, native_mode);
    };
    let stdout_path = path.join(format!("successor-traffic-{mode}.stdout"));
    let stderr_path = path.join(format!("successor-traffic-{mode}.stderr"));
    let create = |path: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    let mut command = Command::new(client);
    command
        .arg("--witness")
        .arg(witness.address.to_string())
        .arg("--enrollment-parent")
        .arg(path)
        .arg("2");
    if let Some(session) = session {
        command.arg("--session").arg(hex(&session));
    }
    let mut child = OwnedChild(
        command
            .arg("serve")
            .arg(path)
            .arg(mode)
            .stdout(Stdio::from(create(&stdout_path)?))
            .stderr(Stdio::from(create(&stderr_path)?))
            .spawn()?,
    );
    store(
        path,
        &format!("successor-traffic-{mode}.pid"),
        &u64::from(child.0.id()).to_be_bytes(),
    )?;
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let output = traffic_log(path, mode, "stdout")?;
        let text = std::str::from_utf8(&output)?;
        if let Some((first, _)) = text.split_once('\n') {
            let port: u16 = first
                .strip_prefix("listening:")
                .ok_or("foreign replacement readiness")?
                .parse()?;
            if port == 0 {
                return Err("foreign replacement returned zero port".into());
            }
            return Ok((child, SocketAddr::from(([127, 0, 0, 1], port))));
        }
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "foreign replacement readiness failed: {}",
                String::from_utf8_lossy(&traffic_log(path, mode, "stderr")?)
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn finish_traffic(
    child: &mut OwnedChild,
    path: &Path,
    mode: &str,
    session: [u8; 32],
    message: Option<p::MessageId>,
    foreign: bool,
) -> Result<()> {
    assert!(wait(child)?.success());
    if foreign {
        assert!(traffic_log(path, mode, "stderr")?.is_empty());
        let stdout = traffic_log(path, mode, "stdout")?;
        let text = std::str::from_utf8(&stdout)?;
        let lines: Vec<_> = text.lines().collect();
        let [ready, served, actual_session, actual_message] = lines.as_slice() else {
            return Err("foreign replacement traffic result shape".into());
        };
        assert!(ready.starts_with("listening:"));
        assert_eq!(
            *served,
            if message.is_some() {
                "served:2:0:1:1"
            } else {
                "served:1:0:0:0"
            }
        );
        assert_eq!(*actual_session, hex(&session));
        assert_eq!(
            *actual_message,
            message.map_or_else(|| hex(&[0; 32]), |id| hex(id.as_bytes()))
        );
    }
    Ok(())
}

fn pin(path: &Path) -> Result<p::AnchorPin> {
    Ok(p::AnchorPin::new(
        p::AnchorIdentity::from_trusted_state(array(path, "witness-id")?)?,
        p::PublicKey::decode(&read(path, "witness-public", p::PUBLIC_KEY_BYTES)?)?,
    ))
}
fn client(path: &Path) -> Result<p::AnchorClient> {
    let address = String::from_utf8(read(path, "retirement-witness-address", 128)?)?.parse()?;
    let signer = p::DeviceSigningKey::open(
        &path.join("signer.key"),
        &key(path)?,
        p::SigningKeyId::from_trusted_state(array(path, "signer-id")?)?,
    )?;
    Ok(p::AnchorClient::new(
        pin(path)?,
        signer,
        Box::new(p::AnchorTcpTransport::new(address)),
        Duration::from_secs(3),
    )?)
}
fn retirement(path: &Path) -> Result<(p::AnchorPin, p::AnchorRetiredSubject)> {
    let pin = pin(path)?;
    let proposal = p::AnchorDeviceReplacementProposal::from_trusted_state(&read(
        path,
        "retirement-proposal",
        65536,
    )?)?;
    let subject = p::AnchorSubject::from_trusted_state(&read(path, "witness-subject", 96)?)?;
    let retired =
        pin.verify_retired_subject(&proposal, subject, &read(path, "retirement-receipt", 8192)?)?;
    Ok((pin, retired))
}
fn open(path: &Path) -> Result<p::RetiredDeviceEnrollment> {
    let (pin, retired) = retirement(path)?;
    Ok(p::RetiredDeviceEnrollment::open(
        enrollment::paths(path)?,
        enrollment::intent(path)?,
        pin,
        retired,
    )?)
}
fn report_proposal(path: &Path) -> Result<p::AnchorRetiredReportProposal> {
    Ok(p::AnchorRetiredReportProposal::from_trusted_state(&read(
        path,
        "retirement-report-proposal",
        353,
    )?)?)
}
fn acknowledged_report(path: &Path) -> Result<Vec<u8>> {
    let (pin, retired) = retirement(path)?;
    let expected = report_proposal(path)?;
    pin.verify_retired_report_acknowledgement(
        retired,
        &expected,
        &read(path, "retirement-ack", 3730)?,
    )?;
    read(path, "retirement-host-report", 8 * 1024 * 1024)
}

fn check_report(path: &Path, report: &p::retired_device::Report) -> Result<()> {
    assert_eq!(report.proposal(), &report_proposal(path)?);
    assert_eq!(report.views().len(), 1);
    let view = report
        .views()
        .first()
        .ok_or("complete original report view")?;
    assert_eq!(view.role, ViewRole::Authoritative);
    let sessions: Vec<_> = view
        .records
        .iter()
        .filter_map(|record| match &record.metadata {
            RecordMetadata::Session(session) => Some(session),
            _ => None,
        })
        .collect();
    assert_eq!(sessions.len(), 1);
    let session = sessions.first().ok_or("original report session")?;
    assert_eq!(session.session, array::<32>(path, "session")?);
    let SessionState::Live { epochs, .. } = &session.state else {
        return Err("original session became terminal before host ACK".into());
    };
    assert_eq!(epochs.len(), 1);
    let epoch = &epochs.first().ok_or("original report epoch")?.accounting;
    assert_eq!((epoch.received, epoch.consumed_before), (1, 0));
    assert_eq!(epoch.deliveries.len(), 1);
    let delivery = epoch
        .deliveries
        .first()
        .ok_or("unconsumed original input")?;
    assert_eq!(
        delivery.message.as_bytes(),
        &array::<32>(path, "retirement-message")?
    );
    assert_eq!(delivery.plaintext_bytes, OLD_PAYLOAD.len());
    Ok(())
}

pub(super) fn device_process(path: &Path, attempt: u8, mode: &str) -> Result<()> {
    if let Some(mode) = mode.strip_prefix("traffic-") {
        return serve_peer(
            path,
            attempt,
            mode.to_owned(),
            Peer::open_with_anchor(path, Some(client(path)?), now()?)?,
        );
    }
    store(
        path,
        &format!("retirement-process-{mode}"),
        &u64::from(std::process::id()).to_be_bytes(),
    )?;
    let (pin, _) = retirement(path)?;
    let mut owner = open(path)?;
    if mode == "inventory" {
        let proposal = owner.installation()?.proposal()?;
        store(path, "retirement-inventory", &proposal.to_bytes())?;
    } else if mode == "prepare-report" {
        let cleanup = owner.installation()?;
        let retained =
            cleanup.verify_retained(&pin, &read(path, "retirement-inventory-receipt", 3690)?)?;
        let proposal = cleanup.prepare_report(&retained)?;
        store(path, "retirement-report-proposal", &proposal.to_bytes())?;
    } else if mode == "report" || mode == "report-reopen" {
        let cleanup = owner.installation()?;
        let retained =
            cleanup.verify_retained(&pin, &read(path, "retirement-inventory-receipt", 3690)?)?;
        let report = cleanup.report(
            &retained,
            &pin,
            &read(path, "retirement-report-receipt", 3730)?,
        )?;
        check_report(path, &report)?;
        if mode == "report" {
            // Host transaction commits complete metadata before any independent ACK.
            store(path, "retirement-host-report", report.as_bytes())?;
            std::process::exit(77);
        }
        assert_eq!(
            report.as_bytes(),
            read(path, "retirement-host-report", 8 * 1024 * 1024)?
        );
        store(
            path,
            "retirement-report-reopened",
            report.proposal().report_id(),
        )?;
    } else if mode == "prepare-ack" {
        let cleanup = owner.installation()?;
        let retained =
            cleanup.verify_retained(&pin, &read(path, "retirement-inventory-receipt", 3690)?)?;
        let expected = report_proposal(path)?;
        let retained_report = pin.verify_retired_report(
            &retained,
            &expected,
            &read(path, "retirement-report-receipt", 3730)?,
        )?;
        cleanup.prepare_host_acknowledgement(
            &read(path, "retirement-host-report", 8 * 1024 * 1024)?,
            &retained_report,
        )?;
        assert_eq!(cleanup.host_acknowledgement_proposal()?, Some(expected));
    } else if mode == "erase-journal" {
        let _report = acknowledged_report(path)?;
        owner
            .installation()?
            .erase_journal(&pin, &read(path, "retirement-ack", 3730)?)?;
        // No completion marker: the next process must inspect the durable terminal.
        std::process::exit(77);
    } else if mode == "erase-signer" {
        let _report = acknowledged_report(path)?;
        assert_eq!(
            owner.installation()?.journal_erasure_status(&pin)?,
            JournalErasureState::Erased
        );
        owner.prepare_signer_erasure(&read(path, "retirement-ack", 3730)?)?;
        assert_eq!(
            owner.signer_erasure_status()?,
            p::SigningFileErasureState::Retained
        );
        owner.erase_signer()?;
        std::process::exit(77);
    } else if mode == "verify" {
        let report = acknowledged_report(path)?;
        // Authenticate the complete retained host bytes again after journal and
        // signer retirement, using the independent expectation and wrapping key.
        let cleanup = owner.installation()?;
        let retained =
            cleanup.verify_retained(&pin, &read(path, "retirement-inventory-receipt", 3690)?)?;
        let expected = report_proposal(path)?;
        let report_receipt = pin.verify_retired_report(
            &retained,
            &expected,
            &read(path, "retirement-report-receipt", 3730)?,
        )?;
        cleanup.prepare_host_acknowledgement(&report, &report_receipt)?;
        store(path, "retirement-host-report-verified", &report)?;
        assert_eq!(
            owner.installation()?.journal_erasure_status(&pin)?,
            JournalErasureState::Erased
        );
        assert_eq!(
            owner.signer_erasure_status()?,
            p::SigningFileErasureState::Erased
        );
        owner.erase_signer()?;
        assert!(matches!(
            p::DeviceEnrollment::open(enrollment::paths(path)?, enrollment::intent(path)?),
            Err(p::DurableError::Suspended)
        ));
        assert!(p::DeviceSigningKey::open(
            &path.join("signer.key"),
            &key(path)?,
            p::SigningKeyId::from_trusted_state(array(path, "signer-id")?)?
        )
        .is_err());
        store(
            path,
            "retirement-verified",
            report_proposal(path)?.report_id(),
        )?;
    } else {
        return Err("unknown retirement process mode".into());
    }
    owner.close();
    Ok(())
}
fn stage(path: &Path, attempt: u8, mode: &str, exit: i32, client: Option<&Path>) -> Result<()> {
    let mut process = if let Some(client) = client {
        let log = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path.join(format!("peer-{attempt}.log")))?;
        OwnedChild(
            Command::new(client)
                .arg("retired")
                .arg(path)
                .arg(mode)
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        )
    } else {
        child(path, attempt, &format!("retirement-{mode}"))?
    };
    let status = wait(&mut process)?;
    assert_eq!(
        status.code(),
        Some(exit),
        "{}",
        String::from_utf8(read(path, &format!("peer-{attempt}.log"), 65536)?)?
    );
    Ok(())
}

pub(crate) fn exercise(client: Option<&Path>) -> Result<()> {
    if client.is_some_and(|path| !path.is_absolute() || !path.is_file()) {
        return Err("retirement client must be an existing absolute executable".into());
    }
    let mut witness = roster_renewal::Witness::start_current()?;
    let s = setup_devices_for(
        Some(&witness.configured),
        None,
        None,
        false,
        false,
        true,
        enrollment::SetupKind::DeviceRetirement,
    )?
    .0;
    eprintln!("PUBLIC_RETIREMENT_STAGE setup_complete");
    let root = s.responder.parent().ok_or("retirement root")?;
    for path in [&s.initiator, &s.responder] {
        store(
            path,
            "retirement-witness-address",
            witness.configured.address.to_string().as_bytes(),
        )?;
    }
    let mut initiator = Peer::open_with_witness(&s.initiator, Some(&witness.configured))?;
    let old_context = Arc::clone(&initiator.context);
    let endpoint = ConnectionEndpoint::client(&old_context, initiator.credentials(), tls_limits())?;
    let (mut server, address) = spawn(&s.responder, 0, "retirement-traffic-bootstrap")?;
    let peer_name = initiator.peer_name.clone();
    let session = endpoint
        .establish(
            initiator.actor()?,
            p::InitiationId::generate()?,
            Run {
                address,
                server_name: &peer_name,
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            now,
        )?
        .session;
    assert!(wait(&mut server)?.success());
    store(&s.initiator, "session", &session)?;
    let message = initiator
        .service
        .stores()?
        .0
        .next_message_id(&old_context, session, now()?)?;
    store(&s.responder, "retirement-message", message.as_bytes())?;
    let (mut server, address) = spawn(
        &s.responder,
        1,
        "retirement-traffic-crash-after-application",
    )?;
    assert!(send(
        &mut initiator,
        &endpoint,
        address,
        session,
        message,
        OLD_PAYLOAD
    )
    .is_err());
    assert_eq!(wait(&mut server)?.code(), Some(77));
    effect(&s.responder, session, message, OLD_PAYLOAD)?;
    eprintln!("PUBLIC_RETIREMENT_STAGE old_effect_committed");
    let next = replacement::prepare_with_client(&s, Some(&witness.configured), client)?;
    eprintln!("PUBLIC_RETIREMENT_STAGE replacement_active");
    store(
        &next.path,
        "retirement-witness-address",
        witness.configured.address.to_string().as_bytes(),
    )?;
    let (pin, retired) = retirement(&s.responder)?;
    let old_signer = p::DeviceSigningKey::open(
        &s.responder.join("signer.key"),
        &key(&s.responder)?,
        p::SigningKeyId::from_trusted_state(array(&s.responder, "signer-id")?)?,
    )?;
    let query = p::AnchorRequest::new(
        &pin,
        retired.subject(),
        p::AnchorOperation::query(),
        &old_signer,
    )?;
    assert!(matches!(
        witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?
            .handle(query.as_bytes(), now()?),
        Err(p::AnchorError::Rejected(p::Error::Scope))
    ));
    drop(old_signer);
    stage(&s.responder, 2, "inventory", 0, client)?;
    let inventory = p::AnchorRetiredCleanupProposal::from_trusted_state(&read(
        &s.responder,
        "retirement-inventory",
        313,
    )?)?;
    {
        let mut controller = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?;
        controller.retain_retired_cleanup(&inventory)?;
        store(
            &s.responder,
            "retirement-inventory-receipt",
            &controller.retired_cleanup_receipt(&inventory)?,
        )?;
    }
    stage(&s.responder, 3, "prepare-report", 0, client)?;
    let expected = report_proposal(&s.responder)?;
    {
        let mut controller = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?;
        controller.retain_retired_report(&expected)?;
        store(
            &s.responder,
            "retirement-report-receipt",
            &controller.retired_report_receipt(&expected)?,
        )?;
    }
    stage(&s.responder, 4, "report", 77, client)?;
    if client.is_some() {
        // The foreign process must produce the same complete report. Preserve all
        // native field assertions; a foreign marker or valid prefix is insufficient.
        let mut owner = open(&s.responder)?;
        let child = owner.installation()?;
        let retained = child.verify_retained(
            &pin,
            &read(&s.responder, "retirement-inventory-receipt", 3690)?,
        )?;
        let report = child.report(
            &retained,
            &pin,
            &read(&s.responder, "retirement-report-receipt", 3730)?,
        )?;
        check_report(&s.responder, &report)?;
        assert_eq!(
            report.as_bytes(),
            read(&s.responder, "retirement-host-report", 8 * 1024 * 1024)?
        );
        owner.close();
    }
    stage(&s.responder, 5, "report-reopen", 0, client)?;
    stage(&s.responder, 6, "prepare-ack", 0, client)?;
    {
        let mut controller = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?;
        controller.acknowledge_retired_report(&expected)?;
        store(
            &s.responder,
            "retirement-ack",
            &controller.retired_report_acknowledgement_receipt(&expected)?,
        )?;
    }
    stage(&s.responder, 7, "erase-journal", 77, client)?;
    stage(&s.responder, 8, "erase-signer", 77, client)?;
    stage(&s.responder, 9, "verify", 0, client)?;
    // Keep operational-owner refusal independently checked even when the eight
    // cleanup processes execute through a foreign language adapter.
    assert!(matches!(
        p::DeviceEnrollment::open(
            enrollment::paths(&s.responder)?,
            enrollment::intent(&s.responder)?
        ),
        Err(p::DurableError::Suspended)
    ));
    assert!(p::DeviceSigningKey::open(
        &s.responder.join("signer.key"),
        &key(&s.responder)?,
        p::SigningKeyId::from_trusted_state(array(&s.responder, "signer-id")?)?,
    )
    .is_err());
    assert_eq!(fs::read(s.responder.join("signer.key"))?, b"QPSRET01");
    effect(&s.responder, session, message, OLD_PAYLOAD)?;
    initiator.service.parts()?.0.admit_peer_roster(
        &next.roster,
        old_context.current_policy()?,
        now()?,
    )?;
    let new_context = context(&next.peer, &initiator.policy_store, now()?)?;
    initiator.context = Arc::clone(&new_context);
    initiator.peer_certificate = read(&next.peer, "tls-peer", 8192)?;
    initiator.peer_name = String::from_utf8(read(&next.peer, "tls-peer-name", 256)?)?;
    let endpoint = ConnectionEndpoint::client(&new_context, initiator.credentials(), tls_limits())?;
    let (mut server, address) =
        traffic(&next.path, "bootstrap", None, client, &witness.configured)?;
    let peer_name = initiator.peer_name.clone();
    let fresh = endpoint
        .establish(
            initiator.actor()?,
            p::InitiationId::generate()?,
            Run {
                address,
                server_name: &peer_name,
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            now,
        )?
        .session;
    finish_traffic(
        &mut server,
        &next.path,
        "bootstrap",
        fresh,
        None,
        client.is_some(),
    )?;
    assert_ne!(fresh, session);
    let fresh_message =
        initiator
            .service
            .stores()?
            .0
            .next_message_id(&new_context, fresh, now()?)?;
    let (mut server, address) = traffic(
        &next.path,
        "message",
        Some(fresh),
        client,
        &witness.configured,
    )?;
    send(
        &mut initiator,
        &endpoint,
        address,
        fresh,
        fresh_message,
        NEW_PAYLOAD,
    )?;
    finish_traffic(
        &mut server,
        &next.path,
        "message",
        fresh,
        Some(fresh_message),
        client.is_some(),
    )?;
    effect(&next.path, fresh, fresh_message, NEW_PAYLOAD)?;
    let witness_requests = u64::try_from(witness.request_count()?)?
        .checked_add(u64::from(client.is_some()))
        .ok_or("witness request census overflow")?;
    assert!(witness_requests > 0 && witness_requests <= 512);
    let public = root.join("public");
    fs::DirBuilder::new().mode(0o700).create(&public)?;
    let traffic_trace = if client.is_some() {
        let mut trace = String::new();
        for mode in ["bootstrap", "message"] {
            let pid =
                u64::from_be_bytes(array(&next.path, &format!("successor-traffic-{mode}.pid"))?);
            trace.push_str(&format!("{mode} {pid}\n"));
        }
        trace.into_bytes()
    } else {
        b"native\n".to_vec()
    };
    store(&public, "successor-traffic-trace", &traffic_trace)?;
    store(
        &public,
        "witness-request-count",
        &witness_requests.to_be_bytes(),
    )?;
    for name in [
        "witness-id",
        "witness-public",
        "witness-subject",
        "retirement-proposal",
        "retirement-receipt",
        "retirement-inventory",
        "retirement-inventory-receipt",
        "retirement-report-proposal",
        "retirement-report-receipt",
        "retirement-host-report",
        "retirement-host-report-verified",
        "retirement-report-reopened",
        "retirement-ack",
        "retirement-verified",
    ] {
        store(&public, name, &read(&s.responder, name, 8 * 1024 * 1024)?)?;
    }
    for mode in [
        "inventory",
        "prepare-report",
        "report",
        "report-reopen",
        "prepare-ack",
        "erase-journal",
        "erase-signer",
        "verify",
    ] {
        let name = format!("retirement-process-{mode}");
        store(&public, &name, &array::<8>(&s.responder, &name)?)?;
    }
    store(
        &public,
        "old-effect",
        &read(
            &s.responder,
            &format!("application-{}", hex(message.as_bytes())),
            65536,
        )?,
    )?;
    store(
        &public,
        "new-effect",
        &read(
            &next.path,
            &format!("application-{}", hex(fresh_message.as_bytes())),
            65536,
        )?,
    )?;
    store(
        &public,
        "successor-enrollment-trace",
        &read(&next.path, "successor-enrollment-trace", 8192)?,
    )?;
    store(
        &public,
        "signer-terminal",
        &fs::read(s.responder.join("signer.key"))?,
    )?;
    store(&public, "result.json", format!("{{\"old_session\":\"{}\",\"old_message\":\"{}\",\"new_session\":\"{}\",\"new_message\":\"{}\",\"report_id\":\"{}\",\"report_sessions\":1,\"unconsumed_deliveries\":1,\"consumed_before\":0,\"host_effects\":1,\"recovery_processes\":8,\"uncertain_process_exits\":3,\"required_witness\":true,\"old_authority_refused\":true,\"original_report_reopened\":true,\"journal_erased\":true,\"signer_erased\":true}}\n", hex(&session), hex(message.as_bytes()), hex(&fresh), hex(fresh_message.as_bytes()), hex(expected.report_id())).as_bytes())?;
    initiator.close();
    witness.join()?;
    eprintln!("PUBLIC_DEVICE_RETIREMENT required_witness=true complete_report=true recovery_processes=8 fresh_generation_tls=true");
    Ok(())
}
