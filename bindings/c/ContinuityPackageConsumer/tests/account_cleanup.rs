// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real installed C whole-account cleanup fixtures and independent native readback.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
use q_periapt_continuity_identity_candidate as p;
use std::{
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PAYLOAD: &[u8] = b"persisted before process exit";
const AD: &[u8] = b"owned-service";

fn paths(path: &Path) -> Result<p::InstallationPaths> {
    Ok(p::InstallationPaths::new(
        &path.join("installation.redb"),
        &path.join("journal.redb"),
        &path.join("archives.redb"),
    )?)
}
fn selected() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("QPC_TEST_PATH").ok_or("original account path missing")?,
    ))
}
fn bytes_id(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 {
        return Err("ID encoding length".into());
    }
    let mut id = [0; 32];
    for (out, part) in id.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *out = u8::from_str_radix(std::str::from_utf8(part)?, 16)?;
    }
    Ok(id)
}
fn discovery(path: &Path) -> Result<p::InstallationRecovery> {
    Ok(p::InstallationRecovery::open(
        paths(path)?,
        p::JournalKey::open(&path.join("wrap.key"))?,
    )?)
}
fn batch(path: &Path) -> Result<p::FanoutId> {
    Ok(p::FanoutId::from_trusted_state(fixture::array(
        path,
        "cleanup-batch",
    )?)?)
}
fn command_log(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("C command log exceeded bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}
fn client(path: &Path, label: &str, arguments: &[OsString]) -> Result<String> {
    let executable =
        PathBuf::from(std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("C client missing")?);
    if !executable.is_absolute() || !executable.is_file() {
        return Err("C client path".into());
    }
    let stdout = format!("cleanup-{label}.stdout");
    let stderr = format!("cleanup-{label}.stderr");
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(&stdout))?;
    let error = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(&stderr))?;
    let mut child = fixture::OwnedChild(
        Command::new(executable)
            .args(arguments)
            .stdout(Stdio::from(output))
            .stderr(Stdio::from(error))
            .spawn()?,
    );
    let status = fixture::wait(&mut child)?;
    let output = command_log(&path.join(stdout))?;
    let error = command_log(&path.join(stderr))?;
    if !status.success() || !error.is_empty() {
        return Err(format!("C cleanup command failed: {status}: {error}").into());
    }
    Ok(output)
}

#[test]
fn prepare_account_cleanup_case() -> Result<()> {
    let (setup, second) = fixture::setup_devices(None, None, None, true)?;
    let second = second.ok_or("second account member")?;
    let root = &setup.initiator;
    let peer_paths = [root.join("peer-0"), root.join("peer-1")];
    let (mut server0, address0) = fixture::spawn(&setup.responder, 90, "bootstrap")?;
    let (mut server1, address1) = fixture::spawn(&second, 91, "bootstrap")?;
    let args = vec![
        "account-connect".into(),
        root.as_os_str().to_owned(),
        peer_paths
            .first()
            .ok_or("peer zero")?
            .as_os_str()
            .to_owned(),
        peer_paths.get(1).ok_or("peer one")?.as_os_str().to_owned(),
        address0.to_string().into(),
        address1.to_string().into(),
        fixture::hex(p::InitiationId::generate()?.as_bytes()).into(),
        fixture::hex(p::InitiationId::generate()?.as_bytes()).into(),
    ];
    let output = client(root, "connect", &args)?;
    assert!(fixture::wait(&mut server0)?.success());
    assert!(fixture::wait(&mut server1)?.success());
    let sessions = output.lines().map(bytes_id).collect::<Result<Vec<_>>>()?;
    assert_eq!(sessions.len(), 2);
    let mut sdk = fixture::sdk(root)?;
    let policy = fixture::protocol_policy(root, &sdk)?;
    let contexts = peer_paths
        .iter()
        .map(|path| {
            fixture::with_bundle_for_family(
                path,
                fixture::array(root, "family")?,
                |bundle, requirements| {
                    Ok(Arc::new(bundle.verify(
                        Arc::clone(&policy),
                        requirements,
                        fixture::now()?,
                    )?))
                },
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let local = contexts
        .first()
        .ok_or("first context")?
        .device(p::BootstrapRole::Initiator);
    let key = p::JournalKey::open(&root.join("wrap.key"))?;
    let installation =
        p::DeviceInstallation::open(paths(root)?, &key, local, &policy, fixture::now()?)?;
    let mut service = installation.activate(key, local, &policy, fixture::now()?, None)?;
    for (path, session) in peer_paths.iter().zip(&sessions) {
        fixture::with_bundle_for_family(
            path,
            fixture::array(root, "family")?,
            |bundle, requirements| {
                let request = bundle.request_reopen(
                    Arc::clone(&policy),
                    requirements,
                    p::BootstrapRole::Initiator,
                    *session,
                    fixture::now()?,
                )?;
                service.reopen_peer(request, fixture::now()?)?;
                Ok(())
            },
        )?;
    }
    let account = fixture::array::<32>(&setup.responder, "local-account")?;
    let targets = contexts
        .iter()
        .zip(&sessions)
        .map(|(context, session)| p::FanoutTarget {
            context,
            session: *session,
        })
        .collect::<Vec<_>>();
    let old = service.stores()?.0.next_fanout_id()?;
    let outputs = service.stores()?.0.send_account_message(
        p::FanoutInput {
            id: old,
            account,
            targets: &targets,
            plaintext: PAYLOAD,
            associated_data: AD,
        },
        fixture::now()?,
    )?;
    assert_eq!(outputs.len(), 2);
    for member in outputs {
        let p::FanoutOutput::Committed(wire) = member.output else {
            return Err("prior account output missing".into());
        };
        fixture::store(
            root,
            &format!("cleanup-old-wire-{}", fixture::hex(&member.device)),
            &wire,
        )?;
        fixture::store(
            root,
            &format!("cleanup-old-message-{}", fixture::hex(&member.device)),
            member.message.as_bytes(),
        )?;
    }
    for (index, ((context, session), receiver)) in contexts
        .iter()
        .zip(&sessions)
        .zip([&setup.responder, &second])
        .enumerate()
    {
        let mut peer = fixture::Peer::open(receiver)?;
        for position in 0..(3 + index) {
            let message = peer.service.stores()?.0.next_message_id(
                &peer.context,
                *session,
                fixture::now()?,
            )?;
            let payload = vec![u8::try_from(position)?; 7 + index + position];
            let wire = peer.service.stores()?.0.send_message(
                &peer.context,
                *session,
                message,
                &payload,
                AD,
                fixture::now()?,
            )?;
            if position != 1 {
                let received = service.stores()?.0.receive_message(
                    context,
                    *session,
                    &wire,
                    AD,
                    fixture::now()?,
                )?;
                assert_eq!(received.message_id(), message);
                assert_eq!(received.as_bytes(), payload);
                fixture::store(
                    root,
                    &format!("cleanup-incoming-{index}-{position}"),
                    message.as_bytes(),
                )?;
            }
        }
        fixture::store(
            root,
            &format!("cleanup-device-{index}"),
            &fixture::array::<16>(receiver, "local-device")?,
        )?;
        peer.close();
    }
    let next = service.stores()?.0.next_fanout_id()?;
    fixture::store(root, "cleanup-batch", next.as_bytes())?;
    fixture::store(root, "cleanup-account", &account)?;
    for (index, session) in sessions.iter().enumerate() {
        fixture::store(root, &format!("cleanup-session-{index}"), session)?;
        let context = contexts.get(index).ok_or("original member context")?;
        fixture::store(root, &format!("cleanup-context-{index}"), &context.digest())?;
        let reserved = service
            .stores()?
            .0
            .next_message_id(context, *session, fixture::now()?)?;
        fixture::store(
            root,
            &format!("cleanup-reserved-{index}"),
            reserved.as_bytes(),
        )?;
    }
    let (revocation, signature) = setup.issuer.policy(2, false)?;
    fixture::store(root, "cleanup-revoke-policy", &revocation)?;
    fixture::store(root, "cleanup-revoke-signature", &signature)?;
    service.close();
    policy.close();
    sdk.close();
    assert!(matches!(
        discovery(root)?.open_account(next, None),
        Err(p::DurableError::Absent)
    ));
    fixture::store(root, "cleanup-prepared", b"two-original-members\n")?;
    Ok(())
}

#[test]
fn observe_account_cleanup_case() -> Result<()> {
    let root = selected()?;
    let phase = match discovery(&root)?.open_account(batch(&root)?, None) {
        Err(p::DurableError::Absent) => "absent",
        Err(error) => return Err(error.into()),
        Ok(mut owner) => {
            let phase = match owner.journal()?.status()? {
                p::FanoutStatus::Reserved => "reserved",
                p::FanoutStatus::Committed => "committed",
                _ => return Err("unexpected aggregate reservation phase".into()),
            };
            owner.close();
            phase
        }
    };
    fixture::store(&root, "cleanup-observed", format!("{phase}\n").as_bytes())?;
    Ok(())
}

#[test]
fn revoke_account_cleanup_case() -> Result<()> {
    let root = selected()?;
    let mut sdk = fixture::sdk(&root)?;
    let trusted = sdk.runtime()?.trusted_state();
    sdk.replace_policy(
        trusted,
        &fixture::read(&root, "cleanup-revoke-policy", 16384)?,
        &fixture::read(&root, "cleanup-revoke-signature", 8192)?,
    )?;
    assert!(!sdk.runtime()?.is_enabled()?);
    sdk.close();
    fixture::store(&root, "cleanup-revoked", b"operational-policy-disabled\n")?;
    Ok(())
}

fn encode(report: &p::FanoutAbandonment) -> Result<String> {
    let p::FanoutAbandonment {
        batch,
        report,
        sessions,
    } = report;
    let mut text = format!(
        "QPC-C-ACCOUNT-LOSS/1\nbatch {}\nreport {}\nmembers {}\n",
        fixture::hex(batch.as_bytes()),
        fixture::hex(report.as_bytes()),
        sessions.len()
    );
    for (member, value) in sessions.iter().enumerate() {
        let p::AbandonedSession {
            device,
            generation,
            context,
            session,
            role,
            progress,
            reserved,
            epochs,
        } = value;
        let p::RekeyProgress {
            confirmed_epoch,
            sending_epoch,
            receiving_epoch,
            pending_epoch,
        } = progress;
        writeln!(text,"member {member} {} {} {} {role} {generation} {confirmed_epoch} {sending_epoch} {receiving_epoch} {} {} {}",fixture::hex(device),fixture::hex(context),fixture::hex(session),u8::from(pending_epoch.is_some()),pending_epoch.unwrap_or(0),epochs.len())?;
        let p::ReservedAbandonment {
            message,
            plaintext_bytes,
            associated_data_bytes,
        } = reserved;
        writeln!(
            text,
            "reserved {member} {} {plaintext_bytes} {associated_data_bytes}",
            fixture::hex(message.as_bytes())
        )?;
        for (index, value) in epochs.iter().enumerate() {
            let p::AbandonedEpoch {
                epoch,
                acknowledged_before,
                sent,
                consumed_before,
                received,
                peer_sent,
                resolution,
                unconfirmed,
                deliveries,
                skipped,
            } = value;
            let (phase, id) = match resolution {
                p::EpochResolutionStatus::Unrequested => (0, [0; 32]),
                p::EpochResolutionStatus::Pending(id) => (1, *id.as_bytes()),
                p::EpochResolutionStatus::Acknowledged(id) => (2, *id.as_bytes()),
            };
            writeln!(text,"epoch {member} {index} {epoch} {acknowledged_before} {sent} {consumed_before} {received} {} {} {phase} {} {} {} {}",u8::from(peer_sent.is_some()),peer_sent.unwrap_or(0),fixture::hex(&id),unconfirmed.len(),deliveries.len(),skipped.len())?;
            for (j, message) in unconfirmed.iter().enumerate() {
                writeln!(
                    text,
                    "unconfirmed {member} {index} {j} {} {}",
                    fixture::hex(message.message_id().as_bytes()),
                    fixture::hex(message.ciphertext_digest())
                )?;
            }
            for (j, value) in deliveries.iter().enumerate() {
                let p::AbandonedDelivery {
                    message,
                    index: position,
                    plaintext_bytes,
                } = value;
                writeln!(
                    text,
                    "delivery {member} {index} {j} {} {position} {plaintext_bytes}",
                    fixture::hex(message.as_bytes())
                )?;
            }
            for (j, position) in skipped.iter().enumerate() {
                writeln!(text, "skipped {member} {index} {j} {position}")?;
            }
        }
    }
    Ok(text)
}

#[test]
fn compare_account_cleanup_report() -> Result<()> {
    let root = selected()?;
    let id = batch(&root)?;
    let mut owner = discovery(&root)?.open_account(id, None)?;
    let p::FanoutStatus::Abandoning(report_id) = owner.journal()?.status()? else {
        return Err("C did not freeze the complete account".into());
    };
    let report = owner.journal()?.begin()?;
    assert_eq!(report.batch, id);
    assert_eq!(report.report, report_id);
    assert_eq!(report.sessions.len(), 2);
    for member in &report.sessions {
        assert_eq!(member.reserved.plaintext_bytes, PAYLOAD.len());
        assert_eq!(member.reserved.associated_data_bytes, AD.len());
        assert_eq!(member.epochs.len(), 1);
        let epoch = member.epochs.first().ok_or("account epoch")?;
        assert_eq!(epoch.sent, 1);
        assert_eq!(epoch.acknowledged_before, 0);
        assert_eq!(epoch.unconfirmed.len(), 1);
        assert_eq!(epoch.skipped, vec![1]);
        let index = if member.device == fixture::array::<16>(&root, "cleanup-device-0")? {
            0
        } else {
            assert_eq!(
                member.device,
                fixture::array::<16>(&root, "cleanup-device-1")?
            );
            1
        };
        assert_eq!(epoch.deliveries.len(), 2 + index);
        assert_eq!(epoch.received, u64::try_from(3 + index)?);
        assert_eq!(
            member.session,
            fixture::array::<32>(&root, &format!("cleanup-session-{index}"))?
        );
    }
    let encoded = encode(&report)?;
    assert_eq!(
        fixture::read(&root, "c-account-loss-report", 1048576)?,
        encoded.as_bytes()
    );
    owner.close();
    fixture::store(&root, "native-account-loss-report", encoded.as_bytes())?;
    Ok(())
}

#[test]
fn verify_account_cleanup_terminal() -> Result<()> {
    let root = selected()?;
    let result = discovery(&root)?.open_account(batch(&root)?, None);
    assert!(matches!(
        result,
        Err(p::DurableError::Protocol(p::Error::Retired))
    ));
    for index in 0..2 {
        let session = fixture::array::<32>(&root, &format!("cleanup-session-{index}"))?;
        let mut owner = discovery(&root)?.open_session(session, None)?;
        assert!(matches!(
            owner.stores()?.0.status(),
            Err(p::DurableError::Suspended)
        ));
        assert!(matches!(
            owner.stores()?.0.begin(),
            Err(p::DurableError::Suspended)
        ));
        owner.close();
    }
    fixture::store(
        &root,
        "cleanup-terminal-verified",
        b"account-retired-independent-closure-refused\n",
    )?;
    Ok(())
}
