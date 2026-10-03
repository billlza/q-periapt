// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public installed-archive fixtures for external process-interruption tests.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
use q_periapt_continuity_identity_candidate as p;
use std::{path::PathBuf, process::Command};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PAYLOAD: &[u8] = b"persisted before process exit";
const AD: &[u8] = b"owned-service";
fn bytes_id(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err("hex identity size".into());
    }
    let mut out = [0; 32];
    for (byte, pair) in out.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(out)
}
fn selected_path() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("QPC_TEST_PATH").ok_or("selected path missing")?,
    ))
}
fn output_id(data: Vec<u8>) -> Result<String> {
    let value = String::from_utf8(data)?;
    if value.len() != 65
        || !value.ends_with('\n')
        || !value
            .as_bytes()
            .get(..64)
            .ok_or("ID prefix")?
            .iter()
            .all(u8::is_ascii_hexdigit)
    {
        return Err("C ID output differs".into());
    }
    Ok(value.trim().to_owned())
}
#[test]
fn prepare_fault_case() -> Result<()> {
    let setup = fixture::setup()?;
    let client =
        PathBuf::from(std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("C client missing")?);
    let request = p::InitiationId::generate()?;
    let (mut server, address) = fixture::spawn(&setup.responder, 81, "bootstrap")?;
    let connected = Command::new(&client)
        .arg("connect")
        .arg(&setup.initiator)
        .args([address.to_string(), fixture::hex(request.as_bytes())])
        .output()?;
    assert!(connected.status.success(), "C connect: {:?}", connected);
    assert!(connected.stderr.is_empty());
    let session = output_id(connected.stdout)?;
    assert!(fixture::wait(&mut server)?.success());
    let next = Command::new(client)
        .arg("next")
        .arg(&setup.responder)
        .arg(&session)
        .output()?;
    assert!(next.status.success(), "C next: {:?}", next);
    assert!(next.stderr.is_empty());
    let message = output_id(next.stdout)?;
    fixture::store(&setup.responder, "fault-session", &bytes_id(&session)?)?;
    fixture::store(&setup.responder, "fault-message", &bytes_id(&message)?)?;
    let (policy, signature) = setup.issuer.policy(2, false)?;
    fixture::store(&setup.responder, "fault-revoke-policy", &policy)?;
    fixture::store(&setup.responder, "fault-revoke-signature", &signature)?;
    let mut peer = fixture::Peer::open(&setup.responder)?;
    let context = fixture::hex(&peer.context.digest());
    let archive = peer.service.stores()?.1.get(bytes_id(&session)?)?;
    fixture::store(
        &setup.responder,
        "native-closure-archive",
        archive.as_bytes(),
    )?;
    peer.close();
    let account = fixture::hex(&fixture::array::<32>(
        &setup.responder,
        "initiator-account",
    )?);
    let device = fixture::hex(&fixture::array::<16>(&setup.responder, "initiator-device")?);
    fixture::store(
        &setup.responder,
        "fault-plan.json",
        format!("{{\"session\":\"{session}\",\"message\":\"{message}\",\"context\":\"{context}\",\"peer_account\":\"{account}\",\"peer_device\":\"{device}\"}}\n").as_bytes(),
    )?;
    Ok(())
}
#[test]
fn observe_fault_case() -> Result<()> {
    let path = selected_path()?;
    let session = fixture::array(&path, "fault-session")?;
    let message = p::MessageId::from_trusted_state(fixture::array(&path, "fault-message")?)?;
    let mut peer = fixture::Peer::open(&path)?;
    let status = peer
        .service
        .stores()?
        .0
        .message_status(&peer.context, session, message)?;
    let number = match status {
        p::MessageStatus::Absent => 1,
        p::MessageStatus::Reserved => 2,
        p::MessageStatus::Committed => 3,
        _ => return Err("unexpected pre-cleanup disposition".into()),
    };
    if number == 3 {
        let wire = peer.service.stores()?.0.send_message(
            &peer.context,
            session,
            message,
            PAYLOAD,
            AD,
            fixture::now()?,
        )?;
        fixture::store(&path, "fault-wire", &wire)?;
    }
    if number == 2 {
        assert!(matches!(
            peer.service.stores()?.0.send_message(
                &peer.context,
                session,
                message,
                b"different",
                AD,
                fixture::now()?
            ),
            Err(p::DurableError::Conflict)
        ));
        assert_eq!(
            peer.service
                .stores()?
                .0
                .message_status(&peer.context, session, message)?,
            p::MessageStatus::Reserved
        );
    }
    peer.close();
    fixture::store(
        &path,
        "fault-native-status",
        match number {
            1 => b"absent\n",
            2 => b"reserved\n",
            3 => b"committed\n",
            _ => return Err("unknown native status".into()),
        },
    )?;
    Ok(())
}
#[test]
fn revoke_fault_case() -> Result<()> {
    let path = selected_path()?;
    let policy = fixture::read(&path, "fault-revoke-policy", 16384)?;
    let signature = fixture::read(&path, "fault-revoke-signature", 8192)?;
    let mut store = fixture::sdk(&path)?;
    let prior = store.runtime()?.trusted_state();
    store.replace_policy(prior, &policy, &signature)?;
    assert!(!store.runtime()?.is_enabled()?);
    store.close();
    Ok(())
}
#[test]
fn verify_closed_fault_case() -> Result<()> {
    let path = selected_path()?;
    let archive = p::SessionClosureArchive::from_bytes(&fixture::read(
        &path,
        "native-closure-archive",
        1024,
    )?)?;
    let report = String::from_utf8(fixture::read(&path, "c-loss-report", 1048576)?)?;
    let header = report
        .lines()
        .nth(1)
        .ok_or("report line")?
        .strip_prefix("report ")
        .ok_or("report ID")?;
    let expected = bytes_id(header)?;
    let paths = p::InstallationPaths::new(
        &path.join("installation.redb"),
        &path.join("journal.redb"),
        &path.join("archives.redb"),
    )?;
    let mut recovery =
        p::InstallationRecovery::open(paths, p::JournalKey::open(&path.join("wrap.key"))?)?;
    assert!(recovery.session_ids()?.is_empty());
    let mut session = recovery.open_session_from_archive(&archive, None)?;
    let p::SessionClosureStatus::Closed(id) = session.stores()?.0.status()? else {
        return Err("not closed".into());
    };
    assert_eq!(*id.as_bytes(), expected);
    session.close();
    Ok(())
}
#[test]
fn inspect_closure_fault_case() -> Result<()> {
    let path = selected_path()?;
    let paths = p::InstallationPaths::new(
        &path.join("installation.redb"),
        &path.join("journal.redb"),
        &path.join("archives.redb"),
    )?;
    let recovery =
        p::InstallationRecovery::open(paths, p::JournalKey::open(&path.join("wrap.key"))?)?;
    let mut session = recovery.open_session(fixture::array(&path, "fault-session")?, None)?;
    let (phase, id) = match session.stores()?.0.status()? {
        p::SessionClosureStatus::Open => ("open", String::new()),
        p::SessionClosureStatus::Pending(id) => ("pending", fixture::hex(id.as_bytes())),
        p::SessionClosureStatus::Closed(id) => ("closed", fixture::hex(id.as_bytes())),
    };
    session.close();
    fixture::store(
        &path,
        "fault-closure-phase",
        format!("{phase} {id}\n").as_bytes(),
    )?;
    Ok(())
}
