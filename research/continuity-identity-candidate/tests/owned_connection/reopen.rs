// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public-only reconstruction after explicit test-clock advertisement expiry.
use super::*;

fn open_existing(path: &Path, at: u64) -> Result<Peer> {
    let policy_store = sdk(path)?;
    let policy = protocol_policy(path, &policy_store)?;
    let local_role = role(path)?;
    let session = array(path, "session")?;
    let request = with_bundle(path, |bundle, requirements| {
        Ok(bundle.request_reopen(Arc::clone(&policy), requirements, local_role, session, at)?)
    })?;
    let key = key(path)?;
    let signer = p::DeviceSigningKey::open(
        &path.join("signer.key"),
        &key,
        p::SigningKeyId::from_trusted_state(array(path, "signer-id")?)?,
    )?;
    let restored = p::DeviceInstallation::reopen_session(paths(path)?, key, request, at, None)?;
    assert_eq!(restored.session_id(), session);
    assert_eq!(restored.role(), local_role);
    let (service, context) = restored.into_parts();
    assert!(std::ptr::eq(Arc::as_ptr(&policy), context.policy()));
    Ok(Peer {
        service,
        signer,
        context,
        policy_store,
        certificate: read(path, "tls-cert", 8192)?,
        tls_key: Zeroizing::new(read(path, "tls-key", 8192)?),
        peer_certificate: read(path, "tls-peer", 8192)?,
        peer_name: String::from_utf8(read(path, "tls-peer-name", 128)?)?,
    })
}
pub(super) fn serve_reopened(path: &Path, attempt: u8) -> Result<()> {
    let at = u64::from_be_bytes(array(path, "reopen-test-time")?);
    serve_restored(path, attempt, "application", || Ok(at))
}
pub(super) fn serve_restored_current(path: &Path, attempt: u8, mode: &str) -> Result<()> {
    serve_restored(path, attempt, mode, now)
}
fn serve_restored(
    path: &Path,
    attempt: u8,
    mode: &str,
    mut clock: impl FnMut() -> io::Result<u64>,
) -> Result<()> {
    let mut peer = open_existing(path, clock()?)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = ConnectionEndpoint::server(&peer.context, peer.credentials(), tls_limits())?;
    publish_ready(path, &format!("ready-{attempt}"), listener.local_addr()?)?;
    let mut application = Application {
        path: path.into(),
        mode: mode.into(),
    };
    endpoint.serve(
        accept(&listener)?,
        peer.actor()?,
        &mut application,
        limits(),
        &Cancellation::default(),
        clock,
    )?;
    peer.close();
    Ok(())
}

#[test]
fn public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls() -> Result<()> {
    // Advance only the injected protocol clock after a real bootstrap. TLS uses
    // its ordinary certificate clock. No wall-clock mutation or sleep races.
    let s = setup_with_advertisement(None, Some(600))?;
    let mut client = Peer::open(&s.initiator)?;
    let endpoint = ConnectionEndpoint::client(&client.context, client.credentials(), tls_limits())?;
    let (mut server, address) = spawn(&s.responder, 0, "bootstrap")?;
    let name = client.peer_name.clone();
    let established = endpoint.establish(
        client.actor()?,
        p::InitiationId::generate()?,
        Run {
            address,
            server_name: &name,
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        now,
    )?;
    assert!(wait(&mut server)?.success());
    store(&s.initiator, "session", &established.session)?;
    assert_eq!(array::<32>(&s.responder, "session")?, established.session);
    let original_context = client.context.digest();
    let context = Arc::clone(&client.context);
    let id = client
        .service
        .stores()?
        .0
        .next_message_id(&context, established.session, now()?)?;
    let body = b"original application commit before advertisement expiry";
    let (mut server, address) = spawn(&s.responder, 1, "crash-after-application")?;
    assert!(send(
        &mut client,
        &endpoint,
        address,
        established.session,
        id,
        body
    )
    .is_err());
    assert_eq!(wait(&mut server)?.code(), Some(77));
    effect(&s.responder, established.session, id, body)?;
    let original_wire =
        client
            .service
            .stores()?
            .0
            .resume_message(&context, established.session, id, now()?)?;
    let public_root = s.initiator.parent().ok_or("evidence root")?;
    store(public_root, "original-outbox", &original_wire)?;
    client.close();
    let at = u64::from_be_bytes(array(&s.initiator, "reopen-test-time")?);
    let policy_store = sdk(&s.initiator)?;
    let policy = protocol_policy(&s.initiator, &policy_store)?;
    let fresh = with_bundle(&s.initiator, |bundle, required| {
        Ok(bundle.verify(policy, required, at)?)
    });
    assert!(matches!(
        fresh
            .err()
            .and_then(|e| e.downcast::<p::Error>().ok())
            .as_deref(),
        Some(p::Error::Validity)
    ));
    drop(policy_store);
    let mut client = open_existing(&s.initiator, at)?;
    assert_eq!(client.context.digest(), original_context);
    let context = Arc::clone(&client.context);
    assert_eq!(
        client
            .service
            .stores()?
            .0
            .resume_message(&context, established.session, id, at)?,
        original_wire
    );
    store(
        public_root,
        "restored-outbox",
        &client
            .service
            .stores()?
            .0
            .resume_message(&context, established.session, id, at)?,
    )?;
    let endpoint = ConnectionEndpoint::client(&client.context, client.credentials(), tls_limits())?;
    let (mut server, address) = spawn(&s.responder, 2, "reopen-application")?;
    let name = client.peer_name.clone();
    let delivered = endpoint.send(
        client.actor()?,
        Submission {
            session: established.session,
            message: id,
            plaintext: body,
            associated_data: b"owned-service",
        },
        Run {
            address,
            server_name: &name,
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        || Ok(at),
    )?;
    assert_eq!(delivered.consumption, Consumption::Confirmed);
    assert!(wait(&mut server)?.success());
    effect(&s.responder, established.session, id, body)?;
    assert_eq!(
        client
            .service
            .stores()?
            .0
            .message_status(&context, established.session, id)?,
        p::MessageStatus::Acknowledged
    );
    client.close();
    let mut reopened = open_existing(&s.initiator, at)?;
    let context = Arc::clone(&reopened.context);
    assert_eq!(
        reopened
            .service
            .stores()?
            .0
            .message_status(&context, established.session, id)?,
        p::MessageStatus::Acknowledged
    );
    let report = format!(
        "{{\"session\":\"{}\",\"message\":\"{}\",\"context\":\"{}\",\"test_protocol_time\":{},\"original_context\":true,\"exact_outbox\":true,\"unknown_commit_reconciled\":true,\"fresh_bootstrap_refused\":true,\"independent_processes\":true,\"injected_protocol_clock\":true,\"application_readbacks\":2}}\n",
        hex(&established.session), hex(id.as_bytes()), hex(&original_context), at,
    );
    store(public_root, "public-reopen-result.json", report.as_bytes())?;
    eprintln!("PUBLIC_SESSION_REOPEN original_context=true exact_outbox=true unknown_commit_reconciled=true app_readbacks=2 independent_processes=true injected_protocol_clock=true");
    Ok(())
}
