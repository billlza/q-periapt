//! The IPC serving loop and its deadlines.

use super::*;

#[test]
fn ipc_rejects_a_response_key_clients_could_not_verify() -> TestResult {
    // A perfectly valid signing key that simply is not the one clients pinned.
    // It signs, and it is a different pair from the request direction, so every
    // other startup check passes. Only comparing a signature against the pinned
    // response key catches it -- and without that the daemon starts, commits
    // state, and only then emits responses every client rejects.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 27)?;
    let (_, client_verification_key) = MlDsa65::generate([95u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([96u8; 32]);
    let (_, unrelated_verification_key) = MlDsa65::generate([99u8; 32]);
    assert!(
        crate::ipc::UnixIpcServer::new_for_test(
            pair.responder,
            client_verification_key,
            ZeroizingBytes::from_bytes(server_signing_key),
            unrelated_verification_key,
        )
        .is_err(),
        "a signing key that does not match the pinned response key must be refused"
    );

    // The matching pair is still accepted, so the check is not simply refusing
    // everything.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 28)?;
    let (server_signing_key_again, _) = MlDsa65::generate([96u8; 32]);
    assert!(crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key_again),
        server_verification_key,
    )
    .is_ok());
    Ok(())
}

#[test]
fn ipc_rejects_one_key_pair_serving_both_directions() -> TestResult {
    // The IPC server verifies requests under the client key and signs responses
    // under its own. One key pair for both directions would let any client
    // authorized to send requests forge responses.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 23)?;
    let (shared_sk, shared_vk) = MlDsa65::generate([93u8; 32]);
    assert!(
        crate::ipc::UnixIpcServer::new_for_test(
            pair.responder,
            shared_vk,
            ZeroizingBytes::from_bytes(shared_sk),
            shared_vk,
        )
        .is_err(),
        "one key pair must not carry both IPC directions"
    );
    Ok(())
}

#[test]
fn a_busy_listener_does_not_starve_the_session_sweep() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair_with_session_ttl(&directory, 53, Duration::from_millis(1))?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
        pair.responder_authorization,
        encapsulated.ciphertexts,
    ))?)?;
    assert_eq!(pair.responder.pending_session_count(), 1);

    let (_, client_verification_key) = MlDsa65::generate([97u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([98u8; 32]);
    let server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let socket_path = directory.join("busy.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let shutdown = AtomicBool::new(false);

    thread::scope(|scope| -> TestResult {
        let serving = scope.spawn(|| {
            let mut server = server;
            let outcome = server.serve_for_test(listener, &shutdown);
            (server, outcome)
        });

        // Keep the listener continuously readable for longer than one
        // maintenance interval. Each connection is dropped without sending a
        // request, which is the cheapest way a client can hold the loop's
        // attention -- and exactly what an unauthenticated peer can do.
        let hammering = Instant::now();
        while hammering.elapsed() < Duration::from_millis(1_400) {
            if let Ok(connection) = std::os::unix::net::UnixStream::connect(&socket_path) {
                drop(connection);
            }
        }
        shutdown.store(true, Ordering::Release);
        // Unblock the final wait so the loop observes the flag promptly.
        let _ = std::os::unix::net::UnixStream::connect(&socket_path);
        let (returned, outcome) = serving
            .join()
            .map_err(|_| io::Error::other("serving thread panicked"))?;
        outcome?;

        // The session expired 1.4s ago. Tying the sweep to an idle wait would
        // leave it here forever, because the wait never timed out.
        assert_eq!(
            returned.agent_for_test().pending_session_count(),
            0,
            "a continuously busy listener starved the session sweep"
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn the_serving_loop_answers_over_a_real_socket_and_stops_on_shutdown() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 31)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([95u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([96u8; 32]);
    let server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let socket_path = directory.join("serve.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || {
        let mut server = server;
        server.serve_for_test(listener, &server_shutdown)
    });

    // The only test that drives the accept path itself: the non-blocking
    // listener, the poll readiness report, and putting the accepted stream back
    // into blocking mode so the handler's SO_RCVTIMEO deadlines behave. An
    // accepted socket inherits non-blocking mode on the BSDs but not on Linux,
    // so this covers a difference the unit tests cannot see.
    let nonce = [26u8; 32];
    let mut client = std::os::unix::net::UnixStream::connect(&socket_path)?;
    client.write_all(&framed_accept_initiator_request(
        &client_signing_key,
        nonce,
        decapsulated.handle,
        encapsulated.initiator_finished,
    )?)?;
    // The server serves one request per connection and then drops the stream,
    // so the read ends when it closes.
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let (key_handle, responder_finished) =
        decode_responder_acceptance_response(&response, &server_verification_key, nonce)?;
    assert!(!key_handle.iter().all(|byte| *byte == 0));
    assert!(!responder_finished.iter().all(|byte| *byte == 0));

    // The loop reads the flag once per accept wait, so it stops within one
    // maintenance interval rather than needing a connection to wake it.
    shutdown.store(true, Ordering::Release);
    server_thread
        .join()
        .map_err(|_| io::Error::other("serving thread panicked"))??;
    Ok(())
}

#[test]
fn the_response_write_budget_does_not_come_out_of_the_request_deadline() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 23)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([93u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([94u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let mut transport = WriteBudgetTransport {
        input: Cursor::new(framed_accept_initiator_request(
            &client_signing_key,
            [24u8; 32],
            decapsulated.handle,
            encapsulated.initiator_finished,
        )?),
        output: Vec::new(),
        write_timeout: std::cell::Cell::new(None),
    };
    // A request deadline with almost nothing left on it, standing in for an
    // operation whose execution consumed the budget. A real advance does this
    // routinely: the witness and authority timeouts together outlast a single
    // IPC timeout.
    let read_deadline = Instant::now()
        .checked_add(Duration::from_millis(50))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    server.handle_io_with_deadline_for_test(&mut transport, read_deadline)?;

    // The response was written on a fresh budget, not on the sliver left of the
    // request's. Sharing the deadline would have failed the write outright and
    // left the client unable to learn the outcome of a committed operation.
    let granted = transport
        .write_timeout
        .get()
        .ok_or_else(|| io::Error::other("no write timeout was set"))?;
    assert!(
        granted > Duration::from_millis(50),
        "response write budget {granted:?} came out of the request deadline"
    );
    assert!(!transport.output.is_empty());
    Ok(())
}

#[test]
fn ipc_write_failure_can_recover_exact_acceptance_with_a_new_nonce() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 17)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([91u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([92u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let first_nonce = [21u8; 32];
    let first_request = framed_accept_initiator_request(
        &client_signing_key,
        first_nonce,
        decapsulated.handle,
        encapsulated.initiator_finished,
    )?;
    let mut failed_write = FailingWriteTransport {
        input: Cursor::new(first_request.clone()),
    };
    assert_eq!(
        server.handle_io_for_test(&mut failed_write),
        Err(crate::ipc::IpcError::Unavailable)
    );
    assert_eq!(
        server.agent_for_test().acceptance_counts_for_test()?,
        (1, 1)
    );

    let mut replayed_nonce = CaptureTransport {
        input: Cursor::new(first_request),
        output: Vec::new(),
    };
    assert_eq!(
        server.handle_io_for_test(&mut replayed_nonce),
        Err(crate::ipc::IpcError::AuthenticationFailed)
    );
    assert!(replayed_nonce.output.is_empty());

    let cached = server
        .agent_for_test()
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    let retry_nonce = [22u8; 32];
    let mut retried = CaptureTransport {
        input: Cursor::new(framed_accept_initiator_request(
            &client_signing_key,
            retry_nonce,
            decapsulated.handle,
            encapsulated.initiator_finished,
        )?),
        output: Vec::new(),
    };
    server.handle_io_for_test(&mut retried)?;
    let (key_handle, responder_finished) = decode_responder_acceptance_response(
        &retried.output,
        &server_verification_key,
        retry_nonce,
    )?;
    assert_eq!(key_handle, *cached.key_handle.as_bytes());
    assert_eq!(responder_finished, *cached.responder_finished.as_bytes());
    assert_eq!(
        server.agent_for_test().acceptance_counts_for_test()?,
        (1, 1)
    );
    server.agent_for_test().destroy_key(cached.key_handle)?;
    assert_eq!(
        server.agent_for_test().acceptance_counts_for_test()?,
        (0, 0)
    );
    Ok(())
}

#[test]
fn ipc_absolute_deadline_evicts_a_pre_auth_trickle_client() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 19)?;
    let (_, client_verification_key) = MlDsa65::generate([93u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([94u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    // A maximum-length frame trickled one byte per 20ms would take minutes;
    // the absolute deadline must fail the connection at ~200ms instead.
    let mut frame = u32::try_from(MAX_FRAME_BYTES)
        .map_err(|_| io::Error::other("IPC frame length does not fit"))?
        .to_be_bytes()
        .to_vec();
    frame.resize(frame.len().saturating_add(512), 0);
    let mut trickle = TricklingTransport {
        input: Cursor::new(frame),
        step: Duration::from_millis(20),
        output: Vec::new(),
    };
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(200))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    let result = server.handle_io_with_deadline_for_test(&mut trickle, deadline);
    let elapsed = started.elapsed();
    assert_eq!(result, Err(crate::ipc::IpcError::InvalidMessage));
    assert!(elapsed >= Duration::from_millis(200));
    assert!(elapsed < Duration::from_secs(10));
    assert!(trickle.output.is_empty());
    Ok(())
}
