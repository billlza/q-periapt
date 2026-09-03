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

/// Frame one Reconcile (command 10) under `nonce`.
fn framed_reconcile(signing_key: &[u8], nonce: [u8; 32]) -> TestResult<Vec<u8>> {
    let mut body = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut body, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC domain encoding failed: {error:?}")))?;
    body.fixed(&nonce)
        .and_then(|()| body.byte(10))
        .map_err(|error| io::Error::other(format!("IPC request encoding failed: {error:?}")))?;
    let envelope = sign_envelope(&body.finish(), signing_key)
        .map_err(|error| io::Error::other(format!("IPC request signing failed: {error:?}")))?;
    let mut framed = Vec::new();
    write_frame(&mut framed, &envelope)
        .map_err(|error| io::Error::other(format!("IPC framing failed: {error:?}")))?;
    Ok(framed)
}

/// The status byte of one framed, signed response to the request under
/// `expected_nonce`.
fn response_status(
    framed: &[u8],
    verification_key: &[u8],
    expected_nonce: [u8; 32],
) -> TestResult<u8> {
    let envelope = read_frame(&mut Cursor::new(framed))
        .map_err(|error| io::Error::other(format!("IPC response framing failed: {error:?}")))?;
    let body = verify_envelope(&envelope, verification_key)
        .map_err(|error| io::Error::other(format!("IPC response signature failed: {error:?}")))?;
    let mut decoder = Decoder::new(body);
    require_domain(&mut decoder, b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC response domain failed: {error:?}")))?;
    let nonce: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response nonce failed: {error:?}")))?;
    assert_eq!(nonce, expected_nonce);
    let _: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response digest failed: {error:?}")))?;
    let status = decoder
        .byte()
        .map_err(|error| io::Error::other(format!("IPC response status failed: {error:?}")))?;
    Ok(status)
}

#[test]
fn the_response_write_budget_comes_from_the_request_deadline_not_the_read_deadline() -> TestResult {
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

    let nonce = [24u8; 32];
    let mut transport = WriteBudgetTransport {
        input: Cursor::new(framed_accept_initiator_request(
            &client_signing_key,
            nonce,
            decapsulated.handle,
            encapsulated.initiator_finished,
        )?),
        output: Vec::new(),
        write_timeout: std::cell::Cell::new(None),
    };
    // A read deadline with almost nothing left on it, standing in for a
    // request whose read phase consumed its budget, under a request deadline
    // with plenty left. The read phase's sliver must not be what the response
    // is written on: a request that took its time to arrive still gets its
    // answer.
    let now = Instant::now();
    let read_deadline = now
        .checked_add(Duration::from_millis(50))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    let request_deadline = now
        .checked_add(Duration::from_secs(10))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    server.handle_io_with_deadlines_for_test(&mut transport, read_deadline, request_deadline)?;

    // The response was written on what the request deadline had left, capped
    // at one I/O timeout -- never on the read deadline's sliver, and never
    // past the request's own deadline.
    let granted = transport
        .write_timeout
        .get()
        .ok_or_else(|| io::Error::other("no write timeout was set"))?;
    assert!(
        granted > Duration::from_millis(50),
        "response write budget {granted:?} came out of the read deadline"
    );
    assert!(
        granted <= Duration::from_secs(5),
        "response write budget {granted:?} exceeds one I/O timeout"
    );
    assert!(
        granted <= request_deadline.saturating_duration_since(now),
        "response write budget {granted:?} runs past the request deadline"
    );
    assert!(!transport.output.is_empty());
    assert_eq!(
        response_status(&transport.output, &server_verification_key, nonce)?,
        0
    );
    Ok(())
}

#[test]
fn a_request_whose_deadline_cannot_cover_the_guarded_operation_is_refused_before_any_round_trip(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 137)?;
    let authority = pair.initiator_authority.clone();
    let (client_signing_key, client_verification_key) = MlDsa65::generate([101u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([102u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;
    // The real transports' bounds: five seconds per round trip. Reconcile's
    // least plan before its own query is two authority round trips and one
    // witness call, fifteen seconds; the request gets two seconds. That is
    // still far below the plan, so the refusal is exactly the one a fifth of a
    // second forced, and strictly below IPC_IO_TIMEOUT, so the write budget
    // asserted below can only have come from the request's own deadline. It is
    // also orders of magnitude above what this path actually costs -- one
    // framed read from a cursor, one ML-DSA-65 verify, the refusal, one
    // ML-DSA-65 sign -- which is the headroom a loaded runner needs: the
    // response write is budgeted from this same deadline, so at 200 ms a
    // scheduling stall made `write_frame_until` fail on a lapsed budget and
    // this test errored `Unavailable` on correct behaviour.
    authority.set_round_trip_bound(Duration::from_secs(5));
    pair.witness.set_round_trip_bound(Duration::from_secs(5));
    // Had the operation started, its coverage snapshot would have paid this.
    // Three seconds is longer than the request's whole deadline, so a snapshot
    // that was actually computed could not be mistaken for a pass: it would
    // blow the elapsed bound below and fail the response write as well.
    authority.delay_next_snapshot(Duration::from_secs(3));
    let lease_calls = authority.lease_call_count();
    let journal = server.agent_for_test().journaled_lease_intents_for_test()?;

    let nonce = [103u8; 32];
    let mut transport = WriteBudgetTransport {
        input: Cursor::new(framed_reconcile(&client_signing_key, nonce)?),
        output: Vec::new(),
        write_timeout: std::cell::Cell::new(None),
    };
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    server.handle_io_with_deadline_for_test(&mut transport, deadline)?;
    let elapsed = started.elapsed();

    // Refused before the first round trip: the delayed snapshot was never
    // requested, no renew was dispatched, nothing was journaled. The armed
    // snapshot delay is three seconds, so a round trip that was really paid
    // lands well past this bound; a second and a half is five times the worst
    // this path has been measured at under full-suite parallelism.
    assert!(
        elapsed < Duration::from_millis(1_500),
        "the refused request still paid for a round trip: {elapsed:?}"
    );
    assert!(
        authority.snapshot_delay_armed(),
        "a snapshot was requested for an operation that could not fit"
    );
    assert_eq!(authority.lease_call_count(), lease_calls);
    assert_eq!(
        server.agent_for_test().journaled_lease_intents_for_test()?,
        journal
    );
    // And answered, with the refusal, on what was left of the request's own
    // deadline -- never on a fresh budget.
    assert_eq!(
        response_status(&transport.output, &server_verification_key, nonce)?,
        24
    );
    let granted = transport
        .write_timeout
        .get()
        .ok_or_else(|| io::Error::other("no write timeout was set"))?;
    assert!(
        granted <= Duration::from_secs(2),
        "response write budget {granted:?} did not come from the request deadline"
    );
    assert_eq!(server.agent_for_test().pending_session_count(), 0);
    // Not a fence: the agent serves on, and a reconcile with a budget of its
    // own gets the answer it always had.
    assert!(server.agent_for_test().public_keys().is_ok());
    assert_eq!(
        server.agent_for_test().reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::NoPendingTransition))
    );
    Ok(())
}

#[test]
fn a_deadline_that_lapses_after_the_durable_reservation_retains_nothing_and_writes_nothing(
) -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 138)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([104u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([105u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;
    // Every port is instantaneous by its bound, so nothing refuses the
    // operation on its plan. The pre-write path -- the frame read, two
    // ML-DSA-65 verifications, the witness round trip and the KEM -- has been
    // measured at about 270 ms alone and 400 ms with the suite running in
    // parallel, in a debug build; the two-second request deadline below is
    // some five times that worst case, so the operation is admitted past the
    // early-out at `ensure_may_retain`. The reservation's four-second fsync
    // then outlives that deadline by two seconds, and the retention gate
    // *after* the write is where the operation learns it.
    server
        .agent_for_test()
        .delay_next_durable_write_for_test(Duration::from_millis(4_000))?;
    let mut transport = CaptureTransport {
        input: Cursor::new(framed_begin(
            &client_signing_key,
            [106u8; 32],
            &pair.initiator_signed_offers,
            &pair.responder_public_keys,
        )?),
        output: Vec::new(),
    };
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(2_000))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    assert_eq!(
        server.handle_io_with_deadline_for_test(&mut transport, deadline),
        Err(crate::ipc::IpcError::Unavailable)
    );
    // The durable reservation ran: the refusal this test is about is the one
    // after the write, not the early-out before it. Without this the test
    // passes green with no coverage the day the pre-write check starts
    // refusing. The slack mirrors the convention in the lease tests: 3_900
    // against a 4_000 ms hook guards only against sleep undershoot on a
    // coarse clock.
    assert!(
        started.elapsed() >= Duration::from_millis(3_900),
        "the durable reservation did not run; the pre-write check refused instead"
    );
    // The deadline was gone when the write began, so nothing was written --
    // not a refusal on a fresh budget, and not a handle.
    assert!(transport.output.is_empty());

    // Durably reserved, never retained: the reservation was released rather
    // than orphaned, and no secret survived the abort.
    let agent = server.agent_for_test();
    assert_eq!(agent.pending_session_count(), 0);
    assert_eq!(agent.durable_session_count_for_test()?, 0);
    assert_eq!(agent.confirmed_key_count(), 0);
    // Not a fence. The offer was consumed by the reservation, so a fresh one
    // under the default budget is what serves.
    assert!(agent.public_keys().is_ok());
    // The reservation was released, but the tombstone it wrote was not: the
    // same offer is refused as the consumed authorization it is, under any
    // deadline. That is what the status-24 contract promises the client.
    assert_eq!(
        agent.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::AuthorizationRejected)
    );
    initiator_encapsulation(agent.begin_encapsulation(BeginEncapsulation::new(
        pair.second_initiator_authorization,
        pair.responder_public_keys,
    ))?)?;
    assert_eq!(agent.pending_session_count(), 1);
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
fn lost_begin_response_is_recovered_by_an_exact_retry_under_a_fresh_nonce() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 142)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([104u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([105u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    // The Begin commits -- a pending secret and its durable reservation --
    // and then its response is lost on the write.
    let first_request = framed_begin(
        &client_signing_key,
        [106u8; 32],
        &pair.initiator_signed_offers,
        &pair.responder_public_keys,
    )?;
    let mut failed_write = FailingWriteTransport {
        input: Cursor::new(first_request.clone()),
    };
    assert_eq!(
        server.handle_io_for_test(&mut failed_write),
        Err(crate::ipc::IpcError::Unavailable)
    );
    assert_eq!(server.agent_for_test().pending_session_count(), 1);
    assert_eq!(server.agent_for_test().durable_session_count_for_test()?, 1);

    // The same bytes are a nonce replay: refused without an answer.
    let mut replayed_nonce = CaptureTransport {
        input: Cursor::new(first_request),
        output: Vec::new(),
    };
    assert_eq!(
        server.handle_io_for_test(&mut replayed_nonce),
        Err(crate::ipc::IpcError::AuthenticationFailed)
    );
    assert!(replayed_nonce.output.is_empty());

    // The exact request under a fresh nonce is answered with the handle the
    // first attempt created -- no second session, no second reservation.
    let retry_nonce = [107u8; 32];
    let mut retried = CaptureTransport {
        input: Cursor::new(framed_begin(
            &client_signing_key,
            retry_nonce,
            &pair.initiator_signed_offers,
            &pair.responder_public_keys,
        )?),
        output: Vec::new(),
    };
    server.handle_io_for_test(&mut retried)?;
    let DecodedBeginEncapsulation {
        handle,
        pq_ciphertext,
        traditional_ciphertext,
        initiator_finished,
    } = decode_begin_encapsulation_response(
        &retried.output,
        &server_verification_key,
        retry_nonce,
    )?;
    assert_eq!(server.agent_for_test().pending_session_count(), 1);
    assert_eq!(server.agent_for_test().durable_session_count_for_test()?, 1);

    // The recovered handle is the live one: the peer completes its side on
    // the recovered ciphertexts and Finished, and this side accepts R under
    // that handle.
    let decapsulated =
        responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
            pair.responder_authorization,
            EncapsulationCiphertexts::from_slices(&pq_ciphertext, &traditional_ciphertext)?,
        ))?)?;
    let acceptance = pair.responder.accept_initiator_finished(
        decapsulated.handle,
        InitiatorFinishedV1::from_bytes(initiator_finished),
    )?;
    server.agent_for_test().accept_responder_finished(
        crate::PendingSessionHandle::decode(handle)?,
        acceptance.responder_finished,
    )?;
    assert_eq!(server.agent_for_test().pending_session_count(), 0);
    assert_eq!(server.agent_for_test().confirmed_key_count(), 1);

    // Acceptance consumed the capability for good: the same offers under yet
    // another nonce now reach the durable tombstone.
    let consumed_nonce = [108u8; 32];
    let mut consumed = CaptureTransport {
        input: Cursor::new(framed_begin(
            &client_signing_key,
            consumed_nonce,
            &pair.initiator_signed_offers,
            &pair.responder_public_keys,
        )?),
        output: Vec::new(),
    };
    server.handle_io_for_test(&mut consumed)?;
    assert_eq!(
        response_status(&consumed.output, &server_verification_key, consumed_nonce)?,
        7
    );
    assert_eq!(server.agent_for_test().pending_session_count(), 0);
    assert_eq!(server.agent_for_test().durable_session_count_for_test()?, 0);
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

#[test]
fn a_termination_signal_is_latched_instead_of_ending_the_process() -> TestResult {
    // The child installs the daemon's handlers, sends itself SIGTERM from
    // another thread, and exits 0 only once it has seen the flag. Without the
    // handlers the signal's default disposition ends the child on the spot,
    // and its status then carries a signal rather than an exit code.
    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::ipc::a_termination_signal_only_sets_the_flag_child")
        .env("Q_PERIAPT_TEST_TERMINATION_SIGNAL", "1")
        .status()?;
    assert_eq!(
        status.code(),
        Some(0),
        "the child did not survive SIGTERM and exit cleanly: {status}"
    );
    Ok(())
}

#[test]
fn a_termination_signal_only_sets_the_flag_child() -> TestResult {
    if std::env::var_os("Q_PERIAPT_TEST_TERMINATION_SIGNAL").is_none() {
        return Ok(());
    }
    let flag = crate::signals::install_termination_handlers()?;
    assert!(!flag.load(Ordering::Acquire), "the flag must start clear");
    let raiser = thread::spawn(|| {
        thread::sleep(Duration::from_millis(100));
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
    });
    let started = Instant::now();
    while !flag.load(Ordering::Acquire) {
        if started.elapsed() > Duration::from_secs(5) {
            // Neither ended nor flagged: a handler ran but stored nothing.
            std::process::exit(3);
        }
        thread::sleep(Duration::from_millis(5));
    }
    join(raiser)??;
    std::process::exit(0)
}

#[test]
fn stopping_the_serving_loop_releases_the_instance_lease() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 57)?;
    let authority = pair.initiator_authority.clone();
    assert!(
        authority.active_lease()?.is_some(),
        "the fixture's holder must start out holding its lease"
    );
    let (_, client_verification_key) = MlDsa65::generate([95u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([96u8; 32]);
    let server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let socket_path = directory.join("stop.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let shutdown = AtomicBool::new(false);
    let asked = thread::scope(|scope| -> TestResult<Instant> {
        let serving = scope.spawn(|| {
            let mut server = server;
            server.serve_and_release_for_test(listener, &shutdown)
        });
        // Let the loop park in its accept wait, then ask it to stop the way the
        // signal handler does: from another thread, with nothing connecting to
        // wake it.
        thread::sleep(Duration::from_millis(200));
        shutdown.store(true, Ordering::Release);
        let asked = Instant::now();
        serving
            .join()
            .map_err(|_| io::Error::other("serving thread panicked"))??;
        Ok(asked)
    })?;
    // One maintenance interval is the most the loop waits before it re-reads
    // the flag. The release that follows is one in-memory authority call and
    // two durable journal writes -- the release's intent row and the write
    // that forgets it -- so it is fsyncs, not authority I/O, that decide how
    // long this takes: measured at 1.02-1.19 s on this host with the suite
    // running in parallel. Four seconds on top of the interval is roughly
    // four times that, which a shared runner's disk needs, and a sixth of
    // LEASE_RELEASE_BUDGET, so the test still proves a stop does not sit
    // waiting for the release budget or a request deadline.
    let bound = crate::ipc::MAINTENANCE_INTERVAL + Duration::from_secs(4);
    assert!(
        asked.elapsed() < bound,
        "the loop took {:?} to stop",
        asked.elapsed()
    );
    assert!(
        authority.active_lease()?.is_none(),
        "the lease was still held after the serving loop stopped"
    );
    Ok(())
}

#[test]
fn a_stop_whose_release_fails_is_reported_and_the_lease_is_left_for_the_ttl() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 58)?;
    let authority = pair.initiator_authority.clone();
    let (_, client_verification_key) = MlDsa65::generate([95u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([96u8; 32]);
    let server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let socket_path = directory.join("unsent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let shutdown = AtomicBool::new(false);
    let (outcome, server) = thread::scope(|scope| {
        let serving = scope.spawn(|| {
            let mut server = server;
            let outcome = server.serve_and_release_for_test(listener, &shutdown);
            (outcome, server)
        });
        thread::sleep(Duration::from_millis(200));
        // The release the stop triggers cannot be sent.
        authority.fail_next_lease_call_before_send(LeaseCallFilter::Release);
        shutdown.store(true, Ordering::Release);
        serving.join()
    })
    .map_err(|_| io::Error::other("serving thread panicked"))?;
    // An orderly stop whose release did not settle is an error exit, not the
    // clean stop that exits 0 -- and the lease was not silently dropped: the
    // authority still holds it, for its TTL or for a retry.
    assert_eq!(outcome, Err(crate::ipc::IpcError::LeaseReleaseFailed));
    assert!(
        authority.active_lease()?.is_some(),
        "a release that was never sent must leave the lease held"
    );
    // It is still this instance's to release.
    server.agent_for_test().release_instance_lease()?;
    assert!(authority.active_lease()?.is_none());
    Ok(())
}

#[test]
fn a_stop_whose_release_settles_but_whose_cleanup_fails_says_the_lease_is_gone() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 59)?;
    let authority = pair.initiator_authority.clone();
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    // The session's durable cancellation will fail the way a diverged store
    // makes it: its row is already gone, but the secret is still held in
    // memory and the stop's erase must still drop it.
    pair.initiator
        .desynchronize_session_for_test(encapsulated.handle)?;
    let (_, client_verification_key) = MlDsa65::generate([95u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([96u8; 32]);
    let server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let socket_path = directory.join("recorded.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let shutdown = AtomicBool::new(true);
    let (outcome, server) = thread::scope(|scope| {
        let serving = scope.spawn(|| {
            let mut server = server;
            let outcome = server.serve_and_release_for_test(listener, &shutdown);
            (outcome, server)
        });
        serving.join()
    })
    .map_err(|_| io::Error::other("serving thread panicked"))?;

    // The release itself settled: the authority holds nothing, so the next
    // start acquires at once. Only the bookkeeping after it failed, and the
    // stop must say exactly that rather than send the operator looking for a
    // lease that has to lapse.
    assert_eq!(
        outcome,
        Err(crate::ipc::IpcError::LeaseReleasedStateNotRecorded)
    );
    assert_eq!(authority.active_lease()?, None);
    assert_eq!(server.agent_for_test().pending_session_count(), 0);
    let reason = format!("{}", crate::ipc::IpcError::LeaseReleasedStateNotRecorded);
    assert!(
        !reason.contains("was not released") && !reason.contains("TTL"),
        "the reason must not claim the lease is still held: {reason}"
    );
    Ok(())
}

/// Run `contender` while the agent's linearizer is held by the stop's
/// unbounded erase: one pending session whose durable cancellation takes two
/// seconds, which is longer than any deadline these tests give the contender.
fn while_the_stops_erase_holds_the_lock<T: Send>(
    pair: &AgentPair,
    contender: impl FnOnce() -> T + Send,
) -> TestResult<T> {
    pair.initiator
        .delay_each_session_cancel_for_test(Duration::from_secs(2))?;
    thread::scope(|scope| -> TestResult<T> {
        let holder = scope.spawn(|| {
            pair.initiator
                .release_instance_lease_within(Duration::from_secs(5))
        });
        // Let the erase take the lock before the contender asks for it.
        thread::sleep(Duration::from_millis(200));
        let outcome = contender();
        holder
            .join()
            .map_err(|_| io::Error::other("the stop thread panicked"))??;
        Ok(outcome)
    })
}

#[test]
fn a_caller_behind_a_busy_linearizer_is_refused_on_its_own_deadline() -> TestResult {
    // The deadline has to reach the lock itself. The longest hold this agent
    // has is the stop's erase -- one `Durability::Immediate` commit per
    // pending session, charged to no deadline at all -- and a caller queued
    // behind it used to block for the whole hold before it reached any
    // admission check. It must instead give up on its own deadline, having
    // set no deadline on the agent and dispatched nothing.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 201)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    let lease_calls = pair.initiator_authority.lease_call_count();

    let (outcome, waited) = while_the_stops_erase_holds_the_lock(&pair, || {
        let deadline = Instant::now().checked_add(Duration::from_millis(300));
        let started = Instant::now();
        let outcome = deadline.map(|deadline| {
            pair.initiator.begin_encapsulation_until(
                BeginEncapsulation::new(
                    pair.second_initiator_authorization.clone(),
                    pair.responder_public_keys.clone(),
                ),
                deadline,
            )
        });
        (outcome, started.elapsed())
    })?;

    assert!(
        matches!(
            outcome,
            Some(Err(AgentError::OperationDeadlineExceeded)) | None
        ),
        "a caller behind the erase must be refused on its deadline: {outcome:?}"
    );
    assert!(
        waited < Duration::from_secs(1),
        "the caller waited out the holder instead of its own deadline: {waited:?}"
    );
    // It renewed nothing, journaled nothing and dispatched nothing: the only
    // lease call in that window is the stop's own release.
    assert_eq!(
        pair.initiator_authority.lease_call_count(),
        lease_calls + 1,
        "the refused caller dispatched a lease call"
    );
    Ok(())
}

#[test]
fn the_idle_sweep_skips_a_busy_agent_instead_of_waiting_for_it() -> TestResult {
    // The sweep is best-effort maintenance the serving loop runs between
    // accepts. Waiting for the lock would only delay the next accept by
    // however long the holder takes, and the holder built here is the
    // unbounded one -- the stop's erase, charged to no deadline at all -- so a
    // pass that finds the agent busy is skipped and retried one maintenance
    // interval later.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 202)?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;

    let waited = while_the_stops_erase_holds_the_lock(&pair, || {
        let started = Instant::now();
        pair.initiator.expire_idle_sessions();
        started.elapsed()
    })?;
    assert!(
        waited < Duration::from_millis(500),
        "the sweep waited for the busy agent: {waited:?}"
    );
    Ok(())
}

#[test]
fn a_poisoned_linearizer_is_reported_at_once_not_at_the_deadline() -> TestResult {
    // Poisoning is decided on the first attempt and never waited on. An
    // implementation that treated every `try_lock` failure as "would block"
    // would answer `OperationDeadlineExceeded` thirty seconds later, which
    // the IPC face reports as status 24 while continuing to serve, instead of
    // the fatal stop `InternalPoisoned` gets.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 203)?;
    pair.initiator.poison_linearizer_for_test();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;

    let started = Instant::now();
    let outcome = pair.initiator.reconcile_transition_until(deadline);
    let waited = started.elapsed();
    assert_eq!(outcome.err(), Some(AgentError::InternalPoisoned));
    assert!(
        waited < Duration::from_secs(1),
        "a poisoned linearizer was waited on for {waited:?}"
    );
    Ok(())
}

#[test]
fn the_commands_that_make_no_port_call_honour_the_callers_deadline_too() -> TestResult {
    // Cancel, Destroy and the public-key read admit nothing, because they
    // make no port call. The linearizer is the only thing they can wait for,
    // so it is the only thing their deadline has to reach -- and a refusal
    // there is at the door, before anything is read or erased.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 204)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let reached = Instant::now();

    assert_eq!(
        pair.initiator.public_keys_until(reached).err(),
        Some(AgentError::OperationDeadlineExceeded)
    );
    assert_eq!(
        pair.initiator
            .cancel_until(encapsulated.handle, reached)
            .err(),
        Some(AgentError::OperationDeadlineExceeded)
    );
    // Refused at the door: the session and its durable reservation are both
    // intact, and the TTL sweep is still the backstop.
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 1);

    pair.initiator.cancel(encapsulated.handle)?;
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.durable_session_count_for_test()?, 0);
    Ok(())
}

/// Frame one of the three commands that make no port call: the public-key
/// read (command 1), or a Cancel (6) or a Destroy (7) over `handle`.
fn framed_no_port_call_command(
    signing_key: &[u8],
    nonce: [u8; 32],
    command: u8,
    handle: Option<[u8; 32]>,
) -> TestResult<Vec<u8>> {
    let mut body = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut body, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC domain encoding failed: {error:?}")))?;
    body.fixed(&nonce)
        .and_then(|()| body.byte(command))
        .and_then(|()| match handle {
            Some(bytes) => body.fixed(&bytes),
            None => Ok(()),
        })
        .map_err(|error| io::Error::other(format!("IPC request encoding failed: {error:?}")))?;
    let envelope = sign_envelope(&body.finish(), signing_key)
        .map_err(|error| io::Error::other(format!("IPC request signing failed: {error:?}")))?;
    let mut framed = Vec::new();
    write_frame(&mut framed, &envelope)
        .map_err(|error| io::Error::other(format!("IPC framing failed: {error:?}")))?;
    Ok(framed)
}

#[test]
fn the_ipc_face_gives_a_no_port_call_command_the_connections_deadline() -> TestResult {
    // The test above calls the three `_until` forms directly, so it says
    // nothing about which form the IPC face reaches for. That wiring needs
    // pinning here: the plain `cancel`, `destroy_key` and `public_keys`
    // differ from it only in the budget the linearizer wait gets --
    // `DEFAULT_OPERATION_BUDGET`, sixty seconds, rather than the connection's
    // own deadline -- so a request queued behind a long hold would keep the
    // one connection slot for a minute, well past `IPC_REQUEST_DEADLINE`, and
    // still answer nothing.
    //
    // The hold here is permanent, which is the shape of the longest one this
    // agent has: the stop's erase, one durable cancellation per pending
    // session and charged to no deadline at all. Each request must come back
    // on its own deadline. Nothing is written back, and that is the contract:
    // a deadline the wait consumed leaves no budget for the response, so the
    // client sees the connection close and recovers by exact retry.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 205)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([106u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([107u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;
    server.agent_for_test().hold_linearizer_for_test();

    // The Destroy handle names no retained key, and the public-key read needs
    // no handle at all: neither request reaches the state that would tell,
    // because the linearizer is as far as any of the three gets.
    for (command, handle, nonce) in [
        (1u8, None, [108u8; 32]),
        (6u8, Some(*encapsulated.handle.as_bytes()), [109u8; 32]),
        (7u8, Some([7u8; 32]), [110u8; 32]),
    ] {
        let mut transport = WriteBudgetTransport {
            input: Cursor::new(framed_no_port_call_command(
                &client_signing_key,
                nonce,
                command,
                handle,
            )?),
            output: Vec::new(),
            write_timeout: std::cell::Cell::new(None),
        };
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(300))
            .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
        let outcome = server.handle_io_with_deadline_for_test(&mut transport, deadline);
        let waited = started.elapsed();

        // Five seconds is an order of magnitude above the deadline this
        // request carries and an order of magnitude below the sixty-second
        // budget the plain forms would give the wait, so a loaded runner
        // cannot make a correct agent look like a stalled one.
        assert!(
            waited < Duration::from_secs(5),
            "command {command} held the connection past its deadline: {waited:?}"
        );
        assert_eq!(
            outcome,
            Err(crate::ipc::IpcError::Unavailable),
            "command {command} answered on a budget the caller never granted"
        );
        assert!(
            transport.output.is_empty(),
            "command {command} wrote a response past the connection deadline"
        );
    }
    Ok(())
}
