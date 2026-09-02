//! Authenticated witness transport and server behaviour.

use super::*;

#[test]
fn authenticated_reference_witness_serializes_concurrent_cas_and_queries() -> TestResult {
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([11u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([12u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [1u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let client_a = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(client_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    assert_eq!(client_a.read_head()?, initial);

    let next_a = StateRevision::new(2, 2, [2u8; 32])?;
    let next_b = StateRevision::new(2, 2, [3u8; 32])?;
    let intent_a = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(TransitionKind::Advance, initial.revision(), next_a)?,
        initial.fence(),
        FenceToken::generate()?,
    )?;
    let intent_b = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(TransitionKind::Advance, initial.revision(), next_b)?,
        initial.fence(),
        FenceToken::generate()?,
    )?;
    let client_b = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(MlDsa65::generate([11u8; 32]).0),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let thread_a = thread::spawn(move || client_a.compare_and_advance(intent_a));
    let thread_b = thread::spawn(move || client_b.compare_and_advance(intent_b));
    let outcome_a = join(thread_a)??;
    let outcome_b = join(thread_b)??;
    let applied = [outcome_a, outcome_b]
        .into_iter()
        .filter(|outcome| {
            matches!(
                outcome,
                WitnessOutcome::Known(receipt)
                    if receipt.disposition() == crate::WitnessDisposition::Applied
            )
        })
        .count();
    assert_eq!(applied, 1);

    let query_client = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(MlDsa65::generate([11u8; 32]).0),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let query_a = query_client.query(intent_a.operation_id())?;
    assert!(matches!(query_a, WitnessOutcome::Known(_)));
    shutdown.store(true, Ordering::Release);
    join(server_thread)??;
    Ok(())
}

#[test]
fn authenticated_reference_witness_waits_for_a_delayed_fragmented_frame() -> TestResult {
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([13u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([14u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [4u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let result =
        (|| -> TestResult {
            let (frame, nonce) = crate::witness::test_support::framed_read_request(&client_sk)?;

            // Keep the accepted connection empty long enough for the server to enter
            // its read, then force partial reads across the length and payload.
            thread::sleep(Duration::from_millis(50));
            stream.write_all(frame.get(..2).ok_or_else(|| {
                io::Error::other("test witness frame omitted its length prefix")
            })?)?;
            stream.flush()?;
            thread::sleep(Duration::from_millis(20));
            stream.write_all(frame.get(2..7).ok_or_else(|| {
                io::Error::other("test witness frame omitted its initial payload bytes")
            })?)?;
            stream.flush()?;
            thread::sleep(Duration::from_millis(20));
            stream.write_all(
                frame
                    .get(7..)
                    .ok_or_else(|| io::Error::other("test witness frame was unexpectedly short"))?,
            )?;
            stream.flush()?;

            let response = read_frame(&mut stream)
                .map_err(|_| io::Error::other("witness response frame was unavailable"))?;
            assert_eq!(
                crate::witness::test_support::read_response_head(&response, &witness_vk, nonce)?,
                initial
            );
            Ok(())
        })();

    shutdown.store(true, Ordering::Release);
    let server_result = join(server_thread)?;
    result?;
    server_result?;
    Ok(())
}

#[test]
fn authenticated_reference_witness_evicts_a_trickling_client_at_its_deadline() -> TestResult {
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([15u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([16u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_millis(500),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let result = (|| -> TestResult {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let (frame, _nonce) = crate::witness::test_support::framed_read_request(&client_sk)?;

        // Trickle one byte per 100ms without ever pausing longer: every gap
        // stays far inside the 500ms budget a per-syscall timeout would grant,
        // so only the absolute per-connection deadline can end the connection.
        // The server's hang-up surfaces as a reset on a subsequent write, so
        // the disconnect must be observed while bytes are still flowing.
        let started = Instant::now();
        let mut disconnected_after = None;
        for byte in frame.iter().take(40) {
            if stream
                .write_all(std::slice::from_ref(byte))
                .and_then(|()| stream.flush())
                .is_err()
            {
                disconnected_after = Some(started.elapsed());
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let Some(elapsed) = disconnected_after else {
            return Err(
                io::Error::other("witness held the trickled connection past its deadline").into(),
            );
        };
        // Well before the 4s the full trickle budget would take, and far
        // before the hours the complete frame would need.
        assert!(elapsed < Duration::from_secs(3));

        // The single serving slot must be free again for a well-behaved client.
        let client = AuthenticatedTcpWitness::new(
            address,
            ZeroizingBytes::from_bytes(MlDsa65::generate([15u8; 32]).0),
            witness_vk,
            Duration::from_secs(2),
        )?;
        assert_eq!(client.read_head()?, initial);
        Ok(())
    })();

    shutdown.store(true, Ordering::Release);
    let server_result = join(server_thread)?;
    result?;
    server_result?;
    Ok(())
}

#[test]
fn witness_server_survives_a_request_level_rejection() -> TestResult {
    // A caller can provoke a request-level rejection on purpose -- replaying one
    // operation id under a different intent. That must reject the request only;
    // if it terminated the listener, a single caller could destroy every
    // subsequent read and query for everyone.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([31u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([32u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let result = (|| -> TestResult {
        let client = AuthenticatedTcpWitness::new(
            address,
            ZeroizingBytes::from_bytes(client_sk),
            witness_vk,
            Duration::from_secs(2),
        )?;

        let operation = OperationId::generate()?;
        let applied = StateRevision::new(2, 2, [2u8; 32])?;
        client.compare_and_advance(WitnessIntent::new(
            operation,
            StateAdvance::new(TransitionKind::Advance, initial.revision(), applied)?,
            initial.fence(),
            FenceToken::generate()?,
        )?)?;

        // Same operation id, different intent: a request-level rejection.
        let conflicting = client.compare_and_advance(WitnessIntent::new(
            operation,
            StateAdvance::new(
                TransitionKind::Advance,
                initial.revision(),
                StateRevision::new(2, 2, [9u8; 32])?,
            )?,
            initial.fence(),
            FenceToken::generate()?,
        )?);
        // The server rejects it and produces no response, so the caller sees an
        // indeterminate outcome rather than a false success.
        assert!(
            matches!(conflicting, Ok(WitnessOutcome::Unknown) | Err(_)),
            "a conflicting replay must not be reported as applied; got {conflicting:?}"
        );

        // The listener must still be serving.
        let head = client.read_head()?;
        assert_eq!(
            head.revision(),
            applied,
            "the witness must still answer after rejecting a request"
        );
        Ok(())
    })();

    shutdown.store(true, Ordering::Release);
    let server_result = join(server_thread)?;
    result?;
    server_result?;
    Ok(())
}

#[test]
fn witness_rejects_one_key_pair_serving_both_directions() -> TestResult {
    // Requests are verified under the client key and responses are signed under
    // the witness key. If those are one key pair, whoever may send requests can
    // also forge responses and the asymmetry the protocol depends on is gone.
    // The authority transport refuses the equivalent by requiring distinct
    // endpoint identities; the witness must refuse it too.
    let directory = TestDirectory::new()?;
    let (shared_sk, shared_vk) = MlDsa65::generate([51u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    assert!(
        ReferenceWitnessServer::provision(
            &directory.join("shared.redb"),
            initial,
            shared_vk,
            ZeroizingBytes::from_bytes(shared_sk),
            shared_vk,
            Duration::from_secs(2),
        )
        .is_err(),
        "one key pair must not carry both protocol directions"
    );

    // The distinct-key configuration the deployment actually uses still works.
    let (client_sk, client_vk) = MlDsa65::generate([52u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([53u8; 32]);
    drop(ReferenceWitnessServer::provision(
        &directory.join("distinct.redb"),
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?);
    let _ = client_sk;
    Ok(())
}

#[test]
fn cas_with_an_unverifiable_response_is_indeterminate_not_a_failure() -> TestResult {
    // The request has already gone out, so the witness may have committed the
    // advance and only the answer was lost or tampered with. Reporting a
    // definite failure would invite the caller to retry or roll back against a
    // state that actually moved.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (_witness_sk, witness_vk) = MlDsa65::generate([61u8; 32]);

    let hostile = thread::spawn(move || -> TestResult {
        let (mut stream, _peer) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        // Consume the request, then answer with a well-framed but unverifiable
        // envelope: signed by nobody the client trusts.
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch);
        let junk = [0x5Au8; 64];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(junk.len() as u32).to_be_bytes());
        framed.extend_from_slice(&junk);
        let _ = stream.write_all(&framed);
        let _ = stream.flush();
        Ok(())
    });

    let client = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(MlDsa65::generate([62u8; 32]).0),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let outcome = client.compare_and_advance(WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(
            TransitionKind::Advance,
            StateRevision::new(1, 1, [5u8; 32])?,
            StateRevision::new(2, 2, [2u8; 32])?,
        )?,
        FenceToken::generate()?,
        FenceToken::generate()?,
    )?);

    assert!(
        matches!(outcome, Ok(WitnessOutcome::Unknown)),
        "an unverifiable response to a state-changing request must be indeterminate; got {outcome:?}"
    );

    let _ = hostile.join();
    Ok(())
}

#[test]
fn authenticated_witness_client_gives_up_on_a_trickling_witness_at_its_deadline() -> TestResult {
    // The counterpart to the server-side trickle test above. The client holds
    // the agent mutex inside a strictly serial IPC loop, so a witness that
    // drips its response must not be able to stall the whole daemon: a
    // per-syscall timeout restarts on every partial read, and only one
    // absolute per-connection deadline bounds the exchange.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (_witness_sk, witness_vk) = MlDsa65::generate([21u8; 32]);

    let hostile = thread::spawn(move || -> TestResult {
        let (mut stream, _peer) = listener.accept()?;
        // Consume whatever the client sends, then answer one byte at a time,
        // never pausing longer than the client's own timeout.
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut scratch = [0u8; 1024];
        let _ = stream.read(&mut scratch);
        // A length header announcing a large frame, then a slow drip.
        let announced = 16_000u32.to_be_bytes();
        if stream
            .write_all(&announced)
            .and_then(|()| stream.flush())
            .is_err()
        {
            return Ok(());
        }
        for _ in 0..64 {
            if stream
                .write_all(&[0u8])
                .and_then(|()| stream.flush())
                .is_err()
            {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    });

    let timeout = Duration::from_millis(500);
    let client = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(MlDsa65::generate([22u8; 32]).0),
        witness_vk,
        timeout,
    )?;
    let started = Instant::now();
    let outcome = client.read_head();
    let elapsed = started.elapsed();

    assert!(
        outcome.is_err(),
        "a trickling witness must not produce a head"
    );
    // Generous relative to the 500ms deadline, but far below the 6.4s this
    // drip would take to finish and the hours a full 16000-byte frame needs.
    assert!(
        elapsed < Duration::from_secs(3),
        "client stalled {elapsed:?} against a {timeout:?} deadline"
    );

    let _ = hostile.join();
    Ok(())
}
