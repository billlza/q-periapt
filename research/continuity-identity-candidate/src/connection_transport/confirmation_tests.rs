// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture,
    crypto::{classical_compromise_tests, digest, envelope, open_envelope, Purpose},
    durable::tests::{directory, new_store},
    DurableError, DurableStatus, PrekeyQuality,
};
use q_periapt_backends::ML_DSA_65_SIG_LEN;
use std::{net::TcpListener, time::Duration};

#[test]
fn native_establish_rejects_public_ready_after_classical_reply_alias() {
    reject_classical_reply_alias(false);
}

#[test]
fn native_establish_authenticates_ready_after_classical_reply_alias() {
    reject_classical_reply_alias(true);
}

fn reject_classical_reply_alias(forge_proof: bool) {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let idir = directory();
    let rdir = directory();
    let ipath = idir
        .path()
        .canonicalize()
        .expect("canonical client directory");
    let rpath = rdir
        .path()
        .canonicalize()
        .expect("canonical responder directory");
    let mut ij = new_store(&ipath, f.initiator_device());
    let mut rj = new_store(&rpath, f.local_device());
    let mut archives = SessionArchiveStore::provision(
        &ipath.join("archives.redb"),
        ij.identity().expect("client journal identity"),
    )
    .expect("client archive index");
    let client = rcgen::generate_simple_self_signed(vec!["client.test".into()])
        .expect("client TLS identity");
    let server =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("server TLS identity");
    let client_key = zeroize::Zeroizing::new(client.signing_key.serialize_der());
    let server_key = zeroize::Zeroizing::new(server.signing_key.serialize_der());
    let tls_limits = Limits {
        max_connections: 1,
        handshake_ms: 10_000,
        request_ms: 10_000,
        idle_ms: 10_000,
    };
    let outgoing = ConnectionEndpoint::client(
        &f.initiator,
        Credentials {
            certificate: client.cert.der(),
            private_key: &client_key,
            peer_certificate: server.cert.der(),
        },
        tls_limits,
    )
    .expect("real client endpoint");
    // The adversarial carrier has the configured TLS peer key. It cannot sign
    // new ML-DSA device messages; its only device-key disclosure is P-256 below.
    let incoming = ConnectionEndpoint::server(
        &f.responder,
        Credentials {
            certificate: server.cert.der(),
            private_key: &server_key,
            peer_certificate: client.cert.der(),
        },
        tls_limits,
    )
    .expect("actual pinned TLS server endpoint");
    let compromised_classic = classical_compromise_tests::capture_classical(&f.signer_r)
        .expect("classical device signing component only");
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("bounded accept");
    let address = listener.local_addr().expect("address");
    let deadline = Instant::now() + Duration::from_secs(20);
    let cancel = Cancellation::default();
    let request = InitiationId::generate().expect("original request");
    let result = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            outgoing.establish(
                Actor {
                    journal: &mut ij,
                    archives: &mut archives,
                    context: &f.initiator,
                    signer: &f.signer_i,
                },
                request,
                Run {
                    address,
                    server_name: "localhost",
                    limits: RunLimits {
                        exchanges: 4,
                        timeout: Duration::from_secs(20),
                        connect_timeout: Duration::from_secs(1),
                        outer_deadline: Some(deadline),
                    },
                    cancel: &cancel,
                },
                || Ok(150),
            )
        });
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "bounded loopback accept");
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => break result.expect("accept loopback client").0,
            }
        };
        let mut channel = Channel::new(stream, incoming.endpoint.accept().expect("TLS engine"))
            .expect("real native TLS channel");
        let first = channel
            .request(&f.responder, &cancel, deadline, &mut || Ok(150))
            .expect("receive actual client initial");
        let initial = payload(first.bytes(), INITIAL)
            .expect("initial carrier")
            .to_vec();
        // This is an honest protocol oracle, with real durable state and KEMs.
        // The carrier only obtains its public response, never its PQ or KEM keys.
        let (pq, classic) = f.sources();
        let honest_reply = rj
            .respond(
                Arc::clone(&f.responder),
                &initial,
                &f.signer_r,
                pq,
                classic,
                150,
            )
            .expect("honest responder protocol operation");
        let (body, original_signature) = open_envelope(&honest_reply).expect("public reply");
        let alternative = classical_compromise_tests::sign_classical_only(
            &compromised_classic,
            Purpose::BootstrapResponder,
            body,
        )
        .expect("alternate low-S classical signature");
        assert_ne!(
            original_signature.get(ML_DSA_65_SIG_LEN..).expect("P-256"),
            alternative
        );
        let mut signature = original_signature
            .get(..ML_DSA_65_SIG_LEN)
            .expect("ML-DSA")
            .to_vec();
        signature.extend_from_slice(&alternative);
        let alias = envelope(body, &signature).expect("same body and unchanged PQ signature");
        channel
            .respond(
                first.id(),
                &frame(REPLY, &alias).expect("reply frame"),
                &f.responder,
                &cancel,
                deadline,
                &mut || Ok(150),
            )
            .expect("deliver alias over real TLS");
        let second = channel
            .request(&f.responder, &cancel, deadline, &mut || Ok(150))
            .expect("receive actual client final");
        let (sent_initial, final_wire) =
            codec::split(payload(second.bytes(), BOOTSTRAP).expect("final carrier"))
                .expect("initial/final pair");
        assert_eq!(sent_initial, initial);
        assert!(matches!(
            rj.finish(Arc::clone(&f.responder), &initial, final_wire, 150),
            Err(DurableError::Protocol(crate::Error::Scope))
        ));
        assert_eq!(
            rj.status(&f.responder, &initial)
                .expect("retained responder state"),
            DurableStatus::AwaitingFinal
        );
        // A session ID is public: it is a hash of the Final prefix, without MACI.
        let claimed_id = digest(
            b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/session-id",
            final_wire.get(..104).expect("public final prefix"),
        );
        let ready = if forge_proof {
            // All public fields are correct for the initiator's provisional
            // session. The attacker has neither its root nor its ACK key.
            let mut proof = b"QPCMACK1".to_vec();
            proof.extend_from_slice(&claimed_id);
            proof.push(1);
            proof.extend_from_slice(&0_u64.to_be_bytes());
            proof.extend_from_slice(&[0; 32]);
            codec::pair(&claimed_id, &proof).expect("well-formed forged proof")
        } else {
            claimed_id.to_vec()
        };
        channel
            .respond(
                second.id(),
                &frame(READY, &ready).expect("false READY"),
                &f.responder,
                &cancel,
                deadline,
                &mut || Ok(150),
            )
            .expect("false peer activation report");
        channel
            .finish(&f.responder, &cancel, deadline, &mut || Ok(150))
            .expect("close carrier");
        let result = handle.join().expect("owned client thread");
        if forge_proof {
            assert!(
                matches!(
                    result,
                    Err(Error::Durable(DurableError::Protocol(
                        crate::Error::Authentication
                    )))
                ),
                "a public ID and forged MAC must not establish: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(Error::Protocol)),
                "public-only READY must not establish: {result:?}"
            );
        }
        claimed_id
    });
    if forge_proof {
        // Key-proof verification follows local message-state activation. Failure
        // is not a rollback; retry must retain this same request, Final and ID.
        ij.next_message_id(&f.initiator, result, 150)
            .expect("local activation can precede rejected peer confirmation");
        let retained = ij
            .resume_reply(Arc::clone(&f.initiator), request, 150)
            .expect("the exact original Final remains recoverable");
        assert_eq!(retained.session_id(), result);
    } else {
        assert!(matches!(
            ij.next_message_id(&f.initiator, result, 150),
            Err(DurableError::Absent)
        ));
    }
    eprintln!("NATIVE_READY_REJECT native_established=0 forged_proof={forge_proof} responder_awaiting_final=1 pq_signature_unchanged=1 tls_peer_key_supplied=1");
}

#[test]
fn native_carrier_rejects_legacy_and_portable_tags() {
    let current = frame(INITIAL, b"initial").expect("native v2 frame");
    assert_eq!(current.get(..8), Some(b"QPCNET02".as_slice()));
    for tag in [b"QPCNET01", b"QPCXCH01"] {
        let mut other = current.clone();
        other.get_mut(..8).expect("tag").copy_from_slice(tag);
        assert!(matches!(codec::open(&other), Err(Error::Protocol)));
    }
}
