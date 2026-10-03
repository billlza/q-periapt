// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn connection_tls_process_cuts_preserve_prekeys_inbox_external_effect_and_exact_ack() {
    for cut in [
        "reply",
        "server-archive",
        "activation",
        "inbox",
        "application",
        "ack",
    ] {
        let mut n = Network::new();
        let endpoint = n.endpoint();
        let application = matches!(cut, "inbox" | "application" | "ack");
        let session = if application {
            let (mut child, address) = spawn(&n, 0, "none", 1);
            let session = n
                .establish(&endpoint, address, limits())
                .expect("bootstrap")
                .session;
            wait(&n, &mut child, 0);
            Some(session)
        } else {
            None
        };
        let message = session.map(|session| {
            n.journal
                .next_message_id(&n.inventory.peer.initiator, session, 150)
                .expect("ID")
        });
        let (mut child, address) = spawn(&n, 1, cut, 1);
        let mut bound = limits();
        bound.exchanges = 2;
        let plaintext = b"durable across network uncertainty";
        let path = n.inventory.path.clone();
        let result = std::thread::scope(|scope| {
            let killer = scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !path.join("cut-ready").exists() {
                    assert!(
                        child.0.try_wait().expect("producer").is_none()
                            && Instant::now() < deadline,
                        "{cut}: {}",
                        fs::read_to_string(path.join("connection-1.log")).expect("log")
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(
                    fs::read_to_string(path.join("cut-ready")).expect("actual cut"),
                    cut
                );
                assert!(child.0.try_wait().expect("parked producer").is_none());
                competing_writer(&path);
                child.0.kill().expect("kill owned process");
                assert!(!child.0.wait().expect("reap").success());
            });
            let result = match (session, message) {
                (Some(session), Some(message)) => endpoint
                    .send(
                        n.actor(),
                        Submission {
                            session,
                            message,
                            plaintext,
                            associated_data: b"crash",
                        },
                        Run {
                            address,
                            server_name: "localhost",
                            limits: bound,
                            cancel: &Cancellation::default(),
                        },
                        || Ok(150),
                    )
                    .map(|_| ()),
                _ => n.establish(&endpoint, address, bound).map(|_| ()),
            };
            killer.join().expect("bounded cut observer");
            result
        });
        assert!(result.is_err(), "no success before reply dispatch");
        n.reopen();
        let (mut replacement, address) = spawn(&n, 2, "none", 1);
        match (session, message) {
            (Some(session), Some(message)) => {
                let result = endpoint
                    .send(
                        n.actor(),
                        Submission {
                            session,
                            message,
                            plaintext,
                            associated_data: b"crash",
                        },
                        Run {
                            address,
                            server_name: "localhost",
                            limits: limits(),
                            cancel: &Cancellation::default(),
                        },
                        || Ok(150),
                    )
                    .expect("exact recovery");
                assert_eq!(result.consumption, Consumption::Confirmed);
                wait(&n, &mut replacement, 2);
                readback(&n, session, message, plaintext);
            }
            _ => {
                let established = n
                    .establish(&endpoint, address, limits())
                    .expect("same initiation resumes");
                wait(&n, &mut replacement, 2);
                assert_eq!(
                    fs::read(n.inventory.path.join("connection-established"))
                        .expect("peer identity"),
                    established.session
                );
            }
        }
        eprintln!("CONNECTION_TLS_PROCESS_RECOVERY cut={cut} same_request_and_input=true");
    }
}

#[test]
fn connection_tls_application_failure_and_post_commit_cancellation_never_invent_consumption() {
    for mode in [
        "fail-application",
        "unknown-application",
        "cancel-application",
    ] {
        let mut n = Network::new();
        let endpoint = n.endpoint();
        let (mut child, address) = spawn(&n, 0, "none", 1);
        let session = n
            .establish(&endpoint, address, limits())
            .expect("bootstrap")
            .session;
        wait(&n, &mut child, 0);
        let context = Arc::clone(&n.inventory.peer.initiator);
        let id = n
            .journal
            .next_message_id(&context, session, 150)
            .expect("ID");
        let (mut child, address) = spawn(&n, 1, mode, 1);
        let mut bound = limits();
        bound.exchanges = 1;
        let result = endpoint.send(
            n.actor(),
            Submission {
                session,
                message: id,
                plaintext: b"external commit uncertainty is not an ACK",
                associated_data: b"",
            },
            Run {
                address,
                server_name: "localhost",
                limits: bound,
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        );
        assert!(result.is_err());
        wait(&n, &mut child, 1);
        assert_eq!(
            n.journal
                .message_status(&context, session, id)
                .expect("outbox retained"),
            MessageStatus::Committed
        );
        let mut receiver = reopen(&n.inventory.path, n.inventory.peer.local_device());
        let state = state(&mut receiver, &session);
        let traffic = state.traffic(0).expect("epoch");
        assert_eq!(traffic.receive_floor, 0);
        assert!(traffic.incoming.get(&id).is_some_and(|s| !s.consumed));
        receiver.close();
        if mode != "fail-application" {
            readback(
                &n,
                session,
                id,
                b"external commit uncertainty is not an ACK",
            );
        }
        let (mut child, address) = spawn(&n, 2, "none", 1);
        let result = endpoint
            .send(
                n.actor(),
                Submission {
                    session,
                    message: id,
                    plaintext: b"external commit uncertainty is not an ACK",
                    associated_data: b"",
                },
                Run {
                    address,
                    server_name: "localhost",
                    limits: limits(),
                    cancel: &Cancellation::default(),
                },
                || Ok(150),
            )
            .expect("same external transaction reconciled");
        assert_eq!(result.consumption, Consumption::Confirmed);
        wait(&n, &mut child, 2);
        readback(
            &n,
            session,
            id,
            b"external commit uncertainty is not an ACK",
        );
    }
}

fn competing_writer(path: &Path) {
    let log =
        fs::File::create_new(path.join("connection-contender.log")).expect("new contender log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::messages::tests::connection_tls::connection_tls_peer_child",
                "--nocapture",
            ])
            .env("QPERIAPT_CONNECTION_TLS_DIR", path)
            .env("QPERIAPT_CONNECTION_TLS_ROLE", "2")
            .env("QPERIAPT_CONNECTION_TLS_GENERATION", "99")
            .env("QPERIAPT_CONNECTION_TLS_OPERATIONS", "0")
            .env("QPERIAPT_CONNECTION_TLS_CUT", "contender")
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("contender"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().expect("contender status") {
            assert!(
                status.success(),
                "{}",
                fs::read_to_string(path.join("connection-contender.log")).expect("log")
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "competing process blocked instead of refusing ownership"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
