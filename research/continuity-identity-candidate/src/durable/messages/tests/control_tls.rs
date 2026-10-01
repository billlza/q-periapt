// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    control_transport::{Cancellation, ControlEndpoint, Run, RunLimits, Session},
    durable::tests::ChildGuard,
};
use q_periapt_rustls::connection::Credentials;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use super::tls_identity::{tls_limits, Identity};
fn limits() -> RunLimits {
    RunLimits {
        exchanges: 12,
        timeout: Duration::from_secs(20),
        connect_timeout: Duration::from_secs(1),
        outer_deadline: None,
    }
}
fn atomic(path: &Path, name: &str, bytes: &[u8]) {
    let pending = path.join(format!("{name}-pending"));
    let mut file = fs::File::create_new(&pending).expect("new public marker");
    file.write_all(bytes).expect("marker");
    file.sync_all().expect("marker sync");
    drop(file);
    fs::rename(pending, path.join(name)).expect("publish complete marker");
}
fn save_fixture(p: &Pair, path: &Path, client: &Identity, server: &Identity) {
    let mut public =
        p.f.reusable
            .public_key()
            .expect("public")
            .to_bytes()
            .to_vec();
    public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
    for (name, bytes) in [
        ("tls-public-keys", public.as_slice()),
        ("tls-session", &p.session),
        ("tls-client.der", &client.certificate),
        ("tls-server.der", &server.certificate),
        ("tls-server.key", server.key.as_slice()),
    ] {
        fs::write(path.join(name), bytes).expect("private fixture directory");
    }
}
fn spawn(
    path: &Path,
    role: u8,
    generation: u8,
    mode: &str,
    target: u64,
) -> (ChildGuard, SocketAddr) {
    let log = fs::File::create_new(path.join(format!("tls-{generation}.log"))).expect("log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "durable::messages::tests::control_tls::control_tls_peer_child",
                "--nocapture",
            ])
            .env("QPERIAPT_CONTROL_TLS_DIR", path)
            .env("QPERIAPT_CONTROL_TLS_ROLE", role.to_string())
            .env("QPERIAPT_CONTROL_TLS_GENERATION", generation.to_string())
            .env("QPERIAPT_CONTROL_TLS_MODE", mode)
            .env("QPERIAPT_CONTROL_TLS_TARGET", target.to_string())
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let ready = path.join(format!("tls-ready-{generation}"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "{}",
            fs::read_to_string(path.join(format!("tls-{generation}.log"))).expect("log")
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let address = fs::read_to_string(ready)
        .expect("address")
        .parse()
        .expect("socket address");
    (child, address)
}
fn wait(child: &mut ChildGuard, path: &Path, generation: u8) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.0.try_wait().expect("status") {
            assert!(
                status.success(),
                "{}",
                fs::read_to_string(path.join(format!("tls-{generation}.log"))).expect("log")
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "owned control server did not terminate"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn accept(listener: &TcpListener, deadline: Instant) -> std::io::Result<std::net::TcpStream> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error),
        }
    }
}

#[test]
fn control_tls_peer_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_CONTROL_TLS_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let generation: u8 = std::env::var("QPERIAPT_CONTROL_TLS_GENERATION")?.parse()?;
    let role: u8 = std::env::var("QPERIAPT_CONTROL_TLS_ROLE")?.parse()?;
    let target: u64 = std::env::var("QPERIAPT_CONTROL_TLS_TARGET")?.parse()?;
    let mode = std::env::var("QPERIAPT_CONTROL_TLS_MODE")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let public = fs::read(path.join("tls-public-keys"))?;
    let (first, second) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
    let f = crate::bootstrap::tests::fixture_from_public(
        PrekeyQuality::OneTimeBoth,
        Some((first.try_into()?, second.try_into()?)),
    );
    let (device, context, signer) = if role == 1 {
        (f.initiator_device(), &f.initiator, &f.signer_i)
    } else {
        (f.local_device(), &f.responder, &f.signer_r)
    };
    let session: [u8; 32] = fs::read(path.join("tls-session"))?
        .try_into()
        .map_err(|_| "session width")?;
    let certificate = fs::read(path.join("tls-server.der"))?;
    let key = Zeroizing::new(fs::read(path.join("tls-server.key"))?);
    let peer = fs::read(path.join("tls-client.der"))?;
    let endpoint = ControlEndpoint::server(
        context,
        session,
        Credentials {
            certificate: &certificate,
            private_key: &key,
            peer_certificate: &peer,
        },
        tls_limits(),
    )?;
    let mut journal = reopen(path, device);
    atomic(
        path,
        &format!("tls-ready-{generation}"),
        listener.local_addr()?.to_string().as_bytes(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    if mode == "stall" {
        let mut stream = accept(&listener, deadline)?;
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut bytes = [0; 4096];
        if stream.read(&mut bytes)? == 0 {
            return Err("missing ClientHello".into());
        }
        atomic(path, "tls-stalled", b"ClientHello received");
        loop {
            if stream.read(&mut bytes)? == 0 {
                break;
            }
        }
        atomic(path, "tls-peer-closed", b"EOF observed after cancellation");
        return Ok(());
    }
    if mode != "normal"
        && mode != "empty"
        && mode != "replay"
        && mode != "reject-tls"
        && !mode.starts_with("cut-")
    {
        return Err("unknown owned TLS test mode".into());
    }
    for _ in 0..12 {
        let stream = accept(&listener, deadline)?;
        let result = endpoint.serve(
            stream,
            Session {
                journal: &mut journal,
                context,
                signer,
            },
            limits(),
            &Cancellation::default(),
            || Ok(150),
        );
        if mode == "empty" || mode == "replay" {
            assert!(matches!(
                result,
                Err(crate::control_transport::Error::Protocol)
            ));
            return Ok(());
        }
        if mode == "reject-tls" {
            assert!(
                result.is_err(),
                "untrusted TLS peer must not reach control completion"
            );
            assert_eq!(journal.rekey_progress(context, session)?.confirmed_epoch, 0);
            return Ok(());
        }
        let result = result?;
        if result.epoch == target {
            atomic(
                path,
                &format!("tls-complete-{generation}"),
                target.to_string().as_bytes(),
            );
            return Ok(());
        }
    }
    Err("test control server exhausted its finite connection allowance".into())
}

#[test]
fn control_tls_wrong_certificate_is_terminal_and_does_not_fallback_or_retry() {
    let mut p = Pair::new();
    p.activate();
    p.jr.close();
    let path = p.pr.clone();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let wrong = Identity::new("localhost");
    save_fixture(&p, &path, &client, &server);
    let (mut child, address) = spawn(&path, 2, 1, "reject-tls", 1);
    let endpoint = ControlEndpoint::client(
        &p.f.initiator,
        p.session,
        client.credentials(&wrong),
        tls_limits(),
    )
    .expect("explicit wrong peer pin");
    let result = endpoint.run(
        Session {
            journal: &mut p.ji,
            context: &p.f.initiator,
            signer: &p.f.signer_i,
        },
        Run {
            target: 1,
            address,
            server_name: "localhost",
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        || Ok(150),
    );
    wait(&mut child, &path, 1);
    assert!(
        matches!(
            result,
            Err(crate::control_transport::Error::Connection(
                q_periapt_rustls::connection::Error::Tls(_)
                    | q_periapt_rustls::connection::Error::PeerIdentity
            ))
        ),
        "{result:?}"
    );
    assert_eq!(
        p.ji.rekey_progress(&p.f.initiator, p.session)
            .expect("unchanged epoch")
            .confirmed_epoch,
        0
    );
}

#[test]
fn control_tls_clock_failure_is_not_a_timestamp_or_a_network_retry() {
    let mut p = Pair::new();
    p.activate();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let endpoint = ControlEndpoint::client(
        &p.f.initiator,
        p.session,
        client.credentials(&server),
        tls_limits(),
    )
    .expect("endpoint");
    let revision = p.ji.image().expect("before").revision;
    let result = endpoint.run(
        Session {
            journal: &mut p.ji,
            context: &p.f.initiator,
            signer: &p.f.signer_i,
        },
        Run {
            target: 1,
            address: SocketAddr::from(([127, 0, 0, 1], 1)),
            server_name: "localhost",
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        || Err(io::Error::other("test clock unavailable")),
    );
    assert!(
        matches!(result, Err(crate::control_transport::Error::Clock(_))),
        "{result:?}"
    );
    assert_eq!(p.ji.image().expect("no reserved work").revision, revision);
}

#[test]
fn control_tls_old_receipt_cannot_complete_a_different_requested_target() {
    let mut p = Pair::new();
    p.activate();
    assert_eq!(complete_rekey(&mut p), 1);
    let old =
        p.jr.rekey_outbox(&p.f.responder, p.session, 1, RekeyFlight::Receipt, 150)
            .expect("actual earlier receipt");
    p.jr.close();
    let path = p.pr.clone();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    save_fixture(&p, &path, &client, &server);
    fs::write(path.join("tls-old-receipt"), old).expect("owned adversarial input");
    let (mut child, address) = spawn(&path, 2, 1, "replay", 2);
    let endpoint = ControlEndpoint::client(
        &p.f.initiator,
        p.session,
        client.credentials(&server),
        tls_limits(),
    )
    .expect("endpoint");
    let result = endpoint.run(
        Session {
            journal: &mut p.ji,
            context: &p.f.initiator,
            signer: &p.f.signer_i,
        },
        Run {
            target: 2,
            address,
            server_name: "localhost",
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        || Ok(150),
    );
    wait(&mut child, &path, 1);
    assert!(
        matches!(result, Err(crate::control_transport::Error::Protocol)),
        "old epoch must not satisfy requested epoch 2: {result:?}"
    );
    let progress =
        p.ji.rekey_progress(&p.f.initiator, p.session)
            .expect("retained target");
    assert_eq!(
        (progress.confirmed_epoch, progress.pending_epoch),
        (1, Some(2))
    );
}

#[test]
fn control_tls_empty_carrier_ack_cannot_manufacture_protocol_completion() {
    let mut p = Pair::new();
    p.activate();
    p.jr.close();
    let path = p.pr.clone();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    save_fixture(&p, &path, &client, &server);
    let (mut child, address) = spawn(&path, 2, 1, "empty", 1);
    let endpoint = ControlEndpoint::client(
        &p.f.initiator,
        p.session,
        client.credentials(&server),
        tls_limits(),
    )
    .expect("endpoint");
    let result = endpoint.run(
        Session {
            journal: &mut p.ji,
            context: &p.f.initiator,
            signer: &p.f.signer_i,
        },
        Run {
            target: 1,
            address,
            server_name: "localhost",
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        || Ok(150),
    );
    wait(&mut child, &path, 1);
    assert!(
        matches!(result, Err(crate::control_transport::Error::Protocol)),
        "{result:?}"
    );
    let progress =
        p.ji.rekey_progress(&p.f.initiator, p.session)
            .expect("actual local state");
    assert_eq!(
        (progress.confirmed_epoch, progress.pending_epoch),
        (0, Some(1))
    );
}

#[test]
fn control_tls_process_loss_before_each_reply_recovers_original_control_bytes() {
    for (cut, active, attempts, flight) in [
        ("cut-offer", 2, 1, Some(RekeyFlight::Offer)),
        ("cut-response", 1, 1, Some(RekeyFlight::Response)),
        ("cut-final", 2, 2, Some(RekeyFlight::Final)),
        ("cut-receipt", 1, 2, Some(RekeyFlight::Receipt)),
        ("cut-ack", 2, 3, None),
    ] {
        let mut p = Pair::new();
        p.activate();
        let path = if active == 1 {
            p.jr.close();
            p.pr.clone()
        } else {
            p.ji.close();
            p.pi.clone()
        };
        let client = Identity::new("client.test");
        let server = Identity::new("localhost");
        save_fixture(&p, &path, &client, &server);
        let (mut child, address) = spawn(&path, 3 - active, 1, cut, 1);
        let (journal, context, signer) = if active == 1 {
            (&mut p.ji, &p.f.initiator, &p.f.signer_i)
        } else {
            (&mut p.jr, &p.f.responder, &p.f.signer_r)
        };
        let endpoint = ControlEndpoint::client(
            context,
            p.session,
            client.credentials(&server),
            tls_limits(),
        )
        .expect("endpoint");
        let watch = path.clone();
        std::thread::scope(|scope| {
            let killer = scope.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !watch.join("tls-cut-ready").exists() {
                    assert!(
                        child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                        "{cut}: {}",
                        fs::read_to_string(watch.join("tls-1.log")).expect("log")
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(
                    fs::read_to_string(watch.join("tls-cut-ready")).expect("stage"),
                    cut
                );
                child.0.kill().expect("kill owned server");
                assert!(!child.0.wait().expect("reap").success());
            });
            let result = endpoint.run(
                Session {
                    journal,
                    context,
                    signer,
                },
                Run {
                    target: 1,
                    address,
                    server_name: "localhost",
                    limits: RunLimits {
                        exchanges: attempts,
                        ..limits()
                    },
                    cancel: &Cancellation::default(),
                },
                || Ok(150),
            );
            killer.join().expect("cut observer");
            assert!(
                matches!(result,Err(crate::control_transport::Error::RetryExhausted{attempts:observed,..}) if observed==attempts),
                "{cut}: {result:?}"
            );
        });
        let resume = journal
            .start_control_delivery(context, p.session, 1, signer, 150)
            .expect("exact pending delivery");
        let message = match resume {
            RekeyControlStep::Output(message) => Ok(message),
            RekeyControlStep::LocallyConfirmed(epoch) => Err(epoch),
        }
        .expect("even a committed receipt still needs dispatch");
        assert_eq!(
            message.as_bytes(),
            fs::read(path.join("tls-cut-input")).expect("actual bytes received by killed peer")
        );
        let (mut child, address) = spawn(&path, 3 - active, 2, "normal", 1);
        let result = endpoint
            .run(
                Session {
                    journal,
                    context,
                    signer,
                },
                Run {
                    target: 1,
                    address,
                    server_name: "localhost",
                    limits: limits(),
                    cancel: &Cancellation::default(),
                },
                || Ok(150),
            )
            .expect("new process reconciles same target");
        assert_eq!(result.epoch, 1);
        wait(&mut child, &path, 2);
        let (peer, pc) = if active == 1 {
            p.jr = reopen(&path, p.f.local_device());
            (&mut p.jr, &p.f.responder)
        } else {
            p.ji = reopen(&path, p.f.initiator_device());
            (&mut p.ji, &p.f.initiator)
        };
        assert_eq!(
            peer.rekey_progress(pc, p.session)
                .expect("actual peer state")
                .confirmed_epoch,
            1
        );
        if let Some(flight) = flight {
            assert_eq!(
                peer.rekey_outbox(pc, p.session, 1, flight, 150)
                    .expect("retained exact response"),
                fs::read(path.join("tls-cut-output")).expect("pre-dispatch wire")
            );
        }
        eprintln!(
            "CONTROL_TLS_PROCESS_RECOVERY cut={cut} failed_exchanges={attempts} recovered_epoch=1"
        );
    }
}

#[test]
fn control_tls_absolute_deadline_and_protocol_expiry_close_a_live_silent_socket() {
    for expiry in [false, true] {
        let mut p = Pair::new();
        p.activate();
        p.jr.close();
        let path = p.pr.clone();
        let client = Identity::new("client.test");
        let server = Identity::new("localhost");
        save_fixture(&p, &path, &client, &server);
        let (mut child, address) = spawn(&path, 2, 1, "stall", 1);
        let endpoint = ControlEndpoint::client(
            &p.f.initiator,
            p.session,
            client.credentials(&server),
            tls_limits(),
        )
        .expect("endpoint");
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("prepare before measured wait");
        let time = Arc::new(std::sync::atomic::AtomicU64::new(150));
        let update = Arc::clone(&time);
        let watch = path.clone();
        std::thread::scope(|scope| {
            let observer = scope.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                while !watch.join("tls-stalled").exists() {
                    assert!(Instant::now() < deadline, "live TLS wait not observed");
                    std::thread::sleep(Duration::from_millis(5));
                }
                if expiry {
                    update.store(201, Ordering::SeqCst);
                }
            });
            let start = Instant::now();
            let result = endpoint.run(
                Session {
                    journal: &mut p.ji,
                    context: &p.f.initiator,
                    signer: &p.f.signer_i,
                },
                Run {
                    target: 1,
                    address,
                    server_name: "localhost",
                    limits: RunLimits {
                        timeout: Duration::from_secs(2),
                        ..limits()
                    },
                    cancel: &Cancellation::default(),
                },
                || Ok(time.load(Ordering::SeqCst)),
            );
            observer.join().expect("observer");
            if expiry {
                assert!(
                    matches!(
                        result,
                        Err(crate::control_transport::Error::Authority(
                            crate::Error::Validity
                        ))
                    ),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(crate::control_transport::Error::Deadline)),
                    "{result:?}"
                );
                assert!(start.elapsed() >= Duration::from_secs(2));
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "absolute run deadline did not bound the live wait"
            );
        });
        wait(&mut child, &path, 1);
        assert!(path.join("tls-peer-closed").is_file());
        assert_eq!(
            p.ji.rekey_progress(&p.f.initiator, p.session)
                .expect("retained metadata")
                .confirmed_epoch,
            0
        );
    }
}

#[test]
fn control_tls_real_processes_complete_alternating_targets_and_preserve_application_keys() {
    for active in [1, 2] {
        let mut p = Pair::new();
        p.activate();
        let client = Identity::new("client.test");
        let server = Identity::new("localhost");
        let path = if active == 1 {
            p.jr.close();
            p.pr.clone()
        } else {
            p.ji.close();
            p.pi.clone()
        };
        save_fixture(&p, &path, &client, &server);
        let (mut child, address) = spawn(&path, 3 - active, 1, "normal", 3);
        let (journal, context, signer) = if active == 1 {
            (&mut p.ji, &p.f.initiator, &p.f.signer_i)
        } else {
            (&mut p.jr, &p.f.responder, &p.f.signer_r)
        };
        let endpoint = ControlEndpoint::client(
            context,
            p.session,
            client.credentials(&server),
            tls_limits(),
        )
        .expect("pinned TLS client");
        for target in 1..=3 {
            let result = endpoint
                .run(
                    Session {
                        journal,
                        context,
                        signer,
                    },
                    Run {
                        target,
                        address,
                        server_name: "localhost",
                        limits: limits(),
                        cancel: &Cancellation::default(),
                    },
                    || Ok(150),
                )
                .expect("real control TLS run");
            assert_eq!(result.epoch, target);
            assert!((2..=3).contains(&result.exchanges));
            assert_eq!(
                journal
                    .rekey_progress(context, p.session)
                    .expect("local state")
                    .confirmed_epoch,
                target
            );
        }
        wait(&mut child, &path, 1);
        if active == 1 {
            p.jr = reopen(&path, p.f.local_device());
        } else {
            p.ji = reopen(&path, p.f.initiator_device());
        }
        let slot =
            p.ji.next_message_id(&p.f.initiator, p.session, 150)
                .expect("new epoch slot");
        let wire = p.send(slot, b"keys installed through real TLS peers");
        assert_eq!(
            p.receive(&wire).as_bytes(),
            b"keys installed through real TLS peers"
        );
    }
}

#[test]
fn control_tls_cancellation_closes_real_socket_and_releases_endpoint_capacity_without_reset() {
    let mut p = Pair::new();
    p.activate();
    p.jr.close();
    let path = p.pr.clone();
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    save_fixture(&p, &path, &client, &server);
    let (mut child, address) = spawn(&path, 2, 1, "stall", 1);
    let endpoint = ControlEndpoint::client(
        &p.f.initiator,
        p.session,
        client.credentials(&server),
        tls_limits(),
    )
    .expect("endpoint");
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let watch = path.clone();
    std::thread::scope(|scope| {
        let observer = scope.spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !watch.join("tls-stalled").exists() {
                assert!(Instant::now() < deadline, "TLS input was not observed");
                std::thread::sleep(Duration::from_millis(5));
            }
            signal.cancel();
        });
        let result = endpoint.run(
            Session {
                journal: &mut p.ji,
                context: &p.f.initiator,
                signer: &p.f.signer_i,
            },
            Run {
                target: 1,
                address,
                server_name: "localhost",
                limits: limits(),
                cancel: &cancel,
            },
            || Ok(150),
        );
        assert!(
            matches!(result, Err(crate::control_transport::Error::Cancelled)),
            "result={result:?}; server={}",
            fs::read_to_string(path.join("tls-1.log")).expect("server log")
        );
        observer.join().expect("observer");
    });
    wait(&mut child, &path, 1);
    assert!(path.join("tls-peer-closed").is_file());
    let before =
        p.ji.rekey_outbox(&p.f.initiator, p.session, 1, RekeyFlight::Offer, 150)
            .expect("committed offer survives cancel");
    let (mut child, address) = spawn(&path, 2, 2, "normal", 1);
    let result = endpoint
        .run(
            Session {
                journal: &mut p.ji,
                context: &p.f.initiator,
                signer: &p.f.signer_i,
            },
            Run {
                target: 1,
                address,
                server_name: "localhost",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        )
        .expect("same endpoint's capacity recovered");
    assert_eq!(result.epoch, 1);
    wait(&mut child, &path, 2);
    assert_eq!(
        p.ji.rekey_outbox(&p.f.initiator, p.session, 1, RekeyFlight::Offer, 150)
            .expect("same offer"),
        before
    );
}
