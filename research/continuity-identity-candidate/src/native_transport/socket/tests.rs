// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{bootstrap::tests::fixture, PrekeyQuality};
use q_periapt_rustls::connection::{Credentials, Endpoint, Limits};
use std::{net::TcpListener, sync::Arc};

#[test]
fn clock_callback_cancellation_is_checked_before_return() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let cancel = Cancellation::default();
    let result = check(
        &f.initiator,
        &cancel,
        Instant::now() + Duration::from_secs(10),
        &mut || {
            cancel.cancel();
            Ok(150)
        },
    );
    assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");
}

#[test]
fn clock_callback_deadline_is_checked_before_return() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut calls = 0;
    let result = check(
        &f.initiator,
        &Cancellation::default(),
        deadline,
        &mut || {
            calls += 1;
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            Ok(150)
        },
    );
    assert_eq!(calls, 1, "the deadline must elapse inside the callback");
    assert!(matches!(result, Err(Error::Deadline)), "{result:?}");
}

#[test]
fn tls_flush_does_not_write_after_clock_callback_cancellation() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let client = rcgen::generate_simple_self_signed(vec!["client.test".into()])
        .expect("client TLS identity");
    let server =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("server TLS identity");
    let key = zeroize::Zeroizing::new(client.signing_key.serialize_der());
    let endpoint = Endpoint::client(
        Arc::clone(&f.initiator.current_policy().expect("policy").runtime),
        Credentials {
            certificate: client.cert.der(),
            private_key: &key,
            peer_certificate: server.cert.der(),
        },
        &f.initiator.digest(),
        Limits {
            max_connections: 1,
            handshake_ms: 10_000,
            request_ms: 10_000,
            idle_ms: 10_000,
        },
    )
    .expect("real TLS endpoint");
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let stream =
        TcpStream::connect(listener.local_addr().expect("address")).expect("loopback connection");
    let (mut peer, _) = listener.accept().expect("accepted connection");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bounded peer read");
    let engine = endpoint.connect("localhost").expect("TLS client");
    let mut channel = Channel::new(stream, engine).expect("native channel");
    let cancel = Cancellation::default();
    let mut calls = 0;
    let result = channel.flush(
        &f.initiator,
        &cancel,
        Instant::now() + Duration::from_secs(10),
        &mut || {
            calls += 1;
            // The first read admits TLS progress; the next admits the first
            // socket write. Cancel while that host callback is executing.
            if calls == 2 {
                cancel.cancel();
            }
            Ok(150)
        },
    );
    assert!(calls >= 2, "the pre-write callback must be reached");
    assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");
    drop(channel);
    let mut received = Vec::new();
    peer.read_to_end(&mut received)
        .expect("peer observes the closed socket");
    assert!(
        received.is_empty(),
        "TLS wrote {} bytes after cancellation in the clock callback",
        received.len()
    );
}
