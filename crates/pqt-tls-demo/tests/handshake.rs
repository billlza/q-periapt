//! Integration test: a real PQ/T hybrid handshake over a loopback TCP socket,
//! for both profiles. Both peers must derive the same session secret.

#![allow(clippy::unwrap_used)]

use pqt_core::Profile;
use pqt_tls_demo::{client_handshake, server_handshake, ServerKeys};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

fn run(profile: Profile) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let keys = ServerKeys::from_seeds([1u8; 64], [2u8; 32]);

    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let (secret, _stats) = server_handshake(&mut s, &keys).unwrap();
        tx.send(*secret.as_bytes()).unwrap();
    });

    let mut s = TcpStream::connect(addr).unwrap();
    let (client_secret, stats) = client_handshake(&mut s, profile).unwrap();
    let server_secret = rx.recv().unwrap();
    server.join().unwrap();

    assert_eq!(
        client_secret.as_bytes(),
        &server_secret,
        "{profile:?}: client and server must derive the same session secret"
    );
    // Sanity on the wire budget: the PQ material dominates (~2.2 KB of ct+pk).
    assert!(stats.bytes_sent + stats.bytes_recv > 2000);
}

#[test]
fn handshake_context_bound() {
    run(Profile::ContextBound);
}

#[test]
fn handshake_compat_xwing() {
    run(Profile::CompatXWing);
}
