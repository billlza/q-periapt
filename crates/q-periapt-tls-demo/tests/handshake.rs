//! Integration test: a real server-authenticated PQ/T hybrid handshake over a
//! loopback TCP socket, for both profiles. Both peers must derive the same session
//! secret, and the client must verify the server's ML-DSA-65 signature.

#![allow(clippy::unwrap_used)]

use q_periapt_core::Profile;
use q_periapt_tls_demo::{
    client_handshake, client_handshake_enhanced, server_handshake, server_handshake_enhanced,
    ServerKeys,
};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

fn run(profile: Profile) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let keys = ServerKeys::from_seeds([1u8; 64], [2u8; 32], [3u8; 32]);
    let server_vk = keys.verifying_key();

    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let (secret, _stats) = server_handshake(&mut s, &keys).unwrap();
        tx.send(*secret.as_bytes()).unwrap();
    });

    let mut s = TcpStream::connect(addr).unwrap();
    let (client_secret, stats) = client_handshake(&mut s, profile, &server_vk).unwrap();
    let server_secret = rx.recv().unwrap();
    server.join().unwrap();

    assert_eq!(
        client_secret.as_bytes(),
        &server_secret,
        "{profile:?}: client and server must derive the same session secret"
    );
    // The PQ material dominates: ~2.2 KB KEM + ~3.3 KB ML-DSA signature.
    assert!(stats.bytes_sent + stats.bytes_recv > 5000);
}

#[test]
fn handshake_context_bound() {
    run(Profile::ContextBound);
}

#[test]
fn handshake_compat_xwing() {
    run(Profile::CompatXWing);
}

/// Full enhanced (NIST L5) handshake: ML-KEM-1024 + X25519 KEM with ML-DSA-87 server
/// auth. Both peers must derive the same secret, and the wire is markedly larger than
/// the default suite (1568-byte KEM ct + 4627-byte signature).
fn run_enhanced(profile: Profile) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let keys = ServerKeys::from_seeds_enhanced([1u8; 64], [2u8; 32], [3u8; 32]);
    let server_vk = keys.verifying_key();

    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let (secret, _stats) = server_handshake_enhanced(&mut s, &keys).unwrap();
        tx.send(*secret.as_bytes()).unwrap();
    });

    let mut s = TcpStream::connect(addr).unwrap();
    let (client_secret, stats) = client_handshake_enhanced(&mut s, profile, &server_vk).unwrap();
    let server_secret = rx.recv().unwrap();
    server.join().unwrap();

    assert_eq!(
        client_secret.as_bytes(),
        &server_secret,
        "{profile:?}: enhanced client and server must derive the same session secret"
    );
    // L5 is bigger: ~3.2 KB KEM (1568 ct + 1568 ek) + ~4.6 KB ML-DSA-87 signature.
    assert!(
        stats.bytes_sent + stats.bytes_recv > 7000,
        "enhanced wire should exceed the default suite"
    );
}

#[test]
fn handshake_enhanced_context_bound() {
    run_enhanced(Profile::ContextBound);
}

/// The enhanced handshake's ML-DSA-87 auth must reject a mismatched server identity.
#[test]
fn handshake_enhanced_rejects_wrong_server_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let keys = ServerKeys::from_seeds_enhanced([4u8; 64], [5u8; 32], [6u8; 32]);
    let wrong_vk = ServerKeys::from_seeds_enhanced([0u8; 64], [0u8; 32], [9u8; 32]).verifying_key();

    let server = thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = server_handshake_enhanced(&mut s, &keys);
        }
    });

    let mut s = TcpStream::connect(addr).unwrap();
    let res = client_handshake_enhanced(&mut s, Profile::ContextBound, &wrong_vk);
    assert!(
        res.is_err(),
        "enhanced client must reject a mismatched ML-DSA-87 server identity"
    );
    let _ = server.join();
}

#[test]
fn handshake_rejects_wrong_server_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let keys = ServerKeys::from_seeds([4u8; 64], [5u8; 32], [6u8; 32]);
    // A different identity key than the server actually holds.
    let wrong_vk = ServerKeys::from_seeds([0u8; 64], [0u8; 32], [9u8; 32]).verifying_key();

    let server = thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = server_handshake(&mut s, &keys);
        }
    });

    let mut s = TcpStream::connect(addr).unwrap();
    let res = client_handshake(&mut s, Profile::ContextBound, &wrong_vk);
    assert!(
        res.is_err(),
        "client must reject a mismatched server identity"
    );
    let _ = server.join();
}
