// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real sockets and bounded worker lifetime. Echo payloads test framing only;
//! authenticated package interoperability is exercised by the external workload.
use super::*;
use q_periapt_continuity_identity_candidate as sdk;
use sdk::session_exchange::Transport;
use std::{
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const FRAME: &[u8] = b"QPCXCH01\x01x";

#[tokio::test]
async fn completed_socket_write_remains_observable_when_shutdown_arrives() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut sender = TcpStream::connect(address).await?;
    let (mut receiver, _) = listener.accept().await?;
    let stop = sdk::Cancellation::default();
    let result = super::framing::bounded(Instant::now() + Duration::from_secs(2), &stop, async {
        sender.write_all(FRAME).await?;
        // The peer can trigger shutdown after seeing the complete bytes,
        // before the server resumes its response-accounting continuation.
        stop.cancel();
        Ok(())
    })
    .await;
    let mut received = vec![0; FRAME.len()];
    tokio::time::timeout(Duration::from_secs(1), receiver.read_exact(&mut received)).await??;
    assert_eq!(received, FRAME);
    assert!(
        result.is_ok(),
        "completed I/O was relabelled as cancellation: {result:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_connections_do_not_hold_all_read_slots() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stop = sdk::Cancellation::default();
    let child_stop = stop.clone();
    let limits = Limits {
        pending: 2,
        per_ip: 2,
        read_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(5),
    };
    let server = tokio::spawn(serve(listener, limits, child_stop, |request, _| {
        Ok(request.to_vec())
    }));
    let one = TcpStream::connect(address).await?;
    let two = TcpStream::connect(address).await?;
    let started = Instant::now();
    let response = tokio::task::spawn_blocking(move || {
        TcpTransport::new(address)?.exchange(
            FRAME,
            Instant::now() + Duration::from_secs(2),
            &sdk::Cancellation::default(),
        )
    })
    .await??;
    assert_eq!(response, FRAME);
    assert!(started.elapsed() < Duration::from_secs(2));
    drop((one, two));
    stop.cancel();
    let stats = server.await??;
    assert_eq!(stats.accepted, 3);
    assert!(stats.evicted_incomplete >= 1);
    assert_eq!(stats.completed_responses, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_length_never_reaches_the_owner() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let stop = sdk::Cancellation::default();
    let child_stop = stop.clone();
    let server = tokio::spawn(serve(
        listener,
        Limits::default(),
        child_stop,
        move |request, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(request.to_vec())
        },
    ));
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&u32::MAX.to_be_bytes()).await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1])).await??,
        0
    );
    stop.cancel();
    let stats = server.await??;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(stats.read_errors, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_owner_is_bounded_and_shutdown_joins_the_actual_worker() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let entered = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&entered);
    let (release, receiver) = mpsc::sync_channel::<()>(1);
    let receiver = Mutex::new(receiver);
    let stop = sdk::Cancellation::default();
    let child_stop = stop.clone();
    let server = tokio::spawn(serve(
        listener,
        Limits::default(),
        child_stop,
        move |request, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            receiver
                .lock()
                .map_err(|_| io::Error::other("receiver lock poisoned"))?
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
            Ok(request.to_vec())
        },
    ));
    let first = tokio::task::spawn_blocking(move || {
        TcpTransport::new(address)?.exchange(
            FRAME,
            Instant::now() + Duration::from_secs(4),
            &sdk::Cancellation::default(),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while entered.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    let second = tokio::task::spawn_blocking(move || {
        TcpTransport::new(address)?.exchange(
            FRAME,
            Instant::now() + Duration::from_secs(1),
            &sdk::Cancellation::default(),
        )
    })
    .await?;
    assert!(second.is_err());
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!server.is_finished(), "worker must not be detached");
    release.send(())?;
    assert!(first.await?.is_err());
    let stats = server.await??;
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    assert_eq!(stats.rejected_busy, 1);
    assert_eq!(stats.completed_responses, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_reply_cancellation_closes_the_real_socket() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (ready, wait) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = [0; 14];
        stream.read_exact(&mut request).await?;
        stream.write_all(&[0, 0]).await?;
        ready
            .send(())
            .map_err(|_| io::Error::other("ready receiver closed"))?;
        stream.read(&mut [0; 1]).await
    });
    let cancel = sdk::Cancellation::default();
    let client_cancel = cancel.clone();
    let client = tokio::task::spawn_blocking(move || {
        TcpTransport::new(address)?.exchange(
            FRAME,
            Instant::now() + Duration::from_secs(3),
            &client_cancel,
        )
    });
    tokio::time::timeout(Duration::from_secs(1), wait).await??;
    let start = Instant::now();
    cancel.cancel();
    assert_eq!(
        client
            .await?
            .err()
            .ok_or("cancelled read succeeded")?
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    match server.await? {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        Ok(_) => return Err("extra data after cancellation".into()),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[test]
fn accepted_deadline_is_preserved_and_route_is_only_metadata() -> Result<()> {
    let cancel = sdk::Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        sdk::session_exchange::Run::until(&cancel, deadline)?.deadline(),
        deadline
    );
    assert!(sdk::session_exchange::Run::until(&cancel, Instant::now()).is_err());
    assert!(
        sdk::session_exchange::Run::until(&cancel, Instant::now() + Duration::from_secs(121))
            .is_err()
    );
    assert_eq!(
        sdk::session_exchange::RequestRoute::inspect(FRAME)?,
        sdk::session_exchange::RequestRoute::Bootstrap
    );
    assert!(sdk::session_exchange::RequestRoute::inspect(b"QPCXCH01\xffx").is_err());
    assert!(sdk::session_exchange::RequestRoute::inspect(&[0; 32769]).is_err());
    Ok(())
}
