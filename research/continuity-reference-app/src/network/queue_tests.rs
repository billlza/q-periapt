// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real carrier sockets; no authenticated-protocol claim is made by echo tests.
use super::*;
use q_periapt_continuity_identity_candidate as sdk;
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Held {
    address: SocketAddr,
    stop: sdk::Cancellation,
    calls: Arc<AtomicUsize>,
    release: mpsc::SyncSender<()>,
    server: JoinHandle<io::Result<Stats>>,
}
async fn held(limits: Limits) -> Result<Held> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stop = sdk::Cancellation::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let (release, receiver) = mpsc::sync_channel(1);
    let receiver = Mutex::new(receiver);
    let server = tokio::spawn(serve(listener, limits, stop.clone(), move |request, _| {
        if count.fetch_add(1, Ordering::SeqCst) == 0 {
            receiver
                .lock()
                .map_err(|_| io::Error::other("gate poisoned"))?
                .recv_timeout(Duration::from_secs(4))
                .map_err(io::Error::other)?;
        }
        Ok(request.to_vec())
    }));
    Ok(Held {
        address,
        stop,
        calls,
        release,
        server,
    })
}
async fn send(address: SocketAddr, id: u8) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(address).await?;
    let mut wire = 10u32.to_be_bytes().to_vec();
    wire.extend_from_slice(b"QPCXCH01\x01");
    wire.push(id);
    stream.write_all(&wire).await?;
    Ok(stream)
}
async fn read(mut stream: TcpStream) -> io::Result<Option<u8>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut prefix = [0; 4];
        if stream.read(&mut prefix[..1]).await? == 0 {
            return Ok(None);
        }
        stream.read_exact(&mut prefix[1..]).await?;
        if u32::from_be_bytes(prefix) != 10 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut body = [0; 10];
        stream.read_exact(&mut body).await?;
        if &body[..9] != b"QPCXCH01\x01" {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(body[9]))
    })
    .await?
}
async fn first(service: &Held) -> Result<TcpStream> {
    let stream = send(service.address, 0).await?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while service.calls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    Ok(stream)
}
async fn extras(service: &Held, count: u8) -> Result<JoinSet<io::Result<Option<u8>>>> {
    let mut replies = JoinSet::new();
    for id in 1..=count {
        replies.spawn(read(send(service.address, id).await?));
    }
    Ok(replies)
}
fn limits(queued: usize) -> Limits {
    Limits {
        queued,
        pending: 8,
        per_ip: 8,
        ..Limits::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_frames_queue_with_a_hard_capacity_and_one_owner() -> Result<()> {
    let service = held(limits(2)).await?;
    let initial = first(&service).await?;
    let mut replies = extras(&service, 3).await?;
    // With the owner still held, exactly one overflow closes and two must wait.
    assert_eq!(replies.join_next().await.ok_or("missing overflow")???, None);
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    service.release.send(())?;
    assert_eq!(read(initial).await?, Some(0));
    let mut observed = Vec::new();
    while let Some(reply) = replies.join_next().await {
        observed.push(reply??.ok_or("queued frame lost")?);
    }
    observed.sort_unstable();
    observed.dedup();
    assert_eq!(observed.len(), 2);
    service.stop.cancel();
    let stats = service.server.await??;
    assert_eq!(service.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        (
            stats.queued_requests,
            stats.rejected_busy,
            stats.completed_responses
        ),
        (2, 1, 3)
    );
    assert_eq!(
        (
            stats.expired_queued,
            stats.evicted_incomplete,
            stats.operation_errors
        ),
        (0, 0, 0)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_expiry_never_resets_the_deadline_or_calls_the_owner() -> Result<()> {
    let service = held(Limits {
        read_timeout: Duration::from_millis(300),
        operation_timeout: Duration::from_millis(300),
        ..limits(2)
    })
    .await?;
    let initial = first(&service).await?;
    let mut replies = extras(&service, 2).await?;
    while let Some(reply) = replies.join_next().await {
        assert_eq!(reply??, None);
    }
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    // The active callback is deliberately held past both queued deadlines.
    service.release.send(())?;
    assert_eq!(read(initial).await?, None);
    service.stop.cancel();
    let stats = service.server.await??;
    assert_eq!(
        (
            stats.queued_requests,
            stats.expired_queued,
            stats.completed_responses
        ),
        (2, 2, 0)
    );
    assert_eq!(
        (
            stats.rejected_busy,
            stats.evicted_incomplete,
            stats.operation_errors
        ),
        (0, 0, 1)
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_discards_queued_inputs_but_joins_the_active_owner() -> Result<()> {
    let service = held(limits(1)).await?;
    let initial = first(&service).await?;
    let mut replies = extras(&service, 2).await?;
    assert_eq!(replies.join_next().await.ok_or("missing overflow")???, None);
    service.stop.cancel();
    assert_eq!(
        replies
            .join_next()
            .await
            .ok_or("missing queued input")???,
        None
    );
    assert!(
        !service.server.is_finished(),
        "active owner detached during shutdown"
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    service.release.send(())?;
    assert_eq!(read(initial).await?, None);
    let stats = service.server.await??;
    assert_eq!(
        (
            stats.queued_requests,
            stats.rejected_busy,
            stats.completed_responses
        ),
        (1, 1, 0)
    );
    assert_eq!((stats.expired_queued, stats.evicted_incomplete), (0, 0));
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
