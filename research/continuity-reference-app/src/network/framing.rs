// SPDX-License-Identifier: Apache-2.0 OR MIT
use q_periapt_continuity_identity_candidate as sdk;
use std::{
    future::Future,
    io,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(super) fn size(length: usize) -> io::Result<()> {
    if !(10..=sdk::contract::MAX_CONNECTION_FRAME_BYTES).contains(&length) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
pub(super) fn check(deadline: Instant, cancel: &sdk::Cancellation) -> io::Result<()> {
    if cancel.is_cancelled() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}
pub(super) async fn cancelled(cancel: &sdk::Cancellation) {
    while !cancel.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
pub(super) async fn bounded<T>(
    deadline: Instant,
    cancel: &sdk::Cancellation,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    check(deadline, cancel)?;
    tokio::select! {
        biased;
        _=cancelled(cancel)=>Err(io::ErrorKind::Interrupted.into()),
        value=tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),operation)=>
            value.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
    }
}
pub(super) async fn read(
    stream: &mut TcpStream,
    deadline: Instant,
    cancel: &sdk::Cancellation,
) -> io::Result<Vec<u8>> {
    let frame = bounded(deadline, cancel, async {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let length = u32::from_be_bytes(header) as usize;
        size(length)?;
        let mut frame = vec![0; length];
        stream.read_exact(&mut frame).await?;
        Ok(frame)
    })
    .await?;
    // Read bytes are still local: cancellation/expiry must prevent owner admission.
    check(deadline, cancel)?;
    Ok(frame)
}
pub(super) async fn write(
    stream: &mut TcpStream,
    frame: &[u8],
    deadline: Instant,
    cancel: &sdk::Cancellation,
) -> io::Result<()> {
    size(frame.len())?;
    // Once a complete write succeeds, those bytes have left our control. Do not
    // relabel that observation as failure if shutdown arrives before accounting.
    // Cancellation before/during I/O still interrupts it; this proves no peer ACK.
    bounded(deadline, cancel, async {
        stream
            .write_all(&(frame.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(frame).await?;
        stream.flush().await
    })
    .await
}
