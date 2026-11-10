// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared native stream I/O. The original absolute deadline and cancellation
//! apply to every partial read/write; no worker or socket outlives the call.
use crate::{Cancellation, MonotonicInstant as Instant};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::Duration,
};

pub(crate) fn remaining(deadline: Instant, cancel: &Cancellation) -> io::Result<Duration> {
    if cancel.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TCP dispatch cancelled",
        ));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TCP exchange deadline expired"))
}
pub(crate) fn send(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
    cancel: &Cancellation,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(
            remaining(deadline, cancel)?.min(Duration::from_millis(25)),
        ))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = bytes.get(written..).ok_or(io::ErrorKind::InvalidData)?,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    remaining(deadline, cancel)?;
    Ok(())
}
pub(crate) fn receive(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
    cancel: &Cancellation,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream.set_read_timeout(Some(
            remaining(deadline, cancel)?.min(Duration::from_millis(25)),
        ))?;
        match stream.read(bytes.get_mut(offset..).ok_or(io::ErrorKind::InvalidData)?) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    remaining(deadline, cancel)?;
    Ok(())
}
