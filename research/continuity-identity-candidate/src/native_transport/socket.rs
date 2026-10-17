// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_rustls::connection::{Connection, Phase, MAX_TLS_IO_BYTES};
use std::io::{Read, Write};

pub(crate) struct Request {
    id: u64,
    wire: Vec<u8>,
}
impl Request {
    #[cfg(feature = "control-tls")]
    pub(crate) fn from_carrier(id: u64, wire: Vec<u8>) -> Self {
        Self { id, wire }
    }
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.wire
    }
}

pub(crate) struct Channel {
    stream: TcpStream,
    engine: Connection,
    finishing: bool,
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.engine.close();
        // Drop cannot report a socket shutdown error; it grants no delivery claim.
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
impl Channel {
    pub(crate) fn new(stream: TcpStream, engine: Connection) -> Result<Self, Error> {
        stream.set_nodelay(true)?;
        stream.set_nonblocking(false)?;
        Ok(Self {
            stream,
            engine,
            finishing: false,
        })
    }
    fn budget(&self, deadline: Instant, engine_ms: u32) -> Result<Duration, Error> {
        Ok(remaining(deadline)?
            .min(Duration::from_millis(u64::from(engine_ms).max(1)))
            .min(Duration::from_millis(25)))
    }
    fn flush(
        &mut self,
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<(), Error> {
        let mut buffer = [0; MAX_TLS_IO_BYTES];
        loop {
            check(context, cancel, deadline, clock)?;
            let progress = match self.engine.progress() {
                Err(connection::Error::Closed) if self.engine.is_closed() && self.finishing => {
                    return Ok(())
                }
                Err(connection::Error::Closed) if self.engine.is_closed() => {
                    return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()))
                }
                Err(error) => return Err(error.into()),
                Ok(progress) => progress,
            };
            if !progress.wants_write {
                return Ok(());
            }
            let phase_deadline = Instant::now()
                .checked_add(Duration::from_millis(u64::from(progress.remaining_ms)))
                .ok_or(Error::InvalidOptions)?;
            let length = self.engine.drain_tls(&mut buffer)?;
            if length == 0 {
                return Err(Error::Protocol);
            }
            let mut pending = buffer.get(..length).ok_or(Error::Protocol)?;
            while !pending.is_empty() {
                check(context, cancel, deadline, clock)?;
                // Draining close_notify can finish the engine before the host
                // writes its ciphertext. Retain the observed absolute deadline.
                let budget = remaining(deadline)?
                    .min(remaining(phase_deadline)?)
                    .min(Duration::from_millis(25));
                self.stream.set_write_timeout(Some(budget))?;
                match self.stream.write(pending) {
                    Ok(0) => return Err(Error::Io(io::ErrorKind::WriteZero.into())),
                    Ok(written) => pending = pending.get(written..).ok_or(Error::Protocol)?,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted
                                | io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                        ) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    fn until(
        &mut self,
        phase: Phase,
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<(), Error> {
        let mut buffer = [0; MAX_TLS_IO_BYTES];
        loop {
            check(context, cancel, deadline, clock)?;
            self.flush(context, cancel, deadline, clock)?;
            let progress = self.engine.progress()?;
            if progress.phase == phase {
                return Ok(());
            }
            self.stream
                .set_read_timeout(Some(self.budget(deadline, progress.remaining_ms)?))?;
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.engine.end_of_input()?;
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                Ok(read) => {
                    let mut pending = buffer.get(..read).ok_or(Error::Protocol)?;
                    while !pending.is_empty() {
                        check(context, cancel, deadline, clock)?;
                        let consumed = self.engine.feed_tls(pending)?;
                        if consumed == 0 {
                            return Err(Error::Protocol);
                        }
                        pending = pending.get(consumed..).ok_or(Error::Protocol)?;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    pub(crate) fn exchange(
        &mut self,
        wire: &[u8],
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<Vec<u8>, Error> {
        self.until(Phase::Ready, context, cancel, deadline, clock)?;
        self.engine.send_request(wire)?;
        self.until(Phase::ResponseReady, context, cancel, deadline, clock)?;
        Ok(self.engine.take_response()?.bytes().to_vec())
    }
    pub(crate) fn request(
        &mut self,
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<Request, Error> {
        self.until(Phase::RequestReady, context, cancel, deadline, clock)?;
        let request = self.engine.take_request()?;
        Ok(Request {
            id: request.request_id(),
            wire: request.bytes().to_vec(),
        })
    }
    pub(crate) fn respond(
        &mut self,
        id: u64,
        wire: &[u8],
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<(), Error> {
        self.engine.send_response(id, wire)?;
        self.flush(context, cancel, deadline, clock)
    }
    pub(crate) fn finish(
        &mut self,
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<(), Error> {
        self.engine.shutdown()?;
        self.finishing = true;
        self.flush(context, cancel, deadline, clock)
    }
}
