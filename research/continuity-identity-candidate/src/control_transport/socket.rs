// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_rustls::connection::{Connection, Phase, MAX_TLS_IO_BYTES};
use std::io::{Read, Write};

pub(super) struct Request {
    id: u64,
    wire: Vec<u8>,
}
impl Request {
    pub(super) fn id(&self) -> u64 {
        self.id
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.wire
    }
}

pub(super) struct Channel {
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
    pub(super) fn new(stream: TcpStream, engine: Connection) -> Result<Self, Error> {
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
    pub(super) fn exchange(
        &mut self,
        wire: &[u8],
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<Option<Vec<u8>>, Error> {
        if wire.is_empty() || wire.len() > MAX_CONTROL {
            return Err(Error::Protocol);
        }
        self.until(Phase::Ready, context, cancel, deadline, clock)?;
        let mut request = MAGIC.to_vec();
        request.extend_from_slice(wire);
        self.engine.send_request(&request)?;
        self.until(Phase::ResponseReady, context, cancel, deadline, clock)?;
        let response = self.engine.take_response()?;
        let bytes = response.bytes();
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(Error::Protocol);
        }
        let (kind, body) = bytes
            .get(MAGIC.len()..)
            .ok_or(Error::Protocol)?
            .split_first()
            .ok_or(Error::Protocol)?;
        match (*kind, body.len()) {
            (0, 0) => Ok(None),
            (1, 1..=MAX_CONTROL) => Ok(Some(body.to_vec())),
            _ => Err(Error::Protocol),
        }
    }
    pub(super) fn request(
        &mut self,
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<Request, Error> {
        self.until(Phase::RequestReady, context, cancel, deadline, clock)?;
        let request = self.engine.take_request()?;
        if request.bytes().get(..MAGIC.len()) != Some(MAGIC.as_slice())
            || !(MAGIC.len() + 1..=MAGIC.len() + MAX_CONTROL).contains(&request.bytes().len())
        {
            return Err(Error::Protocol);
        }
        Ok(Request {
            id: request.request_id(),
            wire: request
                .bytes()
                .get(MAGIC.len()..)
                .ok_or(Error::Protocol)?
                .to_vec(),
        })
    }
    pub(super) fn respond(
        &mut self,
        id: u64,
        wire: Option<&[u8]>,
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<(), Error> {
        let mut response = MAGIC.to_vec();
        match wire {
            Some(wire) if !wire.is_empty() && wire.len() <= MAX_CONTROL => {
                response.push(1);
                response.extend_from_slice(wire);
            }
            Some(_) => return Err(Error::Protocol),
            None => response.push(0),
        }
        self.engine.send_response(id, &response)?;
        self.flush(context, cancel, deadline, clock)
    }
    pub(super) fn finish(
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
