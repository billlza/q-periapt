// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::io::{Read, Write};

const MAX_WIRE_BYTES: usize = 256 * 1024;
const MAX_BUFFER_BYTES: usize = 16 * 1024;

struct Network<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
    cancel: &'a Cancellation,
    used: &'a mut usize,
}
impl Network<'_> {
    fn count(&self, available: usize) -> io::Result<usize> {
        let left = MAX_WIRE_BYTES
            .checked_sub(*self.used)
            .filter(|left| *left > 0)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "witness TLS wire budget exhausted",
                )
            })?;
        Ok(available.min(left))
    }
    fn window(&self) -> io::Result<Duration> {
        Ok(checked_remaining(self.deadline, self.cancel)?.min(Duration::from_millis(25)))
    }
}
impl Read for Network<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.window()?))?;
        let length = self.count(buffer.len())?;
        let read = self.stream.read(
            buffer
                .get_mut(..length)
                .ok_or(io::ErrorKind::InvalidInput)?,
        )?;
        *self.used += read;
        Ok(read)
    }
}
impl Write for Network<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.window()?))?;
        let length = self.count(buffer.len())?;
        let written = self
            .stream
            .write(buffer.get(..length).ok_or(io::ErrorKind::InvalidInput)?)?;
        *self.used += written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        checked_remaining(self.deadline, self.cancel)?;
        self.stream.flush()
    }
}
fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

pub(super) struct Channel {
    stream: TcpStream,
    connection: Connection,
    deadline: Instant,
    cancel: Cancellation,
    received: usize,
    sent: usize,
}
impl Channel {
    pub(super) fn new(
        stream: TcpStream,
        mut connection: Connection,
        deadline: Instant,
        cancel: Cancellation,
    ) -> io::Result<Self> {
        checked_remaining(deadline, &cancel)?;
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        connection.set_buffer_limit(Some(MAX_BUFFER_BYTES));
        Ok(Self {
            stream,
            connection,
            deadline,
            cancel,
            received: 0,
            sent: 0,
        })
    }
    fn check(&self) -> io::Result<()> {
        checked_remaining(self.deadline, &self.cancel).map(|_| ())
    }
    fn flush(&mut self) -> io::Result<()> {
        while self.connection.wants_write() {
            self.check()?;
            let mut output = Network {
                stream: &mut self.stream,
                deadline: self.deadline,
                cancel: &self.cancel,
                used: &mut self.sent,
            };
            match self.connection.write_tls(&mut output) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(error) if transient(&error) => {}
                Err(error) => return Err(error),
            }
        }
        self.check()
    }
    fn receive_tls(&mut self) -> io::Result<()> {
        self.check()?;
        let mut input = Network {
            stream: &mut self.stream,
            deadline: self.deadline,
            cancel: &self.cancel,
            used: &mut self.received,
        };
        match self.connection.read_tls(&mut input) {
            Ok(read) => {
                let state = self
                    .connection
                    .process_new_packets()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                if read == 0 && !state.peer_has_closed() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error),
        }
        self.check()
    }
    pub(super) fn handshake(&mut self) -> io::Result<()> {
        loop {
            self.flush()?;
            if !self.connection.is_handshaking() {
                break;
            }
            self.receive_tls()?;
        }
        if self.connection.protocol_version() != Some(ProtocolVersion::TLSv1_3)
            || self.connection.handshake_kind() != Some(HandshakeKind::Full)
            || self
                .connection
                .negotiated_key_exchange_group()
                .map(|group| group.name())
                != Some(NamedGroup::X25519MLKEM768)
            || self.connection.alpn_protocol() != Some(APPLICATION_PROTOCOL)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "witness TLS protocol differs",
            ));
        }
        self.peer()?;
        self.check()
    }
    pub(super) fn peer(&self) -> io::Result<&[u8]> {
        let leaf = self
            .connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "witness TLS peer certificate missing",
                )
            })?;
        if leaf.is_empty() || leaf.len() > MAX_CERTIFICATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "witness TLS peer certificate exceeds bound",
            ));
        }
        Ok(leaf.as_ref())
    }
    pub(super) fn send_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.check()?;
        if bytes.is_empty() || bytes.len() > REQUEST_BYTES {
            return Err(invalid("witness TLS frame exceeds bound"));
        }
        self.connection
            .writer()
            .write_all(&(bytes.len() as u32).to_be_bytes())?;
        self.connection.writer().write_all(bytes)?;
        self.flush()
    }
    fn receive(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.check()?;
            match self
                .connection
                .reader()
                .read(bytes.get_mut(offset..).ok_or(io::ErrorKind::InvalidInput)?)
            {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(read) => offset += read,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.flush()?;
                    self.receive_tls()?;
                }
                Err(error) => return Err(error),
            }
        }
        self.check()
    }
    pub(super) fn receive_frame(&mut self, expected: usize) -> io::Result<Vec<u8>> {
        let mut prefix = [0; 4];
        self.receive(&mut prefix)?;
        if u32::from_be_bytes(prefix) as usize != expected || expected > REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "witness TLS frame width differs",
            ));
        }
        let mut bytes = vec![0; expected];
        self.receive(&mut bytes)?;
        Ok(bytes)
    }
    pub(super) fn close(&mut self) -> io::Result<()> {
        self.check()?;
        self.connection.send_close_notify();
        self.flush()
    }
    pub(super) fn receive_close(&mut self) -> io::Result<()> {
        let mut extra = [0];
        loop {
            self.check()?;
            match self.connection.reader().read(&mut extra) {
                Ok(0) => return self.check(),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing witness TLS plaintext",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.flush()?;
                    self.receive_tls()?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
