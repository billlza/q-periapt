// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::Cancellation;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

/// Untrusted byte carrier. Implementations must honor the absolute deadline;
/// journal authority comes only from verification of the complete signed reply.
pub trait AnchorTransport: Send {
    /// Optionally narrow an attempt to an enclosing caller's absolute deadline.
    /// The client never accepts an extension of its own attempt budget. Failure
    /// is checked before signing or dispatch; it does not imply rollback of any
    /// earlier command in the enclosing invocation.
    fn constrain_deadline(&self, deadline: Instant) -> io::Result<Instant> {
        Ok(deadline)
    }
    /// Exchange one bounded signed request. Transport failure says nothing about
    /// whether the witness committed; never report a fabricated reply or absence.
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>>;
}

/// Reference TCP carrier: one connection and one length-framed exchange per attempt.
/// Signatures authenticate endpoints; this carrier does not encrypt metadata.
pub struct AnchorTcpTransport {
    address: SocketAddr,
    cancel: Cancellation,
}
impl AnchorTcpTransport {
    /// Configure an explicitly selected endpoint. Witness identity is pinned separately.
    pub fn new(address: SocketAddr) -> Self {
        Self::with_cancellation(address, Cancellation::default())
    }
    /// Share the owner's one-way cancellation signal. Connected reads/writes use
    /// at most 25-ms socket timeouts and retain the original absolute deadline.
    /// Pending connects also poll cancellation at the same interval. Aborted
    /// exchanges reveal no commit outcome: reopen and reconcile the exact command.
    pub fn with_cancellation(address: SocketAddr, cancel: Cancellation) -> Self {
        Self { address, cancel }
    }
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "anchor attempt deadline expired"))
}
pub(super) fn checked_remaining(deadline: Instant, cancel: &Cancellation) -> io::Result<Duration> {
    if cancel.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "witness dispatch cancelled; reconcile original command",
        ));
    }
    remaining(deadline)
}
fn send(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
    cancel: &Cancellation,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(
            checked_remaining(deadline, cancel)?.min(Duration::from_millis(25)),
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
    checked_remaining(deadline, cancel)?;
    Ok(())
}
fn receive(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
    cancel: &Cancellation,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream.set_read_timeout(Some(
            checked_remaining(deadline, cancel)?.min(Duration::from_millis(25)),
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
    checked_remaining(deadline, cancel)?;
    Ok(())
}
impl AnchorTransport for AnchorTcpTransport {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if request.len() != 3674 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut stream = crate::connect::tcp(self.address, deadline, &self.cancel)?;
        checked_remaining(deadline, &self.cancel)?;
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        send(
            &mut stream,
            &(request.len() as u32).to_be_bytes(),
            deadline,
            &self.cancel,
        )?;
        send(&mut stream, request, deadline, &self.cancel)?;
        let mut length = [0; 4];
        receive(&mut stream, &mut length, deadline, &self.cancel)?;
        if u32::from_be_bytes(length) != 3659 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut response = vec![0; 3659];
        receive(&mut stream, &mut response, deadline, &self.cancel)?;
        Ok(response)
    }
}

/// Missing or invalid witness evidence, never a successful unanchored fallback.
#[derive(Debug)]
pub enum AnchorClientError {
    /// I/O, deadline or malformed transport frame; the command may have committed.
    Transport(io::Error),
    /// The response or configured signing owner failed exact cryptographic admission.
    Verification(Error),
    /// The authenticated witness head/command conflicts with the local state.
    Conflict,
}
impl std::fmt::Display for AnchorClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Transport(_) => "witness outcome unavailable; reconcile exact command",
            Self::Verification(_) => "witness response verification failed",
            Self::Conflict => "witness state or writer fence differs",
        })
    }
}
impl std::error::Error for AnchorClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::Conflict => None,
        }
    }
}
impl From<Error> for AnchorClientError {
    fn from(error: Error) -> Self {
        Self::Verification(error)
    }
}

/// Owned pinned witness connection and device signer. The journal consumes this
/// owner; byte transports cannot manufacture authenticated advancement evidence.
pub struct AnchorClient {
    pin: AnchorPin,
    signer: DeviceSigningKey,
    transport: Box<dyn AnchorTransport>,
    timeout: Duration,
}
impl AnchorClient {
    /// Require a finite nonzero attempt budget of at most 60 seconds.
    pub fn new(
        pin: AnchorPin,
        signer: DeviceSigningKey,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<Self, AnchorClientError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(AnchorClientError::Transport(
                io::ErrorKind::InvalidInput.into(),
            ));
        }
        if signer.public_key()?.shares_component(pin.public_key()) {
            return Err(Error::Scope.into());
        }
        Ok(Self {
            pin,
            signer,
            transport,
            timeout,
        })
    }
    pub(crate) fn pin(&self) -> &AnchorPin {
        &self.pin
    }
    pub(crate) fn check_device(&self, device: &VerifiedDevice) -> Result<(), Error> {
        self.signer.check_device(device)
    }
    pub(crate) fn signer_public_key(&self) -> Result<PublicKey, Error> {
        self.signer.public_key()
    }
    pub(crate) fn exchange(
        &mut self,
        subject: AnchorSubject,
        operation: AnchorOperation,
    ) -> Result<AnchorReply, AnchorClientError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| AnchorClientError::Transport(io::ErrorKind::InvalidInput.into()))?;
        let deadline = self
            .transport
            .constrain_deadline(deadline)
            .map_err(AnchorClientError::Transport)?
            .min(deadline);
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        let request = AnchorRequest::new(&self.pin, subject, operation, &self.signer)?;
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        let wire = self
            .transport
            .exchange(request.as_bytes(), deadline)
            .map_err(AnchorClientError::Transport)?;
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        let reply = self.pin.verify_reply(&request, &wire)?;
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, sync::mpsc, thread};
    type HeldReply = (
        SocketAddr,
        mpsc::Receiver<()>,
        thread::JoinHandle<io::Result<()>>,
    );

    // Framing-only tests. The installed C trace separately uses authenticated
    // requests and an actual durable witness, including a partial signed reply.
    fn held_reply(prefix: usize) -> io::Result<HeldReply> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let (ready, receive) = mpsc::channel();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                remaining(deadline)?;
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut request = vec![0; 3678];
            stream.read_exact(&mut request)?;
            assert_eq!(request.get(..4), Some(3674u32.to_be_bytes().as_slice()));
            assert_eq!(request.get(4..), Some([0u8; 3674].as_slice()));
            let mut frame = 3659u32.to_be_bytes().to_vec();
            frame.extend_from_slice(&[9; 3659]);
            stream.write_all(frame.get(..prefix).ok_or(io::ErrorKind::InvalidInput)?)?;
            ready.send(()).map_err(io::Error::other)?;
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => Ok(()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    Ok(())
                }
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extra request after cancellation",
                )),
                Err(error) => Err(error),
            }
        });
        Ok((address, receive, worker))
    }

    #[test]
    fn cancelled_before_connect_never_dispatches() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let cancel = Cancellation::default();
        cancel.cancel();
        let mut transport = AnchorTcpTransport::with_cancellation(listener.local_addr()?, cancel);
        let error = transport
            .exchange(&[0; 3674], Instant::now() + Duration::from_secs(5))
            .expect_err("cancelled exchange");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(
            listener.accept().expect_err("no connection").kind(),
            io::ErrorKind::WouldBlock
        );
        Ok(())
    }

    #[test]
    fn cancellation_releases_empty_partial_header_and_partial_body() -> io::Result<()> {
        for prefix in [0, 2, 804] {
            let (address, ready, server) = held_reply(prefix)?;
            let cancel = Cancellation::default();
            let mut transport = AnchorTcpTransport::with_cancellation(address, cancel.clone());
            let worker = thread::spawn(move || {
                transport.exchange(&[0; 3674], Instant::now() + Duration::from_secs(5))
            });
            ready
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
            let start = Instant::now();
            cancel.cancel();
            let error = worker
                .join()
                .map_err(|_| io::Error::other("client panicked"))?
                .expect_err("partial cancelled reply");
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "held phase {prefix}"
            );
            server
                .join()
                .map_err(|_| io::Error::other("server panicked"))??;
        }
        Ok(())
    }

    #[test]
    fn polling_preserves_absolute_deadline_without_cancellation() -> io::Result<()> {
        let (address, _ready, server) = held_reply(804)?;
        let mut transport = AnchorTcpTransport::new(address);
        let start = Instant::now();
        let error = transport
            .exchange(&[0; 3674], start + Duration::from_millis(250))
            .expect_err("incomplete reply");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(250));
        assert!(start.elapsed() < Duration::from_secs(1));
        server
            .join()
            .map_err(|_| io::Error::other("server panicked"))??;
        Ok(())
    }
}
