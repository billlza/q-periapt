// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

/// Untrusted byte carrier. Implementations must honor the absolute deadline;
/// journal authority comes only from verification of the complete signed reply.
pub trait AnchorTransport: Send {
    /// Exchange one bounded signed request. Transport failure says nothing about
    /// whether the witness committed; never report a fabricated reply or absence.
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>>;
}

/// Reference TCP carrier: one connection and one length-framed exchange per attempt.
/// Signatures authenticate endpoints; this carrier does not encrypt metadata.
pub struct AnchorTcpTransport {
    address: SocketAddr,
}
impl AnchorTcpTransport {
    /// Configure an explicitly selected endpoint. Witness identity is pinned separately.
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "anchor attempt deadline expired"))
}
fn send(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = bytes.get(written..).ok_or(io::ErrorKind::InvalidData)?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn receive(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes.get_mut(offset..).ok_or(io::ErrorKind::InvalidData)?) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    remaining(deadline)?;
    Ok(())
}
impl AnchorTransport for AnchorTcpTransport {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if request.len() != 3674 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut stream = TcpStream::connect_timeout(&self.address, remaining(deadline)?)?;
        stream.set_nodelay(true)?;
        send(&mut stream, &(request.len() as u32).to_be_bytes(), deadline)?;
        send(&mut stream, request, deadline)?;
        let mut length = [0; 4];
        receive(&mut stream, &mut length, deadline)?;
        if u32::from_be_bytes(length) != 3659 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut response = vec![0; 3659];
        receive(&mut stream, &mut response, deadline)?;
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
        if self.signer.public_key()? != device.key {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn exchange(
        &mut self,
        subject: AnchorSubject,
        operation: AnchorOperation,
    ) -> Result<AnchorReply, AnchorClientError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| AnchorClientError::Transport(io::ErrorKind::InvalidInput.into()))?;
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
