//! Bounded canonical codecs shared by repository, witness, and IPC boundaries.

use std::io::{self, Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use q_periapt_backends::Sha3_256Xof;
use q_periapt_core::Xof256;
use rustix::io::Errno;

pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodecError {
    Allocation,
    InvalidLength,
    InvalidValue,
    Io,
    Oversized,
    TrailingBytes,
    Truncated,
}

pub(crate) struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Encoder {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn reserve(&mut self, additional: usize) -> Result<(), CodecError> {
        let required = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(CodecError::Oversized)?;
        if required > self.maximum {
            return Err(CodecError::Oversized);
        }
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| CodecError::Allocation)
    }

    pub(crate) fn byte(&mut self, value: u8) -> Result<(), CodecError> {
        self.reserve(1)?;
        self.bytes.push(value);
        Ok(())
    }

    pub(crate) fn u16(&mut self, value: u16) -> Result<(), CodecError> {
        self.fixed(&value.to_be_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<(), CodecError> {
        self.fixed(&value.to_be_bytes())
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) -> Result<(), CodecError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn lp16(&mut self, value: &[u8]) -> Result<(), CodecError> {
        let length = u16::try_from(value.len()).map_err(|_| CodecError::Oversized)?;
        self.u16(length)?;
        self.fixed(value)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(crate) fn fixed(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let value = self.remaining.get(..length).ok_or(CodecError::Truncated)?;
        self.remaining = self.remaining.get(length..).ok_or(CodecError::Truncated)?;
        Ok(value)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.fixed(N)?
            .try_into()
            .map_err(|_| CodecError::InvalidLength)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, CodecError> {
        self.fixed(1)?.first().copied().ok_or(CodecError::Truncated)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn lp16(&mut self, maximum: usize) -> Result<&'a [u8], CodecError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(CodecError::Oversized);
        }
        self.fixed(length)
    }

    pub(crate) fn finish(self) -> Result<(), CodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

pub(crate) fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> Result<[u8; 32], CodecError> {
    let total = core::iter::once(domain)
        .chain(fields.iter().copied())
        .try_fold(0usize, |size, field| {
            size.checked_add(8)?.checked_add(field.len())
        })
        .ok_or(CodecError::Oversized)?;
    let mut hash = Sha3_256Xof::new();
    hash.reserve(total);
    for field in core::iter::once(domain).chain(fields.iter().copied()) {
        let length = u64::try_from(field.len()).map_err(|_| CodecError::Oversized)?;
        hash.absorb_public(&length.to_be_bytes());
        hash.absorb_public(field);
    }
    Ok(hash.squeeze32())
}

pub(crate) fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), CodecError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(CodecError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| CodecError::Oversized)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(|_| CodecError::Io)
}

pub(crate) fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, CodecError> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).map_err(|_| CodecError::Io)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| CodecError::Oversized)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(CodecError::Oversized);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| CodecError::Allocation)?;
    payload.resize(length, 0);
    reader
        .read_exact(&mut payload)
        .map_err(|_| CodecError::Io)?;
    Ok(payload)
}

/// Stream whose per-syscall timeouts can be rebound so every read and write
/// derives its remaining budget from one absolute per-connection deadline.
pub(crate) trait DeadlineStream: Read + Write {
    fn set_read_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl DeadlineStream for TcpStream {
    fn set_read_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }

    fn set_write_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

#[cfg(unix)]
impl DeadlineStream for UnixStream {
    fn set_read_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }

    fn set_write_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

/// Whether an `accept()` failure is transient, so a long-lived listener should
/// keep serving rather than terminate.
///
/// These daemons are the only thing that ever stops them: a fatal return
/// propagates to `std::process::exit(1)`. They must not die permanently because
/// the process momentarily hit its descriptor limit, was interrupted by a
/// signal, or because a peer reset between the handshake and `accept()`. Only
/// states that make the listener itself unusable (EBADF, EINVAL, ENOTSOCK) are
/// fatal, and those fall through to `false`.
pub(crate) fn accept_error_is_transient(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::OutOfMemory
    ) {
        return true;
    }
    // EMFILE/ENFILE/ENOBUFS carry no stable `ErrorKind` on this toolchain.
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    code == Errno::MFILE.raw_os_error()
        || code == Errno::NFILE.raw_os_error()
        || code == Errno::NOBUFS.raw_os_error()
}

fn remaining_budget(deadline: Instant) -> Result<Duration, CodecError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(CodecError::Io)
}

pub(crate) fn write_frame_until<S: DeadlineStream>(
    stream: &mut S,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), CodecError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(CodecError::Oversized);
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| CodecError::Oversized)?
        .to_be_bytes();
    for bytes in [length.as_slice(), payload] {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let timeout = remaining_budget(deadline)?;
            stream
                .set_write_deadline_timeout(Some(timeout))
                .map_err(|_| CodecError::Io)?;
            let pending = bytes.get(offset..).ok_or(CodecError::Io)?;
            match stream.write(pending) {
                Ok(0) => return Err(CodecError::Io),
                Ok(written) => {
                    offset = offset.checked_add(written).ok_or(CodecError::Io)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(CodecError::Io),
            }
        }
    }
    let timeout = remaining_budget(deadline)?;
    stream
        .set_write_deadline_timeout(Some(timeout))
        .and_then(|()| stream.flush())
        .map_err(|_| CodecError::Io)
}

pub(crate) fn read_frame_until<S: DeadlineStream>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Vec<u8>, CodecError> {
    let mut length = [0u8; 4];
    read_exact_until(stream, &mut length, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| CodecError::Oversized)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(CodecError::Oversized);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| CodecError::Allocation)?;
    payload.resize(length, 0);
    read_exact_until(stream, &mut payload, deadline)?;
    Ok(payload)
}

fn read_exact_until<S: DeadlineStream>(
    stream: &mut S,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), CodecError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let timeout = remaining_budget(deadline)?;
        stream
            .set_read_deadline_timeout(Some(timeout))
            .map_err(|_| CodecError::Io)?;
        let pending = bytes.get_mut(offset..).ok_or(CodecError::Truncated)?;
        match stream.read(pending) {
            Ok(0) => return Err(CodecError::Io),
            Ok(read) => {
                offset = offset.checked_add(read).ok_or(CodecError::Io)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(CodecError::Io),
        }
    }
    remaining_budget(deadline).map(|_| ())
}

pub(crate) fn require_domain(
    decoder: &mut Decoder<'_>,
    expected: &[u8],
    version: u16,
) -> Result<(), CodecError> {
    if decoder.lp16(expected.len())? != expected || decoder.u16()? != version {
        Err(CodecError::InvalidValue)
    } else {
        Ok(())
    }
}

pub(crate) fn encode_domain(
    encoder: &mut Encoder,
    domain: &[u8],
    version: u16,
) -> Result<(), CodecError> {
    encoder.lp16(domain)?;
    encoder.u16(version)
}
