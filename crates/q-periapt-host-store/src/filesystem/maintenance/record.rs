use super::PublicationMaintenanceError as Error;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};

pub(super) const PREFIX: &str = ".private-attempt-v2-";
pub(super) const RECORD_BYTES: usize = 154;
pub(super) const LEASE_BYTES: usize = 24;
pub(super) const INTENT_BYTES: usize = 88;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    File,
    Directory,
}
impl Kind {
    fn byte(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Directory => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Record {
    pub kind: Kind,
    pub nonce: [u8; 16],
    pub parent: [u8; 16],
    pub control: [u8; 16],
    pub lease: [u8; 16],
    pub payload: [u8; 16],
    pub destination: [u8; 32],
}
fn platform() -> u8 {
    if cfg!(windows) {
        2
    } else {
        1
    }
}
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(Error::Invalid)?)
        .ok_or(Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)
}
// The checksum detects damaged bookkeeping; it is not authentication or cleanup
// authority. Original private scope and the continuous lease remain necessary.
fn check_frame(bytes: &[u8], length: usize) -> Result<(), Error> {
    if bytes.len() != length {
        return Err(Error::Invalid);
    }
    let end = length.checked_sub(32).ok_or(Error::Invalid)?;
    let digest: [u8; 32] = Sha256::digest(bytes.get(..end).ok_or(Error::Invalid)?).into();
    if bytes.get(end..) != Some(digest.as_slice()) {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn seal_frame(bytes: &mut Vec<u8>) {
    let digest: [u8; 32] = Sha256::digest(&*bytes).into();
    bytes.extend_from_slice(&digest);
}
impl Record {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORD_BYTES);
        out.extend_from_slice(b"QPSTG002");
        out.push(platform());
        out.push(self.kind.byte());
        for field in [
            &self.nonce,
            &self.parent,
            &self.control,
            &self.lease,
            &self.payload,
        ] {
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.destination);
        seal_frame(&mut out);
        out
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        check_frame(bytes, RECORD_BYTES)?;
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(b"QPSTG002")
            || bytes.get(8) != Some(&platform())
        {
            return Err(Error::Invalid);
        }
        let kind = match bytes.get(9) {
            Some(1) => Kind::File,
            Some(2) => Kind::Directory,
            _ => return Err(Error::Invalid),
        };
        Ok(Self {
            kind,
            nonce: fixed(bytes, 10)?,
            parent: fixed(bytes, 26)?,
            control: fixed(bytes, 42)?,
            lease: fixed(bytes, 58)?,
            payload: fixed(bytes, 74)?,
            destination: fixed(bytes, 90)?,
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    pub(super) fn lease_bytes(&self) -> Vec<u8> {
        lease_bytes(self.nonce)
    }
}
pub(super) fn lease_bytes(nonce: [u8; 16]) -> Vec<u8> {
    let mut bytes = b"QPSTGL02".to_vec();
    bytes.extend_from_slice(&nonce);
    bytes
}
pub(super) fn name(nonce: [u8; 16]) -> OsString {
    let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    format!("{PREFIX}{suffix}").into()
}
pub(super) fn nonce(name: &OsStr) -> Result<[u8; 16], Error> {
    let suffix = name
        .to_str()
        .and_then(|s| s.strip_prefix(PREFIX))
        .ok_or(Error::Invalid)?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Invalid);
    }
    let mut result = [0; 16];
    for (out, chunk) in result.iter_mut().zip(suffix.as_bytes().as_chunks::<2>().0) {
        *out = u8::from_str_radix(std::str::from_utf8(chunk).map_err(|_| Error::Invalid)?, 16)
            .map_err(|_| Error::Invalid)?;
    }
    Ok(result)
}
pub(super) fn destination(name: &OsStr) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"Q-PERIAPT-PRIVATE-PUBLICATION-DESTINATION/v2\0");
    hash.update([platform()]);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hash.update(name.as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for word in name.encode_wide() {
            hash.update(word.to_le_bytes());
        }
    }
    hash.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Intent {
    pub record: [u8; 32],
    pub entries: u64,
    pub bytes: u64,
}
impl Intent {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut out = b"QPSTGC02".to_vec();
        out.extend_from_slice(&self.record);
        out.extend_from_slice(&self.entries.to_be_bytes());
        out.extend_from_slice(&self.bytes.to_be_bytes());
        seal_frame(&mut out);
        out
    }
    pub(super) fn decode(bytes: &[u8], record: &Record) -> Result<Self, Error> {
        check_frame(bytes, INTENT_BYTES)?;
        if bytes.len() != INTENT_BYTES || bytes.get(..8) != Some(b"QPSTGC02") {
            return Err(Error::Invalid);
        }
        let value = Self {
            record: fixed(bytes, 8)?,
            entries: u64::from_be_bytes(fixed(bytes, 40)?),
            bytes: u64::from_be_bytes(fixed(bytes, 48)?),
        };
        if value.record != record.digest()
            || value.entries == 0
            || value.entries > 4096
            || (record.kind == Kind::File && value.entries != 1)
            || value.bytes > 4 * 1024 * 1024 * 1024
        {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
    pub(super) fn receipt(self) -> Vec<u8> {
        let mut out = b"QPSTGD02".to_vec();
        out.extend_from_slice(&Sha256::digest(self.encode()));
        out
    }
}
