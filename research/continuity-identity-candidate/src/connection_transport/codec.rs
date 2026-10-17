// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
const MAGIC: &[u8; 8] = b"QPCNET01";
use crate::contract::MAX_CONNECTION_FRAME_BYTES as MAX_FRAME;
pub(super) const INITIAL: u8 = 1;
pub(super) const BOOTSTRAP: u8 = 2;
pub(super) const MESSAGE: u8 = 3;
pub(super) const REPLY: u8 = 129;
pub(super) const READY: u8 = 130;
pub(super) const ACK: u8 = 131;

pub(super) fn frame(kind: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.is_empty() || body.len() > MAX_FRAME - 9 {
        return Err(Error::Protocol);
    }
    let mut bytes = MAGIC.to_vec();
    bytes.push(kind);
    bytes.extend_from_slice(body);
    Ok(bytes)
}
pub(super) fn open(bytes: &[u8]) -> Result<(u8, &[u8]), Error> {
    if !(10..=MAX_FRAME).contains(&bytes.len()) || bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(Error::Protocol);
    }
    let (kind, body) = bytes
        .get(8..)
        .ok_or(Error::Protocol)?
        .split_first()
        .ok_or(Error::Protocol)?;
    Ok((*kind, body))
}
pub(super) fn payload(bytes: &[u8], expected: u8) -> Result<&[u8], Error> {
    let (kind, body) = open(bytes)?;
    if kind != expected {
        return Err(Error::Protocol);
    }
    Ok(body)
}
pub(super) fn initial(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err(Error::Protocol);
    }
    Ok(bytes)
}
pub(super) fn pair(first: &[u8], second: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(first.len()).map_err(|_| Error::Protocol)?;
    let mut out = length.to_be_bytes().to_vec();
    out.extend_from_slice(first);
    out.extend_from_slice(second);
    Ok(out)
}
pub(super) fn split(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let length = usize::from(u16::from_be_bytes(
        bytes
            .get(..2)
            .ok_or(Error::Protocol)?
            .try_into()
            .map_err(|_| Error::Protocol)?,
    ));
    let body = bytes.get(2..).ok_or(Error::Protocol)?;
    Ok((
        body.get(..length).ok_or(Error::Protocol)?,
        body.get(length..).ok_or(Error::Protocol)?,
    ))
}
