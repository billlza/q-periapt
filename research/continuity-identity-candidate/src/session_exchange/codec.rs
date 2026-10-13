// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::Error;
const MAGIC: &[u8; 8] = b"QPCXCH01";
const MAX: usize = crate::contract::MAX_CONNECTION_FRAME_BYTES;
pub(super) const INITIAL: u8 = 1;
pub(super) const FINAL: u8 = 2;
pub(super) const MESSAGE: u8 = 3;
pub(super) const REPLY: u8 = 129;
pub(super) const READY: u8 = 130;
pub(super) const ACK: u8 = 131;
fn invalid() -> Error {
    crate::Error::Encoding.into()
}
pub(super) fn frame(kind: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.is_empty() || body.len() > MAX - 9 {
        return Err(invalid());
    }
    let mut wire = MAGIC.to_vec();
    wire.push(kind);
    wire.extend_from_slice(body);
    Ok(wire)
}
pub(super) fn open(wire: &[u8]) -> Result<(u8, &[u8]), Error> {
    if !(10..=MAX).contains(&wire.len()) || wire.get(..8) != Some(MAGIC.as_slice()) {
        return Err(invalid());
    }
    let (kind, body) = wire
        .get(8..)
        .and_then(|v| v.split_first())
        .ok_or_else(invalid)?;
    Ok((*kind, body))
}
pub(super) fn payload(wire: &[u8], expected: u8) -> Result<&[u8], Error> {
    let (kind, body) = open(wire)?;
    if kind != expected {
        return Err(invalid());
    }
    Ok(body)
}
pub(super) fn pair(first: &[u8], second: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(first.len()).map_err(|_| invalid())?;
    if first
        .len()
        .checked_add(second.len())
        .and_then(|n| n.checked_add(2))
        .is_none_or(|n| n > MAX - 9)
    {
        return Err(invalid());
    }
    let mut out = length.to_be_bytes().to_vec();
    out.extend_from_slice(first);
    out.extend_from_slice(second);
    Ok(out)
}
pub(super) fn split(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let size = usize::from(u16::from_be_bytes(
        bytes
            .get(..2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ));
    let body = bytes.get(2..).ok_or_else(invalid)?;
    Ok((
        body.get(..size).ok_or_else(invalid)?,
        body.get(size..).ok_or_else(invalid)?,
    ))
}
