// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{Error, Message, MAX_PAYLOAD_BYTES};

pub(super) const CLIENT_CONFIRM: u8 = 1;
pub(super) const SERVER_CONFIRM: u8 = 2;
pub(super) const REQUEST: u8 = 3;
pub(super) const RESPONSE: u8 = 4;
pub(super) const MAX_BODY: usize = 1 + 8 + MAX_PAYLOAD_BYTES;
pub(super) const MAX_FRAME: usize = 4 + MAX_BODY;

pub(super) struct WipingBytes(pub(super) Vec<u8>);
impl Drop for WipingBytes {
    fn drop(&mut self) {
        q_periapt_core::secure_wipe(&mut self.0);
    }
}

pub(super) struct Decoder {
    length: [u8; 4],
    length_used: usize,
    expected: Option<usize>,
    body: WipingBytes,
}
impl Decoder {
    pub(super) fn new() -> Self {
        Self {
            length: [0; 4],
            length_used: 0,
            expected: None,
            body: WipingBytes(Vec::new()),
        }
    }
    /// Consume at most one complete frame; arbitrary TLS/network fragmentation
    /// never changes framing. Length is validated before reserving body storage.
    pub(super) fn push(&mut self, input: &mut &[u8]) -> Result<Option<WipingBytes>, Error> {
        if self.expected.is_none() {
            let take = (4 - self.length_used).min(input.len());
            let (prefix, remaining) = input.split_at(take);
            self.length
                .get_mut(self.length_used..self.length_used + take)
                .ok_or(Error::Protocol)?
                .copy_from_slice(prefix);
            self.length_used += take;
            *input = remaining;
            if self.length_used != 4 {
                return Ok(None);
            }
            let length = u32::from_be_bytes(self.length) as usize;
            if !(1..=MAX_BODY).contains(&length) {
                return Err(Error::Protocol);
            }
            self.body
                .0
                .try_reserve_exact(length)
                .map_err(|_| Error::ResourceLimit)?;
            self.expected = Some(length);
        }
        let expected = self.expected.ok_or(Error::Protocol)?;
        let take = (expected - self.body.0.len()).min(input.len());
        let (prefix, remaining) = input.split_at(take);
        self.body.0.extend_from_slice(prefix);
        *input = remaining;
        if self.body.0.len() == expected {
            let body = std::mem::replace(&mut self.body, WipingBytes(Vec::new()));
            self.length_used = 0;
            self.expected = None;
            Ok(Some(body))
        } else {
            Ok(None)
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.length_used == 0 && self.body.0.is_empty()
    }
}

pub(super) struct Outgoing {
    pub(super) bytes: WipingBytes,
    pub(super) offset: usize,
}
impl Outgoing {
    fn new(kind: u8, fields: &[&[u8]]) -> Result<Self, Error> {
        let length = fields
            .iter()
            .try_fold(1usize, |n, field| n.checked_add(field.len()))
            .ok_or(Error::InvalidLength)?;
        if length > MAX_BODY {
            return Err(Error::InvalidLength);
        }
        let mut bytes = WipingBytes(Vec::new());
        bytes
            .0
            .try_reserve_exact(4 + length)
            .map_err(|_| Error::ResourceLimit)?;
        bytes.0.extend_from_slice(&(length as u32).to_be_bytes());
        bytes.0.push(kind);
        for field in fields {
            bytes.0.extend_from_slice(field);
        }
        Ok(Self { bytes, offset: 0 })
    }
    pub(super) fn confirmation(
        kind: u8,
        policy: &[u8; 68],
        context: &[u8; 96],
        binding: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::new(kind, &[policy, context, binding])
    }
    pub(super) fn message(kind: u8, id: u64, payload: &[u8]) -> Result<Self, Error> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidLength);
        }
        Self::new(kind, &[&id.to_be_bytes(), payload])
    }
}

pub(super) fn parse_message(body: WipingBytes) -> Result<Message, Error> {
    let id = u64::from_be_bytes(
        body.0
            .get(1..9)
            .ok_or(Error::Protocol)?
            .try_into()
            .map_err(|_| Error::Protocol)?,
    );
    let bytes = body.0.get(9..).ok_or(Error::Protocol)?;
    if id == 0 || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Protocol);
    }
    Ok(Message { id, body })
}
