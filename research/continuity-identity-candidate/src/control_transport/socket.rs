// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Existing QPCCTL01 grammar over the shared bounded TLS I/O owner.
use super::*;
use crate::native_transport::{Channel as NativeChannel, Request};
use q_periapt_rustls::connection::Connection;
use std::time::Instant;
pub(super) struct Channel(NativeChannel);
impl Channel {
    pub(super) fn new(stream: TcpStream, engine: Connection) -> Result<Self, Error> {
        Ok(Self(NativeChannel::new(stream, engine)?))
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
        let mut request = MAGIC.to_vec();
        request.extend_from_slice(wire);
        let bytes = self
            .0
            .exchange(&request, context, cancel, deadline, clock)?;
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
        let request = self.0.request(context, cancel, deadline, clock)?;
        if request.bytes().get(..MAGIC.len()) != Some(MAGIC.as_slice())
            || !(MAGIC.len() + 1..=MAGIC.len() + MAX_CONTROL).contains(&request.bytes().len())
        {
            return Err(Error::Protocol);
        }
        Ok(Request::from_carrier(
            request.id(),
            request
                .bytes()
                .get(MAGIC.len()..)
                .ok_or(Error::Protocol)?
                .to_vec(),
        ))
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
        self.0
            .respond(id, &response, context, cancel, deadline, clock)
    }
    pub(super) fn finish(
        &mut self,
        context: &BootstrapContext,
        cancel: &Cancellation,
        deadline: Instant,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<(), Error> {
        self.0.finish(context, cancel, deadline, clock)
    }
}
