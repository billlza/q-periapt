// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::Transport;
use crate::{tcp_io, Cancellation, MonotonicInstant as Instant};
use std::{io, net::SocketAddr, time::Duration};

/// Explicit opaque TCP carrier for QPCXCH01. Inner cryptography authenticates the
/// peer/session and encrypts application data; TCP does not hide public metadata.
/// This is not QPCNET01/TLS and is never selected as a TLS fallback.
pub struct TcpTransport {
    address: SocketAddr,
}
impl TcpTransport {
    /// Select one numeric endpoint, with no DNS, discovery or implicit retries.
    pub fn new(address: SocketAddr) -> io::Result<Self> {
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address.ip(),std::net::IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self { address })
    }
}
impl Transport for TcpTransport {
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: Instant,
        cancel: &Cancellation,
    ) -> io::Result<Vec<u8>> {
        if !(10..=crate::contract::MAX_CONNECTION_FRAME_BYTES).contains(&request.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        tcp_io::remaining(deadline, cancel)?;
        let phase = deadline.min(
            Instant::now() + Duration::from_secs(crate::contract::MAX_CONNECT_TIMEOUT_SECONDS),
        );
        let mut stream = crate::connect::tcp(self.address, phase, cancel)?;
        stream.set_nodelay(true)?;
        tcp_io::send(
            &mut stream,
            &(request.len() as u32).to_be_bytes(),
            deadline,
            cancel,
        )?;
        tcp_io::send(&mut stream, request, deadline, cancel)?;
        let mut header = [0; 4];
        tcp_io::receive(&mut stream, &mut header, deadline, cancel)?;
        let size = u32::from_be_bytes(header) as usize;
        if !(10..=crate::contract::MAX_CONNECTION_FRAME_BYTES).contains(&size) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut response = vec![0; size];
        tcp_io::receive(&mut stream, &mut response, deadline, cancel)?;
        Ok(response)
    }
}
