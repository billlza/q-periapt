// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit trusted witness configuration, reusing the native authenticated carrier.
use super::*;
use q_periapt_host_store::filesystem::OwnedPrivateDirectory;
use std::{
    io,
    time::{Duration, Instant},
};

/// Borrowed endpoint options; no caller pointer is retained by the owner.
#[repr(C)]
pub struct Options {
    pub address: *const u8,
    pub address_length: usize,
    pub timeout_ms: u32,
}
#[derive(Clone, Copy)]
pub(crate) struct Configuration {
    address: SocketAddr,
    timeout: Duration,
}
impl Configuration {
    pub(crate) unsafe fn read(options: *const Options) -> Result<Self> {
        if options.is_null() || !options.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: caller supplies an immutable readable Options and address region.
        let options = unsafe { &*options };
        let address = address(&unsafe { text(options.address, options.address_length, 128) }?)?;
        if address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address.ip(),std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || !(1..=10_000).contains(&options.timeout_ms)
        {
            return Err(Failure::argument());
        }
        Ok(Self {
            address,
            timeout: Duration::from_millis(u64::from(options.timeout_ms)),
        })
    }
    pub(crate) fn client(self, path: &Path, cancel: Cancellation) -> Result<p::AnchorClient> {
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let pin = p::AnchorPin::new(
            p::AnchorIdentity::from_trusted_state(owner::array(&directory, "witness-id")?)?,
            p::PublicKey::decode(&owner::read(&directory, "witness-public", 8192)?)?,
        );
        let key = p::JournalKey::open(&path.join("wrap.key"))?;
        let signer = p::DeviceSigningKey::open(
            &path.join("signer.key"),
            &key,
            p::SigningKeyId::from_trusted_state(owner::array(&directory, "signer-id")?)?,
        )?;
        p::AnchorClient::new(
            pin,
            signer,
            Box::new(Transport {
                inner: p::AnchorTcpTransport::new(self.address),
                cancel,
            }),
            self.timeout,
        )
        .map_err(|error| p::DurableError::from(error).into())
    }
}
struct Transport {
    inner: p::AnchorTcpTransport,
    cancel: Cancellation,
}
impl p::AnchorTransport for Transport {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "witness dispatch cancelled",
            ));
        }
        let reply = self.inner.exchange(request, deadline)?;
        if self.cancel.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "witness dispatch cancelled after exchange; reconcile original command",
            ));
        }
        Ok(reply)
    }
}
