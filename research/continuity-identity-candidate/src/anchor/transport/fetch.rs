// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::AnchorTransport;
use crate::{
    browser::http::{HttpTransport, Profile},
    Cancellation, MonotonicInstant,
};
use std::io;

/// Bounded Fetch carrier for the signed witness protocol. HTTPS does not replace
/// independent witness pinning. Ambient credentials/redirects and implicit retries
/// are refused. Failure or cancellation establishes no commit outcome.
pub struct AnchorFetchTransport {
    inner: HttpTransport,
}
impl AnchorFetchTransport {
    /// Select an absolute HTTPS endpoint without URL credentials or fragments.
    pub fn new(url: &str) -> io::Result<Self> {
        Self::with_cancellation(url, Cancellation::default())
    }
    /// Share the owner's one-way cancellation signal. Browser suspension can
    /// delay its delivery, but late replies never become success.
    pub fn with_cancellation(url: &str, cancel: Cancellation) -> io::Result<Self> {
        Ok(Self {
            inner: HttpTransport::new(url, false, cancel, Profile::Witness)?,
        })
    }
    /// Explicit numeric-loopback HTTP diagnostics, never a fallback from HTTPS.
    pub fn for_loopback(url: &str, cancel: Cancellation) -> io::Result<Self> {
        Ok(Self {
            inner: HttpTransport::new(url, true, cancel, Profile::Witness)?,
        })
    }
}
#[async_trait::async_trait(?Send)]
impl AnchorTransport for AnchorFetchTransport {
    fn constrain_deadline(&self, deadline: MonotonicInstant) -> io::Result<MonotonicInstant> {
        self.inner.remaining(deadline)?;
        Ok(deadline)
    }
    async fn exchange(
        &mut self,
        request: &[u8],
        deadline: MonotonicInstant,
    ) -> io::Result<Vec<u8>> {
        self.inner.exchange(request, deadline).await
    }
}
