// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded Fetch transport shared by witness and session exchanges.
use crate::{session_exchange, Cancellation, MonotonicInstant};
use js_sys::{Function, Reflect, Uint8Array};
use std::{io, time::Duration};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(raw_module = "./bounded-fetch.js")]
extern "C" {
    #[wasm_bindgen(js_name = httpEndpoint, catch)]
    fn endpoint(value: &str, loopback: bool) -> Result<String, JsValue>;
    #[wasm_bindgen(js_name = HttpExchange)]
    type HttpExchange;
    #[wasm_bindgen(static_method_of = HttpExchange, js_name = start, catch)]
    fn start(
        endpoint: &str,
        request: &[u8],
        milliseconds: f64,
        cancelled: &Function,
        profile: u8,
    ) -> Result<HttpExchange, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn reply(this: &HttpExchange) -> Result<Uint8Array, JsValue>;
    #[wasm_bindgen(method)]
    fn cancel(this: &HttpExchange);
}
fn host(error: JsValue) -> io::Error {
    let code = Reflect::get(&error, &JsValue::from_str("code"))
        .ok()
        .and_then(|v| v.as_string());
    let kind = match code.as_deref() {
        Some("Timeout") => io::ErrorKind::TimedOut,
        Some("Cancelled") => io::ErrorKind::Interrupted,
        Some("InvalidEndpoint") => io::ErrorKind::InvalidInput,
        Some("InvalidResponse") => io::ErrorKind::InvalidData,
        Some("Unavailable") => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::Other,
    };
    let status = Reflect::get(&error, &JsValue::from_str("status"))
        .ok()
        .and_then(|v| v.as_f64())
        .filter(|v| v.fract() == 0.0 && (100.0..=599.0).contains(v))
        .map(|v| format!(" (HTTP {v})"))
        .unwrap_or_default();
    // URLs and browser diagnostics can contain credentials; retain only category/status.
    io::Error::new(
        kind,
        format!(
            "browser transport: {}{status}",
            code.as_deref().unwrap_or("HostFailure")
        ),
    )
}
struct Attempt {
    exchange: HttpExchange,
    _cancelled: Closure<dyn FnMut() -> bool>,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.exchange.cancel();
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Profile {
    Witness,
    Session,
}
impl Profile {
    fn code(self) -> u8 {
        match self {
            Self::Witness => 1,
            Self::Session => 2,
        }
    }
    fn accepts(self, length: usize, reply: bool) -> bool {
        match self {
            Self::Witness => length == if reply { 3659 } else { 3674 },
            Self::Session => (10..=crate::contract::MAX_CONNECTION_FRAME_BYTES).contains(&length),
        }
    }
}
pub(crate) struct HttpTransport {
    endpoint: String,
    cancel: Cancellation,
    profile: Profile,
}
impl HttpTransport {
    pub(crate) fn new(
        url: &str,
        loopback: bool,
        cancel: Cancellation,
        profile: Profile,
    ) -> io::Result<Self> {
        Ok(Self {
            endpoint: endpoint(url, loopback).map_err(host)?,
            cancel,
            profile,
        })
    }
    pub(crate) fn remaining(&self, deadline: MonotonicInstant) -> io::Result<Duration> {
        if self.cancel.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        deadline
            .checked_duration_since(MonotonicInstant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
    pub(crate) async fn exchange(
        &mut self,
        request: &[u8],
        deadline: MonotonicInstant,
    ) -> io::Result<Vec<u8>> {
        let budget = self.remaining(deadline)?;
        if !self.profile.accepts(request.len(), false) || budget.as_secs_f64() > 60.0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let cancellation = self.cancel.clone();
        let cancelled = Closure::wrap(
            Box::new(move || cancellation.is_cancelled()) as Box<dyn FnMut() -> bool>
        );
        let exchange = HttpExchange::start(
            &self.endpoint,
            request,
            budget.as_secs_f64() * 1000.0,
            cancelled
                .as_ref()
                .dyn_ref::<Function>()
                .ok_or(io::ErrorKind::InvalidData)?,
            self.profile.code(),
        )
        .map_err(host)?;
        let attempt = Attempt {
            exchange,
            _cancelled: cancelled,
        };
        let bytes = attempt.exchange.reply().await.map_err(host)?;
        self.remaining(deadline)?;
        if !self.profile.accepts(bytes.length() as usize, true) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(bytes.to_vec())
    }
}

/// Explicit browser peer endpoint. Independent protocol pins still authenticate the peer.
pub struct PeerEndpoint {
    endpoint: String,
    loopback: bool,
}
impl PeerEndpoint {
    /// Absolute HTTPS endpoint, without URL credentials or a fragment.
    pub fn new(url: &str) -> io::Result<Self> {
        Self::checked(url, false)
    }
    /// Explicit diagnostic HTTP carrier for numeric loopback only; no fallback.
    pub fn for_loopback(url: &str) -> io::Result<Self> {
        Self::checked(url, true)
    }
    fn checked(url: &str, loopback: bool) -> io::Result<Self> {
        Ok(Self {
            endpoint: endpoint(url, loopback).map_err(host)?,
            loopback,
        })
    }
    pub(super) fn carrier(&self, cancel: Cancellation) -> io::Result<HttpTransport> {
        HttpTransport::new(&self.endpoint, self.loopback, cancel, Profile::Session)
    }
}
#[async_trait::async_trait(?Send)]
impl session_exchange::Transport for HttpTransport {
    async fn exchange(
        &mut self,
        request: &[u8],
        deadline: MonotonicInstant,
        cancel: &Cancellation,
    ) -> io::Result<Vec<u8>> {
        if cancel.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let result = Self::exchange(self, request, deadline).await?;
        if cancel.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(result)
    }
}
