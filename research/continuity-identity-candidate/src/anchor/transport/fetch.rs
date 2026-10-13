// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{remaining, AnchorTransport};
use crate::{Cancellation, MonotonicInstant};
use js_sys::{Function, Reflect, Uint8Array};
use std::io;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(raw_module = "./witness-fetch.js")]
extern "C" {
    #[wasm_bindgen(js_name = witnessEndpoint, catch)]
    fn endpoint(value: &str, loopback: bool) -> Result<String, JsValue>;
    #[wasm_bindgen(js_name = WitnessExchange)]
    type WitnessExchange;
    #[wasm_bindgen(static_method_of = WitnessExchange, js_name = start, catch)]
    fn start(
        endpoint: &str,
        request: &[u8],
        milliseconds: f64,
        cancelled: &Function,
    ) -> Result<WitnessExchange, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn reply(this: &WitnessExchange) -> Result<Uint8Array, JsValue>;
    #[wasm_bindgen(method)]
    fn cancel(this: &WitnessExchange);
}

fn host(error: JsValue) -> io::Error {
    let code = Reflect::get(&error, &JsValue::from_str("code"))
        .ok()
        .and_then(|value| value.as_string());
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
        .and_then(|value| value.as_f64())
        .filter(|value| value.fract() == 0.0 && (100.0..=599.0).contains(value))
        .map(|value| format!(" (HTTP {value})"))
        .unwrap_or_default();
    // Endpoint URLs and browser diagnostics may contain application credentials.
    // Preserve the stable failure category; never include those values in logs.
    io::Error::new(
        kind,
        format!(
            "browser witness transport: {}{status}",
            code.as_deref().unwrap_or("HostFailure"),
        ),
    )
}

struct Attempt {
    exchange: WitnessExchange,
    _cancelled: Closure<dyn FnMut() -> bool>,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        // Detach the JS cancellation callback before its Rust closure is freed.
        // An aborted fetch may already have committed at the remote witness.
        self.exchange.cancel();
    }
}

/// Bounded browser Fetch carrier for the existing signed witness protocol.
/// HTTPS transport does not replace independent witness pinning or reply verification.
/// Ambient credentials and redirects are disabled. Each exchange has one request
/// and no implicit retry; cancellation or failure establishes no commit outcome.
pub struct AnchorFetchTransport {
    endpoint: String,
    cancel: Cancellation,
}
impl AnchorFetchTransport {
    /// Select an absolute HTTPS endpoint. URLs with userinfo or fragments are refused.
    pub fn new(url: &str) -> io::Result<Self> {
        Self::with_cancellation(url, Cancellation::default())
    }
    /// Share a one-way cancellation signal, polled by a 25 ms browser timer.
    /// Browser suspension can delay delivery; late replies never become success.
    pub fn with_cancellation(url: &str, cancel: Cancellation) -> io::Result<Self> {
        Ok(Self {
            endpoint: endpoint(url, false).map_err(host)?,
            cancel,
        })
    }
    /// Explicit diagnostic-only HTTP carrier for numeric 127.0.0.1 or ::1.
    /// This never accepts remote HTTP or falls back from the HTTPS constructor.
    pub fn for_loopback(url: &str, cancel: Cancellation) -> io::Result<Self> {
        Ok(Self {
            endpoint: endpoint(url, true).map_err(host)?,
            cancel,
        })
    }
    fn check_cancel(&self) -> io::Result<()> {
        if self.cancel.is_cancelled() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "witness dispatch cancelled; reconcile original command",
            ))
        } else {
            Ok(())
        }
    }
}
#[async_trait::async_trait(?Send)]
impl AnchorTransport for AnchorFetchTransport {
    fn constrain_deadline(&self, deadline: MonotonicInstant) -> io::Result<MonotonicInstant> {
        self.check_cancel()?;
        remaining(deadline)?;
        Ok(deadline)
    }
    async fn exchange(
        &mut self,
        request: &[u8],
        deadline: MonotonicInstant,
    ) -> io::Result<Vec<u8>> {
        self.check_cancel()?;
        if request.len() != 3674 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let budget = remaining(deadline)?;
        if budget.as_secs_f64() > 60.0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let cancellation = self.cancel.clone();
        let cancelled = Closure::wrap(
            Box::new(move || cancellation.is_cancelled()) as Box<dyn FnMut() -> bool>
        );
        let exchange = WitnessExchange::start(
            &self.endpoint,
            request,
            budget.as_secs_f64() * 1000.0,
            cancelled
                .as_ref()
                .dyn_ref::<Function>()
                .ok_or(io::ErrorKind::InvalidData)?,
        )
        .map_err(host)?;
        let attempt = Attempt {
            exchange,
            _cancelled: cancelled,
        };
        let bytes = attempt.exchange.reply().await.map_err(host)?;
        self.check_cancel()?;
        remaining(deadline)?;
        if bytes.length() != 3659 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(bytes.to_vec())
    }
}
