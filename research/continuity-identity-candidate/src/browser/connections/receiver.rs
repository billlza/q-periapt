// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{CommittedPlaintext, MonotonicInstant};
use js_sys::Function;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(raw_module = "./application.js")]
extern "C" {
    #[wasm_bindgen(js_name = ApplicationExchange)]
    type ApplicationExchange;
    #[wasm_bindgen(static_method_of = ApplicationExchange, js_name = start, catch)]
    fn start(
        callback: &Function,
        session: &[u8],
        message: &[u8],
        plaintext: &[u8],
        milliseconds: f64,
        cancelled: &Function,
    ) -> Result<ApplicationExchange, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn reply(this: &ApplicationExchange) -> Result<(), JsValue>;
    #[wasm_bindgen(method)]
    fn cancel(this: &ApplicationExchange);
    #[wasm_bindgen(method)]
    fn code(this: &ApplicationExchange) -> u8;
}
struct Attempt {
    exchange: ApplicationExchange,
    _cancelled: Closure<dyn FnMut() -> bool>,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.exchange.cancel();
    }
}
struct Consumer<'a> {
    callback: &'a Function,
    cancel: Cancellation,
    deadline: MonotonicInstant,
    failure: Option<(u8, JsValue)>,
}
#[async_trait::async_trait(?Send)]
impl exchange::Consumer for Consumer<'_> {
    async fn commit(&mut self, session: [u8; 32], delivery: &CommittedPlaintext) -> io::Result<()> {
        if self.cancel.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let remaining = self
            .deadline
            .checked_duration_since(MonotonicInstant::now())
            .filter(|v| !v.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        let signal = self.cancel.clone();
        let cancelled =
            Closure::wrap(Box::new(move || signal.is_cancelled()) as Box<dyn FnMut() -> bool>);
        let result = ApplicationExchange::start(
            self.callback,
            &session,
            delivery.message_id().as_bytes(),
            delivery.as_bytes(),
            remaining.as_secs_f64() * 1000.0,
            cancelled
                .as_ref()
                .dyn_ref::<Function>()
                .ok_or(io::ErrorKind::InvalidData)?,
        );
        let exchange = match result {
            Ok(value) => value,
            Err(cause) => {
                self.failure = Some((1, cause));
                return Err(io::Error::other("application invocation failed"));
            }
        };
        let attempt = Attempt {
            exchange,
            _cancelled: cancelled,
        };
        if let Err(cause) = attempt.exchange.reply().await {
            self.failure = Some((attempt.exchange.code(), cause));
            return Err(io::Error::other("application consumption unconfirmed"));
        }
        Ok(())
    }
}
fn result<T>(
    consumer: Consumer<'_>,
    clock: Clock<'_>,
    value: Result<T, exchange::Error>,
) -> Result<T, JsValue> {
    match consumer.failure {
        Some((code, cause)) => Err(Storage::input_failure(
            match code {
                2 => "Cancelled",
                3 => "Deadline",
                _ => "Application",
            },
            &cause,
        )),
        None => clock.finish(value),
    }
}
impl BrowserDevice {
    /// Serve an original peer's bootstrap/data frame. The host callback owns
    /// its plaintext copy and must durably deduplicate before resolving void.
    /// Timeout/cancellation cannot undo or stop an external pending callback.
    pub async fn serve_session_exchange(
        &self,
        peer: &BootstrapPeer,
        request: &[u8],
        callback: &Function,
        timeout: Duration,
        clock: &Function,
    ) -> Result<Vec<u8>, JsValue> {
        let run = run(&self.cancellation, timeout)?;
        let mut consumer = Consumer {
            callback,
            cancel: self.cancellation.clone(),
            deadline: run.deadline(),
            failure: None,
        };
        let mut clock = Clock {
            callback: clock,
            failure: None,
        };
        let mut op = self.operation()?;
        let value = async {
            op.active()?
                .serve_session_exchange(peer, request, &mut consumer, &run, || clock.read())
                .await
        }
        .await;
        op.finish_failure(result(consumer, clock, value)).await
    }
    /// Serve data for an independently reopened exact session. An authenticated
    /// consumed duplicate does not invoke the host consumer again.
    pub async fn serve_session_message(
        &self,
        session: &exchange::Session,
        request: &[u8],
        callback: &Function,
        timeout: Duration,
        clock: &Function,
    ) -> Result<Vec<u8>, JsValue> {
        let run = run(&self.cancellation, timeout)?;
        let mut consumer = Consumer {
            callback,
            cancel: self.cancellation.clone(),
            deadline: run.deadline(),
            failure: None,
        };
        let mut clock = Clock {
            callback: clock,
            failure: None,
        };
        let mut op = self.operation()?;
        let value = async {
            op.active()?
                .serve_session_message(session, request, &mut consumer, &run, || clock.read())
                .await
        }
        .await;
        op.finish_failure(result(consumer, clock, value)).await
    }
}
