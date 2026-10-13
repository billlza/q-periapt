// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Browser operations keep the original enrolled owner around the portable driver.
use super::*;
use crate::{
    session_exchange as exchange, BootstrapBundle, BootstrapPeer, BootstrapRequirements,
    BootstrapRole, InitiationId, MessageId, MessageStatus,
};
use std::{io, sync::Arc};
mod receiver;
mod rekey;

struct Clock<'a> {
    callback: &'a js_sys::Function,
    failure: Option<JsValue>,
}
impl Clock<'_> {
    fn read(&mut self) -> io::Result<u64> {
        match self
            .callback
            .call0(&JsValue::UNDEFINED)
            .and_then(u64::try_from)
        {
            Ok(now) => Ok(now),
            Err(cause) => {
                self.failure = Some(cause);
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "trusted clock failed",
                ))
            }
        }
    }
    fn finish<T>(self, result: Result<T, exchange::Error>) -> Result<T, JsValue> {
        match self.failure {
            Some(cause) => Err(Storage::input_failure("InvalidClock", &cause)),
            None => result.map_err(exchange_failure),
        }
    }
}
fn exchange_failure(error: exchange::Error) -> JsValue {
    match error {
        exchange::Error::Durable(error) => failure(&error),
        exchange::Error::Clock(error) => {
            Storage::input_failure("InvalidClock", &failure(&DurableError::Io(error)))
        }
        exchange::Error::Transport(error) => Storage::input_failure(
            errors::io_code(error.kind(), "PeerTransport"),
            &failure(&DurableError::Io(error)),
        ),
        exchange::Error::Application(error) => {
            Storage::input_failure("Application", &failure(&DurableError::Io(error)))
        }
        exchange::Error::Cancelled => failure(&DurableError::Io(io::ErrorKind::Interrupted.into())),
        exchange::Error::Deadline => failure(&DurableError::Io(io::ErrorKind::TimedOut.into())),
        exchange::Error::ExchangeLimit => {
            Storage::input_failure("ExchangeLimit", &JsValue::UNDEFINED)
        }
    }
}
fn run(cancel: &Cancellation, timeout: Duration) -> Result<exchange::Run<'_>, JsValue> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(input_failure(
            js_sys::Error::new("invalid exchange timeout").into(),
        ));
    }
    exchange::Run::new(cancel, timeout).map_err(exchange_failure)
}
impl BrowserDevice {
    /// Verify independent bundle expectations and admit them at this original service.
    /// No operation, session or prekey is reserved by this preview.
    pub async fn admit_peer(
        &self,
        bundle: &BootstrapBundle,
        policy: Arc<VerifiedSessionPolicy>,
        required: BootstrapRequirements<'_>,
        role: BootstrapRole,
        now: u64,
    ) -> Result<BootstrapPeer, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let context = Arc::new(bundle.verify(policy, required, now)?);
            op.active()?.parts()?.0.admit_peer(context, role, now).await
        }
        .await;
        op.finish(result).await
    }
    /// Reopen authenticated original local session state; not a fresh peer-liveness receipt.
    pub async fn reopen_session(
        &self,
        bundle: &BootstrapBundle,
        policy: Arc<VerifiedSessionPolicy>,
        required: BootstrapRequirements<'_>,
        role: BootstrapRole,
        id: [u8; 32],
        now: u64,
    ) -> Result<exchange::Session, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let peer = op
                .active()?
                .parts()?
                .0
                .reopen_peer_bundle(bundle, policy, required, role, id, now)
                .await?;
            Ok(exchange::Session::from_reopened(&peer))
        }
        .await;
        op.finish(result).await
    }
    /// Establish/reconcile the exact original request through an authenticated peer proof.
    pub async fn establish_session(
        &self,
        peer: &BootstrapPeer,
        id: InitiationId,
        endpoint: &PeerEndpoint,
        timeout: Duration,
        clock: &js_sys::Function,
    ) -> Result<exchange::Session, JsValue> {
        let run = run(&self.cancellation, timeout)?;
        let mut carrier = endpoint
            .carrier(self.cancellation.clone())
            .map_err(|e| failure(&DurableError::Io(e)))?;
        let mut clock = Clock {
            callback: clock,
            failure: None,
        };
        let mut op = self.operation()?;
        let result = async {
            op.active()?
                .establish_session(peer, id, &mut carrier, &run, || clock.read())
                .await
        }
        .await;
        op.finish_failure(clock.finish(result)).await
    }
    /// Observe the original next message identity; it grants no sending authority.
    pub async fn next_session_message_id(
        &self,
        session: &exchange::Session,
        now: u64,
    ) -> Result<MessageId, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.next_session_message_id(session, now).await }.await;
        op.finish_failure(result.map_err(exchange_failure)).await
    }
    /// Reconcile the original outgoing ID without releasing another message.
    pub async fn session_message_status(
        &self,
        session: &exchange::Session,
        id: MessageId,
    ) -> Result<MessageStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.session_message_status(session, id).await }.await;
        op.finish_failure(result.map_err(exchange_failure)).await
    }
    /// Deliver an exact original operation; authenticated PrefixPending is not consumption.
    pub async fn deliver_session_message(
        &self,
        session: &exchange::Session,
        input: exchange::Submission<'_>,
        endpoint: &PeerEndpoint,
        timeout: Duration,
        clock: &js_sys::Function,
    ) -> Result<exchange::Consumption, JsValue> {
        let run = run(&self.cancellation, timeout)?;
        let mut carrier = endpoint
            .carrier(self.cancellation.clone())
            .map_err(|e| failure(&DurableError::Io(e)))?;
        let mut clock = Clock {
            callback: clock,
            failure: None,
        };
        let mut op = self.operation()?;
        let result = async {
            op.active()?
                .deliver_session_message(session, input, &mut carrier, &run, || clock.read())
                .await
        }
        .await;
        op.finish_failure(clock.finish(result)).await
    }
}
