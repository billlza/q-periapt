// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::peers::{self, Endpoint, Peer, Role, Trust};
use super::*;
use engine::session_exchange as exchange;
use std::sync::Arc;

fn message_id(value: &Uint8Array) -> Result<engine::MessageId, JsValue> {
    engine::MessageId::from_trusted_state(array(value)?).map_err(protocol)
}
pub(super) fn timeout(value: &JsValue) -> Result<Duration, JsValue> {
    Ok(Duration::from_millis(read_limit(value, 60000)? as u64))
}
pub(super) fn callable(value: &js_sys::Function) -> Result<(), JsValue> {
    let value: &JsValue = value.as_ref();
    if !value.is_function() {
        return Err(engine::browser::input_failure(
            js_sys::Error::new("expected callback function").into(),
        ));
    }
    Ok(())
}
/// Original local session descriptor. Reopening is not a new peer-liveness receipt.
#[wasm_bindgen(js_name = QPeriaptContinuitySession)]
pub struct Session {
    pub(super) inner: exchange::Session,
}
#[wasm_bindgen(js_class = QPeriaptContinuitySession)]
impl Session {
    pub fn id(&self) -> Vec<u8> {
        self.inner.id().to_vec()
    }
    pub fn role(&self) -> Role {
        peers::public_role(self.inner.role())
    }
}
/// Retained original application input. close/free erases this SDK copy of plaintext.
/// Host copies and committed recovery state have their own lifetimes.
#[wasm_bindgen(js_name = QPeriaptContinuityMessage)]
pub struct Message {
    id: engine::MessageId,
    plaintext: Option<crate::WipingInput>,
    ad: Vec<u8>,
}
impl Message {
    fn submission(&self) -> Result<exchange::Submission<'_>, JsValue> {
        Ok(exchange::Submission {
            message: self.id,
            plaintext: &self
                .plaintext
                .as_ref()
                .ok_or_else(|| protocol(engine::Error::Closed))?
                .0,
            associated_data: &self.ad,
        })
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityMessage)]
impl Message {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: &Uint8Array,
        plaintext: &Uint8Array,
        associated_data: &Uint8Array,
    ) -> Result<Message, JsValue> {
        let id = message_id(id)?;
        let plaintext = crate::WipingInput(read_input(
            plaintext,
            0,
            engine::contract::MAX_PLAINTEXT_BYTES,
        )?);
        let ad = read_input(
            associated_data,
            0,
            engine::contract::MAX_ASSOCIATED_DATA_BYTES,
        )?;
        Ok(Self {
            id,
            plaintext: Some(plaintext),
            ad,
        })
    }
    pub fn close(&mut self) {
        self.plaintext = None;
    }
    pub fn is_closed(&self) -> bool {
        self.plaintext.is_none()
    }
}
#[wasm_bindgen(js_name = QPeriaptContinuityConsumption)]
pub enum Consumption {
    Confirmed = 1,
    PrefixPending = 2,
}
#[wasm_bindgen(js_name = QPeriaptContinuityMessageStatus)]
pub enum MessageStatus {
    Absent = 0,
    Reserved = 1,
    Committed = 2,
    Acknowledged = 3,
    ResolutionPending = 4,
    DeliveryUnknown = 5,
    ReservationAbandoned = 6,
}
impl From<engine::MessageStatus> for MessageStatus {
    fn from(value: engine::MessageStatus) -> Self {
        match value {
            engine::MessageStatus::Absent => Self::Absent,
            engine::MessageStatus::Reserved => Self::Reserved,
            engine::MessageStatus::Committed => Self::Committed,
            engine::MessageStatus::Acknowledged => Self::Acknowledged,
            engine::MessageStatus::ResolutionPending => Self::ResolutionPending,
            engine::MessageStatus::DeliveryUnknown => Self::DeliveryUnknown,
            engine::MessageStatus::ReservationAbandoned => Self::ReservationAbandoned,
        }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Retain requestId across failures. Success requires the original peer's session MAC.
    pub async fn establish_session(
        &self,
        peer: &Peer,
        request_id: &Uint8Array,
        endpoint: &Endpoint,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        clock: &js_sys::Function,
    ) -> Result<Session, JsValue> {
        callable(clock)?;
        let id = engine::InitiationId::from_trusted_state(array(request_id)?).map_err(protocol)?;
        Ok(Session {
            inner: self
                .inner
                .establish_session(
                    &peer.inner,
                    id,
                    &endpoint.inner,
                    timeout(&timeout_ms)?,
                    clock,
                )
                .await?,
        })
    }
    /// Authenticate the original local session/archive. Retry a failed establishment
    /// with its original request ID; this readback is not remote confirmation.
    pub async fn reopen_session(
        &self,
        wire: &Uint8Array,
        policy: &SessionPolicy,
        trust: &Trust,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptContinuityRole")] local_role: JsValue,
        id: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Session, JsValue> {
        Ok(Session {
            inner: self
                .inner
                .reopen_session(
                    &peers::bundle(wire)?,
                    Arc::clone(&policy.inner),
                    trust.required()?,
                    peers::role(&local_role)?,
                    array(id)?,
                    read_time(now)?,
                )
                .await?,
        })
    }
    pub async fn next_session_message_id(
        &self,
        session: &Session,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .next_session_message_id(&session.inner, read_time(now)?)
            .await?
            .as_bytes()
            .to_vec())
    }
    pub async fn session_message_status(
        &self,
        session: &Session,
        id: &Uint8Array,
    ) -> Result<MessageStatus, JsValue> {
        Ok(self
            .inner
            .session_message_status(&session.inner, message_id(id)?)
            .await?
            .into())
    }
    /// PrefixPending is authenticated incomplete consumption, never successful delivery.
    pub async fn deliver_session_message(
        &self,
        session: &Session,
        input: &Message,
        endpoint: &Endpoint,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        clock: &js_sys::Function,
    ) -> Result<Consumption, JsValue> {
        callable(clock)?;
        Ok(
            match self
                .inner
                .deliver_session_message(
                    &session.inner,
                    input.submission()?,
                    &endpoint.inner,
                    timeout(&timeout_ms)?,
                    clock,
                )
                .await?
            {
                exchange::Consumption::Confirmed => Consumption::Confirmed,
                exchange::Consumption::PrefixPending => Consumption::PrefixPending,
            },
        )
    }
    /// Process one peer frame. Resolve the consumer only after its effect and
    /// deduplication record are durable together. Host plaintext copies are separate.
    pub async fn serve_session_exchange(
        &self,
        peer: &Peer,
        wire: &Uint8Array,
        consumer: &js_sys::Function,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        clock: &js_sys::Function,
    ) -> Result<Vec<u8>, JsValue> {
        callable(consumer)?;
        callable(clock)?;
        let wire = read_input(wire, 10, engine::contract::MAX_CONNECTION_FRAME_BYTES)?;
        self.inner
            .serve_session_exchange(&peer.inner, &wire, consumer, timeout(&timeout_ms)?, clock)
            .await
    }
    /// Process only data for this exact reopened session. Cancellation may leave
    /// a host callback running; it never acknowledges an unconfirmed effect.
    pub async fn serve_session_message(
        &self,
        session: &Session,
        wire: &Uint8Array,
        consumer: &js_sys::Function,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        clock: &js_sys::Function,
    ) -> Result<Vec<u8>, JsValue> {
        callable(consumer)?;
        callable(clock)?;
        let wire = read_input(wire, 10, engine::contract::MAX_CONNECTION_FRAME_BYTES)?;
        self.inner
            .serve_session_message(
                &session.inner,
                &wire,
                consumer,
                timeout(&timeout_ms)?,
                clock,
            )
            .await
    }
}
