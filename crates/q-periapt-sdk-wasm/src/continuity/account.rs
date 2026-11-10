// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete-account transactions reuse the same portable owner and journal.
use super::connections::{callable, timeout, Session};
use super::peers::Endpoint;
use super::*;
use engine::session_exchange as exchange;

mod types;
use types::Delivery;
pub(super) use types::{Members, Status};
pub(super) fn status(id: engine::FanoutId, inner: engine::FanoutStatus) -> Status {
    Status { id, inner }
}
pub(super) fn members(inner: engine::FanoutReconciliation) -> Members {
    Members { inner }
}
fn operation(value: &Uint8Array) -> Result<engine::FanoutId, JsValue> {
    engine::FanoutId::from_trusted_state(array(value)?).map_err(protocol)
}

// Member positions are zero based; capacity/time limits deliberately reject zero.
fn read_index(value: &JsValue) -> Result<usize, JsValue> {
    let invalid = || {
        engine::browser::input_failure(
            js_sys::Error::new("expected integer account member index").into(),
        )
    };
    let number = value.as_f64().ok_or_else(invalid)?;
    if !number.is_finite()
        || number.fract() != 0.0
        || !(0.0..engine::MAX_DEVICES as f64).contains(&number)
    {
        return Err(invalid());
    }
    Ok(number as usize)
}

/// Bounded original session descriptors; adding one never creates a session.
/// The journal verifies the complete signed roster and original local ownership.
#[wasm_bindgen(js_name = QPeriaptContinuityAccountTargets)]
pub struct Targets {
    sessions: Vec<exchange::Session>,
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountTargets)]
impl Targets {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }
    pub fn add(&mut self, session: &Session) -> Result<(), JsValue> {
        if self.sessions.len() >= engine::MAX_DEVICES {
            return Err(protocol(engine::Error::Capacity));
        }
        if self
            .sessions
            .iter()
            .any(|old| old.id() == session.inner.id())
        {
            return Err(protocol(engine::Error::Scope));
        }
        self.sessions.push(session.inner.clone());
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.sessions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}
impl Default for Targets {
    fn default() -> Self {
        Self::new()
    }
}

/// Original shared input retained across retries. close/free erases this SDK
/// plaintext copy; committed recovery state and host copies have their own lives.
#[wasm_bindgen(js_name = QPeriaptContinuityAccountMessage)]
pub struct Message {
    id: engine::FanoutId,
    account: [u8; 32],
    plaintext: Option<crate::WipingInput>,
    ad: Vec<u8>,
}
impl Message {
    fn submission<'a>(
        &'a self,
        targets: &'a Targets,
    ) -> Result<exchange::AccountSubmission<'a>, JsValue> {
        Ok(exchange::AccountSubmission {
            id: self.id,
            account: self.account,
            sessions: &targets.sessions,
            plaintext: &self
                .plaintext
                .as_ref()
                .ok_or_else(|| protocol(engine::Error::Closed))?
                .0,
            associated_data: &self.ad,
        })
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountMessage)]
impl Message {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: &Uint8Array,
        account: &Uint8Array,
        plaintext: &Uint8Array,
        associated_data: &Uint8Array,
    ) -> Result<Self, JsValue> {
        let id = operation(id)?;
        let account = array(account)?;
        if account.iter().all(|byte| *byte == 0) {
            return Err(protocol(engine::Error::Encoding));
        }
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
            account,
            plaintext: Some(plaintext),
            ad,
        })
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.id.as_bytes().to_vec()
    }
    pub fn close(&mut self) {
        self.plaintext = None;
    }
    pub fn is_closed(&self) -> bool {
        self.plaintext.is_none()
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Observation reserves nothing; retain this original ID after any error.
    pub async fn next_account_message_id(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .next_account_message_id()
            .await?
            .as_bytes()
            .to_vec())
    }
    pub async fn account_message_status(&self, id: &Uint8Array) -> Result<Status, JsValue> {
        let id = operation(id)?;
        Ok(Status {
            id,
            inner: self.inner.account_message_status(id).await?,
        })
    }
    /// Original complete metadata only; does not finish a reserved transaction.
    pub async fn reconcile_account_message(
        &self,
        id: &Uint8Array,
        targets: &Targets,
    ) -> Result<Members, JsValue> {
        Ok(Members {
            inner: self
                .inner
                .reconcile_account_message(operation(id)?, &targets.sessions)
                .await?,
        })
    }
    /// Every original member must be acknowledged or explicitly accounted.
    pub async fn retire_account_message(
        &self,
        id: &Uint8Array,
        targets: &Targets,
    ) -> Result<(), JsValue> {
        self.inner
            .retire_account_message(operation(id)?, &targets.sessions)
            .await
    }
    /// Commit all required members before dispatching one. Remote business
    /// effects remain separate, and an error never establishes non-commit.
    pub async fn deliver_account_member(
        &self,
        targets: &Targets,
        input: &Message,
        #[wasm_bindgen(unchecked_param_type = "number")] selected: JsValue,
        endpoint: &Endpoint,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        clock: &js_sys::Function,
    ) -> Result<Delivery, JsValue> {
        callable(clock)?;
        Ok(Delivery {
            inner: self
                .inner
                .deliver_account_member(
                    input.submission(targets)?,
                    read_index(&selected)?,
                    &endpoint.inner,
                    timeout(&timeout_ms)?,
                    clock,
                )
                .await?,
        })
    }
}
