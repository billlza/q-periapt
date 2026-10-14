// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[wasm_bindgen(js_name = QPeriaptContinuityAccountPhase)]
pub enum Phase {
    Absent = 0,
    Reserved = 1,
    Committed = 2,
    Abandoning = 3,
    Abandoned = 4,
    Retired = 5,
}
/// Metadata only. Committed describes the local aggregate, not remote effects.
#[wasm_bindgen(js_name = QPeriaptContinuityAccountStatus)]
pub struct Status {
    pub(super) id: engine::FanoutId,
    pub(super) inner: engine::FanoutStatus,
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountStatus)]
impl Status {
    pub fn operation_id(&self) -> Vec<u8> {
        self.id.as_bytes().to_vec()
    }
    pub fn phase(&self) -> Phase {
        match self.inner {
            engine::FanoutStatus::Absent => Phase::Absent,
            engine::FanoutStatus::Reserved => Phase::Reserved,
            engine::FanoutStatus::Committed => Phase::Committed,
            engine::FanoutStatus::Abandoning(_) => Phase::Abandoning,
            engine::FanoutStatus::Abandoned(_) => Phase::Abandoned,
            engine::FanoutStatus::Retired => Phase::Retired,
        }
    }
    pub fn abandonment_id(&self) -> Option<Vec<u8>> {
        match self.inner {
            engine::FanoutStatus::Abandoning(id) | engine::FanoutStatus::Abandoned(id) => {
                Some(id.as_bytes().to_vec())
            }
            _ => None,
        }
    }
}
#[wasm_bindgen(js_name = QPeriaptContinuityAccountOutcome)]
pub enum Outcome {
    Confirmed = 1,
    PrefixPending = 2,
    ResolutionPending = 3,
    DeliveryUnknown = 4,
    HistoryRetired = 5,
    ReservationAbandoned = 6,
}
#[wasm_bindgen(js_name = QPeriaptContinuityAccountDelivery)]
pub struct Delivery {
    pub(super) inner: exchange::AccountDelivered,
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountDelivery)]
impl Delivery {
    pub fn device(&self) -> Vec<u8> {
        self.inner.device.to_vec()
    }
    pub fn session(&self) -> Vec<u8> {
        self.inner.session.to_vec()
    }
    pub fn message(&self) -> Vec<u8> {
        self.inner.message.as_bytes().to_vec()
    }
    pub fn exchanges(&self) -> u16 {
        self.inner.exchanges
    }
    pub fn outcome(&self) -> Outcome {
        use exchange::AccountDeliveryOutcome as E;
        match self.inner.outcome {
            E::Consumption(exchange::Consumption::Confirmed) => Outcome::Confirmed,
            E::Consumption(exchange::Consumption::PrefixPending) => Outcome::PrefixPending,
            E::ResolutionPending => Outcome::ResolutionPending,
            E::DeliveryUnknown => Outcome::DeliveryUnknown,
            E::HistoryRetired => Outcome::HistoryRetired,
            E::ReservationAbandoned => Outcome::ReservationAbandoned,
        }
    }
}
#[wasm_bindgen(js_name = QPeriaptContinuityAccountMemberPhase)]
pub enum MemberPhase {
    Committed = 1,
    Acknowledged = 2,
    ResolutionPending = 3,
    DeliveryUnknown = 4,
    HistoryRetired = 5,
    ReservationAbandoned = 6,
}
#[wasm_bindgen(js_name = QPeriaptContinuityAccountMember)]
pub struct Member {
    inner: engine::FanoutMemberStatus,
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountMember)]
impl Member {
    pub fn device(&self) -> Vec<u8> {
        self.inner.device.to_vec()
    }
    pub fn session(&self) -> Vec<u8> {
        self.inner.session.to_vec()
    }
    pub fn message(&self) -> Vec<u8> {
        self.inner.message.as_bytes().to_vec()
    }
    pub fn phase(&self) -> MemberPhase {
        use engine::FanoutMemberState as E;
        match self.inner.state {
            E::Committed => MemberPhase::Committed,
            E::Acknowledged => MemberPhase::Acknowledged,
            E::ResolutionPending => MemberPhase::ResolutionPending,
            E::DeliveryUnknown => MemberPhase::DeliveryUnknown,
            E::HistoryRetired => MemberPhase::HistoryRetired,
            E::ReservationAbandoned => MemberPhase::ReservationAbandoned,
        }
    }
}
/// Complete original recipient metadata in canonical journal order. No wire escapes.
#[wasm_bindgen(js_name = QPeriaptContinuityAccountMembers)]
pub struct Members {
    pub(super) inner: engine::FanoutReconciliation,
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountMembers)]
impl Members {
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.batch.as_bytes().to_vec()
    }
    pub fn len(&self) -> usize {
        self.inner.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.members.is_empty()
    }
    pub fn member(
        &self,
        #[wasm_bindgen(unchecked_param_type = "number")] index: JsValue,
    ) -> Result<Member, JsValue> {
        let index = read_index(&index)?;
        let inner = *self
            .inner
            .members
            .get(index)
            .ok_or_else(|| protocol(engine::Error::Encoding))?;
        Ok(Member { inner })
    }
}
