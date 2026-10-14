// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::continuity::status::Checkpoint;

/// Independent account approval, verified at current time; not a durable owner.
#[wasm_bindgen(js_name = QPeriaptContinuityCredentialGrant)]
pub struct Grant {
    pub(super) inner: engine::VerifiedCredentialRenewal,
}
#[wasm_bindgen(js_class = QPeriaptContinuityCredentialGrant)]
impl Grant {
    #[wasm_bindgen(constructor)]
    pub fn new(
        bytes: &Uint8Array,
        trust: &AccountTrust,
        original: &HistoricalPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Grant, JsValue> {
        Ok(Self {
            inner: engine::VerifiedCredentialRenewal::verify(
                &read_input(bytes, 1, engine::MAX_CREDENTIAL_RENEWAL_BYTES)?,
                &trust.inner,
                original.inner.checkpoint().digest(),
                read_time(now)?,
            )
            .map_err(protocol)?,
        })
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.operation().as_bytes().to_vec()
    }
    pub fn statement(&self) -> Vec<u8> {
        self.inner.statement_digest().to_vec()
    }
    pub fn target(&self) -> Checkpoint {
        Checkpoint {
            inner: self.inner.successor_device().roster().checkpoint(),
        }
    }
}
/// Original sealed-target expectations. Parsing is not independent approval.
#[wasm_bindgen(js_name = QPeriaptContinuityCredentialProposal)]
pub struct Proposal {
    pub(super) inner: engine::AnchorCredentialRenewalProposal,
}
#[wasm_bindgen(js_class = QPeriaptContinuityCredentialProposal)]
impl Proposal {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &Uint8Array) -> Result<Proposal, JsValue> {
        Ok(Self {
            inner: engine::AnchorCredentialRenewalProposal::from_trusted_state(&read_input(
                bytes, 1, 1024,
            )?)
            .map_err(protocol)?,
        })
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
    pub fn binding(&self) -> Vec<u8> {
        self.inner.binding().to_vec()
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.operation().as_bytes().to_vec()
    }
    pub fn statement(&self) -> Vec<u8> {
        self.inner.transaction_statement().to_vec()
    }
    pub fn credential_statement(&self) -> Vec<u8> {
        self.inner.statement().to_vec()
    }
    pub fn policy_continuation_statement(&self) -> Option<Vec<u8>> {
        self.inner.policy_continuation().map(|value| value.to_vec())
    }
    pub fn independent_policy_statement(&self) -> Option<Vec<u8>> {
        self.inner.policy_renewal().map(|value| value.to_vec())
    }
    pub fn adopts_policy(&self) -> bool {
        self.inner.adopts_policy()
    }
}
/// Original target-free cancellation metadata requiring independent witness approval.
#[wasm_bindgen(js_name = QPeriaptContinuityCredentialCancellation)]
pub struct CancellationRequest {
    pub(super) inner: engine::AnchorCredentialRenewalCancellation,
}
#[wasm_bindgen(js_class = QPeriaptContinuityCredentialCancellation)]
impl CancellationRequest {
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}
/// Historical outcome; neither Pending nor a failed transport means uncommitted.
#[wasm_bindgen(js_name = QPeriaptContinuityCredentialPhase)]
pub enum Phase {
    Absent = 1,
    Pending = 2,
    ExpiredUncommitted = 3,
    Committed = 4,
    Closed = 5,
}
/// Original outcome. Committed can precede remaining ACK/cleanup; activate separately.
#[wasm_bindgen(js_name = QPeriaptContinuityCredentialStatus)]
pub struct Status {
    pub(super) inner: engine::CredentialRenewalStatus,
}
impl Status {
    fn identity(&self) -> Option<(engine::CredentialRenewalId, [u8; 32])> {
        use engine::CredentialRenewalStatus as S;
        match self.inner {
            S::Absent => None,
            S::Pending {
                operation,
                statement,
            }
            | S::ExpiredUncommitted {
                operation,
                statement,
                ..
            }
            | S::Committed {
                operation,
                statement,
                ..
            }
            | S::Closed {
                operation,
                statement,
                ..
            } => Some((operation, statement)),
        }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityCredentialStatus)]
impl Status {
    pub fn phase(&self) -> Phase {
        use engine::CredentialRenewalStatus as S;
        match self.inner {
            S::Absent => Phase::Absent,
            S::Pending { .. } => Phase::Pending,
            S::ExpiredUncommitted { .. } => Phase::ExpiredUncommitted,
            S::Committed { .. } => Phase::Committed,
            S::Closed { .. } => Phase::Closed,
        }
    }
    pub fn operation_id(&self) -> Option<Vec<u8>> {
        self.identity().map(|(o, _)| o.as_bytes().to_vec())
    }
    pub fn statement(&self) -> Option<Vec<u8>> {
        self.identity().map(|(_, s)| s.to_vec())
    }
    pub fn target(&self) -> Option<Checkpoint> {
        use engine::CredentialRenewalStatus as S;
        match self.inner {
            S::Committed { target, .. } | S::Closed { target, .. } => {
                Some(Checkpoint { inner: target })
            }
            _ => None,
        }
    }
    pub fn observed_head(&self) -> Option<Checkpoint> {
        match self.inner {
            engine::CredentialRenewalStatus::ExpiredUncommitted { observed_head, .. } => {
                Some(Checkpoint {
                    inner: observed_head,
                })
            }
            _ => None,
        }
    }
    pub fn observed_at(&self) -> Option<u64> {
        match self.inner {
            engine::CredentialRenewalStatus::ExpiredUncommitted { observed_at, .. } => {
                Some(observed_at)
            }
            _ => None,
        }
    }
}
