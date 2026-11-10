// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// Both independent approvals verified against the original request and live target.
/// This value is neither a durable commit nor current traffic authority.
#[wasm_bindgen(js_name = QPeriaptContinuityPolicyGrant)]
pub struct Grant {
    pub(super) inner: engine::VerifiedPolicyRenewal,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPolicyGrant)]
impl Grant {
    #[wasm_bindgen(constructor)]
    pub fn new(
        account_approval: &Uint8Array,
        policy_approval: &Uint8Array,
        request: &super::super::policy_requests::Request,
        original: &HistoricalPolicy,
        previous: &HistoricalPolicy,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Grant, JsValue> {
        let parse = |bytes| {
            engine::PolicyRenewalApproval::from_bytes(&read_input(
                bytes,
                1,
                engine::MAX_POLICY_RENEWAL_BYTES,
            )?)
            .map_err(protocol)
        };
        Ok(Self {
            inner: engine::VerifiedPolicyRenewal::verify(
                &parse(account_approval)?,
                &parse(policy_approval)?,
                request.inner.scope(),
                &request
                    .inner
                    .materials(&original.inner, &previous.inner, &target.inner),
                read_time(now)?,
            )
            .map_err(protocol)?,
        })
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.scope().operation.as_bytes().to_vec()
    }
    pub fn statement(&self) -> Vec<u8> {
        self.inner.statement_digest().to_vec()
    }
    pub fn target_version(&self) -> u64 {
        self.inner.target_policy().version()
    }
    pub fn target_digest(&self) -> Vec<u8> {
        self.inner.target_policy().digest().to_vec()
    }
}
/// Exact public sealed-target expectations; parsing is not independent witness approval.
#[wasm_bindgen(js_name = QPeriaptContinuityPolicyProposal)]
pub struct Proposal {
    pub(super) inner: engine::AnchorPolicyRenewalProposal,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPolicyProposal)]
impl Proposal {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &Uint8Array) -> Result<Proposal, JsValue> {
        Ok(Self {
            inner: engine::AnchorPolicyRenewalProposal::from_trusted_state(&read_input(
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
        self.inner.statement().to_vec()
    }
}
/// Local policy history. None of these phases grants traffic authority.
#[wasm_bindgen(js_name = QPeriaptContinuityPolicyPhase)]
pub enum Phase {
    Absent = 1,
    Pending = 2,
    Committed = 3,
    AbandonedUncommitted = 4,
}
#[wasm_bindgen(js_name = QPeriaptContinuityPolicyAbandonment)]
pub enum Abandonment {
    Expired = 1,
    RosterAdvanced = 2,
}
#[wasm_bindgen(js_name = QPeriaptContinuityPolicyStatus)]
pub struct Status {
    pub(super) inner: engine::PolicyRenewalStatus,
}
impl Status {
    fn identity(&self) -> Option<(engine::PolicyRenewalId, [u8; 32], engine::PolicyCheckpoint)> {
        use engine::PolicyRenewalStatus as S;
        match self.inner {
            S::Absent => None,
            S::Pending {
                operation,
                statement,
                target,
            }
            | S::Committed {
                operation,
                statement,
                target,
            }
            | S::AbandonedUncommitted {
                operation,
                statement,
                target,
                ..
            } => Some((operation, statement, target)),
        }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityPolicyStatus)]
impl Status {
    pub fn phase(&self) -> Phase {
        use engine::PolicyRenewalStatus as S;
        match self.inner {
            S::Absent => Phase::Absent,
            S::Pending { .. } => Phase::Pending,
            S::Committed { .. } => Phase::Committed,
            S::AbandonedUncommitted { .. } => Phase::AbandonedUncommitted,
        }
    }
    pub fn operation_id(&self) -> Option<Vec<u8>> {
        self.identity().map(|(o, _, _)| o.as_bytes().to_vec())
    }
    pub fn statement(&self) -> Option<Vec<u8>> {
        self.identity().map(|(_, s, _)| s.to_vec())
    }
    pub fn target_version(&self) -> Option<u64> {
        self.identity().map(|(_, _, t)| t.version())
    }
    pub fn target_digest(&self) -> Option<Vec<u8>> {
        self.identity().map(|(_, _, t)| t.digest().to_vec())
    }
    pub fn abandonment(&self) -> Option<Abandonment> {
        match self.inner {
            engine::PolicyRenewalStatus::AbandonedUncommitted { reason, .. } => {
                Some(match reason {
                    engine::PolicyRenewalAbandonment::Expired => Abandonment::Expired,
                    engine::PolicyRenewalAbandonment::RosterAdvanced => Abandonment::RosterAdvanced,
                })
            }
            _ => None,
        }
    }
    pub fn observed_roster(&self) -> Option<super::super::status::Checkpoint> {
        match self.inner {
            engine::PolicyRenewalStatus::AbandonedUncommitted {
                observed_roster, ..
            } => Some(super::super::status::Checkpoint {
                inner: observed_roster,
            }),
            _ => None,
        }
    }
    pub fn observed_at(&self) -> Option<u64> {
        match self.inner {
            engine::PolicyRenewalStatus::AbandonedUncommitted { observed_at, .. } => {
                Some(observed_at)
            }
            _ => None,
        }
    }
}
/// A remote observation is separate from locally retained terminal and cleanup.
#[wasm_bindgen(js_name = QPeriaptContinuityWitnessPolicyState)]
pub enum WitnessState {
    Prepared = 1,
    Applied = 2,
    Closed = 3,
    Acknowledged = 4,
    Unavailable = 5,
}
impl From<engine::AnchorPolicyRenewalState> for WitnessState {
    fn from(value: engine::AnchorPolicyRenewalState) -> Self {
        use engine::AnchorPolicyRenewalState as S;
        match value {
            S::Prepared => Self::Prepared,
            S::Applied => Self::Applied,
            S::Closed => Self::Closed,
            S::Acknowledged => Self::Acknowledged,
            S::Unavailable => Self::Unavailable,
        }
    }
}
#[wasm_bindgen(js_name = QPeriaptContinuityWitnessPolicyStage)]
pub enum Stage {
    Reserved = 1,
    Applied = 2,
    Closed = 3,
    AbandonedBeforePreparation = 4,
}
/// Authenticated original local coordination, including terminal-before-ACK progress.
#[wasm_bindgen(js_name = QPeriaptContinuityWitnessPolicyProgress)]
pub struct Progress {
    pub(super) inner: engine::WitnessedPolicyRenewalProgress,
}
#[wasm_bindgen(js_class = QPeriaptContinuityWitnessPolicyProgress)]
impl Progress {
    pub fn stage(&self) -> Stage {
        use engine::{WitnessedPolicyRenewalDisposition as D, WitnessedPolicyRenewalProgress as P};
        match self.inner {
            P::AbandonedBeforePreparation { .. } => Stage::AbandonedBeforePreparation,
            P::Reserved { .. } => Stage::Reserved,
            P::Terminal {
                disposition: D::Applied,
                ..
            } => Stage::Applied,
            P::Terminal {
                disposition: D::Closed,
                ..
            } => Stage::Closed,
        }
    }
    pub fn retired(&self) -> bool {
        match self.inner {
            engine::WitnessedPolicyRenewalProgress::AbandonedBeforePreparation { .. } => false,
            engine::WitnessedPolicyRenewalProgress::Reserved { .. } => false,
            engine::WitnessedPolicyRenewalProgress::Terminal { retired, .. } => retired,
        }
    }
    pub fn proposal(&self) -> Result<Proposal, JsValue> {
        match self.inner {
            engine::WitnessedPolicyRenewalProgress::AbandonedBeforePreparation { .. } => {
                Err(JsValue::from_str(
                    "Policy preparation was abandoned before any proposal was released",
                ))
            }
            engine::WitnessedPolicyRenewalProgress::Reserved { proposal, .. }
            | engine::WitnessedPolicyRenewalProgress::Terminal { proposal, .. } => {
                Ok(Proposal { inner: proposal })
            }
        }
    }
    pub fn target_version(&self) -> u64 {
        match self.inner {
            engine::WitnessedPolicyRenewalProgress::AbandonedBeforePreparation {
                target, ..
            }
            | engine::WitnessedPolicyRenewalProgress::Reserved { target, .. }
            | engine::WitnessedPolicyRenewalProgress::Terminal { target, .. } => target.version(),
        }
    }
    pub fn target_digest(&self) -> Vec<u8> {
        match self.inner {
            engine::WitnessedPolicyRenewalProgress::AbandonedBeforePreparation {
                target, ..
            }
            | engine::WitnessedPolicyRenewalProgress::Reserved { target, .. }
            | engine::WitnessedPolicyRenewalProgress::Terminal { target, .. } => {
                target.digest().to_vec()
            }
        }
    }
}
