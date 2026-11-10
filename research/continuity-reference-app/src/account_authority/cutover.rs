// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    enrollment::RootInfo,
    witness::{AccountRootDecision, AccountRootPlan, EnrollmentRequest},
};

/// Explicit host approval of one exact candidate, witness plan and prepared head.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverRequest {
    pub preparation: [u8; 32],
    pub enrollment: [u8; 32],
    pub roster: Checkpoint,
    pub journal: [u8; 32],
    pub genesis_head: [u8; 32],
    pub policy: PolicyInput,
    pub plan: AccountRootPlan,
    pub target: EnrollmentRequest,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retirement {
    pub decision: AccountRootDecision,
    #[serde(with = "crate::enrollment::wire")]
    pub receipt: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closure {
    pub operation: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub receipt: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum CutoverStatus {
    /// Approval is retained. The witness may already have an unknown outcome.
    AwaitingOutcome,
    /// An original terminal proof is retained; resume this operation to reconcile.
    Reconciling,
    /// Historical selected root snapshot, not current operating permission.
    Committed { successor: RootInfo },
    /// Permanent non-commit. The previous root remains suspended.
    Closed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cutover {
    pub schema: String,
    pub operation: [u8; 32],
    pub preparation: [u8; 32],
    pub status: CutoverStatus,
}
