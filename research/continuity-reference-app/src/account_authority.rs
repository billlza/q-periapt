// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original host-authorized account/witness association, independent of replacement inputs.
use crate::{
    enrollment::Checkpoint, policy_publisher::PolicyInput, root_preparation::Predecessor,
    witness::Pin,
};
use serde::{Deserialize, Serialize};
mod cutover;
pub use cutover::{Closure, Cutover, CutoverRequest, CutoverStatus, Retirement};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationRequest {
    pub request_id: [u8; 32],
    /// Select an exact historical host-issued enrollment under this root.
    pub enrollment: [u8; 32],
    pub root: Predecessor,
    pub roster: Checkpoint,
    /// Independently selected original policy, verified under the host's retained family.
    pub policy: PolicyInput,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Initialization {
    Preparing,
    Initialized,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Association {
    pub schema: String,
    pub application: [u8; 32],
    pub request: AssociationRequest,
    pub witness: Pin,
    /// Retained initialization history, not a current operating capability.
    pub initialization: Initialization,
}
