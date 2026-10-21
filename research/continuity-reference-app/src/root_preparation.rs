// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently authenticated candidate-root preparation, not account cutover.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predecessor {
    pub revision: u64,
    pub account: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Retain before the first request; a timeout never selects a new correlation.
    pub request_id: [u8; 32],
    pub predecessor: Predecessor,
}
/// One independently selected candidate and one retained enrollment correlation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorRequest {
    pub preparation: [u8; 32],
    pub request_id: [u8; 32],
}
/// Retained linkage, including a closed or issued invitation; never current authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorObservation {
    pub preparation: [u8; 32],
    /// None means this preparation has never linked an enrollment.
    pub enrollment: Option<crate::enrollment::Invitation>,
}
/// Public candidate metadata. No credential, roster or current authority is issued.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub revision: u64,
    pub account: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub public_key: Vec<u8>,
    pub family: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum Status {
    Preparing,
    Prepared { candidate: Candidate },
    Closed,
}
/// Historical operation state. Prepared is not a root-selection capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub schema: String,
    pub operation: [u8; 32],
    pub request: Request,
    pub status: Status,
}
