// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Operator-owned SDK root and exact, recoverable policy publications.
use crate::{enrollment::wire, error::Error, sdk_inputs::SdkInput};
use q_periapt_continuity_identity_candidate as native;
use q_periapt_policy::{Policy, MAX_SIGNED_POLICY_BYTES};
use q_periapt_sdk::{Limits, Runtime};
use serde::{Deserialize, Serialize};

mod operations;
mod signer;
mod store;
pub use store::AuthorityStore;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub operation: [u8; 32],
    pub version: u32,
    pub input: SdkInput,
}
#[derive(Clone, Debug, Serialize)]
pub struct Authority {
    pub identity: [u8; 32],
    #[serde(with = "wire")]
    pub root: Vec<u8>,
    pub allocated_version: u32,
    pub pending: Option<[u8; 32]>,
}
fn document_version(document: &[u8]) -> Result<u32, Error> {
    if document.is_empty() || document.len() > MAX_SIGNED_POLICY_BYTES {
        return Err(Error::Invalid("SDK policy document bounds"));
    }
    let text = std::str::from_utf8(document).map_err(|_| Error::Invalid("SDK policy UTF-8"))?;
    let policy = Policy::from_toml(text).map_err(|_| Error::Invalid("SDK policy document"))?;
    if policy.min_nist_level() > 3 {
        return Err(Error::Invalid("SDK root cannot sign above NIST level 3"));
    }
    Ok(policy.policy_version())
}
fn fail(error: impl std::fmt::Display) -> Error {
    Error::internal("SDK policy authority", error)
}
#[cfg(test)]
fn boundary(name: &str, bytes: &[u8]) -> Result<(), Error> {
    crate::enrollment::test_boundary(name, bytes)
}
