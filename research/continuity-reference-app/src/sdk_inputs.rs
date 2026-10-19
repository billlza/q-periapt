// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact signed SDK inputs; trusted provisioning remains a host responsibility.
use crate::{enrollment::wire, error::Error};
use q_periapt_policy::TrustedPolicyState;
use q_periapt_sdk::{Limits, Runtime};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Explicit operator-provisioned SDK expectation and signed distribution bytes.
/// Supplying these fields is a trust decision, not proof of its authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkInput {
    #[serde(with = "wire")]
    pub root: Vec<u8>,
    #[serde(with = "wire")]
    pub state: Vec<u8>,
    #[serde(with = "wire")]
    pub document: Vec<u8>,
    #[serde(with = "wire")]
    pub signature: Vec<u8>,
}
impl SdkInput {
    pub fn verify(&self) -> Result<Arc<Runtime>, Error> {
        if self.root.len() != 1952
            || self.state.len() != 36
            || self.document.is_empty()
            || self.document.len() > 65536
            || self.signature.len() != 3309
        {
            return Err(Error::Invalid("SDK policy input bounds"));
        }
        let trusted = TrustedPolicyState::decode(&self.state)
            .map_err(|_| Error::Invalid("SDK trusted state"))?;
        let runtime = Runtime::from_signed_policy(
            &self.document,
            &self.signature,
            &self.root,
            Some(&trusted),
            Limits::default(),
        )
        .map_err(|_| Error::Invalid("SDK policy authentication"))?;
        if runtime.trusted_state() != trusted {
            return Err(Error::Invalid("SDK input differs from exact trusted state"));
        }
        Ok(Arc::new(runtime))
    }
}
