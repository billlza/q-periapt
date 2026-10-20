// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local operator publication. SDK trust is provisioned independently; no login dependency.
use crate::{enrollment::wire, error::Error};
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};

pub use crate::sdk_inputs::SdkInput;

mod export;
mod operations;
mod renewal;
mod renewal_store;
mod signer;
mod store;
pub use export::{PolicyApprovalInputs, PolicyInput, PolicyMaterials, PolicyPins};
pub use renewal::{IssuedRenewal, RenewalRequest, RenewalStatus};
pub use store::Publisher;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Anchor {
    LocalOnly {},
    Required {
        identity: [u8; 32],
        #[serde(with = "wire")]
        key: Vec<u8>,
    },
}
impl Anchor {
    fn pin(&self) -> Result<Option<sdk::AnchorPin>, Error> {
        match self {
            Self::LocalOnly {} => Ok(None),
            Self::Required { identity, key } => Ok(Some(sdk::AnchorPin::new(
                sdk::AnchorIdentity::from_trusted_state(*identity)
                    .map_err(|_| Error::Invalid("Witness identity"))?,
                sdk::PublicKey::decode(key).map_err(|_| Error::Invalid("Witness key"))?,
            ))),
        }
    }
}

/// Exact original publication intent. Versions are allocated by the persistent owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMode {
    Disabled,
    ReusableBoth,
}
impl BootstrapMode {
    fn allowed(self) -> Result<sdk::AllowedPrekeyModes, Error> {
        sdk::AllowedPrekeyModes::new(match self {
            Self::Disabled => &[],
            Self::ReusableBoth => &[sdk::PrekeyQuality::ReusableBoth],
        })
        .map_err(|_| Error::Internal)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub bootstrap_mode: BootstrapMode,
    pub valid_from: u64,
    pub valid_until: u64,
    pub send_budget: u16,
    pub anchor: Anchor,
}
impl Request {
    fn parameters(&self, version: u64, now: u64) -> Result<sdk::SessionPolicyParameters, Error> {
        let validity = sdk::Validity::new(self.valid_from, self.valid_until)
            .map_err(|_| Error::Invalid("Policy validity interval"))?;
        if now < self.valid_from || now >= self.valid_until {
            return Err(Error::Invalid("Policy is not currently valid"));
        }
        let pin = self.anchor.pin()?;
        sdk::SessionPolicyParameters::new(
            version,
            validity,
            self.bootstrap_mode.allowed()?,
            pin.as_ref().map_or_else(
                sdk::AnchorRequirement::local_only,
                sdk::AnchorRequirement::required,
            ),
            sdk::ApplicationSendBudget::new(self.send_budget)
                .map_err(|_| Error::Invalid("Policy send budget must be nonzero"))?,
        )
        .map_err(|_| Error::Capacity)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub operation: [u8; 32],
    pub version: u64,
    pub digest: [u8; 32],
    pub request: Request,
    #[serde(with = "wire")]
    pub policy: Vec<u8>,
}

#[derive(Clone, Serialize)]
pub struct Authority {
    pub publisher: [u8; 32],
    pub family: [u8; 32],
    #[serde(with = "wire")]
    pub policy_root: Vec<u8>,
    #[serde(with = "wire")]
    pub sdk_root: Vec<u8>,
    #[serde(with = "wire")]
    pub sdk_state: Vec<u8>,
}

fn fail(error: impl std::fmt::Display) -> Error {
    Error::internal("policy publication", error)
}

#[cfg(test)]
fn boundary(name: &str, bytes: &[u8]) -> Result<(), Error> {
    crate::enrollment::test_boundary(name, bytes)
}
