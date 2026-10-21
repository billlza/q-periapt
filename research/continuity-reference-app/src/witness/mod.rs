// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Restartable Continuity witness host. Local operator enrollment is separate
//! from the authenticated, bounded data plane and from account login.
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod account_root;
mod credential_renewal;
mod enrollment;
mod policy_renewal;
mod replacement;
mod roster_refresh;
mod store;
pub use account_root::{
    AccountRootDecision, AccountRootFreeze, AccountRootOutcome, AccountRootPlan, AccountRootTrust,
};
pub use credential_renewal::{CredentialPolicy, CredentialRenewalTrust};
pub use enrollment::{EnrollmentRequest, EnrollmentTrust};
pub use policy_renewal::PolicyRenewalTrust;
pub use replacement::{
    DevicePredecessorTrust, DeviceReplacementDecision, DeviceReplacementOutcome,
    DeviceReplacementStatus, DeviceReplacementTrust,
};
pub use roster_refresh::RosterRefreshTrust;
pub use store::Witness;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Distribute through an independent trusted channel, never from a TCP reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub identity: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub key: Vec<u8>,
}
impl Pin {
    pub fn as_sdk(&self) -> Result<sdk::AnchorPin> {
        Ok(sdk::AnchorPin::new(
            sdk::AnchorIdentity::from_trusted_state(self.identity)?,
            sdk::PublicKey::decode(&self.key)?,
        ))
    }
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
#[cfg(test)]
fn boundary(name: &str) -> Result<()> {
    crate::enrollment::test_boundary(name, b"original witness boundary")?;
    Ok(())
}
#[cfg(all(test, unix))]
mod tests;
