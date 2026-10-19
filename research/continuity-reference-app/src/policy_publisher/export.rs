// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// Provision through an authenticated operator channel, separately from distributed materials.
#[derive(Serialize)]
pub struct PolicyPins {
    schema: &'static str,
    #[serde(with = "wire")]
    sdk_root: Vec<u8>,
    #[serde(with = "wire")]
    sdk_state: Vec<u8>,
    #[serde(with = "wire")]
    policy_root: Vec<u8>,
    policy_version: u64,
    policy_digest: [u8; 32],
    witness: Option<Witness>,
}
#[derive(Serialize)]
struct Witness {
    identity: [u8; 32],
    #[serde(with = "wire")]
    key: Vec<u8>,
}
/// Signed public distribution, with no implied authority to choose a client's trust pins.
#[derive(Serialize)]
pub struct PolicyMaterials {
    schema: &'static str,
    #[serde(with = "wire")]
    sdk_document: Vec<u8>,
    #[serde(with = "wire")]
    sdk_signature: Vec<u8>,
    #[serde(with = "wire")]
    policy: Vec<u8>,
}
impl Publisher {
    /// Exact original public formats consumed by the independent client's PolicyInputs.
    /// Historical export can succeed after expiry; consumers still verify current time.
    pub fn export(&self, operation: [u8; 32]) -> Result<(PolicyPins, PolicyMaterials), Error> {
        let publication = self.result(operation)?;
        let config = self.config()?;
        let authority = self.authority()?;
        let witness = match publication.request.anchor {
            Anchor::LocalOnly {} => None,
            Anchor::Required { identity, key } => Some(Witness { identity, key }),
        };
        Ok((
            PolicyPins {
                schema: "qperiapt-policy-pins/1",
                sdk_root: authority.sdk_root,
                sdk_state: authority.sdk_state,
                policy_root: authority.policy_root,
                policy_version: publication.version,
                policy_digest: publication.digest,
                witness,
            },
            PolicyMaterials {
                schema: "qperiapt-policy-materials/1",
                sdk_document: config.sdk.document,
                sdk_signature: config.sdk.signature,
                policy: publication.policy,
            },
        ))
    }
}
