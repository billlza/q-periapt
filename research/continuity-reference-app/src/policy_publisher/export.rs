// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// Provision through an authenticated operator channel, separately from distributed materials.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPins {
    schema: String,
    #[serde(with = "wire")]
    sdk_root: Vec<u8>,
    #[serde(with = "wire")]
    sdk_state: Vec<u8>,
    #[serde(with = "wire")]
    policy_root: Vec<u8>,
    policy_version: u64,
    policy_digest: [u8; 32],
    #[serde(deserialize_with = "required_witness")]
    witness: Option<Witness>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    identity: [u8; 32],
    #[serde(with = "wire")]
    key: Vec<u8>,
}
/// Signed public distribution, with no implied authority to choose a client's trust pins.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMaterials {
    schema: String,
    #[serde(with = "wire")]
    sdk_document: Vec<u8>,
    #[serde(with = "wire")]
    sdk_signature: Vec<u8>,
    #[serde(with = "wire")]
    policy: Vec<u8>,
}
fn required_witness<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Witness>, D::Error> {
    Option::<Witness>::deserialize(d)
}
impl PolicyPins {
    /// Verify distributed materials under independently supplied exact pins.
    /// The requested family is retained by the enrollment, not selected by the
    /// materials. Witness pins must match the signed requirement exactly.
    pub fn verify(
        &self,
        materials: &PolicyMaterials,
        family: [u8; 32],
        now: u64,
    ) -> Result<(sdk::VerifiedSessionPolicy, Option<sdk::AnchorPin>), Error> {
        let (pin, runtime) = self.inputs(materials, family)?;
        let policy = pin
            .verify(&materials.policy, runtime, now)
            .map_err(|_| Error::Invalid("Current protocol policy"))?;
        let witness = self.witness(policy.anchor_requirement())?;
        Ok((policy, witness))
    }
    /// Authenticate exact historical policy/SDK bindings for original-state
    /// inspection. This returns no runtime or current traffic permission.
    pub fn verify_historical(
        &self,
        materials: &PolicyMaterials,
        family: [u8; 32],
    ) -> Result<(sdk::HistoricalSessionPolicy, Option<sdk::AnchorPin>), Error> {
        let (pin, runtime) = self.inputs(materials, family)?;
        let policy = pin
            .verify_historical(&materials.policy)
            .map_err(|_| Error::Invalid("Historical protocol policy"))?;
        let binding = runtime
            .policy_binding()
            .map_err(|_| Error::Invalid("Historical SDK binding"))?;
        if policy.sdk_binding() != binding {
            return Err(Error::Invalid("Historical policy differs from SDK pins"));
        }
        let witness = self.witness(policy.anchor_requirement())?;
        Ok((policy, witness))
    }
    fn inputs(
        &self,
        materials: &PolicyMaterials,
        family: [u8; 32],
    ) -> Result<(sdk::PolicyPin, std::sync::Arc<q_periapt_sdk::Runtime>), Error> {
        if self.schema != "qperiapt-policy-pins/1"
            || materials.schema != "qperiapt-policy-materials/1"
        {
            return Err(Error::Invalid("Protocol policy input schema"));
        }
        let runtime = SdkInput {
            root: self.sdk_root.clone(),
            state: self.sdk_state.clone(),
            document: materials.sdk_document.clone(),
            signature: materials.sdk_signature.clone(),
        }
        .verify()?;
        let pin = sdk::PolicyPin::new(
            family,
            sdk::PublicKey::decode(&self.policy_root).map_err(|_| Error::Invalid("Policy root"))?,
            sdk::PolicyCheckpoint::from_trusted_state(self.policy_version, self.policy_digest)
                .map_err(|_| Error::Invalid("Policy checkpoint"))?,
        )
        .map_err(|_| Error::Invalid("Policy scope"))?;
        Ok((pin, runtime))
    }
    fn witness(
        &self,
        requirement: sdk::AnchorRequirement,
    ) -> Result<Option<sdk::AnchorPin>, Error> {
        let witness = self
            .witness
            .as_ref()
            .map(|w| -> Result<_, Error> {
                Ok(sdk::AnchorPin::new(
                    sdk::AnchorIdentity::from_trusted_state(w.identity)
                        .map_err(|_| Error::Invalid("Witness identity"))?,
                    sdk::PublicKey::decode(&w.key).map_err(|_| Error::Invalid("Witness key"))?,
                ))
            })
            .transpose()?;
        let expected = witness.as_ref().map_or_else(
            sdk::AnchorRequirement::local_only,
            sdk::AnchorRequirement::required,
        );
        if requirement != expected {
            return Err(Error::Invalid("Witness pin differs from signed policy"));
        }
        Ok(witness)
    }
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
                schema: "qperiapt-policy-pins/1".into(),
                sdk_root: authority.sdk_root,
                sdk_state: authority.sdk_state,
                policy_root: authority.policy_root,
                policy_version: publication.version,
                policy_digest: publication.digest,
                witness,
            },
            PolicyMaterials {
                schema: "qperiapt-policy-materials/1".into(),
                sdk_document: config.sdk.document,
                sdk_signature: config.sdk.signature,
                policy: publication.policy,
            },
        ))
    }
}
