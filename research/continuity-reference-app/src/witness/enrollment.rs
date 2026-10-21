// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{enrollment::RootInfo, policy_publisher::PolicyInput};

/// Public export shared by the native and independent preparation commands.
/// It grants no authority and must match a separately approved exact head.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub preparation: String,
    pub subject: Vec<u8>,
    pub head: [u8; 32],
}
/// Operator-provisioned trust and exact initial-image approval. Never derive
/// these fields from an incoming enrollment or data-plane request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentTrust {
    pub schema: String,
    pub account: RootInfo,
    pub device: [u8; 16],
    pub generation: u64,
    pub journal: [u8; 32],
    pub genesis_head: [u8; 32],
    #[serde(with = "crate::enrollment::wire")]
    pub certificate: Vec<u8>,
    pub policy: PolicyInput,
}
impl EnrollmentTrust {
    pub(super) fn enroll(
        &self,
        store: &mut sdk::AnchorStore,
        request: &EnrollmentRequest,
        now: u64,
    ) -> Result<()> {
        let (genesis, device, policy) = self.inputs(&store.pin()?, request, now)?;
        store.enroll(&genesis, &device, &policy, now)?;
        Ok(())
    }

    pub(super) fn inputs(
        &self,
        witness_pin: &sdk::AnchorPin,
        request: &EnrollmentRequest,
        now: u64,
    ) -> Result<(
        sdk::AnchorGenesis,
        sdk::VerifiedDevice,
        sdk::VerifiedSessionPolicy,
    )> {
        if self.schema != "qperiapt-witness-enrollment-trust/1"
            || request.preparation != "RequiresWitnessEnrollment"
            || self.account.revision == 0
            || self.account.suspended
            || request.head != self.genesis_head
        {
            return Err("Witness enrollment differs from independent approval".into());
        }
        let roster = self
            .account
            .roster
            .as_ref()
            .ok_or("Current roster required")?;
        let pin = sdk::AccountPin::new(
            self.account.account,
            sdk::PublicKey::decode(&self.account.public_key)?,
            roster.checkpoint.as_sdk()?,
            self.account.family,
        )?;
        let device = pin.verify_device(&self.certificate, &roster.bytes, now)?;
        if device.device_id() != self.device || device.generation() != self.generation {
            return Err("Witness enrollment device differs from independent approval".into());
        }
        let (policy, witness) =
            self.policy
                .pins
                .verify(&self.policy.materials, self.account.family, now)?;
        if witness.as_ref().map(|pin| pin.binding()) != Some(witness_pin.binding()) {
            return Err("Enrollment policy must require this exact witness".into());
        }
        let subject = sdk::AnchorSubject::for_device(
            sdk::JournalIdentity::from_trusted_state(self.journal)?,
            &device,
            &policy,
        )?;
        if subject.to_bytes() != request.subject {
            return Err("Witness enrollment subject differs from independent approval".into());
        }
        let genesis = sdk::AnchorGenesis::from_trusted_state(subject, request.head)?;
        Ok((genesis, device, policy))
    }
}
