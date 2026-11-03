// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::wire;
use serde::Deserialize;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

/// Closed reusable-both or one-time-both advertisement plan. Its ID is observed and retained by
/// the caller before submission; retrying never chooses a new ordinal or plan.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPlan {
    schema: String,
    directory: [u8; 32],
    valid_from: u64,
    valid_until: u64,
}
impl PublicationPlan {
    /// Validate static inputs before opening or activating a device. The SDK
    /// rechecks live policy and time again at every publication release boundary.
    pub fn verify(&self, now: u64) -> Result<sdk::PrekeyPublicationPlan> {
        let kinds: &[sdk::LeafKind] = match self.schema.as_str() {
            "qperiapt-native-publication-plan/1" => &[
                sdk::LeafKind::SignedClassical,
                sdk::LeafKind::LastResortPq,
            ],
            "qperiapt-native-one-time-publication-plan/1" => &[
                sdk::LeafKind::SignedClassical,
                sdk::LeafKind::OneTimeClassical,
                sdk::LeafKind::LastResortPq,
                sdk::LeafKind::OneTimePq,
            ],
            _ => return Err("Unknown publication plan schema".into()),
        };
        let validity = sdk::Validity::new(self.valid_from, self.valid_until)?;
        if now < validity.from() || now >= validity.until() {
            return Err("Publication plan is not currently valid".into());
        }
        Ok(sdk::PrekeyPublicationPlan::new(
            self.directory,
            validity,
            &kinds
                .iter()
                .map(|kind| sdk::PrekeyPublicationKey::generate(*kind, validity))
                .collect::<Vec<_>>(),
        )?)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    schema: String,
    journal: [u8; 32],
    publication: [u8; 32],
    #[serde(with = "wire")]
    artifact: Vec<u8>,
    #[serde(with = "wire")]
    certificate: Vec<u8>,
    #[serde(with = "wire")]
    roster: Vec<u8>,
    checkpoint: Checkpoint,
}
/// Independent host expectation. No field is learned from the advertisement.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationTrust {
    schema: String,
    current: RootInfo,
    device: [u8; 16],
    generation: u64,
    journal: [u8; 32],
    publication: [u8; 32],
}
impl PublicationTrust {
    /// Independently selected policy family.
    pub fn family(&self) -> [u8; 32] {
        self.current.family
    }
    /// Authenticate a directory advertisement without opening or changing storage.
    pub fn verify(
        &self,
        publication: &Publication,
        plan: &PublicationPlan,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<sdk::AuthenticatedPrekeySelection> {
        if self.schema != "qperiapt-native-publication-trust/1"
            || self.current.suspended
            || self.current.revision == 0
            || self.current.family != policy.family()
            || publication.journal != self.journal
            || publication.publication != self.publication
        {
            return Err("Publication differs from current independent trust".into());
        }
        let plan = plan.verify(now)?;
        let (schema, _) = publication_profile(&plan)?;
        let roster = self
            .current
            .roster
            .as_ref()
            .ok_or("Current signed roster is required")?;
        if publication.schema != schema
            || publication.checkpoint != roster.checkpoint
            || publication.roster != roster.bytes
        {
            return Err("Publication schema or current roster differs".into());
        }
        let pin = sdk::AccountPin::new(
            self.current.account,
            sdk::PublicKey::decode(&self.current.public_key)?,
            roster.checkpoint.as_sdk()?,
            self.current.family,
        )?;
        let device = pin.verify_device(&publication.certificate, &roster.bytes, now)?;
        if device.device_id() != self.device || device.generation() != self.generation {
            return Err("Publication device differs from independent expectation".into());
        }
        Ok(plan.verify_artifact(
            &publication.artifact,
            &self.journal,
            sdk::PrekeyPublicationId::from_trusted_state(self.publication)?,
            &device,
            policy,
            now,
        )?)
    }
}
fn publication_profile(
    plan: &sdk::PrekeyPublicationPlan,
) -> Result<(&'static str, sdk::PrekeyQuality)> {
    let kinds: Vec<_> = plan.keys().iter().map(|key| key.kind() as u8).collect();
    match kinds.as_slice() {
        [1, 3] => Ok(("qperiapt-native-publication/1", sdk::PrekeyQuality::ReusableBoth)),
        [1, 2, 3, 4] => Ok((
            "qperiapt-native-one-time-publication/1",
            sdk::PrekeyQuality::OneTimeBoth,
        )),
        _ => Err("Unsupported publication member plan".into()),
    }
}

pub fn clock() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}
impl ActiveDevice {
    pub fn publish(
        &mut self,
        id: [u8; 32],
        plan: &sdk::PrekeyPublicationPlan,
        policy: &sdk::VerifiedSessionPolicy,
    ) -> Result<Publication> {
        let result = (|| {
            let (schema, quality) = publication_profile(plan)?;
            policy.check_mode(quality, clock()?)?;
            let cancel = sdk::Cancellation::default();
            let deadline = sdk::MonotonicInstant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or("Publication deadline overflow")?;
            let prepared = self.owner.prepare_prekey_publication(
                sdk::PrekeyPublicationId::from_trusted_state(id)?,
                plan,
                policy,
                sdk::PrekeyPublicationRun {
                    cancel: &cancel,
                    deadline,
                },
                clock,
            )?;
            Ok(Publication {
                schema: schema.into(),
                journal: self.journal(),
                publication: id,
                artifact: prepared.as_bytes().to_vec(),
                certificate: self.public.certificate().to_vec(),
                roster: self.public.roster().to_vec(),
                checkpoint: self.public.checkpoint().into(),
            })
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
