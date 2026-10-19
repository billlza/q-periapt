// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::wire;
use serde::Deserialize;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

/// Closed reusable-both advertisement plan. Its ID is observed and retained by
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
        if self.schema != "qperiapt-native-publication-plan/1" {
            return Err("Unknown publication plan schema".into());
        }
        let validity = sdk::Validity::new(self.valid_from, self.valid_until)?;
        if now < validity.from() || now >= validity.until() {
            return Err("Publication plan is not currently valid".into());
        }
        Ok(sdk::PrekeyPublicationPlan::new(
            self.directory,
            validity,
            &[
                sdk::PrekeyPublicationKey::generate(sdk::LeafKind::SignedClassical, validity),
                sdk::PrekeyPublicationKey::generate(sdk::LeafKind::LastResortPq, validity),
            ],
        )?)
    }
}
#[derive(Serialize)]
pub struct Publication {
    schema: &'static str,
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
                schema: "qperiapt-native-publication/1",
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
