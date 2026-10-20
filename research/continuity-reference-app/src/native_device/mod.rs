// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native reference consumer of the existing enrollment owner, without an issuer.
//! The host retains the original approved invitation and provisions the wrapping
//! key independently. These inputs are not selected by an enrollment response.
use crate::enrollment::{
    Checkpoint, CredentialExtensionRequest, Invitation, IssuedEnrollment, RootInfo,
};
use q_periapt_continuity_identity_candidate as sdk;
use serde::Serialize;
use std::{net::SocketAddr, path::Path, time::Duration};

mod admission;
mod credential_recovery;
mod mailbox;
mod peer;
mod policy;
mod publication;
mod renewal;
pub use credential_recovery::CredentialRecoveryInputs;
pub use mailbox::Mailbox;
pub use peer::{DeviceExpectation, ExchangeOperation, ExchangeRequest, PeerTrust};
pub use policy::PolicyRecoveryInputs;
pub use publication::{clock, Publication, PublicationPlan};
pub use renewal::RetainedCredentialRequest;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct NativeDevice {
    owner: sdk::DeviceEnrollment,
    invitation: Invitation,
}
#[derive(Serialize)]
pub struct Status {
    schema: &'static str,
    signing_id: [u8; 32],
    persisted_phase: &'static str,
    journal: Option<[u8; 32]>,
    preparation: String,
}
pub struct ActiveDevice {
    owner: sdk::EnrolledDevice,
    public: sdk::EnrollmentPublicAdmission,
}
impl NativeDevice {
    fn paths(directory: &Path, wrapping: &Path) -> Result<sdk::EnrollmentPaths> {
        if !directory.is_absolute() || !wrapping.is_absolute() {
            return Err("Native device and wrapping paths must be absolute".into());
        }
        Ok(sdk::EnrollmentPaths::new(
            wrapping,
            &directory.join("device.key"),
            &directory.join("enrollment.redb"),
            sdk::InstallationPaths::new(
                &directory.join("installation.redb"),
                &directory.join("journal.redb"),
                &directory.join("archives.redb"),
            )?,
        )?)
    }
    /// Explicit first use of a new enrollment with an existing host wrapping key.
    /// A failed creation is reconciled with open, never by replacing any file.
    pub fn begin(
        directory: &Path,
        wrapping: &Path,
        invitation: Invitation,
        now: u64,
    ) -> Result<Self> {
        Self::validate_invitation(&invitation)?;
        invitation.current(now)?;
        let owner = sdk::DeviceEnrollment::provision(
            Self::paths(directory, wrapping)?,
            invitation.intent()?,
        )?;
        Ok(Self { owner, invitation })
    }
    pub fn open(directory: &Path, wrapping: &Path, invitation: Invitation) -> Result<Self> {
        Self::validate_invitation(&invitation)?;
        let owner =
            sdk::DeviceEnrollment::open(Self::paths(directory, wrapping)?, invitation.intent()?)?;
        Ok(Self { owner, invitation })
    }
    fn validate_invitation(value: &Invitation) -> Result<()> {
        value.intent()?;
        if value.operation == [0; 32]
            || value.request_id == [0; 32]
            || value.application == [0; 32]
            || value.root_revision == 0
            || value.deadline < value.valid_from
            || value.deadline > value.valid_until
        {
            return Err("Invalid independently retained invitation".into());
        }
        Ok(())
    }
    pub fn request(&mut self, now: u64) -> Result<Vec<u8>> {
        Ok(self.owner.request(now)?)
    }
    /// Persisted metadata only; an Active phase is not a live permission receipt.
    pub fn status(&mut self) -> Result<Status> {
        let phase = match self.owner.status()? {
            sdk::EnrollmentStatus::Preparing => "Preparing",
            sdk::EnrollmentStatus::Requested => "Requested",
            sdk::EnrollmentStatus::Accepted(_) => "Accepted",
            sdk::EnrollmentStatus::Activating(_) => "Activating",
            sdk::EnrollmentStatus::Active(_) => "Active",
            sdk::EnrollmentStatus::Refreshing { .. } => "Refreshing",
            sdk::EnrollmentStatus::RosterResolved(_) => "RosterResolved",
        };
        let journal = if phase == "Preparing" || phase == "Requested" {
            None
        } else {
            Some(*self.owner.public_admission()?.journal().as_bytes())
        };
        Ok(Status {
            schema: "qperiapt-native-enrollment-status/1",
            signing_id: *self.owner.identity()?.as_bytes(),
            persisted_phase: phase,
            journal,
            preparation: format!("{:?}", self.owner.preparation_status()?),
        })
    }
    pub fn prepare(
        &mut self,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<sdk::InstallationPreparation> {
        self.refresh_current(current, policy, now)?;
        Ok(self.owner.prepare(policy, now)?)
    }
    pub fn activate(
        mut self,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        witness: Option<sdk::AnchorPin>,
        endpoint: Option<SocketAddr>,
        now: u64,
    ) -> Result<ActiveDevice> {
        if self.owner.preparation_status()? == sdk::EnrollmentPreparationStatus::Unprepared {
            return Err("Prepare the original installation before activation".into());
        }
        self.refresh_current(current, policy, now)?;
        let anchor = match (witness, endpoint) {
            (None, None) => None,
            (Some(pin), Some(address)) => Some(self.owner.anchor_client(
                policy,
                now,
                pin,
                Box::new(sdk::AnchorTcpTransport::new(address)),
                Duration::from_secs(10),
            )?),
            _ => {
                return Err(concat!(
                    "Witness endpoint and independently pinned requirement ",
                    "must both be present or absent"
                )
                .into());
            }
        };
        ActiveDevice::from_owner(self.owner.activate(policy, now, anchor)?)
    }
    /// Same-credential current membership. All target material is checked before
    /// calling the SDK's original CAS coordinator; no fallback or new lineage.
    /// An already matching checkpoint is a metadata-only no-op; no runtime
    /// authority is returned. Prepare/activate still perform live SDK admission.
    pub fn refresh_current(
        &mut self,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<()> {
        let result = self.refresh_current_attempt(current, policy, now);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn refresh_current_attempt(
        &mut self,
        current: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<()> {
        let pin = self.pin(current)?;
        let roster = current
            .roster
            .as_ref()
            .ok_or("Current signed roster is required")?;
        let public = self.owner.public_admission()?;
        let live = pin.verify_device(public.certificate(), &roster.bytes, now)?;
        if live.device_id() != self.invitation.device
            || live.generation() != self.invitation.generation
            || policy.family() != self.invitation.family
        {
            return Err("Current membership differs from the original device".into());
        }
        let next = roster.checkpoint.as_sdk()?;
        Self::monotonic(next, public.checkpoint())?;
        if next != public.checkpoint() {
            if policy.anchor_requirement() != sdk::AnchorRequirement::local_only()
                && self.owner.preparation_status()? != sdk::EnrollmentPreparationStatus::Unprepared
            {
                return Err(
                    "Retained witnessed roster changes require their explicit witness coordination"
                        .into(),
                );
            }
            self.owner
                .refresh_roster(public.checkpoint(), &roster.bytes, &pin, policy, now)?;
        }
        Ok(())
    }
    pub fn close(&mut self) {
        self.owner.close();
    }
}
impl ActiveDevice {
    fn from_owner(mut owner: sdk::EnrolledDevice) -> Result<Self> {
        let public = owner.public_admission()?;
        Ok(Self { owner, public })
    }
    pub fn journal(&self) -> [u8; 32] {
        *self.public.journal().as_bytes()
    }
    pub fn next_publication(&mut self) -> Result<[u8; 32]> {
        Ok(*self.owner.next_prekey_publication_id()?.as_bytes())
    }
    pub fn close(&mut self) {
        self.owner.close();
    }
}
impl Drop for ActiveDevice {
    fn drop(&mut self) {
        self.close();
    }
}
