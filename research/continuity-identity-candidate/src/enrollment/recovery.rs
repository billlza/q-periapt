// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Restricted cleanup from the original enrollment and platform storage lease.
use super::*;
use crate::{
    FanoutAbandonmentJournal, FanoutId, HistoricalSessionPolicy, InstallationRecovery,
    InstalledAccountRecovery, InstalledSessionRecovery, SessionClosureJournal,
};

enum Selected {
    Account(Box<InstalledAccountRecovery>),
    Session(Box<InstalledSessionRecovery>),
}

// Journal/index/configuration are released before the original enrollment lease.
// This owner exposes no current runtime, session context, signer or provisioning.
struct Owners {
    selected: Selected,
    enrollment: DeviceEnrollment,
}
/// Restricted original enrollment and selected cleanup journal. No current
/// runtime, session context, signer or provisioning interface is exposed.
/// Closing this owner releases leases without acknowledging loss or erasing state.
pub struct EnrollmentRecovery {
    active: Option<Owners>,
}
impl EnrollmentRecovery {
    /// Retained enrollment metadata only; Active is not current traffic permission.
    pub fn enrollment_status(&mut self) -> Result<EnrollmentStatus, DurableError> {
        self.active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment
            .status()
    }
    /// Borrow only the selected whole-account cleanup flow, with no member subset.
    pub fn account(&mut self) -> Result<&mut FanoutAbandonmentJournal, DurableError> {
        match &mut self.active.as_mut().ok_or(DurableError::Closed)?.selected {
            Selected::Account(owner) => owner.journal(),
            Selected::Session(_) => Err(Error::State.into()),
        }
    }
    /// Borrow only the selected historical session's explicit loss-accounting flow.
    pub fn session(&mut self) -> Result<&mut SessionClosureJournal, DurableError> {
        match &mut self.active.as_mut().ok_or(DurableError::Closed)?.selected {
            Selected::Session(owner) => Ok(owner.stores()?.0),
            Selected::Account(_) => Err(Error::State.into()),
        }
    }
    /// Release all original owners. No report is acknowledged by closing.
    pub fn close(&mut self) {
        self.active = None;
    }
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Consume this original enrollment into complete-account cleanup without
    /// current validity. Required protection still needs its original witness;
    /// missing/conflicting state never provisions or grants traffic permission.
    pub async fn recover_account(
        mut self,
        operation: FanoutId,
        original_policy: &HistoricalSessionPolicy,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<EnrollmentRecovery, DurableError> {
        let (discovery, client) = self.recovery(original_policy, witness).await?;
        let selected = discovery.open_account(operation, client).await?;
        Ok(EnrollmentRecovery {
            active: Some(Owners {
                selected: Selected::Account(Box::new(selected)),
                enrollment: self,
            }),
        })
    }
    /// Consume this original enrollment into one existing session's cleanup flow.
    /// Reserved whole-account work cannot be split through independent closure.
    pub async fn recover_session(
        mut self,
        session: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<EnrollmentRecovery, DurableError> {
        let (discovery, client) = self.recovery(original_policy, witness).await?;
        let selected = discovery.open_session(session, client).await?;
        Ok(EnrollmentRecovery {
            active: Some(Owners {
                selected: Selected::Session(Box::new(selected)),
                enrollment: self,
            }),
        })
    }
    async fn recovery(
        &mut self,
        policy: &HistoricalSessionPolicy,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<(InstallationRecovery, Option<AnchorClient>), DurableError> {
        let image = self.image()?;
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Suspended);
        };
        // This is the original immutable policy pin, not a current permission.
        if admission.policy != policy.checkpoint().digest() {
            return Err(DurableError::Conflict);
        }
        let original = self.original_device_metadata(&image)?;
        let client = match (policy.anchor_requirement().binding(), witness) {
            (None, None) => None,
            (Some(expected), Some((pin, transport, timeout))) => {
                if pin.binding() != expected {
                    return Err(DurableError::Conflict);
                }
                policy.check_external_signer(pin.public_key())?;
                if pin.public_key().shares_component(&original.authority_key) {
                    return Err(Error::Scope.into());
                }
                let client = AnchorClient::new(
                    pin,
                    self.signer(image.identity, false).await?,
                    transport,
                    timeout,
                )?;
                client.check_device(&original)?;
                Some(client)
            }
            (Some(_), None) => return Err(DurableError::AnchorRequired),
            (None, Some(_)) => return Err(DurableError::Conflict),
        };
        let discovery = InstallationRecovery::open_with_storage(
            self.storage.clone(),
            self.paths.installation.clone(),
            self.key().await?,
        )
        .await?;
        discovery.require_enrollment_scope(admission.journal, &original, policy)?;
        Ok((discovery, client))
    }
}
