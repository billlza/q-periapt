// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retain original enrollment authority through whole-device cleanup and signer erasure.
use super::*;
use crate::{
    crypto::SigningFilePlan, retired_device::JournalErasureState, AnchorRetiredCleanupProposal,
    AnchorRetiredReportAcknowledgement, AnchorRetiredSubject, RetiredInstallationRecovery,
};
use redb::ReadableTable;

/// Logical state of the original acknowledged signer file, not retained pages or backups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningFileErasureState {
    /// Original encrypted seed bytes remain; ordinary opening may already be blocked by a partial marker.
    Retained,
    /// Only the exact nonempty retirement marker remains in the original admitted inode.
    Erased,
}
#[derive(Clone, Eq, PartialEq)]
struct SignerPlan {
    file: SigningFilePlan,
    acknowledgement: Vec<u8>,
}
#[derive(Clone, Eq, PartialEq)]
pub(super) struct State {
    identity: SigningKeyId,
    enrollment_digest: [u8; 32],
    inventory: AnchorRetiredCleanupProposal,
    signer: Option<Box<SignerPlan>>,
}
impl State {
    pub(super) fn decode(
        wire: &[u8],
        key: &JournalKey,
        binding: [u8; 32],
    ) -> Result<Self, DurableError> {
        if !(8 + 32 + 32 + 32 + 313 + 1 + 32..=8192).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut mac = auth(key)?;
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *b"QPERTR01" || d.array::<32>()? != binding {
            return Err(DurableError::Conflict);
        }
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let enrollment_digest = d.array()?;
        let inventory = AnchorRetiredCleanupProposal::from_trusted_state(d.take(313)?)?;
        let signer = match d.array::<1>()? {
            [0] => None,
            [1] => {
                let file = SigningFilePlan::decode(&mut d)?;
                if file.identity() != identity || file.report().inventory() != &inventory {
                    return Err(DurableError::Corrupt);
                }
                Some(Box::new(SignerPlan {
                    file,
                    acknowledgement: d.take(3730)?.to_vec(),
                }))
            }
            _ => return Err(DurableError::Corrupt),
        };
        d.finish()?;
        Ok(Self {
            identity,
            enrollment_digest,
            inventory,
            signer,
        })
    }
    fn encode(&self, key: &JournalKey, binding: [u8; 32]) -> Result<Vec<u8>, DurableError> {
        let mut wire = b"QPERTR01".to_vec();
        wire.extend_from_slice(&binding);
        wire.extend_from_slice(self.identity.as_bytes());
        wire.extend_from_slice(&self.enrollment_digest);
        wire.extend_from_slice(&self.inventory.to_bytes());
        match &self.signer {
            None => wire.push(0),
            Some(p) => {
                wire.push(1);
                p.file.encode(&mut wire);
                wire.extend_from_slice(&p.acknowledgement);
            }
        }
        let mut mac = auth(key)?;
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        if wire.len() > 8192 {
            return Err(DurableError::Capacity);
        }
        Ok(wire)
    }
    pub(super) fn check_image(&self, image: &Image, wire: &[u8]) -> Result<(), DurableError> {
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        let (journal, _, policy) = self.inventory.subject().journal_parts();
        if image.identity != self.identity
            || *admission.journal.as_bytes() != journal
            || admission.policy != policy
            || self.enrollment_digest != enrollment_digest(wire)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
fn enrollment_digest(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-RETIRED-ENROLLMENT/v1", wire)
}
fn original_digest(enrollment: &DeviceEnrollment) -> Result<[u8; 32], DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let tx = active.database.begin_read().map_err(storage)?;
    let table = tx.open_table(TABLE).map_err(storage)?;
    let row = table
        .get("enrollment")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    Ok(enrollment_digest(row.value()))
}
fn save(
    enrollment: &DeviceEnrollment,
    old: Option<&State>,
    next: &State,
) -> Result<(), DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let wire = next.encode(&active.key, enrollment.binding)?;
    let expected = old
        .map(|s| s.encode(&active.key, enrollment.binding))
        .transpose()?;
    let tx = transaction(&active.database)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        if table.len().map_err(storage)? != if old.is_some() { 2 } else { 1 }
            || table
                .get("retirement")
                .map_err(storage)?
                .as_ref()
                .map(|v| v.value())
                != expected.as_deref()
            || table
                .get("enrollment")
                .map_err(storage)?
                .as_ref()
                .map(|v| enrollment_digest(v.value()))
                != Some(next.enrollment_digest)
        {
            return Err(DurableError::Conflict);
        }
        table
            .insert("retirement", wire.as_slice())
            .map_err(storage)?;
    }
    tx.commit().map_err(DurableError::CommitUncertain)
}
struct Owners {
    enrollment: DeviceEnrollment,
    pin: AnchorPin,
    retired: AnchorRetiredSubject,
    state: State,
    installation: Option<RetiredInstallationRecovery>,
}
impl Owners {
    fn read(&self) -> Result<(Image, State, VerifiedDevice), DurableError> {
        let active = self
            .enrollment
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        let (image, state) = load_snapshot(&active.database, &active.key, self.enrollment.binding)?;
        let state = state.ok_or(DurableError::Conflict)?;
        if state != self.state {
            return Err(DurableError::Conflict);
        }
        state.inventory.check_retirement(self.retired)?;
        validate_metadata(&self.enrollment, &image)?;
        let original = self.enrollment.original_device_metadata(&image)?;
        check_original(&image, &original, self.retired, &self.pin)?;
        if let Some(plan) = &state.signer {
            self.verify_plan(plan)?;
        }
        Ok((image, state, original))
    }
    fn verify_plan(
        &self,
        plan: &SignerPlan,
    ) -> Result<AnchorRetiredReportAcknowledgement, DurableError> {
        if plan.file.report().inventory() != &self.state.inventory
            || plan.file.identity() != self.state.identity
        {
            return Err(DurableError::Conflict);
        }
        Ok(self.pin.verify_retired_report_acknowledgement(
            self.retired,
            plan.file.report(),
            &plan.acknowledgement,
        )?)
    }
    fn installation(&mut self) -> Result<&mut RetiredInstallationRecovery, DurableError> {
        self.read()?;
        // Reconcile the same saved request, including after erase_journal closed its
        // restricted child. This does not replay host effects or select another backup.
        self.installation = None;
        let mut child = RetiredInstallationRecovery::open(
            self.enrollment.paths.installation.clone(),
            self.enrollment.key()?,
            self.retired,
        )?;
        if child.proposal()? != self.state.inventory {
            return Err(DurableError::Conflict);
        }
        self.installation = Some(child);
        self.installation.as_mut().ok_or(DurableError::Closed)
    }
}
fn validate_metadata(enrollment: &DeviceEnrollment, image: &Image) -> Result<(), DurableError> {
    enrollment.validate_roster_resolution(image)?;
    enrollment.validate_witness_roster(image)?;
    enrollment.validate_policy_pending(image)
}
fn check_original(
    image: &Image,
    original: &VerifiedDevice,
    retired: AnchorRetiredSubject,
    pin: &AnchorPin,
) -> Result<(), DurableError> {
    let Phase::Accepted { admission, .. } = &image.phase else {
        return Err(DurableError::Suspended);
    };
    let (journal, owner, policy) = retired.subject().journal_parts();
    if journal != *admission.journal.as_bytes()
        || owner != crate::bootstrap::storage_owner(original)
        || policy != admission.policy
        || pin.binding() != retired.witness_binding()
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

/// Restricted original enrollment owner for permanent device retirement.
/// Holds the enrollment lease across reporting and host acknowledgement; no signer,
/// enrollment request or operational service is exposed. Historical metadata retains
/// the original identity even after credential/policy expiry.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{EnrolledDevice, RetiredDeviceEnrollment};
/// fn active(old: RetiredDeviceEnrollment) -> EnrolledDevice { old }
/// ```
pub struct RetiredDeviceEnrollment {
    active: Option<Owners>,
}
impl RetiredDeviceEnrollment {
    /// Open the original existing enrollment with independently verified permanent
    /// retirement and its original witness pin. First admission retains the existing
    /// installation's original inventory, then freezes the enrollment metadata.
    /// An unknown commit returns no owner; reopen these exact paths/intent/proof.
    pub fn open(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        let binding = paths.binding(&key, &intent)?;
        let database = open_private_database(&paths.configuration)?;
        let enrollment = DeviceEnrollment {
            active: Some(Active { database, key }),
            paths,
            intent,
            binding,
            account_authority: None,
        };
        Self::from_enrollment(enrollment, pin, retired)
    }
    #[cfg(all(test, unix))]
    pub(crate) fn open_in_database(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
        database: Database,
    ) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        let binding = paths.binding(&key, &intent)?;
        Self::from_enrollment(
            DeviceEnrollment {
                active: Some(Active { database, key }),
                paths,
                intent,
                binding,
                account_authority: None,
            },
            pin,
            retired,
        )
    }
    fn from_enrollment(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
        let (image, saved) = load_snapshot(&active.database, &active.key, enrollment.binding)?;
        validate_metadata(&enrollment, &image)?;
        let original = enrollment.original_device_metadata(&image)?;
        check_original(&image, &original, retired, &pin)?;
        let state = match saved {
            Some(state) => {
                state.inventory.check_retirement(retired)?;
                state
            }
            None => {
                let mut child = RetiredInstallationRecovery::open(
                    enrollment.paths.installation.clone(),
                    enrollment.key()?,
                    retired,
                )?;
                let state = State {
                    identity: image.identity,
                    enrollment_digest: original_digest(&enrollment)?,
                    inventory: child.proposal()?,
                    signer: None,
                };
                save(&enrollment, None, &state)?;
                state
            }
        };
        let owner = Owners {
            enrollment,
            pin,
            retired,
            state,
            installation: None,
        };
        owner.read()?;
        Ok(Self {
            active: Some(owner),
        })
    }
    /// Borrow the existing restricted installation flow for full report retention,
    /// explicit host acknowledgement and journal erasure. Each new borrow reopens
    /// the same independently saved expectation; missing originals are never replaced.
    pub fn installation(&mut self) -> Result<&mut RetiredInstallationRecovery, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)
            .and_then(|o| o.installation().map(|_| ()));
        if let Err(error) = result {
            self.close();
            return Err(error);
        }
        self.active
            .as_mut()
            .and_then(|o| o.installation.as_mut())
            .ok_or(DurableError::Closed)
    }
    /// Retain an exact original signer-file plan after authenticated journal erasure
    /// and purpose-21 host acknowledgement. This authenticates the original device
    /// role, public key, file identity and encrypted bytes without returning a signer.
    /// Exact retries retain the first plan and perform no file mutation.
    pub fn prepare_signer_erasure(&mut self, receipt: &[u8]) -> Result<(), DurableError> {
        let result = (|| {
            let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
            let (image, state, original) = owners.read()?;
            if let Some(plan) = &state.signer {
                owners.pin.verify_retired_report_acknowledgement(
                    owners.retired,
                    plan.file.report(),
                    receipt,
                )?;
                return Ok(());
            }
            let pin = owners.pin.clone();
            let child = owners.installation()?;
            if child.journal_erasure_status(&pin)? != JournalErasureState::Erased {
                return Err(DurableError::Suspended);
            }
            let ack = child.verify_host_acknowledgement(&pin, receipt)?;
            let active = owners
                .enrollment
                .active
                .as_ref()
                .ok_or(DurableError::Closed)?;
            let file = SigningFilePlan::capture(
                &owners.enrollment.paths.signer,
                &active.key,
                image.identity,
                &original,
                &ack,
            )?;
            let mut next = state.clone();
            next.signer = Some(Box::new(SignerPlan {
                file,
                acknowledgement: receipt.to_vec(),
            }));
            save(&owners.enrollment, Some(&state), &next)?;
            owners.state = next;
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Query the original prepared file. Missing, foreign or corrupt state is an
    /// error. A full-length partially marked file still retains encrypted seeds.
    /// This requires the independently stored complete host ACK, never just a tag.
    pub fn signer_erasure_status(&mut self) -> Result<SigningFileErasureState, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let (_, state, original) = owners.read()?;
            let plan = state.signer.as_ref().ok_or(DurableError::Suspended)?;
            let ack = owners.verify_plan(plan)?;
            let active = owners
                .enrollment
                .active
                .as_ref()
                .ok_or(DurableError::Closed)?;
            Ok(
                if plan.file.erased(
                    &owners.enrollment.paths.signer,
                    &active.key,
                    &original,
                    &ack,
                )? {
                    SigningFileErasureState::Erased
                } else {
                    SigningFileErasureState::Retained
                },
            )
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Logically erase only the exact prepared original signing file. Sync the fixed
    /// retirement header before truncating its encrypted body, then sync again.
    /// Always closes this owner; reopen and retry the original plan after I/O failure.
    /// Wrapping key, historical configuration, old pages/backups and previously copied
    /// signing owners remain outside this logical erasure claim.
    pub fn erase_signer(&mut self) -> Result<(), DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let (_, state, original) = owners.read()?;
            let plan = state.signer.as_ref().ok_or(DurableError::Suspended)?;
            let ack = owners.verify_plan(plan)?;
            let active = owners
                .enrollment
                .active
                .as_ref()
                .ok_or(DurableError::Closed)?;
            plan.file.erase(
                &owners.enrollment.paths.signer,
                &active.key,
                &original,
                &ack,
            )
        })();
        self.close();
        result
    }
    /// Close all held enrollment, wrapping and restricted installation owners.
    pub fn close(&mut self) {
        self.active = None;
    }
}
impl EnrolledDevice {
    /// Consume this device's service and signer, retaining its original enrollment
    /// lease for permanent retirement under independently verified witness authority.
    pub fn retire(
        mut self,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
    ) -> Result<RetiredDeviceEnrollment, DurableError> {
        let owners = self.active.take().ok_or(DurableError::Closed)?;
        let EnrolledOwners {
            enrollment,
            mut service,
            mut signer,
            ..
        } = *owners;
        service.close();
        signer.close();
        RetiredDeviceEnrollment::from_enrollment(enrollment, pin, retired)
    }
}
