// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// Retained signed admission materials, not current permission or a trust pin.
/// A host can distribute these public bytes without reopening the private signer.
/// Reconcile pending lifecycle work before using them to prepare a connection;
/// independently pinned current membership, policy and time must still be checked.
pub struct EnrollmentPublicAdmission {
    certificate: Vec<u8>,
    roster: Vec<u8>,
    checkpoint: RosterCheckpoint,
    journal: JournalIdentity,
}
impl EnrollmentPublicAdmission {
    /// Exact retained root-signed certificate, which may have expired.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    /// Exact retained signed roster, which may be superseded or expired.
    pub fn roster(&self) -> &[u8] {
        &self.roster
    }
    /// Retained roster identity; this is not an independently current checkpoint.
    pub fn checkpoint(&self) -> RosterCheckpoint {
        self.checkpoint
    }
    /// Original future or installed journal identity.
    pub fn journal(&self) -> JournalIdentity {
        self.journal
    }
}

impl DeviceEnrollment {
    /// Export retained public admission without granting runtime authority.
    /// This never selects a new pin, refreshes a roster, creates a signer, or
    /// finishes pending lifecycle work. Missing admission returns a state error,
    /// not empty successful output. The original enrollment lease remains held.
    pub fn public_admission(&mut self) -> Result<EnrollmentPublicAdmission, DurableError> {
        let image = self.image()?;
        let Phase::Accepted {
            admission, request, ..
        } = image.phase
        else {
            return Err(Error::State.into());
        };
        let result = (|| {
            let device = self.historical_device_metadata(
                &admission.certificate,
                &admission.roster,
                admission.checkpoint,
            )?;
            let proof = authenticate_enrollment_proof(&request, &self.intent)?;
            if proof.identity != image.identity
                || proof.public != device.key
                || device.device_id() != self.intent.description.id
                || device.generation() != self.intent.description.generation
                || device.description.validity.from() != self.intent.description.validity.from()
            {
                return Err(DurableError::Conflict);
            }
            Ok(EnrollmentPublicAdmission {
                certificate: admission.certificate,
                roster: admission.roster,
                checkpoint: admission.checkpoint,
                journal: admission.journal,
            })
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}

impl EnrolledDevice {
    /// Read the original enrollment's public admission after activation has
    /// reconciled its journal. This is retained metadata, not a new permission.
    pub fn public_admission(&mut self) -> Result<EnrollmentPublicAdmission, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment
            .public_admission();
        if result.is_err() {
            self.close();
        }
        result
    }
}
