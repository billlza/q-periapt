// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Historical R retains its own certificate while admission advances through G.
use super::*;

pub(super) fn same_identity(original: &VerifiedDevice, current: &VerifiedDevice) -> bool {
    original.account_id() == current.account_id()
        && original.device_id() == current.device_id()
        && original.generation() == current.generation()
        && original.description.family == current.description.family
        && original.key == current.key
        && original.authority_key == current.authority_key
}
impl WitnessRoster {
    pub(in crate::enrollment) fn credential_bound(&self) -> bool {
        self.credential.is_some()
    }
    pub(in crate::enrollment) fn retain_credential(
        &mut self,
        certificate: &[u8],
    ) -> Result<(), DurableError> {
        if !self.retired() {
            return Err(DurableError::Suspended);
        }
        if self.credential.is_none() {
            self.credential = Some(certificate.to_vec());
        }
        Ok(())
    }
    pub(in crate::enrollment) fn target_floor(&self) -> u64 {
        self.scope.target.version()
    }
    pub(super) fn certificate<'a>(&'a self, fallback: &'a [u8]) -> &'a [u8] {
        self.credential.as_deref().unwrap_or(fallback)
    }
    pub(super) fn credential_state_matches(&self, image: &Image) -> bool {
        match &image.renewal {
            None => self.credential.is_none(),
            Some(g) => {
                g.witnessed()
                    && self.credential.is_some()
                    && (self.retired()
                        || (g.permits_witness_policy()
                            && g.witness_roster_floor()
                                .is_some_and(|floor| self.target_floor() > floor)))
            }
        }
    }
    pub(super) fn admission_matches(
        &self,
        image: &Image,
        expected: RosterCheckpoint,
        applied: bool,
    ) -> bool {
        let Phase::Accepted { admission, .. } = &image.phase else {
            return false;
        };
        if admission.checkpoint == expected {
            return !applied || admission.roster == self.roster;
        }
        self.retired()
            && image
                .renewal
                .as_ref()
                .and_then(LocalRenewal::witnessed_completion)
                .is_some_and(|g| {
                    g.target == admission.checkpoint && g.target.version() > self.target_floor()
                })
    }
}
impl DeviceEnrollment {
    pub(super) fn check_current_roster_credential(
        &self,
        image: &Image,
        original: &VerifiedDevice,
        target: &VerifiedDevice,
    ) -> Result<(), DurableError> {
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        let current = self.historical_device_metadata(
            &admission.certificate,
            &admission.roster,
            admission.checkpoint,
        )?;
        if !same_identity(original, target)
            || current.credential_digest() != target.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
