// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable original identity, separate from renewable credential authority.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OriginalIdentity {
    pub(super) account: [u8; 32],
    pub(super) description: crate::DeviceDescription,
}
impl OriginalIdentity {
    pub(super) fn from_verified(device: &VerifiedDevice) -> Self {
        Self {
            account: device.account_id(),
            description: device.description.clone(),
        }
    }
    fn owner(&self, key: &PublicKey) -> [u8; 32] {
        crate::bootstrap::credential_storage_owner(
            self.account,
            self.description.id,
            self.description.generation,
            crate::identity::device_credential_digest(self.account, &self.description, key),
        )
    }
    pub(super) fn check(&self, entry: &Entry) -> Result<(), DurableError> {
        if self.owner(&entry.device) != entry.subject.owner {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.description.id);
        out.extend_from_slice(&self.description.generation.to_be_bytes());
        self.description.validity.encode(out);
        out.extend_from_slice(&self.description.family);
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let account = d.array()?;
        nonzero(&account)?;
        let id = d.array()?;
        let generation = d.u64()?;
        let validity = Validity::decode(d)?;
        let family = d.array()?;
        Ok(Self {
            account,
            description: crate::DeviceDescription::new(id, generation, family, validity)?,
        })
    }
}

impl AnchorStore {
    /// Retain immutable original identity for an existing witness subject.
    ///
    /// Authenticate `original` from the original signed credential/roster and
    /// independently retained original pins, using `verify_historical_device`
    /// when those materials have expired. It must match the original subject
    /// owner and full device key, even if current credential authority has renewed.
    /// This is trusted control-plane metadata admission, not current permission,
    /// device replacement, revocation or a data-plane request.
    ///
    /// Exact retries do not write. An I/O error closes this owner and may follow
    /// commit: reopen the same witness and retry the same subject and proof.
    /// Subject, current credential/roster/policy, head, last command and all
    /// pending lifecycle operations remain unchanged.
    pub fn retain_original_identity(
        &mut self,
        subject: AnchorSubject,
        original: &VerifiedDevice,
    ) -> Result<(), DurableError> {
        let id = subject.id(&self.pin()?.binding);
        let mut image = self.image()?;
        let entry = image.entries.get_mut(&id).ok_or(DurableError::Absent)?;
        let identity = OriginalIdentity::from_verified(original);
        if entry.subject != subject
            || entry.device != original.key
            || storage_owner(original) != subject.owner
            || identity.owner(&entry.device) != subject.owner
        {
            return Err(Error::Scope.into());
        }
        match &entry.original_identity {
            Some(retained) if retained == &identity => Ok(()),
            Some(_) => Err(DurableError::Conflict),
            None => {
                entry.original_identity = Some(identity);
                self.persist(&mut image)
            }
        }
    }
}
