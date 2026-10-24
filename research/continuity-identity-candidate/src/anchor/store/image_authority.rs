// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Stored-record validation is distinct from current request admission.
use super::*;

// Implementations are confined to independently pinned original authority or a
// fully verified history. An image or record cannot add its own verification key.
pub(super) trait ImageAuthority {
    fn namespace(&self) -> [u8; 32];
    fn current(&self) -> &AnchorPin;
    fn resolve(&self, binding: [u8; 32]) -> Result<&AnchorPin, DurableError>;
}
impl ImageAuthority for AnchorPin {
    fn namespace(&self) -> [u8; 32] {
        self.binding
    }
    fn current(&self) -> &AnchorPin {
        self
    }
    fn resolve(&self, binding: [u8; 32]) -> Result<&AnchorPin, DurableError> {
        if binding == self.binding {
            Ok(self)
        } else {
            Err(DurableError::Corrupt)
        }
    }
}
impl ImageAuthority for AnchorHandoffHistory {
    fn namespace(&self) -> [u8; 32] {
        self.namespace_binding()
    }
    fn current(&self) -> &AnchorPin {
        self.current_pin()
    }
    fn resolve(&self, binding: [u8; 32]) -> Result<&AnchorPin, DurableError> {
        self.historical_pin(binding)
            .map_err(|_| DurableError::Corrupt)
    }
}

impl Image {
    // Only keys actually retained in this image can be checked here. Account
    // and policy roots represented only by commitments still require independent
    // client adoption with their complete verified materials before new work.
    pub(super) fn check_witness_key(&self, key: &PublicKey) -> Result<(), DurableError> {
        if self
            .entries
            .values()
            .any(|entry| entry.device.shares_component(key))
            || self
                .account_replacements
                .values()
                .any(|p| p.shares_witness_key(key))
            || self
                .account_freezes
                .values()
                .any(|frozen| frozen.shares_witness_key(key))
        {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
}

impl Image {
    pub(super) fn require_adopted(&self, subject: AnchorSubject) -> Result<(), DurableError> {
        if self.inherited.contains(&subject.id(&self.namespace)) {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }
    pub(super) fn require_adopted_account(&self, account: [u8; 32]) -> Result<(), DurableError> {
        for (id, entry) in &self.entries {
            if self.inherited.contains(id)
                && entry
                    .original_identity
                    .as_ref()
                    .is_none_or(|i| i.account == account)
            {
                return Err(DurableError::Suspended);
            }
        }
        Ok(())
    }
}
