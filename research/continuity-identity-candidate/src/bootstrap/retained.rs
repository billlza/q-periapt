// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Private current identity view over an immutable established transcript.
use super::*;
use crate::identity::renewal::ResolvedSessionIdentity;

#[derive(Clone, Copy)]
pub(super) struct StorageBinding {
    journal: [u8; 32],
    role: BootstrapRole,
    owner: [u8; 32],
}

pub(super) struct SessionAuthority {
    journal: [u8; 32],
    session: [u8; 32],
    role: BootstrapRole,
    identities: [Option<ResolvedSessionIdentity>; 2],
}
impl BootstrapContext {
    // Called only after the owning journal has checked the exact established
    // record. No original identity, prekey, transcript or storage byte is changed.
    pub(crate) fn with_session_authority(
        &self,
        journal: [u8; 32],
        session: [u8; 32],
        role: BootstrapRole,
        identities: [Option<ResolvedSessionIdentity>; 2],
    ) -> Result<Self, Error> {
        Ok(Self {
            policy: Arc::clone(&self.policy),
            initiator: Arc::clone(&self.initiator),
            responder: Arc::clone(&self.responder),
            selection: Arc::clone(&self.selection),
            peer: PublicKey::from_bytes(&self.peer.to_bytes())?,
            digest: self.digest,
            storage: self.storage,
            retained: Some(SessionAuthority {
                journal,
                session,
                role,
                identities,
            }),
        })
    }
    // Only the owning journal may mint a fresh credential-to-original-storage
    // binding. This records structural scope, not cached permission: every new
    // operation must reauthorize the exact current credential and root grant.
    pub(crate) fn with_current_storage(
        &self,
        journal: [u8; 32],
        role: BootstrapRole,
        owner: [u8; 32],
    ) -> Result<Self, Error> {
        if self.retained.is_some() {
            return Err(Error::Scope);
        }
        self.check_storage_binding(journal, owner, Some(role))?;
        Ok(Self {
            policy: Arc::clone(&self.policy),
            initiator: Arc::clone(&self.initiator),
            responder: Arc::clone(&self.responder),
            selection: Arc::clone(&self.selection),
            peer: PublicKey::from_bytes(&self.peer.to_bytes())?,
            digest: self.digest,
            retained: None,
            storage: Some(StorageBinding {
                journal,
                role,
                owner,
            }),
        })
    }
    pub(crate) fn storage_binding(&self) -> Option<([u8; 32], BootstrapRole, [u8; 32])> {
        self.storage.map(|v| (v.journal, v.role, v.owner))
    }
    pub(crate) fn check_storage_binding(
        &self,
        journal: [u8; 32],
        owner: [u8; 32],
        role: Option<BootstrapRole>,
    ) -> Result<(), Error> {
        if let Some(binding) = self.storage {
            if binding.journal != journal
                || binding.owner != owner
                || role.is_some_and(|role| role != binding.role)
            {
                return Err(Error::Scope);
            }
        }
        Ok(())
    }
    pub(crate) fn check_journal_role(
        &self,
        journal: [u8; 32],
        owner: [u8; 32],
        role: BootstrapRole,
    ) -> Result<(), Error> {
        self.check_storage_binding(journal, owner, Some(role))?;
        if self
            .retained
            .as_ref()
            .is_some_and(|v| v.journal != journal || v.role != role)
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn role_storage_owner(&self, role: BootstrapRole) -> [u8; 32] {
        if self.retained.as_ref().is_some_and(|v| v.role == role) {
            if let Some(identity) = self.renewed_identity(role) {
                return identity.owner;
            }
        }
        if let Some(binding) = self.storage.filter(|v| v.role == role) {
            return binding.owner;
        }
        storage_owner(self.device(role))
    }
    pub(crate) fn require_fresh_identity(&self, now: u64) -> Result<(), Error> {
        if self.retained.is_some() {
            return Err(Error::Scope);
        }
        self.check_session_identity(now)
    }
    pub(crate) fn retained_binding(&self) -> Option<([u8; 32], [u8; 32], BootstrapRole)> {
        self.retained
            .as_ref()
            .map(|v| (v.journal, v.session, v.role))
    }
    pub(crate) fn renewed_identity(&self, role: BootstrapRole) -> Option<&ResolvedSessionIdentity> {
        self.retained.as_ref().and_then(|v| {
            let [initiator, responder] = &v.identities;
            match role {
                BootstrapRole::Initiator => initiator.as_ref(),
                BootstrapRole::Responder => responder.as_ref(),
            }
        })
    }
    pub(crate) fn session_device(&self, role: BootstrapRole) -> &VerifiedDevice {
        self.renewed_identity(role)
            .map_or_else(|| self.device(role), |v| v.device.as_ref())
    }
}
