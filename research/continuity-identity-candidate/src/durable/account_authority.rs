// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original authority-registry admission at the encrypted journal boundary.
use super::*;
use crate::{AccountAuthorityAccess, AccountAuthorityCheckpoint, ApplicationAccountId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Scope {
    registry: [u8; 32],
    local: AccountAuthorityCheckpoint,
}
impl Scope {
    pub(super) fn check_shape(self, image: &Image) -> Result<(), DurableError> {
        if self.local.account() != image.local_account || image.protection == Protection::Local {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.registry);
        bytes.extend_from_slice(self.local.application().as_bytes());
        bytes.extend_from_slice(&self.local.revision().to_be_bytes());
        bytes.extend_from_slice(&self.local.account());
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let registry = d.array()?;
        crate::codec::nonzero(&registry)?;
        let application = ApplicationAccountId::from_trusted_state(d.array()?)?;
        let local =
            AccountAuthorityCheckpoint::from_trusted_state(application, d.u64()?, d.array()?)?;
        Ok(Self { registry, local })
    }
}

/// Original registry and application revision selected for one witnessed journal.
/// Cloning this public admission descriptor cannot extend its parent's lifetime.
#[derive(Clone)]
pub struct JournalAccountAuthority {
    scope: Scope,
    access: AccountAuthorityAccess,
}
impl JournalAccountAuthority {
    pub(crate) fn check_enrollment(
        &self,
        account: [u8; 32],
        family: [u8; 32],
    ) -> Result<(), DurableError> {
        if self.scope.local.account() != account || self.access.scope().0 != family {
            return Err(DurableError::Conflict);
        }
        self.access.check_accounts(self.scope.local, &[])
    }
    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        self.scope == other.scope
    }
    /// Bind an independently retained checkpoint to its live original registry.
    pub fn new(
        access: AccountAuthorityAccess,
        local: AccountAuthorityCheckpoint,
    ) -> Result<Self, DurableError> {
        access.check_accounts(local, &[])?;
        Ok(Self {
            scope: Scope {
                registry: access.binding(),
                local,
            },
            access,
        })
    }
    fn check(&self, image: &Image) -> Result<(), DurableError> {
        let Protection::Required { witness, .. } = image.protection else {
            return Err(DurableError::AnchorRequired);
        };
        let (_, pinned_witness) = self.access.scope();
        if self.scope.registry != self.access.binding()
            || self.scope.local.account() != image.local_account
            || witness != pinned_witness
        {
            return Err(DurableError::Conflict);
        }
        self.access.check_accounts(self.scope.local, &[])
    }
    // Family is authenticated once when adopting/opening this original binding.
    // Release checks reuse that fixed registry scope and do not re-parse a signed
    // roster merely to read its family. Ordinary per-operation roster checks remain.
    fn check_original_scope(&self, image: &Image) -> Result<(), DurableError> {
        self.check(image)?;
        if rosters::current(image, &image.local_account)?
            .continuation_authority()
            .1
            != self.access.scope().0
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}

impl Image {
    pub(super) fn check_account_authorities(
        &self,
        accounts: &[[u8; 32]],
    ) -> Result<(), DurableError> {
        match (self.account_authority, self.authority_access.as_ref()) {
            (None, None) => Ok(()),
            (Some(scope), Some(access)) if scope.registry == access.binding() => {
                access.check_accounts(scope.local, accounts)
            }
            _ => Err(DurableError::Conflict),
        }
    }
    pub(super) fn check_context_authorities(
        &self,
        context: &BootstrapContext,
    ) -> Result<(), DurableError> {
        self.check_account_authorities(&context.devices().map(VerifiedDevice::account_id))
    }
}

impl Active {
    pub(super) fn check_account_authority(&self, image: &Image) -> Result<(), DurableError> {
        match (image.account_authority, self.account_authority.as_ref()) {
            (None, None) => Ok(()),
            (Some(scope), Some(authority)) if scope == authority.scope => authority.check(image),
            _ => Err(DurableError::Conflict),
        }
    }
    pub(super) fn attach_account_authority(&self, image: &mut Image) -> Result<(), DurableError> {
        self.check_account_authority(image)?;
        image.authority_access = self.account_authority.as_ref().map(|a| a.access.clone());
        Ok(())
    }
}

fn retained_scope(
    image: &Image,
    pending: Option<&write_intent::PendingWrite>,
    key: &JournalKey,
) -> Result<Option<Scope>, DurableError> {
    let target = pending
        .map(|p| p.authenticated_target(key, image.owner))
        .transpose()?;
    let target_scope = target.as_ref().map(|i| i.account_authority);
    if let (Some(original), Some(next)) = (image.account_authority, target_scope) {
        if next != Some(original) {
            return Err(DurableError::Conflict);
        }
    }
    Ok(target_scope.flatten().or(image.account_authority))
}
pub(super) fn admit_reopen(
    image: &Image,
    pending: Option<&write_intent::PendingWrite>,
    key: &JournalKey,
    authority: Option<&JournalAccountAuthority>,
) -> Result<(), DurableError> {
    let required = retained_scope(image, pending, key)?;
    match (required, authority) {
        (None, None) => Ok(()),
        (Some(scope), Some(authority)) if scope == authority.scope => {
            authority.check_original_scope(image)
        }
        _ => Err(DurableError::Conflict),
    }
}

// A pending initial binding is allowed only inside the owning installation
// activation. The caller must commit adopt_account_authority before release.
pub(crate) enum AccountAuthorityOpen {
    Existing(Option<JournalAccountAuthority>),
    Bind(JournalAccountAuthority),
}
impl AccountAuthorityOpen {
    pub(super) fn admit(
        self,
        image: &Image,
        pending: Option<&write_intent::PendingWrite>,
        key: &JournalKey,
    ) -> Result<Option<JournalAccountAuthority>, DurableError> {
        match self {
            Self::Existing(authority) => {
                admit_reopen(image, pending, key, authority.as_ref())?;
                Ok(authority)
            }
            Self::Bind(authority) => {
                if retained_scope(image, pending, key)?.is_some() {
                    admit_reopen(image, pending, key, Some(&authority))?;
                    Ok(Some(authority))
                } else {
                    authority.check_original_scope(image)?;
                    Ok(None)
                }
            }
        }
    }
}

impl DeviceJournal {
    /// Persist the original registry binding through the existing witnessed image
    /// transaction. The registry must independently associate local and peer roots.
    /// A failure can follow commit; retain this exact descriptor and journal identity.
    /// Already bound journals accept only the original descriptor, with fresh admission.
    pub fn adopt_account_authority(
        &mut self,
        authority: JournalAccountAuthority,
    ) -> Result<(), DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            authority.check_original_scope(&image)?;
            if let Some(scope) = image.account_authority {
                if scope != authority.scope {
                    return Err(DurableError::Conflict);
                }
                return self.check_release(&image);
            }
            image.account_authority = Some(authority.scope);
            image.authority_access = Some(authority.access.clone());
            self.active
                .as_mut()
                .ok_or(DurableError::Closed)?
                .account_authority = Some(authority);
            self.persist(&mut image)?;
            self.check_release(&image)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Reopen only a journal already bound to this original registry, or reconcile
    /// its original pending adoption. Missing or different binding is a conflict;
    /// this never silently adopts an unbound image or provisions missing storage.
    pub fn open_anchored_with_account_authority(
        path: &Path,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &crate::VerifiedSessionPolicy,
        expected_id: JournalIdentity,
        client: crate::AnchorClient,
        authority: JournalAccountAuthority,
    ) -> Result<Self, DurableError> {
        Self::open_anchored_admitted(
            path,
            key,
            device,
            policy.historical(),
            expected_id,
            client,
            AccountAuthorityOpen::Existing(Some(authority)),
        )
    }
}
