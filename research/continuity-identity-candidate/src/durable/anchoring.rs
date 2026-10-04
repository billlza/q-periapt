// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh witness admission at the real encrypted journal transaction boundary.
use super::*;
use crate::{
    AnchorClient, AnchorClientError, AnchorHead, AnchorOperation, AnchorOutcome, AnchorSubject,
    VerifiedSessionPolicy,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Protection {
    Local,
    Required {
        policy: [u8; 32],
        witness: [u8; 32],
        fence: u64,
    },
}
impl Protection {
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        match self {
            Self::Local => bytes.extend_from_slice(&[0; 73]),
            Self::Required {
                policy,
                witness,
                fence,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&policy);
                bytes.extend_from_slice(&witness);
                bytes.extend_from_slice(&fence.to_be_bytes());
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let [mode] = d.array()?;
        let policy = d.array()?;
        let witness = d.array()?;
        let fence = d.u64()?;
        match mode {
            0 if policy == [0; 32] && witness == [0; 32] && fence == 0 => Ok(Self::Local),
            1 if policy != [0; 32] && witness != [0; 32] && fence != 0 && fence != u64::MAX => {
                Ok(Self::Required {
                    policy,
                    witness,
                    fence,
                })
            }
            _ => Err(DurableError::Corrupt),
        }
    }
    pub(super) fn check_policy(self, policy: &VerifiedSessionPolicy) -> Result<(), DurableError> {
        match (self, policy.anchor_requirement().binding()) {
            (Self::Local, None) => Ok(()),
            (
                Self::Required {
                    policy: saved,
                    witness,
                    ..
                },
                Some(binding),
            ) if saved == policy.checkpoint().digest() && witness == binding => Ok(()),
            (Self::Local, Some(_)) => Err(DurableError::AnchorRequired),
            _ => Err(DurableError::Conflict),
        }
    }
    fn head(self, revision: u64, digest: [u8; 32]) -> Result<AnchorHead, DurableError> {
        let Self::Required { fence, .. } = self else {
            return Err(DurableError::AnchorRequired);
        };
        Ok(AnchorHead::from_trusted_state(fence, revision, digest)?)
    }
}

pub(super) struct AttachedAnchor {
    client: AnchorClient,
    subject: AnchorSubject,
}
pub(super) fn cleanup_signer_binding(key: &crate::PublicKey) -> [u8; 32] {
    digest(
        b"Q-PERIAPT-CONTINUITY-ARCHIVED-CLOSURE-SIGNER/v1",
        &key.encode(),
    )
}
impl Active {
    // Only an authenticated local archive may supply this original signer binding.
    // This attaches the unchanged witness subject, not renewed session authority.
    pub(super) fn attach_closure_archive(
        &mut self,
        client: AnchorClient,
        signer: [u8; 32],
    ) -> Result<(), DurableError> {
        if signer != cleanup_signer_binding(&client.signer_public_key()?) {
            return Err(DurableError::Conflict);
        }
        self.attach_retained_cleanup_subject(client)
    }
    // The pinned witness authenticates the original enrolled signing owner.
    // This path can only attach to a subject from an already authenticated image.
    pub(super) fn attach_retained_cleanup_subject(
        &mut self,
        client: AnchorClient,
    ) -> Result<(), DurableError> {
        let Protection::Required {
            policy, witness, ..
        } = self.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        if witness != client.pin().binding() {
            return Err(DurableError::Conflict);
        }
        let mut bytes = self.id.to_vec();
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&policy);
        let subject = AnchorSubject::from_trusted_state(&bytes)?;
        self.anchor = Some(AttachedAnchor { client, subject });
        Ok(())
    }

    fn attach(
        &mut self,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        client: AnchorClient,
    ) -> Result<(), DurableError> {
        self.protection.check_policy(policy)?;
        let Protection::Required { witness, .. } = self.protection else {
            return Err(DurableError::AnchorRequired);
        };
        if witness != client.pin().binding() || self.owner != bootstrap::storage_owner(device) {
            return Err(DurableError::Conflict);
        }
        client.check_device(device)?;
        policy.check_external_signer(client.pin().public_key())?;
        if client
            .pin()
            .public_key()
            .shares_component(&device.authority_key)
        {
            return Err(Error::Scope.into());
        }
        let subject = AnchorSubject::for_device(JournalIdentity(self.id), device, policy)?;
        self.anchor = Some(AttachedAnchor { client, subject });
        Ok(())
    }
    pub(super) fn check_current(&mut self, image: &Image) -> Result<(), DurableError> {
        if self.protection == Protection::Local {
            return Ok(());
        }
        let expected = self.protection.head(image.revision, image.digest)?;
        let anchor = self.anchor.as_mut().ok_or(DurableError::AnchorRequired)?;
        let reply = anchor
            .client
            .exchange(anchor.subject, AnchorOperation::query())?;
        if reply.outcome() != AnchorOutcome::Current || reply.observed_head() != expected {
            return Err(AnchorClientError::Conflict.into());
        }
        Ok(())
    }
    pub(super) fn advance_anchor(
        &mut self,
        revision: u64,
        digest: [u8; 32],
        next_digest: [u8; 32],
    ) -> Result<(), DurableError> {
        if self.protection == Protection::Local {
            return Ok(());
        }
        let expected = self.protection.head(revision, digest)?;
        let next = self.protection.head(
            revision.checked_add(1).ok_or(DurableError::Capacity)?,
            next_digest,
        )?;
        let operation = AnchorOperation::advance(expected, next_digest)?;
        let anchor = self.anchor.as_mut().ok_or(DurableError::AnchorRequired)?;
        let reply = anchor.client.exchange(anchor.subject, operation)?;
        // Verification already binds the complete request and exact command ID.
        if !matches!(
            reply.outcome(),
            AnchorOutcome::Advanced | AnchorOutcome::AlreadyAppliedExact
        ) || reply.applied_head()? != next
        {
            return Err(AnchorClientError::Conflict.into());
        }
        Ok(())
    }
}

impl DeviceJournal {
    pub(super) fn check_release(&mut self, image: &Image) -> Result<(), DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .check_current(image);
        if result.is_err() {
            self.close();
        }
        result
    }
    pub(super) fn check_policy(&self, policy: &VerifiedSessionPolicy) -> Result<(), DurableError> {
        self.active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .protection
            .check_policy(policy)
    }
    /// Provision an inactive required-witness journal. Export its genesis for
    /// explicit trusted enrollment, then activate before performing any work.
    /// Durably retain the fresh journal identity before this call, just as for
    /// local provisioning; an unknown creation result never authorizes replacement.
    pub fn provision_anchored(
        path: &Path,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        identity: JournalIdentity,
        now: u64,
    ) -> Result<Self, DurableError> {
        policy.check_device(device, now)?;
        // A disabled/closed policy may be reconciled, but cannot create a new owner.
        let mode = [
            crate::PrekeyQuality::OneTimeBoth,
            crate::PrekeyQuality::ReusableBoth,
            crate::PrekeyQuality::SignedClassicalOneTimePq,
            crate::PrekeyQuality::OneTimeClassicalLastResortPq,
        ]
        .into_iter()
        .find(|mode| policy.allowed_modes().permits(*mode))
        .ok_or(Error::PolicyDenied)?;
        policy.check_mode(mode, now)?;
        let witness = policy
            .anchor_requirement()
            .binding()
            .ok_or(DurableError::AnchorRequired)?;
        let journal = Self::provision_with_protection(
            path,
            key,
            device,
            identity,
            Protection::Required {
                policy: policy.checkpoint().digest(),
                witness,
                fence: 1,
            },
        )?;
        // Publication adds durable I/O after initial admission. A close during
        // that work withholds the new owner but retains its original genesis.
        policy.check_device(device, now)?;
        policy.check_mode(mode, now)?;
        Ok(journal)
    }
    /// Recover only the public enrollment metadata after an unknown creation result.
    /// Requires the independently retained creation identity and exact original
    /// device/policy. This reads an authenticated, empty revision-1 required-witness
    /// image with no pending intent. It never applies a journal transition, returns an operational
    /// journal, or proves enrollment/currentness; enroll this exact genesis explicitly,
    /// then use `open_anchored` with the original witness for fresh admission.
    pub fn recover_anchor_genesis(
        path: &Path,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        expected_id: JournalIdentity,
    ) -> Result<crate::AnchorGenesis, DurableError> {
        let db = open_private_database(path)?;
        let image = load(&db, &key, bootstrap::storage_owner(device))?;
        let witness = policy
            .anchor_requirement()
            .binding()
            .ok_or(DurableError::AnchorRequired)?;
        if image.id != expected_id.0
            || image.local_account != device.account_id()
            || image.protection
                != (Protection::Required {
                    policy: policy.checkpoint().digest(),
                    witness,
                    fence: 1,
                })
            || image.revision != 1
            || !rosters::is_genesis(&image, device)?
        {
            return Err(DurableError::Conflict);
        }
        Ok(crate::AnchorGenesis::from_journal(
            expected_id,
            device,
            policy,
            image.digest,
        )?)
    }
    /// Activate only the exact enrolled genesis using a fresh authenticated query.
    /// Enrollment and signer provisioning remain explicit independent actions.
    pub fn activate_anchor(
        &mut self,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        client: AnchorClient,
    ) -> Result<(), DurableError> {
        let result = (|| {
            let active = self.active.as_mut().ok_or(DurableError::Closed)?;
            let image = load(&active.db, &active.key, active.owner)?;
            if image.id != active.id
                || image.protection != active.protection
                || image.revision != 1
                || !rosters::is_genesis(&image, device)?
                || active.anchor.is_some()
            {
                return Err(DurableError::Conflict);
            }
            active.attach(device, policy, client)?;
            active.check_current(&image)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    // Enrollment release requires more than a head query: an exact signed
    // observation that the witness has independently adopted this current roster.
    // Cleanup and historical intent reconciliation retain their separate queries.
    pub(crate) fn check_enrollment_authority(
        &mut self,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<(), DurableError> {
        let result = (|| {
            self.check_policy(policy)?;
            policy.check_device(device, now)?;
            let image = self.image()?;
            rosters::authorize_device(&image, device, now)?;
            if rosters::current(&image, &device.account_id())?.checkpoint()
                != device.roster().checkpoint()
            {
                return Err(DurableError::Conflict);
            }
            let active = self.active.as_mut().ok_or(DurableError::Closed)?;
            if active.protection != Protection::Local {
                let expected = active.protection.head(image.revision, image.digest)?;
                let anchor = active.anchor.as_mut().ok_or(DurableError::AnchorRequired)?;
                let reply = anchor.client.exchange(
                    anchor.subject,
                    AnchorOperation::admit_authority(device.authority_binding())?,
                )?;
                if reply.observed_head() != expected {
                    return Err(AnchorClientError::Conflict.into());
                }
                match reply.outcome() {
                    AnchorOutcome::AuthorityCurrent => {}
                    AnchorOutcome::AuthorityDenied => {
                        return Err(AnchorClientError::AuthorityDenied.into())
                    }
                    _ => return Err(Error::State.into()),
                }
            }
            policy.check_device(device, now)?;
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Reconcile only the saved command against the independently pinned witness.
    /// A different head or writer fence never authorizes local recovery or output.
    pub fn open_anchored(
        path: &Path,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        expected_id: JournalIdentity,
        client: AnchorClient,
    ) -> Result<Self, DurableError> {
        let db = open_private_database(path)?;
        let owner = bootstrap::storage_owner(device);
        let (image, pending) = write_intent::load_snapshot(&db, &key, owner)?;
        if image.id != expected_id.0 || image.local_account != device.account_id() {
            return Err(DurableError::Conflict);
        }
        let mut active = Active {
            db,
            key,
            owner,
            id: image.id,
            protection: image.protection,
            anchor: None,
        };
        active.attach(device, policy, client)?;
        if let Some(pending) = pending {
            write_intent::reconcile(&mut active, &pending)?;
        }
        let current = load(&active.db, &active.key, owner)?;
        active.check_current(&current)?;
        Ok(Self {
            active: Some(active),
        })
    }
}

#[cfg(all(test, unix))]
mod tests;
