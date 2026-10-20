// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One bounded, semantic companion-grant set retained by original enrollment.
use super::*;
use std::collections::BTreeMap;

const MAX_COMPANIONS: usize = crate::identity::MAX_DEVICES - 1;
pub(in crate::enrollment) const MAX_ACCOUNT_IMAGE: usize =
    MAX_PREINSTALLATION_IMAGE + MAX_COMPANIONS * (crate::MAX_CREDENTIAL_RENEWAL_BYTES + 4) + 140;

#[derive(Clone)]
pub(in crate::enrollment) struct AccountRenewal {
    operation: CredentialRenewalId,
    statement: [u8; 32],
    binding: [u8; 32],
    peers: Vec<Vec<u8>>,
}

impl AccountRenewal {
    pub(super) fn new(
        local: &VerifiedCredentialRenewal,
        peers: &[&VerifiedCredentialRenewal],
    ) -> Result<Self, DurableError> {
        if peers.is_empty() || peers.len() > MAX_COMPANIONS {
            return Err(DurableError::Capacity);
        }
        let previous = local.previous_device().roster();
        let target = local.successor_device().roster();
        let local_id = local.successor_device().device_id();
        let mut selected = BTreeMap::new();
        selected.insert(local_id, local);
        for peer in peers {
            if peer.policy_digest() != local.policy_digest()
                || !previous.same_authority(peer.previous_device().roster())
                || previous.checkpoint() != peer.previous_device().roster().checkpoint()
                || target.checkpoint() != peer.successor_device().roster().checkpoint()
                || selected
                    .insert(peer.successor_device().device_id(), *peer)
                    .is_some()
            {
                return Err(DurableError::Conflict);
            }
        }
        // The signed predecessor can detect omitted same-generation changes.
        // Durable admission additionally checks the complete retained history,
        // including revocations older than this predecessor.
        for (id, generation, certificate) in target.members() {
            if let Some((_, old_generation, old_certificate)) =
                previous.members().find(|(old, _, _)| *old == id)
            {
                if generation < old_generation
                    || (generation == old_generation
                        && certificate != old_certificate
                        && !selected.get(&id).is_some_and(|grant| {
                            grant.previous_device().credential_digest() == old_certificate
                                && grant.successor_device().credential_digest() == certificate
                        }))
                {
                    return Err(Error::Checkpoint.into());
                }
            }
        }
        let binding = local
            .companion_binding(peers)?
            .ok_or(DurableError::Conflict)?;
        let mut retained = Vec::with_capacity(peers.len());
        for (id, grant) in selected {
            if id != local_id {
                retained.push(grant.as_bytes().to_vec());
            }
        }
        Ok(Self {
            operation: local.operation(),
            statement: local.statement_digest(),
            binding,
            peers: retained,
        })
    }

    pub(super) fn same_request(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.statement == other.statement
            && self.binding == other.binding
    }

    pub(super) fn verify(
        &self,
        local: &VerifiedCredentialRenewal,
        original: &VerifiedDevice,
    ) -> Result<Vec<VerifiedCredentialRenewal>, DurableError> {
        let peers = self
            .peers
            .iter()
            .map(|wire| VerifiedCredentialRenewal::from_journal(wire, original.roster()))
            .collect::<Result<Vec<_>, _>>()?;
        let references = peers.iter().collect::<Vec<_>>();
        let checked = Self::new(local, &references)?;
        if !self.same_request(&checked) || self.peers != checked.peers {
            return Err(DurableError::Conflict);
        }
        Ok(peers)
    }

    pub(in crate::enrollment) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        if self.peers.is_empty() || self.peers.len() > MAX_COMPANIONS {
            return Err(DurableError::Capacity);
        }
        out.extend_from_slice(self.operation.as_bytes());
        out.extend_from_slice(&self.statement);
        out.extend_from_slice(&self.binding);
        out.extend_from_slice(
            &u16::try_from(self.peers.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        for peer in &self.peers {
            if peer.is_empty() || peer.len() > crate::MAX_CREDENTIAL_RENEWAL_BYTES {
                return Err(DurableError::Capacity);
            }
            out.extend_from_slice(
                &u32::try_from(peer.len())
                    .map_err(|_| DurableError::Capacity)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(peer);
        }
        Ok(())
    }

    pub(in crate::enrollment) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let operation = CredentialRenewalId::from_trusted_state(d.array()?)?;
        let statement = d.array()?;
        let binding = d.array()?;
        crate::codec::nonzero(&statement)?;
        crate::codec::nonzero(&binding)?;
        let count = usize::from(d.u16()?);
        if count == 0 || count > MAX_COMPANIONS {
            return Err(DurableError::Corrupt);
        }
        let mut peers = Vec::with_capacity(count);
        for _ in 0..count {
            let size = u32::from_be_bytes(d.array()?) as usize;
            if size == 0 || size > crate::MAX_CREDENTIAL_RENEWAL_BYTES {
                return Err(DurableError::Corrupt);
            }
            peers.push(d.take(size)?.to_vec());
        }
        Ok(Self {
            operation,
            statement,
            binding,
            peers,
        })
    }
}

impl LocalRenewal {
    pub(in crate::enrollment) fn has_account_extension(&self) -> bool {
        self.account.is_some()
            || self
                .completed
                .as_ref()
                .is_some_and(|c| c.account_binding.is_some())
    }
    pub(in crate::enrollment) fn encode_account(
        &self,
        out: &mut Vec<u8>,
    ) -> Result<(), DurableError> {
        self.check_account_completion()?;
        out.push(u8::from(self.account.is_some()));
        if let Some(account) = &self.account {
            account.encode(out)?;
        }
        let binding = self.completed.as_ref().and_then(|c| c.account_binding);
        out.push(u8::from(binding.is_some()));
        if let Some(binding) = binding {
            out.extend_from_slice(&binding);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn decode_account(
        &mut self,
        d: &mut Decoder<'_>,
    ) -> Result<(), DurableError> {
        match d.array::<1>()? {
            [0] => {}
            [1] => self.retain_account(AccountRenewal::decode(d)?)?,
            _ => return Err(DurableError::Corrupt),
        }
        match d.array::<1>()? {
            [0] => {}
            [1] => {
                let binding = d.array()?;
                crate::codec::nonzero(&binding)?;
                self.completed
                    .as_mut()
                    .ok_or(DurableError::Corrupt)?
                    .account_binding = Some(binding);
            }
            _ => return Err(DurableError::Corrupt),
        }
        if !self.has_account_extension() {
            return Err(DurableError::Corrupt);
        }
        self.check_account_completion()
    }
    fn check_account_completion(&self) -> Result<(), DurableError> {
        if let CredentialRenewalStatus::Committed { operation, .. } = self.status()? {
            let binding = self.completed.as_ref().and_then(|c| c.account_binding);
            if binding
                != self
                    .account
                    .as_ref()
                    .filter(|a| a.operation == operation)
                    .map(|a| a.binding)
            {
                return Err(DurableError::Conflict);
            }
        }
        Ok(())
    }
    pub(in crate::enrollment) fn account(&self) -> Option<&AccountRenewal> {
        self.account.as_ref()
    }
    pub(in crate::enrollment) fn retain_account(
        &mut self,
        account: AccountRenewal,
    ) -> Result<(), DurableError> {
        let operation = match self.status()? {
            CredentialRenewalStatus::Pending { operation, .. }
            | CredentialRenewalStatus::Committed { operation, .. }
            | CredentialRenewalStatus::ExpiredUncommitted { operation, .. }
            | CredentialRenewalStatus::Closed { operation, .. } => operation,
            CredentialRenewalStatus::Absent => return Err(DurableError::Corrupt),
        };
        if operation != account.operation {
            return Err(DurableError::Conflict);
        }
        self.account = Some(account);
        Ok(())
    }
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Stage local renewal and every changed peer credential from the same
    /// account predecessor into one original-enrollment intent. Companions must
    /// exclude the local grant and cover all other same-generation changes.
    /// Input order and semantic re-signing do not replace the first saved bytes.
    /// Activation and required-witness preparation use this retained collection.
    pub async fn stage_account_credential_renewal(
        &mut self,
        grant: &VerifiedCredentialRenewal,
        companions: &[&VerifiedCredentialRenewal],
        operation: CredentialRenewalId,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let account = match AccountRenewal::new(grant, companions) {
            Ok(account) => account,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        self.stage_renewal(
            grant,
            operation,
            policy,
            now,
            RenewalExtensions {
                continuation: None,
                account: Some(&account),
            },
        )
        .await
    }
    pub(in crate::enrollment) fn account_grants(
        &self,
        image: &Image,
        local: &VerifiedCredentialRenewal,
        original: &VerifiedDevice,
    ) -> Result<Vec<VerifiedCredentialRenewal>, DurableError> {
        match image.renewal.as_ref().and_then(LocalRenewal::account) {
            Some(account) => account.verify(local, original),
            None => Ok(Vec::new()),
        }
    }
}
