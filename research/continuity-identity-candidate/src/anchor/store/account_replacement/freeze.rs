// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently authorized preparation fence, distinct from account retirement.
use super::*;
mod codec;
mod plan;
mod receipt;
pub(in crate::anchor::store) use codec::{decode_records, encode_records};
pub use plan::AnchorAccountReplacementPlan;

/// Original independently approved freeze operation; public correlation, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorAccountFreezeId([u8; 32]);
impl AnchorAccountFreezeId {
    /// Generate once and retain before invoking the trusted control plane.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Recover the exact independently retained original operation.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Stable public identifier, not a proof of commitment.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Approval to stop this account namespace at its then-current witness state.
/// Retain this exact request before calling the independently authenticated control
/// plane. Parsing or an old-root signature does not authorize that call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorAccountFreezeRequest {
    witness: [u8; 32],
    operation: AnchorAccountFreezeId,
    root: PublicKey,
}
impl AnchorAccountFreezeRequest {
    /// Bind independently retained account and witness authority to this operation.
    pub fn from_trusted_state(
        operation: AnchorAccountFreezeId,
        root: PublicKey,
        pin: &AnchorPin,
    ) -> Result<Self, Error> {
        let request = Self {
            witness: pin.binding,
            operation,
            root,
        };
        request.check_pin(pin)?;
        Ok(request)
    }
    /// Exact original operation, independent of a later replacement approval.
    pub fn operation(&self) -> AnchorAccountFreezeId {
        self.operation
    }
    /// Cryptographic account namespace blocked by this request.
    pub fn account(&self) -> [u8; 32] {
        crate::identity::account_id(&self.root)
    }
    fn check_pin(&self, pin: &AnchorPin) -> Result<(), Error> {
        if self.witness != pin.binding || self.root.shares_component(&pin.key) {
            return Err(Error::Scope);
        }
        Ok(())
    }
}

/// Authenticated historical preparation snapshot. This is neither a retirement
/// decision, a live reply nor successor authority. Delayed pre-freeze replies may
/// still arrive; independently retained local authority fences remain necessary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorFrozenAccount {
    request: AnchorAccountFreezeRequest,
    subjects: Vec<AnchorRetiredAccountSubject>,
}
impl AnchorFrozenAccount {
    /// Original independently retained request, never an implicit substitute.
    pub fn request(&self) -> &AnchorAccountFreezeRequest {
        &self.request
    }
    /// All known subjects in the frozen namespace, including retired generations.
    pub fn subjects(&self) -> impl Iterator<Item = AnchorRetiredAccountSubject> + '_ {
        self.subjects.iter().copied()
    }
    /// Commitment to the exact request and original complete witness snapshot.
    pub fn binding(&self) -> Result<[u8; 32], Error> {
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-ACCOUNT-FREEZE/v1",
            &self.to_bytes()?,
        ))
    }
    fn check_shape(&self) -> Result<(), Error> {
        nonzero(&self.request.witness)?;
        if self.subjects.len() > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        let mut last = None;
        for entry in &self.subjects {
            nonzero(&entry.subject.journal)?;
            nonzero(&entry.subject.owner)?;
            nonzero(&entry.subject.policy)?;
            nonzero(&entry.state)?;
            let bytes = entry.subject.to_bytes();
            if last.is_some_and(|old| old >= bytes) {
                return Err(Error::Scope);
            }
            last = Some(bytes);
        }
        Ok(())
    }
}
impl Image {
    pub(in crate::anchor::store) fn subject_frozen(&self, subject: AnchorSubject) -> bool {
        if self.account_freezes.is_empty() {
            return false;
        }
        self.entries
            .values()
            .find(|entry| entry.subject == subject)
            .and_then(|entry| entry.original_identity.as_ref())
            .is_some_and(|identity| self.account_freezes.contains_key(&identity.account))
    }
    pub(in crate::anchor::store) fn check_account_freezes(
        &self,
        pin: &AnchorPin,
    ) -> Result<(), DurableError> {
        if self.account_freezes.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        let mut operations = BTreeSet::new();
        for (account, frozen) in &self.account_freezes {
            frozen.check_shape()?;
            frozen.request.check_pin(pin)?;
            if *account != frozen.request.account()
                || !operations.insert(frozen.request.operation.0)
                || self.account_snapshot(*account, pin)? != frozen.subjects
            {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
    pub(super) fn check_preparation(
        &self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<(), DurableError> {
        match (
            self.account_freezes.get(&p.previous_account()),
            p.preparation,
        ) {
            (None, None) => Ok(()),
            (Some(frozen), Some(binding))
                if binding == frozen.binding()?
                    && p.previous_root == frozen.request.root
                    && p.frozen == frozen.subjects =>
            {
                Ok(())
            }
            _ => Err(DurableError::Conflict),
        }
    }
}
impl AnchorStore {
    /// Atomically capture and freeze an independently authorized account namespace.
    /// No successor is enrolled. Known and future unseen devices are blocked.
    ///
    /// The caller must independently authenticate recovery authority; possession of
    /// the previous root is insufficient. Retain the original request before call.
    /// Errors can follow commit: reopen the original store and retry that request.
    /// Exact retries return the original snapshot, including after retirement.
    pub fn freeze_account(
        &mut self,
        request: &AnchorAccountFreezeRequest,
    ) -> Result<AnchorFrozenAccount, DurableError> {
        let pin = self.pin()?;
        request.check_pin(&pin)?;
        let mut image = self.image()?;
        if let Some(saved) = image.account_freezes.get(&request.account()) {
            return if saved.request == *request {
                Ok(saved.clone())
            } else {
                Err(DurableError::Conflict)
            };
        }
        image.require_account_live(request.account())?;
        if image
            .account_freezes
            .values()
            .any(|saved| saved.request.operation == request.operation)
        {
            return Err(DurableError::Conflict);
        }
        if image.account_freezes.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        let frozen = AnchorFrozenAccount {
            request: request.clone(),
            subjects: image.account_snapshot(request.account(), &pin)?,
        };
        image
            .account_freezes
            .insert(request.account(), frozen.clone());
        self.persist(&mut image)?;
        Ok(frozen)
    }
    /// Recover only this exact original historical snapshot. Absence does not prove
    /// non-commit and grants no permission to reset or resume old-account traffic.
    pub fn account_freeze(
        &mut self,
        request: &AnchorAccountFreezeRequest,
    ) -> Result<AnchorFrozenAccount, DurableError> {
        request.check_pin(&self.pin()?)?;
        let image = self.image()?;
        match image.account_freezes.get(&request.account()) {
            Some(saved) if saved.request == *request => Ok(saved.clone()),
            Some(_) => Err(DurableError::Conflict),
            None if image
                .account_freezes
                .values()
                .any(|saved| saved.request.operation == request.operation) =>
            {
                Err(DurableError::Conflict)
            }
            None => Err(DurableError::Absent),
        }
    }
    /// Prepare an independently approved target against the exact durable freeze.
    /// This read-only descriptor does not commit the replacement or release an owner.
    pub fn frozen_account_replacement_proposal(
        &mut self,
        operation: AnchorAccountReplacementId,
        frozen: &AnchorFrozenAccount,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorAccountReplacementProposal, DurableError> {
        if self.account_freeze(&frozen.request)? != *frozen {
            return Err(DurableError::Conflict);
        }
        self.proposal_for_account(
            operation,
            (&frozen.request.root, Some(frozen.binding()?)),
            genesis,
            next,
            policy,
            now,
        )
    }
}
