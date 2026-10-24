// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Separate account/policy approval of witness substitution for an original
//! journal. Approval is neither durable client adoption nor a traffic lease.
use super::*;
use crate::{AnchorHandoffActivationReceipt, AnchorHandoffHistory, AnchorSubject, RootSigningKey};

mod wire;
pub(crate) use wire::activation_digest;
use wire::{read_pair, verify_pair, BODY_BYTES};

/// Identity of one independently approved witness-adoption operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorHandoffAdoptionId([u8; 32]);
impl AnchorHandoffAdoptionId {
    /// Generate and retain once before requesting either issuer's approval.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Restore an original locally retained operation, never incoming authority.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public operation correlation, not a commit or adoption receipt.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact imported client state to which both issuers must bind their decision.
/// The target derives this from its authenticated complete original image.
/// A caller must independently retain and compare the expected scope; parsing
/// an incoming approval cannot select an expected scope or trusted roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorHandoffAdoptionScope {
    pub(crate) operation: AnchorHandoffAdoptionId,
    pub(crate) subject: AnchorSubject,
    pub(crate) namespace: [u8; 32],
    pub(crate) predecessor: [u8; 32],
    pub(crate) successor: [u8; 32],
    pub(crate) history: [u8; 32],
    pub(crate) activation: [u8; 32],
    pub(crate) entry: [u8; 32],
    pub(crate) credential_owner: [u8; 32],
    pub(crate) authority: [u8; 32],
    pub(crate) family: [u8; 32],
    pub(crate) policy: PolicyCheckpoint,
    pub(crate) validity: Validity,
}
impl AnchorHandoffAdoptionScope {
    /// Exact original adoption operation.
    pub fn operation(&self) -> AnchorHandoffAdoptionId {
        self.operation
    }
    /// Immutable original journal/device/policy subject.
    pub fn subject(&self) -> AnchorSubject {
        self.subject
    }
    /// Full retained entry commitment, including original pending G/P/R and ACKs.
    pub fn inherited_entry_digest(&self) -> [u8; 32] {
        self.entry
    }
    /// Independently verified target history, not permission to replace it later.
    pub fn history_checkpoint(&self) -> [u8; 32] {
        self.history
    }
    /// Admission window for a new adoption decision, not credential extension.
    pub fn validity(&self) -> Validity {
        self.validity
    }
    /// Canonical public scope for authenticated local retention.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode()
    }
    /// Restore the exact locally retained expected scope. This does not verify
    /// signatures, source history, imported state, issuer consent or current time.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes)
    }
    /// Commitment to the complete statement that both issuers must approve.
    pub fn statement_digest(&self) -> [u8; 32] {
        digest(b"Q-PERIAPT-WITNESS-ADOPTION-STATEMENT/v1", &self.encode())
    }
}

/// Independently authenticated identity, policy and exact transfer evidence.
/// Historical metadata may have expired: substituting a witness does not renew
/// it, override revocation or confer current runtime authority.
pub struct AnchorHandoffAdoptionMaterials<'a> {
    /// Original signed device identity and storage owner.
    pub original_device: &'a VerifiedDevice,
    /// Exact imported current credential and roster, including an applied G/R.
    pub current_device: &'a VerifiedDevice,
    /// Original signed policy and independent policy-issuer key.
    pub original_policy: &'a HistoricalSessionPolicy,
    /// Exact imported policy checkpoint, including an applied P.
    pub current_policy: &'a HistoricalSessionPolicy,
    /// Complete history verified from independent origin/current pins/checkpoint.
    pub history: &'a AnchorHandoffHistory,
    /// Exact verified target activation for this history.
    pub activation: &'a AnchorHandoffActivationReceipt,
}

pub(crate) fn check_materials(
    s: &AnchorHandoffAdoptionScope,
    m: &AnchorHandoffAdoptionMaterials<'_>,
) -> Result<(), Error> {
    AnchorHandoffAdoptionScope::decode(&s.encode())?;
    // Preserve same-pin renewal. This dedicated statement changes only witness
    // authority; it must not silently change any other signed policy property.
    continuation::same_profile(m.original_policy, m.current_policy)?;
    let original = m.original_device;
    let current = m.current_device;
    let journal = crate::JournalIdentity::from_trusted_state(s.subject.journal_parts().0)?;
    if s.subject != AnchorSubject::for_device(journal, original, m.original_policy)?
        || s.namespace != m.history.namespace_binding()
        || s.history != m.history.checkpoint()
        || s.successor != m.history.current_pin().binding()
        || s.predecessor == s.successor
        || s.history != m.activation.history_checkpoint()
        || s.activation != activation_digest(m.activation.as_bytes())
        || s.family != m.original_policy.family()
        || s.policy != m.current_policy.checkpoint()
        || s.credential_owner != crate::bootstrap::storage_owner(current)
        || s.authority != current.authority_binding()
        || original.authority_key != current.authority_key
        || original.account != current.account
        || original.key != current.key
        || original.description.id != current.description.id
        || original.description.generation != current.description.generation
        || original.description.family != s.family
        || current.description.family != s.family
        || original.description.validity.from() != current.description.validity.from()
        || original.description.validity.until() > current.description.validity.until()
        || m.current_policy.checkpoint().version() < m.original_policy.checkpoint().version()
        || (m.current_policy.checkpoint().version() == m.original_policy.checkpoint().version()
            && m.current_policy.checkpoint() != m.original_policy.checkpoint())
        || m.current_policy.validity().until() < m.original_policy.validity().until()
    {
        return Err(Error::Scope);
    }
    let logical = m
        .original_policy
        .anchor_requirement()
        .binding()
        .ok_or(Error::Scope)?;
    for binding in [logical, s.predecessor, s.successor] {
        let pin = m.history.historical_pin(binding)?;
        if pin.public_key().shares_component(&current.key)
            || pin.public_key().shares_component(&current.authority_key)
        {
            return Err(Error::Scope);
        }
        m.original_policy.check_external_signer(pin.public_key())?;
    }
    m.original_policy.check_external_signer(&current.key)?;
    m.original_policy
        .check_external_signer(&current.authority_key)?;
    Ok(())
}

/// Signable two-root decision. The issuer must additionally authenticate the
/// user, serialize current authorization and deduplicate this exact operation.
pub struct AnchorHandoffAdoptionStatement {
    scope: AnchorHandoffAdoptionScope,
    account: PublicKey,
    policy: PublicKey,
}
impl AnchorHandoffAdoptionStatement {
    /// Check independent materials and the new decision's admission interval.
    /// No witness/client state is changed and no current traffic is authorized.
    pub fn new(
        scope: &AnchorHandoffAdoptionScope,
        m: &AnchorHandoffAdoptionMaterials<'_>,
        now: u64,
    ) -> Result<Self, Error> {
        check_materials(scope, m)?;
        scope.validity.check(now)?;
        Ok(Self {
            scope: scope.clone(),
            account: m.current_device.authority_key.clone(),
            policy: m.original_policy.signer.clone(),
        })
    }
    /// Canonical statement commitment for issuer review and deduplication.
    pub fn digest(&self) -> [u8; 32] {
        self.scope.statement_digest()
    }
}

/// One issuer's bounded original signature. Parsing alone grants no authority.
pub struct AnchorHandoffAdoptionApproval {
    wire: Vec<u8>,
}
impl AnchorHandoffAdoptionApproval {
    /// Parse exact grammar, retaining original bytes without authenticating them.
    pub fn from_bytes(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() != wire::APPROVAL_BYTES {
            return Err(Error::Encoding);
        }
        let (body, _) = open_envelope(wire)?;
        AnchorHandoffAdoptionScope::decode(body)?;
        Ok(Self {
            wire: wire.to_vec(),
        })
    }
    /// Exact approval bytes; retry these without re-signing the operation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
}
impl RootSigningKey {
    /// Approve witness substitution as the independently pinned account root.
    pub fn approve_anchor_handoff_adoption(
        &self,
        statement: &AnchorHandoffAdoptionStatement,
    ) -> Result<AnchorHandoffAdoptionApproval, Error> {
        if self.public_key()? != statement.account {
            return Err(Error::Scope);
        }
        let body = statement.scope.encode();
        AnchorHandoffAdoptionApproval::from_bytes(&envelope(
            &body,
            &self.sign(Purpose::AnchorHandoffAdoption, &body)?,
        )?)
    }
}
impl PolicySigningKey {
    /// Separately approve the same substitution as the original policy root.
    pub fn approve_anchor_handoff_adoption(
        &self,
        statement: &AnchorHandoffAdoptionStatement,
    ) -> Result<AnchorHandoffAdoptionApproval, Error> {
        if self.public_key()? != statement.policy {
            return Err(Error::Scope);
        }
        let body = statement.scope.encode();
        AnchorHandoffAdoptionApproval::from_bytes(&envelope(
            &body,
            &self.sign(Purpose::AnchorHandoffAdoption, &body)?,
        )?)
    }
}

/// Exact dual-approved historical decision. It proves neither durable adoption
/// nor current permission; it cannot construct an operating witness client.
#[derive(Clone)]
pub struct HistoricalAnchorHandoffAdoption {
    scope: AnchorHandoffAdoptionScope,
    wire: Vec<u8>,
}
impl HistoricalAnchorHandoffAdoption {
    /// Verify both issuers against independently retained expected scope/materials.
    pub fn from_bytes(
        wire: &[u8],
        expected: &AnchorHandoffAdoptionScope,
        m: &AnchorHandoffAdoptionMaterials<'_>,
    ) -> Result<Self, Error> {
        check_materials(expected, m)?;
        let (account, policy) = read_pair(wire)?;
        verify_pair(
            &account,
            &policy,
            expected,
            &m.current_device.authority_key,
            &m.original_policy.signer,
        )?;
        Ok(Self {
            scope: expected.clone(),
            wire: wire.to_vec(),
        })
    }
    /// Assemble and authenticate two original approvals without changing state.
    pub fn from_approvals(
        account: &AnchorHandoffAdoptionApproval,
        policy: &AnchorHandoffAdoptionApproval,
        expected: &AnchorHandoffAdoptionScope,
        m: &AnchorHandoffAdoptionMaterials<'_>,
    ) -> Result<Self, Error> {
        Self::from_bytes(&wire::pair(account, policy)?, expected, m)
    }
    /// Complete signed scope for the future durable adoption compare-and-set.
    pub fn scope(&self) -> &AnchorHandoffAdoptionScope {
        &self.scope
    }
    /// Exact signatures for retention and historical reconciliation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Recheck only the new-decision window. This is not a store commit, a
    /// credential/policy admission or a substitute for either issuer's decision.
    pub fn check_admission(&self, now: u64) -> Result<(), Error> {
        self.scope.validity.check(now)
    }
}

/// Exact bounded container of the two witness-substitution approvals.
pub const MAX_ANCHOR_HANDOFF_ADOPTION_BYTES: usize =
    8 + 2 * (2 + 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES);
