// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Candidate qperiapt-policy-renewal/1: two-root policy extension without a
//! credential or roster transition. Signatures are not a durable adoption,
//! a witness receipt, a current session lease or fresh-bootstrap permission.
use super::*;
use crate::{JournalIdentity, RootSigningKey, RosterCheckpoint};

const TAG: &[u8; 8] = b"QPPRNW01";
const CONTAINER: &[u8; 8] = b"QPPRNB01";
const DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-RENEWAL-CANDIDATE/v1";
const BODY_BYTES: usize = 8 + 7 * 32 + 40 + 3 * 40 + 33 + 1;
const APPROVAL_BYTES: usize = 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES;
/// Exact bounded two-root policy-only approval container.
pub const MAX_POLICY_RENEWAL_BYTES: usize = 8 + 2 * (2 + APPROVAL_BYTES);

/// Independently retained identity of one policy-only operation, never a G ID.
///
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{CredentialRenewalId, PolicyRenewalId};
/// fn substitute(operation: PolicyRenewalId) {
///     let _: CredentialRenewalId = operation;
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyRenewalId([u8; 32]);
impl PolicyRenewalId {
    /// Generate once and retain before either issuer signs or an intent is saved.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Restore the application's original operation, not incoming authority.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public correlation bytes; these are not a commit receipt.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Independently retained expected state. Incoming approval bytes cannot select
/// these values. A durable coordinator must compare all of them with its state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRenewalScope {
    /// Original policy-only operation to preserve across unknown outcomes.
    pub operation: PolicyRenewalId,
    /// Immutable original journal.
    pub journal: JournalIdentity,
    /// Immutable storage owner derived from the original credential.
    pub original_owner: [u8; 32],
    /// Immutable original credential commitment.
    pub original_credential: [u8; 32],
    /// Exact currently retained credential; this operation must not replace it.
    pub current_credential: [u8; 32],
    /// Exact currently retained roster; this operation must not advance it.
    pub current_roster: RosterCheckpoint,
    /// Original session transcript and storage policy P0.
    pub original_policy: PolicyCheckpoint,
    /// Exact previously adopted policy, or P0 for the first adoption.
    pub previous_policy: PolicyCheckpoint,
    /// Exact previous policy authorization digest, absent only for original P0.
    pub previous_authorization: Option<[u8; 32]>,
}

/// Independently verified inputs, with no credential grant or successor roster.
pub struct PolicyRenewalMaterials<'a> {
    /// Authenticated original P0 metadata; it may have expired.
    pub original: &'a HistoricalSessionPolicy,
    /// Authenticated exact predecessor metadata; it may have expired.
    pub previous: &'a HistoricalSessionPolicy,
    /// Independently pinned live target policy and its actual runtime.
    pub target: &'a VerifiedSessionPolicy,
    /// Authenticated original device, used only for immutable identity binding.
    pub original_device: &'a VerifiedDevice,
    /// Independently pinned current device and roster, unchanged by this renewal.
    pub current_device: &'a VerifiedDevice,
}
impl<'a> PolicyRenewalMaterials<'a> {
    /// Retain signed metadata without conferring current runtime permission.
    pub fn historical(&self) -> HistoricalPolicyRenewalMaterials<'a> {
        HistoricalPolicyRenewalMaterials {
            original: self.original,
            previous: self.previous,
            target: self.target.historical(),
            original_device: self.original_device,
            current_device: self.current_device,
        }
    }
}

/// Signature-verified historical inputs. Device snapshots do not track later
/// revocation, time or roster advancement and cannot authorize new work here.
pub struct HistoricalPolicyRenewalMaterials<'a> {
    /// Original authenticated P0.
    pub original: &'a HistoricalSessionPolicy,
    /// Exact predecessor authenticated policy.
    pub previous: &'a HistoricalSessionPolicy,
    /// Authenticated target metadata, with no current runtime lease.
    pub target: &'a HistoricalSessionPolicy,
    /// Original authenticated device identity.
    pub original_device: &'a VerifiedDevice,
    /// Authenticated unchanged credential and roster snapshot.
    pub current_device: &'a VerifiedDevice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundStatement {
    scope: PolicyRenewalScope,
    current_authority: [u8; 32],
    family: [u8; 32],
    target: PolicyCheckpoint,
}
fn check_predecessor(scope: &PolicyRenewalScope) -> Result<(), Error> {
    for value in [
        scope.original_owner,
        scope.original_credential,
        scope.current_credential,
    ] {
        nonzero(&value)?;
    }
    match scope.previous_authorization {
        None if scope.previous_policy == scope.original_policy => Ok(()),
        Some(previous) if scope.previous_policy.version() > scope.original_policy.version() => {
            nonzero(&previous)
        }
        _ => Err(Error::Checkpoint),
    }
}
impl BoundStatement {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_BYTES);
        out.extend_from_slice(TAG);
        for value in [
            *self.scope.operation.as_bytes(),
            *self.scope.journal.as_bytes(),
            self.scope.original_owner,
            self.scope.original_credential,
            self.scope.current_credential,
            self.current_authority,
            self.family,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.scope.current_roster.version().to_be_bytes());
        out.extend_from_slice(&self.scope.current_roster.digest());
        for checkpoint in [
            self.scope.original_policy,
            self.scope.previous_policy,
            self.target,
        ] {
            out.extend_from_slice(&checkpoint.version().to_be_bytes());
            out.extend_from_slice(&checkpoint.digest());
        }
        match self.scope.previous_authorization {
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 32]);
            }
            Some(previous) => {
                out.push(1);
                out.extend_from_slice(&previous);
            }
        }
        out.push(1); // Only the original established sessions.
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BODY_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *TAG {
            return Err(Error::Encoding);
        }
        let operation = PolicyRenewalId::from_trusted_state(d.array()?)?;
        let journal = JournalIdentity::from_trusted_state(d.array()?)?;
        let original_owner = d.array()?;
        let original_credential = d.array()?;
        let current_credential = d.array()?;
        let current_authority = d.array()?;
        let family = d.array()?;
        nonzero(&current_authority)?;
        nonzero(&family)?;
        let current_roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let original_policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let previous_policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let target = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let [kind] = d.array()?;
        let previous = d.array::<32>()?;
        let previous_authorization = match (kind, previous) {
            (0, value) if value == [0; 32] => None,
            (1, value) => {
                nonzero(&value)?;
                Some(value)
            }
            _ => return Err(Error::Encoding),
        };
        if d.array::<1>()? != [1] {
            return Err(Error::Scope);
        }
        d.finish()?;
        let scope = PolicyRenewalScope {
            operation,
            journal,
            original_owner,
            original_credential,
            current_credential,
            current_roster,
            original_policy,
            previous_policy,
            previous_authorization,
        };
        check_predecessor(&scope)?;
        if target.version() <= previous_policy.version() {
            return Err(Error::Checkpoint);
        }
        Ok(Self {
            scope,
            current_authority,
            family,
            target,
        })
    }
}

fn historical_statement(
    scope: &PolicyRenewalScope,
    m: &HistoricalPolicyRenewalMaterials<'_>,
) -> Result<BoundStatement, Error> {
    check_predecessor(scope)?;
    continuation::same_profile(m.original, m.previous)?;
    continuation::same_profile(m.original, m.target)?;
    let original = m.original_device;
    let current = m.current_device;
    let od = &original.description;
    let cd = &current.description;
    if original.authority_key != current.authority_key
        || original.account != current.account
        || original.key != current.key
        || od.id != cd.id
        || od.generation != cd.generation
        || od.family != m.original.family()
        || cd.family != od.family
        || od.validity.from() != cd.validity.from()
        || od.validity.until() > cd.validity.until()
        || scope.original_owner != crate::bootstrap::storage_owner(original)
        || scope.original_credential != original.credential_digest()
        || scope.current_credential != current.credential_digest()
        || scope.current_roster != current.roster().checkpoint()
        || scope.original_policy != m.original.checkpoint()
        || scope.previous_policy != m.previous.checkpoint()
        || m.previous.validity().until() < m.original.validity().until()
        || m.target.validity().until() <= m.previous.validity().until()
        || m.target.checkpoint().version() <= m.previous.checkpoint().version()
    {
        return Err(Error::Scope);
    }
    m.target.check_external_signer(&current.authority_key)?;
    m.target.check_external_signer(&current.key)?;
    Ok(BoundStatement {
        scope: scope.clone(),
        current_authority: current.authority_binding(),
        family: m.original.family(),
        target: m.target.checkpoint(),
    })
}

/// Canonical request for two independent approvals. The host must authenticate
/// the request, serialize current authority and deduplicate the operation.
pub struct PolicyRenewalStatement {
    bound: BoundStatement,
    account_key: PublicKey,
    policy_key: PublicKey,
}
impl PolicyRenewalStatement {
    /// Require a current unchanged credential, roster, target and runtime.
    /// Historical policies authenticate context but confer no current permission.
    pub fn new(
        scope: &PolicyRenewalScope,
        m: &PolicyRenewalMaterials<'_>,
        now: u64,
    ) -> Result<Self, Error> {
        let bound = historical_statement(scope, &m.historical())?;
        m.target.check_current(now)?;
        m.target.check_device(m.current_device, now)?;
        Ok(Self {
            bound,
            account_key: m.current_device.authority_key.clone(),
            policy_key: m.original.signer.clone(),
        })
    }
    /// Stable commitment to the full canonical statement, not a commit receipt.
    pub fn digest(&self) -> [u8; 32] {
        digest(DOMAIN, &self.bound.encode())
    }
}

/// One bounded issuer approval; grammar parsing alone grants no authority.
pub struct PolicyRenewalApproval {
    wire: Vec<u8>,
}
impl PolicyRenewalApproval {
    /// Parse exact grammar and bounds without claiming signature verification.
    pub fn from_bytes(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() != APPROVAL_BYTES {
            return Err(Error::Encoding);
        }
        let (body, _) = open_envelope(wire)?;
        BoundStatement::decode(body)?;
        Ok(Self {
            wire: wire.to_vec(),
        })
    }
    /// Exact original public signature bytes for operation retry.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
}
impl RootSigningKey {
    /// Approve the exact policy-only statement under its independently pinned account root.
    pub fn approve_policy_renewal(
        &self,
        statement: &PolicyRenewalStatement,
    ) -> Result<PolicyRenewalApproval, Error> {
        if self.public_key()? != statement.account_key {
            return Err(Error::Scope);
        }
        let body = statement.bound.encode();
        PolicyRenewalApproval::from_bytes(&envelope(
            &body,
            &self.sign(Purpose::PolicyRenewal, &body)?,
        )?)
    }
}
impl PolicySigningKey {
    /// Approve the same statement under its original independent policy root.
    pub fn approve_policy_renewal(
        &self,
        statement: &PolicyRenewalStatement,
    ) -> Result<PolicyRenewalApproval, Error> {
        if self.public_key()? != statement.policy_key {
            return Err(Error::Scope);
        }
        let body = statement.bound.encode();
        PolicyRenewalApproval::from_bytes(&envelope(
            &body,
            &self.sign(Purpose::PolicyRenewal, &body)?,
        )?)
    }
}
fn verify_approvals(
    account: &PolicyRenewalApproval,
    policy: &PolicyRenewalApproval,
    bound: &BoundStatement,
    account_key: &PublicKey,
    policy_key: &PublicKey,
) -> Result<(), Error> {
    let (a, a_signature) = open_envelope(account.as_bytes())?;
    let (p, p_signature) = open_envelope(policy.as_bytes())?;
    if a != p || a != bound.encode() {
        return Err(Error::Scope);
    }
    account_key.verify(Purpose::PolicyRenewal, a, a_signature)?;
    policy_key.verify(Purpose::PolicyRenewal, p, p_signature)?;
    Ok(())
}
fn read_approvals(wire: &[u8]) -> Result<(PolicyRenewalApproval, PolicyRenewalApproval), Error> {
    if wire.len() != MAX_POLICY_RENEWAL_BYTES {
        return Err(Error::Encoding);
    }
    let mut d = Decoder::new(wire);
    if d.array::<8>()? != *CONTAINER {
        return Err(Error::Encoding);
    }
    let mut read = || {
        let n = usize::from(u16::from_be_bytes(d.array()?));
        PolicyRenewalApproval::from_bytes(d.take(n)?)
    };
    let account = read()?;
    let policy = read()?;
    d.finish()?;
    Ok((account, policy))
}

/// Independently double-approved policy-only relation, not durable adoption.
/// Operational callers must recheck current permission and their exact retained
/// credential, roster and predecessor at the transaction and release boundaries.
pub struct VerifiedPolicyRenewal {
    history: HistoricalPolicyRenewal,
}
impl VerifiedPolicyRenewal {
    /// Verify both approvals against independently retained scope and live materials.
    pub fn verify(
        account: &PolicyRenewalApproval,
        policy: &PolicyRenewalApproval,
        scope: &PolicyRenewalScope,
        materials: &PolicyRenewalMaterials<'_>,
        now: u64,
    ) -> Result<Self, Error> {
        let expected = PolicyRenewalStatement::new(scope, materials, now)?;
        verify_approvals(
            account,
            policy,
            &expected.bound,
            &expected.account_key,
            &expected.policy_key,
        )?;
        let mut wire = CONTAINER.to_vec();
        for approval in [account, policy] {
            let n = u16::try_from(approval.as_bytes().len()).map_err(|_| Error::Capacity)?;
            wire.extend_from_slice(&n.to_be_bytes());
            wire.extend_from_slice(approval.as_bytes());
        }
        Ok(Self {
            history: HistoricalPolicyRenewal {
                bound: expected.bound,
                wire,
                policy_key: expected.policy_key,
            },
        })
    }
    /// Reverify the exact retained public bytes; a stale snapshot cannot renew itself.
    pub fn from_bytes(
        wire: &[u8],
        scope: &PolicyRenewalScope,
        materials: &PolicyRenewalMaterials<'_>,
        now: u64,
    ) -> Result<Self, Error> {
        let (account, policy) = read_approvals(wire)?;
        Self::verify(&account, &policy, scope, materials, now)
    }
    /// Exact approved bytes, retained rather than re-signed after an unknown result.
    pub fn as_bytes(&self) -> &[u8] {
        self.history.as_bytes()
    }
    /// Stable authorization commitment, distinct from joint G/T statements.
    pub fn statement_digest(&self) -> [u8; 32] {
        self.history.statement_digest()
    }
    /// Exact independently retained expected predecessor.
    pub fn scope(&self) -> &PolicyRenewalScope {
        self.history.scope()
    }
    /// Approved target policy checkpoint.
    pub fn target_policy(&self) -> PolicyCheckpoint {
        self.history.target_policy()
    }
    /// Preserve authenticated metadata without granting a runtime or session owner.
    pub fn historical(&self) -> HistoricalPolicyRenewal {
        self.history.clone()
    }
}

/// Authenticated metadata for exact recovery only, without any current permission.
/// It cannot be passed to enrollment activation or used as a credential grant.
///
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{DeviceEnrollment, HistoricalPolicyRenewal};
/// fn activate(enrollment: DeviceEnrollment, history: &HistoricalPolicyRenewal) {
///     let _ = enrollment.activate(history, 250, None);
/// }
/// ```
#[derive(Clone)]
pub struct HistoricalPolicyRenewal {
    bound: BoundStatement,
    wire: Vec<u8>,
    policy_key: PublicKey,
}
impl HistoricalPolicyRenewal {
    /// Verify historical signatures and full relation against independent inputs.
    pub fn from_bytes(
        wire: &[u8],
        scope: &PolicyRenewalScope,
        materials: &HistoricalPolicyRenewalMaterials<'_>,
    ) -> Result<Self, Error> {
        let bound = historical_statement(scope, materials)?;
        let (account, policy) = read_approvals(wire)?;
        verify_approvals(
            &account,
            &policy,
            &bound,
            &materials.current_device.authority_key,
            &materials.original.signer,
        )?;
        Ok(Self {
            bound,
            wire: wire.to_vec(),
            policy_key: materials.original.signer.clone(),
        })
    }
    pub(crate) fn journal_bytes(&self) -> Vec<u8> {
        let mut bytes = self.policy_key.encode();
        bytes.extend_from_slice(&self.wire);
        bytes
    }
    // Authenticate retained public metadata under the independently provisioned
    // enrollment root and family. This does not infer adoption or current time.
    pub(crate) fn from_authority(
        bytes: &[u8],
        account_key: &PublicKey,
        family: [u8; 32],
    ) -> Result<Self, Error> {
        if bytes.len() != crate::PUBLIC_KEY_BYTES + MAX_POLICY_RENEWAL_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(bytes);
        let policy_key = PublicKey::decode(d.take(crate::PUBLIC_KEY_BYTES)?)?;
        let wire = d.take(MAX_POLICY_RENEWAL_BYTES)?;
        d.finish()?;
        let (account, policy) = read_approvals(wire)?;
        let (body, _) = open_envelope(account.as_bytes())?;
        let bound = BoundStatement::decode(body)?;
        if bound.family != family || account_key.shares_component(&policy_key) {
            return Err(Error::Scope);
        }
        PolicyPin::new(family, policy_key.clone(), bound.scope.original_policy)?;
        verify_approvals(&account, &policy, &bound, account_key, &policy_key)?;
        Ok(Self {
            bound,
            wire: wire.to_vec(),
            policy_key,
        })
    }
    pub(crate) fn check_devices(
        &self,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
    ) -> Result<(), Error> {
        self.check_credential_lineage(original, current)?;
        if self.scope().current_roster != current.roster().checkpoint()
            || self.bound.current_authority != current.authority_binding()
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    // The approved credential is immutable; later authenticated roster updates
    // may change its membership. Only a journal may select that current roster,
    // and its caller must still perform current-time membership admission.
    pub(crate) fn check_credential_lineage(
        &self,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
    ) -> Result<(), Error> {
        self.check_same_identity(original, current)?;
        if self.scope().current_credential != current.credential_digest() {
            return Err(Error::Scope);
        }
        Ok(())
    }
    // Only historical identity metadata. A caller accepting a different C must
    // additionally prove its real adopted G in the original journal.
    pub(crate) fn check_same_identity(
        &self,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
    ) -> Result<(), Error> {
        let s = self.scope();
        if s.original_owner != crate::bootstrap::storage_owner(original)
            || s.original_credential != original.credential_digest()
            || self.bound.current_authority
                != crate::identity::authority_binding(
                    current.account_id(),
                    s.current_roster,
                    current.description.family,
                )
            || self.bound.family != original.description.family
            || original.authority_key != current.authority_key
            || original.account != current.account
            || original.key != current.key
            || original.description.id != current.description.id
            || original.description.generation != current.description.generation
            || original.description.family != current.description.family
            || original.description.validity.from() != current.description.validity.from()
            || original.description.validity.until() > current.description.validity.until()
            || self.policy_key.shares_component(&current.key)
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn check_renewed_identity(
        &self,
        original: &VerifiedDevice,
        grant: &crate::VerifiedCredentialRenewal,
    ) -> Result<(), Error> {
        self.check_same_identity(original, grant.successor_device())?;
        if grant.original_storage_owner() != self.scope().original_owner
            || grant.original_credential_digest() != self.scope().original_credential
            || grant.policy_digest() != self.scope().original_policy.digest()
        {
            return Err(Error::Scope);
        }
        grant.resolve_established(original, self.scope().original_policy.digest())?;
        Ok(())
    }
    pub(crate) fn check_context_policy(
        &self,
        original: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
    ) -> Result<(), Error> {
        self.check_target(target)?;
        self.check_original_policy(original)?;
        if self.target_policy() != target.checkpoint()
            || target.validity().until() <= original.validity().until()
        {
            return Err(Error::Scope);
        }
        continuation::same_profile(original, target.historical())
    }
    pub(crate) fn check_original_policy(
        &self,
        original: &HistoricalSessionPolicy,
    ) -> Result<(), Error> {
        if self.scope().original_policy != original.checkpoint()
            || self.policy_key != original.signer
            || self.bound.family != original.family()
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    // Immutable target binding only; callers separately admit current time,
    // runtime and account membership before starting a new operation.
    pub(crate) fn check_target(
        &self,
        target: &impl AsRef<HistoricalSessionPolicy>,
    ) -> Result<(), Error> {
        let target = target.as_ref();
        if self.target_policy() != target.checkpoint()
            || self.bound.family != target.family()
            || self.policy_key != target.signer
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    /// Exact original public authorization bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Exact independently retained original and predecessor expectations.
    pub fn scope(&self) -> &PolicyRenewalScope {
        &self.bound.scope
    }
    /// Stable statement digest, never a completion receipt.
    pub fn statement_digest(&self) -> [u8; 32] {
        digest(DOMAIN, &self.bound.encode())
    }
    /// Target metadata; this accessor grants no current policy permission.
    pub fn target_policy(&self) -> PolicyCheckpoint {
        self.bound.target
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests;
