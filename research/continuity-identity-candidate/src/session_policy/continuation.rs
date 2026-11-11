// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Candidate qperiapt-policy-continuation/1 joint authorization. A verified
//! statement is not a journal transition, current policy owner or session lease.
use super::*;
use crate::{
    CredentialRenewalId, JournalIdentity, RootSigningKey, RosterCheckpoint,
    VerifiedCredentialRenewal,
};

const TAG: &[u8; 8] = b"QPPCTN01";
const CONTAINER: &[u8; 8] = b"QPPCTB01";
const DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-CONTINUATION-CANDIDATE/v1";
const BODY_BYTES: usize = 8 + 9 * 32 + 40 + 3 * 40 + 33 + 1;
const APPROVAL_BYTES: usize = 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES;
/// Exact upper bound for the two independently signed copies of one statement.
pub const MAX_POLICY_CONTINUATION_BYTES: usize = 8 + 2 * (2 + APPROVAL_BYTES);

/// Independently retained installation and predecessor expectations. Incoming
/// approval bytes must not select these values. The durable coordinator must
/// compare them with its original state before reserving any transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyContinuationScope {
    /// Original credential operation, reused for this jointly approved target.
    pub operation: CredentialRenewalId,
    /// Exact original journal, not merely an account or device identity.
    pub journal: JournalIdentity,
    /// Immutable original storage owner.
    pub original_owner: [u8; 32],
    /// Immutable original credential commitment.
    pub original_credential: [u8; 32],
    /// Exact currently retained predecessor credential commitment.
    pub previous_credential: [u8; 32],
    /// Exact currently retained predecessor roster.
    pub previous_roster: RosterCheckpoint,
    /// Original P0 transcript/storage policy checkpoint.
    pub original_policy: PolicyCheckpoint,
    /// Exact last adopted policy, which may have expired.
    pub previous_policy: PolicyCheckpoint,
    /// Exact last adopted policy authorization. None is valid only for the
    /// original P0 predecessor; it is never inferred from an ACK or version floor.
    pub previous_authorization: Option<[u8; 32]>,
}

/// Signature-verified inputs supplied independently of the approval container.
/// P0 and the predecessor are historical; the new policy and credential target
/// must be independently pinned and currently valid. Same-key credential and
/// policy validity extension is the only supported transition in this profile.
pub struct PolicyContinuationMaterials<'a> {
    /// Original signed P0 metadata retained for the installation.
    pub original: &'a HistoricalSessionPolicy,
    /// Signed metadata for the exact last adopted policy.
    pub previous: &'a HistoricalSessionPolicy,
    /// Independently verified live target policy owner; it is only borrowed.
    pub target: &'a VerifiedSessionPolicy,
    /// Independently account-approved credential transition under original P0.
    pub credential: &'a VerifiedCredentialRenewal,
}
impl<'a> PolicyContinuationMaterials<'a> {
    /// Drop all current-runtime requirements for historical verification only.
    pub fn historical(&self) -> HistoricalPolicyContinuationMaterials<'a> {
        HistoricalPolicyContinuationMaterials {
            original: self.original,
            previous: self.previous,
            target: self.target.historical(),
            credential: self.credential.historical(),
        }
    }
}
/// Independently verified signed materials for historical G/T recovery or close.
/// This view grants no current policy, credential, roster or runtime permission.
pub struct HistoricalPolicyContinuationMaterials<'a> {
    /// Immutable original policy P0.
    pub original: &'a HistoricalSessionPolicy,
    /// Exact predecessor policy named in the original approval.
    pub previous: &'a HistoricalSessionPolicy,
    /// Independently pinned signed target policy, possibly expired.
    pub target: &'a HistoricalSessionPolicy,
    /// Independently account-approved original credential transition.
    pub credential: &'a crate::HistoricalCredentialRenewal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundStatement {
    scope: PolicyContinuationScope,
    credential_statement: [u8; 32],
    target_credential: [u8; 32],
    target_authority: [u8; 32],
    family: [u8; 32],
    target_policy: PolicyCheckpoint,
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
            self.scope.previous_credential,
            self.credential_statement,
            self.target_credential,
            self.target_authority,
            self.family,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.scope.previous_roster.version().to_be_bytes());
        out.extend_from_slice(&self.scope.previous_roster.digest());
        for checkpoint in [
            self.scope.original_policy,
            self.scope.previous_policy,
            self.target_policy,
        ] {
            out.extend_from_slice(&checkpoint.version().to_be_bytes());
            out.extend_from_slice(&checkpoint.digest());
        }
        match self.scope.previous_authorization {
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 32]);
            }
            Some(statement) => {
                out.push(1);
                out.extend_from_slice(&statement);
            }
        }
        out.push(1); // Original established sessions only, never fresh bootstrap.
        out
    }
    fn decode(body: &[u8]) -> Result<Self, Error> {
        if body.len() != BODY_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *TAG {
            return Err(Error::Encoding);
        }
        let operation = CredentialRenewalId::from_trusted_state(d.array()?)?;
        let journal = JournalIdentity::from_trusted_state(d.array()?)?;
        let original_owner = d.array()?;
        let original_credential = d.array()?;
        let previous_credential = d.array()?;
        let credential_statement = d.array()?;
        let target_credential = d.array()?;
        let target_authority = d.array()?;
        let family = d.array()?;
        for value in [
            original_owner,
            original_credential,
            previous_credential,
            credential_statement,
            target_credential,
            target_authority,
            family,
        ] {
            nonzero(&value)?;
        }
        let previous_roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let original_policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let previous_policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let target_policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
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
        let scope = PolicyContinuationScope {
            operation,
            journal,
            original_owner,
            original_credential,
            previous_credential,
            previous_roster,
            original_policy,
            previous_policy,
            previous_authorization,
        };
        check_predecessor(&scope)?;
        if target_policy.version() <= previous_policy.version() {
            return Err(Error::Checkpoint);
        }
        Ok(Self {
            scope,
            credential_statement,
            target_credential,
            target_authority,
            family,
            target_policy,
        })
    }
}

fn check_predecessor(scope: &PolicyContinuationScope) -> Result<(), Error> {
    nonzero(&scope.original_owner)?;
    nonzero(&scope.original_credential)?;
    nonzero(&scope.previous_credential)?;
    match scope.previous_authorization {
        None if scope.previous_policy == scope.original_policy => Ok(()),
        Some(previous) if scope.previous_policy.version() > scope.original_policy.version() => {
            nonzero(&previous)
        }
        _ => Err(Error::Checkpoint),
    }
}
pub(super) fn same_profile(
    original: &HistoricalSessionPolicy,
    next: &HistoricalSessionPolicy,
) -> Result<(), Error> {
    if original.family != next.family
        || original.signer != next.signer
        || original.sdk != next.sdk
        || original.modes != next.modes
        || original.anchor != next.anchor
        || original.budget != next.budget
        || original.validity.from() != next.validity.from()
    {
        return Err(Error::Scope);
    }
    Ok(())
}

/// Canonical joint request ready for two independent issuer approvals. The host
/// must separately authenticate the user and serialize/deduplicate the expected
/// predecessor. Constructing or signing it does not reserve or commit anything.
pub struct PolicyContinuationStatement {
    bound: BoundStatement,
    account_key: PublicKey,
    policy_key: PublicKey,
}
impl PolicyContinuationStatement {
    /// Validate the exact predecessor and current target before either issuer
    /// signs. Neither expired P0 nor expired predecessor obtains a runtime owner.
    pub fn new(
        scope: &PolicyContinuationScope,
        m: &PolicyContinuationMaterials<'_>,
        now: u64,
    ) -> Result<Self, Error> {
        let bound = historical_statement(scope, &m.historical())?;
        let grant = m.credential;
        m.target.check_current(now)?;
        m.target.check_device(grant.successor_device(), now)?;
        let account_key = &grant.successor_device().authority_key;
        m.target.check_external_signer(account_key)?;
        Ok(Self {
            bound,
            account_key: account_key.clone(),
            policy_key: m.original.signer.clone(),
        })
    }
    /// Stable statement commitment; randomized envelope bytes are still retained
    /// separately for exact operation retry. This digest is not a witness receipt.
    pub fn digest(&self) -> [u8; 32] {
        digest(DOMAIN, &self.bound.encode())
    }
}

fn historical_statement(
    scope: &PolicyContinuationScope,
    m: &HistoricalPolicyContinuationMaterials<'_>,
) -> Result<BoundStatement, Error> {
    check_predecessor(scope)?;
    same_profile(m.original, m.previous)?;
    same_profile(m.original, m.target)?;
    let grant = m.credential;
    if scope.original_policy != m.original.checkpoint()
        || scope.previous_policy != m.previous.checkpoint()
        || scope.operation != grant.operation()
        || scope.original_owner != grant.original_storage_owner()
        || scope.original_credential != grant.original_credential_digest()
        || scope.previous_credential != grant.previous_device().credential_digest()
        || scope.previous_roster != grant.previous_device().roster().checkpoint()
        || grant.policy_digest() != scope.original_policy.digest()
        || m.previous.validity().until() < m.original.validity().until()
        || m.target.validity().until() <= m.previous.validity().until()
        || m.target.checkpoint().version() <= m.previous.checkpoint().version()
    {
        return Err(Error::Scope);
    }
    m.target
        .check_external_signer(&grant.successor_device().authority_key)?;
    Ok(BoundStatement {
        scope: scope.clone(),
        credential_statement: grant.statement_digest(),
        target_credential: grant.successor_device().credential_digest(),
        target_authority: grant.successor_device().authority_binding(),
        family: m.original.family(),
        target_policy: m.target.checkpoint(),
    })
}

/// One issuer's bounded approval, not sufficient for continuation by itself.
pub struct PolicyContinuationApproval {
    wire: Vec<u8>,
}
impl PolicyContinuationApproval {
    /// Parse only canonical grammar and bounds; this grants no authentication.
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
    /// Exact original public approval bytes; do not re-sign a pending operation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
}
impl RootSigningKey {
    /// Independently approve the canonical joint request under its exact account
    /// root. The host supplies real authorization and current-head serialization.
    pub fn approve_policy_continuation(
        &self,
        statement: &PolicyContinuationStatement,
    ) -> Result<PolicyContinuationApproval, Error> {
        if self.public_key()? != statement.account_key {
            return Err(Error::Scope);
        }
        let body = statement.bound.encode();
        PolicyContinuationApproval::from_bytes(&envelope(
            &body,
            &self.sign(Purpose::PolicyContinuation, &body)?,
        )?)
    }
}
impl PolicySigningKey {
    /// Independently approve the same request under its exact policy root.
    /// Possession of an account approval does not substitute for this approval.
    pub fn approve_policy_continuation(
        &self,
        statement: &PolicyContinuationStatement,
    ) -> Result<PolicyContinuationApproval, Error> {
        if self.public_key()? != statement.policy_key {
            return Err(Error::Scope);
        }
        let body = statement.bound.encode();
        PolicyContinuationApproval::from_bytes(&envelope(
            &body,
            &self.sign(Purpose::PolicyContinuation, &body)?,
        )?)
    }
}

/// Both roots approved one exact original-to-current continuation. This object
/// cannot mint a context or activate storage. Durable admission must compare its
/// predecessor, persist it separately from credential history/receipts and bind
/// the required witness to this exact statement before returning any owner.
pub struct VerifiedPolicyContinuation {
    bound: BoundStatement,
    wire: Vec<u8>,
    policy_key: PublicKey,
}
impl VerifiedPolicyContinuation {
    /// Verify both authentic approvals against independently retained scope and
    /// current pinned materials. Same credential operation with a different
    /// policy approval is a distinct statement and never an implicit retry.
    pub fn verify(
        account: &PolicyContinuationApproval,
        policy: &PolicyContinuationApproval,
        scope: &PolicyContinuationScope,
        materials: &PolicyContinuationMaterials<'_>,
        now: u64,
    ) -> Result<Self, Error> {
        let expected = PolicyContinuationStatement::new(scope, materials, now)?;
        let (a, a_signature) = open_envelope(account.as_bytes())?;
        let (p, p_signature) = open_envelope(policy.as_bytes())?;
        if a != p || a != expected.bound.encode() {
            return Err(Error::Scope);
        }
        expected
            .account_key
            .verify(Purpose::PolicyContinuation, a, a_signature)?;
        expected
            .policy_key
            .verify(Purpose::PolicyContinuation, p, p_signature)?;
        let mut wire = CONTAINER.to_vec();
        for approval in [account, policy] {
            let n = u16::try_from(approval.as_bytes().len()).map_err(|_| Error::Capacity)?;
            wire.extend_from_slice(&n.to_be_bytes());
            wire.extend_from_slice(approval.as_bytes());
        }
        Ok(Self {
            bound: expected.bound,
            wire,
            policy_key: expected.policy_key,
        })
    }
    /// Re-verify a retained complete public container with current independent
    /// scope/materials. Parsing cannot refresh an expired target or closed owner.
    pub fn from_bytes(
        wire: &[u8],
        scope: &PolicyContinuationScope,
        materials: &PolicyContinuationMaterials<'_>,
        now: u64,
    ) -> Result<Self, Error> {
        let (account, policy) = read_approvals(wire)?;
        Self::verify(&account, &policy, scope, materials, now)
    }
    /// Retain authenticated history for recovery. This deliberately drops any
    /// current-time claim and cannot be converted into an operational owner.
    pub fn historical(&self) -> HistoricalPolicyContinuation {
        HistoricalPolicyContinuation {
            bound: self.bound.clone(),
            wire: self.wire.clone(),
            policy_key: self.policy_key.clone(),
        }
    }
    /// Exact original signatures and container bytes for durable coordination.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Stable combined authorization, distinct from the credential-only grant.
    pub fn statement_digest(&self) -> [u8; 32] {
        digest(DOMAIN, &self.bound.encode())
    }
    /// Exact expected original installation and predecessor; not a live lease.
    pub fn scope(&self) -> &PolicyContinuationScope {
        &self.bound.scope
    }
    /// Independently approved target policy checkpoint.
    pub fn target_policy(&self) -> PolicyCheckpoint {
        self.bound.target_policy
    }
    /// Account grant incorporated into this exact joint statement.
    pub fn credential_statement(&self) -> [u8; 32] {
        self.bound.credential_statement
    }
}

fn read_approvals(
    wire: &[u8],
) -> Result<(PolicyContinuationApproval, PolicyContinuationApproval), Error> {
    if wire.len() != MAX_POLICY_CONTINUATION_BYTES {
        return Err(Error::Encoding);
    }
    let mut d = Decoder::new(wire);
    if d.array::<8>()? != *CONTAINER {
        return Err(Error::Encoding);
    }
    let mut approval = || {
        let n = usize::from(u16::from_be_bytes(d.array()?));
        PolicyContinuationApproval::from_bytes(d.take(n)?)
    };
    let account = approval()?;
    let policy = approval()?;
    d.finish()?;
    Ok((account, policy))
}

/// Authenticated joint authorization retained as history, independently of a
/// credential grant or completion receipt. It grants no current policy, roster,
/// runtime or session permission. Every operational use needs current admission.
///
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{DeviceEnrollment, HistoricalPolicyContinuation};
/// fn activate(enrollment: DeviceEnrollment, history: &HistoricalPolicyContinuation) {
///     let _ = enrollment.activate(history, 250, None);
/// }
/// ```
#[derive(Clone)]
pub struct HistoricalPolicyContinuation {
    bound: BoundStatement,
    wire: Vec<u8>,
    policy_key: PublicKey,
}
impl HistoricalPolicyContinuation {
    /// Authenticate retained public approvals against independent historical
    /// scope and pins, without constructing a live policy or runtime owner.
    /// Useful after expiry; this cannot prepare/apply a new operational target.
    pub fn from_bytes(
        wire: &[u8],
        scope: &PolicyContinuationScope,
        materials: &HistoricalPolicyContinuationMaterials<'_>,
    ) -> Result<Self, Error> {
        let expected = historical_statement(scope, materials)?;
        let (account, policy) = read_approvals(wire)?;
        let (a, a_signature) = open_envelope(account.as_bytes())?;
        let (p, p_signature) = open_envelope(policy.as_bytes())?;
        if a != p || a != expected.encode() {
            return Err(Error::Scope);
        }
        materials
            .credential
            .successor_device()
            .authority_key
            .verify(Purpose::PolicyContinuation, a, a_signature)?;
        materials
            .target
            .signer
            .verify(Purpose::PolicyContinuation, p, p_signature)?;
        Ok(Self {
            bound: expected,
            wire: wire.to_vec(),
            policy_key: materials.target.signer.clone(),
        })
    }
    pub(crate) fn journal_bytes(&self) -> Vec<u8> {
        let mut out = self.policy_key.encode();
        out.extend_from_slice(&self.wire);
        out
    }
    pub(crate) fn from_journal(
        bytes: &[u8],
        roster: &crate::VerifiedRoster,
    ) -> Result<Self, Error> {
        let (account_key, family) = roster.continuation_authority();
        Self::from_authority(bytes, account_key, family)
    }
    pub(crate) fn from_authority(
        bytes: &[u8],
        account_key: &PublicKey,
        family: [u8; 32],
    ) -> Result<Self, Error> {
        if bytes.len() != crate::PUBLIC_KEY_BYTES + MAX_POLICY_CONTINUATION_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(bytes);
        let policy_key = PublicKey::decode(d.take(crate::PUBLIC_KEY_BYTES)?)?;
        let wire = d.take(MAX_POLICY_CONTINUATION_BYTES)?;
        d.finish()?;
        let (account, policy) = read_approvals(wire)?;
        let (a, a_signature) = open_envelope(account.as_bytes())?;
        let (p, p_signature) = open_envelope(policy.as_bytes())?;
        if a != p {
            return Err(Error::Scope);
        }
        let bound = BoundStatement::decode(a)?;
        if bound.family != family || account_key.shares_component(&policy_key) {
            return Err(Error::Scope);
        }
        // The authenticated account roster already pins this policy family.
        // A supplied public key must hash to that exact authority identity.
        PolicyPin::new(family, policy_key.clone(), bound.scope.original_policy)?;
        account_key.verify(Purpose::PolicyContinuation, a, a_signature)?;
        policy_key.verify(Purpose::PolicyContinuation, p, p_signature)?;
        Ok(Self {
            bound,
            wire: wire.to_vec(),
            policy_key,
        })
    }
    // Metadata checks only. A historical readback may use a closed/expired
    // owner; creating new work additionally requires the normal live admission.
    pub(crate) fn check_target(
        &self,
        policy: &impl AsRef<HistoricalSessionPolicy>,
    ) -> Result<(), Error> {
        let policy = policy.as_ref();
        if self.bound.target_policy != policy.checkpoint()
            || self.bound.family != policy.family()
            || self.policy_key != policy.signer
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    // Retained sessions keep the entire original profile and SDK binding.
    // This checks the relation, not the target's current runtime/time permission.
    pub(crate) fn check_context_policy(
        &self,
        original: &HistoricalSessionPolicy,
        policy: &impl AsRef<HistoricalSessionPolicy>,
    ) -> Result<(), Error> {
        let policy = policy.as_ref();
        self.check_target(policy)?;
        if self.scope().original_policy != original.checkpoint()
            || policy.validity().until() <= original.validity().until()
        {
            return Err(Error::Scope);
        }
        same_profile(original, policy)
    }
    pub(crate) fn check_credential(
        &self,
        grant: &impl AsRef<crate::HistoricalCredentialRenewal>,
    ) -> Result<(), Error> {
        let grant = grant.as_ref();
        let s = &self.bound.scope;
        if s.operation != grant.operation()
            || s.original_owner != grant.original_storage_owner()
            || s.original_credential != grant.original_credential_digest()
            || s.previous_credential != grant.previous_device().credential_digest()
            || s.previous_roster != grant.previous_device().roster().checkpoint()
            || s.original_policy.digest() != grant.policy_digest()
            || self.bound.credential_statement != grant.statement_digest()
            || self.bound.target_credential != grant.successor_device().credential_digest()
            || self.bound.target_authority != grant.successor_device().authority_binding()
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    /// Original public approvals, without re-signing or extending validity.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Exact historical statement identity, not a current witness receipt.
    pub fn statement_digest(&self) -> [u8; 32] {
        digest(DOMAIN, &self.bound.encode())
    }
    /// Immutable original scope and predecessor expectations.
    pub fn scope(&self) -> &PolicyContinuationScope {
        &self.bound.scope
    }
    /// Historical target checkpoint. A caller must independently verify current
    /// target validity, runtime ownership and durable admission before use.
    pub fn target_policy(&self) -> PolicyCheckpoint {
        self.bound.target_policy
    }
    /// Credential statement incorporated into this historical joint approval.
    pub fn credential_statement(&self) -> [u8; 32] {
        self.bound.credential_statement
    }
}

#[cfg(test)]
pub(crate) mod tests;
