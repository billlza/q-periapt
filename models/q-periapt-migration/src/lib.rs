#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Canonical first-stage migration context layered above the frozen Q-Periapt ABI 2.
//!
//! This crate owns only typed, role-normalized public context bytes. It does not
//! authenticate a handshake transcript, verify a transition certificate, persist a
//! rollback-resistant migration state, or turn ABI 2 policy decisions into
//! unforgeable capabilities. Callers must derive both endpoint policies through
//! [`q_periapt_policy::Policy::load_signed`] (or its monotonic variant), validate
//! every externally asserted transcript commitment at their protocol boundary, and
//! use the same authenticated execution decision at construction, encapsulation,
//! and decapsulation.
//!
//! The exact 315-byte encoding is passed unchanged as ABI 2 `application_context`.
//! ABI 2 then applies its existing policy-context wrapper; callers must not pre-wrap
//! or pre-hash these bytes.

mod codec;

use core::fmt;

use codec::Lp8Writer;
use q_periapt_core::Profile;
use q_periapt_policy::{
    AuthenticatedPolicy, AuthenticatedResolvedSuite, HybridSuite, KeyFormat, TrustedPolicyState,
};

/// Domain separation for the canonical migration-context body.
pub const MIGRATION_CONTEXT_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-CONTEXT/v1";
/// Schema version encoded inside [`MigrationContextV1`].
pub const MIGRATION_CONTEXT_SCHEMA_VERSION: u16 = 1;
/// Exact encoded length of one canonical [`MigrationContextV1`] application body.
pub const MIGRATION_CONTEXT_V1_ENCODED_LEN: usize = 315;

const _: () = {
    assert!(MIGRATION_CONTEXT_DOMAIN.len() == 30);
    assert!(
        (12 * 8)
            + MIGRATION_CONTEXT_DOMAIN.len()
            + core::mem::size_of::<u16>()
            + 16
            + core::mem::size_of::<u8>()
            + core::mem::size_of::<u64>()
            + (5 * 32)
            + core::mem::size_of::<u8>()
            + core::mem::size_of::<u8>()
            == MIGRATION_CONTEXT_V1_ENCODED_LEN
    );
    assert!(MIGRATION_CONTEXT_V1_ENCODED_LEN <= q_periapt_core::MAX_APPLICATION_CONTEXT_BYTES);
};

macro_rules! fixed_bytes_type {
    ($name:ident, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Construct the typed value from its exact fixed-width representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact fixed-width representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

fixed_bytes_type!(
    MigrationProtocolId,
    16,
    "A version-qualified protocol namespace agreed by both endpoint roles."
);
/// SHA3-256 over the exact authenticated endpoint-policy bytes.
///
/// There is intentionally no public raw constructor. Instances can only leave
/// [`AuthenticatedEndpointPolicy`], whose constructor derives them from an
/// [`AuthenticatedPolicy`].
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PolicyDigest([u8; 32]);

impl PolicyDigest {
    const fn from_authenticated_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PolicyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PolicyDigest([redacted])")
    }
}
fixed_bytes_type!(
    CapabilityTranscriptHash,
    32,
    "An externally asserted commitment to canonical, role-ordered capability negotiation bytes."
);
fixed_bytes_type!(
    TransitionStateHash,
    32,
    "An externally asserted commitment to migration-transition state bytes."
);
fixed_bytes_type!(
    PreKemTranscriptHash,
    32,
    "An externally asserted commitment to the non-circular handshake prefix available before this KEM."
);

/// Stable endpoint roles assigned by the authenticated handshake.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EndpointRole {
    /// The protocol initiator.
    Initiator = 1,
    /// The protocol responder.
    Responder = 2,
}

/// Closed NIST security floor committed by a migration context.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SecurityFloor {
    /// NIST security category 1.
    Level1 = 1,
    /// NIST security category 2.
    Level2 = 2,
    /// NIST security category 3.
    Level3 = 3,
    /// NIST security category 5.
    Level5 = 5,
}

impl SecurityFloor {
    fn from_nist_level(level: u8) -> Result<Self, MigrationContextError> {
        match level {
            1 => Ok(Self::Level1),
            2 => Ok(Self::Level2),
            3 => Ok(Self::Level3),
            5 => Ok(Self::Level5),
            _ => Err(MigrationContextError::InvalidSecurityFloor),
        }
    }

    /// Return the stable one-byte NIST category code.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A validated migration generation, reserving zero and `u64::MAX` as invalid sentinels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MigrationEpoch(u64);

impl MigrationEpoch {
    /// Construct a migration epoch in the range `1..u64::MAX`.
    pub fn new(value: u64) -> Result<Self, MigrationContextError> {
        if value == 0 || value == u64::MAX {
            Err(MigrationContextError::InvalidMigrationEpoch)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the underlying monotonic generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A commitment field that was the reserved all-zero value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MigrationCommitmentField {
    /// Initiator endpoint policy digest.
    InitiatorPolicyDigest,
    /// Responder endpoint policy digest.
    ResponderPolicyDigest,
    /// Capability-negotiation transcript hash.
    CapabilityTranscriptHash,
    /// Migration transition-state hash.
    TransitionStateHash,
    /// Pre-KEM handshake transcript hash.
    PreKemTranscriptHash,
}

/// Public-input validation or canonical-encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MigrationContextError {
    /// The version-qualified protocol identifier was the reserved all-zero value.
    InvalidProtocolId,
    /// The migration epoch was zero or `u64::MAX`.
    InvalidMigrationEpoch,
    /// A public commitment used its reserved all-zero representation.
    ZeroCommitment(MigrationCommitmentField),
    /// An authenticated endpoint policy did not authorize the selected suite.
    EndpointPolicyDoesNotAuthorizeSuite,
    /// The common execution decision cannot bind an application context.
    ExecutionDecisionNotContextBound,
    /// An endpoint policy resolved to a profile/key format that cannot bind migration context.
    EndpointPolicyNotContextBound,
    /// Components were constructed against different authenticated execution decisions.
    ExecutionDecisionMismatch,
    /// The selected suite's NIST category was below the effective endpoint-policy floor.
    SuiteBelowSecurityFloor,
    /// A policy exposed a security floor outside the closed NIST categories 1, 2, 3, and 5.
    InvalidSecurityFloor,
    /// The caller-provided output did not have the exact 315-byte extent.
    InvalidOutputLength,
    /// The selected suite cannot be executed by the frozen fixed-suite ABI 2.
    Abi2IncompatibleSuite,
    /// An internal fixed-layout invariant failed; no caller output was modified.
    EncodingInvariant,
}

impl fmt::Display for MigrationContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolId => f.write_str("migration protocol id must be non-zero"),
            Self::InvalidMigrationEpoch => {
                f.write_str("migration epoch must be between 1 and u64::MAX - 1")
            }
            Self::ZeroCommitment(field) => {
                write!(f, "migration commitment must be non-zero: {field:?}")
            }
            Self::EndpointPolicyDoesNotAuthorizeSuite => {
                f.write_str("authenticated endpoint policy does not authorize the selected suite")
            }
            Self::ExecutionDecisionNotContextBound => {
                f.write_str("common execution decision must be ContextBound with expanded keys")
            }
            Self::EndpointPolicyNotContextBound => f.write_str(
                "authenticated endpoint policy must resolve to ContextBound with expanded keys",
            ),
            Self::ExecutionDecisionMismatch => {
                f.write_str("migration components use different common execution decisions")
            }
            Self::SuiteBelowSecurityFloor => {
                f.write_str("selected suite is below the effective endpoint-policy floor")
            }
            Self::InvalidSecurityFloor => f.write_str("security floor must be 1, 2, 3, or 5"),
            Self::InvalidOutputLength => {
                f.write_str("migration context output must be exactly 315 bytes")
            }
            Self::Abi2IncompatibleSuite => {
                f.write_str("frozen ABI 2 supports only ML-KEM-768 + X25519")
            }
            Self::EncodingInvariant => f.write_str("migration context encoding invariant failed"),
        }
    }
}

impl std::error::Error for MigrationContextError {}

/// One endpoint policy projected against a common authenticated execution decision.
///
/// This type has no raw constructor: its digest and floor are derived from
/// [`AuthenticatedPolicy`], while its suite/profile/key-format/state come from one
/// indivisible [`AuthenticatedResolvedSuite`]. It does not prove that the peer
/// presented this policy in the current handshake; that protocol authentication
/// remains a caller responsibility.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedEndpointPolicy {
    digest: PolicyDigest,
    security_floor: SecurityFloor,
    execution_decision: AuthenticatedResolvedSuite,
}

impl fmt::Debug for AuthenticatedEndpointPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedEndpointPolicy([redacted])")
    }
}

impl AuthenticatedEndpointPolicy {
    /// Project an authenticated endpoint policy against `common_execution`.
    ///
    /// The caller cannot supply a standalone suite code. The suite, profile, key
    /// format, and trusted policy state are accepted only as the atomic decision
    /// returned by [`AuthenticatedPolicy::resolve_suite`]. Endpoint policies that do
    /// not authorize that suite, or resolve it to `CompatXWing` / seed-derived keys,
    /// fail closed.
    pub fn from_authenticated_policy(
        policy: &AuthenticatedPolicy,
        common_execution: AuthenticatedResolvedSuite,
    ) -> Result<Self, MigrationContextError> {
        validate_context_bound_execution(common_execution)?;
        let common = common_execution.resolved();
        let endpoint_execution = policy
            .resolve_suite(core::slice::from_ref(&common.suite()))
            .map_err(|_| MigrationContextError::EndpointPolicyDoesNotAuthorizeSuite)?;
        let endpoint = endpoint_execution.resolved();
        if endpoint.profile() != common.profile() || endpoint.key_format() != common.key_format() {
            return Err(MigrationContextError::EndpointPolicyNotContextBound);
        }
        let security_floor = SecurityFloor::from_nist_level(policy.policy().min_nist_level())?;
        if common.suite().nist_level() < security_floor.to_u8() {
            return Err(MigrationContextError::SuiteBelowSecurityFloor);
        }
        Ok(Self {
            digest: PolicyDigest::from_authenticated_bytes(policy.trusted_state().digest()),
            security_floor,
            execution_decision: common_execution,
        })
    }

    /// Return the exact signed endpoint-policy digest.
    #[must_use]
    pub const fn digest(self) -> PolicyDigest {
        self.digest
    }

    /// Return this endpoint's authenticated security floor.
    #[must_use]
    pub const fn security_floor(self) -> SecurityFloor {
        self.security_floor
    }

    /// Return the common authenticated execution decision used for projection.
    #[must_use]
    pub const fn execution_decision(self) -> AuthenticatedResolvedSuite {
        self.execution_decision
    }

    /// Return the suite this endpoint policy authorized.
    #[must_use]
    pub const fn selected_suite(self) -> HybridSuite {
        self.execution_decision.resolved().suite()
    }
}

/// Authenticated endpoint policies normalized to fixed initiator/responder order.
///
/// `local_role` is used only during construction and is never encoded. Thus an
/// initiator holding `(local=A, peer=B)` and a responder holding
/// `(local=B, peer=A)` obtain the same canonical ordering.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RoleOrderedEndpointPolicies {
    initiator: AuthenticatedEndpointPolicy,
    responder: AuthenticatedEndpointPolicy,
    execution_decision: AuthenticatedResolvedSuite,
    effective_floor: SecurityFloor,
}

impl fmt::Debug for RoleOrderedEndpointPolicies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RoleOrderedEndpointPolicies([redacted])")
    }
}

impl RoleOrderedEndpointPolicies {
    /// Normalize local/peer endpoint policies into protocol initiator/responder order.
    pub fn from_local_peer(
        local_role: EndpointRole,
        local: AuthenticatedEndpointPolicy,
        peer: AuthenticatedEndpointPolicy,
    ) -> Result<Self, MigrationContextError> {
        if local.execution_decision != peer.execution_decision {
            return Err(MigrationContextError::ExecutionDecisionMismatch);
        }
        let (initiator, responder) = match local_role {
            EndpointRole::Initiator => (local, peer),
            EndpointRole::Responder => (peer, local),
        };
        let effective_floor = core::cmp::max(local.security_floor, peer.security_floor);
        if local.selected_suite().nist_level() < effective_floor.to_u8() {
            return Err(MigrationContextError::SuiteBelowSecurityFloor);
        }
        require_nonzero(
            initiator.digest.as_bytes(),
            MigrationCommitmentField::InitiatorPolicyDigest,
        )?;
        require_nonzero(
            responder.digest.as_bytes(),
            MigrationCommitmentField::ResponderPolicyDigest,
        )?;
        Ok(Self {
            initiator,
            responder,
            execution_decision: local.execution_decision,
            effective_floor,
        })
    }

    /// Return the initiator endpoint policy.
    #[must_use]
    pub const fn initiator(self) -> AuthenticatedEndpointPolicy {
        self.initiator
    }

    /// Return the responder endpoint policy.
    #[must_use]
    pub const fn responder(self) -> AuthenticatedEndpointPolicy {
        self.responder
    }

    /// Return the common authenticated execution decision.
    #[must_use]
    pub const fn execution_decision(self) -> AuthenticatedResolvedSuite {
        self.execution_decision
    }

    /// Return the suite authorized by both endpoint policies.
    #[must_use]
    pub const fn selected_suite(self) -> HybridSuite {
        self.execution_decision.resolved().suite()
    }

    /// Return the maximum of the two authenticated endpoint-policy floors.
    #[must_use]
    pub const fn effective_floor(self) -> SecurityFloor {
        self.effective_floor
    }
}

/// Stable protocol scope for one migration-bound KEM operation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationScopeV1 {
    protocol_id: MigrationProtocolId,
    encapsulator_role: EndpointRole,
    migration_epoch: MigrationEpoch,
}

impl fmt::Debug for MigrationScopeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationScopeV1([redacted])")
    }
}

impl MigrationScopeV1 {
    /// Construct and validate a migration protocol scope.
    pub fn new(
        protocol_id: MigrationProtocolId,
        encapsulator_role: EndpointRole,
        migration_epoch: MigrationEpoch,
    ) -> Result<Self, MigrationContextError> {
        if all_zero(protocol_id.as_bytes()) {
            return Err(MigrationContextError::InvalidProtocolId);
        }
        Ok(Self {
            protocol_id,
            encapsulator_role,
            migration_epoch,
        })
    }

    /// Return the version-qualified protocol identifier.
    #[must_use]
    pub const fn protocol_id(self) -> MigrationProtocolId {
        self.protocol_id
    }

    /// Return the role that performs the current encapsulation.
    #[must_use]
    pub const fn encapsulator_role(self) -> EndpointRole {
        self.encapsulator_role
    }

    /// Return the migration generation.
    #[must_use]
    pub const fn migration_epoch(self) -> MigrationEpoch {
        self.migration_epoch
    }
}

/// Externally asserted public commitments supplied by the protocol layer.
///
/// Construction validates only canonical shape and reserved values. It does not
/// authenticate the committed preimages or prove their transcript scope.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationCommitmentsV1 {
    capability_transcript_hash: CapabilityTranscriptHash,
    transition_state_hash: TransitionStateHash,
    pre_kem_transcript_hash: PreKemTranscriptHash,
}

impl fmt::Debug for MigrationCommitmentsV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationCommitmentsV1([redacted])")
    }
}

impl MigrationCommitmentsV1 {
    /// Construct externally asserted commitments after protocol-layer validation.
    pub fn new(
        capability_transcript_hash: CapabilityTranscriptHash,
        transition_state_hash: TransitionStateHash,
        pre_kem_transcript_hash: PreKemTranscriptHash,
    ) -> Result<Self, MigrationContextError> {
        require_nonzero(
            capability_transcript_hash.as_bytes(),
            MigrationCommitmentField::CapabilityTranscriptHash,
        )?;
        require_nonzero(
            transition_state_hash.as_bytes(),
            MigrationCommitmentField::TransitionStateHash,
        )?;
        require_nonzero(
            pre_kem_transcript_hash.as_bytes(),
            MigrationCommitmentField::PreKemTranscriptHash,
        )?;
        Ok(Self {
            capability_transcript_hash,
            transition_state_hash,
            pre_kem_transcript_hash,
        })
    }

    /// Return the externally asserted capability-negotiation commitment.
    #[must_use]
    pub const fn capability_transcript_hash(self) -> CapabilityTranscriptHash {
        self.capability_transcript_hash
    }

    /// Return the externally asserted migration-state commitment.
    #[must_use]
    pub const fn transition_state_hash(self) -> TransitionStateHash {
        self.transition_state_hash
    }

    /// Return the externally asserted non-circular pre-KEM transcript commitment.
    #[must_use]
    pub const fn pre_kem_transcript_hash(self) -> PreKemTranscriptHash {
        self.pre_kem_transcript_hash
    }
}

/// Canonical, role-normalized migration context version 1.
///
/// Both peers must construct this value independently from authenticated endpoint
/// policies and caller-validated, externally asserted commitments. Equality of
/// this value is not itself peer authentication or transition authorization; it
/// is the exact public tuple committed by ABI 2 ContextBound.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationContextV1 {
    scope: MigrationScopeV1,
    execution_decision: AuthenticatedResolvedSuite,
    endpoint_policies: RoleOrderedEndpointPolicies,
    commitments: MigrationCommitmentsV1,
}

impl fmt::Debug for MigrationContextV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationContextV1([redacted])")
    }
}

impl MigrationContextV1 {
    /// Construct a context directly from authenticated local/peer policy views.
    ///
    /// `local_role` is used only to normalize endpoint-policy ownership into fixed
    /// initiator/responder order. `execution_decision` supplies the indivisible
    /// suite/profile/key-format/policy-state decision expected at the ABI boundary;
    /// both endpoint policies must independently authorize its selected suite.
    pub fn from_authenticated_policies(
        scope: MigrationScopeV1,
        local_role: EndpointRole,
        execution_decision: AuthenticatedResolvedSuite,
        local_policy: &AuthenticatedPolicy,
        peer_policy: &AuthenticatedPolicy,
        commitments: MigrationCommitmentsV1,
    ) -> Result<Self, MigrationContextError> {
        let local = AuthenticatedEndpointPolicy::from_authenticated_policy(
            local_policy,
            execution_decision,
        )?;
        let peer = AuthenticatedEndpointPolicy::from_authenticated_policy(
            peer_policy,
            execution_decision,
        )?;
        let endpoint_policies =
            RoleOrderedEndpointPolicies::from_local_peer(local_role, local, peer)?;
        Self::try_new(scope, execution_decision, endpoint_policies, commitments)
    }

    /// Assemble a context against one explicit common execution decision.
    ///
    /// `execution_decision` must be the same indivisible decision used to project
    /// both endpoint policies. This prevents the application body from committing
    /// one suite while ABI 2 executes under an unrelated trusted policy state.
    pub fn try_new(
        scope: MigrationScopeV1,
        execution_decision: AuthenticatedResolvedSuite,
        endpoint_policies: RoleOrderedEndpointPolicies,
        commitments: MigrationCommitmentsV1,
    ) -> Result<Self, MigrationContextError> {
        validate_context_bound_execution(execution_decision)?;
        if execution_decision != endpoint_policies.execution_decision {
            return Err(MigrationContextError::ExecutionDecisionMismatch);
        }
        let context = Self {
            scope,
            execution_decision,
            endpoint_policies,
            commitments,
        };
        context.validate()?;
        Ok(context)
    }

    /// Return the stable migration scope.
    #[must_use]
    pub const fn scope(self) -> MigrationScopeV1 {
        self.scope
    }

    /// Return the common authenticated execution decision expected at the ABI boundary.
    #[must_use]
    pub const fn execution_decision(self) -> AuthenticatedResolvedSuite {
        self.execution_decision
    }

    /// Return the role-ordered authenticated endpoint policies.
    #[must_use]
    pub const fn endpoint_policies(self) -> RoleOrderedEndpointPolicies {
        self.endpoint_policies
    }

    /// Return the externally asserted public commitments.
    #[must_use]
    pub const fn commitments(self) -> MigrationCommitmentsV1 {
        self.commitments
    }

    /// Encode the exact twelve-field, 315-byte LP8 application body atomically.
    ///
    /// `out` must be exactly [`MIGRATION_CONTEXT_V1_ENCODED_LEN`] bytes. Validation
    /// and encoding happen in a local fixed-size temporary; the caller buffer is
    /// modified only after complete success.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, MigrationContextError> {
        if out.len() != MIGRATION_CONTEXT_V1_ENCODED_LEN {
            return Err(MigrationContextError::InvalidOutputLength);
        }
        self.validate()?;
        let mut encoded = [0u8; MIGRATION_CONTEXT_V1_ENCODED_LEN];
        self.encode_validated(&mut encoded)?;
        out.copy_from_slice(&encoded);
        Ok(encoded.len())
    }

    fn validate(&self) -> Result<(), MigrationContextError> {
        validate_context_bound_execution(self.execution_decision)?;
        if self.execution_decision != self.endpoint_policies.execution_decision {
            return Err(MigrationContextError::ExecutionDecisionMismatch);
        }
        if all_zero(self.scope.protocol_id.as_bytes()) {
            return Err(MigrationContextError::InvalidProtocolId);
        }
        if self.scope.migration_epoch.get() == 0 || self.scope.migration_epoch.get() == u64::MAX {
            return Err(MigrationContextError::InvalidMigrationEpoch);
        }
        require_nonzero(
            self.endpoint_policies.initiator.digest.as_bytes(),
            MigrationCommitmentField::InitiatorPolicyDigest,
        )?;
        require_nonzero(
            self.endpoint_policies.responder.digest.as_bytes(),
            MigrationCommitmentField::ResponderPolicyDigest,
        )?;
        require_nonzero(
            self.commitments.capability_transcript_hash.as_bytes(),
            MigrationCommitmentField::CapabilityTranscriptHash,
        )?;
        require_nonzero(
            self.commitments.transition_state_hash.as_bytes(),
            MigrationCommitmentField::TransitionStateHash,
        )?;
        require_nonzero(
            self.commitments.pre_kem_transcript_hash.as_bytes(),
            MigrationCommitmentField::PreKemTranscriptHash,
        )?;
        if self.execution_decision.resolved().suite().nist_level()
            < self.endpoint_policies.effective_floor.to_u8()
        {
            return Err(MigrationContextError::SuiteBelowSecurityFloor);
        }
        Ok(())
    }

    fn encode_validated(
        &self,
        out: &mut [u8; MIGRATION_CONTEXT_V1_ENCODED_LEN],
    ) -> Result<(), MigrationContextError> {
        CanonicalMigrationFieldsV1::from_context(self).encode_into(out)
    }
}

#[derive(Clone, Copy)]
struct CanonicalMigrationFieldsV1 {
    scope: MigrationScopeV1,
    initiator_policy_digest: PolicyDigest,
    responder_policy_digest: PolicyDigest,
    capability_transcript_hash: CapabilityTranscriptHash,
    selected_suite: HybridSuite,
    effective_floor: SecurityFloor,
    transition_state_hash: TransitionStateHash,
    pre_kem_transcript_hash: PreKemTranscriptHash,
}

impl CanonicalMigrationFieldsV1 {
    const fn from_context(context: &MigrationContextV1) -> Self {
        Self {
            scope: context.scope,
            initiator_policy_digest: context.endpoint_policies.initiator.digest,
            responder_policy_digest: context.endpoint_policies.responder.digest,
            capability_transcript_hash: context.commitments.capability_transcript_hash,
            selected_suite: context.execution_decision.resolved().suite(),
            effective_floor: context.endpoint_policies.effective_floor,
            transition_state_hash: context.commitments.transition_state_hash,
            pre_kem_transcript_hash: context.commitments.pre_kem_transcript_hash,
        }
    }

    fn encode_into(
        &self,
        out: &mut [u8; MIGRATION_CONTEXT_V1_ENCODED_LEN],
    ) -> Result<(), MigrationContextError> {
        let mut writer = Lp8Writer::new(out);
        writer
            .field(MIGRATION_CONTEXT_DOMAIN)
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(&MIGRATION_CONTEXT_SCHEMA_VERSION.to_be_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(self.scope.protocol_id.as_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(&[self.scope.encapsulator_role as u8])
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(&self.scope.migration_epoch.get().to_be_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(self.initiator_policy_digest.as_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(self.responder_policy_digest.as_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(self.capability_transcript_hash.as_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(&[self.selected_suite.to_u8()])
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(&[self.effective_floor.to_u8()])
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(self.transition_state_hash.as_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        writer
            .field(self.pre_kem_transcript_hash.as_bytes())
            .map_err(|_| MigrationContextError::EncodingInvariant)?;
        if !writer.is_empty() {
            return Err(MigrationContextError::EncodingInvariant);
        }
        Ok(())
    }
}

/// Exact ABI 2 application-context bytes for one validated migration context.
///
/// This adapter permits only ABI 2's fixed ML-KEM-768 + X25519 suite. The bytes
/// are the 315-byte application body, not the ABI's outer policy-context wrapper.
#[derive(Clone, Eq, PartialEq)]
pub struct Abi2MigrationApplicationContextV1 {
    encoded: [u8; MIGRATION_CONTEXT_V1_ENCODED_LEN],
    expected_execution_state: TrustedPolicyState,
}

impl fmt::Debug for Abi2MigrationApplicationContextV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Abi2MigrationApplicationContextV1([redacted])")
    }
}

impl Abi2MigrationApplicationContextV1 {
    /// Borrow the exact bytes to pass to both ABI 2 encapsulation and decapsulation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MIGRATION_CONTEXT_V1_ENCODED_LEN] {
        &self.encoded
    }

    /// Return the trusted policy state that the ABI 2 decision must encode.
    ///
    /// Frozen ABI 2 decision bytes `4..40` must equal this value's canonical
    /// 36-byte encoding before the adapter bytes are used for either KEM direction.
    #[must_use]
    pub const fn expected_execution_state(&self) -> TrustedPolicyState {
        self.expected_execution_state
    }
}

impl TryFrom<&MigrationContextV1> for Abi2MigrationApplicationContextV1 {
    type Error = MigrationContextError;

    fn try_from(context: &MigrationContextV1) -> Result<Self, Self::Error> {
        let execution = context.execution_decision;
        validate_context_bound_execution(execution)?;
        if execution.resolved().suite() != HybridSuite::MlKem768X25519 {
            return Err(MigrationContextError::Abi2IncompatibleSuite);
        }
        if execution != context.endpoint_policies.execution_decision {
            return Err(MigrationContextError::ExecutionDecisionMismatch);
        }
        let mut encoded = [0u8; MIGRATION_CONTEXT_V1_ENCODED_LEN];
        context.encode_into(&mut encoded)?;
        Ok(Self {
            encoded,
            expected_execution_state: execution.trusted_state(),
        })
    }
}

impl AsRef<[u8]> for Abi2MigrationApplicationContextV1 {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

fn validate_context_bound_execution(
    execution: AuthenticatedResolvedSuite,
) -> Result<(), MigrationContextError> {
    let resolved = execution.resolved();
    if resolved.profile() != Profile::ContextBound || resolved.key_format() != KeyFormat::Expanded {
        Err(MigrationContextError::ExecutionDecisionNotContextBound)
    } else {
        Ok(())
    }
}

fn require_nonzero(
    bytes: &[u8],
    field: MigrationCommitmentField,
) -> Result<(), MigrationContextError> {
    if all_zero(bytes) {
        Err(MigrationContextError::ZeroCommitment(field))
    } else {
        Ok(())
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod vector_tests;
