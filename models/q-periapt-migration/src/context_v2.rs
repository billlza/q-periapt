//! Accepted-path Migration Contract V2 context over unchanged ABI 2.

use core::fmt;

use q_periapt_policy::{
    AuthenticatedPolicy, AuthenticatedResolvedSuite, HybridSuite, TrustedPolicyState,
};
use sha3::{Digest, Sha3_256};

use crate::capability::{AuthenticatedNegotiationV1, CapabilityError};
use crate::codec::Lp8Writer;
use crate::state::{
    validate_committed_execution, CommittedMigrationStateV1, ComponentMode, MigrationStateError,
    StateRevisionV1,
};
use crate::transcript::{PreKemTranscriptV1, TranscriptError};
use crate::{
    validate_context_bound_execution, AuthenticatedEndpointPolicy, EndpointRole,
    MigrationContextError, RoleOrderedEndpointPolicies, SecurityFloor,
};

/// Domain for the authenticated Migration Contract V2 application body.
pub const MIGRATION_CONTEXT_V2_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-CONTEXT/v2";
/// V2 schema version.
pub const MIGRATION_CONTEXT_V2_SCHEMA_VERSION: u16 = 2;
/// Exact thirteen-field V2 application-context length.
pub const MIGRATION_CONTEXT_V2_ENCODED_LEN: usize = 324;

const _: () = {
    assert!(MIGRATION_CONTEXT_V2_DOMAIN.len() == 30);
    assert!(
        (13 * 8)
            + MIGRATION_CONTEXT_V2_DOMAIN.len()
            + core::mem::size_of::<u16>()
            + 16
            + core::mem::size_of::<u8>()
            + core::mem::size_of::<u64>()
            + (5 * 32)
            + core::mem::size_of::<u8>()
            + core::mem::size_of::<u8>()
            + core::mem::size_of::<u8>()
            == MIGRATION_CONTEXT_V2_ENCODED_LEN
    );
    assert!(MIGRATION_CONTEXT_V2_ENCODED_LEN <= q_periapt_core::MAX_APPLICATION_CONTEXT_BYTES);
};

/// Digest of one exact V2 application body.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MigrationContextV2Digest([u8; 32]);

impl MigrationContextV2Digest {
    /// Borrow the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MigrationContextV2Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationContextV2Digest([redacted])")
    }
}

/// Canonical V2 context derived only from authenticated policies, offers, and committed state.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationContextV2 {
    local_role: EndpointRole,
    encapsulator_role: EndpointRole,
    execution: AuthenticatedResolvedSuite,
    endpoint_policies: RoleOrderedEndpointPolicies,
    negotiation: AuthenticatedNegotiationV1,
    committed_state: CommittedMigrationStateV1,
    pre_kem_digest: crate::transcript::PreKemTranscriptDigest,
}

/// Authenticated inputs for deriving one exact Migration Contract V2 context.
///
/// Every security-sensitive value remains represented by its authenticated or
/// committed domain type; the record only names the dependency set atomically.
#[derive(Clone, Copy)]
pub struct AuthenticatedMigrationContextV2Input<'a> {
    /// Role of the local endpoint constructing its view.
    pub local_role: EndpointRole,
    /// Role performing KEM encapsulation for this session.
    pub encapsulator_role: EndpointRole,
    /// Common authenticated execution decision.
    pub execution: AuthenticatedResolvedSuite,
    /// Authenticated local endpoint policy.
    pub local_policy: &'a AuthenticatedPolicy,
    /// Authenticated peer endpoint policy.
    pub peer_policy: &'a AuthenticatedPolicy,
    /// Exact committed migration state.
    pub committed_state: CommittedMigrationStateV1,
    /// Role-ordered authenticated capability negotiation.
    pub negotiation: AuthenticatedNegotiationV1,
    /// Typed pre-KEM transcript derived from the same negotiation and state.
    pub pre_kem: &'a PreKemTranscriptV1,
}

impl fmt::Debug for MigrationContextV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationContextV2([redacted])")
    }
}

impl MigrationContextV2 {
    /// Derive all encoded V2 fields from one immutable authenticated contract snapshot.
    pub fn from_authenticated_contract(
        input: AuthenticatedMigrationContextV2Input<'_>,
    ) -> Result<Self, MigrationContractError> {
        let AuthenticatedMigrationContextV2Input {
            local_role,
            encapsulator_role,
            execution,
            local_policy,
            peer_policy,
            committed_state,
            negotiation,
            pre_kem,
        } = input;
        validate_context_bound_execution(execution).map_err(MigrationContractError::Context)?;
        validate_committed_execution(committed_state, execution)
            .map_err(MigrationContractError::State)?;
        if negotiation.execution() != execution
            || negotiation.state_revision() != committed_state.revision()
            || negotiation.protocol_id() != committed_state.state().protocol_id()
            || pre_kem.state_revision() != committed_state.revision()
            || pre_kem.encapsulator_role() != encapsulator_role
            || pre_kem.negotiation_digest() != negotiation.digest()
        {
            return Err(MigrationContractError::SnapshotMismatch);
        }
        let local = AuthenticatedEndpointPolicy::from_authenticated_policy(local_policy, execution)
            .map_err(MigrationContractError::Context)?;
        let peer = AuthenticatedEndpointPolicy::from_authenticated_policy(peer_policy, execution)
            .map_err(MigrationContractError::Context)?;
        let endpoint_policies =
            RoleOrderedEndpointPolicies::from_local_peer(local_role, local, peer)
                .map_err(MigrationContractError::Context)?;
        if endpoint_policies.initiator().digest().as_bytes()
            != &negotiation.initiator_policy_state().digest()
            || endpoint_policies.responder().digest().as_bytes()
                != &negotiation.responder_policy_state().digest()
        {
            return Err(MigrationContractError::PolicyMismatch);
        }
        if negotiation.effective_floor() < endpoint_policies.effective_floor() {
            return Err(MigrationContractError::FloorMismatch);
        }
        Ok(Self {
            local_role,
            encapsulator_role,
            execution,
            endpoint_policies,
            negotiation,
            committed_state,
            pre_kem_digest: pre_kem.digest(),
        })
    }

    /// Encode the exact thirteen LP8 fields atomically.
    pub fn encode(&self) -> Result<[u8; MIGRATION_CONTEXT_V2_ENCODED_LEN], MigrationContractError> {
        self.validate()?;
        let state = self.committed_state.state();
        let revision = self.committed_state.revision();
        let mut encoded = [0u8; MIGRATION_CONTEXT_V2_ENCODED_LEN];
        let mut writer = Lp8Writer::new(&mut encoded);
        let schema = MIGRATION_CONTEXT_V2_SCHEMA_VERSION.to_be_bytes();
        let role = [self.encapsulator_role as u8];
        let epoch = revision.epoch().to_be_bytes();
        let suite = [self.execution.resolved().suite().to_u8()];
        let floor = [self.negotiation.effective_floor().to_u8()];
        let mode = [state.posture().component_mode().to_u8()];
        for field in [
            MIGRATION_CONTEXT_V2_DOMAIN,
            schema.as_slice(),
            state.protocol_id().as_bytes().as_slice(),
            role.as_slice(),
            epoch.as_slice(),
            self.endpoint_policies
                .initiator()
                .digest()
                .as_bytes()
                .as_slice(),
            self.endpoint_policies
                .responder()
                .digest()
                .as_bytes()
                .as_slice(),
            self.negotiation.digest().as_bytes().as_slice(),
            suite.as_slice(),
            floor.as_slice(),
            revision.digest().as_bytes().as_slice(),
            self.pre_kem_digest.as_bytes().as_slice(),
            mode.as_slice(),
        ] {
            writer
                .field(field)
                .map_err(|_| MigrationContractError::EncodingInvariant)?;
        }
        if !writer.is_empty() {
            return Err(MigrationContractError::EncodingInvariant);
        }
        Ok(encoded)
    }

    /// Return SHA3-256 over the exact V2 body.
    pub fn digest(&self) -> Result<MigrationContextV2Digest, MigrationContractError> {
        Ok(MigrationContextV2Digest(
            Sha3_256::digest(self.encode()?).into(),
        ))
    }

    /// Return the common authenticated execution decision.
    #[must_use]
    pub const fn execution(&self) -> AuthenticatedResolvedSuite {
        self.execution
    }

    /// Return the exact committed state revision.
    #[must_use]
    pub const fn state_revision(&self) -> StateRevisionV1 {
        self.committed_state.revision()
    }

    /// Return the agreed encapsulator role.
    #[must_use]
    pub const fn encapsulator_role(&self) -> EndpointRole {
        self.encapsulator_role
    }

    /// Return this process's role, retained locally and never encoded.
    #[must_use]
    pub const fn local_role(&self) -> EndpointRole {
        self.local_role
    }

    /// Return the effective authenticated floor.
    #[must_use]
    pub const fn effective_floor(&self) -> SecurityFloor {
        self.negotiation.effective_floor()
    }

    /// Return the committed component mode.
    #[must_use]
    pub const fn component_mode(&self) -> ComponentMode {
        self.committed_state.state().posture().component_mode()
    }

    fn validate(&self) -> Result<(), MigrationContractError> {
        validate_context_bound_execution(self.execution)
            .map_err(MigrationContractError::Context)?;
        validate_committed_execution(self.committed_state, self.execution)
            .map_err(MigrationContractError::State)?;
        if self.negotiation.execution() != self.execution
            || self.negotiation.state_revision() != self.committed_state.revision()
        {
            return Err(MigrationContractError::SnapshotMismatch);
        }
        Ok(())
    }
}

/// Exact ABI 2 input derived from an accepted-path V2 context.
#[derive(Clone, Eq, PartialEq)]
pub struct Abi2MigrationApplicationContextV2 {
    encoded: [u8; MIGRATION_CONTEXT_V2_ENCODED_LEN],
    expected_execution_state: TrustedPolicyState,
    state_revision: StateRevisionV1,
}

impl fmt::Debug for Abi2MigrationApplicationContextV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Abi2MigrationApplicationContextV2([redacted])")
    }
}

impl Abi2MigrationApplicationContextV2 {
    /// Borrow the exact bytes to pass unchanged as ABI 2 `application_context`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MIGRATION_CONTEXT_V2_ENCODED_LEN] {
        &self.encoded
    }

    /// Return the exact execution-policy state required in ABI2 decision bytes 4..40.
    #[must_use]
    pub const fn expected_execution_state(&self) -> TrustedPolicyState {
        self.expected_execution_state
    }

    /// Return the state revision that acceptance must recheck.
    #[must_use]
    pub const fn state_revision(&self) -> StateRevisionV1 {
        self.state_revision
    }
}

impl TryFrom<&MigrationContextV2> for Abi2MigrationApplicationContextV2 {
    type Error = MigrationContractError;

    fn try_from(context: &MigrationContextV2) -> Result<Self, Self::Error> {
        context.validate()?;
        if context.component_mode() == ComponentMode::PostQuantumOnly {
            return Err(MigrationContractError::TraditionalComponentForbidden);
        }
        if context.execution.resolved().suite() != HybridSuite::MlKem768X25519 {
            return Err(MigrationContractError::Abi2IncompatibleSuite);
        }
        Ok(Self {
            encoded: context.encode()?,
            expected_execution_state: context.execution.trusted_state(),
            state_revision: context.state_revision(),
        })
    }
}

impl AsRef<[u8]> for Abi2MigrationApplicationContextV2 {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

/// V2 contract derivation or ABI adapter failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MigrationContractError {
    /// Existing authenticated-policy/context validation failed.
    Context(MigrationContextError),
    /// Signed/committed state validation failed.
    State(MigrationStateError),
    /// Capability negotiation validation failed.
    Capability(CapabilityError),
    /// Typed transcript validation failed.
    Transcript(TranscriptError),
    /// Inputs did not belong to one immutable state/negotiation snapshot.
    SnapshotMismatch,
    /// Role-ordered endpoint policies differed from signed offers.
    PolicyMismatch,
    /// Negotiation floor was lower than an authenticated endpoint floor.
    FloorMismatch,
    /// Frozen ABI 2 cannot execute a traditional-forbidden state.
    TraditionalComponentForbidden,
    /// Frozen ABI 2 supports only ML-KEM-768 + X25519.
    Abi2IncompatibleSuite,
    /// A fixed-layout invariant failed.
    EncodingInvariant,
}

impl fmt::Display for MigrationContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "migration contract rejected: {self:?}")
    }
}

impl std::error::Error for MigrationContractError {}
