//! Witness V2 authority value types and their canonical codecs.
//!
//! This module defines the typed authority values consumed by the pure
//! `authority` state machine (which re-exports them unchanged) and is the
//! single byte-level definition shared by durable Store V2 records and the
//! authenticated Authority Wire V3 protocol. Protocol modules may restrict
//! which domain values they admit, but must not define a parallel
//! representation for those values.

use core::fmt;

use crate::authority::AuthoritySnapshotV2;
use crate::codec::{encode_domain, require_domain, CodecError, Decoder, Encoder, MAX_FRAME_BYTES};

pub(crate) const HARD_MAX_RECEIPTS: usize = 4096;
pub(crate) const HARD_MAX_CAPABILITIES: usize = 4096;
pub(crate) const HARD_MAX_KEYS: usize = 1024;
pub(crate) const HARD_MIN_LEASE_TTL_MILLIS: u64 = 10_000;
pub(crate) const HARD_MAX_LEASE_TTL_MILLIS: u64 = 5 * 60 * 1000;

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

macro_rules! authority_identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Construct an identifier from exact nonzero bytes.
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, AuthorityValueErrorV2> {
                nonzero(&bytes)
                    .then_some(Self(bytes))
                    .ok_or(AuthorityValueErrorV2::InvalidIdentifier)
            }

            /// Borrow the exact opaque bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

authority_identifier!(
    ProcessInstanceIdV2,
    "An ephemeral process identity that must never be restored from disk."
);
authority_identifier!(
    AuthorityEpochV2,
    "A fresh identity for one explicitly provisioned authority-store epoch."
);
authority_identifier!(
    StateFenceV2,
    "An unpredictable fence changed by every migration-state transition."
);
authority_identifier!(
    CapabilityIdV2,
    "A current-state-scoped authenticated capability-session replay identifier."
);

/// Version-scoped idempotent authority-operation identifier.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationIdV2 {
    expected_authority_version: u64,
    random_id: [u8; 32],
}

impl OperationIdV2 {
    /// Construct an operation identifier for one exact nonzero predecessor version.
    pub fn new(
        expected_authority_version: u64,
        random_id: [u8; 32],
    ) -> Result<Self, AuthorityValueErrorV2> {
        if expected_authority_version == 0 {
            return Err(AuthorityValueErrorV2::InvalidCounter);
        }
        if !nonzero(&random_id) {
            return Err(AuthorityValueErrorV2::InvalidIdentifier);
        }
        Ok(Self {
            expected_authority_version,
            random_id,
        })
    }

    /// Return the exact predecessor authority version in this identifier.
    #[must_use]
    pub const fn expected_authority_version(self) -> u64 {
        self.expected_authority_version
    }

    /// Borrow the opaque random component needed by a typed persistence codec.
    #[must_use]
    pub const fn random_id(&self) -> &[u8; 32] {
        &self.random_id
    }
}

impl fmt::Debug for OperationIdV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationIdV2")
            .field(
                "expected_authority_version",
                &self.expected_authority_version,
            )
            .field("random_id", &"[redacted]")
            .finish()
    }
}

/// State-and-lease-scoped accepted-key identifier that cannot alias after fencing.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AcceptedKeyIdV2 {
    state_global_generation: u64,
    lease_generation: u64,
    random_id: [u8; 32],
}

impl AcceptedKeyIdV2 {
    /// Construct an accepted-key identifier for one exact state and lease generation.
    pub fn new(
        state_global_generation: u64,
        lease_generation: u64,
        random_id: [u8; 32],
    ) -> Result<Self, AuthorityValueErrorV2> {
        if state_global_generation == 0
            || state_global_generation == u64::MAX
            || lease_generation == 0
        {
            return Err(AuthorityValueErrorV2::InvalidCounter);
        }
        if !nonzero(&random_id) {
            return Err(AuthorityValueErrorV2::InvalidIdentifier);
        }
        Ok(Self {
            state_global_generation,
            lease_generation,
            random_id,
        })
    }

    /// Return the exact migration-state global generation that owns this identifier.
    #[must_use]
    pub const fn state_global_generation(self) -> u64 {
        self.state_global_generation
    }

    /// Return the exact lease generation that owns this key identifier.
    #[must_use]
    pub const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Borrow the opaque random component needed by a typed persistence codec.
    #[must_use]
    pub const fn random_id(&self) -> &[u8; 32] {
        &self.random_id
    }
}

impl fmt::Debug for AcceptedKeyIdV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedKeyIdV2")
            .field("state_global_generation", &self.state_global_generation)
            .field("lease_generation", &self.lease_generation)
            .field("random_id", &"[redacted]")
            .finish()
    }
}

/// Invalid pure authority value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthorityValueErrorV2 {
    /// A required identifier was all zero.
    InvalidIdentifier,
    /// A counter used a reserved value.
    InvalidCounter,
    /// A digest was all zero.
    InvalidDigest,
    /// A transition was not the exact legal successor.
    InvalidTransition,
    /// A configured bound or lease lifetime was invalid.
    InvalidLimit,
}

impl fmt::Display for AuthorityValueErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentifier => "authority identifier must be nonzero",
            Self::InvalidCounter => "authority counter uses a reserved value",
            Self::InvalidDigest => "authority digest must be nonzero",
            Self::InvalidTransition => "authority transition is not an exact successor",
            Self::InvalidLimit => "authority resource or lease limit is invalid",
        })
    }
}

impl std::error::Error for AuthorityValueErrorV2 {}

/// Exact four-field migration-state identity used by Witness V2.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StateRevisionV2 {
    global_generation: u64,
    chain_id: [u8; 32],
    epoch: u64,
    digest: [u8; 32],
}

impl StateRevisionV2 {
    /// Construct an exact non-sentinel migration revision.
    pub fn new(
        global_generation: u64,
        chain_id: [u8; 32],
        epoch: u64,
        digest: [u8; 32],
    ) -> Result<Self, AuthorityValueErrorV2> {
        if global_generation == 0
            || global_generation == u64::MAX
            || epoch == 0
            || epoch == u64::MAX
        {
            return Err(AuthorityValueErrorV2::InvalidCounter);
        }
        if !nonzero(&chain_id) {
            return Err(AuthorityValueErrorV2::InvalidIdentifier);
        }
        if !nonzero(&digest) {
            return Err(AuthorityValueErrorV2::InvalidDigest);
        }
        Ok(Self {
            global_generation,
            chain_id,
            epoch,
            digest,
        })
    }

    /// Return the never-reset global generation.
    #[must_use]
    pub const fn global_generation(self) -> u64 {
        self.global_generation
    }

    /// Borrow the migration lineage identifier.
    #[must_use]
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Return the lineage-local epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Borrow the exact migration-state digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for StateRevisionV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateRevisionV2")
            .field("global_generation", &self.global_generation)
            .field("chain_id", &"[redacted]")
            .field("epoch", &self.epoch)
            .field("digest", &"[redacted]")
            .finish()
    }
}

/// Exact migration revision and its writer fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateHeadV2 {
    revision: StateRevisionV2,
    fence: StateFenceV2,
}

impl StateHeadV2 {
    /// Pair an exact migration revision with a nonzero fence.
    #[must_use]
    pub const fn new(revision: StateRevisionV2, fence: StateFenceV2) -> Self {
        Self { revision, fence }
    }

    /// Return the exact migration revision.
    #[must_use]
    pub const fn revision(self) -> StateRevisionV2 {
        self.revision
    }

    /// Return the state writer fence.
    #[must_use]
    pub const fn fence(self) -> StateFenceV2 {
        self.fence
    }
}

/// Exact deployment-configuration generation and digest.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeploymentConfigRevisionV2 {
    generation: u64,
    digest: [u8; 32],
}

impl DeploymentConfigRevisionV2 {
    /// Construct a non-sentinel configuration revision.
    pub fn new(generation: u64, digest: [u8; 32]) -> Result<Self, AuthorityValueErrorV2> {
        if generation == 0 || generation == u64::MAX {
            return Err(AuthorityValueErrorV2::InvalidCounter);
        }
        if !nonzero(&digest) {
            return Err(AuthorityValueErrorV2::InvalidDigest);
        }
        Ok(Self { generation, digest })
    }

    /// Return the monotonic configuration generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Borrow the exact canonical configuration digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for DeploymentConfigRevisionV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeploymentConfigRevisionV2")
            .field("generation", &self.generation)
            .field("digest", &"[redacted]")
            .finish()
    }
}

/// Explicit resource and lease bounds for the pure authority state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityLimitsV2 {
    max_receipts: usize,
    max_capabilities: usize,
    max_keys: usize,
    lease_ttl_millis: u64,
}

impl AuthorityLimitsV2 {
    /// Construct nonzero bounds no larger than the reviewed hard maxima.
    pub fn new(
        max_receipts: usize,
        max_capabilities: usize,
        max_keys: usize,
        lease_ttl_millis: u64,
    ) -> Result<Self, AuthorityValueErrorV2> {
        if max_receipts == 0
            || max_receipts > HARD_MAX_RECEIPTS
            || max_capabilities == 0
            || max_capabilities > HARD_MAX_CAPABILITIES
            || max_keys == 0
            || max_keys > HARD_MAX_KEYS
            || !(HARD_MIN_LEASE_TTL_MILLIS..=HARD_MAX_LEASE_TTL_MILLIS).contains(&lease_ttl_millis)
        {
            return Err(AuthorityValueErrorV2::InvalidLimit);
        }
        Ok(Self {
            max_receipts,
            max_capabilities,
            max_keys,
            lease_ttl_millis,
        })
    }

    pub(crate) const fn max_receipts(self) -> usize {
        self.max_receipts
    }

    pub(crate) const fn max_capabilities(self) -> usize {
        self.max_capabilities
    }

    pub(crate) const fn max_keys(self) -> usize {
        self.max_keys
    }

    pub(crate) const fn lease_ttl_millis(self) -> u64 {
        self.lease_ttl_millis
    }
}

/// Failure to read the external witness's trusted time source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedClockErrorV2;

impl fmt::Display for TrustedClockErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("trusted witness clock unavailable")
    }
}

impl std::error::Error for TrustedClockErrorV2 {}

/// Injected trusted-clock boundary used by the pure authority transition model.
pub trait TrustedClockV2 {
    /// Return current witness time as nondecreasing-compatible Unix milliseconds.
    fn now_millis(&self) -> Result<u64, TrustedClockErrorV2>;
}

/// Exact process-instance generation and ephemeral identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceFenceV2 {
    generation: u64,
    instance_id: ProcessInstanceIdV2,
}

impl InstanceFenceV2 {
    /// Construct a nonzero lease generation for one process identity.
    pub fn new(
        generation: u64,
        instance_id: ProcessInstanceIdV2,
    ) -> Result<Self, AuthorityValueErrorV2> {
        if generation == 0 {
            return Err(AuthorityValueErrorV2::InvalidCounter);
        }
        Ok(Self {
            generation,
            instance_id,
        })
    }

    /// Return the lease generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Return the ephemeral process identity.
    #[must_use]
    pub const fn instance_id(self) -> ProcessInstanceIdV2 {
        self.instance_id
    }
}

/// One witness-clock-bounded exclusive instance lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceLeaseV2 {
    fence: InstanceFenceV2,
    expires_at_millis: u64,
}

impl InstanceLeaseV2 {
    pub(crate) const fn restore(fence: InstanceFenceV2, expires_at_millis: u64) -> Self {
        Self {
            fence,
            expires_at_millis,
        }
    }

    /// Return the exact instance fence.
    #[must_use]
    pub const fn fence(self) -> InstanceFenceV2 {
        self.fence
    }

    /// Return the exclusive upper bound of the lease interval.
    #[must_use]
    pub const fn expires_at_millis(self) -> u64 {
        self.expires_at_millis
    }
}

/// Closed migration-state transition category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateTransitionKindV2 {
    /// Advance within the current lineage.
    Advance,
    /// Enter a new explicitly authorized lineage at epoch one.
    AuthorizedReset,
}

/// Exact predecessor and successor migration heads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateAdvanceV2 {
    kind: StateTransitionKindV2,
    expected: StateHeadV2,
    next: StateHeadV2,
}

impl StateAdvanceV2 {
    /// Validate a normal advance or authorized-reset successor.
    pub fn new(
        kind: StateTransitionKindV2,
        expected: StateHeadV2,
        next: StateHeadV2,
    ) -> Result<Self, AuthorityValueErrorV2> {
        let expected_revision = expected.revision;
        let next_revision = next.revision;
        let common = expected_revision.global_generation.checked_add(1)
            == Some(next_revision.global_generation)
            && expected_revision.digest != next_revision.digest
            && expected.fence != next.fence;
        let kind_valid = match kind {
            StateTransitionKindV2::Advance => {
                expected_revision.chain_id == next_revision.chain_id
                    && expected_revision.epoch.checked_add(1) == Some(next_revision.epoch)
            }
            StateTransitionKindV2::AuthorizedReset => {
                expected_revision.chain_id != next_revision.chain_id && next_revision.epoch == 1
            }
        };
        if !common || !kind_valid {
            return Err(AuthorityValueErrorV2::InvalidTransition);
        }
        Ok(Self {
            kind,
            expected,
            next,
        })
    }

    /// Return the closed transition kind.
    #[must_use]
    pub const fn kind(self) -> StateTransitionKindV2 {
        self.kind
    }

    /// Return the required predecessor head.
    #[must_use]
    pub const fn expected(self) -> StateHeadV2 {
        self.expected
    }

    /// Return the exact successor head.
    #[must_use]
    pub const fn next(self) -> StateHeadV2 {
        self.next
    }
}

/// Exact predecessor and successor deployment revisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigAdvanceV2 {
    expected: DeploymentConfigRevisionV2,
    next: DeploymentConfigRevisionV2,
}

impl ConfigAdvanceV2 {
    /// Validate an exact non-equivocating configuration successor.
    pub fn new(
        expected: DeploymentConfigRevisionV2,
        next: DeploymentConfigRevisionV2,
    ) -> Result<Self, AuthorityValueErrorV2> {
        if expected.generation.checked_add(1) != Some(next.generation)
            || expected.digest == next.digest
        {
            return Err(AuthorityValueErrorV2::InvalidTransition);
        }
        Ok(Self { expected, next })
    }

    /// Return the required predecessor revision.
    #[must_use]
    pub const fn expected(self) -> DeploymentConfigRevisionV2 {
        self.expected
    }

    /// Return the exact successor revision.
    #[must_use]
    pub const fn next(self) -> DeploymentConfigRevisionV2 {
        self.next
    }
}

/// Closed set of security-authority mutations modeled by Stage 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityMutationV2 {
    /// Acquire the sole process lease at the exact prior lease generation.
    AcquireLease {
        /// Lease generation observed before this acquisition.
        expected_lease_generation: u64,
        /// Fresh process identity generated after every process start.
        instance_id: ProcessInstanceIdV2,
    },
    /// Extend the current exact process lease.
    RenewLease {
        /// Exact current process fence.
        fence: InstanceFenceV2,
    },
    /// Relinquish the current exact process lease.
    ReleaseLease {
        /// Exact current process fence.
        fence: InstanceFenceV2,
    },
    /// Advance the migration state and invalidate state-scoped runtime records.
    AdvanceState {
        /// Exact current process fence.
        fence: InstanceFenceV2,
        /// Validated exact migration-state transition.
        advance: StateAdvanceV2,
    },
    /// Advance deployment configuration and fence the old configured process.
    AdvanceConfig {
        /// Exact current process fence.
        fence: InstanceFenceV2,
        /// Validated exact configuration transition.
        advance: ConfigAdvanceV2,
    },
    /// Consume one authenticated capability identifier once in the current state.
    ///
    /// Before invoking this mutation, a Stage 2 adapter must verify that the typed capability
    /// envelope commits to the exact current state head and deployment configuration.
    ConsumeCapability {
        /// Exact current process fence.
        fence: InstanceFenceV2,
        /// Capability identifier to consume.
        capability_id: CapabilityIdV2,
    },
    /// Register one accepted-key handle against its consumed capability.
    RegisterKey {
        /// Exact current process fence.
        fence: InstanceFenceV2,
        /// Previously consumed capability identifier.
        capability_id: CapabilityIdV2,
        /// Fresh opaque accepted-key identifier.
        key_id: AcceptedKeyIdV2,
    },
    /// Revoke one registered accepted-key handle.
    RevokeKey {
        /// Exact current process fence.
        fence: InstanceFenceV2,
        /// Accepted-key identifier to revoke.
        key_id: AcceptedKeyIdV2,
    },
}

/// One exact authority intent before deterministic evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityIntentV2 {
    operation_id: OperationIdV2,
    expected_authority_version: u64,
    expected_config: DeploymentConfigRevisionV2,
    mutation: AuthorityMutationV2,
}

impl AuthorityIntentV2 {
    /// Bind one operation ID to exact authority, configuration, and mutation inputs.
    pub fn new(
        operation_id: OperationIdV2,
        expected_authority_version: u64,
        expected_config: DeploymentConfigRevisionV2,
        mutation: AuthorityMutationV2,
    ) -> Result<Self, AuthorityValueErrorV2> {
        if expected_authority_version == 0 {
            return Err(AuthorityValueErrorV2::InvalidCounter);
        }
        if operation_id.expected_authority_version != expected_authority_version {
            return Err(AuthorityValueErrorV2::InvalidTransition);
        }
        Ok(Self {
            operation_id,
            expected_authority_version,
            expected_config,
            mutation,
        })
    }

    /// Return the exact idempotency identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationIdV2 {
        self.operation_id
    }

    /// Return the required predecessor authority version.
    #[must_use]
    pub const fn expected_authority_version(self) -> u64 {
        self.expected_authority_version
    }

    /// Return the exact deployment configuration required by this operation.
    #[must_use]
    pub const fn expected_config(self) -> DeploymentConfigRevisionV2 {
        self.expected_config
    }

    /// Return the closed mutation.
    #[must_use]
    pub const fn mutation(self) -> AuthorityMutationV2 {
        self.mutation
    }
}

/// Stable semantic rejection recorded for an exact authority operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRejectionV2 {
    /// The configured deployment revision did not match.
    ConfigurationMismatch,
    /// A non-expired process lease already exists.
    LeaseHeld,
    /// The expected lease generation was stale or from the future.
    LeaseGenerationMismatch,
    /// No process lease exists.
    LeaseAbsent,
    /// The process lease reached its witness-clock expiry.
    LeaseExpired,
    /// The process identity or lease generation did not match.
    FenceMismatch,
    /// A renewal did not strictly extend the current lease.
    LeaseRenewalNotExtended,
    /// A mutation-specific monotonic counter or trusted-time sum overflowed.
    MutationOverflow,
    /// The expected migration-state head did not match.
    StateMismatch,
    /// The expected configuration predecessor did not match.
    ConfigTransitionMismatch,
    /// The authenticated capability identifier was already consumed in the current state.
    CapabilityReplay,
    /// The referenced capability identifier was never consumed.
    CapabilityUnknown,
    /// The capability belongs to a retired state, configuration, or lease.
    CapabilityStale,
    /// The capability has already been bound to an accepted key.
    CapabilityAlreadyBound,
    /// The accepted-key identifier was already registered.
    KeyAlreadyRegistered,
    /// The accepted-key identifier belongs to a different migration-state generation.
    KeyStateGenerationMismatch,
    /// The accepted-key identifier belongs to a different lease generation.
    KeyLeaseGenerationMismatch,
    /// The accepted-key identifier was not registered.
    KeyUnknown,
    /// The accepted-key identifier was already revoked.
    KeyRevoked,
    /// The capability table reached its explicit bound.
    CapabilityCapacityExceeded,
    /// The accepted-key table reached its explicit bound.
    KeyCapacityExceeded,
}

/// Applied or rejected disposition stored in an exact receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityDispositionV2 {
    /// The closed mutation was atomically applied.
    Applied,
    /// The mutation was rejected without a partial domain-state change.
    Rejected(AuthorityRejectionV2),
}

/// Immutable receipt for one exact authority intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityReceiptV2 {
    intent: AuthorityIntentV2,
    disposition: AuthorityDispositionV2,
    resulting_authority_version: u64,
}

impl AuthorityReceiptV2 {
    pub(crate) fn restore(
        intent: AuthorityIntentV2,
        disposition: AuthorityDispositionV2,
        resulting_authority_version: u64,
    ) -> Result<Self, AuthorityRestoreErrorV2> {
        if intent.expected_authority_version.checked_add(1) != Some(resulting_authority_version) {
            return Err(AuthorityRestoreErrorV2::Invalid);
        }
        Ok(Self {
            intent,
            disposition,
            resulting_authority_version,
        })
    }

    /// Return the complete stored intent.
    #[must_use]
    pub const fn intent(self) -> AuthorityIntentV2 {
        self.intent
    }

    /// Return the stable applied or rejected result.
    #[must_use]
    pub const fn disposition(self) -> AuthorityDispositionV2 {
        self.disposition
    }

    /// Return the authority version consumed by this receipt.
    #[must_use]
    pub const fn resulting_authority_version(self) -> u64 {
        self.resulting_authority_version
    }

    /// Return the exact locator required to acknowledge this stored result.
    #[must_use]
    pub const fn locator(self) -> ReceiptLocatorV2 {
        ReceiptLocatorV2 {
            operation_id: self.intent.operation_id,
            resulting_authority_version: self.resulting_authority_version,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseMutationKindV2 {
    Acquire,
    Renew,
    Release,
}

pub(crate) fn reachable_lease_receipt_kind(
    receipt: &AuthorityReceiptV2,
) -> Option<LeaseMutationKindV2> {
    let intent = receipt.intent();
    let expected_version = intent.expected_authority_version();
    match (intent.mutation(), receipt.disposition()) {
        (
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                ..
            },
            AuthorityDispositionV2::Applied
            | AuthorityDispositionV2::Rejected(AuthorityRejectionV2::MutationOverflow),
        ) if expected_lease_generation < expected_version => Some(LeaseMutationKindV2::Acquire),
        (
            AuthorityMutationV2::AcquireLease { .. },
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseHeld),
        ) if expected_version >= 2 => Some(LeaseMutationKindV2::Acquire),
        (
            AuthorityMutationV2::AcquireLease { .. },
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseGenerationMismatch),
        ) => Some(LeaseMutationKindV2::Acquire),
        (
            AuthorityMutationV2::RenewLease { fence },
            AuthorityDispositionV2::Applied
            | AuthorityDispositionV2::Rejected(
                AuthorityRejectionV2::LeaseRenewalNotExtended
                | AuthorityRejectionV2::MutationOverflow,
            ),
        ) if fence.generation() < expected_version => Some(LeaseMutationKindV2::Renew),
        (
            AuthorityMutationV2::RenewLease { .. },
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseAbsent),
        ) => Some(LeaseMutationKindV2::Renew),
        (
            AuthorityMutationV2::RenewLease { .. },
            AuthorityDispositionV2::Rejected(
                AuthorityRejectionV2::LeaseExpired | AuthorityRejectionV2::FenceMismatch,
            ),
        ) if expected_version >= 2 => Some(LeaseMutationKindV2::Renew),
        (AuthorityMutationV2::ReleaseLease { fence }, AuthorityDispositionV2::Applied)
            if fence.generation() < expected_version =>
        {
            Some(LeaseMutationKindV2::Release)
        }
        (
            AuthorityMutationV2::ReleaseLease { .. },
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseAbsent),
        ) => Some(LeaseMutationKindV2::Release),
        (
            AuthorityMutationV2::ReleaseLease { .. },
            AuthorityDispositionV2::Rejected(
                AuthorityRejectionV2::LeaseExpired | AuthorityRejectionV2::FenceMismatch,
            ),
        ) if expected_version >= 2 => Some(LeaseMutationKindV2::Release),
        _ => None,
    }
}

/// Exact operation and resulting-version locator for bounded receipt acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptLocatorV2 {
    operation_id: OperationIdV2,
    resulting_authority_version: u64,
}

impl ReceiptLocatorV2 {
    /// Construct a locator for one nonzero resulting authority version.
    pub fn new(
        operation_id: OperationIdV2,
        resulting_authority_version: u64,
    ) -> Result<Self, AuthorityValueErrorV2> {
        if resulting_authority_version == 0 {
            return Err(AuthorityValueErrorV2::InvalidCounter);
        }
        Ok(Self {
            operation_id,
            resulting_authority_version,
        })
    }

    /// Return the exact acknowledged operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationIdV2 {
        self.operation_id
    }

    /// Return the exact acknowledged resulting authority version.
    #[must_use]
    pub const fn resulting_authority_version(self) -> u64 {
        self.resulting_authority_version
    }
}

/// Idempotent outcome of acknowledging a historical receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptAckDispositionV2 {
    /// The exact retained receipt was removed.
    Removed,
    /// No receipt remains for that operation identifier.
    AlreadyAbsent,
}

/// Exact receipt acknowledgement failed without changing authority state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptAckErrorV2 {
    /// The operation exists but its resulting authority version did not match.
    ResultingVersionMismatch,
}

impl fmt::Display for ReceiptAckErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResultingVersionMismatch => {
                f.write_str("receipt resulting authority version mismatch")
            }
        }
    }
}

impl std::error::Error for ReceiptAckErrorV2 {}

/// Admission, trusted-clock, allocation, or invariant failure without a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthorityErrorV2 {
    /// The trusted witness time source was unavailable.
    ClockUnavailable,
    /// An operation ID was reused for a different intent.
    OperationConflict,
    /// The requested predecessor authority version was not current.
    AuthorityVersionMismatch,
    /// The monotonic authority version cannot advance further.
    AuthorityVersionExhausted,
    /// The receipt table is full; no semantic mutation was evaluated.
    ReceiptCapacityExceeded,
    /// A bounded allocation could not be reserved before mutation.
    AllocationFailed,
    /// The in-memory state violated an internal single-writer invariant.
    InternalInvariant,
}

impl fmt::Display for AuthorityErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ClockUnavailable => "trusted witness clock unavailable",
            Self::OperationConflict => "authority operation identifier conflicts",
            Self::AuthorityVersionMismatch => "authority predecessor version mismatch",
            Self::AuthorityVersionExhausted => "authority version exhausted",
            Self::ReceiptCapacityExceeded => "authority receipt capacity exceeded",
            Self::AllocationFailed => "authority bounded allocation failed",
            Self::InternalInvariant => "authority single-writer invariant failed",
        })
    }
}

impl std::error::Error for AuthorityErrorV2 {}

/// Closed receipt-query result at one exact committed authority version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityQueryResultV2 {
    /// The exact retained operation receipt exists.
    Found(Box<AuthorityReceiptV2>),
    /// No receipt exists, observed at this exact current authority version.
    AbsentAtVersion {
        /// Committed authority version at which absence was observed.
        authority_version: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcceptedKeyStatusV2 {
    Registered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityRecordV2 {
    pub(crate) state_head: StateHeadV2,
    pub(crate) config: DeploymentConfigRevisionV2,
    pub(crate) consumed_by: InstanceFenceV2,
    pub(crate) key_id: Option<AcceptedKeyIdV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedKeyRecordV2 {
    pub(crate) capability_id: CapabilityIdV2,
    pub(crate) state_head: StateHeadV2,
    pub(crate) config: DeploymentConfigRevisionV2,
    pub(crate) registered_by: InstanceFenceV2,
    pub(crate) status: AcceptedKeyStatusV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityPersistentMetaV2 {
    pub(crate) authority_version: u64,
    pub(crate) clock_floor_millis: u64,
    pub(crate) config: DeploymentConfigRevisionV2,
    pub(crate) state_head: StateHeadV2,
    pub(crate) lease_generation: u64,
    pub(crate) lease: Option<InstanceLeaseV2>,
    pub(crate) limits: AuthorityLimitsV2,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AuthorityRestoreV2 {
    pub(crate) meta: AuthorityPersistentMetaV2,
    pub(crate) receipts: Vec<(OperationIdV2, AuthorityReceiptV2)>,
    pub(crate) capabilities: Vec<(CapabilityIdV2, CapabilityRecordV2)>,
    pub(crate) keys: Vec<(AcceptedKeyIdV2, AcceptedKeyRecordV2)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityRestoreErrorV2 {
    Allocation,
    Invalid,
}

pub(crate) const STORE_SCHEMA_VERSION: u16 = 2;
pub(crate) const RECEIPT_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-RECEIPT/v2";
pub(crate) const CAPABILITY_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-CAPABILITY/v2";
pub(crate) const KEY_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-KEY/v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityCodecError {
    Allocation,
    Invalid,
}

impl fmt::Display for AuthorityCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "authority codec allocation failed",
            Self::Invalid => "authority codec value is not canonical",
        })
    }
}

impl std::error::Error for AuthorityCodecError {}

pub(crate) fn encode_operation_id(value: OperationIdV2) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(&value.expected_authority_version().to_be_bytes());
    bytes[8..].copy_from_slice(value.random_id());
    bytes
}

pub(crate) fn decode_operation_id(bytes: &[u8]) -> Result<OperationIdV2, AuthorityCodecError> {
    if bytes.len() != 40 {
        return Err(AuthorityCodecError::Invalid);
    }
    OperationIdV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        suffix(bytes, 8)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_accepted_key_id(value: AcceptedKeyIdV2) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[..8].copy_from_slice(&value.state_global_generation().to_be_bytes());
    bytes[8..16].copy_from_slice(&value.lease_generation().to_be_bytes());
    bytes[16..].copy_from_slice(value.random_id());
    bytes
}

pub(crate) fn decode_accepted_key_id(bytes: &[u8]) -> Result<AcceptedKeyIdV2, AuthorityCodecError> {
    if bytes.len() != 48 {
        return Err(AuthorityCodecError::Invalid);
    }
    AcceptedKeyIdV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        decode_u64(field(bytes, 8, 16)?)?,
        suffix(bytes, 16)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_state_revision(value: StateRevisionV2) -> [u8; 80] {
    let mut bytes = [0u8; 80];
    bytes[..8].copy_from_slice(&value.global_generation().to_be_bytes());
    bytes[8..40].copy_from_slice(value.chain_id());
    bytes[40..48].copy_from_slice(&value.epoch().to_be_bytes());
    bytes[48..].copy_from_slice(value.digest());
    bytes
}

pub(crate) fn decode_state_revision(bytes: &[u8]) -> Result<StateRevisionV2, AuthorityCodecError> {
    if bytes.len() != 80 {
        return Err(AuthorityCodecError::Invalid);
    }
    StateRevisionV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        field(bytes, 8, 40)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
        decode_u64(field(bytes, 40, 48)?)?,
        suffix(bytes, 48)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_state_head(value: StateHeadV2) -> [u8; 112] {
    let mut bytes = [0u8; 112];
    bytes[..80].copy_from_slice(&encode_state_revision(value.revision()));
    bytes[80..].copy_from_slice(value.fence().as_bytes());
    bytes
}

pub(crate) fn decode_state_head(bytes: &[u8]) -> Result<StateHeadV2, AuthorityCodecError> {
    if bytes.len() != 112 {
        return Err(AuthorityCodecError::Invalid);
    }
    Ok(StateHeadV2::new(
        decode_state_revision(field(bytes, 0, 80)?)?,
        StateFenceV2::from_bytes(
            suffix(bytes, 80)?
                .try_into()
                .map_err(|_| AuthorityCodecError::Invalid)?,
        )
        .map_err(|_| AuthorityCodecError::Invalid)?,
    ))
}

pub(crate) fn encode_config(value: DeploymentConfigRevisionV2) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(&value.generation().to_be_bytes());
    bytes[8..].copy_from_slice(value.digest());
    bytes
}

pub(crate) fn decode_config(
    bytes: &[u8],
) -> Result<DeploymentConfigRevisionV2, AuthorityCodecError> {
    if bytes.len() != 40 {
        return Err(AuthorityCodecError::Invalid);
    }
    DeploymentConfigRevisionV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        suffix(bytes, 8)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_instance_fence(value: InstanceFenceV2) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(&value.generation().to_be_bytes());
    bytes[8..].copy_from_slice(value.instance_id().as_bytes());
    bytes
}

pub(crate) fn decode_instance_fence(bytes: &[u8]) -> Result<InstanceFenceV2, AuthorityCodecError> {
    if bytes.len() != 40 {
        return Err(AuthorityCodecError::Invalid);
    }
    InstanceFenceV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        ProcessInstanceIdV2::from_bytes(
            suffix(bytes, 8)?
                .try_into()
                .map_err(|_| AuthorityCodecError::Invalid)?,
        )
        .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_lease(value: Option<InstanceLeaseV2>) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(if value.is_some() { 49 } else { 1 })
        .map_err(|_| AuthorityCodecError::Allocation)?;
    match value {
        None => bytes.push(0),
        Some(lease) => {
            bytes.push(1);
            bytes.extend_from_slice(&encode_instance_fence(lease.fence()));
            bytes.extend_from_slice(&lease.expires_at_millis().to_be_bytes());
        }
    }
    Ok(bytes)
}

pub(crate) fn decode_lease(bytes: &[u8]) -> Result<Option<InstanceLeaseV2>, AuthorityCodecError> {
    match bytes {
        [0] => Ok(None),
        [1, rest @ ..] if rest.len() == 48 => Ok(Some(InstanceLeaseV2::restore(
            decode_instance_fence(field(rest, 0, 40)?)?,
            decode_u64(suffix(rest, 40)?)?,
        ))),
        _ => Err(AuthorityCodecError::Invalid),
    }
}

pub(crate) fn encode_limits(value: AuthorityLimitsV2) -> Result<[u8; 32], AuthorityCodecError> {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(
        &u64::try_from(value.max_receipts())
            .map_err(|_| AuthorityCodecError::Invalid)?
            .to_be_bytes(),
    );
    bytes[8..16].copy_from_slice(
        &u64::try_from(value.max_capabilities())
            .map_err(|_| AuthorityCodecError::Invalid)?
            .to_be_bytes(),
    );
    bytes[16..24].copy_from_slice(
        &u64::try_from(value.max_keys())
            .map_err(|_| AuthorityCodecError::Invalid)?
            .to_be_bytes(),
    );
    bytes[24..].copy_from_slice(&value.lease_ttl_millis().to_be_bytes());
    Ok(bytes)
}

pub(crate) fn decode_limits(bytes: &[u8]) -> Result<AuthorityLimitsV2, AuthorityCodecError> {
    if bytes.len() != 32 {
        return Err(AuthorityCodecError::Invalid);
    }
    AuthorityLimitsV2::new(
        usize::try_from(decode_u64(field(bytes, 0, 8)?)?)
            .map_err(|_| AuthorityCodecError::Invalid)?,
        usize::try_from(decode_u64(field(bytes, 8, 16)?)?)
            .map_err(|_| AuthorityCodecError::Invalid)?,
        usize::try_from(decode_u64(field(bytes, 16, 24)?)?)
            .map_err(|_| AuthorityCodecError::Invalid)?,
        decode_u64(suffix(bytes, 24)?)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_receipt(value: AuthorityReceiptV2) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, RECEIPT_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    encode_intent(&mut encoder, value.intent())?;
    match value.disposition() {
        AuthorityDispositionV2::Applied => encoder.byte(1).map_err(map_codec)?,
        AuthorityDispositionV2::Rejected(rejection) => {
            encoder.byte(2).map_err(map_codec)?;
            encoder
                .byte(encode_rejection(rejection))
                .map_err(map_codec)?;
        }
    }
    encoder
        .u64(value.resulting_authority_version())
        .map_err(map_codec)?;
    Ok(encoder.finish())
}

pub(crate) fn decode_receipt(bytes: &[u8]) -> Result<AuthorityReceiptV2, AuthorityCodecError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, RECEIPT_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    let intent = decode_intent(&mut decoder)?;
    let disposition = match decoder.byte().map_err(map_codec)? {
        1 => AuthorityDispositionV2::Applied,
        2 => {
            AuthorityDispositionV2::Rejected(decode_rejection(decoder.byte().map_err(map_codec)?)?)
        }
        _ => return Err(AuthorityCodecError::Invalid),
    };
    let resulting_authority_version = decoder.u64().map_err(map_codec)?;
    decoder.finish().map_err(map_codec)?;
    AuthorityReceiptV2::restore(intent, disposition, resulting_authority_version)
        .map_err(map_restore)
}

pub(crate) fn encode_intent(
    encoder: &mut Encoder,
    value: AuthorityIntentV2,
) -> Result<(), AuthorityCodecError> {
    encoder
        .fixed(&encode_operation_id(value.operation_id()))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.expected_config()))
        .map_err(map_codec)?;
    match value.mutation() {
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation,
            instance_id,
        } => {
            encoder.byte(1).map_err(map_codec)?;
            encoder.u64(expected_lease_generation).map_err(map_codec)?;
            encoder.fixed(instance_id.as_bytes()).map_err(map_codec)
        }
        AuthorityMutationV2::RenewLease { fence } => {
            encoder.byte(2).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)
        }
        AuthorityMutationV2::ReleaseLease { fence } => {
            encoder.byte(3).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)
        }
        AuthorityMutationV2::AdvanceState { fence, advance } => {
            encoder.byte(4).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder
                .byte(match advance.kind() {
                    StateTransitionKindV2::Advance => 1,
                    StateTransitionKindV2::AuthorizedReset => 2,
                })
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_state_head(advance.expected()))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_state_head(advance.next()))
                .map_err(map_codec)
        }
        AuthorityMutationV2::AdvanceConfig { fence, advance } => {
            encoder.byte(5).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_config(advance.expected()))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_config(advance.next()))
                .map_err(map_codec)
        }
        AuthorityMutationV2::ConsumeCapability {
            fence,
            capability_id,
        } => {
            encoder.byte(6).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder.fixed(capability_id.as_bytes()).map_err(map_codec)
        }
        AuthorityMutationV2::RegisterKey {
            fence,
            capability_id,
            key_id,
        } => {
            encoder.byte(7).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder.fixed(capability_id.as_bytes()).map_err(map_codec)?;
            encoder
                .fixed(&encode_accepted_key_id(key_id))
                .map_err(map_codec)
        }
        AuthorityMutationV2::RevokeKey { fence, key_id } => {
            encoder.byte(8).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_accepted_key_id(key_id))
                .map_err(map_codec)
        }
    }
}

pub(crate) fn decode_intent(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityIntentV2, AuthorityCodecError> {
    let operation_id = decode_operation_id(decoder.fixed(40).map_err(map_codec)?)?;
    let expected_config = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
    let mutation = match decoder.byte().map_err(map_codec)? {
        1 => AuthorityMutationV2::AcquireLease {
            expected_lease_generation: decoder.u64().map_err(map_codec)?,
            instance_id: ProcessInstanceIdV2::from_bytes(decoder.array().map_err(map_codec)?)
                .map_err(|_| AuthorityCodecError::Invalid)?,
        },
        2 => AuthorityMutationV2::RenewLease {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
        },
        3 => AuthorityMutationV2::ReleaseLease {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
        },
        4 => {
            let fence = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
            let kind = match decoder.byte().map_err(map_codec)? {
                1 => StateTransitionKindV2::Advance,
                2 => StateTransitionKindV2::AuthorizedReset,
                _ => return Err(AuthorityCodecError::Invalid),
            };
            let expected = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
            let next = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
            AuthorityMutationV2::AdvanceState {
                fence,
                advance: StateAdvanceV2::new(kind, expected, next)
                    .map_err(|_| AuthorityCodecError::Invalid)?,
            }
        }
        5 => {
            let fence = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
            let expected = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
            let next = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
            AuthorityMutationV2::AdvanceConfig {
                fence,
                advance: ConfigAdvanceV2::new(expected, next)
                    .map_err(|_| AuthorityCodecError::Invalid)?,
            }
        }
        6 => AuthorityMutationV2::ConsumeCapability {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
            capability_id: CapabilityIdV2::from_bytes(decoder.array().map_err(map_codec)?)
                .map_err(|_| AuthorityCodecError::Invalid)?,
        },
        7 => AuthorityMutationV2::RegisterKey {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
            capability_id: CapabilityIdV2::from_bytes(decoder.array().map_err(map_codec)?)
                .map_err(|_| AuthorityCodecError::Invalid)?,
            key_id: decode_accepted_key_id(decoder.fixed(48).map_err(map_codec)?)?,
        },
        8 => AuthorityMutationV2::RevokeKey {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
            key_id: decode_accepted_key_id(decoder.fixed(48).map_err(map_codec)?)?,
        },
        _ => return Err(AuthorityCodecError::Invalid),
    };
    AuthorityIntentV2::new(
        operation_id,
        operation_id.expected_authority_version(),
        expected_config,
        mutation,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) const fn encode_rejection(value: AuthorityRejectionV2) -> u8 {
    match value {
        AuthorityRejectionV2::ConfigurationMismatch => 1,
        AuthorityRejectionV2::LeaseHeld => 2,
        AuthorityRejectionV2::LeaseGenerationMismatch => 3,
        AuthorityRejectionV2::LeaseAbsent => 4,
        AuthorityRejectionV2::LeaseExpired => 5,
        AuthorityRejectionV2::FenceMismatch => 6,
        AuthorityRejectionV2::LeaseRenewalNotExtended => 7,
        AuthorityRejectionV2::MutationOverflow => 8,
        AuthorityRejectionV2::StateMismatch => 9,
        AuthorityRejectionV2::ConfigTransitionMismatch => 10,
        AuthorityRejectionV2::CapabilityReplay => 11,
        AuthorityRejectionV2::CapabilityUnknown => 12,
        AuthorityRejectionV2::CapabilityStale => 13,
        AuthorityRejectionV2::CapabilityAlreadyBound => 14,
        AuthorityRejectionV2::KeyAlreadyRegistered => 15,
        AuthorityRejectionV2::KeyStateGenerationMismatch => 16,
        AuthorityRejectionV2::KeyLeaseGenerationMismatch => 17,
        AuthorityRejectionV2::KeyUnknown => 18,
        AuthorityRejectionV2::KeyRevoked => 19,
        AuthorityRejectionV2::CapabilityCapacityExceeded => 20,
        AuthorityRejectionV2::KeyCapacityExceeded => 21,
    }
}

pub(crate) fn decode_rejection(value: u8) -> Result<AuthorityRejectionV2, AuthorityCodecError> {
    match value {
        1 => Ok(AuthorityRejectionV2::ConfigurationMismatch),
        2 => Ok(AuthorityRejectionV2::LeaseHeld),
        3 => Ok(AuthorityRejectionV2::LeaseGenerationMismatch),
        4 => Ok(AuthorityRejectionV2::LeaseAbsent),
        5 => Ok(AuthorityRejectionV2::LeaseExpired),
        6 => Ok(AuthorityRejectionV2::FenceMismatch),
        7 => Ok(AuthorityRejectionV2::LeaseRenewalNotExtended),
        8 => Ok(AuthorityRejectionV2::MutationOverflow),
        9 => Ok(AuthorityRejectionV2::StateMismatch),
        10 => Ok(AuthorityRejectionV2::ConfigTransitionMismatch),
        11 => Ok(AuthorityRejectionV2::CapabilityReplay),
        12 => Ok(AuthorityRejectionV2::CapabilityUnknown),
        13 => Ok(AuthorityRejectionV2::CapabilityStale),
        14 => Ok(AuthorityRejectionV2::CapabilityAlreadyBound),
        15 => Ok(AuthorityRejectionV2::KeyAlreadyRegistered),
        16 => Ok(AuthorityRejectionV2::KeyStateGenerationMismatch),
        17 => Ok(AuthorityRejectionV2::KeyLeaseGenerationMismatch),
        18 => Ok(AuthorityRejectionV2::KeyUnknown),
        19 => Ok(AuthorityRejectionV2::KeyRevoked),
        20 => Ok(AuthorityRejectionV2::CapabilityCapacityExceeded),
        21 => Ok(AuthorityRejectionV2::KeyCapacityExceeded),
        _ => Err(AuthorityCodecError::Invalid),
    }
}

pub(crate) fn encode_capability_record(
    value: CapabilityRecordV2,
) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, CAPABILITY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    encoder
        .fixed(&encode_state_head(value.state_head))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.config))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_instance_fence(value.consumed_by))
        .map_err(map_codec)?;
    match value.key_id {
        None => encoder.byte(0).map_err(map_codec)?,
        Some(key_id) => {
            encoder.byte(1).map_err(map_codec)?;
            encoder
                .fixed(&encode_accepted_key_id(key_id))
                .map_err(map_codec)?;
        }
    }
    Ok(encoder.finish())
}

pub(crate) fn decode_capability_record(
    bytes: &[u8],
) -> Result<CapabilityRecordV2, AuthorityCodecError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, CAPABILITY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    let state_head = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
    let config = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
    let consumed_by = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
    let key_id = match decoder.byte().map_err(map_codec)? {
        0 => None,
        1 => Some(decode_accepted_key_id(
            decoder.fixed(48).map_err(map_codec)?,
        )?),
        _ => return Err(AuthorityCodecError::Invalid),
    };
    decoder.finish().map_err(map_codec)?;
    Ok(CapabilityRecordV2 {
        state_head,
        config,
        consumed_by,
        key_id,
    })
}

pub(crate) fn encode_key_record(
    value: AcceptedKeyRecordV2,
) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, KEY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    encoder
        .fixed(value.capability_id.as_bytes())
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_state_head(value.state_head))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.config))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_instance_fence(value.registered_by))
        .map_err(map_codec)?;
    encoder
        .byte(match value.status {
            AcceptedKeyStatusV2::Registered => 1,
            AcceptedKeyStatusV2::Revoked => 2,
        })
        .map_err(map_codec)?;
    Ok(encoder.finish())
}

pub(crate) fn decode_key_record(bytes: &[u8]) -> Result<AcceptedKeyRecordV2, AuthorityCodecError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, KEY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    let capability_id = CapabilityIdV2::from_bytes(decoder.array().map_err(map_codec)?)
        .map_err(|_| AuthorityCodecError::Invalid)?;
    let state_head = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
    let config = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
    let registered_by = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
    let status = match decoder.byte().map_err(map_codec)? {
        1 => AcceptedKeyStatusV2::Registered,
        2 => AcceptedKeyStatusV2::Revoked,
        _ => return Err(AuthorityCodecError::Invalid),
    };
    decoder.finish().map_err(map_codec)?;
    Ok(AcceptedKeyRecordV2 {
        capability_id,
        state_head,
        config,
        registered_by,
        status,
    })
}

pub(crate) fn encode_receipt_locator(value: ReceiptLocatorV2) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[..40].copy_from_slice(&encode_operation_id(value.operation_id()));
    bytes[40..].copy_from_slice(&value.resulting_authority_version().to_be_bytes());
    bytes
}

pub(crate) fn decode_receipt_locator(
    bytes: &[u8],
) -> Result<ReceiptLocatorV2, AuthorityCodecError> {
    if bytes.len() != 48 {
        return Err(AuthorityCodecError::Invalid);
    }
    ReceiptLocatorV2::new(
        decode_operation_id(field(bytes, 0, 40)?)?,
        decode_u64(suffix(bytes, 40)?)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_snapshot(
    encoder: &mut Encoder,
    value: AuthoritySnapshotV2,
) -> Result<(), AuthorityCodecError> {
    encoder.u64(value.authority_version()).map_err(map_codec)?;
    encoder.u64(value.clock_floor_millis()).map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.config()))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_state_head(value.state_head()))
        .map_err(map_codec)?;
    encoder.u64(value.lease_generation()).map_err(map_codec)?;
    encoder
        .lp16(&encode_lease(value.active_lease())?)
        .map_err(map_codec)?;
    for count in [
        value.receipt_count(),
        value.capability_count(),
        value.retained_key_count(),
        value.active_key_count(),
    ] {
        encoder
            .u64(u64::try_from(count).map_err(|_| AuthorityCodecError::Invalid)?)
            .map_err(map_codec)?;
    }
    Ok(())
}

pub(crate) fn decode_snapshot(
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritySnapshotV2, AuthorityCodecError> {
    AuthoritySnapshotV2::restore_wire(
        decoder.u64().map_err(map_codec)?,
        decoder.u64().map_err(map_codec)?,
        decode_config(decoder.fixed(40).map_err(map_codec)?)?,
        decode_state_head(decoder.fixed(112).map_err(map_codec)?)?,
        decoder.u64().map_err(map_codec)?,
        decode_lease(decoder.lp16(49).map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

fn decode_count(value: u64) -> Result<usize, AuthorityCodecError> {
    usize::try_from(value).map_err(|_| AuthorityCodecError::Invalid)
}

fn decode_u64(bytes: &[u8]) -> Result<u64, AuthorityCodecError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| AuthorityCodecError::Invalid)?,
    ))
}

fn field(bytes: &[u8], start: usize, end: usize) -> Result<&[u8], AuthorityCodecError> {
    bytes.get(start..end).ok_or(AuthorityCodecError::Invalid)
}

fn suffix(bytes: &[u8], start: usize) -> Result<&[u8], AuthorityCodecError> {
    bytes.get(start..).ok_or(AuthorityCodecError::Invalid)
}

fn map_codec(error: CodecError) -> AuthorityCodecError {
    match error {
        CodecError::Allocation => AuthorityCodecError::Allocation,
        CodecError::InvalidLength
        | CodecError::InvalidValue
        | CodecError::Io
        | CodecError::Oversized
        | CodecError::TrailingBytes
        | CodecError::Truncated => AuthorityCodecError::Invalid,
    }
}

fn map_restore(error: AuthorityRestoreErrorV2) -> AuthorityCodecError {
    match error {
        AuthorityRestoreErrorV2::Allocation => AuthorityCodecError::Allocation,
        AuthorityRestoreErrorV2::Invalid => AuthorityCodecError::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use q_periapt_backends::Sha3_256Xof;
    use q_periapt_core::Xof256;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn append_record(corpus: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AuthorityCodecError> {
        let length = u64::try_from(bytes.len()).map_err(|_| AuthorityCodecError::Invalid)?;
        let additional = 8usize
            .checked_add(bytes.len())
            .ok_or(AuthorityCodecError::Invalid)?;
        corpus
            .try_reserve_exact(additional)
            .map_err(|_| AuthorityCodecError::Allocation)?;
        corpus.extend_from_slice(&length.to_be_bytes());
        corpus.extend_from_slice(bytes);
        Ok(())
    }

    fn config(
        generation: u64,
        byte: u8,
    ) -> Result<DeploymentConfigRevisionV2, AuthorityCodecError> {
        DeploymentConfigRevisionV2::new(generation, [byte; 32])
            .map_err(|_| AuthorityCodecError::Invalid)
    }

    fn head(
        generation: u64,
        chain: u8,
        epoch: u64,
        digest: u8,
        fence: u8,
    ) -> Result<StateHeadV2, AuthorityCodecError> {
        Ok(StateHeadV2::new(
            StateRevisionV2::new(generation, [chain; 32], epoch, [digest; 32])
                .map_err(|_| AuthorityCodecError::Invalid)?,
            StateFenceV2::from_bytes([fence; 32]).map_err(|_| AuthorityCodecError::Invalid)?,
        ))
    }

    fn instance_fence(generation: u64, byte: u8) -> Result<InstanceFenceV2, AuthorityCodecError> {
        InstanceFenceV2::new(
            generation,
            ProcessInstanceIdV2::from_bytes([byte; 32])
                .map_err(|_| AuthorityCodecError::Invalid)?,
        )
        .map_err(|_| AuthorityCodecError::Invalid)
    }

    fn intent(
        version: u64,
        byte: u8,
        config: DeploymentConfigRevisionV2,
        mutation: AuthorityMutationV2,
    ) -> Result<AuthorityIntentV2, AuthorityCodecError> {
        AuthorityIntentV2::new(
            OperationIdV2::new(version, [byte; 32]).map_err(|_| AuthorityCodecError::Invalid)?,
            version,
            config,
            mutation,
        )
        .map_err(|_| AuthorityCodecError::Invalid)
    }

    fn receipt(
        intent: AuthorityIntentV2,
        disposition: AuthorityDispositionV2,
    ) -> Result<AuthorityReceiptV2, AuthorityCodecError> {
        AuthorityReceiptV2::restore(
            intent,
            disposition,
            intent
                .expected_authority_version()
                .checked_add(1)
                .ok_or(AuthorityCodecError::Invalid)?,
        )
        .map_err(map_restore)
    }

    #[test]
    fn store_v2_canonical_bytes_match_the_frozen_stage2a1_corpus() -> TestResult {
        // Level 1 reliability guard: detect accidental changes to already-persisted
        // Store V2 bytes. This digest is not a malicious-tamper authenticity claim.
        let mut corpus = Vec::new();
        let config_one = config(1, 0x31)?;
        let config_two = config(2, 0x32)?;
        let head_one = head(1, 0x41, 1, 0x51, 0x61)?;
        let head_two = head(2, 0x41, 2, 0x52, 0x62)?;
        let fence = instance_fence(1, 0x71)?;
        let capability_id = CapabilityIdV2::from_bytes([0x81; 32])?;
        let key_id = AcceptedKeyIdV2::new(1, 1, [0x91; 32])?;
        let limits = AuthorityLimitsV2::new(64, 32, 16, 10_000)?;

        // Store V2 meta and key primitives, in the persisted field order.
        append_record(&mut corpus, &1u64.to_be_bytes())?;
        append_record(&mut corpus, &10_000u64.to_be_bytes())?;
        append_record(&mut corpus, &encode_config(config_one))?;
        append_record(&mut corpus, &encode_state_head(head_one))?;
        append_record(&mut corpus, &1u64.to_be_bytes())?;
        append_record(
            &mut corpus,
            &encode_lease(Some(InstanceLeaseV2::restore(fence, 20_000)))?,
        )?;
        append_record(&mut corpus, &encode_limits(limits)?)?;
        append_record(
            &mut corpus,
            &encode_operation_id(OperationIdV2::new(1, [0x11; 32])?),
        )?;
        append_record(&mut corpus, &encode_accepted_key_id(key_id))?;
        append_record(&mut corpus, &encode_state_revision(head_one.revision()))?;
        append_record(&mut corpus, &encode_instance_fence(fence))?;

        let state_advance =
            StateAdvanceV2::new(StateTransitionKindV2::Advance, head_one, head_two)?;
        let config_advance = ConfigAdvanceV2::new(config_one, config_two)?;
        let mutations = [
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([0xa1; 32])?,
            },
            AuthorityMutationV2::RenewLease { fence },
            AuthorityMutationV2::ReleaseLease { fence },
            AuthorityMutationV2::AdvanceState {
                fence,
                advance: state_advance,
            },
            AuthorityMutationV2::AdvanceConfig {
                fence,
                advance: config_advance,
            },
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id,
            },
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id,
                key_id,
            },
            AuthorityMutationV2::RevokeKey { fence, key_id },
        ];
        for (index, mutation) in mutations.into_iter().enumerate() {
            let tag = u8::try_from(index + 1)?;
            let intent = intent(u64::from(tag), tag, config_one, mutation)?;
            let mut encoded_intent = Encoder::new(MAX_FRAME_BYTES);
            encode_intent(&mut encoded_intent, intent)?;
            append_record(&mut corpus, &encoded_intent.finish())?;
            append_record(
                &mut corpus,
                &encode_receipt(receipt(intent, AuthorityDispositionV2::Applied)?)?,
            )?;
        }
        let rejections = [
            AuthorityRejectionV2::ConfigurationMismatch,
            AuthorityRejectionV2::LeaseHeld,
            AuthorityRejectionV2::LeaseGenerationMismatch,
            AuthorityRejectionV2::LeaseAbsent,
            AuthorityRejectionV2::LeaseExpired,
            AuthorityRejectionV2::FenceMismatch,
            AuthorityRejectionV2::LeaseRenewalNotExtended,
            AuthorityRejectionV2::MutationOverflow,
            AuthorityRejectionV2::StateMismatch,
            AuthorityRejectionV2::ConfigTransitionMismatch,
            AuthorityRejectionV2::CapabilityReplay,
            AuthorityRejectionV2::CapabilityUnknown,
            AuthorityRejectionV2::CapabilityStale,
            AuthorityRejectionV2::CapabilityAlreadyBound,
            AuthorityRejectionV2::KeyAlreadyRegistered,
            AuthorityRejectionV2::KeyStateGenerationMismatch,
            AuthorityRejectionV2::KeyLeaseGenerationMismatch,
            AuthorityRejectionV2::KeyUnknown,
            AuthorityRejectionV2::KeyRevoked,
            AuthorityRejectionV2::CapabilityCapacityExceeded,
            AuthorityRejectionV2::KeyCapacityExceeded,
        ];
        for (index, rejection) in rejections.into_iter().enumerate() {
            let tag = u8::try_from(index + 1)?;
            append_record(&mut corpus, &[encode_rejection(rejection)])?;
            let intent = intent(
                u64::from(tag),
                tag,
                config_one,
                AuthorityMutationV2::AcquireLease {
                    expected_lease_generation: 0,
                    instance_id: ProcessInstanceIdV2::from_bytes([tag; 32])?,
                },
            )?;
            append_record(
                &mut corpus,
                &encode_receipt(receipt(
                    intent,
                    AuthorityDispositionV2::Rejected(rejection),
                )?)?,
            )?;
        }

        append_record(
            &mut corpus,
            &encode_capability_record(CapabilityRecordV2 {
                state_head: head_one,
                config: config_one,
                consumed_by: fence,
                key_id: Some(key_id),
            })?,
        )?;
        for status in [
            AcceptedKeyStatusV2::Registered,
            AcceptedKeyStatusV2::Revoked,
        ] {
            append_record(
                &mut corpus,
                &encode_key_record(AcceptedKeyRecordV2 {
                    capability_id,
                    state_head: head_one,
                    config: config_one,
                    registered_by: fence,
                    status,
                })?,
            )?;
        }

        let mut hash = Sha3_256Xof::new();
        hash.reserve(corpus.len());
        hash.absorb_public(&corpus);
        let digest = hash.squeeze32();
        assert_eq!(corpus.len(), 8_525);
        assert_eq!(
            digest,
            [
                0x12, 0x18, 0x70, 0xa6, 0xdb, 0x43, 0x1b, 0x26, 0x5b, 0xad, 0x6c, 0x76, 0xf9, 0xfe,
                0x20, 0xf3, 0xdb, 0x0d, 0x01, 0x90, 0x2f, 0x2d, 0xca, 0x5e, 0x1a, 0x3e, 0xd4, 0x27,
                0x5c, 0x9e, 0x63, 0x7b,
            ]
        );
        Ok(())
    }
}
