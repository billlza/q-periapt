//! Pure Witness V2 authority state and deterministic transition rules.
//!
//! This Stage 1 module consumes already authenticated, typed state and configuration
//! revisions. It does not verify authority signatures or deployment identities, persist
//! state, expose a wire/IPC protocol, authorize cryptographic key use, or import v1 data.
//! Those security boundaries must fail closed in later adapters; this state machine alone
//! is not a disk-clone or live-memory-snapshot defense. A Stage 2 service must retire its
//! pending capability work atomically with every state advance and verify each typed capability
//! envelope against the exact current head and config in the same authority-version transaction
//! before it can use this module.

use core::fmt;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

const HARD_MAX_RECEIPTS: usize = 4096;
const HARD_MAX_CAPABILITIES: usize = 4096;
const HARD_MAX_KEYS: usize = 1024;
const HARD_MIN_LEASE_TTL_MILLIS: u64 = 10_000;
const HARD_MAX_LEASE_TTL_MILLIS: u64 = 5 * 60 * 1000;

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

/// Public bounded projection of current pure authority state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshotV2 {
    authority_version: u64,
    clock_floor_millis: u64,
    config: DeploymentConfigRevisionV2,
    state_head: StateHeadV2,
    lease_generation: u64,
    active_lease: Option<InstanceLeaseV2>,
    receipt_count: usize,
    capability_count: usize,
    retained_key_count: usize,
    active_key_count: usize,
}

impl AuthoritySnapshotV2 {
    /// Return the monotonic authority-operation version.
    #[must_use]
    pub const fn authority_version(self) -> u64 {
        self.authority_version
    }

    /// Return the in-memory nondecreasing trusted-clock floor.
    ///
    /// A future adapter must persist every successful floor advance atomically.
    #[must_use]
    pub const fn clock_floor_millis(self) -> u64 {
        self.clock_floor_millis
    }

    /// Return the exact deployment-configuration revision.
    #[must_use]
    pub const fn config(self) -> DeploymentConfigRevisionV2 {
        self.config
    }

    /// Return the exact migration-state head.
    #[must_use]
    pub const fn state_head(self) -> StateHeadV2 {
        self.state_head
    }

    /// Return the most recently allocated lease generation.
    #[must_use]
    pub const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Return the current non-expired process lease, if any.
    #[must_use]
    pub const fn active_lease(self) -> Option<InstanceLeaseV2> {
        self.active_lease
    }

    /// Return the number of retained exact operation receipts.
    #[must_use]
    pub const fn receipt_count(self) -> usize {
        self.receipt_count
    }

    /// Return the number of current-state-scoped consumed capabilities.
    #[must_use]
    pub const fn capability_count(self) -> usize {
        self.capability_count
    }

    /// Return all accepted-key records retained until an explicit fencing transition.
    #[must_use]
    pub const fn retained_key_count(self) -> usize {
        self.retained_key_count
    }

    /// Return active registrations bound to the current head, config, and lease.
    ///
    /// This accounting value is not cryptographic key-use authorization.
    #[must_use]
    pub const fn active_key_count(self) -> usize {
        self.active_key_count
    }
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
enum PlannedMutationV2 {
    Acquire(InstanceLeaseV2),
    Renew(InstanceLeaseV2),
    Release,
    AdvanceState(StateHeadV2),
    AdvanceConfig(DeploymentConfigRevisionV2),
    Consume {
        capability_id: CapabilityIdV2,
        record: CapabilityRecordV2,
    },
    Register {
        fence: InstanceFenceV2,
        capability_id: CapabilityIdV2,
        key_id: AcceptedKeyIdV2,
    },
    Revoke {
        key_id: AcceptedKeyIdV2,
        record: AcceptedKeyRecordV2,
    },
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReservationPointV2 {
    Receipt,
    Capability,
    Key,
}

/// Uniquely owned, bounded Witness V2 authority state with no clone or export path.
///
/// A persistence adapter must provide equivalent single-writer transactional ownership;
/// constructing two independently mutable copies at one authority version is forbidden.
pub struct AuthorityStateV2 {
    authority_version: u64,
    clock_floor_millis: u64,
    config: DeploymentConfigRevisionV2,
    state_head: StateHeadV2,
    lease_generation: u64,
    lease: Option<InstanceLeaseV2>,
    receipts: HashMap<OperationIdV2, AuthorityReceiptV2>,
    capabilities: HashMap<CapabilityIdV2, CapabilityRecordV2>,
    keys: HashMap<AcceptedKeyIdV2, AcceptedKeyRecordV2>,
    limits: AuthorityLimitsV2,
    #[cfg(test)]
    fail_next_reservation: Option<ReservationPointV2>,
}

impl fmt::Debug for AuthorityStateV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityStateV2")
            .field("authority_version", &self.authority_version)
            .field("clock_floor_millis", &self.clock_floor_millis)
            .field("config", &self.config)
            .field("state_head", &self.state_head)
            .field("lease_generation", &self.lease_generation)
            .field("lease", &self.lease)
            .field("receipt_count", &self.receipts.len())
            .field("capability_count", &self.capabilities.len())
            .field("retained_key_count", &self.keys.len())
            .finish()
    }
}

impl AuthorityStateV2 {
    /// Provision a fresh pure authority state at version one and trusted time.
    pub fn provision<C: TrustedClockV2>(
        state_head: StateHeadV2,
        config: DeploymentConfigRevisionV2,
        limits: AuthorityLimitsV2,
        clock: &C,
    ) -> Result<Self, AuthorityErrorV2> {
        let clock_floor_millis = clock
            .now_millis()
            .map_err(|_| AuthorityErrorV2::ClockUnavailable)?;
        Ok(Self {
            authority_version: 1,
            clock_floor_millis,
            config,
            state_head,
            lease_generation: 0,
            lease: None,
            receipts: HashMap::new(),
            capabilities: HashMap::new(),
            keys: HashMap::new(),
            limits,
            #[cfg(test)]
            fail_next_reservation: None,
        })
    }

    pub(crate) fn durable_image(&self) -> Result<AuthorityRestoreV2, AuthorityRestoreErrorV2> {
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(self.receipts.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        receipts.extend(self.receipts.iter().map(|(id, receipt)| (*id, *receipt)));
        receipts.sort_unstable_by_key(|(id, _)| *id);

        let mut capabilities = Vec::new();
        capabilities
            .try_reserve_exact(self.capabilities.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        capabilities.extend(self.capabilities.iter().map(|(id, record)| (*id, *record)));
        capabilities.sort_unstable_by_key(|(id, _)| *id);

        let mut keys = Vec::new();
        keys.try_reserve_exact(self.keys.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        keys.extend(self.keys.iter().map(|(id, record)| (*id, *record)));
        keys.sort_unstable_by_key(|(id, _)| *id);

        Ok(AuthorityRestoreV2 {
            meta: self.persistent_meta(),
            receipts,
            capabilities,
            keys,
        })
    }

    pub(crate) const fn persistent_meta(&self) -> AuthorityPersistentMetaV2 {
        AuthorityPersistentMetaV2 {
            authority_version: self.authority_version,
            clock_floor_millis: self.clock_floor_millis,
            config: self.config,
            state_head: self.state_head,
            lease_generation: self.lease_generation,
            lease: self.lease,
            limits: self.limits,
        }
    }

    pub(crate) fn restore(image: &AuthorityRestoreV2) -> Result<Self, AuthorityRestoreErrorV2> {
        let meta = image.meta;
        let receipt_entries = &image.receipts;
        let capability_entries = &image.capabilities;
        let key_entries = &image.keys;
        if meta.authority_version == 0
            || receipt_entries.len() > meta.limits.max_receipts
            || capability_entries.len() > meta.limits.max_capabilities
            || key_entries.len() > meta.limits.max_keys
            || matches!(
                meta.lease,
                Some(lease)
                    if lease.fence.generation != meta.lease_generation
                        || meta.lease_generation == 0
            )
        {
            return Err(AuthorityRestoreErrorV2::Invalid);
        }

        let mut receipts = HashMap::new();
        receipts
            .try_reserve(receipt_entries.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        let mut receipt_versions = HashSet::new();
        receipt_versions
            .try_reserve(receipt_entries.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        for &(operation_id, receipt) in receipt_entries {
            if operation_id != receipt.intent.operation_id
                || receipt.intent.expected_authority_version.checked_add(1)
                    != Some(receipt.resulting_authority_version)
                || receipt.resulting_authority_version > meta.authority_version
                || !receipt_versions.insert(receipt.resulting_authority_version)
                || receipts.insert(operation_id, receipt).is_some()
            {
                return Err(AuthorityRestoreErrorV2::Invalid);
            }
        }

        let mut capabilities = HashMap::new();
        capabilities
            .try_reserve(capability_entries.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        let mut bound_key_ids = HashSet::new();
        bound_key_ids
            .try_reserve(capability_entries.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        for &(capability_id, record) in capability_entries {
            if record.state_head != meta.state_head
                || record.config.generation > meta.config.generation
                || (record.config.generation == meta.config.generation
                    && record.config != meta.config)
                || record.consumed_by.generation == 0
                || record.consumed_by.generation > meta.lease_generation
                || matches!(
                    record.key_id,
                    Some(key_id)
                        if key_id.state_global_generation
                            != record.state_head.revision.global_generation
                            || key_id.lease_generation != record.consumed_by.generation
                            || !bound_key_ids.insert(key_id)
                )
                || capabilities.insert(capability_id, record).is_some()
            {
                return Err(AuthorityRestoreErrorV2::Invalid);
            }
        }

        let mut keys = HashMap::new();
        keys.try_reserve(key_entries.len())
            .map_err(|_| AuthorityRestoreErrorV2::Allocation)?;
        for &(key_id, record) in key_entries {
            let Some(lease) = meta.lease else {
                return Err(AuthorityRestoreErrorV2::Invalid);
            };
            if key_id.state_global_generation != meta.state_head.revision.global_generation
                || key_id.lease_generation != record.registered_by.generation
                || record.state_head != meta.state_head
                || record.config != meta.config
                || record.registered_by != lease.fence
                || keys.insert(key_id, record).is_some()
            {
                return Err(AuthorityRestoreErrorV2::Invalid);
            }
        }

        for (capability_id, capability) in &capabilities {
            if let Some(key_id) = capability.key_id {
                let Some(key) = keys.get(&key_id) else {
                    if capability.config == meta.config
                        && matches!(
                            meta.lease,
                            Some(lease) if lease.fence == capability.consumed_by
                        )
                    {
                        return Err(AuthorityRestoreErrorV2::Invalid);
                    }
                    continue;
                };
                if key.capability_id != *capability_id
                    || key.state_head != capability.state_head
                    || key.config != capability.config
                    || key.registered_by != capability.consumed_by
                {
                    return Err(AuthorityRestoreErrorV2::Invalid);
                }
            }
        }
        for (key_id, key) in &keys {
            if !matches!(
                capabilities.get(&key.capability_id),
                Some(capability) if capability.key_id == Some(*key_id)
            ) {
                return Err(AuthorityRestoreErrorV2::Invalid);
            }
        }

        Ok(Self {
            authority_version: meta.authority_version,
            clock_floor_millis: meta.clock_floor_millis,
            config: meta.config,
            state_head: meta.state_head,
            lease_generation: meta.lease_generation,
            lease: meta.lease,
            receipts,
            capabilities,
            keys,
            limits: meta.limits,
            #[cfg(test)]
            fail_next_reservation: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_reservation_for_store_test(&mut self, point: ReservationPointV2) {
        self.fail_next_reservation = Some(point);
    }

    /// Observe trusted time and return the current bounded projection.
    pub fn snapshot<C: TrustedClockV2>(
        &mut self,
        clock: &C,
    ) -> Result<AuthoritySnapshotV2, AuthorityErrorV2> {
        let now = self.observe_clock(clock)?;
        let active_lease = self.lease.filter(|lease| now < lease.expires_at_millis);
        let active_key_count = match active_lease {
            Some(lease) => self
                .keys
                .values()
                .filter(|record| {
                    record.status == AcceptedKeyStatusV2::Registered
                        && record.registered_by == lease.fence
                        && record.state_head == self.state_head
                        && record.config == self.config
                })
                .count(),
            None => 0,
        };
        Ok(AuthoritySnapshotV2 {
            authority_version: self.authority_version,
            clock_floor_millis: self.clock_floor_millis,
            config: self.config,
            state_head: self.state_head,
            lease_generation: self.lease_generation,
            active_lease,
            receipt_count: self.receipts.len(),
            capability_count: self.capabilities.len(),
            retained_key_count: self.keys.len(),
            active_key_count,
        })
    }

    /// Return one immutable historical receipt without observing time or authorizing current use.
    ///
    /// Callers must use [`Self::apply`] for exact replay because replay remains fail-closed on
    /// trusted-clock outage. This read-only lookup is only for result reconciliation.
    #[must_use]
    pub fn receipt(&self, operation_id: OperationIdV2) -> Option<AuthorityReceiptV2> {
        self.receipts.get(&operation_id).copied()
    }

    /// Remove one exactly located historical receipt after its result is durably known.
    ///
    /// Acknowledgement is idempotent, does not observe the clock, does not create a recursive
    /// receipt, and does not change the authority version. Once removed, the original intent's
    /// predecessor version is stale, so submitting that old intent cannot execute it again.
    /// `AlreadyAbsent` proves only absence, not that the original operation ever executed.
    /// A future adapter must authenticate this request and atomically persist it, and callers
    /// must acknowledge only an exact receipt they have already retained durably.
    pub fn acknowledge_receipt(
        &mut self,
        locator: ReceiptLocatorV2,
    ) -> Result<ReceiptAckDispositionV2, ReceiptAckErrorV2> {
        match self.receipts.entry(locator.operation_id) {
            Entry::Vacant(_) => Ok(ReceiptAckDispositionV2::AlreadyAbsent),
            Entry::Occupied(entry) => {
                if entry.get().resulting_authority_version != locator.resulting_authority_version {
                    return Err(ReceiptAckErrorV2::ResultingVersionMismatch);
                }
                entry.remove();
                Ok(ReceiptAckDispositionV2::Removed)
            }
        }
    }

    /// Evaluate one exact mutation after observing trusted witness time.
    pub fn apply<C: TrustedClockV2>(
        &mut self,
        clock: &C,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityReceiptV2, AuthorityErrorV2> {
        let now = self.observe_clock(clock)?;
        if let Some(receipt) = self.receipts.get(&intent.operation_id).copied() {
            return if receipt.intent == intent {
                Ok(receipt)
            } else {
                Err(AuthorityErrorV2::OperationConflict)
            };
        }
        if intent.expected_authority_version != self.authority_version {
            return Err(AuthorityErrorV2::AuthorityVersionMismatch);
        }
        let next_authority_version = self
            .authority_version
            .checked_add(1)
            .ok_or(AuthorityErrorV2::AuthorityVersionExhausted)?;
        if self.receipts.len() >= self.limits.max_receipts {
            return Err(AuthorityErrorV2::ReceiptCapacityExceeded);
        }
        self.reserve_receipt_slot()?;

        let decision = self.plan(now, intent);
        if let Ok(plan) = decision {
            self.reserve_for_plan(plan)?;
            let receipt = AuthorityReceiptV2 {
                intent,
                disposition: AuthorityDispositionV2::Applied,
                resulting_authority_version: next_authority_version,
            };
            self.insert_new_receipt(receipt)?;
            self.apply_plan(plan);
            self.authority_version = next_authority_version;
            Ok(receipt)
        } else {
            let rejection = decision.err().ok_or(AuthorityErrorV2::InternalInvariant)?;
            let receipt = AuthorityReceiptV2 {
                intent,
                disposition: AuthorityDispositionV2::Rejected(rejection),
                resulting_authority_version: next_authority_version,
            };
            self.insert_new_receipt(receipt)?;
            self.authority_version = next_authority_version;
            Ok(receipt)
        }
    }

    fn observe_clock<C: TrustedClockV2>(&mut self, clock: &C) -> Result<u64, AuthorityErrorV2> {
        let observed = clock
            .now_millis()
            .map_err(|_| AuthorityErrorV2::ClockUnavailable)?;
        if observed > self.clock_floor_millis {
            self.clock_floor_millis = observed;
        }
        Ok(self.clock_floor_millis)
    }

    fn plan(
        &self,
        now: u64,
        intent: AuthorityIntentV2,
    ) -> Result<PlannedMutationV2, AuthorityRejectionV2> {
        if intent.expected_config != self.config {
            return Err(AuthorityRejectionV2::ConfigurationMismatch);
        }
        match intent.mutation {
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                instance_id,
            } => self.plan_acquire(now, expected_lease_generation, instance_id),
            AuthorityMutationV2::RenewLease { fence } => {
                let lease = self.require_lease(now, fence)?;
                let expires_at_millis = now
                    .checked_add(self.limits.lease_ttl_millis)
                    .ok_or(AuthorityRejectionV2::MutationOverflow)?;
                if expires_at_millis <= lease.expires_at_millis {
                    return Err(AuthorityRejectionV2::LeaseRenewalNotExtended);
                }
                Ok(PlannedMutationV2::Renew(InstanceLeaseV2 {
                    fence,
                    expires_at_millis,
                }))
            }
            AuthorityMutationV2::ReleaseLease { fence } => {
                self.require_lease(now, fence)?;
                Ok(PlannedMutationV2::Release)
            }
            AuthorityMutationV2::AdvanceState { fence, advance } => {
                self.require_lease(now, fence)?;
                if advance.expected != self.state_head {
                    return Err(AuthorityRejectionV2::StateMismatch);
                }
                Ok(PlannedMutationV2::AdvanceState(advance.next))
            }
            AuthorityMutationV2::AdvanceConfig { fence, advance } => {
                self.require_lease(now, fence)?;
                if advance.expected != self.config {
                    return Err(AuthorityRejectionV2::ConfigTransitionMismatch);
                }
                Ok(PlannedMutationV2::AdvanceConfig(advance.next))
            }
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id,
            } => {
                self.require_lease(now, fence)?;
                if self.capabilities.contains_key(&capability_id) {
                    return Err(AuthorityRejectionV2::CapabilityReplay);
                }
                if self.capabilities.len() >= self.limits.max_capabilities {
                    return Err(AuthorityRejectionV2::CapabilityCapacityExceeded);
                }
                Ok(PlannedMutationV2::Consume {
                    capability_id,
                    record: CapabilityRecordV2 {
                        state_head: self.state_head,
                        config: self.config,
                        consumed_by: fence,
                        key_id: None,
                    },
                })
            }
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id,
                key_id,
            } => self.plan_register(now, fence, capability_id, key_id),
            AuthorityMutationV2::RevokeKey { fence, key_id } => {
                self.require_lease(now, fence)?;
                let key = self
                    .keys
                    .get(&key_id)
                    .ok_or(AuthorityRejectionV2::KeyUnknown)?;
                if key.status == AcceptedKeyStatusV2::Revoked {
                    return Err(AuthorityRejectionV2::KeyRevoked);
                }
                Ok(PlannedMutationV2::Revoke {
                    key_id,
                    record: AcceptedKeyRecordV2 {
                        status: AcceptedKeyStatusV2::Revoked,
                        ..*key
                    },
                })
            }
        }
    }

    fn plan_acquire(
        &self,
        now: u64,
        expected_lease_generation: u64,
        instance_id: ProcessInstanceIdV2,
    ) -> Result<PlannedMutationV2, AuthorityRejectionV2> {
        if matches!(self.lease, Some(lease) if now < lease.expires_at_millis) {
            return Err(AuthorityRejectionV2::LeaseHeld);
        }
        if expected_lease_generation != self.lease_generation {
            return Err(AuthorityRejectionV2::LeaseGenerationMismatch);
        }
        let generation = self
            .lease_generation
            .checked_add(1)
            .ok_or(AuthorityRejectionV2::MutationOverflow)?;
        let fence = InstanceFenceV2::new(generation, instance_id)
            .map_err(|_| AuthorityRejectionV2::MutationOverflow)?;
        let expires_at_millis = now
            .checked_add(self.limits.lease_ttl_millis)
            .ok_or(AuthorityRejectionV2::MutationOverflow)?;
        Ok(PlannedMutationV2::Acquire(InstanceLeaseV2 {
            fence,
            expires_at_millis,
        }))
    }

    fn plan_register(
        &self,
        now: u64,
        fence: InstanceFenceV2,
        capability_id: CapabilityIdV2,
        key_id: AcceptedKeyIdV2,
    ) -> Result<PlannedMutationV2, AuthorityRejectionV2> {
        self.require_lease(now, fence)?;
        if key_id.state_global_generation != self.state_head.revision.global_generation {
            return Err(AuthorityRejectionV2::KeyStateGenerationMismatch);
        }
        if key_id.lease_generation != fence.generation {
            return Err(AuthorityRejectionV2::KeyLeaseGenerationMismatch);
        }
        let capability = self
            .capabilities
            .get(&capability_id)
            .ok_or(AuthorityRejectionV2::CapabilityUnknown)?;
        if capability.state_head != self.state_head
            || capability.config != self.config
            || capability.consumed_by != fence
        {
            return Err(AuthorityRejectionV2::CapabilityStale);
        }
        if capability.key_id.is_some() {
            return Err(AuthorityRejectionV2::CapabilityAlreadyBound);
        }
        if self.keys.contains_key(&key_id) {
            return Err(AuthorityRejectionV2::KeyAlreadyRegistered);
        }
        if self.keys.len() >= self.limits.max_keys {
            return Err(AuthorityRejectionV2::KeyCapacityExceeded);
        }
        Ok(PlannedMutationV2::Register {
            fence,
            capability_id,
            key_id,
        })
    }

    fn require_lease(
        &self,
        now: u64,
        fence: InstanceFenceV2,
    ) -> Result<InstanceLeaseV2, AuthorityRejectionV2> {
        let lease = self.lease.ok_or(AuthorityRejectionV2::LeaseAbsent)?;
        if now >= lease.expires_at_millis {
            return Err(AuthorityRejectionV2::LeaseExpired);
        }
        if lease.fence != fence {
            return Err(AuthorityRejectionV2::FenceMismatch);
        }
        Ok(lease)
    }

    fn reserve_for_plan(&mut self, plan: PlannedMutationV2) -> Result<(), AuthorityErrorV2> {
        match plan {
            PlannedMutationV2::Consume { .. } => self.reserve_capability_slot(),
            PlannedMutationV2::Register { .. } => self.reserve_key_slot(),
            PlannedMutationV2::Acquire(_)
            | PlannedMutationV2::Renew(_)
            | PlannedMutationV2::Release
            | PlannedMutationV2::AdvanceState(_)
            | PlannedMutationV2::AdvanceConfig(_)
            | PlannedMutationV2::Revoke { .. } => Ok(()),
        }
    }

    fn reserve_receipt_slot(&mut self) -> Result<(), AuthorityErrorV2> {
        #[cfg(test)]
        self.fail_reservation_if_requested(ReservationPointV2::Receipt)?;
        self.receipts
            .try_reserve(1)
            .map_err(|_| AuthorityErrorV2::AllocationFailed)
    }

    fn reserve_capability_slot(&mut self) -> Result<(), AuthorityErrorV2> {
        #[cfg(test)]
        self.fail_reservation_if_requested(ReservationPointV2::Capability)?;
        self.capabilities
            .try_reserve(1)
            .map_err(|_| AuthorityErrorV2::AllocationFailed)
    }

    fn reserve_key_slot(&mut self) -> Result<(), AuthorityErrorV2> {
        #[cfg(test)]
        self.fail_reservation_if_requested(ReservationPointV2::Key)?;
        self.keys
            .try_reserve(1)
            .map_err(|_| AuthorityErrorV2::AllocationFailed)
    }

    #[cfg(test)]
    fn fail_reservation_if_requested(
        &mut self,
        point: ReservationPointV2,
    ) -> Result<(), AuthorityErrorV2> {
        if self.fail_next_reservation == Some(point) {
            self.fail_next_reservation = None;
            return Err(AuthorityErrorV2::AllocationFailed);
        }
        Ok(())
    }

    fn insert_new_receipt(&mut self, receipt: AuthorityReceiptV2) -> Result<(), AuthorityErrorV2> {
        match self.receipts.insert(receipt.intent.operation_id, receipt) {
            None => Ok(()),
            Some(original) => {
                self.receipts.insert(original.intent.operation_id, original);
                Err(AuthorityErrorV2::InternalInvariant)
            }
        }
    }

    fn apply_plan(&mut self, plan: PlannedMutationV2) {
        match plan {
            PlannedMutationV2::Acquire(lease) => {
                self.lease_generation = lease.fence.generation;
                self.lease = Some(lease);
                self.keys.clear();
            }
            PlannedMutationV2::Renew(lease) => self.lease = Some(lease),
            PlannedMutationV2::Release => {
                self.lease = None;
                self.keys.clear();
            }
            PlannedMutationV2::AdvanceState(next) => {
                self.state_head = next;
                self.capabilities.clear();
                self.keys.clear();
            }
            PlannedMutationV2::AdvanceConfig(next) => {
                self.config = next;
                self.lease = None;
                self.keys.clear();
            }
            PlannedMutationV2::Consume {
                capability_id,
                record,
            } => {
                self.capabilities.insert(capability_id, record);
            }
            PlannedMutationV2::Register {
                fence,
                capability_id,
                key_id,
            } => {
                self.capabilities.insert(
                    capability_id,
                    CapabilityRecordV2 {
                        state_head: self.state_head,
                        config: self.config,
                        consumed_by: fence,
                        key_id: Some(key_id),
                    },
                );
                self.keys.insert(
                    key_id,
                    AcceptedKeyRecordV2 {
                        capability_id,
                        state_head: self.state_head,
                        config: self.config,
                        registered_by: fence,
                        status: AcceptedKeyStatusV2::Registered,
                    },
                );
            }
            PlannedMutationV2::Revoke { key_id, record } => {
                self.keys.insert(key_id, record);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::error::Error;
    use std::io;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
    const TEST_LEASE_TTL_MILLIS: u64 = HARD_MIN_LEASE_TTL_MILLIS;

    struct FakeClock {
        now: Cell<Option<u64>>,
    }

    impl FakeClock {
        const fn new(now: u64) -> Self {
            Self {
                now: Cell::new(Some(now)),
            }
        }

        fn set(&self, now: u64) {
            self.now.set(Some(now));
        }

        fn fail(&self) {
            self.now.set(None);
        }
    }

    impl TrustedClockV2 for FakeClock {
        fn now_millis(&self) -> Result<u64, TrustedClockErrorV2> {
            self.now.get().ok_or(TrustedClockErrorV2)
        }
    }

    fn operation(
        expected_authority_version: u64,
        byte: u8,
    ) -> Result<OperationIdV2, AuthorityValueErrorV2> {
        OperationIdV2::new(expected_authority_version, [byte; 32])
    }

    fn instance(byte: u8) -> Result<ProcessInstanceIdV2, AuthorityValueErrorV2> {
        ProcessInstanceIdV2::from_bytes([byte; 32])
    }

    fn state_fence(byte: u8) -> Result<StateFenceV2, AuthorityValueErrorV2> {
        StateFenceV2::from_bytes([byte; 32])
    }

    fn capability(byte: u8) -> Result<CapabilityIdV2, AuthorityValueErrorV2> {
        CapabilityIdV2::from_bytes([byte; 32])
    }

    fn key(byte: u8) -> Result<AcceptedKeyIdV2, AuthorityValueErrorV2> {
        key_for_scope(1, 1, byte)
    }

    fn key_for(lease_generation: u64, byte: u8) -> Result<AcceptedKeyIdV2, AuthorityValueErrorV2> {
        key_for_scope(1, lease_generation, byte)
    }

    fn key_for_scope(
        state_global_generation: u64,
        lease_generation: u64,
        byte: u8,
    ) -> Result<AcceptedKeyIdV2, AuthorityValueErrorV2> {
        AcceptedKeyIdV2::new(state_global_generation, lease_generation, [byte; 32])
    }

    fn revision(
        generation: u64,
        chain: u8,
        epoch: u64,
        digest: u8,
    ) -> Result<StateRevisionV2, AuthorityValueErrorV2> {
        StateRevisionV2::new(generation, [chain; 32], epoch, [digest; 32])
    }

    fn head(
        generation: u64,
        chain: u8,
        epoch: u64,
        digest: u8,
        fence: u8,
    ) -> Result<StateHeadV2, AuthorityValueErrorV2> {
        Ok(StateHeadV2::new(
            revision(generation, chain, epoch, digest)?,
            state_fence(fence)?,
        ))
    }

    fn config(
        generation: u64,
        digest: u8,
    ) -> Result<DeploymentConfigRevisionV2, AuthorityValueErrorV2> {
        DeploymentConfigRevisionV2::new(generation, [digest; 32])
    }

    fn limits(
        receipts: usize,
        capabilities: usize,
        keys: usize,
        ttl: u64,
    ) -> Result<AuthorityLimitsV2, AuthorityValueErrorV2> {
        AuthorityLimitsV2::new(receipts, capabilities, keys, ttl)
    }

    fn fixture(
        clock: &FakeClock,
        configured_limits: AuthorityLimitsV2,
    ) -> Result<AuthorityStateV2, AuthorityErrorV2> {
        AuthorityStateV2::provision(
            head(1, 1, 1, 1, 1).map_err(|_| AuthorityErrorV2::InternalInvariant)?,
            config(1, 1).map_err(|_| AuthorityErrorV2::InternalInvariant)?,
            configured_limits,
            clock,
        )
    }

    fn current_intent(
        state: &mut AuthorityStateV2,
        clock: &FakeClock,
        operation_byte: u8,
        mutation: AuthorityMutationV2,
    ) -> TestResult<AuthorityIntentV2> {
        let snapshot = state.snapshot(clock)?;
        Ok(AuthorityIntentV2::new(
            operation(snapshot.authority_version(), operation_byte)?,
            snapshot.authority_version(),
            snapshot.config(),
            mutation,
        )?)
    }

    fn apply_current(
        state: &mut AuthorityStateV2,
        clock: &FakeClock,
        operation_byte: u8,
        mutation: AuthorityMutationV2,
    ) -> TestResult<AuthorityReceiptV2> {
        let intent = current_intent(state, clock, operation_byte, mutation)?;
        Ok(state.apply(clock, intent)?)
    }

    fn require_lease(snapshot: AuthoritySnapshotV2) -> TestResult<InstanceLeaseV2> {
        snapshot
            .active_lease()
            .ok_or_else(|| io::Error::other("expected one active authority lease").into())
    }

    fn acquire(
        state: &mut AuthorityStateV2,
        clock: &FakeClock,
        operation_byte: u8,
        instance_byte: u8,
    ) -> TestResult<InstanceFenceV2> {
        let expected_generation = state.snapshot(clock)?.lease_generation();
        let receipt = apply_current(
            state,
            clock,
            operation_byte,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: expected_generation,
                instance_id: instance(instance_byte)?,
            },
        )?;
        assert_eq!(receipt.disposition(), AuthorityDispositionV2::Applied);
        Ok(require_lease(state.snapshot(clock)?)?.fence())
    }

    fn assert_rejected(receipt: AuthorityReceiptV2, expected: AuthorityRejectionV2) {
        assert_eq!(
            receipt.disposition(),
            AuthorityDispositionV2::Rejected(expected)
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct TestDomainState {
        clock_floor_millis: u64,
        config: DeploymentConfigRevisionV2,
        state_head: StateHeadV2,
        lease_generation: u64,
        lease: Option<InstanceLeaseV2>,
        capabilities: HashMap<CapabilityIdV2, CapabilityRecordV2>,
        keys: HashMap<AcceptedKeyIdV2, AcceptedKeyRecordV2>,
    }

    fn test_domain_state(state: &AuthorityStateV2) -> TestDomainState {
        TestDomainState {
            clock_floor_millis: state.clock_floor_millis,
            config: state.config,
            state_head: state.state_head,
            lease_generation: state.lease_generation,
            lease: state.lease,
            capabilities: state.capabilities.clone(),
            keys: state.keys.clone(),
        }
    }

    fn apply_receipted_rejection(
        state: &mut AuthorityStateV2,
        clock: &FakeClock,
        intent: AuthorityIntentV2,
        expected: AuthorityRejectionV2,
    ) -> TestResult<AuthorityReceiptV2> {
        let domain_before = test_domain_state(state);
        let version_before = state.authority_version;
        let receipt_count_before = state.receipts.len();
        let receipt = state.apply(clock, intent)?;
        assert_rejected(receipt, expected);
        assert_eq!(test_domain_state(state), domain_before);
        assert_eq!(
            state.authority_version,
            version_before
                .checked_add(1)
                .ok_or(AuthorityErrorV2::InternalInvariant)?
        );
        assert_eq!(state.receipts.len(), receipt_count_before + 1);
        assert_eq!(state.receipt(intent.operation_id()), Some(receipt));
        assert_eq!(
            receipt.resulting_authority_version(),
            state.authority_version
        );
        Ok(receipt)
    }

    #[test]
    fn state_and_config_revisions_require_exact_successors() -> TestResult {
        assert_eq!(
            StateRevisionV2::new(0, [1; 32], 1, [1; 32]),
            Err(AuthorityValueErrorV2::InvalidCounter)
        );
        assert_eq!(
            StateRevisionV2::new(1, [0; 32], 1, [1; 32]),
            Err(AuthorityValueErrorV2::InvalidIdentifier)
        );
        assert_eq!(
            StateRevisionV2::new(1, [1; 32], 1, [0; 32]),
            Err(AuthorityValueErrorV2::InvalidDigest)
        );
        let original = revision(1, 1, 1, 1)?;
        let other_chain = revision(1, 2, 1, 1)?;
        assert_ne!(original, other_chain);

        let initial = head(1, 1, 1, 1, 1)?;
        let advanced = head(2, 1, 2, 2, 2)?;
        let reset = head(2, 2, 1, 3, 3)?;
        assert!(StateAdvanceV2::new(StateTransitionKindV2::Advance, initial, advanced).is_ok());
        assert!(
            StateAdvanceV2::new(StateTransitionKindV2::AuthorizedReset, initial, reset).is_ok()
        );
        assert_eq!(reset.revision().global_generation(), 2);
        assert_ne!(key_for_scope(1, 1, 1)?, key_for_scope(2, 1, 1)?);
        assert_eq!(
            StateAdvanceV2::new(StateTransitionKindV2::Advance, initial, reset),
            Err(AuthorityValueErrorV2::InvalidTransition)
        );
        assert_eq!(
            StateAdvanceV2::new(StateTransitionKindV2::AuthorizedReset, initial, advanced),
            Err(AuthorityValueErrorV2::InvalidTransition)
        );

        let config_one = config(1, 1)?;
        let config_two = config(2, 2)?;
        assert!(ConfigAdvanceV2::new(config_one, config_two).is_ok());
        assert_eq!(
            ConfigAdvanceV2::new(config_one, config(2, 1)?),
            Err(AuthorityValueErrorV2::InvalidTransition)
        );
        assert_eq!(
            DeploymentConfigRevisionV2::new(u64::MAX, [1; 32]),
            Err(AuthorityValueErrorV2::InvalidCounter)
        );
        Ok(())
    }

    #[test]
    fn limits_and_identifiers_reject_reserved_values() -> TestResult {
        assert_eq!(
            AuthorityLimitsV2::new(0, 1, 1, 1),
            Err(AuthorityValueErrorV2::InvalidLimit)
        );
        assert_eq!(
            AuthorityLimitsV2::new(1, 1, 1, HARD_MIN_LEASE_TTL_MILLIS - 1),
            Err(AuthorityValueErrorV2::InvalidLimit)
        );
        assert_eq!(
            AuthorityLimitsV2::new(1, 1, 1, HARD_MAX_LEASE_TTL_MILLIS + 1),
            Err(AuthorityValueErrorV2::InvalidLimit)
        );
        assert_eq!(
            OperationIdV2::new(1, [0; 32]),
            Err(AuthorityValueErrorV2::InvalidIdentifier)
        );
        assert_eq!(
            OperationIdV2::new(0, [1; 32]),
            Err(AuthorityValueErrorV2::InvalidCounter)
        );
        assert_ne!(
            OperationIdV2::new(1, [1; 32])?,
            OperationIdV2::new(2, [1; 32])?
        );
        assert_eq!(
            InstanceFenceV2::new(0, instance(1)?),
            Err(AuthorityValueErrorV2::InvalidCounter)
        );
        assert_eq!(
            AcceptedKeyIdV2::new(0, 1, [1; 32]),
            Err(AuthorityValueErrorV2::InvalidCounter)
        );
        assert_eq!(
            AcceptedKeyIdV2::new(u64::MAX, 1, [1; 32]),
            Err(AuthorityValueErrorV2::InvalidCounter)
        );
        assert_eq!(
            AcceptedKeyIdV2::new(1, 0, [1; 32]),
            Err(AuthorityValueErrorV2::InvalidCounter)
        );
        assert_eq!(
            AcceptedKeyIdV2::new(1, 1, [0; 32]),
            Err(AuthorityValueErrorV2::InvalidIdentifier)
        );
        Ok(())
    }

    #[test]
    fn mutation_set_is_closed_to_eight_stage_one_transitions() -> TestResult {
        fn tag(mutation: AuthorityMutationV2) -> u8 {
            match mutation {
                AuthorityMutationV2::AcquireLease { .. } => 1,
                AuthorityMutationV2::RenewLease { .. } => 2,
                AuthorityMutationV2::ReleaseLease { .. } => 3,
                AuthorityMutationV2::AdvanceState { .. } => 4,
                AuthorityMutationV2::AdvanceConfig { .. } => 5,
                AuthorityMutationV2::ConsumeCapability { .. } => 6,
                AuthorityMutationV2::RegisterKey { .. } => 7,
                AuthorityMutationV2::RevokeKey { .. } => 8,
            }
        }

        let fence = InstanceFenceV2::new(1, instance(1)?)?;
        let state_advance = StateAdvanceV2::new(
            StateTransitionKindV2::Advance,
            head(1, 1, 1, 1, 1)?,
            head(2, 1, 2, 2, 2)?,
        )?;
        let config_advance = ConfigAdvanceV2::new(config(1, 1)?, config(2, 2)?)?;
        let mutations = [
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(1)?,
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
                capability_id: capability(1)?,
            },
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: key(1)?,
            },
            AuthorityMutationV2::RevokeKey {
                fence,
                key_id: key(1)?,
            },
        ];
        assert_eq!(mutations.map(tag), [1, 2, 3, 4, 5, 6, 7, 8]);
        Ok(())
    }

    #[test]
    fn lease_is_exclusive_and_old_fences_are_rejected() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 4, 4, TEST_LEASE_TTL_MILLIS)?)?;
        let first_fence = acquire(&mut state, &clock, 1, 11)?;
        let first_lease = require_lease(state.snapshot(&clock)?)?;
        assert_eq!(first_lease.expires_at_millis(), 10_100);

        let held = apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 1,
                instance_id: instance(12)?,
            },
        )?;
        assert_rejected(held, AuthorityRejectionV2::LeaseHeld);

        clock.set(10_100);
        let second_fence = acquire(&mut state, &clock, 3, 12)?;
        assert_eq!(second_fence.generation(), 2);
        let stale = apply_current(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::ConsumeCapability {
                fence: first_fence,
                capability_id: capability(1)?,
            },
        )?;
        assert_rejected(stale, AuthorityRejectionV2::FenceMismatch);
        Ok(())
    }

    #[test]
    fn trusted_clock_floor_prevents_expired_lease_revival() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(16, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let acquire_intent = current_intent(
            &mut state,
            &clock,
            1,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(11)?,
            },
        )?;
        let acquire_receipt = state.apply(&clock, acquire_intent)?;
        let fence = require_lease(state.snapshot(&clock)?)?.fence();

        clock.set(10_140);
        assert_eq!(state.apply(&clock, acquire_intent)?, acquire_receipt);
        let expired_snapshot = state.snapshot(&clock)?;
        assert_eq!(expired_snapshot.clock_floor_millis(), 10_140);
        assert_eq!(expired_snapshot.active_lease(), None);

        clock.set(90);
        let expired = apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::RenewLease { fence },
        )?;
        assert_rejected(expired, AuthorityRejectionV2::LeaseExpired);
        assert_eq!(state.snapshot(&clock)?.clock_floor_millis(), 10_140);
        assert_eq!(state.snapshot(&clock)?.active_lease(), None);
        Ok(())
    }

    #[test]
    fn clock_failure_has_no_state_effect() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(8, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let acquire_intent = current_intent(
            &mut state,
            &clock,
            1,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(1)?,
            },
        )?;
        let receipt = state.apply(&clock, acquire_intent)?;
        let fence = require_lease(state.snapshot(&clock)?)?.fence();
        let conflicting = AuthorityIntentV2::new(
            acquire_intent.operation_id(),
            acquire_intent.expected_authority_version(),
            acquire_intent.expected_config(),
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(2)?,
            },
        )?;
        let fresh = current_intent(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        let domain_before = test_domain_state(&state);
        clock.fail();
        assert_eq!(
            state.snapshot(&clock),
            Err(AuthorityErrorV2::ClockUnavailable)
        );
        assert_eq!(
            state.apply(&clock, acquire_intent),
            Err(AuthorityErrorV2::ClockUnavailable)
        );
        assert_eq!(
            state.apply(&clock, conflicting),
            Err(AuthorityErrorV2::ClockUnavailable)
        );
        assert_eq!(
            state.apply(&clock, fresh),
            Err(AuthorityErrorV2::ClockUnavailable)
        );
        assert_eq!(state.receipt(acquire_intent.operation_id()), Some(receipt));
        assert_eq!(test_domain_state(&state), domain_before);
        assert_eq!(state.authority_version, 2);
        assert_eq!(state.receipts.len(), 1);
        Ok(())
    }

    #[test]
    fn provision_fails_closed_when_trusted_clock_is_unavailable() -> TestResult {
        let clock = FakeClock::new(100);
        clock.fail();
        assert!(matches!(
            AuthorityStateV2::provision(
                head(1, 1, 1, 1, 1)?,
                config(1, 1)?,
                limits(4, 1, 1, TEST_LEASE_TTL_MILLIS)?,
                &clock,
            ),
            Err(AuthorityErrorV2::ClockUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn renew_strictly_extends_and_release_clears_keys_only() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        let too_early = apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::RenewLease { fence },
        )?;
        assert_rejected(too_early, AuthorityRejectionV2::LeaseRenewalNotExtended);
        clock.set(110);
        let renewed = apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::RenewLease { fence },
        )?;
        assert_eq!(renewed.disposition(), AuthorityDispositionV2::Applied);
        assert_eq!(
            require_lease(state.snapshot(&clock)?)?.expires_at_millis(),
            10_110
        );

        apply_current(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        let old_state_key = key_for_scope(1, fence.generation(), 1)?;
        apply_current(
            &mut state,
            &clock,
            5,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: old_state_key,
            },
        )?;
        apply_current(
            &mut state,
            &clock,
            6,
            AuthorityMutationV2::ReleaseLease { fence },
        )?;
        let released = state.snapshot(&clock)?;
        assert_eq!(released.active_lease(), None);
        assert_eq!(released.retained_key_count(), 0);
        assert_eq!(released.active_key_count(), 0);
        assert_eq!(released.capability_count(), 1);
        Ok(())
    }

    #[test]
    fn exact_receipts_are_stable_and_conflicting_reuse_fails() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(2, 2, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        let consume_intent = current_intent(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        let first = state.apply(&clock, consume_intent)?;
        let version = state.snapshot(&clock)?.authority_version();
        assert_eq!(state.apply(&clock, consume_intent)?, first);
        assert_eq!(state.snapshot(&clock)?.authority_version(), version);

        let conflicting = AuthorityIntentV2::new(
            consume_intent.operation_id(),
            consume_intent.expected_authority_version(),
            consume_intent.expected_config(),
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(2)?,
            },
        )?;
        assert_eq!(
            state.apply(&clock, conflicting),
            Err(AuthorityErrorV2::OperationConflict)
        );
        let new_operation = current_intent(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::ReleaseLease { fence },
        )?;
        assert_eq!(
            state.apply(&clock, new_operation),
            Err(AuthorityErrorV2::ReceiptCapacityExceeded)
        );
        assert_eq!(state.apply(&clock, consume_intent)?, first);
        Ok(())
    }

    #[test]
    fn receipt_acknowledgement_restores_capacity_without_reexecuting_old_intent() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(1, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let intent = current_intent(
            &mut state,
            &clock,
            1,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(11)?,
            },
        )?;
        let receipt = state.apply(&clock, intent)?;
        let fence = require_lease(state.snapshot(&clock)?)?.fence();
        let blocked = current_intent(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ReleaseLease { fence },
        )?;
        assert_eq!(
            state.apply(&clock, blocked),
            Err(AuthorityErrorV2::ReceiptCapacityExceeded)
        );

        clock.fail();
        assert_eq!(state.receipt(intent.operation_id()), Some(receipt));
        assert_eq!(
            state.apply(&clock, intent),
            Err(AuthorityErrorV2::ClockUnavailable)
        );
        let wrong_locator = ReceiptLocatorV2::new(
            intent.operation_id(),
            receipt
                .resulting_authority_version()
                .checked_add(1)
                .ok_or(AuthorityErrorV2::InternalInvariant)?,
        )?;
        assert_eq!(
            state.acknowledge_receipt(wrong_locator),
            Err(ReceiptAckErrorV2::ResultingVersionMismatch)
        );
        assert_eq!(
            state.acknowledge_receipt(receipt.locator()),
            Ok(ReceiptAckDispositionV2::Removed)
        );
        assert_eq!(
            state.acknowledge_receipt(receipt.locator()),
            Ok(ReceiptAckDispositionV2::AlreadyAbsent)
        );
        assert_eq!(state.authority_version, 2);
        assert_eq!(
            AuthorityIntentV2::new(
                intent.operation_id(),
                2,
                intent.expected_config(),
                AuthorityMutationV2::ReleaseLease { fence },
            ),
            Err(AuthorityValueErrorV2::InvalidTransition)
        );

        clock.set(100);
        assert_eq!(
            state.apply(&clock, intent),
            Err(AuthorityErrorV2::AuthorityVersionMismatch)
        );
        let same_random_new_version = AuthorityIntentV2::new(
            operation(2, 1)?,
            2,
            intent.expected_config(),
            AuthorityMutationV2::ReleaseLease { fence },
        )?;
        assert_ne!(
            same_random_new_version.operation_id(),
            intent.operation_id()
        );
        let released = state.apply(&clock, same_random_new_version)?;
        assert_eq!(released.disposition(), AuthorityDispositionV2::Applied);
        assert_eq!(
            state.acknowledge_receipt(receipt.locator()),
            Ok(ReceiptAckDispositionV2::AlreadyAbsent)
        );
        assert_eq!(
            state.receipt(same_random_new_version.operation_id()),
            Some(released)
        );
        assert_eq!(state.snapshot(&clock)?.receipt_count(), 1);
        Ok(())
    }

    #[test]
    fn reservation_failures_are_atomic_and_exactly_retryable() -> TestResult {
        let receipt_clock = FakeClock::new(100);
        let mut receipt_state = fixture(&receipt_clock, limits(8, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let acquire_intent = current_intent(
            &mut receipt_state,
            &receipt_clock,
            1,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(1)?,
            },
        )?;
        let mut expected_after_clock = test_domain_state(&receipt_state);
        expected_after_clock.clock_floor_millis = 200;
        receipt_clock.set(200);
        receipt_state.fail_next_reservation = Some(ReservationPointV2::Receipt);
        assert_eq!(
            receipt_state.apply(&receipt_clock, acquire_intent),
            Err(AuthorityErrorV2::AllocationFailed)
        );
        assert_eq!(test_domain_state(&receipt_state), expected_after_clock);
        assert_eq!(receipt_state.authority_version, 1);
        assert!(receipt_state.receipts.is_empty());
        assert_eq!(receipt_state.fail_next_reservation, None);
        let acquire_receipt = receipt_state.apply(&receipt_clock, acquire_intent)?;
        assert_eq!(
            acquire_receipt.disposition(),
            AuthorityDispositionV2::Applied
        );

        let capability_clock = FakeClock::new(100);
        let mut capability_state =
            fixture(&capability_clock, limits(8, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let capability_fence = acquire(&mut capability_state, &capability_clock, 1, 1)?;
        let capability_id = capability(1)?;
        let consume_intent = current_intent(
            &mut capability_state,
            &capability_clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence: capability_fence,
                capability_id,
            },
        )?;
        let capability_domain_before = test_domain_state(&capability_state);
        let capability_version_before = capability_state.authority_version;
        let capability_receipts_before = capability_state.receipts.clone();
        capability_state.fail_next_reservation = Some(ReservationPointV2::Capability);
        assert_eq!(
            capability_state.apply(&capability_clock, consume_intent),
            Err(AuthorityErrorV2::AllocationFailed)
        );
        assert_eq!(
            test_domain_state(&capability_state),
            capability_domain_before
        );
        assert_eq!(
            capability_state.authority_version,
            capability_version_before
        );
        assert_eq!(capability_state.receipts, capability_receipts_before);
        assert_eq!(capability_state.fail_next_reservation, None);
        assert_eq!(
            capability_state.receipt(consume_intent.operation_id()),
            None
        );
        let consume_receipt = capability_state.apply(&capability_clock, consume_intent)?;
        assert_eq!(
            consume_receipt.disposition(),
            AuthorityDispositionV2::Applied
        );
        assert_eq!(capability_state.capabilities.len(), 1);

        let key_clock = FakeClock::new(100);
        let mut key_state = fixture(&key_clock, limits(8, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let key_fence = acquire(&mut key_state, &key_clock, 1, 1)?;
        let key_capability_id = capability(1)?;
        apply_current(
            &mut key_state,
            &key_clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence: key_fence,
                capability_id: key_capability_id,
            },
        )?;
        let key_id = key_for_scope(1, key_fence.generation(), 1)?;
        let register_intent = current_intent(
            &mut key_state,
            &key_clock,
            3,
            AuthorityMutationV2::RegisterKey {
                fence: key_fence,
                capability_id: key_capability_id,
                key_id,
            },
        )?;
        let key_domain_before = test_domain_state(&key_state);
        let key_version_before = key_state.authority_version;
        let key_receipts_before = key_state.receipts.clone();
        key_state.fail_next_reservation = Some(ReservationPointV2::Key);
        assert_eq!(
            key_state.apply(&key_clock, register_intent),
            Err(AuthorityErrorV2::AllocationFailed)
        );
        assert_eq!(test_domain_state(&key_state), key_domain_before);
        assert_eq!(key_state.authority_version, key_version_before);
        assert_eq!(key_state.receipts, key_receipts_before);
        assert_eq!(key_state.fail_next_reservation, None);
        assert_eq!(key_state.receipt(register_intent.operation_id()), None);
        assert_eq!(
            key_state
                .capabilities
                .get(&key_capability_id)
                .copied()
                .ok_or_else(|| io::Error::other("expected retained capability"))?
                .key_id,
            None
        );
        assert!(key_state.keys.is_empty());
        let register_receipt = key_state.apply(&key_clock, register_intent)?;
        assert_eq!(
            register_receipt.disposition(),
            AuthorityDispositionV2::Applied
        );
        assert_eq!(
            key_state
                .capabilities
                .get(&key_capability_id)
                .copied()
                .ok_or_else(|| io::Error::other("expected bound capability"))?
                .key_id,
            Some(key_id)
        );
        assert!(key_state.keys.contains_key(&key_id));
        Ok(())
    }

    #[test]
    fn semantic_rejections_have_exact_receipts() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(8, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let intent = current_intent(
            &mut state,
            &clock,
            1,
            AuthorityMutationV2::ReleaseLease {
                fence: InstanceFenceV2::new(1, instance(1)?)?,
            },
        )?;
        let receipt = state.apply(&clock, intent)?;
        assert_rejected(receipt, AuthorityRejectionV2::LeaseAbsent);
        assert_eq!(receipt.resulting_authority_version(), 2);
        assert_eq!(state.apply(&clock, intent)?, receipt);
        assert_eq!(state.snapshot(&clock)?.authority_version(), 2);
        Ok(())
    }

    #[test]
    fn closed_rejections_are_receipted_without_domain_mutation() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;

        let initial = state.snapshot(&clock)?;
        let configuration_mismatch = AuthorityIntentV2::new(
            operation(initial.authority_version(), 1)?,
            initial.authority_version(),
            config(9, 9)?,
            AuthorityMutationV2::ReleaseLease {
                fence: InstanceFenceV2::new(1, instance(1)?)?,
            },
        )?;
        apply_receipted_rejection(
            &mut state,
            &clock,
            configuration_mismatch,
            AuthorityRejectionV2::ConfigurationMismatch,
        )?;

        let lease_generation_mismatch = current_intent(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 1,
                instance_id: instance(1)?,
            },
        )?;
        apply_receipted_rejection(
            &mut state,
            &clock,
            lease_generation_mismatch,
            AuthorityRejectionV2::LeaseGenerationMismatch,
        )?;

        let first_fence = acquire(&mut state, &clock, 3, 11)?;
        let wrong_config_advance = ConfigAdvanceV2::new(config(5, 5)?, config(6, 6)?)?;
        let config_transition_mismatch = current_intent(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::AdvanceConfig {
                fence: first_fence,
                advance: wrong_config_advance,
            },
        )?;
        apply_receipted_rejection(
            &mut state,
            &clock,
            config_transition_mismatch,
            AuthorityRejectionV2::ConfigTransitionMismatch,
        )?;

        apply_current(
            &mut state,
            &clock,
            5,
            AuthorityMutationV2::ConsumeCapability {
                fence: first_fence,
                capability_id: capability(1)?,
            },
        )?;
        clock.set(10_100);
        let second_fence = acquire(&mut state, &clock, 6, 12)?;
        let stale_capability = current_intent(
            &mut state,
            &clock,
            7,
            AuthorityMutationV2::RegisterKey {
                fence: second_fence,
                capability_id: capability(1)?,
                key_id: key_for(second_fence.generation(), 1)?,
            },
        )?;
        apply_receipted_rejection(
            &mut state,
            &clock,
            stale_capability,
            AuthorityRejectionV2::CapabilityStale,
        )?;

        let unknown_key = current_intent(
            &mut state,
            &clock,
            8,
            AuthorityMutationV2::RevokeKey {
                fence: second_fence,
                key_id: key_for(second_fence.generation(), 9)?,
            },
        )?;
        apply_receipted_rejection(
            &mut state,
            &clock,
            unknown_key,
            AuthorityRejectionV2::KeyUnknown,
        )?;
        Ok(())
    }

    #[test]
    fn capability_consumption_is_one_shot() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(16, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        let first = apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        assert_eq!(first.disposition(), AuthorityDispositionV2::Applied);
        let replay = apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        assert_rejected(replay, AuthorityRejectionV2::CapabilityReplay);
        let full = apply_current(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(2)?,
            },
        )?;
        assert_rejected(full, AuthorityRejectionV2::CapabilityCapacityExceeded);
        assert_eq!(state.snapshot(&clock)?.capability_count(), 1);
        Ok(())
    }

    #[test]
    fn key_registration_and_revocation_are_closed() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 3, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        let missing = apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: key(1)?,
            },
        )?;
        assert_rejected(missing, AuthorityRejectionV2::CapabilityUnknown);

        apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        let wrong_generation = apply_current(
            &mut state,
            &clock,
            30,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: key_for(2, 1)?,
            },
        )?;
        assert_rejected(
            wrong_generation,
            AuthorityRejectionV2::KeyLeaseGenerationMismatch,
        );
        apply_current(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: key(1)?,
            },
        )?;
        let rebound = apply_current(
            &mut state,
            &clock,
            5,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: key(2)?,
            },
        )?;
        assert_rejected(rebound, AuthorityRejectionV2::CapabilityAlreadyBound);

        apply_current(
            &mut state,
            &clock,
            6,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(2)?,
            },
        )?;
        let duplicate_key = apply_current(
            &mut state,
            &clock,
            7,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(2)?,
                key_id: key(1)?,
            },
        )?;
        assert_rejected(duplicate_key, AuthorityRejectionV2::KeyAlreadyRegistered);

        let revoked = apply_current(
            &mut state,
            &clock,
            8,
            AuthorityMutationV2::RevokeKey {
                fence,
                key_id: key(1)?,
            },
        )?;
        assert_eq!(revoked.disposition(), AuthorityDispositionV2::Applied);
        let again = apply_current(
            &mut state,
            &clock,
            9,
            AuthorityMutationV2::RevokeKey {
                fence,
                key_id: key(1)?,
            },
        )?;
        assert_rejected(again, AuthorityRejectionV2::KeyRevoked);
        assert_eq!(state.snapshot(&clock)?.retained_key_count(), 1);
        assert_eq!(state.snapshot(&clock)?.active_key_count(), 0);
        Ok(())
    }

    #[test]
    fn expired_keys_are_fenced_and_cannot_alias_the_next_lease() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 3, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let first_fence = acquire(&mut state, &clock, 1, 11)?;
        apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence: first_fence,
                capability_id: capability(1)?,
            },
        )?;
        let old_key = key_for(first_fence.generation(), 1)?;
        apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::RegisterKey {
                fence: first_fence,
                capability_id: capability(1)?,
                key_id: old_key,
            },
        )?;

        clock.set(10_100);
        let expired = state.snapshot(&clock)?;
        assert_eq!(expired.active_lease(), None);
        assert_eq!(expired.retained_key_count(), 1);
        assert_eq!(expired.active_key_count(), 0);

        let second_fence = acquire(&mut state, &clock, 4, 12)?;
        assert_eq!(second_fence.generation(), 2);
        assert_eq!(state.snapshot(&clock)?.retained_key_count(), 0);
        apply_current(
            &mut state,
            &clock,
            5,
            AuthorityMutationV2::ConsumeCapability {
                fence: second_fence,
                capability_id: capability(2)?,
            },
        )?;
        let old_generation = apply_current(
            &mut state,
            &clock,
            6,
            AuthorityMutationV2::RegisterKey {
                fence: second_fence,
                capability_id: capability(2)?,
                key_id: old_key,
            },
        )?;
        assert_rejected(
            old_generation,
            AuthorityRejectionV2::KeyLeaseGenerationMismatch,
        );
        let new_key = key_for(second_fence.generation(), 1)?;
        assert_ne!(new_key, old_key);
        let registered = apply_current(
            &mut state,
            &clock,
            7,
            AuthorityMutationV2::RegisterKey {
                fence: second_fence,
                capability_id: capability(2)?,
                key_id: new_key,
            },
        )?;
        assert_eq!(registered.disposition(), AuthorityDispositionV2::Applied);
        assert_eq!(state.snapshot(&clock)?.active_key_count(), 1);
        Ok(())
    }

    #[test]
    fn key_capacity_never_evicts_an_existing_record() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 2, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        for (operation_byte, capability_byte) in [(2, 1), (3, 2)] {
            apply_current(
                &mut state,
                &clock,
                operation_byte,
                AuthorityMutationV2::ConsumeCapability {
                    fence,
                    capability_id: capability(capability_byte)?,
                },
            )?;
        }
        apply_current(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: key(1)?,
            },
        )?;
        let full = apply_current(
            &mut state,
            &clock,
            5,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(2)?,
                key_id: key(2)?,
            },
        )?;
        assert_rejected(full, AuthorityRejectionV2::KeyCapacityExceeded);
        assert_eq!(state.snapshot(&clock)?.retained_key_count(), 1);
        assert_eq!(state.snapshot(&clock)?.active_key_count(), 1);
        assert!(state.keys.contains_key(&key(1)?));
        Ok(())
    }

    #[test]
    fn state_advance_atomically_invalidates_capabilities_and_keys() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        let old_state_key = key_for_scope(1, fence.generation(), 1)?;
        apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: old_state_key,
            },
        )?;
        let original_head = state.snapshot(&clock)?.state_head();
        let next_head = head(2, 1, 2, 2, 2)?;
        let transition =
            StateAdvanceV2::new(StateTransitionKindV2::Advance, original_head, next_head)?;
        let receipt = apply_current(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::AdvanceState {
                fence,
                advance: transition,
            },
        )?;
        assert_eq!(receipt.disposition(), AuthorityDispositionV2::Applied);
        let snapshot = state.snapshot(&clock)?;
        assert_eq!(snapshot.state_head(), next_head);
        assert_eq!(snapshot.capability_count(), 0);
        assert_eq!(snapshot.retained_key_count(), 0);
        assert_eq!(snapshot.active_key_count(), 0);
        assert_eq!(require_lease(snapshot)?.fence(), fence);
        let new_state_scope = apply_current(
            &mut state,
            &clock,
            5,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        assert_eq!(
            new_state_scope.disposition(),
            AuthorityDispositionV2::Applied
        );
        assert_eq!(state.snapshot(&clock)?.capability_count(), 1);
        let stale_key_id = current_intent(
            &mut state,
            &clock,
            6,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: old_state_key,
            },
        )?;
        apply_receipted_rejection(
            &mut state,
            &clock,
            stale_key_id,
            AuthorityRejectionV2::KeyStateGenerationMismatch,
        )?;
        let new_state_key = key_for_scope(2, fence.generation(), 1)?;
        assert_ne!(old_state_key, new_state_key);
        assert_eq!(new_state_key.state_global_generation(), 2);
        assert_eq!(new_state_key.lease_generation(), fence.generation());
        let registered = apply_current(
            &mut state,
            &clock,
            7,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: new_state_key,
            },
        )?;
        assert_eq!(registered.disposition(), AuthorityDispositionV2::Applied);
        assert_eq!(state.snapshot(&clock)?.active_key_count(), 1);
        Ok(())
    }

    #[test]
    fn rejected_state_advance_preserves_domain_records() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        let wrong_expected = head(4, 4, 4, 4, 4)?;
        let wrong_next = head(5, 4, 5, 5, 5)?;
        let advance =
            StateAdvanceV2::new(StateTransitionKindV2::Advance, wrong_expected, wrong_next)?;
        let before = state.snapshot(&clock)?;
        let rejected = apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::AdvanceState { fence, advance },
        )?;
        assert_rejected(rejected, AuthorityRejectionV2::StateMismatch);
        let after = state.snapshot(&clock)?;
        assert_eq!(after.state_head(), before.state_head());
        assert_eq!(after.capability_count(), before.capability_count());
        assert_eq!(after.retained_key_count(), before.retained_key_count());
        assert_eq!(after.active_key_count(), before.active_key_count());
        assert_eq!(after.authority_version(), before.authority_version() + 1);
        Ok(())
    }

    #[test]
    fn config_advance_fences_lease_and_keys_but_preserves_capabilities() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(32, 2, 2, TEST_LEASE_TTL_MILLIS)?)?;
        let fence = acquire(&mut state, &clock, 1, 11)?;
        apply_current(
            &mut state,
            &clock,
            2,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(1)?,
            },
        )?;
        apply_current(
            &mut state,
            &clock,
            3,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id: capability(1)?,
                key_id: key(1)?,
            },
        )?;
        let before = state.snapshot(&clock)?;
        let next_config = config(2, 2)?;
        let advance = ConfigAdvanceV2::new(before.config(), next_config)?;
        apply_current(
            &mut state,
            &clock,
            4,
            AuthorityMutationV2::AdvanceConfig { fence, advance },
        )?;
        let after = state.snapshot(&clock)?;
        assert_eq!(after.config(), next_config);
        assert_eq!(after.state_head(), before.state_head());
        assert_eq!(after.active_lease(), None);
        assert_eq!(after.retained_key_count(), 0);
        assert_eq!(after.active_key_count(), 0);
        assert_eq!(after.capability_count(), 1);

        let old_fence = apply_current(
            &mut state,
            &clock,
            5,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id: capability(2)?,
            },
        )?;
        assert_rejected(old_fence, AuthorityRejectionV2::LeaseAbsent);
        let new_fence = acquire(&mut state, &clock, 6, 12)?;
        let preserved = apply_current(
            &mut state,
            &clock,
            7,
            AuthorityMutationV2::ConsumeCapability {
                fence: new_fence,
                capability_id: capability(1)?,
            },
        )?;
        assert_rejected(preserved, AuthorityRejectionV2::CapabilityReplay);
        apply_current(
            &mut state,
            &clock,
            8,
            AuthorityMutationV2::ConsumeCapability {
                fence: new_fence,
                capability_id: capability(2)?,
            },
        )?;
        let old_config_key = key_for_scope(1, fence.generation(), 1)?;
        let wrong_lease_generation = current_intent(
            &mut state,
            &clock,
            9,
            AuthorityMutationV2::RegisterKey {
                fence: new_fence,
                capability_id: capability(2)?,
                key_id: old_config_key,
            },
        )?;
        apply_receipted_rejection(
            &mut state,
            &clock,
            wrong_lease_generation,
            AuthorityRejectionV2::KeyLeaseGenerationMismatch,
        )?;
        let new_config_key = key_for_scope(1, new_fence.generation(), 1)?;
        assert_ne!(old_config_key, new_config_key);
        let registered = apply_current(
            &mut state,
            &clock,
            10,
            AuthorityMutationV2::RegisterKey {
                fence: new_fence,
                capability_id: capability(2)?,
                key_id: new_config_key,
            },
        )?;
        assert_eq!(registered.disposition(), AuthorityDispositionV2::Applied);
        Ok(())
    }

    #[test]
    fn error_priority_is_stable_at_capacity() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(1, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let acquire_intent = current_intent(
            &mut state,
            &clock,
            1,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(11)?,
            },
        )?;
        let receipt = state.apply(&clock, acquire_intent)?;

        let conflict = AuthorityIntentV2::new(
            acquire_intent.operation_id(),
            acquire_intent.expected_authority_version(),
            acquire_intent.expected_config(),
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(12)?,
            },
        )?;
        assert_eq!(
            state.apply(&clock, conflict),
            Err(AuthorityErrorV2::OperationConflict)
        );
        assert_eq!(state.apply(&clock, acquire_intent)?, receipt);

        let stale = AuthorityIntentV2::new(
            operation(1, 2)?,
            1,
            config(9, 9)?,
            AuthorityMutationV2::ReleaseLease {
                fence: require_lease(state.snapshot(&clock)?)?.fence(),
            },
        )?;
        assert_eq!(
            state.apply(&clock, stale),
            Err(AuthorityErrorV2::AuthorityVersionMismatch)
        );
        let full = AuthorityIntentV2::new(
            operation(state.snapshot(&clock)?.authority_version(), 3)?,
            state.snapshot(&clock)?.authority_version(),
            config(9, 9)?,
            AuthorityMutationV2::ReleaseLease {
                fence: require_lease(state.snapshot(&clock)?)?.fence(),
            },
        )?;
        assert_eq!(
            state.apply(&clock, full),
            Err(AuthorityErrorV2::ReceiptCapacityExceeded)
        );
        Ok(())
    }

    #[test]
    fn monotonic_overflow_paths_do_not_partially_mutate() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = fixture(&clock, limits(4, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        state.authority_version = u64::MAX;
        let intent = AuthorityIntentV2::new(
            operation(u64::MAX, 1)?,
            u64::MAX,
            state.config,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(1)?,
            },
        )?;
        assert_eq!(
            state.apply(&clock, intent),
            Err(AuthorityErrorV2::AuthorityVersionExhausted)
        );
        assert!(state.receipts.is_empty());
        assert_eq!(state.lease, None);

        let overflow_clock = FakeClock::new(u64::MAX - 5);
        let mut time_state = fixture(&overflow_clock, limits(4, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        let overflow = apply_current(
            &mut time_state,
            &overflow_clock,
            2,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: instance(2)?,
            },
        )?;
        assert_rejected(overflow, AuthorityRejectionV2::MutationOverflow);
        assert_eq!(time_state.lease, None);

        let normal_clock = FakeClock::new(100);
        let mut generation_state = fixture(&normal_clock, limits(4, 1, 1, TEST_LEASE_TTL_MILLIS)?)?;
        generation_state.lease_generation = u64::MAX;
        let exhausted = apply_current(
            &mut generation_state,
            &normal_clock,
            3,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: u64::MAX,
                instance_id: instance(3)?,
            },
        )?;
        assert_rejected(exhausted, AuthorityRejectionV2::MutationOverflow);
        assert_eq!(generation_state.lease, None);
        Ok(())
    }

    #[test]
    fn debug_output_redacts_security_identifiers_and_digests() -> TestResult {
        let clock = FakeClock::new(100);
        let mut state = AuthorityStateV2::provision(
            StateHeadV2::new(
                StateRevisionV2::new(1, [b'A'; 32], 1, [b'B'; 32])?,
                StateFenceV2::from_bytes([b'C'; 32])?,
            ),
            DeploymentConfigRevisionV2::new(1, [b'D'; 32])?,
            limits(4, 1, 1, TEST_LEASE_TTL_MILLIS)?,
            &clock,
        )?;
        let intent = current_intent(
            &mut state,
            &clock,
            b'F',
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([b'E'; 32])?,
            },
        )?;
        let receipt = state.apply(&clock, intent)?;
        let fence = require_lease(state.snapshot(&clock)?)?.fence();
        let capability_id = CapabilityIdV2::from_bytes([b'G'; 32])?;
        let key_id = AcceptedKeyIdV2::new(1, fence.generation(), [b'H'; 32])?;
        let register_intent = current_intent(
            &mut state,
            &clock,
            b'I',
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id,
                key_id,
            },
        )?;
        let snapshot = state.snapshot(&clock)?;
        let rendered = format!(
            "{state:?} {snapshot:?} {intent:?} {receipt:?} {register_intent:?} {:?} {capability_id:?} {key_id:?}",
            receipt.locator()
        );
        for forbidden in [
            "AAAAAAAA", "BBBBBBBB", "CCCCCCCC", "DDDDDDDD", "EEEEEEEE", "FFFFFFFF", "GGGGGGGG",
            "HHHHHHHH", "IIIIIIII",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        assert!(rendered.contains("[redacted]"));
        Ok(())
    }

    #[test]
    fn identical_inputs_produce_identical_state_and_receipt() -> TestResult {
        let clock_a = FakeClock::new(100);
        let clock_b = FakeClock::new(100);
        let configured_limits = limits(8, 2, 2, TEST_LEASE_TTL_MILLIS)?;
        let mut first = fixture(&clock_a, configured_limits)?;
        let mut second = fixture(&clock_b, configured_limits)?;
        let mutation = AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: instance(11)?,
        };
        let first_intent = current_intent(&mut first, &clock_a, 1, mutation)?;
        let second_intent = current_intent(&mut second, &clock_b, 1, mutation)?;
        assert_eq!(
            first.apply(&clock_a, first_intent)?,
            second.apply(&clock_b, second_intent)?
        );
        assert_eq!(first.snapshot(&clock_a)?, second.snapshot(&clock_b)?);
        assert_eq!(first.receipts, second.receipts);
        assert_eq!(first.capabilities, second.capabilities);
        assert_eq!(first.keys, second.keys);
        Ok(())
    }
}
