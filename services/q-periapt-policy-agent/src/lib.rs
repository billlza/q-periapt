#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Process-isolated policy-agent reference implementation.
//!
//! The library separates exact durable state, authenticated external witnessing,
//! the frozen ABI 2 execution adapter, and the session acceptance state machine.
//! The only `unsafe` operations are the narrowly reviewed ABI 2 calls in the
//! private `crypto` module and macOS descriptor ACL calls in `macos_acl`.

mod authentication;
mod authority;
mod authority_codec;
mod authority_journal;
mod authority_protocol;
mod authority_store;
mod authority_transport;
mod codec;
mod crypto;
mod filesystem;
#[cfg(target_os = "macos")]
mod macos_acl;
mod repository;
mod service;
mod types;
mod witness;

#[cfg(all(test, unix))]
mod tests;

#[cfg(unix)]
pub mod ipc;

pub use authority::{
    AcceptedKeyIdV2, AuthorityDispositionV2, AuthorityEpochV2, AuthorityErrorV2, AuthorityIntentV2,
    AuthorityLimitsV2, AuthorityMutationV2, AuthorityQueryResultV2, AuthorityReceiptV2,
    AuthorityRejectionV2, AuthoritySnapshotV2, AuthorityStateV2, AuthorityValueErrorV2,
    CapabilityIdV2, ConfigAdvanceV2, DeploymentConfigRevisionV2, InstanceFenceV2, InstanceLeaseV2,
    OperationIdV2, ProcessInstanceIdV2, ReceiptAckDispositionV2, ReceiptAckErrorV2,
    ReceiptLocatorV2, StateAdvanceV2, StateFenceV2, StateHeadV2, StateRevisionV2,
    StateTransitionKindV2, TrustedClockErrorV2, TrustedClockV2,
};
pub use authority_protocol::{
    AuthorityClientIdV3, AuthorityKnownFailureV3, AuthorityOutcomeV3, AuthorityServerIdV3,
    AuthorityUnknownV3, AuthorityWireIdentityV3, DurablyRetainedAuthorityReceiptV3,
};
pub use authority_store::{AuthorityStoreErrorV2, AuthorityStoreV2, SystemTimeClockV2};
pub use authority_transport::{
    AuthenticatedTcpAuthorityV3, AuthorityServerErrorV3, AuthorityServerProvisionV3,
    AuthorityTransportErrorV3, AuthorityTransportLimitsV3, InstanceAuthorityPort,
    ReferenceAuthorityServerV3,
};
pub use crypto::{Abi2EngineError, EncapsulationCiphertexts, EncapsulationPublicKeys};
pub use repository::{MigrationTrustRoots, RepositoryError, StateRepository};
pub use service::{
    AgentConfig, AgentError, AgentLimits, BeginDecapsulation, BeginDecapsulationResult,
    BeginEncapsulation, BeginEncapsulationResult, ConfirmedKeyHandle, EndpointIdentity,
    InitiatorDecapsulationResult, InitiatorEncapsulationResult, PendingSessionHandle, PolicyAgent,
    ResponderAcceptanceResult, ResponderDecapsulationResult, ResponderEncapsulationResult,
    SessionAuthorization, SignedPolicyBundle,
};
pub use types::{
    FenceToken, OperationId, SessionId, StateAdvance, StateHead, StateRevision, StateValueError,
    TransitionKind,
};
pub use witness::{
    AuthenticatedTcpWitness, ReferenceWitnessServer, WitnessDisposition, WitnessError,
    WitnessIntent, WitnessOutcome, WitnessPort, WitnessReceipt,
};
