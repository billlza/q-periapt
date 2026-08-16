#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Process-isolated policy-agent reference implementation.
//!
//! The library separates exact durable state, authenticated external witnessing,
//! the frozen ABI 2 execution adapter, and the session acceptance state machine.
//! The only `unsafe` operations are the narrowly reviewed ABI 2 calls in the
//! private `crypto` module and macOS descriptor ACL calls in `macos_acl`.

mod authentication;
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
