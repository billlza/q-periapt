// SPDX-License-Identifier: Apache-2.0 OR MIT
#![deny(unsafe_code)]
//! Host-owned policy persistence, separate from the portable cryptographic SDK.
//!
//! The private filesystem boundary is shared with the policy agent. The only
//! native unsafe code is its existing, quarantined macOS descriptor-ACL adapter.

pub mod filesystem;
#[cfg(target_os = "macos")]
mod macos_acl;

mod policy;
pub use policy::{
    PolicyRecoveryAuthorization, PolicyRecoveryOutcome, PolicyRecoveryRequest, PolicyRecoveryTrust,
    MAX_POLICY_AUTHORITY_RECOVERIES, POLICY_RECOVERY_AUTHORIZATION_BYTES,
};
pub use policy::{PolicyStore, StoreError};
