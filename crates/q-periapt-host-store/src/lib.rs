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
pub use policy::{PolicyStore, StoreError};
