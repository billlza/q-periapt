// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-selected authorization of original retained state, separate from renewal
//! of a certificate. Public device metadata is never account authentication.
use crate::{
    enrollment::{wire, Checkpoint},
    native_device::RetainedCredentialRequest,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialGrantRequest {
    pub retained: RetainedCredentialRequest,
    /// Exact host issuance that supplied the installation's original credential.
    #[serde(deserialize_with = "selection")]
    pub original_extension: Option<[u8; 32]>,
    /// Exact host issuance currently retained by this original installation.
    #[serde(deserialize_with = "selection")]
    pub previous_extension: Option<[u8; 32]>,
    /// Separately approved, already-issued target certificate extension.
    pub successor_extension: [u8; 32],
    /// Independently selected current account roster, not the reported old head.
    pub target_checkpoint: Checkpoint,
}

fn selection<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
    Option::<[u8; 32]>::deserialize(d)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedCredentialGrant {
    pub enrollment: [u8; 32],
    pub operation: [u8; 32],
    /// Correlation only: the SDK grant binds original storage owner, not journal ID.
    pub journal: [u8; 32],
    pub root_revision: u64,
    pub statement: [u8; 32],
    pub checkpoint: Checkpoint,
    #[serde(with = "wire")]
    pub grant: Vec<u8>,
}
