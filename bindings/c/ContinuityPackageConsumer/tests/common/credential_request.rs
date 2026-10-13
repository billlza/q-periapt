// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public Android issuer-request interchange, separate from the signed grant.
use crate::{p, policy_request::Input, Result};
use std::{fs, path::Path};

pub(crate) struct CredentialRequest {
    pub(crate) operation: p::CredentialRenewalId,
    pub(crate) journal: p::JournalIdentity,
    pub(crate) original_owner: [u8; 32],
    pub(crate) original_policy: [u8; 32],
    pub(crate) current_policy: p::PolicyCheckpoint,
    pub(crate) authorization: Option<[u8; 32]>,
    pub(crate) previous: p::RosterCheckpoint,
    pub(crate) original: p::RosterCheckpoint,
    pub(crate) validity: p::Validity,
    pub(crate) account: [u8; 32],
    pub(crate) original_c: Vec<u8>,
    pub(crate) original_r: Vec<u8>,
    pub(crate) previous_c: Vec<u8>,
    pub(crate) previous_r: Vec<u8>,
}
pub(crate) fn read_credential_request(path: &Path, big_endian: bool) -> Result<CredentialRequest> {
    let bytes = fs::read(path)?;
    assert_eq!(bytes.len(), 33120);
    let mut r = Input {
        bytes: &bytes,
        offset: 0,
        big_endian,
    };
    let operation = p::CredentialRenewalId::from_trusted_state(r.array()?)?;
    let journal = p::JournalIdentity::from_trusted_state(r.array()?)?;
    let original_owner = r.array()?;
    let original_policy = r.array()?;
    let current_policy = r.policy()?;
    let authority = r.array()?;
    let authorization = match r.u32()? {
        0 if authority == [0; 32] => None,
        1 if authority != [0; 32] => Some(authority),
        _ => return Err("credential request authorization".into()),
    };
    assert_eq!(r.u32()?, 0);
    let result = CredentialRequest {
        operation,
        journal,
        original_owner,
        original_policy,
        current_policy,
        authorization,
        previous: r.roster()?,
        original: r.roster()?,
        validity: p::Validity::new(r.u64()?, r.u64()?)?,
        account: r.array()?,
        original_c: r.record()?,
        original_r: r.record()?,
        previous_c: r.record()?,
        previous_r: r.record()?,
    };
    assert_eq!(r.offset, bytes.len());
    Ok(result)
}
