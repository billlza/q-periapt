// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable signing owners, provisioned before enrollment or public-key release.
use super::{Material, PublicKey, SigningSeed, PUBLIC_KEY_BYTES};
use crate::{codec::Decoder, DurableError, Error, JournalKey};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use q_periapt_core::ZeroizingBytes;
#[cfg(unix)]
use q_periapt_host_store::filesystem::open_private_parent;
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{fs::File, io::Read, path::Path};
use zeroize::Zeroizing;

const HEADER: usize = 8 + 1 + 32 + 24;
const PLAINTEXT: usize = 8 + 32 + 32 + PUBLIC_KEY_BYTES;
const FILE_BYTES: usize = HEADER + PLAINTEXT + 16;

#[cfg(all(test, unix))]
mod tests;

/// Independently retained identity of one immutable signing-key file.
/// It is public correlation data, not secret generation entropy or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningKeyId([u8; 32]);
impl SigningKeyId {
    /// Generate an identity before provisioning the corresponding key file.
    pub fn generate() -> Result<Self, Error> {
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(id)
    }
    /// Restore trusted configuration, never the header of an untrusted file.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public bytes for independent configuration or a provisioning request.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn seal(
    wrapping: &JournalKey,
    identity: SigningKeyId,
    role: u8,
    seed: &SigningSeed,
    public: &PublicKey,
) -> Result<Vec<u8>, DurableError> {
    let mut plaintext = Zeroizing::new(b"QPSMAT01".to_vec());
    plaintext.extend_from_slice(seed.pq.as_bytes());
    plaintext.extend_from_slice(seed.classic.as_bytes());
    plaintext.extend_from_slice(&public.encode());
    let mut wire = b"QPSIGN01".to_vec();
    wire.push(role);
    wire.extend_from_slice(&identity.0);
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
    wire.extend_from_slice(&nonce);
    let key = wrapping.signing_owner_key()?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &wire, plaintext.as_mut_slice().into())
        .map_err(|_| DurableError::Authentication)?;
    wire.extend_from_slice(&plaintext);
    wire.extend_from_slice(&tag);
    Ok(wire)
}

fn unseal(
    wrapping: &JournalKey,
    identity: SigningKeyId,
    role: u8,
    wire: &[u8],
) -> Result<Material, DurableError> {
    if wire.len() != FILE_BYTES {
        return Err(DurableError::Corrupt);
    }
    let mut outer = Decoder::new(wire);
    if outer.array::<8>()? != *b"QPSIGN01" {
        return Err(DurableError::Corrupt);
    }
    if outer.array::<1>()? != [role] || outer.array::<32>()? != identity.0 {
        return Err(DurableError::Conflict);
    }
    let nonce = outer.array::<24>()?;
    let mut plaintext = Zeroizing::new(outer.take(PLAINTEXT)?.to_vec());
    let tag = outer.array::<16>()?;
    outer.finish()?;
    let key = wrapping.signing_owner_key()?;
    XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            wire.get(..HEADER).ok_or(DurableError::Corrupt)?,
            plaintext.as_mut_slice().into(),
            &Tag::from(tag),
        )
        .map_err(|_| DurableError::Authentication)?;
    let mut inner = Decoder::new(&plaintext);
    if inner.array::<8>()? != *b"QPSMAT01" {
        return Err(DurableError::Corrupt);
    }
    let mut seed = SigningSeed {
        pq: ZeroizingBytes::zeroed(),
        classic: ZeroizingBytes::zeroed(),
    };
    seed.pq.as_mut_bytes().copy_from_slice(inner.take(32)?);
    seed.classic.as_mut_bytes().copy_from_slice(inner.take(32)?);
    let public = PublicKey::decode(inner.take(PUBLIC_KEY_BYTES)?)?;
    inner.finish()?;
    let material = seed
        .materialize()
        .map_err(DurableError::InvalidCheckpoint)?;
    if material.public != public {
        return Err(DurableError::InvalidCheckpoint(Error::Scope));
    }
    Ok(material)
}

fn check_file(file: &File, length: usize) -> Result<(), DurableError> {
    let metadata = file.metadata()?;
    if metadata.len() != length as u64 {
        return Err(DurableError::PrivateFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(DurableError::PrivateFile);
        }
    }
    Ok(())
}

pub(super) fn provision(
    path: &Path,
    wrapping: &JournalKey,
    identity: SigningKeyId,
    role: u8,
) -> Result<Material, DurableError> {
    let seed = SigningSeed::generate()?;
    let material = seed.materialize()?;
    let sealed = seal(wrapping, identity, role, &seed, &material.public)?;
    #[cfg(all(test, unix))]
    tests::at_boundary("generated", &material.public);
    publish_private_bytes(path, &sealed)?;
    #[cfg(all(test, unix))]
    tests::at_boundary("published", &material.public);
    Ok(material)
}

#[cfg(unix)]
pub(super) fn open(
    path: &Path,
    wrapping: &JournalKey,
    identity: SigningKeyId,
    role: u8,
) -> Result<Material, DurableError> {
    let (parent, leaf) = open_private_parent(path).map_err(|_| DurableError::PrivateFile)?;
    let mut file = parent
        .open_state_file(leaf)
        .map_err(|_| DurableError::PrivateFile)?;
    let material = read_owner(&mut file, wrapping, identity, role)?;
    parent
        .sync_entries()
        .map_err(|_| DurableError::PrivateFile)?;
    Ok(material)
}

fn read_owner(
    file: &mut File,
    wrapping: &JournalKey,
    identity: SigningKeyId,
    role: u8,
) -> Result<Material, DurableError> {
    check_file(file, FILE_BYTES)?;
    let mut bytes = vec![0; FILE_BYTES];
    file.read_exact(&mut bytes)?;
    let mut trailing = [0];
    if file.read(&mut trailing)? != 0 {
        return Err(DurableError::PrivateFile);
    }
    let material = unseal(wrapping, identity, role, &bytes)?;
    check_file(file, FILE_BYTES)?;
    // Reconcile a complete image observed after an interrupted first write.
    // No owner/public identity becomes usable until this exact inode is synced.
    file.sync_all()?;
    Ok(material)
}

#[cfg(not(unix))]
pub(super) fn open(
    path: &Path,
    wrapping: &JournalKey,
    identity: SigningKeyId,
    role: u8,
) -> Result<Material, DurableError> {
    // The shared adapter explicitly refuses platforms without private-file admission.
    let mut file = q_periapt_host_store::filesystem::open_private_file(path, false)
        .map_err(|_| DurableError::PrivateFile)?;
    read_owner(&mut file, wrapping, identity, role)
}
