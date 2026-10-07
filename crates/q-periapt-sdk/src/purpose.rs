// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The SDK's versioned application-key schedule. This does not change either
//! hybrid combiner, authenticate peers, or implement a TLS/session protocol.

use crate::{check_context, Error, SharedSecret, State};
use hkdf::Hkdf;
use q_periapt_core::ZeroizingBytes;
use sha2::Sha256;
use std::sync::Arc;
use zeroize::Zeroize;

/// Maximum printable-ASCII protocol/algorithm label length in bytes.
pub const MAX_PROTOCOL_LABEL_BYTES: usize = 255;
const SALT: &[u8] = b"QPeriapt-SDK-HKDF-SHA256-v1";
const INFO_DOMAIN: &[u8] = b"QPeriapt-SDK-Key-v1";

/// Global protocol directions, not the caller's local send/receive perspective.
/// Both peers choose the same purpose for the same wire direction. The protocol
/// label must also distinguish the application protocol, version and algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyPurpose {
    /// Application traffic from the initiator to the responder.
    InitiatorTraffic = 1,
    /// Application traffic from the responder to the initiator.
    ResponderTraffic = 2,
    /// A protocol's initiator key-confirmation computation.
    InitiatorConfirmation = 3,
    /// A protocol's responder key-confirmation computation.
    ResponderConfirmation = 4,
    /// An application-specific exported key; labels separate exporter uses.
    Exporter = 5,
}

impl TryFrom<u32> for KeyPurpose {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::InitiatorTraffic),
            2 => Ok(Self::ResponderTraffic),
            3 => Ok(Self::InitiatorConfirmation),
            4 => Ok(Self::ResponderConfirmation),
            5 => Ok(Self::Exporter),
            _ => Err(Error::InvalidPurpose),
        }
    }
}

/// One non-cloneable 256-bit application key, revoked with its runtime.
/// It cannot be used as another KEM secret or recursively derived.
///
/// ```compile_fail
/// use q_periapt_sdk::DerivedKey;
/// fn duplicate(key: &DerivedKey) -> DerivedKey { key.clone() }
/// ```
pub struct DerivedKey {
    bytes: Option<ZeroizingBytes<32>>,
    state: Arc<State>,
}
impl DerivedKey {
    /// Explicitly copy for an external cipher/MAC implementation. The caller
    /// owns the resulting copy and its erasure; this does not export a KEM key.
    pub fn export_for_protocol(&self) -> Result<ZeroizingBytes<32>, Error> {
        self.state.ensure_open()?;
        let bytes = self.bytes.as_ref().ok_or(Error::Closed)?;
        let mut output = ZeroizingBytes::zeroed();
        output.as_mut_bytes().copy_from_slice(bytes.as_bytes());
        Ok(output)
    }

    /// Erase this owner. Already exported copies remain caller-owned.
    pub fn close(&mut self) {
        self.bytes = None;
    }
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[&[u8]]) -> Result<ZeroizingBytes<32>, Error> {
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    // Avoid Hkdf::new, which discards the returned PRK without wiping it.
    prk.zeroize();
    let mut output = ZeroizingBytes::zeroed();
    hkdf.expand_multi_info(info, output.as_mut_bytes())
        .map_err(|_| Error::Backend)?;
    // HMAC/hash owned states and buffers use their zeroize features. Upstream
    // internal temporary arrays and compiler copies are not all erase-guaranteed.
    Ok(output)
}

fn derive(
    secret: &[u8; 32],
    state: &[u8; 36],
    root: &[u8; 32],
    purpose: KeyPurpose,
    label: &[u8],
    context: &[u8],
) -> Result<ZeroizingBytes<32>, Error> {
    if label.is_empty() || label.len() > MAX_PROTOCOL_LABEL_BYTES {
        return Err(Error::InvalidLength);
    }
    if !label.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(Error::InvalidPurpose);
    }
    check_context(context)?;
    let label_len = u16::try_from(label.len()).map_err(|_| Error::InvalidLength)?;
    let context_len = u32::try_from(context.len()).map_err(|_| Error::InvalidLength)?;
    hkdf32(
        secret,
        SALT,
        &[
            INFO_DOMAIN,
            &1_u32.to_be_bytes(), // fixed ML-KEM-768+X25519 suite
            &2_u32.to_be_bytes(), // ContextBound only
            state,
            root,
            &(purpose as u32).to_be_bytes(),
            &label_len.to_be_bytes(),
            label,
            &context_len.to_be_bytes(),
            context,
            &32_u16.to_be_bytes(),
        ],
    )
}

impl SharedSecret {
    /// Derive a version-1 HKDF-SHA-256 purpose key without exporting the combined
    /// KEM secret. The info binds suite, profile, authenticated policy state,
    /// SHA-256 of the pinned trust root, purpose, protocol label, context and
    /// output length. Label: 1..=255 bytes of ASCII 0x21..=0x7e; context: <=64 KiB.
    ///
    /// Peers must agree on the complete label/context and global direction.
    /// Fresh handshakes still need fresh KEM keys/randomness. This API supplies
    /// neither peer authentication nor the actual key-confirmation exchange.
    pub fn derive_key(
        &self,
        purpose: KeyPurpose,
        protocol_label: &[u8],
        context: &[u8],
    ) -> Result<DerivedKey, Error> {
        let _operation = self.state.begin()?;
        let secret = self.inner.as_ref().ok_or(Error::Closed)?;
        let bytes = derive(
            secret.as_bytes(),
            &self.state.configuration.trusted_state().encode(),
            &self.state.trust_root_digest,
            purpose,
            protocol_label,
            context,
        )?;
        Ok(DerivedKey {
            bytes: Some(bytes),
            state: Arc::clone(&self.state),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc5869_appendix_a1_first_block() {
        let salt: Vec<u8> = (0..=12).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let key = hkdf32(&[0x0b; 22], &salt, &[&info]).expect("RFC HKDF");
        assert_eq!(
            key.as_bytes(),
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf,
            ]
        );
    }

    #[test]
    fn directions_labels_context_policy_and_root_are_distinct_domains() {
        fn key(
            state: &[u8; 36],
            root: &[u8; 32],
            purpose: KeyPurpose,
            label: &[u8],
            context: &[u8],
        ) -> ZeroizingBytes<32> {
            derive(&[7; 32], state, root, purpose, label, context).expect("derived")
        }
        let state = [2; 36];
        let root = [3; 32];
        let baseline = key(
            &state,
            &root,
            KeyPurpose::InitiatorTraffic,
            b"app/v1/aes256",
            b"transcript",
        );
        // Independently generated with Python's stdlib HMAC-SHA-256; the exact
        // field encoding is specified in docs/SDK_KEY_DERIVATION.md.
        assert_eq!(
            baseline.as_bytes(),
            &[
                0x89, 0x9c, 0x3f, 0xe0, 0xb3, 0x41, 0x9a, 0x6f, 0x39, 0x47, 0xc4, 0xe2, 0x37, 0xda,
                0xf8, 0x97, 0x0b, 0x2c, 0x29, 0x44, 0x2d, 0x9f, 0xce, 0x43, 0x85, 0xd3, 0x0d, 0x25,
                0x58, 0x24, 0x2f, 0x65,
            ]
        );
        for purpose in [
            KeyPurpose::ResponderTraffic,
            KeyPurpose::InitiatorConfirmation,
            KeyPurpose::ResponderConfirmation,
            KeyPurpose::Exporter,
        ] {
            assert_ne!(
                baseline.as_bytes(),
                key(&state, &root, purpose, b"app/v1/aes256", b"transcript").as_bytes()
            );
        }
        for (other_state, other_root, label, context) in [
            (
                [4; 36],
                root,
                b"app/v1/aes256".as_slice(),
                b"transcript".as_slice(),
            ),
            (state, [4; 32], b"app/v1/aes256", b"transcript"),
            (state, root, b"app/v2/aes256", b"transcript"),
            (state, root, b"app/v1/aes256", b"transcript2"),
        ] {
            assert_ne!(
                baseline.as_bytes(),
                key(
                    &other_state,
                    &other_root,
                    KeyPurpose::InitiatorTraffic,
                    label,
                    context
                )
                .as_bytes()
            );
        }
        assert_ne!(
            key(&state, &root, KeyPurpose::Exporter, b"ab", b"c").as_bytes(),
            key(&state, &root, KeyPurpose::Exporter, b"a", b"bc").as_bytes()
        );
    }
}
