// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete source-state capture for the privileged witness handoff control plane.
use super::*;

/// An unsigned, complete state observation from the original authenticated store.
///
/// Capture does not freeze the source, retire its authority or authorize a target.
/// A future freeze must compare this exact state at its durable commit boundary.
/// The bytes contain public witness metadata, including unresolved operations and
/// retained outcomes; they contain neither the storage MAC nor a private key.
/// Transfer must authenticate them through the approved handoff transaction.
pub struct AnchorHandoffSourceState {
    pin: AnchorPin,
    revision: u64,
    bytes: Vec<u8>,
    commitment: [u8; 32],
}

impl AnchorHandoffSourceState {
    /// The source authority independently supplied when the store was opened.
    pub fn pin(&self) -> &AnchorPin {
        &self.pin
    }

    /// Original aggregate revision, without advancing any subject or operation.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Domain-separated commitment to the exact complete canonical state.
    /// This digest is not an authority signature or a durable freeze receipt.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Canonical source bytes without the source's keyed storage authenticator.
    /// They remain unsigned metadata and must not be imported as live authority.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AnchorStore {
    /// Observe complete authenticated source state without changing the store.
    ///
    /// This privileged control-plane operation includes pending G/P/R work,
    /// acknowledgements, retirement and account history. It does not require a
    /// quiescent store. The observation can become stale as soon as it returns;
    /// it grants no permission to reset, freeze, retire or activate an authority.
    pub fn handoff_source_state(&mut self) -> Result<AnchorHandoffSourceState, DurableError> {
        let image = self.image()?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let bytes = image_codec::encode_body(&active.pin, &image)?;
        let commitment = digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-SOURCE/v1", &bytes);
        Ok(AnchorHandoffSourceState {
            pin: active.pin.clone(),
            revision: image.revision,
            bytes,
            commitment,
        })
    }
}
