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
    history: handoff::history::HistoryContext,
}

impl AnchorHandoffSourceState {
    pub(super) fn history_context(&self) -> handoff::history::HistoryContext {
        self.history
    }
    pub(super) fn from_image(pin: &AnchorPin, image: &Image) -> Result<Self, DurableError> {
        let bytes = image_codec::encode_body(pin, image)?;
        Ok(Self::captured(
            pin,
            image.revision,
            bytes,
            handoff::history::HistoryContext::initial(pin),
        ))
    }
    pub(super) fn captured(
        pin: &AnchorPin,
        revision: u64,
        bytes: Vec<u8>,
        history: handoff::history::HistoryContext,
    ) -> Self {
        let commitment = digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-SOURCE/v1", &bytes);
        Self {
            pin: pin.clone(),
            revision,
            bytes,
            commitment,
            history,
        }
    }
    /// The source authority independently supplied when the store was opened.
    pub fn pin(&self) -> &AnchorPin {
        &self.pin
    }

    /// Complete source-image revision, distinct from individual subject heads.
    /// Capture does not advance it. A separate client authorization advances
    /// the store metadata revision while preserving its original subject entry.
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
    /// Activated imports also retain their complete prior import, authenticated
    /// history and all indexed client authorization rows in the capture. This
    /// prospective source format does not itself enable a successive freeze or
    /// import; those transactions retain their separate admission requirements.
    pub fn handoff_source_state(&mut self) -> Result<AnchorHandoffSourceState, DurableError> {
        let image = self.image()?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        match &active.transferred {
            None => AnchorHandoffSourceState::from_image(&active.pin, &image),
            Some(transferred) => transferred.capture_source(&active.db, &active.wrapping, &image),
        }
    }
}
