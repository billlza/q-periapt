// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A permanent historical fact under its own signature purpose, never a live reply.
use super::*;

fn body(p: &AnchorAccountReplacementProposal) -> Result<Vec<u8>, Error> {
    let mut bytes = b"QPARTR01".to_vec();
    bytes.extend_from_slice(&p.witness);
    bytes.extend_from_slice(&p.binding()?);
    Ok(bytes)
}
impl AnchorStore {
    /// Sign the exact committed account-wide retirement. This immutable statement
    /// is separate from a fresh operating reply and grants no successor authority.
    pub fn retired_account_receipt(
        &mut self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<Vec<u8>, DurableError> {
        self.retired_account_observation(p)?;
        let bytes = body(p)?;
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let signature = active
                .signer
                .sign(Purpose::AnchorAccountRetirement, &bytes)?;
            envelope(&bytes, &signature).map_err(DurableError::from)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Verify permanent retirement against the exact independently approved
    /// original descriptor and witness. No freshness, delivery, erasure, current
    /// successor authority or transfer to another witness key is asserted.
    ///
    /// ```compile_fail
    /// use q_periapt_continuity_identity_candidate::{AnchorReply, AnchorRetiredAccount};
    /// fn operating_reply(retired: AnchorRetiredAccount) -> AnchorReply { retired }
    /// ```
    pub fn verify_retired_account(
        &self,
        p: &AnchorAccountReplacementProposal,
        wire: &[u8],
    ) -> Result<AnchorRetiredAccount, Error> {
        p.check_shape()?;
        if p.witness != self.binding {
            return Err(Error::Scope);
        }
        if wire.len() != 4 + 72 + crate::crypto::SIGNATURE_BYTES {
            return Err(Error::Encoding);
        }
        let (observed, signature) = open_envelope(wire)?;
        self.key
            .verify(Purpose::AnchorAccountRetirement, observed, signature)?;
        if observed != body(p)? {
            return Err(Error::Scope);
        }
        Ok(AnchorRetiredAccount {
            proposal: p.clone(),
        })
    }
}
