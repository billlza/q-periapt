// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A terminal non-commit has its own purpose; retirement and live replies cannot substitute.
use super::*;
fn body(p: &AnchorAccountReplacementProposal) -> Result<Vec<u8>, Error> {
    let mut bytes = b"QPARNM01".to_vec();
    bytes.extend_from_slice(&p.witness);
    bytes.extend_from_slice(&p.binding()?);
    Ok(bytes)
}
impl AnchorStore {
    /// Sign the original retained non-commit decision, including after later history.
    pub fn closed_account_replacement_receipt(
        &mut self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<Vec<u8>, DurableError> {
        self.closed_account_replacement(p)?;
        let result = (|| {
            let bytes = body(p)?;
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let signature = active
                .signer
                .sign(Purpose::AnchorAccountReplacementClosure, &bytes)?;
            envelope(&bytes, &signature).map_err(DurableError::from)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Verify permanent non-commit against the exact independently retained proposal
    /// and witness. This proof never restores old-root or successor permission.
    pub fn verify_closed_account_replacement(
        &self,
        p: &AnchorAccountReplacementProposal,
        wire: &[u8],
    ) -> Result<AnchorClosedAccountReplacement, Error> {
        check_scope(p, self)?;
        if wire.len() != 4 + 72 + crate::crypto::SIGNATURE_BYTES {
            return Err(Error::Encoding);
        }
        let (observed, signature) = open_envelope(wire)?;
        self.key.verify(
            Purpose::AnchorAccountReplacementClosure,
            observed,
            signature,
        )?;
        if observed != body(p)? {
            return Err(Error::Scope);
        }
        Ok(AnchorClosedAccountReplacement {
            proposal: p.clone(),
        })
    }
}
