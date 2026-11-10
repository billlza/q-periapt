// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
fn body(plan: &AnchorAccountReplacementPlan) -> Result<Vec<u8>, Error> {
    let mut bytes = b"QPAPCL01".to_vec();
    bytes.extend_from_slice(&plan.target().witness);
    bytes.extend_from_slice(&plan.binding()?);
    Ok(bytes)
}
impl AnchorStore {
    /// Sign only the retained original plan non-commit, with its own signature purpose.
    pub fn closed_account_preparation_receipt(
        &mut self,
        plan: &AnchorAccountReplacementPlan,
    ) -> Result<Vec<u8>, DurableError> {
        self.closed_account_preparation(plan)?;
        let result = (|| {
            let bytes = body(plan)?;
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let signature = active
                .signer
                .sign(Purpose::AnchorAccountPreparationClosure, &bytes)?;
            envelope(&bytes, &signature).map_err(DurableError::from)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Verify permanent non-commit of this independently retained plan. It is not
    /// proof that the account froze, and does not grant current traffic authority.
    pub fn verify_closed_account_preparation(
        &self,
        plan: &AnchorAccountReplacementPlan,
        wire: &[u8],
    ) -> Result<AnchorClosedAccountPreparation, Error> {
        check_scope(plan.target(), self)?;
        if wire.len() != 4 + 72 + crate::crypto::SIGNATURE_BYTES {
            return Err(Error::Encoding);
        }
        let (observed, signature) = open_envelope(wire)?;
        self.key.verify(
            Purpose::AnchorAccountPreparationClosure,
            observed,
            signature,
        )?;
        if observed != body(plan)? {
            return Err(Error::Scope);
        }
        Ok(AnchorClosedAccountPreparation { plan: plan.clone() })
    }
}
