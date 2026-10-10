// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sign a commitment to the complete bounded snapshot without enlarging signed messages.
use super::*;
const BODY_BYTES: usize = 8 + 32 + 32;
const SIGNED_BYTES: usize = 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES;
fn body(frozen: &AnchorFrozenAccount) -> Result<Vec<u8>, Error> {
    let mut bytes = b"QPAFRS01".to_vec();
    bytes.extend_from_slice(&frozen.request.witness);
    bytes.extend_from_slice(&frozen.binding()?);
    Ok(bytes)
}
impl AnchorStore {
    /// Recover and sign only the original persisted freeze. The outer frame carries
    /// its complete snapshot; a separate-purpose signature binds its digest.
    pub fn account_freeze_receipt(
        &mut self,
        request: &AnchorAccountFreezeRequest,
    ) -> Result<Vec<u8>, DurableError> {
        let frozen = self.account_freeze(request)?;
        let result = (|| {
            let bytes = body(&frozen)?;
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let signature = active.signer.sign(Purpose::AnchorAccountFreeze, &bytes)?;
            let mut wire = frozen.to_bytes()?;
            wire.extend_from_slice(&envelope(&bytes, &signature)?);
            Ok(wire)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Verify the original freeze under the independently retained witness and
    /// request. This fact grants neither retirement nor successor operating authority.
    pub fn verify_account_freeze(
        &self,
        request: &AnchorAccountFreezeRequest,
        wire: &[u8],
    ) -> Result<AnchorFrozenAccount, Error> {
        request.check_pin(self)?;
        let size = wire
            .len()
            .checked_sub(SIGNED_BYTES)
            .ok_or(Error::Encoding)?;
        // Snapshot parsing has its own fixed capacity; no larger signed-body limit.
        let (snapshot, signed) = wire.split_at_checked(size).ok_or(Error::Encoding)?;
        let frozen = AnchorFrozenAccount::decode(snapshot)?;
        if frozen.request != *request {
            return Err(Error::Scope);
        }
        let (observed, signature) = open_envelope(signed)?;
        self.key
            .verify(Purpose::AnchorAccountFreeze, observed, signature)?;
        if observed != body(&frozen)? {
            return Err(Error::Scope);
        }
        Ok(frozen)
    }
}
