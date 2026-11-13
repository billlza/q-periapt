// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fixed-size proof metadata; the account snapshot keeps its existing bound.
use super::*;
const SCOPE_BYTES: usize = 3 * 32 + 16;
const BODY_BYTES: usize = 8 + SCOPE_BYTES + 8 + 32;
const WIRE_BYTES: usize = 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES;
pub(in crate::anchor::store::account_replacement::freeze) const PROOF_BYTES: usize =
    SCOPE_BYTES + 8 + WIRE_BYTES;
impl Scope {
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.namespace);
        out.extend_from_slice(&self.history);
        out.extend_from_slice(&self.decision);
        self.validity.encode(out);
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let scope = Self {
            namespace: d.array()?,
            history: d.array()?,
            decision: d.array()?,
            validity: Validity::decode(d)?,
        };
        for value in [scope.namespace, scope.history, scope.decision] {
            nonzero(&value)?;
        }
        Ok(scope)
    }
}
impl Proof {
    pub(in crate::anchor::store::account_replacement::freeze) fn encode(
        &self,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if self.wire.len() != WIRE_BYTES {
            return Err(Error::Encoding);
        }
        self.scope.encode(out);
        out.extend_from_slice(&self.admitted.to_be_bytes());
        out.extend_from_slice(&self.wire);
        Ok(())
    }
    pub(in crate::anchor::store::account_replacement::freeze) fn decode(
        d: &mut Decoder<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            scope: Scope::decode(d)?,
            admitted: d.u64()?,
            wire: d.take(WIRE_BYTES)?.to_vec(),
        })
    }
}
impl AnchorTransferredAccountFreezeApproval {
    /// Canonical independent operator approval; save before attempting commitment.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = b"QPTAFA01".to_vec();
        self.scope().encode(&mut out);
        out.extend_from_slice(&self.proposal.frozen.to_bytes()?);
        Ok(out)
    }
    /// Restore only independently retained approval bytes. This does not obtain
    /// operator authorization from a peer or assert current time validity.
    pub fn restore_trusted_state(
        bytes: &[u8],
        request: &AnchorAccountFreezeRequest,
        history: &AnchorHandoffHistory,
    ) -> Result<Self, DurableError> {
        if bytes.len() > 8 + SCOPE_BYTES + super::super::codec::MAX_FREEZE_BYTES {
            return Err(Error::Capacity.into());
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPTAFA01" {
            return Err(Error::Encoding.into());
        }
        let scope = Scope::decode(&mut d)?;
        let size = bytes
            .len()
            .checked_sub(8 + SCOPE_BYTES)
            .ok_or(Error::Encoding)?;
        let frozen = AnchorFrozenAccount::decode(d.take(size)?)?;
        d.finish()?;
        Self::from_trusted_state(
            AnchorTransferredAccountFreezeProposal {
                frozen,
                namespace: scope.namespace,
                history: scope.history,
            },
            request,
            history,
            scope.decision,
            scope.validity,
        )
    }
}
