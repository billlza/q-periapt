// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
pub(super) const SCOPE_BYTES: usize = 3 * 32 + 16;
impl Scope {
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.namespace);
        out.extend_from_slice(&self.history);
        out.extend_from_slice(&self.decision);
        self.validity.encode(out);
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let scope = Self {
            namespace: d.array()?,
            history: d.array()?,
            decision: d.array()?,
            validity: Validity::decode(d)?,
        };
        for bytes in [scope.namespace, scope.history, scope.decision] {
            nonzero(&bytes)?;
        }
        Ok(scope)
    }
}
impl AnchorTransferredAccountReplacementApproval {
    /// Canonical original independently retained approval; parsing does not grant
    /// account-recovery operator authority to network-selected bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"QPTARA01".to_vec();
        self.scope.encode(&mut bytes);
        bytes.extend_from_slice(&self.proposal.to_bytes()?);
        Ok(bytes)
    }
    /// Recover an approval from the independent host record and exact original
    /// target inputs. Expired inputs remain historical, never fresh permission.
    pub fn restore_trusted_state(
        bytes: &[u8],
        materials: &AnchorTransferredAccountReplacementMaterials<'_>,
    ) -> Result<Self, DurableError> {
        if bytes.len() > 8 + SCOPE_BYTES + MAX_PROPOSAL_BYTES {
            return Err(Error::Capacity.into());
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPTARA01" {
            return Err(Error::Encoding.into());
        }
        let scope = Scope::decode(&mut d)?;
        let length = bytes
            .len()
            .checked_sub(8 + SCOPE_BYTES)
            .ok_or(Error::Encoding)?;
        let proposal = AnchorAccountReplacementProposal::from_trusted_state(d.take(length)?)?;
        d.finish()?;
        let restored =
            Self::from_trusted_state(proposal, materials, scope.decision, scope.validity)?;
        if restored.scope != scope {
            return Err(Error::Scope.into());
        }
        Ok(restored)
    }
}
