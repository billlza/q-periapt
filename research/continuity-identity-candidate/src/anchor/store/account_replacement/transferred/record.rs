// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fixed-size signed decisions alongside immutable proposal and freeze records.
use super::*;
const BODY_BYTES: usize = 8 + codec::SCOPE_BYTES + 5 * 32 + 1 + 8;
pub(super) const WIRE_BYTES: usize = 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES;

#[derive(Clone)]
pub(in crate::anchor::store) struct Record {
    scope: Scope,
    witness: [u8; 32],
    operation: [u8; 32],
    account: [u8; 32],
    freeze: [u8; 32],
    proposal: [u8; 32],
    committed: Option<u64>,
    wire: Vec<u8>,
}
impl Record {
    fn body(&self) -> Vec<u8> {
        let mut b = b"QPTARD01".to_vec();
        self.scope.encode(&mut b);
        for value in [
            self.witness,
            self.operation,
            self.account,
            self.freeze,
            self.proposal,
        ] {
            b.extend_from_slice(&value);
        }
        b.push(u8::from(self.committed.is_some()));
        b.extend_from_slice(&self.committed.unwrap_or(0).to_be_bytes());
        b
    }
    pub(super) fn sign(
        a: &AnchorTransferredAccountReplacementApproval,
        committed: Option<u64>,
        signer: &AnchorSigningKey,
    ) -> Result<Self, DurableError> {
        let mut r = Self {
            scope: a.scope.clone(),
            witness: a.proposal.witness,
            operation: *a.proposal.operation.as_bytes(),
            account: a.proposal.previous_account(),
            freeze: a.proposal.preparation.ok_or(Error::Scope)?,
            proposal: a.proposal.binding()?,
            committed,
            wire: Vec::new(),
        };
        let body = r.body();
        let signature = signer.sign(Purpose::AnchorTransferredAccountDecision, &body)?;
        r.wire = envelope(&body, &signature)?;
        Ok(r)
    }
    pub(super) fn decode(
        wire: &[u8],
        authority: &impl ImageAuthority,
    ) -> Result<Self, DurableError> {
        if wire.len() != WIRE_BYTES {
            return Err(DurableError::Corrupt);
        }
        let (body, signature) = open_envelope(wire)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *b"QPTARD01" {
            return Err(Error::Encoding.into());
        }
        let scope = Scope::decode(&mut d)?;
        let (witness, operation, account, freeze, proposal) =
            (d.array()?, d.array()?, d.array()?, d.array()?, d.array()?);
        let flag = d.array::<1>()?;
        let at = d.u64()?;
        d.finish()?;
        let committed = match flag {
            [0] if at == 0 => None,
            [1] => {
                scope.validity.check(at)?;
                Some(at)
            }
            _ => return Err(DurableError::Corrupt),
        };
        for value in [witness, operation, account, freeze, proposal] {
            nonzero(&value)?;
        }
        scope.check(witness, authority)?;
        authority.resolve(witness)?.key.verify(
            Purpose::AnchorTransferredAccountDecision,
            body,
            signature,
        )?;
        Ok(Self {
            scope,
            witness,
            operation,
            account,
            freeze,
            proposal,
            committed,
            wire: wire.to_vec(),
        })
    }
    fn check_proposal(&self, p: &AnchorAccountReplacementProposal) -> Result<(), DurableError> {
        if self.witness != p.witness
            || self.operation != *p.operation.as_bytes()
            || self.account != p.previous_account()
            || Some(self.freeze) != p.preparation
            || self.proposal != p.binding()?
        {
            return Err(Error::Scope.into());
        }
        if let Some(at) = self.committed {
            p.validity.check(at)?;
            p.policy_validity.check(at)?;
        }
        Ok(())
    }
    pub(super) fn decision(
        &self,
        a: &AnchorTransferredAccountReplacementApproval,
    ) -> Result<AnchorTransferredAccountDecision, DurableError> {
        self.check_proposal(&a.proposal)?;
        if self.scope != a.scope {
            return Err(Error::Scope.into());
        }
        Ok(AnchorTransferredAccountDecision {
            proposal: a.proposal.clone(),
            wire: self.wire.clone(),
            state: if self.committed.is_some() {
                AnchorAccountReplacementState::Committed
            } else {
                AnchorAccountReplacementState::Closed
            },
        })
    }
    pub(in crate::anchor::store) fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    pub(super) fn decision_id(&self) -> [u8; 32] {
        self.scope.decision
    }
}
impl Image {
    pub(in crate::anchor::store) fn require_account_decision(
        &self,
        p: &AnchorAccountReplacementProposal,
        authority: &impl ImageAuthority,
    ) -> Result<(), DurableError> {
        let r = self
            .account_decisions
            .get(p.operation.as_bytes())
            .ok_or(DurableError::Suspended)?;
        let verified = Record::decode(r.as_bytes(), authority)?;
        verified.check_proposal(p)?;
        if verified.committed.is_none() {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(in crate::anchor::store) fn check_account_decisions(
        &self,
        authority: &impl ImageAuthority,
    ) -> Result<(), DurableError> {
        if self.account_decisions.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        let mut decisions = BTreeSet::new();
        for (op, r) in &self.account_decisions {
            let r = Record::decode(r.as_bytes(), authority)?;
            if *op != r.operation
                || !decisions.insert(r.scope.decision)
                || self.account_closures.contains_key(op)
            {
                return Err(DurableError::Corrupt);
            }
            let frozen = self
                .account_freezes
                .get(&r.account)
                .ok_or(DurableError::Corrupt)?;
            if frozen.binding()? != r.freeze {
                return Err(DurableError::Corrupt);
            }
            let retained = self
                .account_replacements
                .values()
                .find(|p| p.operation.as_bytes() == op);
            match (r.committed, retained) {
                (Some(_), Some(p)) => r.check_proposal(p)?,
                (None, None) => {}
                _ => return Err(DurableError::Corrupt),
            }
        }
        for p in self.account_replacements.values() {
            if self
                .account_freezes
                .get(&p.previous_account())
                .is_some_and(|f| f.is_transferred() || f.snapshot_witness() != p.witness)
            {
                self.require_account_decision(p, authority)?;
            }
        }
        Ok(())
    }
}
pub(in crate::anchor::store) fn encode_records(
    records: &BTreeMap<[u8; 32], Record>,
    authority: &impl ImageAuthority,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    if records.is_empty() || records.len() > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (op, r) in records {
        let r = Record::decode(r.as_bytes(), authority)?;
        if *op != r.operation {
            return Err(DurableError::Corrupt);
        }
        out.extend_from_slice(op);
        out.extend_from_slice(r.as_bytes());
    }
    Ok(())
}
pub(in crate::anchor::store) fn decode_records(
    d: &mut Decoder<'_>,
    authority: &impl ImageAuthority,
) -> Result<BTreeMap<[u8; 32], Record>, DurableError> {
    let count = usize::from(d.u16()?);
    if count == 0 || count > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    let mut records = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let op = d.array()?;
        if previous.is_some_and(|p| p >= op) {
            return Err(DurableError::Corrupt);
        }
        let r = Record::decode(d.take(WIRE_BYTES)?, authority)?;
        if r.operation != op {
            return Err(DurableError::Corrupt);
        }
        records.insert(op, r);
        previous = Some(op);
    }
    Ok(records)
}
