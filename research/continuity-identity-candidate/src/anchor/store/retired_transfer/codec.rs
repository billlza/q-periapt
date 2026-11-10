// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
pub(super) const APPROVAL_BYTES: usize = 8 + 4 * 32 + 16 + 32 + 313 + 1 + 32 + 32;
pub(super) const WIRE_BYTES: usize = 4 + APPROVAL_BYTES + 8 + crate::crypto::SIGNATURE_BYTES;
impl AnchorTransferredCleanupApproval {
    pub(crate) const BYTES: usize = APPROVAL_BYTES;
    /// Canonical independent approval. No network input may select this expectation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = b"QPTCLA01".to_vec();
        for v in [self.namespace, self.history, self.signer, self.decision] {
            b.extend_from_slice(&v);
        }
        self.validity.encode(&mut b);
        b.extend_from_slice(&self.retirement);
        b.extend_from_slice(&self.inventory.to_bytes());
        b.push((self.stage.index() + 1) as u8);
        b.extend_from_slice(&self.report.unwrap_or([0; 32]));
        b.extend_from_slice(&self.previous);
        b
    }
    /// Restore the same independently retained decision and complete public inputs.
    pub fn restore_trusted_state(
        bytes: &[u8],
        materials: &AnchorTransferredCleanupMaterials<'_>,
    ) -> Result<Self, DurableError> {
        let restored = Self::decode(bytes)?;
        restored.check(materials.history)?;
        let mut expected = Self::from_trusted_state(
            materials,
            restored.stage,
            restored.validity,
            restored.decision,
        )?;
        // A later verified history restores an old independently retained
        // approval without silently changing its signing authority or checkpoint.
        expected.signer = restored.signer;
        expected.history = restored.history;
        if restored != expected {
            return Err(Error::Scope.into());
        }
        Ok(restored)
    }
    fn decode(bytes: &[u8]) -> Result<Self, DurableError> {
        if bytes.len() != APPROVAL_BYTES {
            return Err(Error::Encoding.into());
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPTCLA01" {
            return Err(Error::Encoding.into());
        }
        let (namespace, history, signer, decision) =
            (d.array()?, d.array()?, d.array()?, d.array()?);
        let validity = Validity::decode(&mut d)?;
        let retirement = d.array()?;
        let inventory = AnchorRetiredCleanupProposal::from_trusted_state(d.take(313)?)?;
        let stage = match d.array::<1>()? {
            [1] => AnchorTransferredCleanupStage::Inventory,
            [2] => AnchorTransferredCleanupStage::Report,
            [3] => AnchorTransferredCleanupStage::Acknowledged,
            _ => return Err(Error::Encoding.into()),
        };
        let value = d.array()?;
        let report = if stage == AnchorTransferredCleanupStage::Inventory {
            if value != [0; 32] {
                return Err(Error::Encoding.into());
            }
            None
        } else {
            nonzero(&value)?;
            Some(value)
        };
        let previous = d.array()?;
        d.finish()?;
        Ok(Self {
            namespace,
            history,
            signer,
            decision,
            validity,
            retirement,
            inventory,
            report,
            previous,
            stage,
        })
    }
}
impl AnchorTransferredCleanupReceipt {
    pub(crate) const BYTES: usize = WIRE_BYTES;
    pub(super) fn sign(
        approval: &AnchorTransferredCleanupApproval,
        at: u64,
        signer: &AnchorSigningKey,
    ) -> Result<Self, DurableError> {
        approval.validity.check(at)?;
        let mut body = approval.to_bytes();
        body.get_mut(..8)
            .ok_or(Error::Encoding)?
            .copy_from_slice(b"QPTCLR01");
        body.extend_from_slice(&at.to_be_bytes());
        let signature = signer.sign(Purpose::AnchorTransferredCleanup, &body)?;
        Ok(Self {
            approval: approval.clone(),
            at,
            wire: envelope(&body, &signature)?,
        })
    }
    pub(super) fn decode(
        wire: &[u8],
        authority: &impl ImageAuthority,
    ) -> Result<Self, DurableError> {
        if wire.len() != WIRE_BYTES {
            return Err(Error::Encoding.into());
        }
        let (body, signature) = open_envelope(wire)?;
        if body.len() != APPROVAL_BYTES + 8 || body.get(..8) != Some(b"QPTCLR01") {
            return Err(Error::Encoding.into());
        }
        let mut approved = body.get(..APPROVAL_BYTES).ok_or(Error::Encoding)?.to_vec();
        approved
            .get_mut(..8)
            .ok_or(Error::Encoding)?
            .copy_from_slice(b"QPTCLA01");
        let approval = AnchorTransferredCleanupApproval::decode(&approved)?;
        approval.check(authority)?;
        let at = u64::from_be_bytes(
            body.get(APPROVAL_BYTES..)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        );
        approval.validity.check(at)?;
        authority.resolve(approval.signer)?.key.verify(
            Purpose::AnchorTransferredCleanup,
            body,
            signature,
        )?;
        Ok(Self {
            approval,
            at,
            wire: wire.to_vec(),
        })
    }
    pub(super) fn check(&self, authority: &impl ImageAuthority) -> Result<(), DurableError> {
        if Self::decode(&self.wire, authority)? != *self {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
}
pub(in crate::anchor::store) fn encode_records(
    records: &BTreeMap<[u8; 32], Record>,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (id, r) in records {
        out.extend_from_slice(id);
        out.push(u8::try_from(r.receipts.len()).map_err(|_| DurableError::Capacity)?);
        for proof in &r.receipts {
            out.extend_from_slice(proof.as_bytes());
        }
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
    let mut last = None;
    for _ in 0..count {
        let id = d.array()?;
        if last.is_some_and(|p| p >= id) {
            return Err(DurableError::Corrupt);
        }
        last = Some(id);
        let [n] = d.array()?;
        if !(1..=3).contains(&n) {
            return Err(DurableError::Corrupt);
        }
        let mut receipts = Vec::new();
        for _ in 0..n {
            receipts.push(AnchorTransferredCleanupReceipt::decode(
                d.take(WIRE_BYTES)?,
                authority,
            )?);
        }
        records.insert(id, Record { receipts });
    }
    Ok(records)
}
