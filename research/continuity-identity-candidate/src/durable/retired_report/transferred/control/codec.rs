// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
const TAG: &[u8; 8] = b"QPTCCP01";
fn auth(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let mut derived = ZeroizingBytes::<32>::zeroed();
    hkdf::Hkdf::<Sha256>::new(None, key.0.as_bytes())
        .expand(
            b"Q-PERIAPT-TRANSFERRED-CLEANUP-CONTROL-KEY/v1",
            derived.as_mut_bytes(),
        )
        .map_err(|_| Error::Provider)?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| Error::Provider.into())
}
impl Control {
    pub(crate) fn context_binding(wire: &[u8]) -> Result<[u8; 32], DurableError> {
        if !(107 + 32..=Self::MAX_BYTES).contains(&wire.len())
            || wire.get(..8) != Some(TAG.as_slice())
        {
            return Err(DurableError::Corrupt);
        }
        wire.get(8..40)
            .ok_or(DurableError::Corrupt)?
            .try_into()
            .map_err(|_| DurableError::Corrupt)
    }
    pub(crate) fn encode(&self, key: &JournalKey) -> Result<Vec<u8>, DurableError> {
        if self.steps.len() > 3 {
            return Err(DurableError::Capacity);
        }
        let mut out = TAG.to_vec();
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.inventory);
        out.push(u8::from(self.report.is_some()));
        out.extend_from_slice(&self.report.unwrap_or([0; 32]));
        out.push(u8::from(self.accounted));
        out.push(u8::try_from(self.steps.len()).map_err(|_| DurableError::Capacity)?);
        for s in &self.steps {
            out.extend_from_slice(&s.approval.to_bytes());
            out.push(u8::from(s.receipt.is_some()));
            if let Some(r) = &s.receipt {
                out.extend_from_slice(r.as_bytes());
            }
        }
        let mut mac = auth(key)?;
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        if out.len() > Self::MAX_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(out)
    }
    pub(crate) fn decode(
        key: &JournalKey,
        ctx: &TransferredRetirementContext,
        inventory: &AnchorRetiredCleanupProposal,
        report: Option<&AnchorRetiredReportProposal>,
        ack: Option<&AnchorRetiredReportProposal>,
        wire: &[u8],
    ) -> Result<Self, DurableError> {
        Self::context_binding(wire)?;
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut mac = auth(key)?;
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *TAG {
            return Err(DurableError::Corrupt);
        }
        let context = d.array()?;
        let inventory_binding = d.array()?;
        let flag = d.array::<1>()?;
        let value = d.array()?;
        let report_binding = match flag {
            [0] if value == [0; 32] => None,
            [1] => {
                crate::codec::nonzero(&value)?;
                Some(value)
            }
            _ => return Err(DurableError::Corrupt),
        };
        let accounted = match d.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err(DurableError::Corrupt),
        };
        let [count] = d.array()?;
        if count > 3 {
            return Err(DurableError::Corrupt);
        }
        let mut saved = Self {
            context,
            inventory: inventory_binding,
            report: report_binding,
            accounted,
            steps: Vec::new(),
        };
        saved.check_metadata(ctx, inventory, report, ack)?;
        let mut decisions = std::collections::BTreeSet::new();
        for n in 0..usize::from(count) {
            let raw = d.take(Approval::BYTES)?;
            let prior = if n == 0 {
                None
            } else {
                Some(
                    saved
                        .steps
                        .last()
                        .and_then(|s| s.receipt.as_ref())
                        .ok_or(DurableError::Corrupt)?,
                )
            };
            let a = Approval::restore_trusted_state(
                raw,
                &ctx.materials(inventory, if n == 0 { None } else { report }, prior),
            )?;
            if index(a.stage()) != n
                || !decisions.insert(a.operator_decision())
                || (n == 2 && !accounted)
            {
                return Err(DurableError::Corrupt);
            }
            let receipt = match d.array::<1>()? {
                [0] => None,
                [1] => Some(a.verify_receipt(
                    ctx.history(),
                    d.take(AnchorTransferredCleanupReceipt::BYTES)?,
                )?),
                _ => return Err(DurableError::Corrupt),
            };
            saved.steps.push(Step {
                approval: a,
                receipt,
            });
        }
        d.finish()?;
        if report.is_some() {
            saved.verified(Stage::Inventory)?;
        }
        if accounted {
            saved.verified(Stage::Report)?;
        }
        Ok(saved)
    }
}
