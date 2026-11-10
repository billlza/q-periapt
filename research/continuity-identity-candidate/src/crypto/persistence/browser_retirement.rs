// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original authenticated catalogue record retirement, not native inode emulation.
use super::*;
use crate::{
    storage::Storage, AnchorRetiredReportAcknowledgement, AnchorRetiredReportProposal,
    VerifiedDevice,
};

const TERMINAL: &[u8; 8] = b"QPSRET01";
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SigningFilePlan {
    identity: SigningKeyId,
    record: [u8; 32],
    digest: [u8; 32],
    report: AnchorRetiredReportProposal,
}
impl SigningFilePlan {
    pub(crate) fn identity(&self) -> SigningKeyId {
        self.identity
    }
    pub(crate) fn report(&self) -> &AnchorRetiredReportProposal {
        &self.report
    }
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"QPSRPL02");
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.record);
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.report.to_bytes());
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        if d.array::<8>()? != *b"QPSRPL02" {
            return Err(Error::Encoding);
        }
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let record = d.array()?;
        crate::codec::nonzero(&record)?;
        Ok(Self {
            identity,
            record,
            digest: d.array()?,
            report: AnchorRetiredReportProposal::from_trusted_state(d.take(353)?)?,
        })
    }
    fn check_ack(
        &self,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<(), DurableError> {
        if &self.report != ack.proposal()
            || self.report.inventory().subject().journal_parts().1
                != crate::bootstrap::storage_owner(original)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(crate) async fn capture(
        store: &Storage,
        path: &Path,
        key: &JournalKey,
        identity: SigningKeyId,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<Self, DurableError> {
        let record = store.read_signer_record(path).await?;
        if record.revision != 1 || unseal(key, identity, 2, &record.bytes)?.public != original.key {
            return Err(DurableError::Conflict);
        }
        let plan = Self {
            identity,
            record: record.identity,
            digest: crate::crypto::digest(
                b"Q-PERIAPT-CONTINUITY-RETIRED-SIGNER-FILE/v1",
                &record.bytes,
            ),
            report: ack.proposal().clone(),
        };
        plan.check_ack(original, ack)?;
        Ok(plan)
    }
    fn inspect(
        &self,
        id: [u8; 32],
        revision: u32,
        bytes: &[u8],
        key: &JournalKey,
        original: &VerifiedDevice,
    ) -> Result<bool, DurableError> {
        if id != self.record {
            return Err(DurableError::Conflict);
        }
        match (revision, bytes.len()) {
            (2, 8) if bytes == TERMINAL => Ok(true),
            (1, FILE_BYTES) => {
                if crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-RETIRED-SIGNER-FILE/v1", bytes)
                    != self.digest
                    || unseal(key, self.identity, 2, bytes)?.public != original.key
                {
                    return Err(DurableError::Conflict);
                }
                Ok(false)
            }
            _ => Err(DurableError::Corrupt),
        }
    }
    pub(crate) async fn erased(
        &self,
        store: &Storage,
        path: &Path,
        key: &JournalKey,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<bool, DurableError> {
        self.check_ack(original, ack)?;
        let record = store.read_signer_record(path).await?;
        self.inspect(
            record.identity,
            record.revision,
            &record.bytes,
            key,
            original,
        )
    }
    pub(crate) async fn erase(
        &self,
        store: &Storage,
        path: &Path,
        key: &JournalKey,
        original: &VerifiedDevice,
        ack: &AnchorRetiredReportAcknowledgement,
    ) -> Result<(), DurableError> {
        self.check_ack(original, ack)?;
        store
            .retire_signer_record(path, |record| {
                self.inspect(
                    record.identity,
                    record.revision,
                    &record.bytes,
                    key,
                    original,
                )
            })
            .await
    }
}
