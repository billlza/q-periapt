// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded inverse of the shared public-view grammar, never an authority parser.
use super::*;
use crate::codec::Decoder;
mod bootstrap;
mod session;

struct Reader<'a>(Decoder<'a>);
impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        let [value] = self.0.array()?;
        Ok(value)
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }
    fn number(&mut self) -> Result<u64, Error> {
        self.0.u64()
    }
    fn size(&mut self) -> Result<usize, Error> {
        usize::try_from(self.number()?).map_err(|_| Error::Encoding)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.0.array()
    }
    fn option<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        if self.boolean()? {
            parse(self).map(Some)
        } else {
            Ok(None)
        }
    }
    fn list<T>(
        &mut self,
        minimum_bytes: usize,
        parse: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        self.bounded_list(minimum_bytes, usize::MAX, parse)
    }
    fn bounded_list<T>(
        &mut self,
        minimum_bytes: usize,
        maximum_count: usize,
        mut parse: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let count = self.size()?;
        if minimum_bytes == 0 || count > maximum_count || count > self.0.remaining() / minimum_bytes
        {
            return Err(Error::Encoding);
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(parse(self)?);
        }
        Ok(values)
    }
    fn blob(&mut self) -> Result<Vec<u8>, Error> {
        let length = self.size()?;
        Ok(self.0.take(length)?.to_vec())
    }
    fn phase(&mut self) -> Result<DurableStatus, Error> {
        DurableStatus::decode(self.byte()?).map_err(|_| Error::Encoding)
    }
    fn checkpoint(&mut self) -> Result<RosterCheckpoint, Error> {
        RosterCheckpoint::from_trusted_state(self.number()?, self.array()?)
    }
    fn record(&mut self) -> Result<RecordMetadataEntry, Error> {
        let id = self.array()?;
        let context = self.array()?;
        let phase = self.phase()?;
        let authorities = self.list(32, Self::array)?;
        let one_time_claims = self.list(32, Self::array)?;
        let inventory_references = self.list(32, Self::array)?;
        let metadata = match self.byte()? {
            1 => self.bootstrap()?,
            2 => RecordMetadata::Prekey {
                request: PrekeyId::from_trusted_state(self.array()?)?,
                kind: LeafKind::decode(self.byte()?)?,
                validity: Validity::new(self.number()?, self.number()?)?,
                public_fingerprint: self.option(Self::array)?,
                source: self.option(|r| BootstrapOperationId::from_trusted_state(r.array()?))?,
            },
            3 => RecordMetadata::Session(self.session()?),
            4 => RecordMetadata::Roster {
                account: self.array()?,
                checkpoint: self.checkpoint()?,
                public_history: self.blob()?,
            },
            5 => self.fanout()?,
            6 => RecordMetadata::PrekeyPublications {
                next_epoch: self.number()?,
                public_history: self.blob()?,
            },
            _ => return Err(Error::Encoding),
        };
        Ok(RecordMetadataEntry {
            id,
            context,
            phase,
            authorities,
            one_time_claims,
            inventory_references,
            metadata,
        })
    }
}

pub(in crate::durable) fn decode_public_view(
    bytes: &[u8],
) -> Result<PendingWriteRecoveryView, Error> {
    if bytes.len() > crate::anchor::MAX_PENDING_RECOVERY_METADATA || bytes.len() < 96 {
        return Err(Error::Encoding);
    }
    let mut reader = Reader(Decoder::new(bytes));
    let head = AnchorHead::from_trusted_state(reader.number()?, reader.number()?, reader.array()?)?;
    let local_account = reader.array()?;
    let next_fanout_ordinal = reader.number()?;
    let maximum_records = crate::contract::MAX_SESSION_OPERATION_RECORDS
        + crate::contract::MAX_PREKEY_RECORDS
        + crate::contract::MAX_ACCOUNT_ROSTER_RECORDS
        + 1;
    let records = reader.bounded_list(90, maximum_records, Reader::record)?;
    reader.0.finish()?;
    if records
        .iter()
        .zip(records.iter().skip(1))
        .any(|(a, b)| a.id >= b.id)
    {
        return Err(Error::Encoding);
    }
    let encoded = encode_public_view(head, local_account, next_fanout_ordinal, &records)
        .map_err(|_| Error::Encoding)?;
    if encoded != bytes {
        return Err(Error::Encoding);
    }
    Ok(PendingWriteRecoveryView {
        head,
        local_account,
        next_fanout_ordinal,
        records,
    })
}
