// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded canonical preparation state; decoding alone grants no authority.
use super::*;
pub(super) const REQUEST_BYTES: usize = 8 + 32 + 32 + PUBLIC_KEY_BYTES;
const MAX_FREEZE_BYTES: usize = 8 + REQUEST_BYTES + 2 + 209 * MAX_ENTRIES;

impl AnchorAccountFreezeRequest {
    /// Persist before control-plane submission. These bytes are not authorization.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REQUEST_BYTES);
        bytes.extend_from_slice(b"QPAFRQ01");
        bytes.extend_from_slice(&self.witness);
        bytes.extend_from_slice(&self.operation.0);
        bytes.extend_from_slice(&self.root.encode());
        bytes
    }
    /// Decode the original independently retained request, never a network-selected approval.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != REQUEST_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAFRQ01" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        nonzero(&witness)?;
        let operation = AnchorAccountFreezeId::from_trusted_state(d.array()?)?;
        let root = PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?;
        d.finish()?;
        Ok(Self {
            witness,
            operation,
            root,
        })
    }
}
impl AnchorFrozenAccount {
    pub(super) fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.check_shape()?;
        let mut out = b"QPAFRZ01".to_vec();
        out.extend_from_slice(&self.request.to_bytes());
        out.extend_from_slice(
            &u16::try_from(self.subjects.len())
                .map_err(|_| Error::Capacity)?
                .to_be_bytes(),
        );
        for entry in &self.subjects {
            entry.subject.encode(&mut out);
            entry.head.encode(&mut out);
            encode_last(entry.last, &mut out);
            out.extend_from_slice(&entry.state);
        }
        if out.len() > MAX_FREEZE_BYTES {
            return Err(Error::Capacity);
        }
        Ok(out)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_FREEZE_BYTES {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAFRZ01" {
            return Err(Error::Encoding);
        }
        let request = AnchorAccountFreezeRequest::from_bytes(d.take(REQUEST_BYTES)?)?;
        let count = usize::from(d.u16()?);
        if count > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        let mut subjects = Vec::with_capacity(count);
        for _ in 0..count {
            let subject = AnchorSubject::decode(&mut d)?;
            let head = AnchorHead::decode(&mut d)?;
            let last = decode_last(&mut d, head)?;
            let state = d.array()?;
            subjects.push(AnchorRetiredAccountSubject {
                subject,
                head,
                last,
                state,
            });
        }
        d.finish()?;
        let result = Self { request, subjects };
        result.check_shape()?;
        Ok(result)
    }
}
pub(in crate::anchor::store) fn encode_records(
    records: &BTreeMap<[u8; 32], AnchorFrozenAccount>,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (account, frozen) in records {
        out.extend_from_slice(account);
        let bytes = frozen.to_bytes()?;
        out.extend_from_slice(
            &u32::try_from(bytes.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&bytes);
    }
    Ok(())
}
pub(in crate::anchor::store) fn decode_records(
    d: &mut Decoder<'_>,
) -> Result<BTreeMap<[u8; 32], AnchorFrozenAccount>, DurableError> {
    let count = usize::from(d.u16()?);
    if count == 0 || count > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    let mut result = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let account = d.array()?;
        if previous.is_some_and(|last| last >= account) {
            return Err(DurableError::Corrupt);
        }
        previous = Some(account);
        let size =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        if size > MAX_FREEZE_BYTES {
            return Err(DurableError::Capacity);
        }
        let frozen = AnchorFrozenAccount::decode(d.take(size)?)?;
        if account != frozen.request.account() {
            return Err(DurableError::Corrupt);
        }
        result.insert(account, frozen);
    }
    Ok(result)
}
