// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical public expectations and bounded authenticated-store records.
use super::*;

impl AnchorAccountReplacementProposal {
    /// Decode an independently retained expectation. These public bytes do not
    /// approve account recovery or authorize a trusted-control-plane call.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PROPOSAL_BYTES {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPARPL01" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        let operation = AnchorAccountReplacementId::from_trusted_state(d.array()?)?;
        let previous_root = PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?;
        let successor_root = PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?;
        let identity = OriginalIdentity::decode(&mut d)?;
        let target = AnchorSubject::decode(&mut d)?;
        let genesis = d.array()?;
        let key = d.array()?;
        let authority = d.array()?;
        let validity = Validity::decode(&mut d)?;
        let roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let policy_validity = Validity::decode(&mut d)?;
        let count = usize::from(d.u16()?);
        if count > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        let mut frozen = Vec::with_capacity(count);
        for _ in 0..count {
            let subject = AnchorSubject::decode(&mut d)?;
            let head = AnchorHead::decode(&mut d)?;
            let last = decode_last(&mut d, head)?;
            let state = d.array()?;
            frozen.push(AnchorRetiredAccountSubject {
                subject,
                head,
                last,
                state,
            });
        }
        d.finish()?;
        let result = Self {
            witness,
            operation,
            previous_root,
            successor_root,
            identity,
            target,
            genesis,
            key,
            authority,
            validity,
            roster,
            policy,
            policy_validity,
            frozen,
        };
        result.check_shape()?;
        Ok(result)
    }
    /// Retain these exact bytes with the independent host approval before commit.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.check_shape()?;
        let mut out = Vec::with_capacity(4600 + 209 * self.frozen.len());
        out.extend_from_slice(b"QPARPL01");
        out.extend_from_slice(&self.witness);
        out.extend_from_slice(&self.operation.0);
        out.extend_from_slice(&self.previous_root.encode());
        out.extend_from_slice(&self.successor_root.encode());
        self.identity.encode(&mut out);
        self.target.encode(&mut out);
        out.extend_from_slice(&self.genesis);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.authority);
        self.validity.encode(&mut out);
        out.extend_from_slice(&self.roster.version().to_be_bytes());
        out.extend_from_slice(&self.roster.digest());
        out.extend_from_slice(&self.policy.version().to_be_bytes());
        out.extend_from_slice(&self.policy.digest());
        self.policy_validity.encode(&mut out);
        out.extend_from_slice(
            &u16::try_from(self.frozen.len())
                .map_err(|_| Error::Capacity)?
                .to_be_bytes(),
        );
        for old in &self.frozen {
            old.subject.encode(&mut out);
            old.head.encode(&mut out);
            encode_last(old.last, &mut out);
            out.extend_from_slice(&old.state);
        }
        if out.len() > MAX_PROPOSAL_BYTES {
            return Err(Error::Capacity);
        }
        Ok(out)
    }
}

pub(in crate::anchor::store) fn encode_records(
    records: &BTreeMap<[u8; 32], AnchorAccountReplacementProposal>,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (account, proposal) in records {
        out.extend_from_slice(account);
        let body = proposal.to_bytes()?;
        out.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&body);
    }
    Ok(())
}
pub(in crate::anchor::store) fn decode_records(
    d: &mut Decoder<'_>,
) -> Result<BTreeMap<[u8; 32], AnchorAccountReplacementProposal>, DurableError> {
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
        if size > MAX_PROPOSAL_BYTES {
            return Err(DurableError::Capacity);
        }
        let proposal = AnchorAccountReplacementProposal::from_trusted_state(d.take(size)?)?;
        if account != proposal.previous_account() {
            return Err(DurableError::Corrupt);
        }
        result.insert(account, proposal);
    }
    Ok(result)
}
