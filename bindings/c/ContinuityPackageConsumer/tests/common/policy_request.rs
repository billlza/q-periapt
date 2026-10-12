// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same-host public ABI record parser shared by independent consumer traces.
use crate::{p, Result};
use std::{fs, path::Path};
struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
    big_endian: bool,
}
impl Input<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.offset.checked_add(N).ok_or("input offset")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated public record")?
            .try_into()?;
        self.offset = end;
        Ok(value)
    }
    fn u64(&mut self) -> Result<u64> {
        let bytes = self.array()?;
        Ok(if self.big_endian {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_ne_bytes(bytes)
        })
    }
    fn u32(&mut self) -> Result<u32> {
        let bytes = self.array()?;
        Ok(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_ne_bytes(bytes)
        })
    }
    fn roster(&mut self) -> Result<p::RosterCheckpoint> {
        Ok(p::RosterCheckpoint::from_trusted_state(
            self.u64()?,
            self.array()?,
        )?)
    }
    fn policy(&mut self) -> Result<p::PolicyCheckpoint> {
        Ok(p::PolicyCheckpoint::from_trusted_state(
            self.u64()?,
            self.array()?,
        )?)
    }
    fn record(&mut self) -> Result<Vec<u8>> {
        let n = usize::try_from(self.u32()?)?;
        let bytes = self.array::<8192>()?;
        if n == 0 || n > 8192 || bytes.get(n..).ok_or("record tail")?.iter().any(|x| *x != 0) {
            return Err("noncanonical public record".into());
        }
        Ok(bytes.get(..n).ok_or("record length")?.to_vec())
    }
}
pub(crate) struct Request {
    pub(crate) scope: p::PolicyRenewalScope,
    pub(crate) account: [u8; 32],
    pub(crate) original_checkpoint: p::RosterCheckpoint,
    pub(crate) original_c: Vec<u8>,
    pub(crate) original_r: Vec<u8>,
    pub(crate) current_c: Vec<u8>,
    pub(crate) current_r: Vec<u8>,
}
/// Android exports explicit big-endian public fields; existing C/Swift/JVM probes use native ABI order.
pub(crate) fn read_request(path: &Path, big_endian: bool) -> Result<Request> {
    let bytes = fs::read(path)?;
    assert_eq!(bytes.len(), 33176);
    let mut r = Input {
        bytes: &bytes,
        offset: 0,
        big_endian,
    };
    let operation = p::PolicyRenewalId::from_trusted_state(r.array()?)?;
    let journal = p::JournalIdentity::from_trusted_state(r.array()?)?;
    let original_owner = r.array()?;
    let original_credential = r.array()?;
    let current_credential = r.array()?;
    let current_roster = r.roster()?;
    let original_policy = r.policy()?;
    let previous_policy = r.policy()?;
    let authorization = r.array()?;
    let previous_authorization = match r.u32()? {
        0 if authorization == [0; 32] => None,
        1 if authorization != [0; 32] => Some(authorization),
        _ => return Err("optional policy authorization".into()),
    };
    assert_eq!(r.u32()?, 0);
    let scope = p::PolicyRenewalScope {
        operation,
        journal,
        original_owner,
        original_credential,
        current_credential,
        current_roster,
        original_policy,
        previous_policy,
        previous_authorization,
    };
    let result = Request {
        scope,
        account: r.array()?,
        original_checkpoint: r.roster()?,
        original_c: r.record()?,
        original_r: r.record()?,
        current_c: r.record()?,
        current_r: r.record()?,
    };
    assert_eq!(r.offset, bytes.len());
    Ok(result)
}
