// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn checkpoint(out: &mut Vec<u8>, version: u64, digest: [u8; 32]) {
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&digest);
}
fn read_roster(d: &mut Decoder<'_>) -> Result<RosterCheckpoint, DurableError> {
    Ok(RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?)
}
fn read_policy(d: &mut Decoder<'_>) -> Result<PolicyCheckpoint, DurableError> {
    Ok(PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?)
}
fn flag(d: &mut Decoder<'_>) -> Result<bool, DurableError> {
    match d.array::<1>()? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(DurableError::Corrupt),
    }
}

impl Preparation {
    pub(in crate::enrollment) fn new(policy: PolicyCheckpoint) -> Self {
        Self {
            selected: false,
            policy,
            extension: None,
        }
    }
    pub(in crate::enrollment) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        out.push(u8::from(self.selected));
        checkpoint(out, self.policy.version(), self.policy.digest());
        out.push(u8::from(self.extension.is_some()));
        if let Some(e) = &self.extension {
            out.extend_from_slice(&e.approval.operation);
            out.push(u8::from(e.approval.previous.is_some()));
            if let Some(id) = e.approval.previous {
                out.extend_from_slice(&id);
            }
            checkpoint(
                out,
                e.approval.predecessor.version(),
                e.approval.predecessor.digest(),
            );
            out.extend_from_slice(&e.approval.until.to_be_bytes());
            e.origin.encode(out)?;
            checkpoint(out, e.origin_policy.version(), e.origin_policy.digest());
            out.extend_from_slice(&e.previous_until.to_be_bytes());
            checkpoint(
                out,
                e.previous_checkpoint.version(),
                e.previous_checkpoint.digest(),
            );
            checkpoint(out, e.previous_policy.version(), e.previous_policy.digest());
            checkpoint(
                out,
                e.issued_checkpoint.version(),
                e.issued_checkpoint.digest(),
            );
            field(out, &e.issued_roster)?;
            out.extend_from_slice(&e.target);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let selected = flag(d)?;
        let policy = read_policy(d)?;
        let extension = if flag(d)? {
            let id = d.array()?;
            let previous = if flag(d)? { Some(d.array()?) } else { None };
            let approval = EnrollmentExtensionApproval::from_trusted_state(
                id,
                previous,
                read_roster(d)?,
                d.u64()?,
            )?;
            let origin = Admission::decode(d)?;
            let origin_policy = read_policy(d)?;
            let previous_until = d.u64()?;
            let previous_checkpoint = read_roster(d)?;
            let previous_policy = read_policy(d)?;
            let issued_checkpoint = read_roster(d)?;
            let issued_roster = take(d)?;
            let target = d.array()?;
            crate::codec::nonzero(&target)?;
            Some(Box::new(Extension {
                approval,
                origin,
                origin_policy,
                previous_until,
                previous_checkpoint,
                previous_policy,
                issued_checkpoint,
                issued_roster,
                target,
            }))
        } else {
            None
        };
        Ok(Self {
            selected,
            policy,
            extension,
        })
    }
}
