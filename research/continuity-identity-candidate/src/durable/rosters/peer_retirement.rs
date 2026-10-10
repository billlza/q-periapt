// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit local adoption of an independently authenticated remote root retirement.
use super::*;

// The encrypted image authenticates this local decision and its exact original
// statement. This is not a retained transferable witness signature or target grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PeerRetirement {
    operation: [u8; 32],
    statement: [u8; 32],
    successor: [u8; 32],
    witness: [u8; 32],
}
impl PeerRetirement {
    fn from_observation(observed: &crate::AnchorRetiredAccount) -> Result<Self, DurableError> {
        let proposal = observed.proposal();
        Ok(Self {
            operation: *proposal.operation().as_bytes(),
            statement: proposal.binding()?,
            successor: proposal.successor_account(),
            witness: proposal.witness_binding(),
        })
    }
    pub(super) fn wrap(&self, payload: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
        let mut result = Zeroizing::new(Vec::with_capacity(8 + 128 + payload.len()));
        result.extend_from_slice(b"QPRHST07");
        result.extend_from_slice(&self.operation);
        result.extend_from_slice(&self.statement);
        result.extend_from_slice(&self.successor);
        result.extend_from_slice(&self.witness);
        result.extend_from_slice(&payload);
        result
    }
    pub(super) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let result = Self {
            operation: decoder.array()?,
            statement: decoder.array()?,
            successor: decoder.array()?,
            witness: decoder.array()?,
        };
        if [
            result.operation,
            result.statement,
            result.successor,
            result.witness,
        ]
        .contains(&[0; 32])
        {
            return Err(DurableError::Corrupt);
        }
        Ok(result)
    }
}

pub(super) fn check_scope(image: &Image, saved: &Stored) -> Result<(), DurableError> {
    let Some(retired) = &saved.peer_retirement else {
        return Ok(());
    };
    if saved.roster.account_id() == image.local_account
        || saved.roster.account_id() == retired.successor
        || saved.local_commit.is_some()
        || saved.policy_continuation.is_some()
        || saved.policy_renewal.is_some()
        || !matches!(image.protection, Protection::Required { witness, .. } if witness == retired.witness)
    {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}

impl DeviceJournal {
    pub(crate) fn retire_peer_account(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        retirement: &crate::AnchorRetiredAccount,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<(), DurableError> {
        self.check_policy(scope.original_policy)?;
        let proposal = retirement.proposal();
        if proposal.previous_account() == scope.local_identity().0 {
            return Err(DurableError::Conflict);
        }
        let mut image = self.image()?;
        peer_roster::authorize(&image, scope, policy, now)?;
        match image.protection {
            Protection::Required { witness, .. } if witness == proposal.witness_binding() => {}
            Protection::Required { .. } => return Err(DurableError::Conflict),
            Protection::Local => return Err(DurableError::AnchorRequired),
        }
        let mut saved = get(&image, &proposal.previous_account())?;
        let expected = PeerRetirement::from_observation(retirement)?;
        match saved.peer_retirement {
            Some(previous) if previous != expected => return Err(DurableError::Conflict),
            Some(_) => {}
            None => {
                saved.peer_retirement = Some(expected);
                check_scope(&image, &saved)?;
                self.check_operational_release(&image, policy, now)?;
                peer_roster::authorize(&image, scope, policy, now)?;
                image
                    .records
                    .insert(id(&proposal.previous_account()), saved.record()?);
                // The ordinary encrypted-image/witness-head transaction makes the
                // peer floor part of this sender's rollback-protected journal.
                self.persist(&mut image)?;
            }
        }
        self.check_operational_release(&image, policy, now)?;
        peer_roster::authorize(&image, scope, policy, now)?;
        Ok(())
    }
}
