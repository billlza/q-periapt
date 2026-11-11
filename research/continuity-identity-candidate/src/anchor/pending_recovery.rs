// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact independently approved completion of one retained ordinary write.
use super::*;

pub(crate) const MAX_PENDING_RECOVERY_METADATA: usize =
    4 * crate::contract::MAX_JOURNAL_IMAGE_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingWriteRecoveryScope {
    pub(crate) witness: [u8; 32],
    pub(crate) subject: AnchorSubject,
    pub(crate) expected: AnchorHead,
    pub(crate) target: AnchorHead,
    pub(crate) authority: [u8; 32],
    pub(crate) policy: [u8; 32],
    pub(crate) policy_authorization: Option<[u8; 32]>,
    pub(crate) intent: [u8; 32],
}
impl PendingWriteRecoveryScope {
    fn check(&self) -> Result<(), Error> {
        for value in [self.witness, self.authority, self.policy, self.intent] {
            nonzero(&value)?;
        }
        if let Some(value) = self.policy_authorization {
            nonzero(&value)?;
        }
        let operation = AnchorOperation::advance(self.expected, self.target.digest())?;
        if operation != AnchorOperation(Command::Advance(self.expected, self.target)) {
            return Err(Error::Scope);
        }
        Ok(())
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.witness);
        self.subject.encode(out);
        self.expected.encode(out);
        self.target.encode(out);
        out.extend_from_slice(&self.authority);
        out.extend_from_slice(&self.policy);
        out.push(u8::from(self.policy_authorization.is_some()));
        out.extend_from_slice(&self.policy_authorization.unwrap_or([0; 32]));
        out.extend_from_slice(&self.intent);
    }
    pub(crate) fn metadata_prefix(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut out = b"QPWRMD01".to_vec();
        self.encode(&mut out);
        Ok(out)
    }
    pub(crate) fn proposal(
        self,
        metadata: &[u8],
    ) -> Result<AnchorPendingWriteRecoveryProposal, Error> {
        self.check()?;
        let proposal = AnchorPendingWriteRecoveryProposal {
            scope: self,
            metadata: digest(b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-METADATA/v1", metadata),
        };
        proposal.check_metadata(metadata)?;
        Ok(proposal)
    }
}

/// Immutable public expectation, not authority to bypass expiry. Independently
/// authenticate and retain the exact proposal and complete metadata before the
/// privileged witness-control-plane call. Never approve directly from an incoming
/// device request merely because its historical signature is valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorPendingWriteRecoveryProposal {
    pub(crate) scope: PendingWriteRecoveryScope,
    metadata: [u8; 32],
}
impl AnchorPendingWriteRecoveryProposal {
    /// Exact public proposal encoding size, excluding the two-signature envelope.
    pub const ENCODED_BYTES: usize = 393;
    /// Canonical QPWRPL01 expectation for independent durable approval.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"QPWRPL01".to_vec();
        self.scope.encode(&mut out);
        out.extend_from_slice(&self.metadata);
        out
    }
    /// Restore independently retained approval metadata. Parsing is not approval,
    /// freshness, a signature check or an operational device capability.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::ENCODED_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPWRPL01" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        let subject = AnchorSubject::decode(&mut d)?;
        let expected = AnchorHead::decode(&mut d)?;
        let target = AnchorHead::decode(&mut d)?;
        let authority = d.array()?;
        let policy = d.array()?;
        let tag = d.array::<1>()?;
        let authorization = d.array()?;
        let policy_authorization = match tag {
            [0] if authorization == [0; 32] => None,
            [1] => {
                nonzero(&authorization)?;
                Some(authorization)
            }
            _ => return Err(Error::Encoding),
        };
        let scope = PendingWriteRecoveryScope {
            witness,
            subject,
            expected,
            target,
            authority,
            policy,
            policy_authorization,
            intent: d.array()?,
        };
        scope.check()?;
        let metadata = d.array()?;
        nonzero(&metadata)?;
        d.finish()?;
        Ok(Self { scope, metadata })
    }
    /// Exact original witness subject, which must remain live and unfrozen.
    pub fn subject(&self) -> AnchorSubject {
        self.scope.subject
    }
    /// Original source head; no claim that it is still current.
    pub fn expected_head(&self) -> AnchorHead {
        self.scope.expected
    }
    /// Original sealed target; this is not a newly generated image.
    pub fn target_head(&self) -> AnchorHead {
        self.scope.target
    }
    /// Commitment to the complete authenticated local ordinary pending record.
    pub fn pending_intent_digest(&self) -> [u8; 32] {
        self.scope.intent
    }
    /// Current credential/roster authority expected by the original local image.
    pub fn expected_authority(&self) -> [u8; 32] {
        self.scope.authority
    }
    /// Exact policy checkpoint digest retained by the original source and target.
    pub fn expected_policy_digest(&self) -> [u8; 32] {
        self.scope.policy
    }
    /// Exact retained G/T or independent P authorization, when present.
    pub fn expected_policy_authorization(&self) -> Option<[u8; 32]> {
        self.scope.policy_authorization
    }
    /// Binding of the entire independently retained approval expectation.
    pub fn binding(&self) -> [u8; 32] {
        digest(
            b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1",
            &self.to_bytes(),
        )
    }
    pub(crate) fn confirm_reply(&self, reply: &AnchorReply) -> Result<(), Error> {
        let operation = AnchorOperation::advance(self.scope.expected, self.scope.target.digest())?;
        if reply.authority != self.scope.witness
            || reply.subject != self.scope.subject
            || reply.operation != AnchorOperation::query()
            || reply.outcome != AnchorOutcome::Current
            || reply.head != self.scope.target
            || reply.last
                != Some(command_id(
                    &self.scope.witness,
                    self.scope.subject,
                    operation,
                ))
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn check_metadata(&self, bytes: &[u8]) -> Result<(), Error> {
        let prefix = self.scope.metadata_prefix()?;
        if bytes.len() > MAX_PENDING_RECOVERY_METADATA
            || bytes.len() < prefix.len() + 2 * (8 + 96)
            || !bytes.starts_with(&prefix)
            || digest(b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-METADATA/v1", bytes) != self.metadata
        {
            return Err(Error::Authentication);
        }
        let mut d = Decoder::new(bytes);
        d.take(prefix.len())?;
        for _ in 0..2 {
            let length =
                usize::try_from(u64::from_be_bytes(d.array()?)).map_err(|_| Error::Encoding)?;
            if length < 96 {
                return Err(Error::Encoding);
            }
            d.take(length)?;
        }
        d.finish()
    }
}
