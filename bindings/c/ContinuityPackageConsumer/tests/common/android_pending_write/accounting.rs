// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
pub(super) struct Request {
    pub(super) proposal: p::AnchorPendingWriteRecoveryProposal,
    pub(super) metadata: Vec<u8>,
    pub(super) signed: Vec<u8>,
}
impl Request {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1006 || bytes.len() > 436 + 8388608 + 8192 {
            return Err("complete request bound".into());
        }
        let size = |offset| -> Result<usize> {
            Ok(usize::try_from(u32::from_be_bytes(
                bytes.get(offset..offset + 4).ok_or("length")?.try_into()?,
            ))?)
        };
        let metadata = size(0)?;
        let signed = size(4)?;
        if !(569..=8388608).contains(&metadata)
            || !(1..=8192).contains(&signed)
            || bytes.len() != 436 + metadata + signed
            || bytes.get(401..404) != Some(&[0; 3])
        {
            return Err("complete request fields".into());
        }
        let proposal = p::AnchorPendingWriteRecoveryProposal::from_trusted_state(
            bytes.get(8..401).ok_or("proposal")?,
        )?;
        assert_eq!(bytes.get(404..436).ok_or("binding")?, proposal.binding());
        Ok(Self {
            proposal,
            metadata: bytes.get(436..436 + metadata).ok_or("metadata")?.to_vec(),
            signed: bytes
                .get(436 + metadata..)
                .ok_or("signed request")?
                .to_vec(),
        })
    }
}

// Independent public-format oracle for this deliberately single-member R1 -> R2
// operation. It uses only the issuer's approved signed materials and verified
// device, never the Android enrollment, signer, wrapping key or journal files.
pub(super) fn roster_metadata(
    root: &p::RootSigningKey,
    family: [u8; 32],
    wire: &[u8],
    checkpoint: p::RosterCheckpoint,
    device: &p::VerifiedDevice,
) -> Result<Vec<u8>> {
    let mut roster = b"QPROWR01".to_vec();
    roster.extend_from_slice(&root.account_id()?);
    roster.extend_from_slice(&family);
    roster.extend_from_slice(&checkpoint.version().to_be_bytes());
    roster.extend_from_slice(&checkpoint.digest());
    roster.extend_from_slice(&root.public_key()?.encode());
    roster.extend_from_slice(&u32::try_from(wire.len())?.to_be_bytes());
    roster.extend_from_slice(wire);
    let mut metadata = b"QPRHST01".to_vec();
    metadata.extend_from_slice(&u32::try_from(roster.len())?.to_be_bytes());
    metadata.extend_from_slice(&roster);
    metadata.extend_from_slice(&1u16.to_be_bytes());
    metadata.extend_from_slice(&device.device_id());
    metadata.extend_from_slice(&device.generation().to_be_bytes());
    metadata.extend_from_slice(&device.credential_digest());
    Ok(metadata)
}

#[derive(Clone, Copy)]
pub(super) struct ExpectedEffect<'a> {
    pub(super) account: [u8; 32],
    pub(super) previous: p::RosterCheckpoint,
    pub(super) target: p::RosterCheckpoint,
    pub(super) before: &'a [u8],
    pub(super) after: &'a [u8],
    pub(super) session: [u8; 32],
    pub(super) message: p::MessageId,
}
impl ExpectedEffect<'_> {
    pub(super) fn check(&self, request: &Request) -> Result<()> {
        let Self {
            account,
            previous,
            target,
            before,
            after,
            session,
            message,
        } = *self;
        let inspected = request.proposal.inspect_metadata(&request.metadata)?;
        let source = inspected.source();
        let destination = inspected.target();
        assert_eq!(source.local_account, destination.local_account);
        assert_eq!(source.next_fanout_ordinal, destination.next_fanout_ordinal);
        assert_eq!(source.records.len(), destination.records.len());
        let mut roster_changes = 0;
        let mut unknown = 0;
        for (a, b) in source.records.iter().zip(&destination.records) {
            let mut expected = a.clone();
            if let p::retired_device::RecordMetadata::Roster {
                account: owner,
                checkpoint,
                public_history,
            } = &mut expected.metadata
            {
                if *owner == account {
                    assert_eq!(*checkpoint, previous);
                    assert_eq!(public_history, before);
                    assert_eq!(expected.context, previous.digest());
                    expected.context = target.digest();
                    *checkpoint = target;
                    *public_history = after.to_vec();
                    roster_changes += 1;
                }
            }
            assert_eq!(
                &expected, b,
                "only the independently approved remote roster may change"
            );
            if let p::retired_device::RecordMetadata::Session(value) = &a.metadata {
                if value.session == session {
                    let p::retired_device::SessionState::Live { epochs, .. } = &value.state else {
                        return Err("original unknown message lost its retained session".into());
                    };
                    unknown += epochs
                        .iter()
                        .flat_map(|e| &e.accounting.unconfirmed)
                        .filter(|m| m.message_id() == message)
                        .count();
                }
            }
        }
        assert_eq!((roster_changes, unknown), (1, 1));
        Ok(())
    }
}
