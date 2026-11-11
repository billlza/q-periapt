// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded test-pipe export of the actual local application resolution API.
use q_periapt_continuity_identity_candidate::{
    BootstrapContext, ClosedEpochResolution, DeviceJournal, DurableError, EpochResolutionId,
    EpochResolutionStatus, Error, MessageId,
};

type Result<T> = std::result::Result<T, DurableError>;

fn encoding() -> DurableError {
    DurableError::Protocol(Error::Encoding)
}

fn put(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|n| n > 32767)
    {
        return Err(Error::Capacity.into());
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn count(output: &mut Vec<u8>, value: usize) -> Result<()> {
    put(
        output,
        &u16::try_from(value).map_err(|_| encoding())?.to_be_bytes(),
    )
}

fn report(value: ClosedEpochResolution) -> Result<Vec<u8>> {
    let mut output = value.resolution_id().as_bytes().to_vec();
    for count in [
        value.epoch(),
        value.acknowledged_before(),
        value.sent_count(),
        value.consumed_before(),
        value.observed_receive_count(),
        value.peer_sent_count(),
    ] {
        put(&mut output, &count.to_be_bytes())?;
    }
    count(&mut output, value.unconfirmed_messages().len())?;
    for row in value.unconfirmed_messages() {
        put(&mut output, row.message_id().as_bytes())?;
        put(&mut output, row.ciphertext_digest())?;
    }
    count(&mut output, value.unconsumed_deliveries().len())?;
    for row in value.unconsumed_deliveries() {
        put(&mut output, row.message_id().as_bytes())?;
        put(&mut output, &row.index().to_be_bytes())?;
        put(
            &mut output,
            &u32::try_from(row.as_bytes().len())
                .map_err(|_| encoding())?
                .to_be_bytes(),
        )?;
        put(&mut output, row.as_bytes())?;
    }
    count(&mut output, value.skipped_indices().len())?;
    for index in value.skipped_indices() {
        put(&mut output, &index.to_be_bytes())?;
    }
    Ok(output)
}

pub(super) fn command(
    owner: &mut DeviceJournal,
    context: &BootstrapContext,
    session: [u8; 32],
    command: u8,
    payload: &[u8],
    now: u64,
) -> Result<Vec<u8>> {
    if command == 27 {
        let id = MessageId::from_trusted_state(payload.try_into().map_err(|_| encoding())?)?;
        return Ok(format!("{:?}", owner.message_status(context, session, id)?).into_bytes());
    }
    let epoch = u64::from_be_bytes(
        payload
            .get(..8)
            .ok_or_else(encoding)?
            .try_into()
            .map_err(|_| encoding())?,
    );
    match command {
        24 if payload.len() == 8 => {
            report(owner.begin_closed_epoch_resolution(context, session, epoch, now)?)
        }
        25 if payload.len() == 40 => {
            let id = EpochResolutionId::from_trusted_state(
                payload[8..].try_into().map_err(|_| encoding())?,
            )?;
            owner.acknowledge_closed_epoch_resolution(context, session, epoch, id, now)?;
            Ok(id.as_bytes().to_vec())
        }
        26 if payload.len() == 8 => Ok(
            match owner.closed_epoch_resolution_status(context, session, epoch)? {
                EpochResolutionStatus::Unrequested => vec![0],
                EpochResolutionStatus::Pending(id) => [vec![1], id.as_bytes().to_vec()].concat(),
                EpochResolutionStatus::Acknowledged(id) => {
                    [vec![2], id.as_bytes().to_vec()].concat()
                }
            },
        ),
        _ => Err(encoding()),
    }
}
