// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Decode only after the original registry MAC and path binding are checked.
use super::*;
use crate::{codec::Decoder, AnchorIdentity, PUBLIC_KEY_BYTES};
pub(in crate::account_authority) const MAX_HISTORY: usize =
    AnchorHandoffHistory::MAX_BYTES + 2 * (32 + PUBLIC_KEY_BYTES) + 32 + 4;
pub(in crate::account_authority) const MAX_RECORD: usize = 1
    + 33
    + 32
    + 16
    + Plan::MAX_BYTES
    + AnchorFrozenAccount::MAX_RETAINED_BYTES
    + Approval::MAX_BYTES
    + AnchorTransferredAccountDecision::WIRE_BYTES;

fn put(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}
fn take<'a>(d: &mut Decoder<'a>, max: usize) -> Result<&'a [u8], DurableError> {
    let size =
        usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
    if size > max {
        return Err(DurableError::Corrupt);
    }
    Ok(d.take(size)?)
}
pub(in crate::account_authority) fn encode_history(
    history: &AnchorHandoffHistory,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    for pin in [
        history.historical_pin(history.namespace_binding())?,
        history.current_pin(),
    ] {
        out.extend_from_slice(pin.identity().as_bytes());
        out.extend_from_slice(&pin.public_key().encode());
    }
    out.extend_from_slice(&history.checkpoint());
    put(&history.to_bytes()?, out)
}
pub(in crate::account_authority) fn decode_history(
    d: &mut Decoder<'_>,
) -> Result<AnchorHandoffHistory, DurableError> {
    let mut pin = || {
        Ok::<_, DurableError>(AnchorPin::new(
            AnchorIdentity::from_trusted_state(d.array()?)?,
            PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?,
        ))
    };
    let origin = pin()?;
    let current = pin()?;
    let checkpoint = d.array()?;
    AnchorHandoffHistory::restore_trusted_state(
        take(d, AnchorHandoffHistory::MAX_BYTES)?,
        &origin,
        &current,
        checkpoint,
    )
}
pub(in crate::account_authority) fn encode(
    record: Option<&Record>,
    out: &mut Vec<u8>,
    managed: bool,
) -> Result<(), DurableError> {
    let Some(record) = record else {
        out.push(0);
        return Ok(());
    };
    out.push(1);
    out.extend_from_slice(&record.logical);
    put(&record.plan.to_bytes()?, out)?;
    put(
        &record
            .frozen
            .as_ref()
            .map(AnchorFrozenAccount::transferred_record)
            .transpose()?
            .unwrap_or_default(),
        out,
    )?;
    put(
        &record
            .approval
            .as_ref()
            .map(Approval::to_bytes)
            .transpose()?
            .unwrap_or_default(),
        out,
    )?;
    put(record.receipt.as_deref().unwrap_or(&[]), out)?;
    if managed {
        match record.managed {
            None => out.push(0),
            Some(checkpoint) => {
                out.push(1);
                out.extend_from_slice(&checkpoint);
            }
        }
    } else if record.managed.is_some() {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}
pub(in crate::account_authority) fn decode(
    d: &mut Decoder<'_>,
    history: &AnchorHandoffHistory,
    managed: bool,
) -> Result<Option<Box<Record>>, DurableError> {
    match d.array::<1>()? {
        [0] => return Ok(None),
        [1] => {}
        _ => return Err(DurableError::Corrupt),
    }
    let logical = d.array()?;
    crate::codec::nonzero(&logical)?;
    let plan = Plan::restore_authenticated_record(take(d, Plan::MAX_BYTES)?, history)?;
    let bytes = take(d, AnchorFrozenAccount::MAX_RETAINED_BYTES)?;
    let frozen = if bytes.is_empty() {
        None
    } else {
        Some(AnchorFrozenAccount::restore_transferred_record(
            bytes, history,
        )?)
    };
    let bytes = take(d, Approval::MAX_BYTES)?;
    let approval = if bytes.is_empty() {
        None
    } else {
        Some(Approval::restore_authenticated_record(bytes, history)?)
    };
    let bytes = take(d, AnchorTransferredAccountDecision::WIRE_BYTES)?;
    let receipt = if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    };
    let managed = if managed {
        match d.array::<1>()? {
            [0] => None,
            [1] => Some(d.array()?),
            _ => return Err(DurableError::Corrupt),
        }
    } else {
        None
    };
    Ok(Some(Box::new(Record {
        logical,
        plan,
        frozen,
        approval,
        receipt,
        managed,
    })))
}
