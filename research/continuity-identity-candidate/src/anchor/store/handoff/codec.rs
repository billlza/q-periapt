// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
const TAG: &[u8; 8] = b"QPAHC001";
const RETIRED_TAG: &[u8; 8] = b"QPAHC002";

pub(super) fn put(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn take<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8], Error> {
    let length = usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| Error::Capacity)?;
    if length > MAX_IMAGE {
        return Err(Error::Capacity);
    }
    d.take(length)
}

fn raw_wrap(content: &[u8], journal: Option<&Journal>) -> Result<Vec<u8>, DurableError> {
    let Some(journal) = journal else {
        return Ok(content.to_vec());
    };
    let mut out = if journal.retired.is_some() {
        RETIRED_TAG
    } else {
        TAG
    }
    .to_vec();
    put(content, &mut out)?;
    out.push(u8::try_from(journal.cancelled.len()).map_err(|_| DurableError::Capacity)?);
    for r in &journal.cancelled {
        put(&r.plan.to_bytes(), &mut out)?;
        put(r.as_bytes(), &mut out)?;
    }
    match &journal.frozen {
        None => out.push(0),
        Some(r) => {
            out.push(1);
            put(&r.plan.to_bytes(), &mut out)?;
            put(r.as_bytes(), &mut out)?;
        }
    }
    if let Some(retired) = &journal.retired {
        put(&retired.approval.to_bytes(), &mut out)?;
        put(&retired.acknowledgement, &mut out)?;
        put(retired.receipt.as_bytes(), &mut out)?;
    }
    if out.len().checked_add(32).ok_or(DurableError::Capacity)? > MAX_IMAGE {
        return Err(DurableError::Capacity);
    }
    Ok(out)
}

pub(in super::super) fn validate(
    pin: &AnchorPin,
    revision: u64,
    content: &[u8],
    journal: Option<&Journal>,
) -> Result<(), DurableError> {
    let Some(journal) = journal else {
        return Ok(());
    };
    if journal.cancelled.len() > MAX_CANCELLED
        || (journal.cancelled.is_empty() && journal.frozen.is_none())
        || (journal.cancelled.len() == MAX_CANCELLED && journal.frozen.is_some())
        || (journal.retired.is_some() && journal.frozen.is_none())
    {
        return Err(DurableError::Corrupt);
    }
    let mut ids = std::collections::BTreeSet::new();
    for r in journal.cancelled.iter().chain(journal.frozen.iter()) {
        if r.plan.source.binding != pin.binding
            || r.plan.revision > revision
            || !ids.insert(r.plan.operation)
        {
            return Err(DurableError::Corrupt);
        }
        let verified = r.plan.verify_receipt(r.as_bytes())?;
        if verified.state != r.state {
            return Err(DurableError::Corrupt);
        }
    }
    if journal
        .cancelled
        .iter()
        .any(|r| r.state != AnchorHandoffState::Cancelled)
    {
        return Err(DurableError::Corrupt);
    }
    if let Some(r) = &journal.frozen {
        if r.state != AnchorHandoffState::Frozen || r.plan.revision != revision {
            return Err(DurableError::Corrupt);
        }
        let prior = Journal {
            cancelled: journal.cancelled.clone(),
            frozen: None,
            retired: None,
        };
        let prior = if prior.cancelled.is_empty() {
            None
        } else {
            Some(&prior)
        };
        if source_commitment(&raw_wrap(content, prior)?) != r.plan.commitment {
            return Err(DurableError::Corrupt);
        }
        if let Some(retired) = &journal.retired {
            retired.verify(r)?;
        }
    }
    Ok(())
}

pub(in super::super) fn wrap(
    pin: &AnchorPin,
    revision: u64,
    content: &[u8],
    journal: Option<&Journal>,
) -> Result<Vec<u8>, DurableError> {
    validate(pin, revision, content, journal)?;
    raw_wrap(content, journal)
}

// Called only after the outer image's MAC has been verified. No nested wrapper
// is accepted and no unauthenticated record selects its own authority pin.
pub(in super::super) fn unwrap<'a>(
    pin: &AnchorPin,
    bytes: &'a [u8],
) -> Result<(&'a [u8], Option<Journal>), DurableError> {
    if !bytes.starts_with(TAG) && !bytes.starts_with(RETIRED_TAG) {
        return Ok((bytes, None));
    }
    let mut d = Decoder::new(bytes);
    let tag = d.array::<8>()?;
    if tag != *TAG && tag != *RETIRED_TAG {
        return Err(DurableError::Corrupt);
    }
    let content = take(&mut d)?;
    if content.starts_with(TAG) || content.starts_with(RETIRED_TAG) {
        return Err(DurableError::Corrupt);
    }
    let [count] = d.array()?;
    if usize::from(count) > MAX_CANCELLED {
        return Err(DurableError::Capacity);
    }
    let read = |d: &mut Decoder<'_>| -> Result<AnchorHandoffReceipt, DurableError> {
        let plan = AnchorHandoffPlan::restore_trusted_state(take(d)?)?;
        if plan.source.binding != pin.binding {
            return Err(DurableError::Corrupt);
        }
        Ok(plan.verify_receipt(take(d)?)?)
    };
    let mut cancelled = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        cancelled.push(read(&mut d)?);
    }
    let frozen = match d.array::<1>()? {
        [0] => None,
        [1] => Some(read(&mut d)?),
        _ => return Err(DurableError::Corrupt),
    };
    let retired = if tag == *RETIRED_TAG {
        let freeze = frozen.as_ref().ok_or(DurableError::Corrupt)?;
        let approval = AnchorHandoffTargetApproval::restore_trusted_state(
            take(&mut d)?,
            &freeze.plan.source,
            &freeze.plan.target,
        )?;
        let acknowledgement = take(&mut d)?.to_vec();
        let receipt = approval.verify_retirement_receipt(
            freeze.as_bytes(),
            &acknowledgement,
            take(&mut d)?,
        )?;
        Some(retirement::Retirement {
            approval,
            acknowledgement,
            receipt,
        })
    } else {
        None
    };
    d.finish()?;
    Ok((
        content,
        Some(Journal {
            cancelled,
            frozen,
            retired,
        }),
    ))
}
