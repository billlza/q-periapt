// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
pub(crate) fn encode_history(history: &[Transfer], out: &mut Vec<u8>) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u16::try_from(history.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for r in history {
        out.extend_from_slice(r.operation.as_bytes());
        out.extend_from_slice(&r.previous);
        out.extend_from_slice(&r.next);
        out.push(r.kind);
        out.extend_from_slice(&r.closure);
    }
    Ok(())
}
pub(crate) fn decode_history(d: &mut Decoder<'_>) -> Result<Vec<Transfer>, DurableError> {
    let count = usize::from(d.u16()?);
    if count == 0 || count > MAX_TRANSFERS {
        return Err(DurableError::Corrupt);
    }
    let mut history = Vec::with_capacity(count);
    for _ in 0..count {
        let operation = AnchorAccountReplacementId::from_trusted_state(d.array()?)?;
        let previous = d.array()?;
        let next = d.array()?;
        let [kind] = d.array()?;
        let closure = d.array()?;
        history.push(Transfer {
            operation,
            previous,
            next,
            kind,
            closure,
        });
    }
    Ok(history)
}
