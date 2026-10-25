// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
const DOMAIN: &[u8] = b"Q-PERIAPT-ANCHOR-SOURCE-CONTROL-MAC/v1";

pub(super) fn seal(key: &JournalKey, body: &[u8]) -> Result<Vec<u8>, DurableError> {
    if body.len().checked_add(32).ok_or(DurableError::Capacity)? > MAX_CONTROL_IMAGE {
        return Err(DurableError::Capacity);
    }
    let mut bytes = body.to_vec();
    let mut mac = authenticator(key)?;
    mac.update(DOMAIN);
    mac.update(body);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(bytes)
}
pub(super) fn authenticate<'a>(
    key: &JournalKey,
    bytes: &'a [u8],
) -> Result<&'a [u8], DurableError> {
    if !(40..=MAX_CONTROL_IMAGE).contains(&bytes.len()) {
        return Err(DurableError::Corrupt);
    }
    let (body, tag) = bytes.split_at(bytes.len().checked_sub(32).ok_or(DurableError::Corrupt)?);
    let mut mac = authenticator(key)?;
    mac.update(DOMAIN);
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| DurableError::Authentication)?;
    Ok(body)
}
