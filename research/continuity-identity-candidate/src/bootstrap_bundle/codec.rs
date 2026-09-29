// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::codec::Decoder;
const TAG: &[u8; 8] = b"QPBNDL01";
const MAX_PART: usize = 8192;

fn modes(quality: PrekeyQuality) -> (bool, bool) {
    match quality {
        PrekeyQuality::OneTimeBoth => (true, true),
        PrekeyQuality::ReusableBoth => (false, false),
        PrekeyQuality::SignedClassicalOneTimePq => (false, true),
        PrekeyQuality::OneTimeClassicalLastResortPq => (true, false),
    }
}
fn part<'a>(d: &mut Decoder<'a>, required: bool) -> Result<&'a [u8], Error> {
    let size = usize::from(d.u16()?);
    if size > MAX_PART {
        return Err(Error::Capacity);
    }
    if required && size == 0 {
        return Err(Error::Encoding);
    }
    d.take(size)
}
fn optional(bytes: &[u8], required: bool) -> Result<Option<&[u8]>, Error> {
    match (required, bytes.is_empty()) {
        (true, false) => Ok(Some(bytes)),
        (false, true) => Ok(None),
        _ => Err(Error::Encoding),
    }
}
pub(super) fn decode(wire: &[u8]) -> Result<(PrekeyQuality, BootstrapMaterials<'_>), Error> {
    if wire.len() > MAX_BOOTSTRAP_BUNDLE_BYTES {
        return Err(Error::Capacity);
    }
    let mut d = Decoder::new(wire);
    if d.array::<8>()? != *TAG {
        return Err(Error::Encoding);
    }
    let quality = match d.array::<1>()? {
        [1] => PrekeyQuality::OneTimeBoth,
        [2] => PrekeyQuality::ReusableBoth,
        [3] => PrekeyQuality::SignedClassicalOneTimePq,
        [4] => PrekeyQuality::OneTimeClassicalLastResortPq,
        _ => return Err(Error::Encoding),
    };
    let (classical, pq) = modes(quality);
    let materials = BootstrapMaterials {
        initiator_credential: part(&mut d, true)?,
        initiator_roster: part(&mut d, true)?,
        responder_credential: part(&mut d, true)?,
        responder_roster: part(&mut d, true)?,
        responder_manifest: part(&mut d, true)?,
        signed_classical: part(&mut d, true)?,
        last_resort_pq: part(&mut d, true)?,
        one_time_classical: optional(part(&mut d, false)?, classical)?,
        one_time_pq: optional(part(&mut d, false)?, pq)?,
    };
    d.finish()?;
    Ok((quality, materials))
}
pub(super) fn encode(
    quality: PrekeyQuality,
    materials: BootstrapMaterials<'_>,
) -> Result<Vec<u8>, Error> {
    let fields = [
        materials.initiator_credential,
        materials.initiator_roster,
        materials.responder_credential,
        materials.responder_roster,
        materials.responder_manifest,
        materials.signed_classical,
        materials.last_resort_pq,
        materials.one_time_classical.unwrap_or(&[]),
        materials.one_time_pq.unwrap_or(&[]),
    ];
    let mut size = TAG.len() + 1;
    for field in fields {
        if field.len() > MAX_PART {
            return Err(Error::Capacity);
        }
        size = size.checked_add(2 + field.len()).ok_or(Error::Capacity)?;
    }
    if size > MAX_BOOTSTRAP_BUNDLE_BYTES {
        return Err(Error::Capacity);
    }
    // Empty optional fields have exactly one canonical representation: absent.
    if materials.one_time_classical.is_some_and(|b| b.is_empty())
        || materials.one_time_pq.is_some_and(|b| b.is_empty())
    {
        return Err(Error::Encoding);
    }
    let mut wire = Vec::with_capacity(size);
    wire.extend_from_slice(TAG);
    wire.push(quality as u8);
    for field in fields {
        wire.extend_from_slice(&(field.len() as u16).to_be_bytes());
        wire.extend_from_slice(field);
    }
    decode(&wire)?;
    Ok(wire)
}
