// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{codec::Decoder, PUBLIC_KEY_BYTES};
use hmac::{Hmac, Mac};
use redb::{ReadableDatabase, ReadableTableMetadata, TableHandle};
use sha2::Sha256;

const TAG: &[u8; 8] = b"QPAAST01";
const PREPARATION_TAG: &[u8; 8] = b"QPAAST02";
const MAX_BYTES: usize = 76
    + MAX_ACCOUNTS * (32 + PUBLIC_KEY_BYTES + 40)
    + MAX_REPLACEMENTS * (32 + 8 + 1 + 4 + 65_536 + 4 + AnchorAccountReplacementPlan::MAX_BYTES);

fn mac(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let derived = key.account_authority_key()?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| Error::Provider.into())
}
pub(super) fn binding(
    path: &Path,
    key: &JournalKey,
    identity: AccountAuthorityIdentity,
    family: [u8; 32],
    witness: [u8; 32],
) -> Result<[u8; 32], DurableError> {
    let path = path.to_str().ok_or(DurableError::PrivateFile)?.as_bytes();
    let mut result = mac(key)?;
    result.update(b"Q-PERIAPT-CONTINUITY-ACCOUNT-AUTHORITY-SCOPE/v1");
    result.update(identity.as_bytes());
    result.update(&family);
    result.update(&witness);
    result.update(
        &u32::try_from(path.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    result.update(path);
    Ok(result.finalize().into_bytes().into())
}
pub(super) fn encode(
    image: &Image,
    key: &JournalKey,
    binding: [u8; 32],
) -> Result<Vec<u8>, DurableError> {
    if image.initial.len() > MAX_ACCOUNTS || image.replacements.len() > MAX_REPLACEMENTS {
        return Err(DurableError::Capacity);
    }
    let preparations = image.replacements.iter().any(|r| r.preparation.is_some());
    let mut wire = if preparations { PREPARATION_TAG } else { TAG }.to_vec();
    wire.extend_from_slice(&binding);
    wire.extend_from_slice(
        &u16::try_from(image.initial.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (application, initial) in &image.initial {
        wire.extend_from_slice(application.as_bytes());
        wire.extend_from_slice(&initial.root.encode());
        wire.extend_from_slice(&initial.roster.version().to_be_bytes());
        wire.extend_from_slice(&initial.roster.digest());
    }
    wire.extend_from_slice(
        &u16::try_from(image.replacements.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for record in &image.replacements {
        let proposal = record.proposal.to_bytes()?;
        wire.extend_from_slice(record.application.as_bytes());
        wire.extend_from_slice(&record.revision.to_be_bytes());
        wire.push(u8::from(record.committed));
        wire.extend_from_slice(
            &u32::try_from(proposal.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(&proposal);
        if preparations {
            let plan = record
                .preparation
                .as_ref()
                .map(AnchorAccountReplacementPlan::to_bytes)
                .transpose()?;
            let bytes = plan.as_deref().unwrap_or(&[]);
            wire.extend_from_slice(
                &u32::try_from(bytes.len())
                    .map_err(|_| DurableError::Capacity)?
                    .to_be_bytes(),
            );
            wire.extend_from_slice(bytes);
        }
    }
    let mut tag = mac(key)?;
    tag.update(b"Q-PERIAPT-CONTINUITY-ACCOUNT-AUTHORITY-IMAGE/v1");
    tag.update(&wire);
    wire.extend_from_slice(&tag.finalize().into_bytes());
    if wire.len() > MAX_BYTES {
        return Err(DurableError::Capacity);
    }
    Ok(wire)
}
pub(super) fn decode(
    wire: &[u8],
    key: &JournalKey,
    binding: [u8; 32],
) -> Result<Image, DurableError> {
    if !(76..=MAX_BYTES).contains(&wire.len()) {
        return Err(DurableError::Corrupt);
    }
    let (body, tag) = wire.split_at(wire.len() - 32);
    let mut expected = mac(key)?;
    expected.update(b"Q-PERIAPT-CONTINUITY-ACCOUNT-AUTHORITY-IMAGE/v1");
    expected.update(body);
    expected
        .verify_slice(tag)
        .map_err(|_| DurableError::Authentication)?;
    let mut d = Decoder::new(body);
    let version = d.array::<8>()?;
    let preparations = match &version {
        tag if tag == TAG => false,
        tag if tag == PREPARATION_TAG => true,
        _ => return Err(DurableError::Conflict),
    };
    if d.array::<32>()? != binding {
        return Err(DurableError::Conflict);
    }
    let count = usize::from(d.u16()?);
    if count > MAX_ACCOUNTS {
        return Err(DurableError::Corrupt);
    }
    let mut initial = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let application = ApplicationAccountId::from_trusted_state(d.array()?)?;
        if previous.is_some_and(|old| old >= application) {
            return Err(DurableError::Corrupt);
        }
        previous = Some(application);
        let root = PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?;
        let roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        initial.insert(application, Initial { root, roster });
    }
    let count = usize::from(d.u16()?);
    if count > MAX_REPLACEMENTS {
        return Err(DurableError::Corrupt);
    }
    let mut replacements = Vec::with_capacity(count);
    for _ in 0..count {
        let application = ApplicationAccountId::from_trusted_state(d.array()?)?;
        let revision = d.u64()?;
        let committed = match d.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err(DurableError::Corrupt),
        };
        let length =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        if length > 65_536 {
            return Err(DurableError::Corrupt);
        }
        let proposal = Proposal::from_trusted_state(d.take(length)?)?;
        let preparation = if preparations {
            let length = usize::try_from(u32::from_be_bytes(d.array()?))
                .map_err(|_| DurableError::Capacity)?;
            if length > AnchorAccountReplacementPlan::MAX_BYTES {
                return Err(DurableError::Corrupt);
            }
            if length == 0 {
                None
            } else {
                Some(AnchorAccountReplacementPlan::from_trusted_state(
                    d.take(length)?,
                )?)
            }
        } else {
            None
        };
        replacements.push(Replacement {
            application,
            revision,
            proposal,
            preparation,
            committed,
        });
    }
    d.finish()?;
    if preparations && replacements.iter().all(|r| r.preparation.is_none()) {
        return Err(DurableError::Corrupt);
    }
    Ok(Image {
        initial,
        replacements,
    })
}
pub(super) fn read(
    db: &Database,
    key: &JournalKey,
    binding: [u8; 32],
) -> Result<Image, DurableError> {
    let transaction = db.begin_read().map_err(storage)?;
    let tables = transaction
        .list_tables()
        .map_err(storage)?
        .collect::<Vec<_>>();
    if tables.len() != 1 || tables.first().is_none_or(|t| t.name() != TABLE.name()) {
        return Err(DurableError::Corrupt);
    }
    if transaction
        .list_multimap_tables()
        .map_err(storage)?
        .next()
        .is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = transaction.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let record = table
        .get("state")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    decode(record.value(), key, binding)
}
pub(super) fn write(db: &Database, wire: &[u8]) -> Result<(), DurableError> {
    let transaction = transaction(db)?;
    transaction
        .open_table(TABLE)
        .map_err(storage)?
        .insert("state", wire)
        .map_err(storage)?;
    transaction.commit().map_err(DurableError::CommitUncertain)
}
