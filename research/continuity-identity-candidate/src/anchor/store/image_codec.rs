// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete witness image codec; decoding authenticates before interpreting state.
//!
//! Keep all historical layouts, cross-record validation and capacity checks here.
//! Transaction ownership and compare-and-commit remain in the parent store.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct EntryFormat {
    joint: bool,
    policy: bool,
    independent: bool,
    roster: bool,
    lineage: bool,
}
impl EntryFormat {
    pub(super) const COMPLETE: Self = Self {
        joint: true,
        policy: true,
        independent: true,
        roster: true,
        lineage: true,
    };
}
pub(super) fn encode_entry(
    entry: &Entry,
    pin: &impl ImageAuthority,
    format: EntryFormat,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    entry.check_renewal_state(pin)?;
    if let Some(identity) = &entry.original_identity {
        identity.check(entry)?;
    }
    entry.subject.encode(out);
    out.extend_from_slice(&entry.device.encode());
    out.extend_from_slice(&entry.credential_owner);
    out.extend_from_slice(&entry.authority);
    entry.validity.encode(out);
    out.extend_from_slice(&entry.genesis);
    entry.head.encode(out);
    encode_last(entry.last, out);
    if format.joint {
        out.extend_from_slice(&entry.renewal_floor.to_be_bytes());
        out.push(u8::from(entry.renewal_ack.is_some()));
        out.extend_from_slice(&entry.renewal_ack.unwrap_or([0; 32]));
        if let Some(record) = &entry.renewal {
            record.encode(out);
        } else {
            out.push(0);
        }
    }
    if format.policy {
        out.extend_from_slice(&entry.policy_floor.to_be_bytes());
        match (entry.credential_authorization, entry.policy_authorization) {
            (None, None) => out.push(0),
            (Some(credential), Some(policy)) => {
                out.push(1);
                out.extend_from_slice(&credential);
                policy.encode(out);
            }
            _ => return Err(DurableError::Corrupt),
        }
    }
    if format.independent {
        match &entry.independent_policy {
            None => out.push(0),
            Some(state) => {
                out.push(1);
                state.encode(out);
            }
        }
    }
    if format.roster {
        match &entry.independent_roster {
            None => out.push(0),
            Some(state) => {
                out.push(1);
                state.encode(out);
            }
        }
    }
    if format.lineage {
        match &entry.original_identity {
            None => out.push(0),
            Some(identity) => {
                out.push(1);
                identity.encode(out);
            }
        }
    }
    Ok(())
}

pub(super) fn encode(
    key: &JournalKey,
    pin: &AnchorPin,
    image: &Image,
) -> Result<Vec<u8>, DurableError> {
    let mut bytes = encode_body(pin, image)?;
    let mut auth = authenticator(key)?;
    auth.update(&bytes);
    bytes.extend_from_slice(&auth.finalize().into_bytes());
    Ok(bytes)
}

// The same complete canonical state feeds local storage authentication and a
// prospective handoff commitment. This body has no authenticity on its own.
pub(super) fn encode_body(pin: &AnchorPin, image: &Image) -> Result<Vec<u8>, DurableError> {
    let content = encode_content(pin, image)?;
    if image.handoff.is_none() {
        return Ok(content);
    }
    handoff::wrap(pin, image.revision, &content, image.handoff.as_ref())
}

pub(super) fn encode_content(
    pin: &impl ImageAuthority,
    image: &Image,
) -> Result<Vec<u8>, DurableError> {
    if image.entries.len() > MAX_ENTRIES {
        return Err(DurableError::Capacity);
    }
    image.check_witness_key(&pin.current().key)?;
    image.check_replacements(pin)?;
    image.check_retired_cleanup(pin)?;
    image.check_retired_reports(pin)?;
    image.check_account_replacements(pin)?;
    image.check_account_freezes(pin)?;
    image.check_account_closures()?;
    let credential_policy_format = image
        .entries
        .values()
        .any(Entry::has_credential_policy_composition);
    let policy_credential_format = image.entries.values().any(|e| {
        e.independent_policy
            .as_ref()
            .is_some_and(|p| p.credential_after)
    });
    let roster_credential_format = image
        .entries
        .values()
        .any(Entry::has_roster_credential_composition);
    let closure_format =
        roster_credential_format || credential_policy_format || !image.account_closures.is_empty();
    let freeze_format = closure_format || !image.account_freezes.is_empty();
    let account_format = freeze_format || !image.account_replacements.is_empty();
    let acknowledged_report_format = image.retired_reports.values().any(|r| r.acknowledged);
    let report_format = account_format || !image.retired_reports.is_empty();
    let cleanup_format = report_format || !image.retired_cleanup.is_empty();
    let replacement_format = cleanup_format || !image.replacements.is_empty();
    let lineage_format = replacement_format
        || image
            .entries
            .values()
            .any(|entry| entry.original_identity.is_some());
    let roster_format = lineage_format
        || image
            .entries
            .values()
            .any(|entry| entry.independent_roster.is_some());
    let independent = roster_format
        || image
            .entries
            .values()
            .any(|entry| entry.independent_policy.is_some());
    let joint = image
        .entries
        .values()
        .any(|entry| entry.renewal_floor != 0 || entry.renewal.is_some());
    let cancellation = image.entries.values().any(|entry| {
        entry
            .renewal
            .as_ref()
            .is_some_and(CredentialRenewalRecord::is_cancellation)
    });
    let policy_format = image.entries.values().any(|entry| {
        entry.policy_floor != 0
            || entry.policy_authorization.is_some()
            || entry.credential_authorization.is_some()
            || entry
                .renewal
                .as_ref()
                .is_some_and(CredentialRenewalRecord::has_policy)
    });
    let policy_cancellation = image.entries.values().any(|e| {
        e.renewal
            .as_ref()
            .is_some_and(CredentialRenewalRecord::is_policy_cancellation)
    });
    let mut bytes = if roster_credential_format {
        b"QPANC020".to_vec()
    } else if policy_credential_format {
        b"QPANC019".to_vec()
    } else if credential_policy_format {
        b"QPANC018".to_vec()
    } else if closure_format {
        b"QPANC017".to_vec()
    } else if freeze_format {
        b"QPANC016".to_vec()
    } else if account_format {
        b"QPANC015".to_vec()
    } else if acknowledged_report_format {
        b"QPANC014".to_vec()
    } else if report_format {
        b"QPANC013".to_vec()
    } else if cleanup_format {
        b"QPANC012".to_vec()
    } else if replacement_format {
        b"QPANC011".to_vec()
    } else if lineage_format {
        b"QPANC010".to_vec()
    } else if roster_format {
        b"QPANC009".to_vec()
    } else if independent {
        b"QPANC008".to_vec()
    } else if policy_cancellation {
        b"QPANC007".to_vec()
    } else if policy_format {
        b"QPANC006".to_vec()
    } else if cancellation {
        b"QPANC004".to_vec()
    } else if joint {
        b"QPANC003".to_vec()
    } else {
        b"QPANC002".to_vec()
    };
    bytes.extend_from_slice(&pin.namespace());
    bytes.extend_from_slice(&image.revision.to_be_bytes());
    bytes.extend_from_slice(&(image.entries.len() as u16).to_be_bytes());
    for (id, entry) in &image.entries {
        if *id != entry.subject.id(&pin.namespace()) {
            return Err(DurableError::Corrupt);
        }
        bytes.extend_from_slice(id);
        encode_entry(
            entry,
            pin,
            EntryFormat {
                joint: joint || policy_format || independent,
                policy: policy_format || independent,
                independent,
                roster: roster_format,
                lineage: lineage_format,
            },
            &mut bytes,
        )?;
    }
    if replacement_format {
        bytes.extend_from_slice(
            &u16::try_from(image.replacements.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        for (binding, proposal) in &image.replacements {
            bytes.extend_from_slice(binding);
            let encoded = proposal.to_bytes()?;
            bytes.extend_from_slice(
                &u32::try_from(encoded.len())
                    .map_err(|_| DurableError::Capacity)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&encoded);
        }
    }
    if cleanup_format {
        retired_cleanup::encode_records(&image.retired_cleanup, &mut bytes)?;
    }
    if report_format {
        retired_report::encode_records(&image.retired_reports, &mut bytes)?;
    }
    if account_format {
        account_replacement::encode_records(&image.account_replacements, &mut bytes)?;
    }
    if freeze_format {
        account_replacement::freeze::encode_records(&image.account_freezes, &mut bytes)?;
    }
    if closure_format {
        account_replacement::closure::encode_records(&image.account_closures, &mut bytes)?;
    }
    if bytes.len() + 32 > MAX_IMAGE {
        return Err(DurableError::Capacity);
    }
    Ok(bytes)
}
pub(super) fn decode(
    key: &JournalKey,
    pin: &AnchorPin,
    bytes: &[u8],
) -> Result<Image, DurableError> {
    let result = (|| {
        if !(82..=MAX_IMAGE).contains(&bytes.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = bytes.split_at(bytes.len() - 32);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let (body, handoff) = handoff::unwrap(pin, body)?;
        let mut image = decode_content(pin, body)?;
        image.digest = image_digest(bytes);
        image.handoff = handoff;
        if image.handoff.is_some() {
            let content = encode_content(pin, &image)?;
            handoff::validate(pin, image.revision, &content, image.handoff.as_ref())?;
        }
        Ok(image)
    })();
    match result {
        Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
        other => other,
    }
}

// Caller must first authenticate the enclosing image or exact signed source
// commitment. This parser selects no authority from untrusted record bytes.
pub(super) fn decode_content(
    pin: &impl ImageAuthority,
    body: &[u8],
) -> Result<Image, DurableError> {
    let result = (|| {
        if !(50..=MAX_IMAGE - 32).contains(&body.len()) {
            return Err(DurableError::Corrupt);
        }
        let mut d = Decoder::new(body);
        let version = ImageVersion::decode(d.array()?)?;
        if d.array::<32>()? != pin.namespace() {
            return Err(DurableError::Conflict);
        }
        let revision = d.u64()?;
        generation(revision)?;
        let count = usize::from(d.u16()?);
        if count > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        let mut entries = BTreeMap::new();
        let mut previous = None;
        let mut owners = std::collections::BTreeSet::new();
        for _ in 0..count {
            let id = d.array()?;
            if previous.is_some_and(|previous| previous >= id) {
                return Err(DurableError::Corrupt);
            }
            previous = Some(id);
            let subject = AnchorSubject::decode(&mut d)?;
            let device = PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?;
            let credential_owner = if version >= ImageVersion::V2 {
                let owner = d.array()?;
                nonzero(&owner)?;
                owner
            } else {
                subject.owner
            };
            let authority = d.array()?;
            nonzero(&authority)?;
            let validity = Validity::decode(&mut d)?;
            let genesis = d.array()?;
            nonzero(&genesis)?;
            let head = AnchorHead::decode(&mut d)?;
            let last = decode_last(&mut d, head)?;
            let (renewal_floor, renewal_ack, renewal) = if version >= ImageVersion::V3 {
                let floor = d.u64()?;
                let [present] = d.array()?;
                let binding = d.array()?;
                let ack = match present {
                    0 if binding == [0; 32] => None,
                    1 => {
                        nonzero(&binding)?;
                        Some(binding)
                    }
                    _ => return Err(DurableError::Corrupt),
                };
                (
                    floor,
                    ack,
                    CredentialRenewalRecord::decode(
                        &mut d,
                        version >= ImageVersion::V4,
                        version >= ImageVersion::V6,
                        version >= ImageVersion::V7,
                    )?,
                )
            } else {
                (0, None, None)
            };
            let (policy_floor, credential_authorization, policy_authorization) =
                if version >= ImageVersion::V6 {
                    let floor = d.u64()?;
                    let (credential, policy) = match d.array::<1>()? {
                        [0] => (None, None),
                        [1] => {
                            let credential = d.array()?;
                            nonzero(&credential)?;
                            (Some(credential), Some(PolicyAuthority::decode(&mut d)?))
                        }
                        _ => return Err(DurableError::Corrupt),
                    };
                    (floor, credential, policy)
                } else {
                    (0, None, None)
                };
            let independent_policy = if version >= ImageVersion::V8 {
                match d.array::<1>()? {
                    [0] => None,
                    [1] => Some(PolicyRenewal::decode(&mut d, version >= ImageVersion::V19)?),
                    _ => return Err(DurableError::Corrupt),
                }
            } else {
                None
            };
            let independent_roster = if version >= ImageVersion::V9 {
                match d.array::<1>()? {
                    [0] => None,
                    [1] => Some(RosterRefresh::decode(&mut d)?),
                    _ => return Err(DurableError::Corrupt),
                }
            } else {
                None
            };
            let original_identity = if version >= ImageVersion::V10 {
                match d.array::<1>()? {
                    [0] => None,
                    [1] => Some(OriginalIdentity::decode(&mut d)?),
                    _ => return Err(DurableError::Corrupt),
                }
            } else {
                None
            };
            if id != subject.id(&pin.namespace())
                || device.shares_component(&pin.current().key)
                || !owners.insert(subject.owner)
                || (last.is_none() && head.digest != genesis)
            {
                return Err(DurableError::Corrupt);
            }
            let entry = Entry {
                subject,
                original_identity,
                device,
                credential_owner,
                authority,
                validity,
                genesis,
                head,
                last,
                renewal_floor,
                renewal_ack,
                renewal,
                credential_authorization,
                policy_authorization,
                policy_floor,
                independent_policy,
                independent_roster,
            };
            if version < ImageVersion::V18 && entry.has_credential_policy_composition() {
                return Err(DurableError::Conflict);
            }
            if version < ImageVersion::V20 && entry.has_roster_credential_composition() {
                return Err(DurableError::Conflict);
            }
            entry.check_renewal_state(pin)?;
            if let Some(identity) = &entry.original_identity {
                identity.check(&entry)?;
            }
            entries.insert(id, entry);
        }
        let replacements = if version >= ImageVersion::V11 {
            replacement::decode_decisions(&mut d, version >= ImageVersion::V15)?
        } else {
            BTreeMap::new()
        };
        let retired_cleanup = if version >= ImageVersion::V12 {
            retired_cleanup::decode_records(&mut d, pin, version >= ImageVersion::V15)?
        } else {
            BTreeMap::new()
        };
        let retired_reports = if version >= ImageVersion::V13 {
            retired_report::decode_records(
                &mut d,
                pin,
                version >= ImageVersion::V14,
                version >= ImageVersion::V15,
            )?
        } else {
            BTreeMap::new()
        };
        let account_replacements = if version >= ImageVersion::V15 {
            account_replacement::decode_records(&mut d, version >= ImageVersion::V16)?
        } else {
            BTreeMap::new()
        };
        let account_freezes = if version >= ImageVersion::V16 {
            account_replacement::freeze::decode_records(&mut d, version >= ImageVersion::V17)?
        } else {
            BTreeMap::new()
        };
        let account_closures = if version >= ImageVersion::V17 {
            account_replacement::closure::decode_records(&mut d, version >= ImageVersion::V18)?
        } else {
            BTreeMap::new()
        };
        d.finish()?;
        if version >= ImageVersion::V10
            && version < ImageVersion::V16
            && !entries
                .values()
                .any(|entry| entry.original_identity.is_some())
        {
            return Err(DurableError::Corrupt);
        }
        let image = Image {
            revision,
            digest: [0; 32],
            entries,
            replacements,
            retired_cleanup,
            retired_reports,
            account_replacements,
            account_freezes,
            account_closures,
            handoff: None,
        };
        image.check_witness_key(&pin.current().key)?;
        image.check_replacements(pin)?;
        image.check_retired_cleanup(pin)?;
        image.check_retired_reports(pin)?;
        image.check_account_replacements(pin)?;
        image.check_account_freezes(pin)?;
        image.check_account_closures()?;
        if version == ImageVersion::V14 && !image.retired_reports.values().any(|r| r.acknowledged) {
            return Err(DurableError::Corrupt);
        }
        if (ImageVersion::V11..=ImageVersion::V14).contains(&version)
            && image.replacements.is_empty()
        {
            return Err(DurableError::Corrupt);
        }
        Ok(image)
    })();
    match result {
        Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
        other => other,
    }
}
