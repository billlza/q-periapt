// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test-only pre-change journal plaintext reference from d71c6fc126fa78b56ab1073a574b13e7a99168e1.
use super::*;

pub(in crate::durable) fn check(image: &Image, plaintext: &[u8]) {
    assert!(
        plaintext == legacy(image).expect("legacy image encoding").as_slice(),
        "journal plaintext bytes changed"
    );
}

fn legacy(image: &Image) -> Result<Zeroizing<Vec<u8>>, DurableError> {
    let publication = image
        .records
        .values()
        .any(|r| r.kind == RecordKind::Publication);
    let (_, inner_tag) = image_tags(publication, image.account_authority.is_some());
    let mut plaintext = Zeroizing::new(inner_tag.to_vec());
    image.protection.encode(&mut plaintext);
    if let Some(scope) = image.account_authority {
        scope.encode(&mut plaintext);
    }
    plaintext.extend_from_slice(&image.local_account);
    plaintext.extend_from_slice(&image.next_fanout.to_be_bytes());
    plaintext.extend_from_slice(&(image.records.len() as u16).to_be_bytes());
    for (id, record) in &image.records {
        plaintext.extend_from_slice(id);
        plaintext.extend_from_slice(&record.context);
        plaintext.push(record.kind as u8);
        plaintext.push(record.phase as u8);
        plaintext.push(record.authorities.len() as u8);
        for account in &record.authorities {
            plaintext.extend_from_slice(account);
        }
        plaintext.push(record.keys.len() as u8);
        for key in &record.keys {
            plaintext.extend_from_slice(key);
        }
        plaintext.push(record.prekeys.len() as u8);
        for key in &record.prekeys {
            plaintext.extend_from_slice(key);
        }
        if matches!(record.kind, RecordKind::Initiator | RecordKind::Responder) {
            cancellation::encode(&record.cancellation, &mut plaintext);
        } else if record.cancellation.is_some() {
            return Err(DurableError::Corrupt);
        }
        plaintext.extend_from_slice(&(record.payload.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&record.payload);
    }
    Ok(plaintext)
}

#[test]
#[should_panic(expected = "journal plaintext bytes changed")]
fn legacy_image_oracle_rejects_an_altered_encoding() {
    let fixture = fixture(PrekeyQuality::OneTimeBoth);
    let directory = directory();
    let path = directory.path().canonicalize().expect("original directory");
    let mut journal = new_store(&path, fixture.initiator_device());
    let image = journal.image().expect("image");
    let mut encoded = legacy(&image).expect("image encoding");
    *encoded.first_mut().expect("tag byte") ^= 1;
    check(&image, &encoded);
}
