// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    tests::interval, AccountPin, DeviceDescription, DeviceSigningKey, RootSigningKey,
    VerifiedDevice,
};
use std::sync::{Arc, Barrier};

fn roster(version: u64) -> VerifiedRoster {
    let root = RootSigningKey::deterministic([11; 32], [12; 32]).expect("root");
    let signed = root.issue_roster(version, interval(), &[]).expect("roster");
    AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root public key"),
        signed.checkpoint(),
        [77; 32],
    )
    .expect("pin")
    .verify_roster(signed.as_bytes(), 150)
    .expect("verified roster")
}

fn member() -> (RootSigningKey, VerifiedDevice) {
    let root = RootSigningKey::deterministic([21; 32], [22; 32]).expect("root");
    let signer = DeviceSigningKey::deterministic([23; 32], [24; 32]).expect("device signer");
    let description = DeviceDescription::new([25; 16], 1, [77; 32], interval()).expect("device");
    let credential = root
        .issue_device(description, signer.public_key().expect("device key"))
        .expect("credential");
    let signed = root
        .issue_roster(
            1,
            interval(),
            &[root.roster_entry(&credential).expect("member entry")],
        )
        .expect("roster");
    let device = AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("public root"),
        signed.checkpoint(),
        [77; 32],
    )
    .expect("pin")
    .verify_device(&credential, signed.as_bytes(), 150)
    .expect("device chain");
    (root, device)
}

#[test]
fn exact_input_reuses_only_successful_historical_verification() {
    let cache = RosterDecodeCache::default();
    let original = roster(1).journal_bytes();
    assert_eq!(
        cache.decode(&original).expect("first").journal_bytes(),
        original
    );
    assert_eq!(
        cache.decode(&original).expect("retry").journal_bytes(),
        original
    );
    let mut damaged = original.clone();
    *damaged.last_mut().expect("signature byte") ^= 1;
    for _ in 0..2 {
        assert!(matches!(
            cache.decode(&damaged),
            Err(DurableError::InvalidCheckpoint(_))
        ));
    }
    let state = cache.state.lock().expect("cache state");
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.encoded_bytes, original.len());
    drop(state);
    assert_eq!(
        cache
            .decode(&original)
            .expect("still original")
            .journal_bytes(),
        original
    );
}

#[test]
fn complete_pin_metadata_is_part_of_the_cache_input() {
    let cache = RosterDecodeCache::default();
    let (_, device) = member();
    let original = device.roster().journal_bytes();
    let first = cache.decode(&original).expect("original family");
    let mut another_family = original.clone();
    *another_family.get_mut(8 + 32).expect("family byte") ^= 1;
    let other = cache
        .decode(&another_family)
        .expect("historical other-family pin");
    assert!(!first.same_authority(&other));
    assert_eq!(other.journal_bytes(), another_family);
    assert!(first.authorize_device(&device, 150).is_ok());
    assert!(other.authorize_device(&device, 150).is_err());
}

#[test]
fn cached_signature_does_not_cache_time_or_current_membership() {
    let cache = RosterDecodeCache::default();
    let (root, device) = member();
    let original = device.roster().journal_bytes();
    cache
        .decode(&original)
        .expect("warm")
        .authorize_device(&device, 150)
        .expect("member");
    assert!(cache
        .decode(&original)
        .expect("historical after expiry")
        .authorize_device(&device, 250)
        .is_err());
    let issued = root
        .issue_roster(2, interval(), &[])
        .expect("revoked roster");
    let revoked = AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root key"),
        issued.checkpoint(),
        [77; 32],
    )
    .expect("revocation pin")
    .verify_roster(issued.as_bytes(), 150)
    .expect("revocation signature");
    let current = cache.decode(&revoked.journal_bytes()).expect("new head");
    assert_eq!(current.checkpoint(), revoked.checkpoint());
    assert!(current.authorize_device(&device, 150).is_err());
}

#[test]
fn warm_roster_never_bypasses_record_kind_scope_or_metadata() {
    use super::super::{decode_with_cache, id, Stored};
    use crate::durable::{DurableStatus, Record, RecordKind};
    let cache = RosterDecodeCache::default();
    let verified = roster(1);
    let key = id(&verified.account_id());
    let original = Stored::initial(&verified).record().expect("record");
    decode_with_cache(&key, &original, Some(&cache)).expect("warm exact record");
    let mut wrong_key = key;
    *wrong_key.first_mut().expect("key byte") ^= 1;
    assert!(matches!(
        decode_with_cache(&wrong_key, &original, Some(&cache)),
        Err(DurableError::Corrupt)
    ));
    let changes: [fn(&mut Record); 6] = [
        |r| r.kind = RecordKind::Messages,
        |r| r.phase = DurableStatus::Rejected,
        |r| r.authorities.push([1; 32]),
        |r| r.keys.push([2; 32]),
        |r| r.prekeys.push([3; 32]),
        |r| *r.context.first_mut().expect("context byte") ^= 1,
    ];
    for change in changes {
        let mut record = Stored::initial(&verified).record().expect("fresh envelope");
        change(&mut record);
        assert!(matches!(
            decode_with_cache(&key, &record, Some(&cache)),
            Err(DurableError::Corrupt)
        ));
    }
}

#[test]
fn cache_capacity_does_not_change_valid_input_admission() {
    let cache = RosterDecodeCache::default();
    let original = roster(1).journal_bytes();
    cache.decode(&original).expect("warm original encoding");
    for version in 2..=u64::try_from(MAX_ROSTERS + 2).expect("bounded fixture") {
        let verified = roster(version);
        let decoded = cache
            .decode(&verified.journal_bytes())
            .expect("decode even when full");
        assert_eq!(decoded.checkpoint(), verified.checkpoint());
        let state = cache.state.lock().expect("cache state");
        assert!(state.entries.len() <= MAX_ROSTERS);
        assert!(state.encoded_bytes <= MAX_CACHED_ENCODING_BYTES);
    }
    let state = cache.state.lock().expect("cache state");
    assert!(state.entries.len() < MAX_ROSTERS + 1);
    assert!(state.encoded_bytes + original.len() > MAX_CACHED_ENCODING_BYTES);
    drop(state);
    assert_eq!(
        cache
            .decode(&original)
            .expect("original cached input")
            .checkpoint()
            .version(),
        1
    );
}

#[test]
fn concurrent_identical_decodes_do_not_duplicate_cache_entries() {
    let cache = Arc::new(RosterDecodeCache::default());
    let encoded = Arc::new(roster(1).journal_bytes());
    let barrier = Arc::new(Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let encoded = Arc::clone(&encoded);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                assert_eq!(
                    cache
                        .decode(&encoded)
                        .expect("same verified input")
                        .journal_bytes(),
                    *encoded
                );
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("decode worker");
    }
    let state = cache.state.lock().expect("cache state");
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.encoded_bytes, encoded.len());
}
