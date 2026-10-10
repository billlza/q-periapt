// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[test]
fn account_freeze_each_sync_fault_recovers_original_request_once_without_target_enrollment() {
    let mut calibration = required_case();
    let original = freeze_request(&calibration, original_root(&calibration), 180);
    let (_, count) = with_fault_database(&mut calibration, false);
    count.store(0, Ordering::SeqCst);
    calibration
        .store
        .freeze_account(&original)
        .expect("measure actual freeze barriers");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = required_case();
            let original = freeze_request(&c, original_root(&c), 180);
            let before = c.store.image().expect("original image").revision;
            let (remaining, _) = with_fault_database(&mut c, after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(c.store.freeze_account(&original), after);
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            assert!(
                c.store.active.is_none(),
                "uncertain witness owner is consumed"
            );
            c.store = reopen(&c.server);
            let image = c.store.image().expect("original authenticated store");
            assert_eq!(image.entries.len(), 1);
            assert!(image.account_replacements.is_empty());
            assert!(image.revision == before || image.revision == before + 1);
            if image.account_freezes.is_empty() {
                assert!(matches!(
                    c.store.account_freeze(&original),
                    Err(DurableError::Absent)
                ));
            } else {
                assert_retired(&mut c, AnchorOperation::query());
            }
            let frozen = c
                .store
                .freeze_account(&original)
                .expect("reconcile exact original request");
            assert_eq!(frozen.subjects().count(), 1);
            assert_eq!(
                c.store
                    .freeze_account(&original)
                    .expect("idempotent original retry"),
                frozen
            );
            assert_eq!(
                c.store.image().expect("one freeze only").revision,
                before + 1
            );
            assert_retired(&mut c, AnchorOperation::query());
        }
    }
    eprintln!(
        "ANCHOR_ACCOUNT_FREEZE_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}
#[test]
fn account_freeze_authenticated_image_rejects_missing_entries_and_altered_snapshot() {
    let mut c = required_case();
    let original = freeze_request(&c, original_root(&c), 180);
    c.store.freeze_account(&original).expect("freeze");
    let mut image = c.store.image().expect("frozen image");
    let active = c.store.active.as_ref().expect("original store");
    let bytes = encode(&active.wrapping, &active.pin, &image).expect("authenticated freeze image");
    assert_eq!(bytes.get(..8).expect("complete format tag"), b"QPANC016");
    assert_eq!(
        decode(&active.wrapping, &active.pin, &bytes)
            .expect("same exact image")
            .account_freezes,
        image.account_freezes
    );
    let id = *image.entries.keys().next().expect("original subject");
    let entry = image.entries.remove(&id).expect("retained entry");
    assert!(encode(&active.wrapping, &active.pin, &image).is_err());
    image.entries.insert(id, entry);
    image
        .entries
        .values_mut()
        .next()
        .expect("original entry")
        .authority[0] ^= 1;
    assert!(encode(&active.wrapping, &active.pin, &image).is_err());
}

#[test]
fn account_freeze_empty_witness_reopens_without_enrolling_a_dummy_subject() {
    let mut c = required_case();
    let mut empty = c.store.image().expect("owned fixture image");
    empty.entries.clear();
    c.store
        .persist(&mut empty)
        .expect("explicit empty-witness fixture");
    let original = freeze_request(&c, original_root(&c), 180);
    let frozen = c
        .store
        .freeze_account(&original)
        .expect("freeze namespace before any enrollment");
    assert_eq!(frozen.subjects().count(), 0);
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .account_freeze(&original)
            .expect("original freeze without entries"),
        frozen
    );
    let image = c.store.image().expect("empty authenticated witness");
    assert!(image.entries.is_empty() && image.account_replacements.is_empty());
    let active = c.store.active.as_ref().expect("live original owner");
    let bytes = encode(&active.wrapping, &active.pin, &image).expect("new bounded format");
    assert_eq!(bytes.get(..8).expect("complete format tag"), b"QPANC016");
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("current old account");
    assert!(matches!(
        c.store.enroll(&c.genesis, device, policy, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
}
