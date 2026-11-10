// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[test]
fn account_freeze_receipt_binds_original_request_snapshot_witness_and_signature_purpose() {
    let mut c = required_case();
    let original = freeze_request(&c, original_root(&c), 180);
    let bytes = original.to_bytes();
    assert_eq!(
        AnchorAccountFreezeRequest::from_bytes(&bytes).expect("original request round trip"),
        original
    );
    assert!(AnchorAccountFreezeRequest::from_bytes(
        bytes
            .get(..bytes.len() - 1)
            .expect("bounded request truncation")
    )
    .is_err());
    let mut extra = bytes;
    extra.push(0);
    assert!(AnchorAccountFreezeRequest::from_bytes(&extra).is_err());
    assert!(c.store.account_freeze_receipt(&original).is_err());
    let frozen = c.store.freeze_account(&original).expect("freeze");
    let wire = c
        .store
        .account_freeze_receipt(&original)
        .expect("signed exact historical snapshot");
    assert_eq!(
        c.pin
            .verify_account_freeze(&original, &wire)
            .expect("verified snapshot"),
        frozen
    );
    let changed = freeze_request(&c, original_root(&c), 181);
    assert!(c.pin.verify_account_freeze(&changed, &wire).is_err());
    let other = required_case();
    assert!(other.pin.verify_account_freeze(&original, &wire).is_err());
    let request = request(&c, AnchorOperation::query());
    assert!(c.pin.verify_reply(&request, &wire).is_err());
    let signed_bytes = 4 + 72 + crate::crypto::SIGNATURE_BYTES;
    let snapshot_size = wire.len() - signed_bytes;
    for index in [snapshot_size - 1, wire.len() - 1, snapshot_size + 4 + 72] {
        let mut damaged = wire.clone();
        *damaged
            .get_mut(index)
            .expect("selected snapshot or signature byte") ^= 1;
        assert!(c.pin.verify_account_freeze(&original, &damaged).is_err());
    }
    let (body, _) = open_envelope(wire.get(snapshot_size..).expect("exact signed envelope"))
        .expect("bounded signed body");
    let signature = c
        .store
        .active
        .as_ref()
        .expect("original signer")
        .signer
        .sign(Purpose::AnchorAccountRetirement, body)
        .expect("other-purpose fixture signature");
    let mut wrong_purpose = wire
        .get(..snapshot_size)
        .expect("exact full snapshot")
        .to_vec();
    wrong_purpose.extend_from_slice(&envelope(body, &signature).expect("bounded envelope"));
    assert!(matches!(
        c.pin.verify_account_freeze(&original, &wrong_purpose),
        Err(Error::Authentication)
    ));
    let mut extra = wire.clone();
    extra.push(0);
    assert!(c.pin.verify_account_freeze(&original, &extra).is_err());
    for length in [0, signed_bytes - 1, wire.len() - 1] {
        assert!(c
            .pin
            .verify_account_freeze(
                &original,
                wire.get(..length).expect("bounded receipt truncation")
            )
            .is_err());
    }
    c.store.close();
    c.store = reopen(&c.server);
    let replayed = c
        .store
        .account_freeze_receipt(&original)
        .expect("recovered original snapshot");
    assert_eq!(
        c.pin
            .verify_account_freeze(&original, &replayed)
            .expect("same statement"),
        frozen
    );
}
