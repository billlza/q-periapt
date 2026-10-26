// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Semantically corrupt, correctly MAC-authenticated owned fixture records.
use super::*;

pub(crate) fn snapshot_registry(store: &AccountAuthorityStore) -> Vec<u8> {
    let active = store.active.as_ref().expect("original registry");
    codec::encode(&active.image, &active.key, store.binding).expect("original authenticated image")
}
pub(crate) fn restore_registry_snapshot(path: &Path, bytes: &[u8]) {
    let db = open_private_database(path).expect("same closed test database");
    codec::write(&db, bytes).expect("restore exact owned fixture snapshot");
}
pub(crate) fn rejects_transferred_images(store: &AccountAuthorityStore) {
    let active = store.active.as_ref().expect("active original registry");
    let read = |image: &Image| -> Result<_, DurableError> {
        let wire = codec::encode(image, &active.key, store.binding)?;
        codec::decode(&wire, &active.key, store.binding)?.current(store.family, &store.pin)
    };
    read(&active.image).expect("actual original graph");
    for (app, initial) in &active.image.initial {
        if initial.witness.is_some() {
            let mut changed = active.image.clone();
            changed
                .initial
                .get_mut(app)
                .expect("original new association")
                .root = store.pin.public_key().clone();
            assert!(read(&changed).is_err());
        }
    }
    let mut changed = active.image.clone();
    changed.history = None;
    assert!(read(&changed).is_err());
    let mut changed = active.image.clone();
    changed
        .replacements
        .first_mut()
        .expect("record")
        .transferred = None;
    assert!(read(&changed).is_err());
    let mut changed = active.image.clone();
    changed.replacements.first_mut().expect("record").revision += 1;
    assert!(read(&changed).is_err());
    let mut changed = active.image.clone();
    changed
        .replacements
        .first_mut()
        .expect("record")
        .transferred
        .as_mut()
        .expect("transferred")
        .logical = [240; 32];
    assert!(read(&changed).is_err());
    let mut changed = active.image.clone();
    let r = changed.replacements.first_mut().expect("record");
    let plan = r
        .transferred
        .as_ref()
        .expect("transferred")
        .plan
        .to_bytes()
        .expect("plan");
    r.preparation = Some(
        AnchorAccountReplacementPlan::from_trusted_state(plan.get(72..).expect("plan prefix"))
            .expect("legacy syntax"),
    );
    assert!(read(&changed).is_err());
    let bound = active
        .image
        .replacements
        .first()
        .expect("record")
        .transferred
        .as_ref()
        .expect("transferred")
        .approval
        .is_some();
    if bound {
        let mut changed = active.image.clone();
        changed
            .replacements
            .first_mut()
            .expect("record")
            .transferred
            .as_mut()
            .expect("transferred")
            .frozen = None;
        assert!(read(&changed).is_err());
        let mut changed = active.image.clone();
        changed
            .replacements
            .first_mut()
            .expect("record")
            .transferred
            .as_mut()
            .expect("transferred")
            .approval = None;
        assert!(read(&changed).is_err());
        let mut changed = active.image.clone();
        let r = changed.replacements.first_mut().expect("record");
        r.proposal = r
            .transferred
            .as_ref()
            .expect("transferred")
            .plan
            .target()
            .clone();
        assert!(read(&changed).is_err());
    }
    let mut changed = active.image.clone();
    let r = changed.replacements.first_mut().expect("record");
    r.decision = if r.decision == Decision::Committed {
        Decision::ClosedExact
    } else {
        Decision::Committed
    };
    assert!(read(&changed).is_err());
    if active
        .image
        .replacements
        .first()
        .expect("record")
        .transferred
        .as_ref()
        .expect("transferred")
        .receipt
        .is_some()
    {
        let mut changed = active.image.clone();
        changed
            .replacements
            .first_mut()
            .expect("record")
            .transferred
            .as_mut()
            .expect("transferred")
            .receipt = None;
        assert!(read(&changed).is_err());
        let mut changed = active.image.clone();
        *changed
            .replacements
            .first_mut()
            .expect("record")
            .transferred
            .as_mut()
            .expect("transferred")
            .receipt
            .as_mut()
            .expect("receipt")
            .last_mut()
            .expect("signature") ^= 1;
        assert!(read(&changed).is_err());
    }
}
