// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_root_preparation_binds_exact_future_freeze_and_never_uses_legacy_bind() {
    for stage in [None, Some(0), Some(1), Some(2)] {
        let mut t = Transferred::at(stage, 2);
        let root = t.f.original.root.public_key().expect("independent root");
        let materials = AnchorTransferredAccountReplacementMaterials {
            previous_root: &root,
            genesis: &t.successor.genesis,
            device: &t.successor.device,
            policy: &t.policy,
            history: &t.history,
        };
        let bytes = t
            .preparation
            .to_bytes()
            .expect("original persisted public plan");
        let restored =
            AnchorTransferredAccountReplacementPlan::restore_trusted_state(&bytes, &materials)
                .expect("same independently approved target after cold parse");
        assert_eq!(restored, t.preparation);
        assert_eq!(
            restored.binding().expect("binding"),
            t.preparation.binding().expect("same")
        );
        assert_eq!(restored.operation(), t.approval.proposal().operation());
        assert_eq!(
            restored
                .bind(&t.frozen, &t.history)
                .expect("exact signed freeze"),
            *t.approval.proposal()
        );
        // The embedded legacy target descriptor is not authority to treat a
        // transferred signed freeze as the older unsigned/local preparation.
        let legacy = AnchorAccountReplacementPlan::from_trusted_state(
            bytes.get(72..).expect("complete preparation prefix"),
        )
        .expect("legacy target syntax");
        assert!(legacy.bind(&t.frozen).is_err());
        let rows = journal_rows(&t);
        let decision = t.decide(false);
        assert_eq!(
            decision
                .retirement()
                .expect("committed original target")
                .proposal(),
            t.approval.proposal()
        );
        assert_eq!(
            restored
                .bind(&t.frozen, &t.history)
                .expect("stable after retirement"),
            *t.approval.proposal()
        );
        assert!(
            journal_rows(&t) == rows,
            "the read-only target plan must not consume pending work"
        );
    }
}

#[test]
fn transferred_root_preparation_rejects_changed_target_history_request_and_framing() {
    let t = Transferred::new();
    let other = Transferred::new();
    let root = t.f.original.root.public_key().expect("original root");
    let materials = AnchorTransferredAccountReplacementMaterials {
        previous_root: &root,
        genesis: &t.successor.genesis,
        device: &t.successor.device,
        policy: &t.policy,
        history: &t.history,
    };
    let bytes = t.preparation.to_bytes().expect("retained plan");
    for offset in [0, 8, 40, 80] {
        let mut changed = bytes.clone();
        *changed.get_mut(offset).expect("in-bounds fixture field") ^= 1;
        assert!(
            AnchorTransferredAccountReplacementPlan::restore_trusted_state(&changed, &materials)
                .is_err()
        );
    }
    for cut in [0, 8, 72, bytes.len() - 1] {
        assert!(
            AnchorTransferredAccountReplacementPlan::restore_trusted_state(
                bytes.get(..cut).expect("checked truncated fixture"),
                &materials
            )
            .is_err()
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        AnchorTransferredAccountReplacementPlan::restore_trusted_state(&trailing, &materials)
            .is_err()
    );
    let oversized = vec![0; 8 + 64 + 8192 + 1];
    assert!(
        AnchorTransferredAccountReplacementPlan::restore_trusted_state(&oversized, &materials)
            .is_err()
    );
    assert!(t.preparation.bind(&other.frozen, &t.history).is_err());
    assert!(t.preparation.bind(&t.frozen, &other.history).is_err());
    assert!(
        AnchorTransferredAccountReplacementPlan::restore_trusted_state(
            &bytes,
            &AnchorTransferredAccountReplacementMaterials {
                genesis: &other.successor.genesis,
                ..materials
            }
        )
        .is_err()
    );
    // Changing only the freeze operation makes a different independent plan.
    // It remains valid syntax, but cannot bind the original signed freeze.
    let mut changed_request = bytes.clone();
    let at = 72 + 8 + 8 + 32;
    *changed_request
        .get_mut(at)
        .expect("original request operation field") ^= 1;
    let changed = AnchorTransferredAccountReplacementPlan::restore_trusted_state(
        &changed_request,
        &materials,
    )
    .expect("independently retained alternative request is syntactically valid");
    assert_ne!(
        changed.binding().expect("other binding"),
        t.preparation.binding().expect("original binding")
    );
    assert!(changed.bind(&t.frozen, &t.history).is_err());
}
