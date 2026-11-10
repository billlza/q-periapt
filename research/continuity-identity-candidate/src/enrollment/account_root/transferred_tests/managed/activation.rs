// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize};

#[test]
fn transferred_managed_current_target_runs_only_after_commit_and_closes_with_controller() {
    for closed in [false, true] {
        let mut t = Transferred::with_controller(Some(2), 2);
        let mut owner = t.controller.take().expect("original managed preparation");
        owner
            .bind_transferred_freeze(&t.frozen, t.approval.clone())
            .expect("approved full freeze");
        let wire = t.decide(closed);
        owner
            .retain_transferred_decision(wire.as_bytes())
            .expect("exact original outcome");
        owner.close();
        let mut owner = resume(&t).expect("cold same registry, parent and child");
        let calls = Arc::new(AtomicUsize::new(0));
        let carrier = target_activation::CurrentCarrier {
            store: Arc::new(Mutex::new(t.target)),
            clock: Arc::new(AtomicU64::new(185)),
            calls: Arc::clone(&calls),
        };
        let target = DeviceEnrollment::open(t.successor.paths.clone(), t.successor.intent.clone())
            .expect("independently enrolled exact target");
        let result = owner.activate_successor(
            target,
            &t.policy,
            185,
            Box::new(carrier),
            Duration::from_secs(3),
        );
        if closed {
            assert!(matches!(result, Err(DurableError::Suspended)));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "Closed refuses before network or target activation"
            );
        } else {
            let mut live = result.expect("actual B-bound target under original registry");
            assert!(calls.load(Ordering::SeqCst) > 0);
            let (service, _, device) = live.parts().expect("actual target owners");
            for (id, allowed) in [(225, true), (226, false)] {
                if !allowed {
                    owner.close();
                }
                let result = service
                    .stores()
                    .expect("owned target stores")
                    .0
                    .generate_prekey(
                        &t.policy,
                        device,
                        PrekeyId::from_trusted_state([id; 32]).expect("new target prekey"),
                        LeafKind::OneTimePq,
                        Validity::new(185, 199).expect("valid window"),
                        185,
                    );
                if allowed {
                    result.expect("real target crypto after current admission");
                } else {
                    assert!(
                        result.is_err(),
                        "controller closure must revoke delegated crypto"
                    );
                }
            }
            live.close();
        }
        owner.close();
        t.f.assert_fenced();
    }
}
