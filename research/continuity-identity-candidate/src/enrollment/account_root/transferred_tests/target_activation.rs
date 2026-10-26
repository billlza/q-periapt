// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize};

pub(super) struct CurrentCarrier {
    pub(super) store: Arc<Mutex<AnchorStore>>,
    pub(super) clock: Arc<AtomicU64>,
    pub(super) calls: Arc<AtomicUsize>,
}
impl AnchorTransport for CurrentCarrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.store
            .lock()
            .expect("actual current Witness")
            .handle(request, self.clock.load(Ordering::SeqCst))
            .map_err(io::Error::other)
    }
}
#[test]
fn transferred_root_target_uses_fresh_current_witness_admission_only_after_commit() {
    for closed in [false, true] {
        let mut t = Transferred::at(Some(2), 2);
        let mut parent = t.open().expect("original parent fence");
        let decision = t.decide(closed);
        parent
            .retain_account_decision(decision.as_bytes())
            .expect("same root decision");
        parent.close();
        let calls = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(AtomicU64::new(185));
        let carrier = CurrentCarrier {
            store: Arc::new(Mutex::new(t.target)),
            clock,
            calls: Arc::clone(&calls),
        };
        let mut target =
            DeviceEnrollment::open(t.successor.paths.clone(), t.successor.intent.clone())
                .expect("original independently enrolled target");
        let client = target
            .anchor_client(
                &t.policy,
                185,
                t.history.current_pin().clone(),
                Box::new(carrier),
                Duration::from_secs(3),
            )
            .expect("currentB target signer client");
        let result = target.activate(&t.policy, 185, Some(client));
        assert!(
            calls.load(Ordering::SeqCst) > 0,
            "test must reach actual server admission"
        );
        if closed {
            assert!(
                result.is_err(),
                "Closed must not enroll or activate the target"
            );
        } else {
            let mut live = result.expect("fresh currentB admission for exact committed successor");
            let (service, _, device) = live.parts().expect("actual target owners");
            service
                .stores()
                .expect("target stores")
                .0
                .generate_prekey(
                    &t.policy,
                    device,
                    PrekeyId::from_trusted_state([209; 32]).expect("target prekey"),
                    LeafKind::OneTimePq,
                    Validity::new(185, 200).expect("target interval"),
                    185,
                )
                .expect("real target operation after fresh admission");
            live.close();
        }
        t.f.assert_fenced();
    }
}
