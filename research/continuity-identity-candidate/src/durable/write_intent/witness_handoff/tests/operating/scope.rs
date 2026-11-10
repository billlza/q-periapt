// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::AtomicUsize;

struct NoDispatch(Arc<AtomicUsize>);
impl AnchorTransport for NoDispatch {
    fn exchange(&mut self, _: &[u8], _: crate::MonotonicInstant) -> io::Result<Vec<u8>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
#[test]
fn transferred_witness_operating_refuses_missing_foreign_or_changed_selection_before_dispatch() {
    for fault in ["missing", "request", "receipt", "image"] {
        let mut c = Case::new(None);
        let mut owner = super::super::transferred::network::adopt(&mut c);
        let calls = Arc::new(AtomicUsize::new(0));
        owner
            .attach_current_witness(
                DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("original signer"),
                Box::new(NoDispatch(Arc::clone(&calls))),
                Duration::from_secs(1),
            )
            .expect("selected owner");
        let carrier = owner.into_current_witness().expect("current client");
        let db = open_private_database(&c.path()).expect("original database");
        let before = rows(&db);
        let tx = transaction(&db).expect("owned mutation");
        {
            let mut table = tx.open_table(TABLE).expect("table");
            let saved = table
                .get(ROW)
                .expect("read")
                .expect("selection")
                .value()
                .to_vec();
            let mut f = Fence::decode(&c.key(), &saved).expect("original fence");
            match fault {
                "missing" => {
                    table.remove(ROW).expect("remove");
                }
                "request" => {
                    let foreign = Case::new(None);
                    f.request = foreign.plan.request.clone();
                    table
                        .insert(ROW, f.encode(&c.key()).expect("valid MAC").as_slice())
                        .expect("write");
                }
                "receipt" => {
                    *f.receipt
                        .as_mut()
                        .expect("receipt")
                        .get_mut(100)
                        .expect("receipt mutation byte") ^= 1;
                    table
                        .insert(ROW, f.encode(&c.key()).expect("valid MAC").as_slice())
                        .expect("write");
                }
                _ => {
                    f.image[0] ^= 1;
                    table
                        .insert(ROW, f.encode(&c.key()).expect("valid MAC").as_slice())
                        .expect("write");
                }
            }
        }
        tx.commit().expect("commit owned corruption");
        drop(db);
        assert!(DeviceJournal::open_anchored(
            &c.path(),
            c.key(),
            &c.device,
            &c.policy,
            c.identity,
            carrier
        )
        .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let db = open_private_database(&c.path()).expect("read failed attempt");
        assert!(
            rows(&db) == before,
            "failed selection cannot mutate original image or pending"
        );
    }
}

#[test]
fn transferred_witness_operating_refuses_old_client_before_any_old_authority_request() {
    let mut c = Case::new(None);
    super::super::transferred::network::adopt(&mut c).close();
    let calls = Arc::new(AtomicUsize::new(0));
    let old = AnchorClient::new(
        c.plan
            .history
            .historical_pin(c.plan.scope().logical)
            .expect("old pin")
            .clone(),
        DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("original signer"),
        Box::new(NoDispatch(Arc::clone(&calls))),
        Duration::from_secs(1),
    )
    .expect("old client");
    assert!(DeviceJournal::open_anchored(
        &c.path(),
        c.key(),
        &c.device,
        &c.policy,
        c.identity,
        old
    )
    .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
