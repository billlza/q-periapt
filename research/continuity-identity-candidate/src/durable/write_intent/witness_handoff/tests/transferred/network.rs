// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{AnchorPolicyRenewalState, AnchorStore, AnchorTcpTransport, WitnessPendingRecovery};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    thread,
    time::Instant,
};

#[derive(Clone, Copy)]
pub(super) enum Delivery {
    Exact,
    Lost,
    Replay,
}
pub(super) fn server<T>(
    mut target: AnchorStore,
    count: usize,
    delivery: Delivery,
    client: impl FnOnce(SocketAddr) -> T,
) -> (T, AnchorStore) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let mut first = None;
            for _ in 0..count {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "client did not reach listener");
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => return Err(e),
                    }
                };
                stream
                    .set_nonblocking(false)
                    .expect("bounded blocking frame reader");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .expect("write timeout");
                let mut prefix = [0; 4];
                stream.read_exact(&mut prefix).expect("request length");
                assert_eq!(
                    u32::from_be_bytes(prefix) as usize,
                    crate::anchor::transferred::REQUEST_BYTES
                );
                let mut request = vec![0; crate::anchor::transferred::REQUEST_BYTES];
                stream
                    .read_exact(&mut request)
                    .expect("whole signed request");
                let reply = target
                    .handle(&request, 700)
                    .expect("historical original status after policy expiry");
                assert_eq!(reply.len(), crate::anchor::transferred::REPLY_BYTES);
                if matches!(delivery, Delivery::Lost) {
                    continue;
                }
                let bytes = if matches!(delivery, Delivery::Replay) {
                    first.get_or_insert_with(|| reply.clone()).as_slice()
                } else {
                    reply.as_slice()
                };
                stream
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .expect("reply prefix");
                stream.write_all(bytes).expect("reply");
            }
            Ok(target)
        });
        let result = client(address);
        (
            result,
            worker
                .join()
                .expect("server thread")
                .expect("framed test server"),
        )
    })
}
pub(in crate::durable::write_intent::witness_handoff::tests) fn adopt(
    c: &mut Case,
) -> WitnessJournalAdoption {
    let mut owner = if c.journal.active.is_some() {
        c.journal
            .begin_witness_handoff(c.plan.clone(), || Ok(180))
            .expect("prepare")
    } else {
        WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || Ok(180))
            .expect("prepare original")
    };
    owner
        .adopt_authorization(&c.receipt)
        .expect("durable adoption");
    owner
}
pub(super) fn attach(owner: &mut WitnessJournalAdoption, address: SocketAddr) {
    owner
        .attach_current_witness(
            signer(),
            Box::new(AnchorTcpTransport::new(address)),
            Duration::from_secs(3),
        )
        .expect("current verified witness");
}
pub(in crate::durable::write_intent::witness_handoff::tests) fn pending_write(
    owner: &WitnessJournalAdoption,
) -> Result<PendingWrite, DurableError> {
    let (_, pending) = owner
        .active
        .as_ref()
        .ok_or(DurableError::Closed)?
        .snapshot()?;
    match pending {
        Some(PendingIntent::Write(pending)) => Ok(pending),
        _ => Err(DurableError::Conflict),
    }
}

#[test]
fn transferred_witness_tcp_recovers_exact_sealed_policy_target_through_current_authority() {
    for stage in [0, 1, 2] {
        let mut c = Case::new(Some(stage));
        let before = c.original_rows();
        let mut owner = adopt(&mut c);
        let pending = pending_write(&owner).expect("actual P intent");
        let sealed = pending.target;
        let ((), target) = server(
            c.target.take().expect("target"),
            2,
            Delivery::Exact,
            |address| {
                attach(&mut owner, address);
                for _ in 0..2 {
                    assert_eq!(
                        owner
                            .recover_original_pending()
                            .expect("fresh current-witness recovery"),
                        WitnessPendingRecovery::Policy(if stage == 0 {
                            AnchorPolicyRenewalState::Prepared
                        } else {
                            AnchorPolicyRenewalState::Applied
                        })
                    );
                }
            },
        );
        c.target = Some(target);
        let after = rows(&owner.active.as_ref().expect("owner").db);
        assert_eq!(after.1, before.1, "original sealed intent retained");
        assert!(
            after.0 == if stage == 0 { before.0 } else { sealed },
            "only exact retained target may be installed"
        );
        owner.close();
        c.reopen_target();
        let mut owner = c.resume();
        assert_eq!(
            owner
                .authorization_receipt()
                .expect("unchanged authorization")
                .as_bytes(),
            c.receipt
        );
    }
}

#[test]
fn transferred_witness_tcp_loss_and_replay_close_owner_without_losing_original_recovery() {
    let mut c = Case::new(Some(1));
    let before = c.original_rows();
    let mut owner = adopt(&mut c);
    let (result, target) = server(
        c.target.take().expect("target"),
        1,
        Delivery::Lost,
        |address| {
            attach(&mut owner, address);
            owner.recover_original_pending()
        },
    );
    c.target = Some(target);
    assert!(result.is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert_eq!(c.original_rows(), before);
    let mut owner = c.resume();
    let ((), target) = server(
        c.target.take().expect("target"),
        2,
        Delivery::Replay,
        |address| {
            attach(&mut owner, address);
            owner
                .recover_original_pending()
                .expect("first fresh exact result installs target");
            assert!(
                owner.recover_original_pending().is_err(),
                "a signed previous attempt is not a fresh response"
            );
        },
    );
    c.target = Some(target);
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    let recovered = c.original_rows();
    assert_eq!(recovered.1, before.1);
    assert_ne!(recovered.0, before.0);
    let mut owner = c.resume();
    let (state, target) = server(
        c.target.take().expect("target"),
        1,
        Delivery::Exact,
        |address| {
            attach(&mut owner, address);
            owner
                .recover_original_pending()
                .expect("recover same already installed target")
        },
    );
    c.target = Some(target);
    assert_eq!(
        state,
        WitnessPendingRecovery::Policy(AnchorPolicyRenewalState::Applied)
    );
    assert_eq!(rows(&owner.active.as_ref().expect("owner").db), recovered);
}
