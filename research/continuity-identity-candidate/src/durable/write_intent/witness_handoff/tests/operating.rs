// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::*;
mod process;
mod scope;
mod storage;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

struct Stop<'a>(&'a AtomicBool);
impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn serve<T>(mut target: AnchorStore, run: impl FnOnce(SocketAddr) -> T) -> (T, AnchorStore, usize) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("bounded accept");
    let address = listener.local_addr().expect("address");
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| -> io::Result<_> {
            let mut frames = 0;
            let deadline = Instant::now() + Duration::from_secs(30);
            while !stop.load(Ordering::Acquire) {
                if Instant::now() >= deadline || frames >= 256 {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let mut prefix = [0; 4];
                stream.read_exact(&mut prefix)?;
                assert_eq!(
                    u32::from_be_bytes(prefix) as usize,
                    crate::anchor::transferred::REQUEST_BYTES
                );
                let mut request = vec![0; crate::anchor::transferred::REQUEST_BYTES];
                stream.read_exact(&mut request)?;
                let reply = target.handle(&request, 190).map_err(io::Error::other)?;
                stream.write_all(&(reply.len() as u32).to_be_bytes())?;
                stream.write_all(&reply)?;
                frames += 1;
            }
            Ok((target, frames))
        });
        let guard = Stop(&stop);
        let result = run(address);
        drop(guard);
        let (target, frames) = worker
            .join()
            .expect("server thread")
            .expect("current witness frames");
        (result, target, frames)
    })
}
fn client(owner: WitnessJournalAdoption, address: SocketAddr) -> AnchorClient {
    let mut owner = owner;
    owner
        .attach_current_witness(
            DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("original signer"),
            Box::new(AnchorTcpTransport::new(address)),
            Duration::from_secs(3),
        )
        .expect("attach exact current witness");
    owner
        .into_current_witness()
        .expect("transfer current client and close journal lease")
}
fn open(c: &Case, client: AnchorClient) -> DeviceJournal {
    DeviceJournal::open_anchored(&c.path(), c.key(), &c.device, &c.policy, c.identity, client)
        .expect("original journal current witness admission")
}

#[test]
fn transferred_witness_operating_journal_preserves_original_prekey_and_cold_reopens() {
    let mut c = Case::new(None);
    let owner = super::transferred::network::adopt(&mut c);
    let (original, _) = owner
        .active
        .as_ref()
        .expect("owner")
        .snapshot()
        .expect("original image");
    let retained: Vec<_> = original
        .records
        .iter()
        .map(|(id, r)| (*id, r.payload.to_vec()))
        .collect();
    let ((), target, frames) = serve(c.target.take().expect("target"), |address| {
        let mut journal = open(&c, client(owner, address));
        journal
            .generate_prekey(
                &c.policy,
                &c.device,
                PrekeyId::from_trusted_state([56; 32]).expect("ID"),
                LeafKind::OneTimePq,
                Validity::new(180, 300).expect("validity"),
                190,
            )
            .expect("new controlled prekey after transfer");
        let image = journal.image().expect("fresh current head");
        assert!(image.revision > original.revision);
        for (id, payload) in &retained {
            assert!(
                image
                    .records
                    .get(id)
                    .expect("original prekey")
                    .payload
                    .as_slice()
                    == payload
            );
        }
        assert!(rows(&journal.active.as_ref().expect("active").db)
            .1
            .is_none());
        journal.close();
        c.assert_ordinary_refused();
        let owner = c.resume();
        let mut journal = open(&c, client(owner, address));
        assert_eq!(
            journal.image().expect("same reopened head").digest,
            image.digest
        );
        journal.close();
    });
    assert!(frames > 3);
    c.target = Some(target);
    c.reopen_target();
    let ((), target, frames) = serve(c.target.take().expect("cold target"), |address| {
        let mut journal = open(&c, client(c.resume(), address));
        journal
            .generate_prekey(
                &c.policy,
                &c.device,
                PrekeyId::from_trusted_state([57; 32]).expect("next ID"),
                LeafKind::OneTimePq,
                Validity::new(180, 300).expect("validity"),
                190,
            )
            .expect("new work after both sides reopen");
        journal.close();
    });
    assert!(frames > 2);
    c.target = Some(target);
}

#[test]
fn transferred_witness_existing_policy_recovery_reuses_original_guarded_transaction() {
    for stage in [0, 1, 2] {
        let mut c = Case::new(Some(stage));
        let owner = super::transferred::network::adopt(&mut c);
        let (image, _) = owner
            .active
            .as_ref()
            .expect("owner")
            .snapshot()
            .expect("original state");
        let pending =
            super::transferred::network::pending_write(&owner).expect("actual policy intent");
        let proposal = pending.policy_proposal(&image).expect("exact P proposal");
        let before = rows(&owner.active.as_ref().expect("owner").db);
        let ((), target, frames) = serve(c.target.take().expect("target"), |address| {
            let mut carrier = client(owner, address);
            let state = DeviceJournal::recover_policy_renewal(
                &c.path(),
                c.key(),
                &c.device,
                c.policy.historical(),
                c.identity,
                proposal,
                &mut carrier,
            )
            .expect("public original P recovery with current witness");
            assert_eq!(
                state,
                if stage == 0 {
                    AnchorPolicyRenewalState::Prepared
                } else {
                    AnchorPolicyRenewalState::Applied
                }
            );
            let adopted = c.resume();
            let after = rows(&adopted.active.as_ref().expect("owner").db);
            assert!(
                after.1 == before.1,
                "original pending remains until parent terminal"
            );
            assert!(
                after.0
                    == if stage == 0 {
                        before.0.clone()
                    } else {
                        pending.target.clone()
                    }
            );
            drop(adopted);
            assert!(matches!(
                DeviceJournal::open_anchored(
                    &c.path(),
                    c.key(),
                    &c.device,
                    &c.policy,
                    c.identity,
                    carrier
                ),
                Err(DurableError::Suspended)
            ));
        });
        assert_eq!(frames, 1);
        c.target = Some(target);
    }
}

#[test]
fn transferred_witness_operating_admits_exact_already_installed_ordinary_intent() {
    let mut c = Case::new(None);
    let owner = super::transferred::network::adopt(&mut c);
    let ((), target, frames) = serve(c.target.take().expect("target"), |address| {
        let mut journal = open(&c, client(owner, address));
        let mut image = journal.image().expect("original current image");
        image.next_fanout += 1;
        let sealed = journal
            .seal_next_image(&mut image)
            .expect("one exact target");
        let active = journal.active.as_mut().expect("active owner");
        let pending = PendingWrite::new(active, &image, &sealed).expect("original ordinary intent");
        reserve(active, &pending).expect("original durable intent");
        active
            .advance_anchor(
                pending.expected_revision,
                pending.expected_digest,
                pending.next_digest,
            )
            .expect("witness committed original command");
        journal.close();
        let mut recovery = c.resume();
        recovery
            .attach_current_witness(
                DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("signer"),
                Box::new(AnchorTcpTransport::new(address)),
                Duration::from_secs(3),
            )
            .expect("current witness for original recovery");
        assert_eq!(
            recovery
                .recover_original_pending()
                .expect("install original exact target"),
            WitnessPendingRecovery::AdvanceApplied
        );
        let recovered = rows(&recovery.active.as_ref().expect("owner").db);
        assert!(recovered.0 == sealed && recovered.1.as_deref() == Some(pending.wire.as_slice()));
        let mut journal = open(
            &c,
            recovery
                .into_current_witness()
                .expect("current coordinator client"),
        );
        let final_rows = rows(&journal.active.as_ref().expect("active").db);
        assert!(
            final_rows.0 == sealed && final_rows.1.is_none(),
            "finish exact intent without resealing or second operation"
        );
        assert_eq!(
            journal.image().expect("fresh current head").digest,
            pending.next_digest
        );
        journal.close();
    });
    assert!(frames >= 5);
    c.target = Some(target);
}
