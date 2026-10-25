// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::AtomicUsize;

fn faulted(
    journal: &mut DeviceJournal,
    path: &Path,
    after: bool,
) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let old = journal.active.take().expect("original active owner");
    drop(old.db);
    let (db, remaining, count, _) = crate::durable::tests::fault_database_path(path, after);
    journal.active = Some(Active { db, ..old });
    (remaining, count)
}
pub(super) fn target(journal: &mut DeviceJournal) -> (Image, Vec<u8>) {
    let mut image = journal.image().expect("fresh original head");
    image.next_fanout += 1;
    let sealed = journal
        .seal_next_image(&mut image)
        .expect("one exact sealed state");
    (image, sealed)
}
#[test]
fn transferred_witness_operating_sync_faults_keep_control_intent_and_image_atomic() {
    let mut c = Case::new(None);
    let owner = super::super::transferred::network::adopt(&mut c);
    let (barriers, target_store, _) = serve(c.target.take().expect("target"), |address| {
        let mut journal = open(&c, client(owner, address));
        let (image, sealed) = target(&mut journal);
        let (_, count) = faulted(&mut journal, &c.path(), false);
        count.store(0, Ordering::SeqCst);
        commit(journal.active.as_mut().expect("owner"), &image, &sealed).expect("calibration");
        let barriers = count.load(Ordering::SeqCst);
        journal.close();
        barriers
    });
    c.target = Some(target_store);
    assert!((4..=16).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = Case::new(None);
            let owner = super::super::transferred::network::adopt(&mut c);
            let ((), target_store, _) = serve(c.target.take().expect("target"), |address| {
                let mut journal = open(&c, client(owner, address));
                let before = rows(&journal.active.as_ref().expect("owner").db);
                let (image, sealed) = target(&mut journal);
                let (remaining, _) = faulted(&mut journal, &c.path(), after);
                remaining.store(cut, Ordering::SeqCst);
                let result = commit(journal.active.as_mut().expect("owner"), &image, &sealed);
                crate::durable::tests::assert_sync_failure(result, after);
                journal.close();
                let owner = c.resume();
                let observed = rows(&owner.active.as_ref().expect("owner").db);
                assert!(observed.0 == before.0 || observed.0 == sealed);
                let published = observed.1.is_some() || observed.0 == sealed;
                let mut journal = open(&c, client(owner, address));
                let recovered = rows(&journal.active.as_ref().expect("owner").db);
                assert!(recovered.0 == if published { sealed } else { before.0 });
                assert!(recovered.1.is_none());
                journal.close();
            });
            c.target = Some(target_store);
        }
    }
    eprintln!(
        "TRANSFERRED_OPERATING_SYNC barriers={barriers} faults={}",
        2 * barriers
    );
}
