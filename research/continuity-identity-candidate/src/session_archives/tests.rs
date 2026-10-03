// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture,
    durable::tests::{assert_sync_failure, directory, fault_database_path, new_store},
    PrekeyQuality,
};
use q_periapt_host_store::filesystem::PrivateDatabaseError;
use std::{fs, sync::atomic::Ordering};

#[test]
fn session_archive_index_rejects_extra_multimap_schema_on_open_and_live_lookup() {
    for boundary in ["open", "get", "session_ids"] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let id = JournalIdentity::from_trusted_state([42; 32]).expect("independent identity");
        let file = path.join("archives.redb");
        let mut store = SessionArchiveStore::provision(&file, id).expect("index");
        let tx = transaction(store.active.as_ref().expect("active database"))
            .expect("owned schema mutation");
        tx.open_multimap_table(redb::MultimapTableDefinition::<&str, &[u8]>::new(
            "unexpected_archive_metadata",
        ))
        .expect("extra multimap")
        .insert("unrecognized", b"not part of QPCSIX01".as_slice())
        .expect("extra row");
        tx.commit().expect("persist different schema");
        if boundary == "get" {
            assert!(
                matches!(store.get([1; 32]), Err(DurableError::Corrupt)),
                "live lookup must not mistake unsupported storage for absence"
            );
            assert!(matches!(store.get([1; 32]), Err(DurableError::Closed)));
        } else if boundary == "session_ids" {
            assert!(matches!(store.session_ids(), Err(DurableError::Corrupt)));
            assert!(matches!(store.session_ids(), Err(DurableError::Closed)));
        } else {
            store.close();
            assert!(
                matches!(
                    SessionArchiveStore::open(&file, id),
                    Err(DurableError::Corrupt)
                ),
                "opening must validate the complete schema"
            );
        }
    }
}

#[test]
fn session_archive_index_is_exact_bounded_private_and_never_resets_existing_storage() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.local_device());
    let id = journal.identity().expect("ID");
    let file = path.join("archives.redb");
    assert!(SessionArchiveStore::open(&file, id).is_err());
    assert!(!file.exists());
    let mut store = SessionArchiveStore::provision(&file, id).expect("explicit new index");
    assert!(matches!(
        SessionArchiveStore::open(&file, id),
        Err(DurableError::Database(PrivateDatabaseError::Busy))
    ));
    assert!(SessionArchiveStore::provision(&file, id).is_err());
    assert!(matches!(store.get([1; 32]), Err(DurableError::Absent)));
    let first = journal
        .archive_session_closure(&f.responder, [1; 32])
        .expect("prepared archive");
    let mut corrupt = first.as_bytes().to_vec();
    *corrupt.last_mut().expect("MAC") ^= 1;
    let bad = SessionClosureArchive::from_bytes(&corrupt).expect("canonical untrusted bytes");
    assert!(matches!(
        store.retain(&journal, &f.responder, [1; 32], &bad),
        Err(DurableError::Authentication)
    ));
    assert!(matches!(store.get([1; 32]), Err(DurableError::Absent)));
    for index in 1..=MAX_ARCHIVES {
        let session = [u8::try_from(index).expect("bounded index"); 32];
        let archive = journal
            .archive_session_closure(&f.responder, session)
            .expect("bounded public scope");
        store
            .retain(&journal, &f.responder, session, &archive)
            .expect("durable archive");
    }
    store
        .retain(&journal, &f.responder, [1; 32], &first)
        .expect("idempotence at capacity");
    let extra = journal
        .archive_session_closure(&f.responder, [129; 32])
        .expect("extra intended session");
    assert!(matches!(
        store.retain(&journal, &f.responder, [129; 32], &extra),
        Err(DurableError::Capacity)
    ));
    assert!(matches!(store.get([1; 32]), Err(DurableError::Closed)));
    let wrong = JournalIdentity::from_trusted_state([99; 32]).expect("different pin");
    assert!(matches!(
        SessionArchiveStore::open(&file, wrong),
        Err(DurableError::Conflict)
    ));
    store = SessionArchiveStore::open(&file, id).expect("exact original index");
    assert_eq!(
        store.get([1; 32]).expect("original").as_bytes(),
        first.as_bytes()
    );
    assert!(matches!(store.get([129; 32]), Err(DurableError::Absent)));
    let other = fixture(PrekeyQuality::ReusableBoth);
    let changed = journal
        .archive_session_closure(&other.responder, [1; 32])
        .expect("valid MAC for another context");
    assert!(matches!(
        store.retain(&journal, &other.responder, [1; 32], &changed),
        Err(DurableError::Conflict)
    ));
    store = SessionArchiveStore::open(&file, id).expect("reopen");
    assert_eq!(
        store.get([1; 32]).expect("unchanged").as_bytes(),
        first.as_bytes()
    );
    store.close();
    let link = path.join("archive-link.redb");
    std::os::unix::fs::symlink(&file, &link).expect("symlink");
    assert!(SessionArchiveStore::open(&link, id).is_err());
    let db = open_private_database(&file).expect("inspection");
    let tx = transaction(&db).expect("tamper public index");
    tx.open_table(TABLE)
        .expect("table")
        .insert(&[1; 32], changed.as_bytes())
        .expect("replace under wrong key input");
    tx.commit().expect("commit malformed scope");
    drop(db);
    // This archive still indexes the same session but its valid MAC covers another
    // context. The actual journal/context verifier, not public parsing, rejects it.
    store =
        SessionArchiveStore::open(&file, id).expect("canonical metadata alone is not authority");
    assert!(matches!(
        journal.verify_closure_archive(
            [1; 32],
            f.responder.digest(),
            &store.get([1; 32]).expect("bytes")
        ),
        Err(DurableError::Conflict)
    ));
    store.close();
    let db = open_private_database(&file).expect("inspection");
    let tx = transaction(&db).expect("tamper index key");
    tx.open_table(TABLE)
        .expect("table")
        .insert(&[2; 32], first.as_bytes())
        .expect("wrong index");
    tx.commit().expect("commit");
    drop(db);
    assert!(matches!(
        SessionArchiveStore::open(&file, id),
        Err(DurableError::Conflict)
    ));
    assert!(fs::metadata(&file).expect("retained original file").len() > 0);
}
#[test]
fn session_archive_index_every_sync_fault_recovers_exact_or_absent_without_replacement() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.local_device());
    let id = journal.identity().expect("id");
    let archive = journal
        .archive_session_closure(&f.responder, [7; 32])
        .expect("archive");
    let file = path.join("baseline.redb");
    SessionArchiveStore::provision(&file, id)
        .expect("index")
        .close();
    let (db, _, count, _) = fault_database_path(&file, false);
    let mut store = SessionArchiveStore {
        active: Some(db),
        journal: id,
    };
    count.store(0, Ordering::SeqCst);
    store
        .retain(&journal, &f.responder, [7; 32], &archive)
        .expect("baseline");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    store.close();
    let mut outcomes = std::collections::BTreeSet::new();
    for cut in 1..=barriers {
        for after in [false, true] {
            let file = path.join(format!("cut-{cut}-{after}.redb"));
            SessionArchiveStore::provision(&file, id)
                .expect("new bounded index")
                .close();
            let (db, remaining, _, _) = fault_database_path(&file, after);
            let mut failed = SessionArchiveStore {
                active: Some(db),
                journal: id,
            };
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                failed.retain(&journal, &f.responder, [7; 32], &archive),
                after,
            );
            assert!(failed.active.is_none());
            let mut recovered = SessionArchiveStore::open(&file, id).expect("redb recovery");
            let outcome = recovered.get([7; 32]);
            if matches!(&outcome, Err(DurableError::Absent)) {
                outcomes.insert(false);
            } else {
                let saved = outcome.expect("only exact or absent outcomes");
                assert_eq!(saved.as_bytes(), archive.as_bytes());
                outcomes.insert(true);
            }
            recovered
                .retain(&journal, &f.responder, [7; 32], &archive)
                .expect("same ID exact retry");
            recovered
                .retain(&journal, &f.responder, [7; 32], &archive)
                .expect("idempotent");
            assert_eq!(
                load(recovered.active.as_ref().expect("active"), id)
                    .expect("index")
                    .len(),
                1
            );
            assert_eq!(
                recovered.get([7; 32]).expect("retained").as_bytes(),
                archive.as_bytes()
            );
        }
    }
    assert_eq!(outcomes, std::collections::BTreeSet::from([false, true]));
    eprintln!("SESSION_ARCHIVE_INDEX_SYNC barriers={barriers} before_after_faults={} outcomes={outcomes:?}",barriers*2);
}

pub(crate) fn fault_index(
    path: &Path,
    journal: JournalIdentity,
    after: bool,
) -> (
    SessionArchiveStore,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let (db, remaining, count, _) = fault_database_path(path, after);
    load(&db, journal).expect("validated exact index");
    (
        SessionArchiveStore {
            active: Some(db),
            journal,
        },
        remaining,
        count,
    )
}

pub(crate) fn rewrite_archive(path: &Path, session: [u8; 32], bytes: Option<&[u8]>) {
    let db = open_private_database(path).expect("owned adversarial index edit");
    let tx = transaction(&db).expect("transaction");
    {
        let mut table = tx.open_table(TABLE).expect("table");
        if let Some(bytes) = bytes {
            table.insert(&session, bytes).expect("replacement");
        } else {
            table.remove(&session).expect("removed metadata");
        }
    }
    tx.commit().expect("persist adversarial metadata");
}
