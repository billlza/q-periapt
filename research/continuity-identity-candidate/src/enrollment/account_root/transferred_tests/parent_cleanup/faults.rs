// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::crypto::{inject_signer_io, SignerIoFault, SignerIoStage};
use crate::durable::tests::{assert_sync_failure, fault_database_path};
use hmac::Mac;
use std::sync::atomic::Ordering;

pub(super) fn row(flow: &Flow, name: &str) -> Vec<u8> {
    let db = open_private_database(&flow.t.f.original.paths.configuration)
        .expect("closed original parent");
    let tx = db.begin_read().expect("read");
    let table = tx.open_table(TABLE).expect("parent table");
    let r = table.get(name).expect("read row").expect("required row");
    r.value().to_vec()
}
fn replace(flow: &Flow, name: &str, wire: Option<&[u8]>) {
    let db =
        open_private_database(&flow.t.f.original.paths.configuration).expect("owned test parent");
    let tx = transaction(&db).expect("test mutation");
    {
        let mut table = tx.open_table(TABLE).expect("parent");
        if let Some(wire) = wire {
            table.insert(name, wire).expect("same row");
        } else {
            table.remove(name).expect("remove original row");
        }
    }
    tx.commit().expect("test metadata mutation");
}
#[test]
fn transferred_parent_cleanup_missing_rows_bad_proofs_and_independent_checkpoint_refuse_cold_owner()
{
    let mut flow = managed(Some(2), 2);
    let mut owner = resume_managed(&flow).expect("same original controller");
    let ack = owner
        .with_retired_cleanup(|parent| {
            let ack = report_ack(&mut flow, parent);
            erase_journal(&flow, parent, &ack);
            parent.prepare_signer_erasure(&ack)?;
            Ok(ack)
        })
        .expect("signer plan independently retained");
    owner.close();
    let signer = fs::read(&flow.t.f.original.paths.signer).expect("original signer still retained");
    for name in [
        "retirement",
        crate::enrollment::account_root::ROW,
        crate::enrollment::witness_handoff::ROW,
    ] {
        let original = row(&flow, name);
        replace(&flow, name, None);
        assert!(
            resume_managed(&flow).is_err(),
            "missing {name} cannot reconstruct erased journal"
        );
        assert!(fs::read(&flow.t.f.original.paths.signer).expect("original signer") == signer);
        replace(&flow, name, Some(&original));
    }
    let original = row(&flow, "retirement");
    let mut bad = original.clone();
    *bad.last_mut().expect("MAC") ^= 1;
    replace(&flow, "retirement", Some(&bad));
    assert!(resume_managed(&flow).is_err());
    let mut body = original.get(..original.len() - 32).expect("body").to_vec();
    assert_eq!(body.get(..8), Some(b"QPERTR02".as_slice()));
    *body
        .get_mut(72)
        .expect("retained original child checkpoint") ^= 1;
    let key = JournalKey::open(&flow.t.f.original.paths.wrapping).expect("original test key");
    let mut mac = crate::enrollment::auth(&key).expect("valid test MAC");
    mac.update(&body);
    body.extend_from_slice(&mac.finalize().into_bytes());
    replace(&flow, "retirement", Some(&body));
    assert!(
        matches!(resume_managed(&flow), Err(DurableError::Conflict)),
        "valid local MAC cannot replace the independently retained registry checkpoint"
    );
    replace(&flow, "retirement", Some(&original));
    let mut owner = resume_managed(&flow).expect("same independent checkpoint restored");
    let mut wrong = ack.clone();
    *wrong.last_mut().expect("signature") ^= 1;
    assert!(owner
        .with_retired_cleanup(|parent| parent.prepare_signer_erasure(&wrong))
        .is_err());
    assert!(matches!(owner.state(), Err(DurableError::Closed)));
    assert!(
        fs::read(&flow.t.f.original.paths.signer).expect("original signer unchanged") == signer
    );
    let mut owner = resume_managed(&flow).expect("no replacement operation after failure");
    owner
        .with_retired_cleanup(|parent| {
            parent.prepare_signer_erasure(&ack)?;
            parent.erase_signer()
        })
        .expect("exact original proof can finish");
    owner.close();
}

fn parent_sync(flow: &Flow, ack: Option<&[u8]>) {
    let path = &flow.t.f.original.paths.configuration;
    let baseline = fs::read(path).expect("closed parent");
    let signer = fs::read(&flow.t.f.original.paths.signer).expect("retained signer");
    let open = |db| {
        RetiredDeviceEnrollment::open_transferred_database(
            flow.t.f.original.paths.clone(),
            flow.t.f.original.intent.clone(),
            flow.context.clone(),
            db,
        )
    };
    let (db, _, count, _) = fault_database_path(path, false);
    let mut owner = open(db).expect("calibrate original retirement");
    if let Some(ack) = ack {
        owner
            .prepare_signer_erasure(ack)
            .expect("calibrate original signer plan");
    }
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(path, &baseline).expect("same owned parent before transaction");
            let (db, remaining, count, _) = fault_database_path(path, after);
            count.store(0, Ordering::SeqCst);
            remaining.store(cut, Ordering::SeqCst);
            let opened = open(db);
            if let Some(ack) = ack {
                let mut owner = opened.expect("existing original inventory");
                assert_sync_failure(owner.prepare_signer_erasure(ack), after);
                assert!(matches!(
                    owner.signer_erasure_status(),
                    Err(DurableError::Closed)
                ));
            } else {
                assert_sync_failure(opened, after);
            }
            let observed = count.load(Ordering::SeqCst);
            assert!(observed >= cut);
            remaining.store(0, Ordering::SeqCst);
            assert!(
                fs::read(&flow.t.f.original.paths.signer)
                    .expect("signer untouched by parent failure")
                    == signer
            );
            let mut owner = reopen(flow);
            if let Some(ack) = ack {
                owner
                    .prepare_signer_erasure(ack)
                    .expect("exact original signer plan retry");
                assert_eq!(
                    owner.signer_erasure_status().expect("retained file"),
                    SigningFileErasureState::Retained
                );
            }
            owner.close();
            eprintln!("TRANSFERRED_PARENT_SYNC signer_plan={} after={after} cut={cut} calibrated={barriers} close_syncs={} exact_original=true",ack.is_some(),observed-cut);
        }
    }
}
#[test]
fn transferred_parent_cleanup_every_parent_sync_preserves_original_root_selection_and_proof() {
    let (mut flow, mut root) = prepared(Some(2), 2);
    root.close();
    parent_sync(&flow, None);
    let mut parent = reopen(&flow);
    let ack = report_ack(&mut flow, &mut parent);
    erase_journal(&flow, &mut parent, &ack);
    parent.close();
    parent_sync(&flow, Some(&ack));
}

#[test]
fn transferred_parent_cleanup_signer_io_errors_close_managed_owner_and_recover_same_plan() {
    let mut flow = managed(Some(2), 2);
    let mut owner = resume_managed(&flow).expect("original controller");
    owner
        .with_retired_cleanup(|parent| {
            let ack = report_ack(&mut flow, parent);
            erase_journal(&flow, parent, &ack);
            parent.prepare_signer_erasure(&ack)
        })
        .expect("original signer plan");
    owner.close();
    let original = fs::read(&flow.t.f.original.paths.signer).expect("original sealed signer");
    let parent = row(&flow, "retirement");
    let mut cases = (0..=8).map(SignerIoFault::Prefix).collect::<Vec<_>>();
    for stage in [
        SignerIoStage::HeaderWrite,
        SignerIoStage::HeaderSync,
        SignerIoStage::Truncate,
        SignerIoStage::TerminalSync,
        SignerIoStage::DirectorySync,
    ] {
        for after in [false, true] {
            cases.push(SignerIoFault::Boundary(stage, after));
        }
    }
    assert_eq!(cases.len(), 19);
    for (index, case) in cases.into_iter().enumerate() {
        fs::write(&flow.t.f.original.paths.signer, &original)
            .expect("restore owned same inode and original encrypted fixture bytes");
        let mut owner = resume_managed(&flow).expect("same acknowledged original plan");
        let injection = inject_signer_io(case);
        assert!(owner
            .with_retired_cleanup(|parent| parent.erase_signer())
            .is_err());
        assert!(injection.fired());
        assert!(matches!(owner.state(), Err(DurableError::Closed)));
        drop(injection);
        let mut recovered = resume_managed(&flow)
            .expect("unknown signing-file outcome keeps original controller inputs");
        recovered
            .with_retired_cleanup(|parent| parent.erase_signer())
            .expect("same original inode can complete");
        recovered.close();
        assert_eq!(
            fs::read(&flow.t.f.original.paths.signer).expect("original terminal"),
            b"QPSRET01"
        );
        assert!(
            row(&flow, "retirement") == parent,
            "no new plan after unknown result"
        );
        eprintln!("TRANSFERRED_PARENT_SIGNER_IO case={index} closed_controller=true original_plan=true terminal=true");
    }
}
