// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn expected(closed: bool) -> AccountRootEnrollmentState {
    if closed {
        AccountRootEnrollmentState::WitnessClosed
    } else {
        AccountRootEnrollmentState::WitnessCommitted
    }
}
fn fault_intent(
    t: &Transferred,
    after: bool,
    cut: usize,
) -> (
    Result<AccountRootEnrollmentRecovery, DurableError>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut parent = DeviceEnrollment::open_original_storage(
        t.f.original.paths.clone(),
        t.f.original.intent.clone(),
    )
    .expect("original signer-free parent");
    let (remaining, count) = fault_parent(&mut parent, after);
    count.store(0, Ordering::SeqCst);
    remaining.store(cut, Ordering::SeqCst);
    (
        AccountRootEnrollmentRecovery::prepare_transferred(parent, t.plan()),
        count,
    )
}

#[test]
fn transferred_root_parent_sync_faults_reconcile_exact_child_result_without_old_owner() {
    for receipt in [false, true] {
        for closed in [false, true] {
            let mut t = Transferred::at(Some(2), 2);
            let outcome = t.decide(closed);
            if receipt {
                t.open().expect("initial parent intent").close();
            }
            let parent =
                fs::read(&t.f.original.paths.configuration).expect("quiescent owned parent");
            let child = fs::read(t.f.original.paths.installation.files()[1])
                .expect("quiescent owned child");
            let original = journal_rows(&t);
            let (barriers, close_syncs) = if receipt {
                let mut owner = t.open().expect("original intent");
                let (remaining, count) =
                    fault_parent(&mut owner.active.as_mut().expect("owner").enrollment, false);
                count.store(0, Ordering::SeqCst);
                remaining.store(usize::MAX, Ordering::SeqCst);
                owner
                    .retain_account_decision(outcome.as_bytes())
                    .expect("calibrate parent receipt");
                let n = count.load(Ordering::SeqCst);
                owner.close();
                (n, count.load(Ordering::SeqCst) - n)
            } else {
                let (owner, count) = fault_intent(&t, false, usize::MAX);
                let mut owner = owner.expect("calibrate parent intent");
                let n = count.load(Ordering::SeqCst);
                owner.close();
                (n, count.load(Ordering::SeqCst) - n)
            };
            assert!((2..=8).contains(&barriers));
            for after in [false, true] {
                for cut in 1..=barriers {
                    fs::write(&t.f.original.paths.configuration, &parent)
                        .expect("restore owned parent only");
                    fs::write(t.f.original.paths.installation.files()[1], &child)
                        .expect("restore same owned child");
                    if receipt {
                        let mut owner = t.open().expect("same intent before fault");
                        let (remaining, _) = fault_parent(
                            &mut owner.active.as_mut().expect("owner").enrollment,
                            after,
                        );
                        remaining.store(cut, Ordering::SeqCst);
                        crate::durable::tests::assert_sync_failure(
                            owner.retain_account_decision(outcome.as_bytes()),
                            after,
                        );
                        assert!(matches!(owner.status(), Err(DurableError::Closed)));
                        let mut resumed = t
                            .open()
                            .expect("child committed result repairs missing parent ACK");
                        assert_eq!(
                            resumed.status().expect("exact auto-reconciliation"),
                            expected(closed)
                        );
                        assert!(
                            resumed
                                .account_decision()
                                .expect("original signed result")
                                .as_bytes()
                                == outcome.as_bytes()
                        );
                        resumed.close();
                    } else {
                        let (result, _) = fault_intent(&t, after, cut);
                        crate::durable::tests::assert_sync_failure(result.map(|_| ()), after);
                        let mut resumed = t.open().expect("original parent intent retry");
                        assert_eq!(
                            resumed.status().expect("root outcome still unknown"),
                            AccountRootEnrollmentState::IntentRetained
                        );
                        assert_eq!(
                            resumed
                                .retain_account_decision(outcome.as_bytes())
                                .expect("original decision"),
                            expected(closed)
                        );
                        resumed.close();
                    }
                    assert!(
                        journal_rows(&t) == original,
                        "original sealed image, pending or selection changed"
                    );
                    t.f.assert_fenced();
                }
            }
            eprintln!("TRANSFERRED_ROOT_PARENT_SYNC receipt={receipt} closed={closed} barriers={barriers} faults={} close_syncs={close_syncs}",2*barriers);
        }
    }
}

#[test]
fn transferred_root_parent_retained_receipt_restores_exact_child_backup_without_signer() {
    for closed in [false, true] {
        let mut t = Transferred::at(Some(1), 2);
        let path = t.f.original.paths.installation.files()[1].to_path_buf();
        let backup = fs::read(&path).expect("same original journal before root fence");
        let mut owner = t.open().expect("original root intent");
        let outcome = t.decide(closed);
        owner
            .retain_account_decision(outcome.as_bytes())
            .expect("both durable outcomes");
        owner.close();
        fs::write(&path, backup).expect("restore same pending and selection without root fence");
        let signer = fs::read(&t.f.original.paths.signer).expect("owned signer backup");
        fs::remove_file(&t.f.original.paths.signer).expect("owned fixture signer unavailable");
        let mut owner = t
            .open()
            .expect("retained parent result repairs original child without a signer");
        assert_eq!(
            owner.status().expect("same exact decision"),
            expected(closed)
        );
        assert!(
            owner
                .account_decision()
                .expect("same result bytes")
                .as_bytes()
                == outcome.as_bytes()
        );
        owner.close();
        assert!(
            !t.f.original.paths.signer.exists(),
            "recovery must not regenerate signer"
        );
        fs::write(&t.f.original.paths.signer, signer).expect("restore same fixture signer");
        t.f.assert_fenced();
    }
}

#[test]
fn transferred_root_parent_rejects_mac_valid_checkpoint_or_selection_damage() {
    for kind in ["child-checkpoint", "authority", "selection", "receipt"] {
        let mut t = Transferred::at(Some(0), 2);
        let mut owner = t.open().expect("original intent");
        let outcome = t.decide(false);
        owner
            .retain_account_decision(outcome.as_bytes())
            .expect("original result");
        let owners = owner.active.as_ref().expect("restricted owner");
        let parent = owners.enrollment.active.as_ref().expect("parent");
        let mut state = owners.state.clone();
        match kind {
            "child-checkpoint" => state.child.as_mut().expect("exact checkpoint")[0] ^= 1,
            "authority" => state.authority.as_mut().expect("authority").logical[0] ^= 1,
            "selection" => state.selection.as_mut().expect("selection")[0] ^= 1,
            "receipt" => {
                *state
                    .receipt
                    .as_mut()
                    .expect("decision")
                    .last_mut()
                    .expect("signature") ^= 1
            }
            _ => unreachable!(),
        }
        let tampered = state
            .encode(&parent.key, owners.enrollment.binding)
            .expect("valid storage MAC does not grant protocol authority");
        owner.close();
        let original =
            fs::read(&t.f.original.paths.configuration).expect("original committed parent");
        let db = open_private_database(&t.f.original.paths.configuration).expect("owned parent");
        let tx = transaction(&db).expect("transaction");
        tx.open_table(TABLE)
            .expect("table")
            .insert(ROW, tampered.as_slice())
            .expect("owned damaged record");
        tx.commit().expect("retained damage");
        drop(db);
        assert!(
            t.open().is_err(),
            "MAC-valid {kind} damage must not reopen recovery"
        );
        fs::write(&t.f.original.paths.configuration, original).expect("restore exact parent");
        t.open().expect("exact restored parent").close();
    }
}

#[test]
fn transferred_root_parent_refuses_missing_selection_on_either_side_without_fallback() {
    for parent in [false, true] {
        let t = Transferred::at(Some(2), 2);
        t.open().expect("original parent intent").close();
        let path = if parent {
            &t.f.original.paths.configuration
        } else {
            t.f.original.paths.installation.files()[1]
        };
        let original = fs::read(path).expect("owned complete store");
        let db = open_private_database(path).expect("owned store");
        let tx = transaction(&db).expect("transaction");
        let mut table = tx
            .open_table(if parent { TABLE } else { JOURNAL })
            .expect("table");
        assert!(table
            .remove("witness-handoff")
            .expect("remove exact owned selection")
            .is_some());
        drop(table);
        tx.commit().expect("persist missing row");
        drop(db);
        assert!(
            t.open().is_err(),
            "a missing selection row cannot mean old Witness permission"
        );
        fs::write(path, original).expect("restore exact independently retained context");
        t.open().expect("exact original selection restored").close();
    }
}
