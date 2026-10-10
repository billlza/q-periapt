// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AnchorCredentialRenewalCancellation as Cancellation;
use redb::ReadableTable;

fn staged() -> (Fixture, crate::VerifiedCredentialRenewal) {
    let f = fixture();
    let proof = grant(&f, &f.original, 2, 190);
    open(&f.c)
        .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, 150)
        .expect("stage only");
    (f, proof)
}
fn reserve(f: &Fixture, at: u64) -> Cancellation {
    open(&f.c)
        .prepare_witnessed_credential_cancellation(&f.c.policy, at)
        .expect("target-free reservation")
}
fn close(f: &Fixture, proof: &crate::VerifiedCredentialRenewal, cancellation: Cancellation) {
    f.carrier
        .store
        .lock()
        .expect("witness")
        .close_unprepared_credential_renewal(cancellation, proof, &f.c.policy)
        .expect("independent grant cancellation");
}
fn closed(proof: &crate::VerifiedCredentialRenewal) -> CredentialRenewalStatus {
    CredentialRenewalStatus::Closed {
        operation: proof.operation(),
        statement: proof.statement_digest(),
        target: proof.successor_device().roster().checkpoint(),
    }
}
fn reconcile(
    f: &Fixture,
    proof: &crate::VerifiedCredentialRenewal,
    at: u64,
) -> CredentialRenewalStatus {
    let mut owner = open(&f.c);
    let mut anchor = client(f, &mut owner, at);
    owner
        .reconcile_witnessed_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &f.c.policy,
            at,
            &mut anchor,
        )
        .expect("reconcile original operation")
}

#[test]
fn target_free_closed_preserves_both_original_and_previously_renewed_live_predecessors() {
    for prior in [false, true] {
        let f = fixture();
        let first = grant(&f, &f.original, 2, 190);
        let (previous, version, at) = if prior {
            prepare(&f, &first, 170);
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 170);
            owner
                .commit_witnessed_credential_renewal(
                    first.operation(),
                    first.statement_digest(),
                    &f.c.policy,
                    170,
                    &mut anchor,
                )
                .expect("C1");
            (first.successor_device(), 3, 175)
        } else {
            (&f.original, 2, 150)
        };
        let proof = grant(&f, previous, version, 220);
        open(&f.c)
            .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, at)
            .expect("stage");
        let saved = disk(&f).0;
        let before = f.carrier.requests.lock().expect("requests").len();
        if prior {
            let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
            let db = open_private_database(f.c.paths.installation.files()[1]).expect("journal");
            assert!(
                matches!(
                    DeviceJournal::reserve_credential_cancellation_in_database(
                        &db,
                        &key,
                        &f.original,
                        f.c.policy.historical(),
                        f.id,
                        proof.historical(),
                        None
                    ),
                    Err(DurableError::Conflict)
                ),
                "missing prior completion must fail"
            );
            drop(db);
            assert_eq!(disk(&f), (saved.clone(), None));
        }
        let cancellation = reserve(&f, at);
        assert_eq!(reserve(&f, at), cancellation);
        assert_eq!(f.carrier.requests.lock().expect("requests").len(), before);
        let reserved = disk(&f);
        assert_eq!(reserved.0, saved);
        let wire = reserved.1.as_ref().expect("durable reservation");
        assert_eq!(wire.len(), 320);
        assert_eq!(wire.get(..8), Some(b"QPWINT03".as_slice()));
        assert_eq!(wire.get(40..288), Some(cancellation.to_bytes().as_slice()));
        assert_eq!(
            reconcile(&f, &proof, at),
            renewal::pending(&proof),
            "Unavailable is never Closed"
        );
        assert_eq!(disk(&f), reserved);
        // Direct journal entry points must not turn target-free reservation into
        // an ordinary write, a missing proposal, or operational authority.
        assert!(matches!(
            DeviceJournal::inspect_credential_renewal_preparation(
                f.c.paths.installation.files()[1],
                JournalKey::open(&f.c.paths.wrapping).expect("key"),
                &f.original,
                &f.c.policy,
                f.id,
            ),
            Err(DurableError::Suspended)
        ));
        let mut owner = open(&f.c);
        let anchor = client(&f, &mut owner, at);
        assert!(matches!(
            DeviceJournal::open_anchored(
                f.c.paths.installation.files()[1],
                JournalKey::open(&f.c.paths.wrapping).expect("key"),
                &f.original,
                &f.c.policy,
                f.id,
                anchor,
            ),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            DeviceJournal::open(
                f.c.paths.installation.files()[1],
                JournalKey::open(&f.c.paths.wrapping).expect("key"),
                &f.original,
                f.id,
            ),
            Err(DurableError::Suspended)
        ));
        let anchor = client(&f, &mut owner, at);
        assert!(matches!(
            crate::BootstrapCancellationJournal::open_anchored(
                f.c.paths.installation.files()[1],
                JournalKey::open(&f.c.paths.wrapping).expect("key"),
                f.id,
                anchor,
            ),
            Err(DurableError::Suspended)
        ));
        let archive_path =
            f.c.paths
                .configuration
                .parent()
                .expect("directory")
                .join("cancellation-test-archives");
        let mut archives = crate::SessionArchiveStore::provision(&archive_path, f.id)
            .expect("original empty archive index");
        let anchor = client(&f, &mut owner, at);
        assert!(
            matches!(
                crate::FanoutAbandonmentJournal::open_anchored(
                    f.c.paths.installation.files()[1],
                    JournalKey::open(&f.c.paths.wrapping).expect("key"),
                    f.id,
                    crate::FanoutId::from_trusted_state([39; 32]).expect("batch"),
                    &mut archives,
                    anchor,
                ),
                Err(DurableError::Suspended)
            ),
            "pending cannot be interpreted as absent batch"
        );
        let mut anchor = client(&f, &mut owner, at);
        assert!(owner
            .commit_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                at,
                &mut anchor
            )
            .is_err());
        assert!(!f
            .carrier
            .requests
            .lock()
            .expect("requests")
            .get(before..)
            .expect("prefix")
            .contains(&5));
        let mut owner = open(&f.c);
        let anchor = client(&f, &mut owner, at);
        assert!(owner
            .prepare_witnessed_credential_renewal(&f.c.policy, at, anchor)
            .is_err());
        assert_eq!(disk(&f), reserved);
        close(&f, &proof, cancellation);
        assert_eq!(reconcile(&f, &proof, at), closed(&proof));
        assert_eq!(disk(&f), (saved.clone(), None));
        activate(&f, at).expect("predecessor still live").close();
        assert_eq!(disk(&f), (saved, None));
        assert!(open(&f.c)
            .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, at)
            .is_err());
        if prior {
            assert_eq!(reconcile(&f, &first, at), renewal::committed(&first));
        }
        let next = grant(&f, previous, version + 1, 240);
        prepare(&f, &next, at);
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, at);
        assert_eq!(
            owner
                .commit_witnessed_credential_renewal(
                    next.operation(),
                    next.statement_digest(),
                    &f.c.policy,
                    at,
                    &mut anchor
                )
                .expect("next higher grant"),
            renewal::committed(&next)
        );
    }
}

#[test]
fn expired_policy_reservation_and_lost_status_or_ack_never_reseal_the_original_image() {
    for cut in [(6, false), (6, true), (8, false), (8, true)] {
        let (f, proof) = staged();
        let original = disk(&f).0;
        let policy = historical(&f);
        f.c.policy.close();
        f.c.policy.runtime.close();
        f.carrier.clock.store(250, Ordering::SeqCst);
        let mut owner = open(&f.c);
        let cancellation = owner
            .prepare_witnessed_credential_cancellation(&policy, 250)
            .expect("historical reservation");
        close(&f, &proof, cancellation);
        let reserved = disk(&f);
        *f.carrier.cut.lock().expect("cut") = Some(cut);
        let mut anchor = client(&f, &mut owner, 250);
        assert!(owner
            .reconcile_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &policy,
                250,
                &mut anchor
            )
            .is_err());
        assert!(owner.active.is_none());
        assert_eq!(disk(&f), reserved);
        assert_eq!(reconcile(&f, &proof, 250), closed(&proof));
        assert_eq!(disk(&f), (original, None));
        assert!(activate(&f, 250).is_err());
    }
}

#[test]
fn cancellation_configuration_sync_failures_recover_original_reservation_without_dispatch() {
    let (f, _) = staged();
    let (mut owner, _, count) = faulty(&f.c, false);
    count.store(0, Ordering::SeqCst);
    owner
        .prepare_witnessed_credential_cancellation(&f.c.policy, 150)
        .expect("calibrate");
    let syncs = count.load(Ordering::SeqCst);
    owner.close();
    assert!((1..=4).contains(&syncs));
    let mut cuts = 0;
    for after in [false, true] {
        for cut in 1..=syncs {
            let (f, proof) = staged();
            let original = disk(&f).0;
            let (mut owner, remaining, _) = faulty(&f.c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.prepare_witnessed_credential_cancellation(&f.c.policy, 150),
                after,
            );
            assert!(owner.active.is_none());
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            let saved = disk(&f);
            assert_eq!(saved.0, original);
            let before = f.carrier.requests.lock().expect("requests").len();
            let cancellation = reserve(&f, 250);
            assert_eq!(reserve(&f, 250), cancellation);
            assert_eq!(disk(&f), saved);
            assert_eq!(f.carrier.requests.lock().expect("requests").len(), before);
            close(&f, &proof, cancellation);
            assert_eq!(reconcile(&f, &proof, 250), closed(&proof));
            assert_eq!(disk(&f), (original, None));
            cuts += 1;
        }
    }
    eprintln!("cancellation configuration reservation cuts={cuts}");
}

#[test]
fn cancellation_reservation_journal_sync_failures_preserve_image_and_exact_retry() {
    let (f, proof) = staged();
    let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
    let (db, _, count, _) = fault_database_path(f.c.paths.installation.files()[1], false);
    count.store(0, Ordering::SeqCst);
    DeviceJournal::reserve_credential_cancellation_in_database(
        &db,
        &key,
        &f.original,
        f.c.policy.historical(),
        f.id,
        proof.historical(),
        None,
    )
    .expect("calibrate");
    let syncs = count.load(Ordering::SeqCst);
    count.store(0, Ordering::SeqCst);
    DeviceJournal::reserve_credential_cancellation_in_database(
        &db,
        &key,
        &f.original,
        f.c.policy.historical(),
        f.id,
        proof.historical(),
        None,
    )
    .expect("exact retry");
    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(db);
    assert!((1..=8).contains(&syncs));
    let mut cuts = 0;
    for after in [false, true] {
        for cut in 1..=syncs {
            let (f, proof) = staged();
            let original = disk(&f).0;
            let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
            let (db, remaining, _, _) =
                fault_database_path(f.c.paths.installation.files()[1], after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                DeviceJournal::reserve_credential_cancellation_in_database(
                    &db,
                    &key,
                    &f.original,
                    f.c.policy.historical(),
                    f.id,
                    proof.historical(),
                    None,
                ),
                after,
            );
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            drop(db);
            let failed = disk(&f);
            assert_eq!(failed.0, original);
            let cancellation = reserve(&f, 250);
            let retried = disk(&f);
            assert_eq!(retried.0, original);
            if failed.1.is_some() {
                assert_eq!(retried.1, failed.1);
            }
            assert_eq!(reserve(&f, 250), cancellation);
            close(&f, &proof, cancellation);
            assert_eq!(reconcile(&f, &proof, 250), closed(&proof));
            assert_eq!(disk(&f), (original, None));
            cuts += 1;
        }
    }
    eprintln!("cancellation journal reservation cuts={cuts}");
}

#[test]
fn cancellation_never_replaces_full_proposals_or_rebases_missing_retained_reservation() {
    let f = fixture();
    let proof = grant(&f, &f.original, 2, 190);
    prepare(&f, &proof, 150);
    let saved = disk(&f);
    assert!(open(&f.c)
        .prepare_witnessed_credential_cancellation(&f.c.policy, 250)
        .is_err());
    assert_eq!(disk(&f), saved);
    let (f, _) = staged();
    reserve(&f, 150);
    {
        let db = open_private_database(f.c.paths.installation.files()[1]).expect("journal");
        let tx = db.begin_write().expect("fixture corruption");
        tx.open_table(JOURNAL)
            .expect("table")
            .remove("pending")
            .expect("remove fixture reservation");
        tx.commit().expect("fixture commit");
    }
    let saved = disk(&f);
    assert!(matches!(
        open(&f.c).prepare_witnessed_credential_cancellation(&f.c.policy, 250),
        Err(DurableError::Conflict)
    ));
    assert_eq!(disk(&f), saved);
}

#[test]
fn cancellation_terminal_and_retirement_configuration_sync_cuts_never_ack_an_unsaved_terminal() {
    let setup = || {
        let (f, proof) = staged();
        let cancellation = reserve(&f, 150);
        close(&f, &proof, cancellation);
        (f, proof)
    };
    let (f, proof) = setup();
    let (mut owner, _, count) = faulty(&f.c, false);
    let mut anchor = client(&f, &mut owner, 150);
    count.store(0, Ordering::SeqCst);
    owner
        .reconcile_witnessed_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &f.c.policy,
            150,
            &mut anchor,
        )
        .expect("calibrate");
    let syncs = count.load(Ordering::SeqCst);
    owner.close();
    assert!((2..=12).contains(&syncs));
    let mut cuts = 0;
    for after in [false, true] {
        for cut in 1..=syncs {
            let (f, proof) = setup();
            let original = disk(&f).0;
            let (mut owner, remaining, _) = faulty(&f.c, after);
            let mut anchor = client(&f, &mut owner, 150);
            let before = f.carrier.requests.lock().expect("requests").len();
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.reconcile_witnessed_credential_renewal(
                    proof.operation(),
                    proof.statement_digest(),
                    &f.c.policy,
                    150,
                    &mut anchor,
                ),
                after,
            );
            assert!(owner.active.is_none());
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            let status = open(&f.c)
                .credential_renewal_status()
                .expect("durable state");
            let acked = f
                .carrier
                .requests
                .lock()
                .expect("requests")
                .get(before..)
                .expect("prefix")
                .contains(&8);
            if acked {
                assert_eq!(status, closed(&proof), "ACK requires saved Closed");
            }
            if status == renewal::pending(&proof) {
                assert!(!acked);
            }
            f.carrier.clock.store(250, Ordering::SeqCst);
            f.c.policy.close();
            assert_eq!(reconcile(&f, &proof, 250), closed(&proof));
            assert_eq!(disk(&f), (original, None));
            cuts += 1;
        }
    }
    eprintln!("cancellation terminal configuration cuts={cuts}");
}

#[test]
fn cancellation_retirement_journal_sync_cuts_preserve_exact_closed_proof() {
    use crate::durable::WitnessedCredentialIntent;
    let setup = || {
        let (f, proof) = staged();
        let cancellation = reserve(&f, 150);
        close(&f, &proof, cancellation);
        *f.carrier.cut.lock().expect("cut") = Some((8, false));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 150);
        assert!(owner
            .reconcile_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                150,
                &mut anchor
            )
            .is_err());
        (f, proof, cancellation)
    };
    let (f, _, cancellation) = setup();
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    let terminal = owner
        .persisted_witness_intent_terminal(
            f.c.policy.historical(),
            150,
            WitnessedCredentialIntent::Cancellation(cancellation),
        )
        .expect("durable terminal");
    let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
    let (db, _, count, _) = fault_database_path(f.c.paths.installation.files()[1], false);
    count.store(0, Ordering::SeqCst);
    DeviceJournal::retire_witnessed_credential_intent_in_database(
        &db,
        &key,
        &f.original,
        &f.c.policy,
        f.id,
        &terminal,
        &mut anchor,
    )
    .expect("calibrate");
    let syncs = count.load(Ordering::SeqCst);
    count.store(0, Ordering::SeqCst);
    DeviceJournal::retire_witnessed_credential_intent_in_database(
        &db,
        &key,
        &f.original,
        &f.c.policy,
        f.id,
        &terminal,
        &mut anchor,
    )
    .expect("exact absent retry");
    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(db);
    owner.close();
    assert!((1..=8).contains(&syncs));
    let mut cuts = 0;
    for after in [false, true] {
        for cut in 1..=syncs {
            let (f, proof, cancellation) = setup();
            let saved = disk(&f);
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 150);
            let terminal = owner
                .persisted_witness_intent_terminal(
                    f.c.policy.historical(),
                    150,
                    WitnessedCredentialIntent::Cancellation(cancellation),
                )
                .expect("durable terminal");
            let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
            let (db, remaining, _, _) =
                fault_database_path(f.c.paths.installation.files()[1], after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                DeviceJournal::retire_witnessed_credential_intent_in_database(
                    &db,
                    &key,
                    &f.original,
                    &f.c.policy,
                    f.id,
                    &terminal,
                    &mut anchor,
                ),
                after,
            );
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            drop(db);
            owner.close();
            let failed = disk(&f);
            assert_eq!(failed.0, saved.0);
            assert!(failed.1.is_none() || failed.1 == saved.1);
            f.carrier.clock.store(250, Ordering::SeqCst);
            f.c.policy.close();
            assert_eq!(reconcile(&f, &proof, 250), closed(&proof));
            assert_eq!(disk(&f), (saved.0, None));
            cuts += 1;
        }
    }
    eprintln!("cancellation intent retirement cuts={cuts}");
}

#[test]
fn cancellation_closed_cannot_ack_or_erase_a_full_proposal_with_the_same_operation() {
    let (f, proof) = staged();
    let config = fs::read(&f.c.paths.configuration).expect("staged config backup");
    let journal = fs::read(f.c.paths.installation.files()[1]).expect("original journal backup");
    let mut owner = open(&f.c);
    let anchor = client(&f, &mut owner, 150);
    owner
        .prepare_witnessed_credential_renewal(&f.c.policy, 150, anchor)
        .expect("local proposal only");
    owner.close();
    let proposal_intent = disk(&f).1.expect("QPWINT02");
    fs::write(&f.c.paths.configuration, config).expect("restore staged fixture");
    fs::write(f.c.paths.installation.files()[1], journal).expect("restore original fixture");
    let cancellation = reserve(&f, 150);
    close(&f, &proof, cancellation);
    *f.carrier.cut.lock().expect("cut") = Some((8, false));
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    assert!(owner
        .reconcile_witnessed_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &f.c.policy,
            150,
            &mut anchor
        )
        .is_err());
    {
        let db = open_private_database(f.c.paths.installation.files()[1]).expect("journal");
        let tx = db.begin_write().expect("adversarial replacement");
        tx.open_table(JOURNAL)
            .expect("table")
            .insert("pending", proposal_intent.as_slice())
            .expect("same operation different kind");
        tx.commit().expect("fixture commit");
    }
    let saved = disk(&f);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 250);
    let before = f.carrier.requests.lock().expect("requests").len();
    assert!(matches!(
        owner.reconcile_witnessed_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &f.c.policy,
            250,
            &mut anchor
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        f.carrier.requests.lock().expect("requests").len(),
        before,
        "refuse before ACK"
    );
    assert_eq!(disk(&f), saved);
    assert_eq!(
        open(&f.c)
            .credential_renewal_status()
            .expect("retained Closed"),
        closed(&proof)
    );
}

#[test]
fn authenticated_cancellation_configuration_rejects_downgrade_and_applied_disposition() {
    for corruption in ["downgrade", "applied"] {
        let (f, _) = staged();
        reserve(&f, 150);
        let key = JournalKey::open(&f.c.paths.wrapping).expect("key");
        {
            let db = open_private_database(&f.c.paths.configuration).expect("config");
            let tx = db.begin_write().expect("fixture transaction");
            {
                let mut table = tx.open_table(TABLE).expect("table");
                let mut bytes = table
                    .get("enrollment")
                    .expect("lookup")
                    .expect("present")
                    .value()
                    .to_vec();
                assert_eq!(bytes.get(..8), Some(b"QPENST05".as_slice()));
                let body_len = bytes.len() - 32;
                match corruption {
                    "downgrade" => bytes
                        .get_mut(..8)
                        .expect("tag")
                        .copy_from_slice(b"QPENST04"),
                    "applied" => *bytes.get_mut(body_len - 1).expect("terminal") = 1,
                    _ => unreachable!("fixed cases"),
                }
                let mut mac = auth(&key).expect("fixture MAC");
                mac.update(bytes.get(..body_len).expect("body"));
                bytes
                    .get_mut(body_len..)
                    .expect("MAC")
                    .copy_from_slice(&mac.finalize().into_bytes());
                table
                    .insert("enrollment", bytes.as_slice())
                    .expect("authenticated invalid fixture");
            }
            tx.commit().expect("commit");
        }
        let saved = disk(&f);
        assert!(DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err());
        assert_eq!(disk(&f), saved);
    }
}
