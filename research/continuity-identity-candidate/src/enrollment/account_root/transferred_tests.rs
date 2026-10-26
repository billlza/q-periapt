// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::*;

#[path = "transferred_tests/fixture.rs"]
mod fixture;
#[path = "transferred_tests/managed.rs"]
mod managed;
#[path = "transferred_tests/preparation.rs"]
mod preparation;
#[path = "transferred_tests/process.rs"]
mod process;
#[path = "transferred_tests/recovery.rs"]
mod recovery;
#[path = "transferred_tests/registry.rs"]
mod registry;
#[path = "transferred_tests/target_activation.rs"]
mod target_activation;
use fixture::Transferred;
#[path = "transferred_tests/cleanup.rs"]
mod cleanup;
#[path = "transferred_tests/client_cleanup.rs"]
mod client_cleanup;
#[path = "transferred_tests/mixed_cleanup.rs"]
mod mixed_cleanup;
#[path = "transferred_tests/next_attempt.rs"]
mod next_attempt;
#[path = "transferred_tests/parent_cleanup.rs"]
mod parent_cleanup;

const JOURNAL: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("continuity_device_candidate_v21");
fn journal_rows(t: &Transferred) -> Vec<(String, Vec<u8>)> {
    let db =
        open_private_database(t.f.original.paths.installation.files()[1]).expect("original child");
    let tx = db.begin_read().expect("read child");
    let table = tx.open_table(JOURNAL).expect("child table");
    table
        .iter()
        .expect("child rows")
        .map(|row| {
            let (k, v) = row.expect("row");
            (k.value().to_string(), v.value().to_vec())
        })
        .filter(|(name, _)| name != "account-root-fence")
        .collect()
}
fn original_parent(t: &Transferred) -> Vec<u8> {
    parent_rows(&open_private_database(&t.f.original.paths.configuration).expect("same parent")).0
}

#[test]
fn transferred_root_parent_legacy_entry_refuses_before_retaining_incompatible_intent() {
    let t = Transferred::new();
    assert_eq!(
        t.target.pin().expect("active B").binding(),
        t.history.current_pin().binding()
    );
    assert_eq!(
        t.policy.anchor_requirement().binding(),
        Some(t.history.current_pin().binding())
    );
    assert_eq!(
        t.approval.proposal().successor(),
        t.successor.genesis.subject()
    );
    assert!(matches!(
        AccountRootEnrollmentRecovery::resume_original(
            t.f.original.paths.clone(),
            t.f.original.intent.clone(),
            t.history.current_pin().clone(),
            t.approval.proposal().clone()
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let db =
        open_private_database(&t.f.original.paths.configuration).expect("same original parent");
    assert!(
        parent_rows(&db).1.is_none(),
        "a rejected current-Witness proposal must not poison the legacy parent intent"
    );
}

#[test]
fn transferred_root_parent_keeps_real_pending_and_witness_selection_for_each_decision() {
    for stage in [None, Some(0), Some(1), Some(2)] {
        for selection in 0..=2 {
            for closed in [false, true] {
                let mut t = Transferred::at(stage, selection);
                let rows = journal_rows(&t);
                let parent = original_parent(&t);
                let key = fs::read(&t.f.original.paths.wrapping).expect("original key bytes");
                let signer =
                    fs::read(&t.f.original.paths.signer).expect("original sealed signer bytes");
                assert_eq!(
                    rows.iter().any(|(name, _)| name == "pending"),
                    stage.is_some()
                );
                let mut owner = t
                    .open()
                    .expect("original parent with exact current authority");
                assert_eq!(
                    owner.status().expect("retained original"),
                    AccountRootEnrollmentState::IntentRetained
                );
                let outcome = t.decide(closed);
                let expected = if closed {
                    AccountRootEnrollmentState::WitnessClosed
                } else {
                    AccountRootEnrollmentState::WitnessCommitted
                };
                assert_eq!(
                    owner
                        .retain_account_decision(outcome.as_bytes())
                        .expect("child then parent outcome"),
                    expected
                );
                owner.close();
                let mut recovered = t.open().expect("same parent cold recovery");
                assert_eq!(recovered.status().expect("permanent outcome"), expected);
                assert_eq!(
                    recovered
                        .account_decision()
                        .expect("same exact signed result")
                        .as_bytes(),
                    outcome.as_bytes()
                );
                recovered.close();
                t.f.assert_fenced();
                assert!(
                    journal_rows(&t) == rows,
                    "original child image/pending/selection changed"
                );
                assert!(
                    original_parent(&t) == parent,
                    "original parent image changed"
                );
                assert!(
                    fs::read(&t.f.original.paths.wrapping).expect("retained key") == key,
                    "original key changed"
                );
                assert!(
                    fs::read(&t.f.original.paths.signer).expect("retained signer") == signer,
                    "original sealed signer changed"
                );
                eprintln!("TRANSFERRED_ROOT_PARENT stage={stage:?} selection={selection} closed={closed} original_rows=true original_secrets=true");
            }
        }
    }
}

#[test]
fn transferred_root_parent_reconciles_verified_selection_ahead_without_rewriting_child() {
    for selection in 3..=5 {
        let t = Transferred::at(Some(2), selection);
        let child = journal_rows(&t);
        let parent = original_parent(&t);
        t.open()
            .expect("verified child selection precedes parent root intent")
            .close();
        assert!(
            journal_rows(&t) == child,
            "original child image/pending/selection changed"
        );
        assert!(
            original_parent(&t) == parent,
            "original parent image changed"
        );
        t.open().expect("exact reconciled parent retry").close();
        t.f.assert_fenced();
    }
}

#[test]
fn transferred_root_parent_rejects_backup_losing_pending_before_reconstructing_child_fence() {
    let t = Transferred::at(Some(0), 0);
    let path = t.f.original.paths.installation.files()[1];
    let exact = fs::read(path).expect("original image and P target");
    t.open().expect("independent parent checkpoint").close();
    fs::write(path, &t.pre_pending).expect("owned backup loses only pending work");
    assert!(matches!(t.open(), Err(DurableError::Conflict)));
    fs::write(path, exact).expect("restore original P");
    t.open()
        .expect("same exact retained parent can reconstruct missing fence")
        .close();
}

#[test]
fn transferred_root_parent_consumes_live_enrolled_owner_without_reopening_signer() {
    let mut t = Transferred::with_live_owner();
    let plan = t.plan();
    let mut owner = t
        .live
        .take()
        .expect("actual enrolled owner")
        .begin_transferred_account_root_replacement(plan)
        .expect("consume original service and signer");
    let decision = t.decide(false);
    assert_eq!(
        owner
            .retain_account_decision(decision.as_bytes())
            .expect("original parent result"),
        AccountRootEnrollmentState::WitnessCommitted
    );
    owner.close();
    t.f.assert_fenced();
}
