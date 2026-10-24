// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{fs, path::PathBuf, time::Duration};
mod recovery;
mod support;
mod transferred;
mod validation;
use support::*;

pub(super) fn boundary(stage: &str, after: bool) {
    let Some(path) = std::env::var_os("QPERIAPT_WITNESS_ADOPTION_DIR") else {
        return;
    };
    if std::env::var("QPERIAPT_WITNESS_ADOPTION_CUT")
        .ok()
        .as_deref()
        != Some(format!("{stage}-{}", if after { "after" } else { "before" }).as_str())
    {
        return;
    }
    crate::durable::tests::publish_process_checkpoint(Path::new(&path), stage.as_bytes());
    loop {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn witness_journal_adoption_commits_exact_authority_without_resealing_original_state() {
    let mut c = Case::new(None);
    let before = c.original_rows();
    let mut owner = c
        .journal
        .begin_witness_handoff(c.plan.clone(), || Ok(180))
        .expect("prepare");
    assert!(matches!(c.journal.image(), Err(DurableError::Closed)));
    assert_eq!(
        owner.status().expect("state"),
        WitnessJournalAdoptionState::Prepared
    );
    assert_eq!(rows(&owner.active.as_ref().expect("owner").db), before);
    assert_eq!(
        owner.adopt_authorization(&c.receipt).expect("adopt"),
        WitnessJournalAdoptionState::Adopted
    );
    assert_eq!(rows(&owner.active.as_ref().expect("owner").db), before);
    owner.close();
    c.assert_ordinary_refused();
    let mut owner = c.resume();
    assert_eq!(
        owner
            .authorization_receipt()
            .expect("exact decision")
            .as_bytes(),
        c.receipt
    );
    let before_retry = fs::read(c.path()).expect("original database under the same open lease");
    owner
        .adopt_authorization(&c.receipt)
        .expect("exact historical retry");
    assert!(fs::read(c.path()).expect("no retry rewrite") == before_retry);
    owner.close();
}

#[test]
fn witness_journal_adoption_preserves_real_prepared_and_applied_policy_intents() {
    for applied in [0, 1, 2] {
        let c = Case::new(Some(applied));
        let before = c.original_rows();
        assert!(
            before.1.is_some(),
            "actual sealed original P remains pending"
        );
        let mut owner =
            WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || {
                Ok(180)
            })
            .expect("prepare original with P");
        owner
            .adopt_authorization(&c.receipt)
            .expect("adopt with unresolved P");
        assert_eq!(rows(&owner.active.as_ref().expect("owner").db), before);
        owner.close();
        let mut owner = c.resume();
        assert_eq!(
            owner.status().expect("cold adoption"),
            WitnessJournalAdoptionState::Adopted
        );
        assert_eq!(rows(&owner.active.as_ref().expect("owner").db), before);
    }
}

#[test]
fn witness_journal_adoption_rechecks_preparation_time_and_rejects_foreign_decisions() {
    for times in [[179, 180], [180, 191], [180, 179]] {
        let c = Case::new(Some(0));
        let before = c.original_rows();
        let mut clock = times.into_iter();
        assert!(WitnessJournalAdoption::prepare_original(
            &c.path(),
            c.key(),
            c.plan.clone(),
            || clock.next().ok_or(DurableError::Conflict)
        )
        .is_err());
        assert!(matches!(
            WitnessJournalAdoption::resume_original(&c.path(), c.key(), c.plan.clone()),
            Err(DurableError::Absent)
        ));
        assert_eq!(c.original_rows(), before);
    }
    let c = Case::new(Some(0));
    let other = Case::new(None);
    assert!(WitnessJournalAdoption::prepare_original(
        &c.path(),
        c.key(),
        other.plan.clone(),
        || Ok(180)
    )
    .is_err());
    let mut owner =
        WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || Ok(180))
            .expect("original preparation");
    assert!(owner.adopt_authorization(&other.receipt).is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    let mut owner = c.resume();
    owner
        .adopt_authorization(&c.receipt)
        .expect("exact recovery");
    owner.close();
    let mut original =
        WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || {
            Err(DurableError::Conflict)
        })
        .expect("historical exact preparation retry");
    assert_eq!(
        original.status().expect("state"),
        WitnessJournalAdoptionState::Adopted
    );
}
