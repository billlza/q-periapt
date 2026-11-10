// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual G/R/cancellation survive handoff, root retirement and original cleanup.
use super::fixture::Work;
use super::parent_cleanup::{commit_managed, resume_managed};
use super::*;
use crate::retired_device::{Intent, JournalErasureState, RecordMetadata, ViewRole};

fn run(work: Work, selection: u8) {
    let mut flow = commit_managed(Transferred::with_pending(work, selection));
    let original = journal_rows(&flow.t);
    let parent = original_parent(&flow.t);
    let key = fs::read(&flow.t.f.original.paths.wrapping).expect("same original wrapping bytes");
    let signer = fs::read(&flow.t.f.original.paths.signer).expect("original signing bytes");
    let expected = flow.t.expected_intent.clone();
    let mut owner = resume_managed(&flow).expect("same committed controller");
    let (ack, report_id) = owner
        .with_retired_cleanup(|parent| {
            let child = parent.installation()?;
            let (report, verified, previous) = flow.report(child);
            assert_eq!(
                report.intent(),
                &expected,
                "exact public transaction and original logical operation"
            );
            let roles = report.views().iter().map(|v| v.role).collect::<Vec<_>>();
            let wanted = match work {
                Work::Credential(0) | Work::Roster(0) => {
                    vec![ViewRole::Authoritative, ViewRole::UncommittedTarget]
                }
                Work::Credential(1) | Work::Roster(1) => {
                    vec![ViewRole::SupersededSource, ViewRole::Authoritative]
                }
                Work::Credential(2) | Work::Roster(2) | Work::Cancellation(_) => {
                    vec![ViewRole::Authoritative]
                }
                _ => return Err(DurableError::Corrupt),
            };
            assert_eq!(roles, wanted);
            let prekey = PrekeyId::from_trusted_state([199; 32]).expect("actual original prekey");
            assert!(
                report.views().iter().all(|v| v.records.iter().any(
                    |r| matches!(r.metadata,RecordMetadata::Prekey{request,..}if request==prekey)
                )),
                "retain sealed original prekeys in all actual views"
            );
            assert!(
                journal_rows(&flow.t) == original,
                "report must not apply, discard or reseal pending work"
            );
            assert!(fs::read(&flow.t.f.original.paths.signer).expect("signer") == signer);
            let report_id = *report.proposal().report_id();
            let ack = flow.account(child, &report, &verified, &previous);
            child.erase_journal(flow.context.accounting_pin(), ack.as_bytes())?;
            parent.prepare_signer_erasure(ack.as_bytes())?;
            parent.erase_signer()?;
            Ok((ack.as_bytes().to_vec(), report_id))
        })
        .expect("same controller survives complete original cleanup");
    owner
        .successor_authority()
        .expect("committed mapping retained");
    owner.close();
    assert!(original_parent(&flow.t) == parent);
    assert!(fs::read(&flow.t.f.original.paths.wrapping).expect("original key") == key);
    assert_eq!(
        fs::read(&flow.t.f.original.paths.signer).expect("original signer terminal"),
        b"QPSRET01"
    );
    let mut recovered =
        resume_managed(&flow).expect("same original independent inputs without erased secrets");
    recovered
        .with_retired_cleanup(|parent| {
            assert_eq!(
                parent.signer_erasure_status()?,
                SigningFileErasureState::Erased
            );
            parent.prepare_signer_erasure(&ack)?;
            let child = parent.installation()?;
            assert_eq!(
                child.journal_erasure_status(flow.context.accounting_pin())?,
                JournalErasureState::Erased
            );
            Ok(())
        })
        .expect("cold exact original terminal");
    recovered.close();
    assert!(matches!(
        expected,
        Intent::Write { .. } | Intent::Cancellation(_)
    ));
    assert_ne!(report_id, [0; 32]);
    eprintln!("TRANSFERRED_MIXED_CLEANUP work={work:?} selection={selection} exact_intent=true sealed_prekeys=true original_registry=true journal_erased=true signer_erased=true cold_recovered=true");
}

#[test]
fn transferred_mixed_cleanup_credential_all_three_phases_and_selections() {
    for stage in 0..=2 {
        for selection in 0..=2 {
            run(Work::Credential(stage), selection);
        }
    }
}
#[test]
fn transferred_mixed_cleanup_roster_all_three_phases_and_selections() {
    for stage in 0..=2 {
        for selection in 0..=2 {
            run(Work::Roster(stage), selection);
        }
    }
}
#[test]
fn transferred_mixed_cleanup_target_free_cancellation_and_signed_closed_selections() {
    for closed in [false, true] {
        for selection in 0..=2 {
            run(Work::Cancellation(closed), selection);
        }
    }
}
#[test]
fn transferred_mixed_cleanup_root_closed_preserves_pending_and_refuses_erasure() {
    for work in [
        Work::Credential(0),
        Work::Credential(1),
        Work::Credential(2),
        Work::Roster(0),
        Work::Roster(1),
        Work::Roster(2),
        Work::Cancellation(false),
        Work::Cancellation(true),
    ] {
        let mut t = Transferred::with_pending(work, 2);
        t.controller
            .take()
            .expect("original preparing controller")
            .close();
        let rows = journal_rows(&t);
        let parent = original_parent(&t);
        let signer = fs::read(&t.f.original.paths.signer).expect("original signing bytes");
        let mut owner =
            super::managed::resume(&t).expect("same preparing controller after cold reopen");
        owner
            .bind_transferred_freeze(&t.frozen, t.approval.clone())
            .expect("same approved freeze");
        let closed = t.decide(true);
        owner
            .retain_transferred_decision(closed.as_bytes())
            .expect("permanent noncommit");
        assert!(matches!(
            owner.with_retired_cleanup(|_| Ok(())),
            Err(DurableError::Suspended)
        ));
        owner.close();
        assert!(journal_rows(&t) == rows && original_parent(&t) == parent);
        assert!(fs::read(&t.f.original.paths.signer).expect("original signer retained") == signer);
        t.f.assert_fenced();
        eprintln!("TRANSFERRED_MIXED_CLOSED work={work:?} original_pending=true cleanup_refused=true old_authority_suspended=true");
    }
}
