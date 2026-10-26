// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Existing root and witness transactions remain mutually exclusive, not merged.
use super::*;
use crate::{
    AccountRootEnrollmentRecovery, AccountRootEnrollmentState, AnchorAccountReplacementId,
    AnchorAccountReplacementProposal, AnchorRequirement, InstallationPreparation,
};

fn proposal(
    f: &Fixture,
) -> (
    crate::enrollment::tests::Case,
    AnchorAccountReplacementProposal,
) {
    let target = case_with_anchor(AnchorRequirement::required(&f.pin));
    let (mut owner, _, _) = accepted(&target);
    let image = owner.image().expect("accepted target");
    let device = owner
        .original_device_metadata(&image)
        .expect("target credential");
    let genesis = match owner
        .prepare(&target.policy, 150)
        .expect("real inactive target installation")
    {
        InstallationPreparation::RequiresEnrollment(genesis) => Ok(genesis),
        _ => Err("required witness target"),
    }
    .expect("target genesis");
    owner.close();
    assert_eq!(target.policy.checkpoint(), f.c.policy.checkpoint());
    let p = f
        .carrier
        .store
        .lock()
        .expect("original witness")
        .account_root_replacement_proposal(
            AnchorAccountReplacementId::generate().expect("independent root operation"),
            &f.c.intent.root,
            &genesis,
            &device,
            &f.c.policy,
            150,
        )
        .expect("real independently prepared account-root replacement proposal");
    (target, p)
}
fn parent_rows(f: &Fixture) -> Vec<(String, Vec<u8>)> {
    let db = open_private_database(&f.c.paths.configuration).expect("closed owned enrollment");
    let read = db.begin_read().expect("read");
    let table = read.open_table(TABLE).expect("parent table");
    table
        .iter()
        .expect("rows")
        .map(|row| {
            let (key, value) = row.expect("row");
            (key.value().to_owned(), value.value().to_vec())
        })
        .collect()
}
fn first(f: &Fixture) -> Transfer {
    let subject =
        AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
    Transfer::new(
        &mut f.carrier.store.lock().expect("A"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        151,
    )
}

#[test]
fn enrollment_witness_successive_selection_cannot_overwrite_existing_account_root_intent() {
    let f = fixture();
    let (_target, proposal) = proposal(&f);
    let mut recovery = activate(&f, 150)
        .expect("original owner")
        .begin_account_root_replacement(f.pin.clone(), proposal.clone())
        .expect("actual original root intent and child fence");
    assert_eq!(
        recovery.status().expect("retained root"),
        AccountRootEnrollmentState::IntentRetained
    );
    recovery.close();
    let before = disk(&f);
    let parent = parent_rows(&f);
    let first = first(&f);
    let subject =
        AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
    let second = first.successor(
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        (154, 99),
    );
    for selected in [&first, &second] {
        assert!(
            matches!(
                DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()),
                Err(DurableError::Suspended)
            ),
            "public open refuses the existing root transaction before returning an owner"
        );
        // Also exercise the internal guard used after restricted storage open;
        // this raw owner is deliberately not a public recovery entry point.
        let mut owner =
            DeviceEnrollment::open_original_storage(f.c.paths.clone(), f.c.intent.clone())
                .expect("owned restricted storage admission");
        assert!(matches!(
            owner.prepare_witness_handoff(f.c.policy.historical(), selected.plan.clone(), || Ok(
                155
            )),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        assert_eq!(disk(&f), before);
        assert_eq!(parent_rows(&f), parent);
        assert_eq!(
            selected.requests.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
    let mut recovery = AccountRootEnrollmentRecovery::resume_original(
        f.c.paths.clone(),
        f.c.intent.clone(),
        f.pin.clone(),
        proposal.clone(),
    )
    .expect("same original root recovery");
    assert_eq!(
        recovery.proposal().expect("unchanged root proposal"),
        proposal
    );
    recovery.close();
    assert_eq!(parent_rows(&f), parent);
}

#[test]
fn enrollment_witness_successive_selection_refuses_legacy_root_transaction_without_mutation() {
    for twice in [false, true] {
        let f = fixture();
        let (_target, proposal) = proposal(&f);
        let first = first(&f);
        first.adopt_parent(&f.c, 152).close();
        let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
        let second = if twice {
            let next = first.successor(
                &f.c,
                &f.original,
                &f.original,
                f.c.policy.historical(),
                subject,
                (154, 99),
            );
            next.adopt_parent(&f.c, 155).close();
            Some(next)
        } else {
            None
        };
        let selected = second.as_ref().unwrap_or(&first);
        selected.set_time(156);
        let parent = parent_rows(&f);
        let before = disk(&f);
        let mut owner = open(&f.c);
        let carrier = selected.client(&mut owner, &f.c);
        let active = owner
            .activate(&f.c.policy, 156, Some(carrier))
            .expect("valid selected owner");
        let error = active
            .begin_account_root_replacement(f.pin.clone(), proposal.clone())
            .err();
        assert!(
            matches!(&error, Some(DurableError::Conflict)),
            "legacy root entry must reject the selected Witness before child preflight: {error:?}"
        );
        let error = AccountRootEnrollmentRecovery::resume_original(
            f.c.paths.clone(),
            f.c.intent.clone(),
            f.pin.clone(),
            proposal,
        )
        .err();
        assert!(
            matches!(&error, Some(DurableError::Conflict)),
            "cold legacy root recovery must reject the same selected Witness: {error:?}"
        );
        assert_eq!(
            parent_rows(&f),
            parent,
            "legacy root path cannot replace retained Witness selection"
        );
        assert_eq!(disk(&f), before);
        let mut owner = open(&f.c);
        let carrier = selected.client(&mut owner, &f.c);
        owner
            .activate(&f.c.policy, 156, Some(carrier))
            .expect("same original selected installation after refused root")
            .close();
    }
}
