// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::*;
#[path = "witness_handoff_tests/fixture.rs"]
mod fixture;
#[path = "witness_handoff_tests/transfer.rs"]
pub(super) mod transfer;
use fixture::Fixture;
#[path = "witness_handoff_tests/faults.rs"]
mod faults;
#[path = "witness_handoff_tests/process.rs"]
pub(super) mod process;
#[path = "witness_handoff_tests/validation.rs"]
mod validation;
pub(super) fn process_boundary(stage: &str, after: bool) {
    process::boundary(stage, after);
}

#[test]
fn enrollment_witness_selection_reopens_original_signer_and_operational_installation() {
    let f = Fixture::new();
    let signer = fs::read(&f.c.paths.signer).expect("original protected signer");
    let wrap = fs::read(&f.c.paths.wrapping).expect("original wrapping key");
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || Ok(180))
            .expect("parent preparation"),
        WitnessJournalAdoptionState::Prepared
    );
    assert!(owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            f.carrier(),
            Duration::from_secs(3)
        )
        .is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .adopt_witness_handoff(
                f.c.policy.historical(),
                f.transfer.plan.clone(),
                &f.transfer.receipt
            )
            .expect("child and parent"),
        WitnessJournalAdoptionState::Adopted
    );
    owner.close();
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .witness_handoff_status(f.c.policy.historical(), f.transfer.plan.clone())
            .expect("original selection"),
        WitnessJournalAdoptionState::Adopted
    );
    let client = owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            f.carrier(),
            Duration::from_secs(3),
        )
        .expect("retained signer factory");
    let mut active = owner
        .activate(&f.c.policy, 190, Some(client))
        .expect("same installation");
    let (service, _, device) = active.parts().expect("controlled owners");
    let journal = service.stores().expect("original children").0;
    assert_eq!(journal.identity().expect("ID"), f.identity);
    let retained = journal
        .prekey_leaf(&f.c.policy, device, f.prekey, 190)
        .expect("original prekey");
    assert_eq!(retained.public_key(), f.leaf.public_key());
    assert_eq!(retained.kind(), f.leaf.kind());
    assert_eq!(retained.validity(), f.leaf.validity());
    journal
        .generate_prekey(
            &f.c.policy,
            device,
            PrekeyId::from_trusted_state([74; 32]).expect("new ID"),
            LeafKind::OneTimePq,
            interval(),
            190,
        )
        .expect("new work under current witness");
    active.close();
    assert_eq!(fs::read(&f.c.paths.signer).expect("same signer"), signer);
    assert_eq!(fs::read(&f.c.paths.wrapping).expect("same wrapping"), wrap);
    let mut owner = open(&f.c);
    let client = owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            f.carrier(),
            Duration::from_secs(3),
        )
        .expect("cold parent and journal reopen");
    owner
        .activate(&f.c.policy, 190, Some(client))
        .expect("reopened original owner")
        .close();
}

#[test]
fn enrollment_witness_selection_refuses_old_journal_backup_before_dispatch() {
    let f = Fixture::new();
    let old = fs::read(f.c.paths.installation.files()[1]).expect("old exact journal backup");
    let mut owner = open(&f.c);
    owner
        .prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || Ok(180))
        .expect("prepare");
    owner
        .adopt_witness_handoff(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            &f.transfer.receipt,
        )
        .expect("adopt");
    owner.close();
    let current = fs::read(f.c.paths.installation.files()[1]).expect("selected journal backup");
    fs::write(f.c.paths.installation.files()[1], old).expect("simulate journal-only rollback");
    let mut owner = open(&f.c);
    assert!(owner
        .prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || Ok(180))
        .is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    let mut owner = open(&f.c);
    assert!(owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            f.carrier(),
            Duration::from_secs(3)
        )
        .is_err());
    let mut owner = open(&f.c);
    assert!(owner
        .anchor_client(
            &f.c.policy,
            190,
            f.origin.clone(),
            f.carrier(),
            Duration::from_secs(3)
        )
        .is_err());
    assert_eq!(
        f.transfer
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no request may escape the stale child admission checks"
    );
    fs::write(f.c.paths.installation.files()[1], current).expect("restore exact original metadata");
    let mut owner = open(&f.c);
    let client = owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            f.carrier(),
            Duration::from_secs(3),
        )
        .expect("exact original recovery");
    owner
        .activate(&f.c.policy, 190, Some(client))
        .expect("same state restored")
        .close();
}
