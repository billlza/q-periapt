// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::ManagedAccountRootAdoption;
#[path = "adoption/process.rs"]
mod process;

struct Adoption {
    s: Setup,
    // None deliberately reuses the original plan's prepared, never-active target.
    target: Option<Account>,
    other: Option<AccountAuthorityCheckpoint>,
    proposal: Proposal,
    noncommit: Vec<u8>,
    receipt: Vec<u8>,
    approved: ManagedAccountRootAdoption,
}
impl Adoption {
    fn new(bound: bool, until: u64, cross_application: bool) -> (Self, Managed) {
        let (s, mut registry, original) = Setup::new(until);
        let target = cross_application.then(|| {
            account(
                &s.f._dir
                    .path()
                    .canonicalize()
                    .expect("private base")
                    .join("other-application-target"),
                &s.f.policy,
            )
        });
        let other = target.as_ref().map(|target| {
            registry
                .associate(
                    ApplicationAccountId::from_trusted_state([106; 32]).expect("other application"),
                    &target.device,
                )
                .expect("independently associated other account")
        });
        let mut managed = s.begin(registry, original);
        if bound {
            managed
                .bind_witness_freeze(&s.freeze())
                .expect("original local binding");
        }
        let winner = target.as_ref().unwrap_or(&s.f.target);
        let (proposal, noncommit, receipt) = {
            let mut witness = s.f.witness.lock().expect("witness");
            let frozen = if bound {
                witness
                    .account_freeze(s.plan.request())
                    .expect("same bound original snapshot")
            } else {
                let competing = AnchorAccountFreezeRequest::from_trusted_state(
                    AnchorAccountFreezeId::from_trusted_state([107; 32])
                        .expect("competing freeze identity"),
                    s.f.original.root.public_key().expect("old root"),
                    &s.f.pin,
                )
                .expect("separate approved competing request");
                let frozen = witness
                    .freeze_account(&competing)
                    .expect("competing freeze wins");
                assert!(matches!(
                    witness.freeze_account(s.plan.request()),
                    Err(DurableError::Conflict)
                ));
                frozen
            };
            let proposal = witness
                .frozen_account_replacement_proposal(
                    AnchorAccountReplacementId::from_trusted_state([108; 32])
                        .expect("winning operation"),
                    &frozen,
                    &winner.genesis,
                    &winner.device,
                    &s.f.policy,
                    150,
                )
                .expect("independently approved exact winner");
            witness
                .replace_account_root(
                    &proposal,
                    &s.f.original.root.public_key().expect("old root"),
                    &winner.genesis,
                    &winner.device,
                    &s.f.policy,
                    150,
                )
                .expect("actual competing commit");
            witness
                .close_account_preparation(&s.plan)
                .expect("permanent losing-plan non-commit");
            let noncommit = witness
                .closed_account_preparation_receipt(&s.plan)
                .expect("signed losing-plan terminal decision");
            let receipt = witness
                .retired_account_receipt(&proposal)
                .expect("signed actual winner");
            (proposal, noncommit, receipt)
        };
        let approved = ManagedAccountRootAdoption::verify(
            &s.f.pin,
            &s.plan,
            proposal.clone(),
            &noncommit,
            &receipt,
        )
        .expect("independent exact approval and authenticated outcomes");
        (
            Self {
                s,
                target,
                other,
                proposal,
                noncommit,
                receipt,
                approved,
            },
            managed,
        )
    }
    fn winner(&self) -> &Account {
        self.target.as_ref().unwrap_or(&self.s.f.target)
    }
    fn resume(&self) -> Managed {
        Managed::resume_adoption(
            self.s.registry(),
            self.s.expected,
            self.s.f.original.paths.clone(),
            self.s.f.original.intent.clone(),
            self.s.f.pin.clone(),
            &self.approved,
        )
        .expect("reconcile original committed adoption")
    }
    fn activate(&self, managed: &mut Managed, now: u64) -> Result<EnrolledDevice, DurableError> {
        let target = self.winner();
        let enrollment = DeviceEnrollment::open(target.paths.clone(), target.intent.clone())?;
        managed.activate_successor(
            enrollment,
            &self.s.f.policy,
            now,
            Box::new(Carrier(Arc::clone(&self.s.f.witness))),
            Duration::from_secs(3),
        )
    }
    fn finish(&self, managed: &mut Managed) {
        let checkpoint = managed
            .adopt_committed_winner(&self.approved)
            .expect("adopt exact original winner");
        assert_eq!(checkpoint.account(), self.winner().device.account_id());
        assert_eq!(checkpoint.revision(), 2);
        assert_eq!(
            managed
                .adopt_committed_winner(&self.approved)
                .expect("idempotent adoption"),
            checkpoint
        );
        assert_eq!(
            managed
                .retain_witness_retirement(&self.receipt)
                .expect("same historical retirement"),
            checkpoint
        );
        assert!(
            managed.retain_witness_noncommit(&self.noncommit).is_err(),
            "adopted winner must not manufacture a local preparation"
        );
        assert_eq!(
            managed
                .state()
                .expect("known preparation refusal preserves completed owner"),
            State::Committed
        );
        let mut current = self
            .activate(managed, 150)
            .expect("current witness admission of real successor");
        current
            .next_prekey_publication_id()
            .expect("controlled successor operation");
        managed.close();
        assert!(matches!(
            current.next_prekey_publication_id(),
            Err(DurableError::Closed)
        ));
        current.close();
        self.s.f.assert_fenced();
        let registry = self.s.registry();
        assert_eq!(
            registry
                .preparation(self.s.plan.operation())
                .expect("original loss remains recorded")
                .1,
            State::Closed
        );
        assert!(
            matches!(
                registry.preparation(self.proposal.operation()),
                Err(DurableError::Conflict)
            ),
            "adopted history has no fabricated plan"
        );
        assert_eq!(
            registry
                .replacement(self.proposal.operation())
                .expect("exact adopted statement")
                .2,
            &self.proposal
        );
        assert_eq!(
            registry
                .access()
                .expect("fresh access")
                .current(self.s.expected.application())
                .expect("same successor mapping"),
            checkpoint
        );
    }
}

#[test]
fn managed_root_adopts_only_the_approved_committed_winner_with_no_fabricated_plan() {
    for bound in [false, true] {
        let (a, mut managed) = Adoption::new(bound, 200, false);
        a.finish(&mut managed);
        let mut managed = a.resume();
        a.finish(&mut managed);
    }
}

#[test]
fn managed_root_adoption_receipts_cannot_choose_the_winner_or_replace_approval() {
    let (a, mut managed) = Adoption::new(false, 200, false);
    let mut bad = a.receipt.clone();
    *bad.last_mut().expect("signed retirement") ^= 1;
    assert!(ManagedAccountRootAdoption::verify(
        &a.s.f.pin,
        &a.s.plan,
        a.proposal.clone(),
        &a.noncommit,
        &bad
    )
    .is_err());
    let mut bytes = a.proposal.to_bytes().expect("approved statement");
    *bytes.last_mut().expect("frozen commitment") ^= 1;
    let different = Proposal::from_trusted_state(&bytes).expect("parseable but unapproved winner");
    assert!(ManagedAccountRootAdoption::verify(
        &a.s.f.pin,
        &a.s.plan,
        different,
        &a.noncommit,
        &a.receipt
    )
    .is_err());
    assert!(ManagedAccountRootAdoption::verify(
        &a.s.f.pin,
        &a.s.plan,
        a.proposal.clone(),
        &a.receipt,
        &a.receipt
    )
    .is_err());
    assert_eq!(
        managed
            .state()
            .expect("invalid proofs did not mutate original owner"),
        State::Preparing
    );
    a.finish(&mut managed);
}

fn original_parent(a: &Adoption) -> (Vec<u8>, Option<Vec<u8>>) {
    let db = open_private_database(&a.s.f.original.paths.configuration)
        .expect("quiescent original parent");
    parent_rows(&db)
}

#[test]
fn managed_root_adoption_checks_registry_admission_before_changing_the_parent() {
    let (a, mut managed) = Adoption::new(true, 200, true);
    managed.close();
    let before = original_parent(&a);
    let mut managed = a.s.resume();
    assert!(
        managed.adopt_committed_winner(&a.approved).is_err(),
        "a valid witness fact cannot reuse another application account's root"
    );
    assert!(
        matches!(managed.state(), Err(DurableError::Closed)),
        "original non-commit may already be durable"
    );
    assert!(
        before == original_parent(&a),
        "registry refusal must precede any parent target or retirement change"
    );
    let registry = a.s.registry();
    assert_eq!(
        registry
            .preparation(a.s.plan.operation())
            .expect("original closure retained")
            .1,
        State::Closed
    );
    assert!(matches!(
        registry.replacement(a.proposal.operation()),
        Err(DurableError::Absent)
    ));
    let other = a.other.expect("independently retained other application");
    assert_eq!(
        registry
            .access()
            .expect("fresh registry access")
            .current(other.application())
            .expect("other mapping preserved"),
        other
    );
}

#[test]
fn managed_root_adoption_history_cannot_extend_an_expired_winner_credential() {
    let (a, mut managed) = Adoption::new(false, 160, false);
    managed
        .adopt_committed_winner(&a.approved)
        .expect("historical commit at time 150");
    assert!(matches!(
        a.activate(&mut managed, 170),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let mut managed = a.resume();
    assert_eq!(
        managed
            .state()
            .expect("original historical result remains available"),
        State::Committed
    );
    managed.close();
    a.s.f.assert_fenced();
}
