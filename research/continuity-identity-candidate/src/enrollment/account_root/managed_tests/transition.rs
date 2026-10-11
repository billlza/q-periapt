// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::ManagedAccountRootTransition;
#[path = "transition/process.rs"]
mod process;

struct CurrentCarrier(Arc<Mutex<AnchorStore>>);
impl AnchorTransport for CurrentCarrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0
            .lock()
            .expect("original witness")
            .handle(request, 170)
            .map_err(io::Error::other)
    }
}
struct Transition {
    s: Setup,
    target: Account,
    next: AnchorAccountReplacementPlan,
    noncommit: Vec<u8>,
    freeze: Vec<u8>,
    approved: ManagedAccountRootTransition,
}
impl Transition {
    fn new(bound: bool) -> (Self, Managed) {
        let (s, registry, original) = Setup::new(160);
        let mut managed = s.begin(registry, original);
        if bound {
            let proposal = managed
                .bind_witness_freeze(&s.freeze())
                .expect("original expired target");
            assert!(matches!(
                s.f.witness.lock().expect("witness").replace_account_root(
                    &proposal,
                    &s.f.original.root.public_key().expect("original root"),
                    &s.f.target.genesis,
                    &s.f.target.device,
                    &s.f.policy,
                    170
                ),
                Err(DurableError::Protocol(Error::Validity))
            ));
        }
        let target = account_at(
            &s.f._dir
                .path()
                .canonicalize()
                .expect("owned root")
                .join("approved-next"),
            &s.f.policy,
            200,
            170,
        );
        let (next, noncommit, freeze) = {
            let mut witness = s.f.witness.lock().expect("witness");
            witness
                .close_account_preparation(&s.plan)
                .expect("independently authorized permanent non-commit");
            let noncommit = witness
                .closed_account_preparation_receipt(&s.plan)
                .expect("signed exact non-commit");
            // Closing a plan does not cancel its original freeze request. This
            // also exercises a freeze arriving after an unbound plan was closed.
            let frozen = witness
                .freeze_account(s.plan.request())
                .expect("original or late freeze");
            let freeze = witness
                .account_freeze_receipt(s.plan.request())
                .expect("signed original snapshot");
            let next = witness
                .frozen_account_replacement_plan(
                    AnchorAccountReplacementId::from_trusted_state([97; 32])
                        .expect("next original operation"),
                    &frozen,
                    &target.genesis,
                    &target.device,
                    &s.f.policy,
                    170,
                )
                .expect("separately approved valid target");
            (next, noncommit, freeze)
        };
        let approved = ManagedAccountRootTransition::verify(
            &s.f.pin,
            &s.plan,
            next.clone(),
            &noncommit,
            &freeze,
        )
        .expect("pinned original proof and independent next approval");
        (
            Self {
                s,
                target,
                next,
                noncommit,
                freeze,
                approved,
            },
            managed,
        )
    }
    fn resume(&self) -> Managed {
        Managed::resume_transition(
            self.s.registry(),
            self.s.expected,
            self.s.f.original.paths.clone(),
            self.s.f.original.intent.clone(),
            self.s.f.pin.clone(),
            &self.approved,
        )
        .expect("reconcile same approved transition")
    }
    fn finish(&self, managed: &mut Managed) {
        let proposal = managed
            .transition_after_noncommit(&self.approved)
            .expect("exact idempotent transition");
        assert_eq!(proposal.operation(), self.next.operation());
        let receipt = {
            let mut witness = self.s.f.witness.lock().expect("witness");
            witness
                .replace_account_root(
                    &proposal,
                    &self.s.f.original.root.public_key().expect("old root"),
                    &self.target.genesis,
                    &self.target.device,
                    &self.s.f.policy,
                    170,
                )
                .expect("real successor commitment");
            witness
                .retired_account_receipt(&proposal)
                .expect("signed actual retirement")
        };
        let checkpoint = managed
            .retain_witness_retirement(&receipt)
            .expect("all original commits reconciled");
        assert_eq!(checkpoint.revision(), 2);
        assert_eq!(checkpoint.account(), self.target.device.account_id());
        assert_eq!(
            managed
                .transition_after_noncommit(&self.approved)
                .expect("same transition after final commitment"),
            proposal
        );
        let enrollment =
            DeviceEnrollment::open(self.target.paths.clone(), self.target.intent.clone())
                .expect("original next enrollment");
        let mut current = managed
            .activate_successor(
                enrollment,
                &self.s.f.policy,
                170,
                Box::new(CurrentCarrier(Arc::clone(&self.s.f.witness))),
                Duration::from_secs(3),
            )
            .expect("fresh current successor authority");
        current
            .next_prekey_publication_id()
            .expect("actual successor owner");
        managed.close();
        assert!(matches!(
            current.next_prekey_publication_id(),
            Err(DurableError::Closed)
        ));
        current.close();
        self.s.f.assert_fenced();
    }
}

#[test]
fn managed_root_terminal_observation_and_next_target_preserve_original_identity() {
    for bound in [false, true] {
        let (t, mut managed) = Transition::new(bound);
        assert_eq!(
            managed
                .retain_witness_noncommit(&t.noncommit)
                .expect("original permanent non-commit"),
            State::Closed
        );
        assert_eq!(
            managed
                .retain_witness_noncommit(&t.noncommit)
                .expect("same terminal result"),
            State::Closed
        );
        assert!(matches!(
            managed.bind_witness_freeze(&t.freeze),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert_eq!(
            managed.state().expect("no reset or unfreezing"),
            State::Closed
        );
        managed.close();
        let mut managed = t.s.resume();
        assert_eq!(
            managed.state().expect("recovered closed original plan"),
            State::Closed
        );
        let proposal = managed
            .transition_after_noncommit(&t.approved)
            .expect("separate approved target");
        assert_eq!(proposal.operation(), t.next.operation());
        managed.close();
        let mut managed = t.resume();
        assert_eq!(
            managed.state().expect("same pending next operation"),
            State::Pending
        );
        t.finish(&mut managed);
        let registry = t.s.registry();
        assert_eq!(
            registry
                .preparation(t.s.plan.operation())
                .expect("retained old operation")
                .1,
            State::Closed
        );
        assert_eq!(
            registry
                .preparation(t.next.operation())
                .expect("retained next operation")
                .1,
            State::Committed
        );
        assert_eq!(
            registry
                .operation_checkpoint(t.next.operation())
                .expect("original revision expectation"),
            t.s.expected
        );
    }
}

#[test]
fn managed_root_transition_receipts_cannot_choose_or_change_the_next_approval() {
    let (t, mut managed) = Transition::new(true);
    let mut bad = t.noncommit.clone();
    *bad.last_mut().expect("signed receipt") ^= 1;
    assert!(ManagedAccountRootTransition::verify(
        &t.s.f.pin,
        &t.s.plan,
        t.next.clone(),
        &bad,
        &t.freeze
    )
    .is_err());
    assert!(ManagedAccountRootTransition::verify(
        &t.s.f.pin,
        &t.s.plan,
        t.s.plan.clone(),
        &t.noncommit,
        &t.freeze
    )
    .is_err());
    assert!(ManagedAccountRootTransition::verify(
        &t.s.f.pin,
        &t.next,
        t.next.clone(),
        &t.noncommit,
        &t.freeze
    )
    .is_err());
    assert!(managed.retain_witness_noncommit(&bad).is_err());
    assert_eq!(
        managed
            .state()
            .expect("invalid input retained original owner"),
        State::Pending
    );
    t.finish(&mut managed);
}

#[test]
fn managed_root_transition_never_recreates_missing_original_enrollment() {
    let (t, mut managed) = Transition::new(true);
    managed.close();
    let parent = &t.s.f.original.paths.configuration;
    let backup = parent.with_extension("owned-backup");
    fs::rename(parent, &backup).expect("temporarily retain owned original parent");
    assert!(Managed::resume_transition(
        t.s.registry(),
        t.s.expected,
        t.s.f.original.paths.clone(),
        t.s.f.original.intent.clone(),
        t.s.f.pin.clone(),
        &t.approved
    )
    .is_err());
    assert!(
        !parent.exists(),
        "missing state must not trigger a new enrollment"
    );
    fs::rename(&backup, parent).expect("restore exact original owned parent");
    let mut managed = t.resume();
    t.finish(&mut managed);
}

#[test]
fn managed_root_closed_next_target_requires_another_independent_approval() {
    let (mut t, mut managed) = Transition::new(true);
    managed
        .transition_after_noncommit(&t.approved)
        .expect("first replacement attempt");
    let old_next = t.next.clone();
    let closure = {
        let mut witness = t.s.f.witness.lock().expect("witness");
        witness
            .close_account_preparation(&old_next)
            .expect("independently abandon second target");
        witness
            .closed_account_preparation_receipt(&old_next)
            .expect("signed second non-commit")
    };
    managed
        .retain_witness_noncommit(&closure)
        .expect("permanent second closure");
    assert!(
        matches!(
            managed.transition_after_noncommit(&t.approved),
            Err(DurableError::Protocol(Error::Retired))
        ),
        "a replay must not report a known closed next proposal as an admitted transition"
    );
    assert_eq!(
        managed.state().expect("known refusal keeps owner"),
        State::Closed
    );
    let target = account_at(
        &t.s.f
            ._dir
            .path()
            .canonicalize()
            .expect("private base")
            .join("third-approved-target"),
        &t.s.f.policy,
        200,
        170,
    );
    let next = {
        let mut witness = t.s.f.witness.lock().expect("same witness");
        let frozen = witness
            .account_freeze(old_next.request())
            .expect("same original freeze");
        witness
            .frozen_account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([98; 32]).expect("third operation"),
                &frozen,
                &target.genesis,
                &target.device,
                &t.s.f.policy,
                170,
            )
            .expect("independent third approval")
    };
    t.approved = ManagedAccountRootTransition::verify(
        &t.s.f.pin,
        &old_next,
        next.clone(),
        &closure,
        &t.freeze,
    )
    .expect("new proof and explicit approval");
    t.next = next;
    t.target = target;
    managed
        .transition_after_noncommit(&t.approved)
        .expect("advance original parent history");
    managed.close();
    let mut managed = t.resume();
    t.finish(&mut managed);
    assert_eq!(
        t.s.registry()
            .preparation(old_next.operation())
            .expect("permanent prior closure")
            .1,
        State::Closed
    );
}

#[test]
fn managed_root_cleanup_alternate_target_resumes_after_original_journal_and_signer_erasure() {
    for bound in [false, true] {
        let (t, mut managed) = Transition::new(bound);
        t.finish(&mut managed);
        let mut managed = t.resume();
        let enrollment = DeviceEnrollment::open(t.target.paths.clone(), t.target.intent.clone())
            .expect("same next enrollment");
        let mut current = managed
            .activate_successor(
                enrollment,
                &t.s.f.policy,
                170,
                Box::new(CurrentCarrier(Arc::clone(&t.s.f.witness))),
                Duration::from_secs(3),
            )
            .expect("actual current alternate target");
        super::cleanup::erase_original(&mut managed, &t.s.f, &mut current);
        assert_eq!(
            managed
                .transition_after_noncommit(&t.approved)
                .expect("same completed transition")
                .operation(),
            t.next.operation()
        );
        managed.close();
        current.close();
        let mut managed = t.resume();
        super::cleanup::assert_erased(&mut managed);
        assert_eq!(
            managed.state().expect("retained next commitment"),
            State::Committed
        );
        let enrollment = DeviceEnrollment::open(t.target.paths.clone(), t.target.intent.clone())
            .expect("same next enrollment");
        let mut current = managed
            .activate_successor(
                enrollment,
                &t.s.f.policy,
                170,
                Box::new(CurrentCarrier(Arc::clone(&t.s.f.witness))),
                Duration::from_secs(3),
            )
            .expect("alternate target after restart");
        current
            .next_prekey_publication_id()
            .expect("governed current owner");
    }
}
