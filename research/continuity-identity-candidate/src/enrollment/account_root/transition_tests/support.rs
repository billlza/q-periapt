// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
struct CurrentCarrier(Arc<Mutex<AnchorStore>>);
impl AnchorTransport for CurrentCarrier {
    fn exchange(&mut self, bytes: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0
            .lock()
            .expect("witness")
            .handle(bytes, 170)
            .map_err(io::Error::other)
    }
}
pub(super) struct Transition {
    pub(super) f: Fixture,
    pub(super) owner: AccountRootEnrollmentRecovery,
    pub(super) registry: AccountAuthorityStore,
    pub(super) expected: AccountAuthorityCheckpoint,
    pub(super) old: Proposal,
    pub(super) next: Proposal,
    pub(super) transition: AccountRootJournalTransition,
    pub(super) before_fence: Vec<u8>,
    target: Account,
    parent: Vec<u8>,
    child: (Vec<u8>, Option<Vec<u8>>),
    transitions: usize,
}
impl Transition {
    pub(super) fn new() -> Self {
        let f = fixture_with_target_until(160);
        let base = f
            ._dir
            .path()
            .canonicalize()
            .expect("canonical owned fixture root");
        let mut registry = AccountAuthorityStore::provision(
            &base.join("authority"),
            JournalKey::provision(&base.join("authority-key")).expect("key"),
            AccountAuthorityIdentity::generate().expect("identity"),
            f.policy.family(),
            f.pin.clone(),
        )
        .expect("registry");
        let expected = registry
            .associate(
                ApplicationAccountId::from_trusted_state([61; 32]).expect("application"),
                &f.original.device,
            )
            .expect("original independent association");
        let before_fence =
            fs::read(f.original.paths.installation.files()[1]).expect("original child backup");
        let child = child_rows(&f);
        let operating = f.activate();
        let parent = parent_rows(
            &operating
                .active
                .as_ref()
                .expect("operating")
                .enrollment
                .active
                .as_ref()
                .expect("parent")
                .database,
        )
        .0;
        let mut witness = f.witness.lock().expect("witness");
        let request = AnchorAccountFreezeRequest::from_trusted_state(
            AnchorAccountFreezeId::from_trusted_state([62; 32]).expect("freeze id"),
            f.original.root.public_key().expect("root"),
            &f.pin,
        )
        .expect("approved freeze");
        let plan = witness
            .account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([63; 32]).expect("operation"),
                request,
                &f.target.genesis,
                &f.target.device,
                &f.policy,
                150,
            )
            .expect("original approved target");
        registry
            .begin_preparation(expected, plan.clone())
            .expect("retain original approval before freeze");
        let frozen = witness
            .freeze_account(plan.request())
            .expect("freeze account");
        registry
            .bind_preparation(plan.operation(), &frozen)
            .expect("exact original freeze");
        let old = registry
            .replacement(plan.operation())
            .expect("bound original")
            .2
            .clone();
        drop(witness);
        let owner = operating
            .begin_account_root_replacement(f.pin.clone(), old.clone())
            .expect("original parent and child fences");
        let mut witness = f.witness.lock().expect("witness");
        assert!(matches!(
            witness.replace_account_root(
                &old,
                &f.original.root.public_key().expect("root"),
                &f.target.genesis,
                &f.target.device,
                &f.policy,
                170
            ),
            Err(DurableError::Protocol(Error::Validity))
        ));
        assert_eq!(
            witness
                .close_account_preparation(&plan)
                .expect("explicit original closure"),
            WitnessState::Closed
        );
        let closed = f
            .pin
            .verify_closed_account_preparation(
                &plan,
                &witness
                    .closed_account_preparation_receipt(&plan)
                    .expect("signed original decision"),
            )
            .expect("pinned original non-commit");
        registry
            .close_preparation(&closed)
            .expect("old authority remains suspended");
        let target = account_at(&base.join("fresh-target"), &f.policy, 200, 170);
        let next_plan = witness
            .frozen_account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([64; 32]).expect("new operation"),
                &frozen,
                &target.genesis,
                &target.device,
                &f.policy,
                170,
            )
            .expect("separate current target approval");
        registry
            .begin_preparation(expected, next_plan.clone())
            .expect("new intent");
        registry
            .bind_preparation(next_plan.operation(), &frozen)
            .expect("retain original freeze");
        let next = registry
            .replacement(next_plan.operation())
            .expect("new bound proposal")
            .2
            .clone();
        let transition =
            AccountRootJournalTransition::from_closed_preparation(closed, next.clone())
                .expect("authenticated original and approved next");
        drop(witness);
        Self {
            f,
            owner,
            registry,
            expected,
            old,
            next,
            transition,
            before_fence,
            target,
            parent,
            child,
            transitions: 1,
        }
    }
    pub(super) fn approve_another_target(&mut self) {
        let original = self
            .registry
            .preparation(self.next.operation())
            .expect("original intermediate plan")
            .2
            .clone();
        let mut witness = self.f.witness.lock().expect("same witness");
        assert_eq!(
            witness
                .close_account_preparation(&original)
                .expect("independently abandon intermediate target"),
            WitnessState::Closed
        );
        let closed = self
            .f
            .pin
            .verify_closed_account_preparation(
                &original,
                &witness
                    .closed_account_preparation_receipt(&original)
                    .expect("original signed non-commit"),
            )
            .expect("exact pinned closure");
        self.registry
            .close_preparation(&closed)
            .expect("same authority remains suspended");
        let frozen = witness
            .account_freeze(original.request())
            .expect("same original freeze");
        let base = self
            .f
            ._dir
            .path()
            .canonicalize()
            .expect("owned fixture root");
        let target = account_at(&base.join("third-target"), &self.f.policy, 200, 170);
        let plan = witness
            .frozen_account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([65; 32]).expect("third operation"),
                &frozen,
                &target.genesis,
                &target.device,
                &self.f.policy,
                170,
            )
            .expect("separate approved target");
        self.registry
            .begin_preparation(self.expected, plan.clone())
            .expect("retain next approval");
        self.registry
            .bind_preparation(plan.operation(), &frozen)
            .expect("same authenticated freeze");
        let next = self
            .registry
            .replacement(plan.operation())
            .expect("exact bound target")
            .2
            .clone();
        self.transition =
            AccountRootJournalTransition::from_closed_preparation(closed, next.clone())
                .expect("next original non-commit and approval");
        self.old = self.next.clone();
        self.next = next;
        self.target = target;
        self.transitions += 1;
    }
    pub(super) fn resume(&mut self) {
        self.owner = AccountRootEnrollmentRecovery::resume_transition(
            self.f.original.paths.clone(),
            self.f.original.intent.clone(),
            self.f.pin.clone(),
            &self.transition,
        )
        .expect("same original transition");
    }
    pub(super) fn assert_parent_preserved(&self) {
        let owners = self.owner.active.as_ref().expect("restricted owner");
        assert_eq!(
            parent_rows(&owners.enrollment.active.as_ref().expect("parent").database).0,
            self.parent
        );
        assert_eq!(owners.state.history.len(), self.transitions);
    }
    pub(super) fn assert_child_preserved(&self) {
        assert_eq!(child_rows(&self.f), self.child);
    }
    pub(super) fn commit(&mut self) {
        let mut witness = self.f.witness.lock().expect("witness");
        assert_eq!(
            witness
                .replace_account_root(
                    &self.next,
                    &self.f.original.root.public_key().expect("root"),
                    &self.target.genesis,
                    &self.target.device,
                    &self.f.policy,
                    170
                )
                .expect("real witness commit"),
            WitnessState::Committed
        );
        let wire = witness
            .retired_account_receipt(&self.next)
            .expect("signed retirement");
        let retired = self
            .f
            .pin
            .verify_retired_account(&self.next, &wire)
            .expect("independent verification");
        drop(witness);
        assert_eq!(
            self.owner
                .retain_witness_retirement(&wire)
                .expect("parent and child terminal"),
            AccountRootEnrollmentState::WitnessCommitted
        );
        assert_eq!(
            self.registry
                .commit_replacement(&retired)
                .expect("select approved account"),
            RegistryState::Committed
        );
        let mut enrollment =
            DeviceEnrollment::open(self.target.paths.clone(), self.target.intent.clone())
                .expect("same original prepared target");
        let client = enrollment
            .anchor_client(
                &self.f.policy,
                170,
                self.f.pin.clone(),
                Box::new(CurrentCarrier(Arc::clone(&self.f.witness))),
                Duration::from_secs(3),
            )
            .expect("fresh current-time admission");
        let mut current = enrollment
            .activate(&self.f.policy, 170, Some(client))
            .expect("actual current successor owner");
        current
            .next_prekey_publication_id()
            .expect("real owning API remains usable");
        current.close();
        self.assert_parent_preserved();
    }
}
impl Drop for Transition {
    fn drop(&mut self) {
        self.owner.close();
        self.registry.close();
    }
}
fn child_rows(f: &Fixture) -> (Vec<u8>, Option<Vec<u8>>) {
    let db = open_private_database(f.original.paths.installation.files()[1])
        .expect("quiescent original journal");
    let tx = db.begin_read().expect("read child");
    let table = tx
        .open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "continuity_device_candidate_v21",
        ))
        .expect("actual journal schema");
    (
        table
            .get("image")
            .expect("image")
            .expect("original image")
            .value()
            .to_vec(),
        table
            .get("pending")
            .expect("pending")
            .map(|p| p.value().to_vec()),
    )
}
