// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original managed journal and registry exist before Witness transfer and freeze.
use super::*;
use crate::AccountAuthorityReplacementState as State;

#[derive(Clone)]
pub(super) struct RegistryRecovery {
    pub(super) expected: AccountAuthorityCheckpoint,
    pub(super) path: std::path::PathBuf,
    key: std::path::PathBuf,
    identity: AccountAuthorityIdentity,
}
impl RegistryRecovery {
    pub(super) fn publish(&self, root: &std::path::Path) {
        let mut bytes = self.identity.as_bytes().to_vec();
        bytes.extend_from_slice(self.expected.application().as_bytes());
        bytes.extend_from_slice(&self.expected.revision().to_be_bytes());
        bytes.extend_from_slice(&self.expected.account());
        fs::write(root.join("registry-inputs"), bytes)
            .expect("original independent registry checkpoint");
    }
    pub(super) fn restore(root: &std::path::Path) -> Self {
        let bytes =
            fs::read(root.join("registry-inputs")).expect("original public registry inputs");
        let mut d = Decoder::new(&bytes);
        let identity = AccountAuthorityIdentity::from_trusted_state(d.array().expect("identity"))
            .expect("registry identity");
        let app = ApplicationAccountId::from_trusted_state(d.array().expect("application"))
            .expect("application");
        let expected = AccountAuthorityCheckpoint::from_trusted_state(
            app,
            d.u64().expect("revision"),
            d.array().expect("account"),
        )
        .expect("original checkpoint");
        d.finish().expect("complete inputs");
        let base = root.parent().expect("original fixture directory");
        Self {
            identity,
            expected,
            path: base.join("original-registry"),
            key: base.join("original-registry-key"),
        }
    }
    pub(super) fn open(&self, f: &Fixture) -> AccountAuthorityStore {
        self.open_with(f.policy.family(), f.pin.clone())
    }
    pub(super) fn open_with(&self, family: [u8; 32], pin: AnchorPin) -> AccountAuthorityStore {
        self.try_open(family, pin)
            .expect("same original registry identity and pin")
    }
    pub(super) fn try_open(
        &self,
        family: [u8; 32],
        pin: AnchorPin,
    ) -> Result<AccountAuthorityStore, DurableError> {
        AccountAuthorityStore::open(
            &self.path,
            JournalKey::open(&self.key)?,
            self.identity,
            family,
            pin,
        )
    }
}

pub(super) struct OriginalRegistry {
    pub(super) owner: AccountAuthorityStore,
    pub(super) identity: AccountAuthorityIdentity,
    pub(super) expected: AccountAuthorityCheckpoint,
    pub(super) unrelated: AccountAuthorityCheckpoint,
    pub(super) path: std::path::PathBuf,
    key: std::path::PathBuf,
    pub(super) before_preparation: Vec<u8>,
    old: AccountAuthorityLease,
    other: AccountAuthorityLease,
}
impl OriginalRegistry {
    pub(super) fn recovery(&self) -> RegistryRecovery {
        RegistryRecovery {
            expected: self.expected,
            path: self.path.clone(),
            key: self.key.clone(),
            identity: self.identity,
        }
    }
    pub(super) fn new(f: &Fixture) -> Self {
        let base = f
            ._dir
            .path()
            .canonicalize()
            .expect("owned canonical registry parent");
        let path = base.join("original-registry");
        let key = base.join("original-registry-key");
        let identity =
            AccountAuthorityIdentity::generate().expect("independent original registry identity");
        let mut owner = AccountAuthorityStore::provision(
            &path,
            JournalKey::provision(&key).expect("original registry key"),
            identity,
            f.policy.family(),
            f.pin.clone(),
        )
        .expect("same original registry");
        let expected = owner
            .associate(
                ApplicationAccountId::from_trusted_state([220; 32]).expect("original application"),
                &f.original.device,
            )
            .expect("original root association");
        let unrelated = owner
            .associate(
                ApplicationAccountId::from_trusted_state([221; 32]).expect("unrelated application"),
                &f.target.device,
            )
            .expect("independent unrelated root");
        let access = owner.access().expect("original runtime");
        Self {
            owner,
            identity,
            expected,
            unrelated,
            path,
            key,
            before_preparation: Vec::new(),
            old: access.admit(expected).expect("old admission"),
            other: access.admit(unrelated).expect("unrelated admission"),
        }
    }
    pub(super) fn authority(&self) -> JournalAccountAuthority {
        JournalAccountAuthority::new(
            self.owner.access().expect("same live registry"),
            self.expected,
        )
        .expect("original application descriptor")
    }
    pub(super) fn activate(&self, f: &Fixture) -> EnrolledDevice {
        let mut enrollment = DeviceEnrollment::open_with_account_authority(
            f.original.paths.clone(),
            f.original.intent.clone(),
            self.authority(),
        )
        .expect("original parent");
        let client = enrollment
            .anchor_client(
                &f.policy,
                150,
                f.pin.clone(),
                Box::new(Carrier(Arc::clone(&f.witness))),
                Duration::from_secs(3),
            )
            .expect("original A client");
        enrollment
            .activate(&f.policy, 150, Some(client))
            .expect("original managed journal before transfer")
    }
    pub(super) fn prepare(
        &mut self,
        plan: &AnchorTransferredAccountReplacementPlan,
        history: &AnchorHandoffHistory,
    ) {
        self.before_preparation = crate::account_authority::tests::snapshot_registry(&self.owner);
        self.old
            .check()
            .expect("old lease live before local intent");
        assert_eq!(
            self.owner
                .begin_transferred_preparation(self.expected, plan.clone(), history)
                .expect("durable target before server freeze"),
            State::Preparing
        );
        assert!(matches!(self.old.check(), Err(DurableError::Suspended)));
        self.other
            .check()
            .expect("unrelated original lease stays usable");
        assert!(matches!(
            self.owner.replacement(plan.operation()),
            Err(DurableError::Suspended)
        ));
    }
    pub(super) fn reopen(&mut self, f: &Fixture) {
        self.owner.close();
        self.owner = AccountAuthorityStore::open(
            &self.path,
            JournalKey::open(&self.key).expect("original registry key"),
            self.identity,
            f.policy.family(),
            f.pin.clone(),
        )
        .expect("same original pin/path/identity after cold reopen");
    }
}

#[test]
fn transferred_registry_preserves_original_managed_pending_and_selects_only_committed_target() {
    for stage in [None, Some(0), Some(1), Some(2)] {
        for closed in [false, true] {
            let mut t = Transferred::with_registry(stage, 2);
            let mut registry = t.registry.take().expect("registry existed before transfer");
            let rows = journal_rows(&t);
            let key = fs::read(&t.f.original.paths.wrapping).expect("original wrapping bytes");
            let registry_binding = registry.owner.access().expect("access").binding();
            registry.reopen(&t.f);
            assert_eq!(
                registry
                    .owner
                    .transferred_preparation(t.preparation.operation())
                    .expect("original intent")
                    .2,
                &t.preparation
            );
            assert_eq!(
                registry
                    .owner
                    .begin_transferred_preparation(
                        registry.expected,
                        t.preparation.clone(),
                        &t.history
                    )
                    .expect("exact original retry"),
                State::Preparing
            );
            assert_eq!(
                registry
                    .owner
                    .bind_transferred_preparation(
                        t.preparation.operation(),
                        &t.frozen,
                        t.approval.clone()
                    )
                    .expect("same full approved account freeze"),
                State::Pending
            );
            registry.reopen(&t.f);
            let mut parent = t.open().expect("same original parent and child");
            let decision = t.decide(closed);
            parent
                .retain_account_decision(decision.as_bytes())
                .expect("child then parent before registry publication");
            parent.close();
            // A purpose37 type cannot bypass exact approval/receipt retention via legacy APIs.
            if closed {
                assert!(registry
                    .owner
                    .close_replacement(&decision.closure().expect("closed fact"))
                    .is_err());
            } else {
                assert!(registry
                    .owner
                    .commit_replacement(&decision.retirement().expect("retired fact"))
                    .is_err());
            }
            let expected_state = if closed {
                State::Closed
            } else {
                State::Committed
            };
            assert_eq!(
                registry
                    .owner
                    .retain_transferred_account_decision(
                        t.preparation.operation(),
                        decision.as_bytes()
                    )
                    .expect("exact signed outcome"),
                expected_state
            );
            assert!(
                journal_rows(&t) == rows,
                "registry must not replace original sealed image/pending/selection"
            );
            assert!(fs::read(&t.f.original.paths.wrapping).expect("retained key") == key);
            registry.reopen(&t.f);
            assert_eq!(
                registry
                    .owner
                    .transferred_account_decision(t.preparation.operation())
                    .expect("cold signed result")
                    .as_bytes(),
                decision.as_bytes()
            );
            assert_eq!(
                registry
                    .owner
                    .retain_transferred_account_decision(
                        t.preparation.operation(),
                        decision.as_bytes()
                    )
                    .expect("exact terminal retry"),
                expected_state
            );
            let access = registry.owner.access().expect("same binding");
            assert_eq!(access.binding(), registry_binding);
            access
                .check_witness(registry.unrelated, t.f.pin.binding())
                .expect("unrelated application retains logical A");
            assert!(access
                .check_witness(registry.unrelated, t.history.current_pin().binding())
                .is_err());
            assert!(access.admit(registry.expected).is_err());
            if closed {
                assert!(matches!(
                    access.current(registry.expected.application()),
                    Err(DurableError::Suspended)
                ));
            } else {
                let current = access
                    .current(registry.expected.application())
                    .expect("new root mapping");
                assert_eq!(current.revision(), registry.expected.revision() + 1);
                assert_eq!(current.account(), t.successor.device.account_id());
                access
                    .check_witness(current, t.history.current_pin().binding())
                    .expect("target logical B");
                assert!(access.check_witness(current, t.f.pin.binding()).is_err());
                let mut target = DeviceEnrollment::open_with_account_authority(
                    t.successor.paths.clone(),
                    t.successor.intent.clone(),
                    JournalAccountAuthority::new(access, current)
                        .expect("same registry target descriptor"),
                )
                .expect("actual original target enrollment");
                let carrier = target_activation::CurrentCarrier {
                    store: Arc::new(Mutex::new(t.target)),
                    clock: Arc::new(std::sync::atomic::AtomicU64::new(185)),
                    calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                };
                let client = target
                    .anchor_client(
                        &t.policy,
                        185,
                        t.history.current_pin().clone(),
                        Box::new(carrier),
                        Duration::from_secs(3),
                    )
                    .expect("actual B target carrier");
                let mut active = target
                    .activate(&t.policy, 185, Some(client))
                    .expect("managed target admitted through same registry");
                let (service, _, device) = active.parts().expect("actual target owners");
                service
                    .stores()
                    .expect("stores")
                    .0
                    .generate_prekey(
                        &t.policy,
                        device,
                        PrekeyId::from_trusted_state([222; 32]).expect("new target prekey"),
                        LeafKind::OneTimePq,
                        Validity::new(185, 199).expect("live window"),
                        185,
                    )
                    .expect("real managed target operation");
                registry.owner.close();
                assert!(
                    service
                        .stores()
                        .expect("owned handles remain closable")
                        .0
                        .generate_prekey(
                            &t.policy,
                            device,
                            PrekeyId::from_trusted_state([223; 32]).expect("next prekey"),
                            LeafKind::OneTimePq,
                            Validity::new(185, 199).expect("window"),
                            185
                        )
                        .is_err(),
                    "closing registry revokes the actual target"
                );
                active.close();
            }
            eprintln!("TRANSFERRED_REGISTRY stage={stage:?} closed={closed} original_rows=true same_registry=true");
        }
    }
}

#[path = "registry/recovery.rs"]
mod recovery;

#[path = "registry/process.rs"]
mod process;

#[path = "registry/association.rs"]
mod association;
