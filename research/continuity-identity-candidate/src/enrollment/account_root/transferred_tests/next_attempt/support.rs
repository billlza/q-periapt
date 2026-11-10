// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::fixture::Work;
use super::super::registry::RegistryRecovery;
use super::super::*;
use crate::AccountAuthorityReplacementState as State;

pub(super) struct Scenario {
    pub(super) t: Transferred,
    pub(super) registry: AccountAuthorityStore,
    pub(super) recovery: RegistryRecovery,
    pub(super) closed: Vec<u8>,
}
impl Scenario {
    pub(super) fn new(work: Work, retain: bool) -> Self {
        let mut t = Transferred::with_pending(work, 2);
        let mut controller = t.controller.take().expect("same original controller");
        controller
            .bind_transferred_freeze(&t.frozen, t.approval.clone())
            .expect("original complete account freeze");
        let closed = t.decide(true).as_bytes().to_vec();
        if retain {
            controller
                .retain_transferred_decision(&closed)
                .expect("same signed Closed");
        }
        controller.close();
        let recovery = t
            .registry_recovery
            .as_ref()
            .expect("original registry")
            .clone();
        let registry = recovery.open(&t.f);
        Self {
            t,
            registry,
            recovery,
            closed,
        }
    }
    pub(super) fn reopen(&mut self) {
        self.registry.close();
        self.registry = self.recovery.open(&self.t.f);
    }
    pub(super) fn assert_old(&self) {
        assert_eq!(
            self.registry
                .transferred_account_decision(self.t.preparation.operation())
                .expect("permanent old closure")
                .as_bytes(),
            self.closed
        );
        assert!(self
            .registry
            .access()
            .expect("access")
            .admit(self.recovery.expected)
            .is_err());
    }
    pub(super) fn extend_history(&mut self) {
        cleanup::handoff(&mut self.t);
        let wire = self
            .t
            .f
            .issuer
            .issue_session_policy(
                &self.t.f.runtime,
                SessionPolicyParameters::new(
                    3,
                    Validity::new(180, 230).expect("current C policy"),
                    AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("mode"),
                    AnchorRequirement::required(self.t.history.current_pin()),
                    ApplicationSendBudget::new(3).expect("budget"),
                )
                .expect("independently approved current policy"),
            )
            .expect("current policy signature");
        self.t.policy = PolicyPin::new(
            self.t.f.policy.family(),
            self.t
                .f
                .issuer
                .public_key()
                .expect("independent policy root"),
            wire.checkpoint(),
        )
        .expect("current policy pin")
        .verify(wire.as_bytes(), Arc::clone(&self.t.f.runtime), 196)
        .expect("verified C-bound target policy");
    }
}
pub(super) struct Next {
    pub(super) account: Account,
    pub(super) plan: AnchorTransferredAccountReplacementPlan,
    pub(super) approval: AnchorTransferredAccountReplacementApproval,
    pub(super) now: u64,
}
impl Next {
    pub(super) fn new(s: &mut Scenario, label: &str, id: u8, now: u64) -> Self {
        let until = if now < 195 { 200 } else { 220 };
        let base =
            s.t.f
                ._dir
                .path()
                .canonicalize()
                .expect("original owned directory");
        let account = account_at(&base.join(label), &s.t.policy, until, now);
        let root =
            s.t.f
                .original
                .root
                .public_key()
                .expect("independent old root");
        let materials = AnchorTransferredAccountReplacementMaterials {
            previous_root: &root,
            genesis: &account.genesis,
            device: &account.device,
            policy: &s.t.policy,
            history: &s.t.history,
        };
        let image =
            s.t.target
                .handoff_source_state()
                .expect("complete original Witness image");
        let plan =
            s.t.target
                .frozen_transferred_account_replacement_plan(
                    AnchorAccountReplacementId::from_trusted_state([id; 32])
                        .expect("new approved attempt ID"),
                    &s.t.frozen,
                    &materials,
                    now,
                )
                .expect("new target with exact original freeze");
        assert_eq!(
            s.t.target
                .handoff_source_state()
                .expect("unchanged Witness")
                .as_bytes(),
            image.as_bytes()
        );
        let wire = plan.to_bytes().expect("retained preparation");
        assert_eq!(wire.get(..8), Some(b"QPTARP02".as_slice()));
        let restored =
            AnchorTransferredAccountReplacementPlan::restore_trusted_state(&wire, &materials)
                .expect("independent current target and original exact freeze commitment");
        assert_eq!(restored, plan);
        let proposal = plan
            .bind(&s.t.frozen, &s.t.history)
            .expect("complete original signed freeze");
        assert_eq!(
            proposal.preparation_binding(),
            s.t.approval.proposal().preparation_binding()
        );
        assert_eq!(
            proposal.predecessors().collect::<Vec<_>>(),
            s.t.approval.proposal().predecessors().collect::<Vec<_>>()
        );
        for subject in proposal.predecessors() {
            assert_eq!(
                proposal
                    .predecessor_observation(subject)
                    .expect("exact observation"),
                s.t.approval
                    .proposal()
                    .predecessor_observation(subject)
                    .expect("original observation")
            );
        }
        let approval = AnchorTransferredAccountReplacementApproval::from_trusted_state(
            proposal,
            &materials,
            [id + 1; 32],
            Validity::new(now, now + 4).expect("independent approval interval"),
        )
        .expect("separate full new-attempt approval");
        Self {
            account,
            plan,
            approval,
            now,
        }
    }
    pub(super) fn prepare(&self, s: &mut Scenario) {
        assert_eq!(
            s.registry
                .begin_transferred_preparation(s.recovery.expected, self.plan.clone(), &s.t.history)
                .expect("new separately approved target retained"),
            State::Preparing
        );
        s.assert_old();
        assert_eq!(
            s.registry
                .bind_transferred_preparation(
                    self.plan.operation(),
                    &s.t.frozen,
                    self.approval.clone()
                )
                .expect("same original freeze and complete target approval"),
            State::Pending
        );
    }
    pub(super) fn decide(&self, s: &mut Scenario, closed: bool) -> Vec<u8> {
        if closed {
            s.t.target
                .close_transferred_account_replacement(&self.approval)
                .expect("permanent separately approved next closure")
                .as_bytes()
                .to_vec()
        } else {
            let root =
                s.t.f
                    .original
                    .root
                    .public_key()
                    .expect("independent old root");
            s.t.target
                .replace_transferred_account_root(
                    &self.approval,
                    &AnchorTransferredAccountReplacementMaterials {
                        previous_root: &root,
                        genesis: &self.account.genesis,
                        device: &self.account.device,
                        policy: &s.t.policy,
                        history: &s.t.history,
                    },
                    || Ok(self.now),
                )
                .expect("fresh current admission and original full freeze")
                .as_bytes()
                .to_vec()
        }
    }
    pub(super) fn activate(self, mut s: Scenario) {
        let access = s.registry.access().expect("same registry binding");
        let current = access
            .current(s.recovery.expected.application())
            .expect("committed next mapping");
        assert_eq!(current.revision(), s.recovery.expected.revision() + 1);
        assert_eq!(current.account(), self.account.device.account_id());
        let mut enrollment = DeviceEnrollment::open_with_account_authority(
            self.account.paths.clone(),
            self.account.intent.clone(),
            JournalAccountAuthority::new(access, current).expect("approved next association"),
        )
        .expect("same prepared target parent");
        let carrier = target_activation::CurrentCarrier {
            store: Arc::new(Mutex::new(s.t.target)),
            clock: Arc::new(std::sync::atomic::AtomicU64::new(self.now)),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let client = enrollment
            .anchor_client(
                &s.t.policy,
                self.now,
                s.t.history.current_pin().clone(),
                Box::new(carrier),
                Duration::from_secs(3),
            )
            .expect("actual current Witness carrier");
        let mut active = enrollment
            .activate(&s.t.policy, self.now, Some(client))
            .expect("actual governed SDK successor");
        let (service, _, device) = active.parts().expect("live owners");
        service
            .stores()
            .expect("stores")
            .0
            .generate_prekey(
                &s.t.policy,
                device,
                PrekeyId::from_trusted_state([216; 32]).expect("new target prekey"),
                LeafKind::OneTimePq,
                Validity::new(self.now, self.now + 2).expect("current window"),
                self.now,
            )
            .expect("real target operation after separately approved commitment");
        s.registry.close();
        assert!(
            service
                .stores()
                .expect("closable handles")
                .0
                .generate_prekey(
                    &s.t.policy,
                    device,
                    PrekeyId::from_trusted_state([217; 32]).expect("another prekey"),
                    LeafKind::OneTimePq,
                    Validity::new(self.now, self.now + 2).expect("window"),
                    self.now,
                )
                .is_err(),
            "closing original registry revokes new target"
        );
        active.close();
        s.t.f.assert_fenced();
    }
}
