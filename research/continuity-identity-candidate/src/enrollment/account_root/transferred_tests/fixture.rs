// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "policy.rs"]
mod policy;
use policy::prepare_policy;
pub(super) struct Transferred {
    pub(super) f: Fixture,
    pub(super) target: AnchorStore,
    pub(super) history: AnchorHandoffHistory,
    pub(super) successor: Account,
    pub(super) policy: VerifiedSessionPolicy,
    pub(super) approval: AnchorTransferredAccountReplacementApproval,
    pub(super) selected: Option<WitnessJournalAdoptionPlan>,
    pub(super) pre_pending: Vec<u8>,
    pub(super) live: Option<EnrolledDevice>,
    pub(super) public_inputs: Vec<(&'static str, Vec<u8>)>,
}
impl Transferred {
    pub(super) fn new() -> Self {
        Self::at(None, 0)
    }
    pub(super) fn at(stage: Option<u8>, selection: u8) -> Self {
        Self::build(stage, selection, false)
    }
    pub(super) fn with_live_owner() -> Self {
        Self::build(None, 0, true)
    }
    fn build(stage: Option<u8>, selection: u8, retain_live: bool) -> Self {
        let f = fixture();
        let mut active = f.activate();
        let (service, _, device) = active.parts().expect("original controlled owners");
        service
            .stores()
            .expect("original stores")
            .0
            .generate_prekey(
                &f.policy,
                device,
                PrekeyId::from_trusted_state([199; 32]).expect("prekey identity"),
                LeafKind::OneTimePq,
                Validity::new(100, 200).expect("prekey window"),
                150,
            )
            .expect("actual sealed secret prekey");
        active.close();
        let pre_pending =
            fs::read(f.original.paths.installation.files()[1]).expect("original pre-P backup");
        let renewed = stage.map(|stage| prepare_policy(&f, stage));
        let live = retain_live.then(|| f.activate());
        let base = f._dir.path().canonicalize().expect("owned directory");
        let mut source = f.witness.lock().expect("original witness");
        let key = JournalKey::provision(&base.join("B-key")).expect("independent B key");
        let signer = AnchorSigningKey::generate().expect("B signer");
        let pin = AnchorPin::new(
            AnchorIdentity::generate().expect("B identity"),
            signer.public_key().expect("B public"),
        );
        let state = source.handoff_source_state().expect("complete A state");
        let plan = AnchorHandoffPlan::from_trusted_state(
            [201; 32],
            &state,
            pin.clone(),
            Validity::new(170, 190).expect("source window"),
            [202; 32],
        )
        .expect("source approval");
        let approved = AnchorHandoffTargetApproval::from_trusted_state(
            &plan,
            &f.pin,
            &pin,
            Validity::new(170, 190).expect("target window"),
            [203; 32],
        )
        .expect("independent target approval");
        let freeze = source.freeze_handoff(&plan, 175).expect("source freeze");
        let mut imported = AnchorHandoffTarget::provision_import(
            &base.join("B-store"),
            key,
            &signer,
            approved.clone(),
            state.as_bytes(),
            freeze.as_bytes(),
            175,
        )
        .expect("complete target import");
        let ack = imported.import_receipt().expect("import receipt");
        let retired = source
            .retire_handoff(&approved, ack.as_bytes(), || Ok(175))
            .expect("irreversible A retirement");
        let history = imported
            .verify_source_retirement(retired.as_bytes())
            .expect("independent history");
        let (mut target, activation) = imported
            .activate(retired.as_bytes(), signer)
            .expect("B activation");
        drop(source);
        let checkpoint = |p: &VerifiedSessionPolicy| {
            [
                p.checkpoint().version().to_be_bytes().as_slice(),
                &p.checkpoint().digest(),
            ]
            .concat()
        };
        let current = renewed
            .as_ref()
            .filter(|_| stage.is_some_and(|s| s >= 1))
            .map_or(&f.policy, |(policy, _)| policy);
        let mut public_inputs = vec![
            (
                "origin-pin",
                [
                    f.pin.identity().as_bytes().as_slice(),
                    &f.pin.public_key().encode(),
                ]
                .concat(),
            ),
            ("history", history.to_bytes().expect("exact history bytes")),
            ("history-checkpoint", history.checkpoint().to_vec()),
            ("target-approval", approved.to_bytes()),
            ("freeze", freeze.as_bytes().to_vec()),
            ("import", ack.as_bytes().to_vec()),
            ("retired", retired.as_bytes().to_vec()),
            ("activated", activation.as_bytes().to_vec()),
            ("original-policy", f.policy_wire.clone()),
            ("original-policy-checkpoint", checkpoint(&f.policy)),
            (
                "current-policy",
                renewed
                    .as_ref()
                    .filter(|_| stage.is_some_and(|s| s >= 1))
                    .map_or_else(|| f.policy_wire.clone(), |(_, wire)| wire.clone()),
            ),
            ("current-policy-checkpoint", checkpoint(current)),
            (
                "policy-root",
                f.issuer
                    .public_key()
                    .expect("independent policy root")
                    .encode(),
            ),
            ("policy-family", f.policy.family().to_vec()),
        ];
        let selected = if selection == 0 {
            None
        } else {
            let current_policy = if stage.is_some_and(|s| s >= 1) {
                renewed.as_ref().expect("P target").0.historical()
            } else {
                f.policy.historical()
            };
            let materials = AnchorHandoffAdoptionMaterials {
                original_device: &f.original.device,
                current_device: &f.original.device,
                original_policy: f.policy.historical(),
                current_policy,
                history: &history,
                activation: &activation,
            };
            let scope = target
                .handoff_adoption_scope(
                    AnchorHandoffAdoptionId::generate().expect("selection identity"),
                    f.original.genesis.subject(),
                    &materials,
                    Validity::new(180, 190).expect("selection window"),
                )
                .expect("actual imported original state");
            let statement = AnchorHandoffAdoptionStatement::new(&scope, &materials, 180)
                .expect("selection statement");
            let approved = HistoricalAnchorHandoffAdoption::from_approvals(
                &f.original
                    .root
                    .approve_anchor_handoff_adoption(&statement)
                    .expect("account consent"),
                &f.issuer
                    .approve_anchor_handoff_adoption(&statement)
                    .expect("policy consent"),
                &scope,
                &materials,
            )
            .expect("independent dual-root selection");
            public_inputs.push(("selection-scope", scope.to_bytes()));
            public_inputs.push(("selection-approval", approved.as_bytes().to_vec()));
            let plan =
                WitnessJournalAdoptionPlan::new(&approved, &materials).expect("selection plan");
            let receipt = target
                .authorize_handoff_client(plan.authorization_request(), || Ok(180))
                .expect("durable target authorization");
            if matches!(selection, 1 | 2 | 5) {
                let mut parent =
                    DeviceEnrollment::open(f.original.paths.clone(), f.original.intent.clone())
                        .expect("same parent");
                parent
                    .prepare_witness_handoff(f.policy.historical(), plan.clone(), || Ok(180))
                    .expect("parent prepared");
                if selection == 2 {
                    parent
                        .adopt_witness_handoff(
                            f.policy.historical(),
                            plan.clone(),
                            receipt.as_bytes(),
                        )
                        .expect("parent adopted");
                }
                parent.close();
            }
            if selection >= 3 {
                let mut child = WitnessJournalAdoption::prepare_original(
                    f.original.paths.installation.files()[1],
                    JournalKey::open(&f.original.paths.wrapping).expect("same key"),
                    plan.clone(),
                    || Ok(180),
                )
                .expect("child ahead of parent");
                if selection >= 4 {
                    child
                        .adopt_authorization(receipt.as_bytes())
                        .expect("child adopted");
                }
                child.close();
            }
            Some(plan)
        };
        let wire = f
            .issuer
            .issue_session_policy(
                &f.runtime,
                SessionPolicyParameters::new(
                    2,
                    Validity::new(100, 200).expect("policy window"),
                    AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                    AnchorRequirement::required(&pin),
                    ApplicationSendBudget::new(3).expect("budget"),
                )
                .expect("policy parameters"),
            )
            .expect("B-bound target policy");
        let policy = PolicyPin::new(
            f.policy.family(),
            f.issuer.public_key().expect("policy root"),
            wire.checkpoint(),
        )
        .expect("policy trust")
        .verify(wire.as_bytes(), Arc::clone(&f.runtime), 185)
        .expect("verified target policy");
        public_inputs.push(("successor-policy", wire.as_bytes().to_vec()));
        public_inputs.push(("successor-policy-checkpoint", checkpoint(&policy)));
        let successor = account_at(&base.join("after-transfer-target"), &policy, 200, 185);
        let root = f
            .original
            .root
            .public_key()
            .expect("independent original account");
        let request = AnchorAccountFreezeRequest::from_trusted_state(
            AnchorAccountFreezeId::from_trusted_state([204; 32]).expect("freeze ID"),
            root.clone(),
            &pin,
        )
        .expect("account scope");
        let proposed = target
            .transferred_account_freeze_proposal(&request, &history)
            .expect("full account observation");
        let freeze = AnchorTransferredAccountFreezeApproval::from_trusted_state(
            proposed,
            &request,
            &history,
            [205; 32],
            Validity::new(181, 195).expect("account freeze window"),
        )
        .expect("independent account approval");
        let wire = target
            .freeze_transferred_account(&freeze, || Ok(185))
            .expect("whole account frozen");
        let frozen = freeze
            .verify_receipt(&history, &wire)
            .expect("same complete freeze");
        let materials = AnchorTransferredAccountReplacementMaterials {
            previous_root: &root,
            genesis: &successor.genesis,
            device: &successor.device,
            policy: &policy,
            history: &history,
        };
        let proposal = target
            .transferred_account_replacement_proposal(
                AnchorAccountReplacementId::from_trusted_state([206; 32]).expect("root ID"),
                &frozen,
                &materials,
                185,
            )
            .expect("exact successor observation");
        let approval = AnchorTransferredAccountReplacementApproval::from_trusted_state(
            proposal,
            &materials,
            [207; 32],
            Validity::new(185, 195).expect("account window"),
        )
        .expect("independent exact root approval");
        Self {
            f,
            target,
            history,
            successor,
            policy,
            approval,
            selected,
            pre_pending,
            live,
            public_inputs,
        }
    }
    pub(super) fn plan(&self) -> TransferredAccountRootJournalPlan {
        TransferredAccountRootJournalPlan::new(
            self.f.pin.clone(),
            self.approval.clone(),
            self.history.clone(),
            self.selected.clone(),
        )
        .expect("exact independently retained root and selection")
    }
    pub(super) fn open(&self) -> Result<AccountRootEnrollmentRecovery, DurableError> {
        AccountRootEnrollmentRecovery::resume_transferred_original(
            self.f.original.paths.clone(),
            self.f.original.intent.clone(),
            self.plan(),
        )
    }
    pub(super) fn decide(&mut self, closed: bool) -> AnchorTransferredAccountDecision {
        let root = self
            .f
            .original
            .root
            .public_key()
            .expect("original account authority");
        let materials = AnchorTransferredAccountReplacementMaterials {
            previous_root: &root,
            genesis: &self.successor.genesis,
            device: &self.successor.device,
            policy: &self.policy,
            history: &self.history,
        };
        if closed {
            self.target
                .close_transferred_account_replacement(&self.approval)
        } else {
            self.target
                .replace_transferred_account_root(&self.approval, &materials, || Ok(185))
        }
        .expect("actual permanent target decision")
    }
}
