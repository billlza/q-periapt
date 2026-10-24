// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::*;
use std::{io, os::unix::fs::DirBuilderExt, sync::Mutex};

struct Carrier(Arc<Mutex<AnchorStore>>);
impl AnchorTransport for Carrier {
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: crate::MonotonicInstant,
    ) -> io::Result<Vec<u8>> {
        if crate::MonotonicInstant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0
            .lock()
            .expect("source lease")
            .handle(request, 170)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}
pub(super) struct Case {
    _directory: tempfile::TempDir,
    pub(super) root: PathBuf,
    pub(super) journal: DeviceJournal,
    pub(super) plan: WitnessJournalAdoptionPlan,
    pub(super) receipt: Vec<u8>,
    device: VerifiedDevice,
    policy: VerifiedSessionPolicy,
    identity: JournalIdentity,
    public_inputs: Vec<(&'static str, Vec<u8>)>,
}
fn policy(
    issuer: &PolicySigningKey,
    runtime: &Arc<q_periapt_sdk::Runtime>,
    pin: &AnchorPin,
    version: u64,
) -> VerifiedSessionPolicy {
    let p = issuer
        .issue_session_policy(
            runtime,
            SessionPolicyParameters::new(
                version,
                Validity::new(100, 400 + 100 * version).expect("validity"),
                AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                AnchorRequirement::required(pin),
                ApplicationSendBudget::new(3).expect("budget"),
            )
            .expect("parameters"),
        )
        .expect("issued policy");
    PolicyPin::new(
        issuer.policy_family().expect("family"),
        issuer.public_key().expect("public"),
        p.checkpoint(),
    )
    .expect("pin")
    .verify(p.as_bytes(), Arc::clone(runtime), 150)
    .expect("verified policy")
}
impl Case {
    pub(super) fn new(pending_policy: Option<u8>) -> Self {
        let directory = crate::durable::tests::directory();
        let root = directory.path().canonicalize().expect("root");
        for child in ["client", "source", "target"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(child))
                .expect("owned private directory");
        }
        let source_key = JournalKey::provision(&root.join("source/key")).expect("source key");
        let source_signer = AnchorSigningKey::generate().expect("source signer");
        let mut source = AnchorStore::provision(
            &root.join("source/state.redb"),
            source_key,
            source_signer,
            AnchorIdentity::generate().expect("identity"),
        )
        .expect("source");
        let pin = source.pin().expect("pin");
        let (_, _, _, runtime) =
            crate::tests::session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
        let issuer = PolicySigningKey::generate().expect("policy root");
        let old = policy(&issuer, &runtime, &pin, 1);
        let target_policy = policy(&issuer, &runtime, &pin, 2);
        let account = RootSigningKey::generate().expect("account root");
        let signer = DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("device signer");
        let certificate = account
            .issue_device(
                DeviceDescription::new(
                    [3; 16],
                    1,
                    old.family(),
                    Validity::new(100, 500).expect("time"),
                )
                .expect("description"),
                signer.public_key().expect("public"),
            )
            .expect("certificate");
        let roster = account
            .issue_roster(
                1,
                Validity::new(100, 500).expect("time"),
                &[account.roster_entry(&certificate).expect("entry")],
            )
            .expect("roster");
        let device = AccountPin::new(
            account.account_id().expect("account"),
            account.public_key().expect("root"),
            roster.checkpoint(),
            old.family(),
        )
        .expect("account pin")
        .verify_device(&certificate, roster.as_bytes(), 150)
        .expect("device");
        let identity = JournalIdentity::generate().expect("journal identity");
        let mut journal = DeviceJournal::provision_anchored(
            &root.join("client/state.redb"),
            JournalKey::provision(&root.join("client/key")).expect("key"),
            &device,
            &old,
            identity,
            150,
        )
        .expect("original journal");
        let genesis = journal.anchor_genesis(&device, &old).expect("genesis");
        source
            .enroll(&genesis, &device, &old, 150)
            .expect("original source enrollment");
        let shared = Arc::new(Mutex::new(source));
        let client = AnchorClient::new(
            pin.clone(),
            signer,
            Box::new(Carrier(Arc::clone(&shared))),
            Duration::from_secs(10),
        )
        .expect("client");
        journal
            .activate_anchor(&device, &old, client)
            .expect("original active journal");
        journal
            .generate_prekey(
                &old,
                &device,
                PrekeyId::from_trusted_state([55; 32]).expect("prekey ID"),
                LeafKind::OneTimePq,
                Validity::new(100, 300).expect("time"),
                150,
            )
            .expect("actual retained secret prekey");
        if let Some(stage) = pending_policy {
            let scope = PolicyRenewalScope {
                operation: PolicyRenewalId::generate().expect("P ID"),
                journal: identity,
                original_owner: bootstrap::storage_owner(&device),
                original_credential: device.credential_digest(),
                current_credential: device.credential_digest(),
                current_roster: device.roster().checkpoint(),
                original_policy: old.checkpoint(),
                previous_policy: old.checkpoint(),
                previous_authorization: None,
            };
            let materials = PolicyRenewalMaterials {
                original: old.historical(),
                previous: old.historical(),
                target: &target_policy,
                original_device: &device,
                current_device: &device,
            };
            let statement =
                PolicyRenewalStatement::new(&scope, &materials, 170).expect("P statement");
            let approval = VerifiedPolicyRenewal::verify(
                &account
                    .approve_policy_renewal(&statement)
                    .expect("account P"),
                &issuer.approve_policy_renewal(&statement).expect("policy P"),
                &scope,
                &materials,
                170,
            )
            .expect("P approval");
            let proposal = journal
                .prepare_policy_renewal(&approval, &materials, 170)
                .expect("real sealed P target");
            let mut source = shared.lock().expect("source");
            source
                .prepare_policy_renewal(proposal, &approval, &materials, 170)
                .expect("witness P preparation");
            if stage >= 1 {
                let command = AnchorRequest::new(
                    &pin,
                    genesis.subject(),
                    AnchorOperation::commit_policy_renewal(&proposal),
                    &DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("device"),
                )
                .expect("commit command");
                let answer = source
                    .handle(command.as_bytes(), 170)
                    .expect("real witness P commit");
                assert_eq!(
                    pin.verify_reply(&command, &answer)
                        .expect("reply")
                        .policy_renewal_state(&proposal)
                        .expect("exact P"),
                    AnchorPolicyRenewalState::Applied
                );
            }
            drop(source);
            if stage == 2 {
                let mut client = AnchorClient::new(
                    pin.clone(),
                    DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("original signer"),
                    Box::new(Carrier(Arc::clone(&shared))),
                    Duration::from_secs(10),
                )
                .expect("recovery client");
                assert_eq!(
                    DeviceJournal::recover_policy_renewal(
                        &root.join("client/state.redb"),
                        JournalKey::open(&root.join("client/key")).expect("original key"),
                        &device,
                        old.historical(),
                        identity,
                        proposal,
                        &mut client
                    )
                    .expect("install exact sealed original P"),
                    AnchorPolicyRenewalState::Applied
                );
            }
        }
        let mut source = shared.lock().expect("source");
        let target_key = JournalKey::provision(&root.join("target/key")).expect("target wrapping");
        let target_signer = AnchorSigningKey::generate().expect("target signer");
        let target_pin = AnchorPin::new(
            AnchorIdentity::generate().expect("target identity"),
            target_signer.public_key().expect("target public"),
        );
        let image = source.handoff_source_state().expect("whole source");
        let transfer = AnchorHandoffPlan::from_trusted_state(
            [121; 32],
            &image,
            target_pin.clone(),
            Validity::new(170, 190).expect("source interval"),
            [122; 32],
        )
        .expect("independent transfer approval");
        let target_approval = AnchorHandoffTargetApproval::from_trusted_state(
            &transfer,
            &pin,
            &target_pin,
            Validity::new(170, 190).expect("target interval"),
            [123; 32],
        )
        .expect("separate target approval");
        let frozen = source.freeze_handoff(&transfer, 175).expect("frozen");
        let mut imported = AnchorHandoffTarget::provision_import(
            &root.join("target/state.redb"),
            target_key,
            &target_signer,
            target_approval.clone(),
            image.as_bytes(),
            frozen.as_bytes(),
            175,
        )
        .expect("whole import");
        let ack = imported.import_receipt().expect("import receipt");
        let retired = source
            .retire_handoff(&target_approval, ack.as_bytes(), || Ok(175))
            .expect("source retirement");
        let history = imported
            .verify_source_retirement(retired.as_bytes())
            .expect("history");
        let (mut target, activation) = imported
            .activate(retired.as_bytes(), target_signer)
            .expect("target activation");
        let current_policy = if pending_policy.is_some_and(|stage| stage >= 1) {
            target_policy.historical()
        } else {
            old.historical()
        };
        let materials = AnchorHandoffAdoptionMaterials {
            original_device: &device,
            current_device: &device,
            original_policy: old.historical(),
            current_policy,
            history: &history,
            activation: &activation,
        };
        let scope = target
            .handoff_adoption_scope(
                AnchorHandoffAdoptionId::generate().expect("decision ID"),
                genesis.subject(),
                &materials,
                Validity::new(180, 190).expect("adoption interval"),
            )
            .expect("exact imported state");
        let statement = AnchorHandoffAdoptionStatement::new(&scope, &materials, 180)
            .expect("adoption statement");
        let approved = HistoricalAnchorHandoffAdoption::from_approvals(
            &account
                .approve_anchor_handoff_adoption(&statement)
                .expect("account consent"),
            &issuer
                .approve_anchor_handoff_adoption(&statement)
                .expect("policy consent"),
            &scope,
            &materials,
        )
        .expect("both independent approvals");
        let plan = WitnessJournalAdoptionPlan::new(&approved, &materials).expect("verified plan");
        let receipt = target
            .authorize_handoff_client(plan.authorization_request(), || Ok(180))
            .expect("durable server decision")
            .as_bytes()
            .to_vec();
        let public_inputs = vec![
            (
                "origin-pin",
                [
                    pin.identity().as_bytes().as_slice(),
                    &pin.public_key().encode(),
                ]
                .concat(),
            ),
            (
                "current-pin",
                [
                    target_pin.identity().as_bytes().as_slice(),
                    &target_pin.public_key().encode(),
                ]
                .concat(),
            ),
            ("history", history.to_bytes().expect("history")),
            ("checkpoint", history.checkpoint().to_vec()),
            ("target-approval", target_approval.to_bytes()),
            ("freeze", frozen.as_bytes().to_vec()),
            ("ack", ack.as_bytes().to_vec()),
            ("retired", retired.as_bytes().to_vec()),
            ("activation", activation.as_bytes().to_vec()),
            ("request", plan.request.clone()),
            ("device", device.key.encode()),
            ("receipt", receipt.clone()),
        ];
        Self {
            _directory: directory,
            root,
            journal,
            plan,
            receipt,
            device,
            policy: old,
            identity,
            public_inputs,
        }
    }
    pub(super) fn path(&self) -> PathBuf {
        self.root.as_path().join("client/state.redb")
    }
    pub(super) fn key(&self) -> JournalKey {
        JournalKey::open(&self.root.as_path().join("client/key")).expect("original key")
    }
    pub(super) fn resume(&self) -> WitnessJournalAdoption {
        WitnessJournalAdoption::resume_original(&self.path(), self.key(), self.plan.clone())
            .expect("same original adoption")
    }
    pub(super) fn original_rows(&self) -> (Vec<u8>, Option<Vec<u8>>) {
        if let Some(active) = &self.journal.active {
            rows(&active.db)
        } else {
            rows(&open_private_database(&self.path()).expect("original database"))
        }
    }
    pub(super) fn assert_ordinary_refused(&self) {
        assert!(matches!(
            DeviceJournal::recover_anchor_genesis(
                &self.path(),
                self.key(),
                &self.device,
                &self.policy,
                self.identity
            ),
            Err(DurableError::Suspended)
        ));
    }
    pub(super) fn publish_child_inputs(&self) {
        for (name, bytes) in &self.public_inputs {
            fs::write(self.root.as_path().join(name), bytes).expect("owned public expectation");
        }
    }
}
pub(super) fn restore_child_plan(root: &Path) -> WitnessJournalAdoptionPlan {
    let read =
        |name| fs::read(root.join(name)).expect("original independently retained public input");
    let pin = |name| {
        let bytes = read(name);
        let mut d = Decoder::new(&bytes);
        let identity =
            AnchorIdentity::from_trusted_state(d.array().expect("ID")).expect("identity");
        let key = PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("key")).expect("key");
        d.finish().expect("complete pin");
        AnchorPin::new(identity, key)
    };
    let origin = pin("origin-pin");
    let current = pin("current-pin");
    let history = AnchorHandoffHistory::restore_trusted_state(
        &read("history"),
        &origin,
        &current,
        read("checkpoint").try_into().expect("checkpoint"),
    )
    .expect("original pinned history");
    let approval = AnchorHandoffTargetApproval::restore_trusted_state(
        &read("target-approval"),
        &origin,
        &current,
    )
    .expect("target expectation");
    let activation = approval
        .verify_activation_receipt(
            &read("freeze"),
            &read("ack"),
            &read("retired"),
            &read("activation"),
        )
        .expect("exact activation");
    let request = read("request");
    let restored = crate::session_policy::RetainedAdoptionRequest::restore(
        &request,
        &PublicKey::decode(&read("device")).expect("original device key"),
        &history,
        &activation,
    )
    .expect("original public proofs");
    WitnessJournalAdoptionPlan {
        request,
        approved: restored.approved,
        history,
        account: restored.account,
    }
}
pub(super) fn rows(db: &Database) -> (Vec<u8>, Option<Vec<u8>>) {
    let read = db.begin_read().expect("read");
    let table = image_table(&read).expect("table");
    let image = table
        .get("image")
        .expect("lookup")
        .expect("image")
        .value()
        .to_vec();
    let pending = table
        .get("pending")
        .expect("lookup")
        .map(|v| v.value().to_vec());
    (image, pending)
}
