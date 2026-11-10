// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared actual source retirement, target activation and client approval fixture.
use super::*;
use std::{
    io::{self, Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicU64, AtomicUsize},
        Mutex,
    },
    time::Instant,
};
pub(in crate::enrollment::tests) struct Transfer {
    _directory: tempfile::TempDir,
    pub(in crate::enrollment::tests) plan: WitnessJournalAdoptionPlan,
    pub(in crate::enrollment::tests) receipt: Vec<u8>,
    pub(in crate::enrollment::tests) control: AnchorHandoffClientAuthorizationReceipt,
    approval: AnchorHandoffTargetApproval,
    retirement: Vec<u8>,
    signer_id: SigningKeyId,
    public_inputs: Vec<(&'static str, Vec<u8>)>,
    pub(in crate::enrollment::tests) target: Arc<Mutex<AnchorStore>>,
    clock: Arc<AtomicU64>,
    pub(in crate::enrollment::tests) requests: Arc<AtomicUsize>,
}
impl Transfer {
    pub(in crate::enrollment::tests) fn successor(
        &self,
        c: &Case,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
        subject: AnchorSubject,
        decision: (u64, u8),
    ) -> Self {
        let mut next = Self::with_decision(
            &mut self.target.lock().expect("actual selected source"),
            c,
            original,
            current,
            policy,
            subject,
            decision,
        );
        next.plan = next
            .plan
            .clone()
            .continue_from(&self.plan, &self.control)
            .expect("independently retained exact predecessor and target receipt");
        next
    }
    pub(in crate::enrollment::tests) fn reopen_target(&self) {
        let path = self
            ._directory
            .path()
            .canonicalize()
            .expect("original target directory");
        let mut target = self.target.lock().expect("exclusive target");
        target.close();
        let key = JournalKey::open(&path.join("target.key")).expect("same target key");
        let signer = AnchorSigningKey::open(&path.join("target.signer"), &key, self.signer_id)
            .expect("same protected target signer");
        let mut imported =
            AnchorHandoffTarget::open(&path.join("target.redb"), key, self.approval.clone())
                .expect("original activated state");
        *target = imported
            .activate(&self.retirement, signer)
            .expect("exact activation reopen")
            .0;
    }
    pub(in crate::enrollment::tests) fn adopt_parent(&self, c: &Case, at: u64) -> DeviceEnrollment {
        let mut owner = open(c);
        owner
            .prepare_witness_handoff(c.policy.historical(), self.plan.clone(), || Ok(at))
            .expect("prepare original parent selection");
        owner
            .adopt_witness_handoff(c.policy.historical(), self.plan.clone(), &self.receipt)
            .expect("adopt exact original selection");
        owner
    }
    pub(in crate::enrollment::tests) fn client(
        &self,
        owner: &mut DeviceEnrollment,
        c: &Case,
    ) -> AnchorClient {
        owner
            .current_witness_anchor_client(
                c.policy.historical(),
                self.plan.clone(),
                self.carrier(),
                Duration::from_secs(3),
            )
            .expect("retained signer and selected child")
    }
    pub(in crate::enrollment::tests) fn new(
        source: &mut AnchorStore,
        c: &Case,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
        current_policy: &HistoricalSessionPolicy,
        subject: AnchorSubject,
        at: u64,
    ) -> Self {
        Self::with_decision(
            source,
            c,
            original,
            current,
            current_policy,
            subject,
            (at, 75),
        )
    }
    pub(in crate::enrollment::tests) fn with_decision(
        source: &mut AnchorStore,
        c: &Case,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
        current_policy: &HistoricalSessionPolicy,
        subject: AnchorSubject,
        decision: (u64, u8),
    ) -> Self {
        let (at, operation) = decision;
        let directory = directory();
        let path = directory.path().canonicalize().expect("target directory");
        let origin = source.pin().expect("original source pin");
        let until = at.checked_add(20).expect("fixture interval");
        let adopt_at = at.checked_add(1).expect("fixture admission");
        let target_key =
            JournalKey::provision(&path.join("target.key")).expect("distinct target storage key");
        let signer_id = SigningKeyId::generate().expect("target signer identity");
        let target_signer =
            AnchorSigningKey::provision(&path.join("target.signer"), &target_key, signer_id)
                .expect("distinct protected witness signer");
        let target_pin = AnchorPin::new(
            AnchorIdentity::generate().expect("target ID"),
            target_signer.public_key().expect("target public"),
        );
        let image = source
            .handoff_source_state()
            .expect("full original witness state");
        let transfer = AnchorHandoffPlan::from_trusted_state(
            [operation; 32],
            &image,
            target_pin.clone(),
            Validity::new(at, until).expect("transfer interval"),
            [76; 32],
        )
        .expect("source approval");
        let approval = AnchorHandoffTargetApproval::from_trusted_state(
            &transfer,
            &origin,
            &target_pin,
            Validity::new(at, until).expect("target interval"),
            [77; 32],
        )
        .expect("independent target approval");
        let freeze = source.freeze_handoff(&transfer, at).expect("source frozen");
        let mut imported = AnchorHandoffTarget::provision_import(
            &path.join("target.redb"),
            target_key,
            &target_signer,
            approval.clone(),
            image.as_bytes(),
            freeze.as_bytes(),
            at,
        )
        .expect("full state imported");
        let ack = imported.import_receipt().expect("exact import");
        let retirement = source
            .retire_handoff(&approval, ack.as_bytes(), || Ok(at))
            .expect("irreversible retirement");
        let history = imported
            .verify_source_retirement(retirement.as_bytes())
            .expect("verified root history");
        let (mut target, activation) = imported
            .activate(retirement.as_bytes(), target_signer)
            .expect("target activated");
        let materials = AnchorHandoffAdoptionMaterials {
            original_device: original,
            current_device: current,
            original_policy: c.policy.historical(),
            current_policy,
            history: &history,
            activation: &activation,
        };
        let scope = target
            .handoff_adoption_scope(
                AnchorHandoffAdoptionId::generate().expect("adoption ID"),
                subject,
                &materials,
                Validity::new(adopt_at, until).expect("client admission"),
            )
            .expect("original imported client");
        let statement = AnchorHandoffAdoptionStatement::new(&scope, &materials, adopt_at)
            .expect("exact decision");
        // This is the existing policy fixture's independently held issuer; the
        // device signer itself was generated and sealed by actual enrollment.
        let issuer =
            PolicySigningKey::deterministic([82; 32], [83; 32]).expect("fixture policy issuer");
        let account_approval = c
            .root
            .approve_anchor_handoff_adoption(&statement)
            .expect("account approval");
        let policy_approval = issuer
            .approve_anchor_handoff_adoption(&statement)
            .expect("policy approval");
        let approved = HistoricalAnchorHandoffAdoption::from_approvals(
            &account_approval,
            &policy_approval,
            &scope,
            &materials,
        )
        .expect("two-root approval");
        let plan = WitnessJournalAdoptionPlan::new(&approved, &materials)
            .expect("independent client plan");
        let control = target
            .authorize_handoff_client(plan.authorization_request(), || Ok(adopt_at))
            .expect("target authorization");
        let receipt = control.as_bytes().to_vec();
        let namespace = history
            .historical_pin(history.namespace_binding())
            .expect("original namespace pin");
        let public_inputs = vec![
            (
                "origin-pin",
                [
                    namespace.identity().as_bytes().as_slice(),
                    &namespace.public_key().encode(),
                ]
                .concat(),
            ),
            (
                "source-pin",
                [
                    origin.identity().as_bytes().as_slice(),
                    &origin.public_key().encode(),
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
            ("history", history.to_bytes().expect("public history")),
            ("checkpoint", history.checkpoint().to_vec()),
            ("target-approval", approval.to_bytes()),
            ("freeze", freeze.as_bytes().to_vec()),
            ("ack", ack.as_bytes().to_vec()),
            ("retired", retirement.as_bytes().to_vec()),
            ("activation", activation.as_bytes().to_vec()),
            ("scope", scope.to_bytes()),
            ("account-approval", account_approval.as_bytes().to_vec()),
            ("policy-approval", policy_approval.as_bytes().to_vec()),
            (
                "policy-root",
                issuer.public_key().expect("policy root").encode(),
            ),
            (
                "policy-checkpoint",
                [
                    c.policy.checkpoint().version().to_be_bytes().as_slice(),
                    &c.policy.checkpoint().digest(),
                ]
                .concat(),
            ),
            ("policy-wire", c.initial_policy_wire.clone()),
            ("account-root", c.intent.root.encode()),
            ("receipt", receipt.clone()),
        ];
        Self {
            _directory: directory,
            public_inputs,
            plan,
            receipt,
            control,
            approval,
            retirement: retirement.as_bytes().to_vec(),
            signer_id,
            target: Arc::new(Mutex::new(target)),
            clock: Arc::new(AtomicU64::new(adopt_at)),
            requests: Arc::new(AtomicUsize::new(0)),
        }
    }
    pub(in crate::enrollment::tests) fn publish_public_inputs(&self, root: &Path) {
        for (name, bytes) in &self.public_inputs {
            fs::write(root.join(name), bytes).expect("owned exact public inputs");
        }
    }
    pub(in crate::enrollment::tests) fn set_time(&self, now: u64) {
        self.clock.store(now, Ordering::SeqCst);
    }
    pub(in crate::enrollment::tests) fn carrier(&self) -> Box<dyn AnchorTransport> {
        Box::new(Carrier(
            Arc::clone(&self.target),
            Arc::clone(&self.clock),
            Arc::clone(&self.requests),
        ))
    }
}
struct Carrier(Arc<Mutex<AnchorStore>>, Arc<AtomicU64>, Arc<AtomicUsize>);
impl AnchorTransport for Carrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        self.2.fetch_add(1, Ordering::SeqCst);
        let now = self.1.load(Ordering::SeqCst);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let target = Arc::clone(&self.0);
        std::thread::scope(|scope| {
            let server = scope.spawn(move || -> io::Result<()> {
                let mut stream = loop {
                    if Instant::now() >= deadline {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    match listener.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(e) => return Err(e),
                    }
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let mut prefix = [0; 4];
                stream.read_exact(&mut prefix)?;
                if u32::from_be_bytes(prefix) as usize != crate::anchor::transferred::REQUEST_BYTES
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let mut input = vec![0; crate::anchor::transferred::REQUEST_BYTES];
                stream.read_exact(&mut input)?;
                let reply = target
                    .lock()
                    .map_err(|_| io::Error::other("witness poisoned"))?
                    .handle(&input, now)
                    .map_err(io::Error::other)?;
                stream.write_all(&(reply.len() as u32).to_be_bytes())?;
                stream.write_all(&reply)
            });
            let result = AnchorTcpTransport::new(address).exchange(request, deadline);
            server
                .join()
                .map_err(|_| io::Error::other("witness thread panic"))??;
            result
        })
    }
}
