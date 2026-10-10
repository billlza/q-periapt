// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorAccountReplacementId, AnchorAccountReplacementState, AnchorGenesis, AnchorIdentity,
    AnchorRequirement, AnchorSigningKey, AnchorStore, AnchorTransport, ApplicationSendBudget,
    DeviceDescription, RootSigningKey,
};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, sync::Mutex};

pub(super) struct Carrier(pub(super) Arc<Mutex<AnchorStore>>);
impl AnchorTransport for Carrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0
            .lock()
            .expect("fixture witness lock")
            .handle(request, 150)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}
pub(super) struct Case {
    pub(super) _directory: tempfile::TempDir,
    pub(super) path: PathBuf,
    pub(super) witness: Arc<Mutex<AnchorStore>>,
    pub(super) pin: AnchorPin,
    pub(super) f: crate::bootstrap::tests::Fixture,
    pub(super) journal: DeviceJournal,
    pub(super) identity: JournalIdentity,
    pub(super) genesis: AnchorGenesis,
    pub(super) next: VerifiedDevice,
    pub(super) next_genesis: AnchorGenesis,
    pub(super) next_identity: JournalIdentity,
    pub(super) next_path: PathBuf,
}
impl Case {
    pub(super) fn connected_peer(&mut self) -> (DeviceJournal, [u8; 32]) {
        let path = self
            .path
            .parent()
            .expect("canonical fixture root")
            .join("peer");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private peer directory");
        let identity = crate::durable::tests::retain_new_identity(&path.join("store-id"));
        let device = self.f.initiator_device();
        let policy = self.f.initiator.current_policy().expect("peer policy");
        let mut peer = DeviceJournal::provision_anchored(
            &path.join("state.redb"),
            JournalKey::provision(&path.join("key")).expect("peer key"),
            device,
            policy,
            identity,
            150,
        )
        .expect("peer genesis");
        let genesis = peer
            .anchor_genesis(device, policy)
            .expect("peer enrollment");
        self.witness
            .lock()
            .expect("witness lock")
            .enroll(&genesis, device, policy, 150)
            .expect("peer admission");
        let client = crate::AnchorClient::new(
            self.pin.clone(),
            DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("peer signer"),
            Box::new(Carrier(Arc::clone(&self.witness))),
            Duration::from_secs(10),
        )
        .expect("peer client");
        peer.activate_anchor(device, policy, client)
            .expect("peer activation");
        let session = self.connect_peer(&mut peer);
        (peer, session)
    }
    pub(super) fn connect_peer(&mut self, peer: &mut DeviceJournal) -> [u8; 32] {
        let request = crate::InitiationId::from_trusted_state([211; 32])
            .expect("original bootstrap operation");
        let initial = peer
            .initiate(
                Arc::clone(&self.f.initiator),
                request,
                &self.f.signer_i,
                150,
            )
            .expect("durable initial");
        let (pq, classical) = self.f.sources();
        let reply = self
            .journal
            .respond(
                Arc::clone(&self.f.responder),
                &initial,
                &self.f.signer_r,
                pq,
                classical,
                150,
            )
            .expect("durable reply");
        let result = peer
            .accept_reply(Arc::clone(&self.f.initiator), request, &reply, 150)
            .expect("durable final");
        let session = self
            .journal
            .finish(
                Arc::clone(&self.f.responder),
                &initial,
                result.final_message(),
                150,
            )
            .expect("responder final");
        assert_eq!(
            peer.activate_initiator_messages(Arc::clone(&self.f.initiator), request, 150)
                .expect("initiator chains"),
            session
        );
        assert_eq!(
            self.journal
                .activate_responder_messages(Arc::clone(&self.f.responder), &initial, 150)
                .expect("responder chains"),
            session
        );
        session
    }
    pub(super) fn proposal(&self, id: u8) -> Proposal {
        self.witness
            .lock()
            .expect("fixture witness lock")
            .account_root_replacement_proposal(
                AnchorAccountReplacementId::from_trusted_state([id; 32])
                    .expect("original operation"),
                &self.f.local_device().authority_key,
                &self.next_genesis,
                &self.next,
                self.f.responder.current_policy().expect("fixture policy"),
                150,
            )
            .expect("original complete proposal")
    }
    pub(super) fn receipt(&self, p: &Proposal) -> Vec<u8> {
        let mut witness = self.witness.lock().expect("fixture witness lock");
        assert_eq!(
            witness
                .replace_account_root(
                    p,
                    &self.f.local_device().authority_key,
                    &self.next_genesis,
                    &self.next,
                    self.f.responder.current_policy().expect("policy"),
                    150
                )
                .expect("original witness commit"),
            AnchorAccountReplacementState::Committed
        );
        witness
            .retired_account_receipt(p)
            .expect("exact signed retirement")
    }
    pub(super) fn key(&self) -> JournalKey {
        JournalKey::open(&self.path.join("key")).expect("original key")
    }
    pub(super) fn resume(&self, p: &Proposal) -> AccountRootJournalRecovery {
        AccountRootJournalRecovery::resume_original(
            &self.path.join("state.redb"),
            self.key(),
            self.f.local_device(),
            self.identity,
            self.pin.clone(),
            p.clone(),
        )
        .expect("original fence recovery")
    }
    pub(super) fn client(&self, next: bool) -> crate::AnchorClient {
        crate::AnchorClient::new(
            self.pin.clone(),
            DeviceSigningKey::deterministic(
                [if next { 184 } else { 96 }; 32],
                [if next { 185 } else { 97 }; 32],
            )
            .expect("fixture signer"),
            Box::new(Carrier(Arc::clone(&self.witness))),
            Duration::from_secs(10),
        )
        .expect("bounded client")
    }
    pub(super) fn assert_ordinary_refused(&self) {
        assert!(matches!(
            DeviceJournal::open(
                &self.path.join("state.redb"),
                self.key(),
                self.f.local_device(),
                self.identity
            ),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            DeviceJournal::open_anchored(
                &self.path.join("state.redb"),
                self.key(),
                self.f.local_device(),
                self.f.responder.current_policy().expect("policy"),
                self.identity,
                self.client(false)
            ),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            DeviceJournal::recover_anchor_genesis(
                &self.path.join("state.redb"),
                self.key(),
                self.f.local_device(),
                self.f.responder.current_policy().expect("policy"),
                self.identity
            ),
            Err(DurableError::Suspended)
        ));
    }
}
pub(super) fn case() -> Case {
    let directory = crate::durable::tests::directory();
    let base = directory.path().canonicalize().expect("fixture root");
    let path = base.join("old");
    let next_path = base.join("next");
    let server = base.join("witness");
    for p in [&path, &next_path, &server] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(p)
            .expect("private fixture directory");
    }
    let witness_key = JournalKey::provision(&server.join("key")).expect("witness wrapping key");
    let signer = AnchorSigningKey::generate().expect("fixture witness signer");
    let witness_id = AnchorIdentity::generate().expect("fixture witness identity");
    let mut witness =
        AnchorStore::provision(&server.join("state.redb"), witness_key, signer, witness_id)
            .expect("witness store");
    let pin = witness.pin().expect("independent witness pin");
    let f = crate::bootstrap::tests::fixture_with_anchor_and_budget(
        crate::PrekeyQuality::OneTimeBoth,
        AnchorRequirement::required(&pin),
        ApplicationSendBudget::new(1024).expect("send budget"),
    );
    let identity = crate::durable::tests::retain_new_identity(&path.join("store-id"));
    let mut journal = DeviceJournal::provision_anchored(
        &path.join("state.redb"),
        JournalKey::provision(&path.join("key")).expect("original key"),
        f.local_device(),
        f.responder.current_policy().expect("policy"),
        identity,
        150,
    )
    .expect("original genesis");
    let genesis = journal
        .anchor_genesis(
            f.local_device(),
            f.responder.current_policy().expect("policy"),
        )
        .expect("original enrollment");
    witness
        .enroll(
            &genesis,
            f.local_device(),
            f.responder.current_policy().expect("policy"),
            150,
        )
        .expect("trusted old enrollment");
    let root = RootSigningKey::deterministic([180; 32], [181; 32]).expect("new root");
    let signer = DeviceSigningKey::deterministic([184; 32], [185; 32]).expect("new device key");
    let old = f.local_device();
    let description = DeviceDescription::new(
        old.device_id(),
        old.generation(),
        old.description.family,
        old.description.validity,
    )
    .expect("new device description");
    let certificate = root
        .issue_device(description, signer.public_key().expect("new public key"))
        .expect("new credential");
    let roster = root
        .issue_roster(
            1,
            old.roster_validity,
            &[root.roster_entry(&certificate).expect("new member")],
        )
        .expect("new roster");
    let next = crate::AccountPin::new(
        root.account_id().expect("new account"),
        root.public_key().expect("new root key"),
        roster.checkpoint(),
        old.description.family,
    )
    .expect("independent target pin")
    .verify_device(&certificate, roster.as_bytes(), 150)
    .expect("new verified device");
    let next_identity = crate::durable::tests::retain_new_identity(&next_path.join("store-id"));
    let mut next_journal = DeviceJournal::provision_anchored(
        &next_path.join("state.redb"),
        JournalKey::provision(&next_path.join("key")).expect("target key"),
        &next,
        f.responder.current_policy().expect("policy"),
        next_identity,
        150,
    )
    .expect("target genesis");
    let next_genesis = next_journal
        .anchor_genesis(&next, f.responder.current_policy().expect("policy"))
        .expect("exact target enrollment");
    next_journal.close();
    let mut c = Case {
        _directory: directory,
        path,
        witness: Arc::new(Mutex::new(witness)),
        pin,
        f,
        journal,
        identity,
        genesis,
        next,
        next_genesis,
        next_identity,
        next_path,
    };
    c.journal.close();
    c.journal = DeviceJournal::open_anchored(
        &c.path.join("state.redb"),
        c.key(),
        c.f.local_device(),
        c.f.responder.current_policy().expect("policy"),
        c.identity,
        c.client(false),
    )
    .expect("live original witnessed owner");
    c
}
pub(super) fn rows(db: &Database) -> (Vec<u8>, Option<Vec<u8>>) {
    let tx = db.begin_read().expect("fixture read");
    let table = image_table(&tx).expect("original schema");
    let image = table
        .get("image")
        .expect("image read")
        .expect("original image")
        .value()
        .to_vec();
    let pending = table
        .get("pending")
        .expect("intent read")
        .map(|v| v.value().to_vec());
    (image, pending)
}
