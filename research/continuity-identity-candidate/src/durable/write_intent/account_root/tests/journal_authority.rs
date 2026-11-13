// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityCheckpoint, AccountAuthorityIdentity, AccountAuthorityStore,
    ApplicationAccountId, JournalAccountAuthority,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    Mutex,
};
#[path = "journal_authority/recovery.rs"]
mod recovery;

struct Managed {
    c: Case,
    registry: Arc<Mutex<AccountAuthorityStore>>,
    local: AccountAuthorityCheckpoint,
    peer: AccountAuthorityCheckpoint,
    admission: JournalAccountAuthority,
    sender: DeviceJournal,
    session: [u8; 32],
}
impl Managed {
    fn new() -> Self {
        let mut m = Self::unbound();
        m.sender
            .adopt_account_authority(m.admission.clone())
            .expect("durable registry binding");
        m
    }
    fn unbound() -> Self {
        let mut c = case();
        let (sender, session) = c.connected_peer();
        let base = c.path.parent().expect("fixture parent");
        let mut registry = AccountAuthorityStore::provision(
            &base.join("authority.redb"),
            JournalKey::provision(&base.join("authority-key")).expect("independent key"),
            AccountAuthorityIdentity::generate().expect("independent identity"),
            c.f.initiator_device().description.family,
            c.pin.clone(),
        )
        .expect("original registry");
        let local = registry
            .associate(
                ApplicationAccountId::from_trusted_state([11; 32]).expect("local app"),
                c.f.initiator_device(),
            )
            .expect("local association");
        let peer = registry
            .associate(
                ApplicationAccountId::from_trusted_state([12; 32]).expect("peer app"),
                c.f.local_device(),
            )
            .expect("peer association");
        let admission = JournalAccountAuthority::new(registry.access().expect("access"), local)
            .expect("original admission");
        Self {
            c,
            registry: Arc::new(Mutex::new(registry)),
            local,
            peer,
            admission,
            sender,
            session,
        }
    }
    fn path(&self) -> std::path::PathBuf {
        self.c.path.parent().expect("parent").join("peer")
    }
    fn client(&self, transport: Box<dyn crate::AnchorTransport>) -> crate::AnchorClient {
        crate::AnchorClient::new(
            self.c.pin.clone(),
            DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("original sender"),
            transport,
            Duration::from_secs(10),
        )
        .expect("original pinned client")
    }
    fn reopen(
        &self,
        identity: JournalIdentity,
        client: crate::AnchorClient,
    ) -> Result<DeviceJournal, DurableError> {
        DeviceJournal::open_anchored_with_account_authority(
            &self.path().join("state.redb"),
            JournalKey::open(&self.path().join("key"))?,
            self.c.f.initiator_device(),
            self.c.f.initiator.current_policy()?,
            identity,
            client,
            self.admission.clone(),
        )
    }
    fn ordinary_client(&self) -> crate::AnchorClient {
        self.client(Box::new(Carrier(Arc::clone(&self.c.witness))))
    }
}
impl Drop for Managed {
    fn drop(&mut self) {
        self.sender.close();
        self.registry.lock().expect("owned registry").close();
    }
}

#[test]
fn journal_account_authority_fences_real_peer_traffic_and_preserves_unknown_deliveries() {
    let mut m = Managed::new();
    let identity = m.sender.identity().expect("original sender identity");
    let id = m
        .sender
        .next_message_id(&m.c.f.initiator, m.session, 150)
        .expect("original message");
    let wire = m
        .sender
        .send_message(
            &m.c.f.initiator,
            m.session,
            id,
            b"original payload",
            b"authority",
            150,
        )
        .expect("actual ciphertext");
    assert_eq!(
        m.c.journal
            .receive_message(&m.c.f.responder, m.session, &wire, b"authority", 150)
            .expect("actual peer receive")
            .as_bytes(),
        b"original payload"
    );
    m.c.journal
        .consume_message(&m.c.f.responder, m.session, id, 150)
        .expect("remote consumption");
    let ack =
        m.c.journal
            .message_acknowledgement(&m.c.f.responder, m.session, 150)
            .expect("valid ACK held in transit");
    let inbound_id =
        m.c.journal
            .next_message_id(&m.c.f.responder, m.session, 150)
            .expect("inbound id");
    let inbound =
        m.c.journal
            .send_message(
                &m.c.f.responder,
                m.session,
                inbound_id,
                b"in transit",
                b"authority",
                150,
            )
            .expect("valid inbound ciphertext");
    let bound_image = m.sender.image().expect("bound image").digest;
    m.sender
        .adopt_account_authority(m.admission.clone())
        .expect("exact adoption retry");
    assert_eq!(m.sender.image().expect("same image").digest, bound_image);
    m.sender.close();
    let backup = fs::read(m.path().join("state.redb")).expect("complete bound backup");
    assert!(matches!(
        DeviceJournal::open_anchored(
            &m.path().join("state.redb"),
            JournalKey::open(&m.path().join("key")).expect("original key"),
            m.c.f.initiator_device(),
            m.c.f.initiator.current_policy().expect("policy"),
            identity,
            m.ordinary_client()
        ),
        Err(DurableError::Conflict)
    ));
    m.sender = m
        .reopen(identity, m.ordinary_client())
        .expect("original managed reopen");
    assert_eq!(
        m.sender
            .resume_message(&m.c.f.initiator, m.session, id, 150)
            .expect("before root fence"),
        wire
    );
    let proposal = m.c.proposal(248);
    m.registry
        .lock()
        .expect("registry")
        .begin_replacement(m.peer, proposal.clone())
        .expect("durable peer root intent");
    assert!(
        m.c.witness
            .lock()
            .expect("witness")
            .retired_account_receipt(&proposal)
            .is_err(),
        "the witness has not retired the root yet"
    );
    for _ in 0..2 {
        assert!(matches!(
            m.sender
                .resume_message(&m.c.f.initiator, m.session, id, 150),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            m.sender
                .receive_message(&m.c.f.initiator, m.session, &inbound, b"authority", 150),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            m.sender
                .accept_message_acknowledgement(&m.c.f.initiator, m.session, &ack, 150),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            m.sender.next_message_id(&m.c.f.initiator, m.session, 150),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            m.sender.install_roster(m.c.f.local_device().roster(), 150),
            Err(DurableError::Suspended)
        ));
        let targets = [crate::FanoutTarget {
            context: &m.c.f.initiator,
            session: m.session,
        }];
        let batch = m
            .sender
            .next_fanout_id()
            .expect("local identity alone is still current");
        assert!(matches!(
            m.sender.send_account_message(
                crate::FanoutInput {
                    id: batch,
                    account: m.peer.account(),
                    targets: &targets,
                    plaintext: b"old root fanout",
                    associated_data: b"authority"
                },
                150
            ),
            Err(DurableError::Suspended)
        ));
        m.sender.close();
        fs::write(m.path().join("state.redb"), &backup)
            .expect("restore only original owned journal backup");
        m.sender = m
            .reopen(identity, m.ordinary_client())
            .expect("same local account remains current");
    }
    let report = m
        .sender
        .begin_session_closure(&m.c.f.initiator, m.session)
        .expect("historical loss accounting remains available");
    assert_eq!(report.peer_account, m.peer.account());
    assert!(report.epochs.iter().any(|e| !e.unconfirmed.is_empty()));
    m.registry
        .lock()
        .expect("registry")
        .access()
        .expect("access")
        .admit(m.local)
        .expect("unrelated local mapping stays live");
}

struct FencingCarrier {
    witness: Arc<Mutex<crate::AnchorStore>>,
    registry: Arc<Mutex<AccountAuthorityStore>>,
    peer: AccountAuthorityCheckpoint,
    proposal: Proposal,
    armed: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}
impl crate::AnchorTransport for FencingCarrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let reply = self
            .witness
            .lock()
            .expect("witness")
            .handle(request, 150)
            .map_err(io::Error::other)?;
        if self.armed.load(Ordering::SeqCst) && self.calls.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
            self.registry
                .lock()
                .expect("registry")
                .begin_replacement(self.peer, self.proposal.clone())
                .map_err(io::Error::other)?;
        }
        Ok(reply)
    }
}

#[test]
fn journal_account_authority_rechecks_after_the_final_real_witness_reply() {
    let mut m = Managed::new();
    let identity = m.sender.identity().expect("identity");
    let id = m
        .sender
        .next_message_id(&m.c.f.initiator, m.session, 150)
        .expect("id");
    m.sender
        .send_message(
            &m.c.f.initiator,
            m.session,
            id,
            b"cached",
            b"authority",
            150,
        )
        .expect("actual cached ciphertext");
    let proposal = m.c.proposal(249);
    let calls = Arc::new(AtomicUsize::new(0));
    let armed = Arc::new(AtomicBool::new(false));
    let client = m.client(Box::new(FencingCarrier {
        witness: Arc::clone(&m.c.witness),
        registry: Arc::clone(&m.registry),
        peer: m.peer,
        proposal,
        calls: Arc::clone(&calls),
        armed: Arc::clone(&armed),
    }));
    m.sender.close();
    m.sender = m.reopen(identity, client).expect("original managed owner");
    armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        m.sender
            .resume_message(&m.c.f.initiator, m.session, id, 150),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "fence after admission, during the final witness reply"
    );
}

#[test]
fn journal_account_authority_pending_local_root_uses_restricted_original_recovery() {
    let mut m = Managed::new();
    let local = JournalAccountAuthority::new(
        m.registry
            .lock()
            .expect("registry")
            .access()
            .expect("access"),
        m.peer,
    )
    .expect("receiver admission");
    m.c.journal
        .adopt_account_authority(local.clone())
        .expect("managed receiver");
    let proposal = m.c.proposal(250);
    m.c.journal.close();
    m.registry
        .lock()
        .expect("registry")
        .begin_replacement(m.peer, proposal.clone())
        .expect("parent intent before journal fence");
    assert!(matches!(
        DeviceJournal::open_anchored_with_account_authority(
            &m.c.path.join("state.redb"),
            m.c.key(),
            m.c.f.local_device(),
            m.c.f.responder.current_policy().expect("policy"),
            m.c.identity,
            m.c.client(false),
            local
        ),
        Err(DurableError::Suspended)
    ));
    let mut recovery = m.c.resume(&proposal);
    assert_eq!(
        recovery
            .status()
            .expect("original fence after interrupted parent step"),
        AccountRootJournalState::LocalFenced
    );
    let receipt = m.c.receipt(&proposal);
    recovery
        .retain_witness_retirement(&receipt)
        .expect("original historical receipt");
    let retired = recovery.retirement().expect("verified original retirement");
    m.registry
        .lock()
        .expect("registry")
        .commit_replacement(&retired)
        .expect("select exact successor");
    assert_eq!(
        m.registry
            .lock()
            .expect("registry")
            .access()
            .expect("access")
            .current(m.peer.application())
            .expect("selected successor")
            .account(),
        m.c.next.account_id()
    );
    assert_eq!(
        recovery.proposal().expect("original operation retained"),
        proposal
    );
}
