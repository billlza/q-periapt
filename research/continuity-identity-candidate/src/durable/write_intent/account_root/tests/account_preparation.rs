// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityCheckpoint, AccountAuthorityIdentity,
    AccountAuthorityReplacementState as State, AccountAuthorityStore, AnchorAccountFreezeId,
    AnchorAccountFreezeRequest, AnchorAccountReplacementId, AnchorAccountReplacementPlan,
    ApplicationAccountId, JournalAccountAuthority,
};
#[path = "account_preparation/closure.rs"]
mod closure;
#[path = "account_preparation/process.rs"]
mod process;
#[path = "account_preparation/recovery.rs"]
mod recovery;
#[path = "account_preparation/transition.rs"]
mod transition;

struct Prepared {
    c: Case,
    registry: AccountAuthorityStore,
    identity: AccountAuthorityIdentity,
    expected: AccountAuthorityCheckpoint,
    other: AccountAuthorityCheckpoint,
    plan: AnchorAccountReplacementPlan,
    peer: DeviceJournal,
    session: [u8; 32],
}
impl Prepared {
    fn new() -> Self {
        Self::with_target_until(None)
    }
    fn with_target_until(until: Option<u64>) -> Self {
        let mut c = case_with_target_until(until);
        let base = c.path.parent().expect("owned fixture root");
        let identity = AccountAuthorityIdentity::generate().expect("original registry identity");
        let mut registry = AccountAuthorityStore::provision(
            &base.join("authority.redb"),
            JournalKey::provision(&base.join("authority-key")).expect("separate original key"),
            identity,
            c.f.local_device().description.family,
            c.pin.clone(),
        )
        .expect("original registry");
        let expected = registry
            .associate(
                ApplicationAccountId::from_trusted_state([31; 32]).expect("local app"),
                c.f.local_device(),
            )
            .expect("local root association");
        let other = registry
            .associate(
                ApplicationAccountId::from_trusted_state([32; 32]).expect("peer app"),
                c.f.initiator_device(),
            )
            .expect("peer root association");
        c.journal
            .adopt_account_authority(
                JournalAccountAuthority::new(registry.access().expect("access"), expected)
                    .expect("original scope"),
            )
            .expect("durable local binding");
        let (peer, session) = c.connected_peer();
        let request = AnchorAccountFreezeRequest::from_trusted_state(
            AnchorAccountFreezeId::from_trusted_state([241; 32])
                .expect("original freeze operation"),
            c.f.local_device().authority_key.clone(),
            &c.pin,
        )
        .expect("independent freeze approval");
        let plan = c
            .witness
            .lock()
            .expect("witness")
            .account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([242; 32])
                    .expect("original replacement operation"),
                request,
                &c.next_genesis,
                &c.next,
                c.f.responder.current_policy().expect("policy"),
                150,
            )
            .expect("original target and freeze plan");
        Self {
            c,
            registry,
            identity,
            expected,
            other,
            plan,
            peer,
            session,
        }
    }
    fn reopen(&mut self) {
        self.registry.close();
        let base = self.c.path.parent().expect("owned fixture root");
        self.registry = AccountAuthorityStore::open(
            &base.join("authority.redb"),
            JournalKey::open(&base.join("authority-key")).expect("same key"),
            self.identity,
            self.c.f.local_device().description.family,
            self.c.pin.clone(),
        )
        .expect("same original registry");
    }
    fn query(&self) -> crate::AnchorReply {
        let request = crate::AnchorRequest::new(
            &self.c.pin,
            self.c.genesis.subject(),
            crate::AnchorOperation::query(),
            &self.c.f.signer_r,
        )
        .expect("fresh original query");
        let wire = self
            .c
            .witness
            .lock()
            .expect("witness")
            .handle(request.as_bytes(), 150)
            .expect("old witness still live before freeze");
        self.c
            .pin
            .verify_reply(&request, &wire)
            .expect("authenticated original observation")
    }
    fn frozen(&self) -> crate::AnchorFrozenAccount {
        let mut witness = self.c.witness.lock().expect("witness");
        witness
            .freeze_account(self.plan.request())
            .expect("exact original freeze");
        let wire = witness
            .account_freeze_receipt(self.plan.request())
            .expect("signed original complete snapshot");
        self.c
            .pin
            .verify_account_freeze(self.plan.request(), &wire)
            .expect("independently pinned exact original snapshot")
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.registry.close();
        self.peer.close();
        self.c.journal.close();
    }
}
#[test]
fn account_preparation_retains_original_target_before_freeze_and_recovers_after_real_head_progress()
{
    let mut p = Prepared::new();
    let saved_plan = p.plan.to_bytes().expect("canonical original plan");
    assert!(saved_plan.len() <= 8192);
    assert_eq!(
        AnchorAccountReplacementPlan::from_trusted_state(&saved_plan).expect("exact retained plan"),
        p.plan
    );
    let old_head = p.query().observed_head();
    let id =
        p.c.journal
            .next_message_id(&p.c.f.responder, p.session, 150)
            .expect("original message identity");
    let wire =
        p.c.journal
            .send_message(
                &p.c.f.responder,
                p.session,
                id,
                b"after plan before freeze",
                b"original preparation",
                150,
            )
            .expect("actual intervening old-device work");
    assert_eq!(
        p.peer
            .receive_message(
                &p.c.f.initiator,
                p.session,
                &wire,
                b"original preparation",
                150
            )
            .expect("actual peer decrypt")
            .as_bytes(),
        b"after plan before freeze"
    );
    let current_head = p.query().observed_head();
    assert_ne!(old_head, current_head);
    let access = p.registry.access().expect("original access");
    let old = access.admit(p.expected).expect("original live lease");
    let other = access.admit(p.other).expect("unrelated live lease");
    assert_eq!(
        p.registry
            .begin_preparation(p.expected, p.plan.clone())
            .expect("durable original local draft"),
        State::Preparing
    );
    assert!(matches!(old.check(), Err(DurableError::Suspended)));
    other.check().expect("unrelated entry remains live");
    assert!(
        matches!(
            p.registry.replacement(p.plan.operation()),
            Err(DurableError::Suspended)
        ),
        "a target template is not an exact witness proposal"
    );
    assert!(matches!(
        p.c.journal
            .resume_message(&p.c.f.responder, p.session, id, 150),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        p.query().observed_head(),
        current_head,
        "local fence precedes witness freeze"
    );
    p.reopen();
    assert!(matches!(
        access.current(p.expected.application()),
        Err(DurableError::Closed)
    ));
    let (app, state, restored) = p
        .registry
        .preparation(p.plan.operation())
        .expect("same original plan after reopen");
    assert_eq!(app, p.expected.application());
    assert_eq!(state, State::Preparing);
    assert_eq!(restored.to_bytes().expect("exact bytes"), saved_plan);
    assert!(matches!(
        p.registry.access().expect("new owner").current(app),
        Err(DurableError::Suspended)
    ));
    crate::account_authority::tests::rejects_preparation_images(&p.registry);
    let frozen = p.frozen();
    assert_eq!(
        frozen
            .subjects()
            .find(|entry| entry.subject() == p.c.genesis.subject())
            .expect("original frozen subject")
            .observed_head(),
        current_head
    );
    assert_eq!(
        p.registry
            .bind_preparation(p.plan.operation(), &frozen)
            .expect("bind only exact authenticated freeze"),
        State::Pending
    );
    let (_, _, proposal) = p
        .registry
        .replacement(p.plan.operation())
        .expect("exact original bound proposal");
    let proposal = proposal.clone();
    crate::account_authority::tests::rejects_preparation_images(&p.registry);
    p.reopen();
    assert_eq!(
        p.registry
            .begin_preparation(p.expected, p.plan.clone())
            .expect("original preparation retry after binding"),
        State::Pending
    );
    assert_eq!(
        p.registry
            .bind_preparation(p.plan.operation(), &frozen)
            .expect("exact binding retry"),
        State::Pending
    );
    assert_eq!(
        p.registry
            .replacement(p.plan.operation())
            .expect("retained original bound snapshot")
            .2,
        &proposal
    );
    let mut recovery = p.c.resume(&proposal);
    let receipt = p.c.receipt(&proposal);
    recovery
        .retain_witness_retirement(&receipt)
        .expect("retained original child fence and decision");
    let retired =
        p.c.pin
            .verify_retired_account(&proposal, &receipt)
            .expect("independent exact retirement");
    assert_eq!(
        p.registry
            .commit_replacement(&retired)
            .expect("original root mapping commit"),
        State::Committed
    );
    p.reopen();
    assert_eq!(
        p.registry
            .begin_preparation(p.expected, p.plan.clone())
            .expect("historical original preparation"),
        State::Committed
    );
    let current = p
        .registry
        .access()
        .expect("current owner")
        .current(p.expected.application())
        .expect("selected successor");
    assert_eq!(current.revision(), 2);
    assert_eq!(current.account(), proposal.successor_account());
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("retained original intent forever")
            .2
            .to_bytes()
            .expect("original bytes"),
        saved_plan
    );
    assert!(matches!(old.check(), Err(DurableError::Closed)));
}

#[test]
fn account_preparation_rejects_changed_request_target_and_other_authenticated_freeze() {
    let mut p = Prepared::new();
    let mut changed = p.plan.to_bytes().expect("original plan");
    let expiry = changed
        .len()
        .checked_sub(3)
        .expect("policy expiry before empty predecessor count");
    assert_eq!(
        changed.get(expiry + 1..).expect("empty predecessor count"),
        [0, 0]
    );
    *changed.get_mut(expiry).expect("target policy expiry byte") ^= 1;
    let changed = AnchorAccountReplacementPlan::from_trusted_state(&changed)
        .expect("syntactically valid altered target expectation");
    assert_ne!(changed, p.plan);
    let changed_request = AnchorAccountFreezeRequest::from_trusted_state(
        AnchorAccountFreezeId::from_trusted_state([243; 32]).expect("different request"),
        p.c.f.local_device().authority_key.clone(),
        &p.c.pin,
    )
    .expect("same account different original request");
    let changed_request_plan =
        p.c.witness
            .lock()
            .expect("witness")
            .account_replacement_plan(
                p.plan.operation(),
                changed_request,
                &p.c.next_genesis,
                &p.c.next,
                p.c.f.responder.current_policy().expect("policy"),
                150,
            )
            .expect("different plan before freezing");
    p.registry
        .begin_preparation(p.expected, p.plan.clone())
        .expect("original independent approval");
    for changed in [changed, changed_request_plan] {
        assert!(matches!(
            p.registry.begin_preparation(p.expected, changed),
            Err(DurableError::Conflict)
        ));
    }
    let unrelated = AnchorAccountFreezeRequest::from_trusted_state(
        AnchorAccountFreezeId::from_trusted_state([244; 32]).expect("unrelated request"),
        p.c.f.initiator_device().authority_key.clone(),
        &p.c.pin,
    )
    .expect("independent unrelated namespace");
    let wrong =
        p.c.witness
            .lock()
            .expect("witness")
            .freeze_account(&unrelated)
            .expect("actual authenticated other account freeze");
    assert!(matches!(
        p.registry.bind_preparation(p.plan.operation(), &wrong),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("original approval unchanged")
            .2,
        &p.plan
    );
    let frozen = p.frozen();
    p.registry
        .bind_preparation(p.plan.operation(), &frozen)
        .expect("original freeze still binds");
    p.reopen();
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("original approval after restart")
            .2,
        &p.plan
    );
    assert!(matches!(
        p.registry.bind_preparation(p.plan.operation(), &wrong),
        Err(DurableError::Protocol(Error::Scope))
    ));
}
