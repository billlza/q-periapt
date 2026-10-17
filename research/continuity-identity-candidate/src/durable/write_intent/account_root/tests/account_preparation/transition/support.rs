// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::fs::DirBuilderExt;
enum Terminal {
    Exact(Box<crate::AnchorClosedAccountReplacement>),
    Plan(Box<crate::AnchorClosedAccountPreparation>),
}

pub(super) struct Transition {
    pub(super) p: Prepared,
    pub(super) owner: AccountRootJournalRecovery,
    pub(super) transition: AccountRootJournalTransition,
    pub(super) old: Proposal,
    pub(super) next: Proposal,
    pub(super) device: VerifiedDevice,
    genesis: crate::AnchorGenesis,
    original: (Vec<u8>, Option<Vec<u8>>),
}
impl Transition {
    pub(super) fn new() -> Self {
        Self::build(false)
    }
    pub(super) fn new_exact() -> Self {
        Self::build(true)
    }
    fn build(exact: bool) -> Self {
        let mut p = Prepared::with_target_until(Some(160));
        retain_unacknowledged_and_pending(&mut p);
        let original = rows(&p.c.journal.active.as_ref().expect("old owner").db);
        assert!(original.1.is_some());
        p.registry
            .begin_preparation(p.expected, p.plan.clone())
            .expect("original approval retained first");
        let frozen = p.frozen();
        p.registry
            .bind_preparation(p.plan.operation(), &frozen)
            .expect("original freeze bound");
        let old = p
            .registry
            .replacement(p.plan.operation())
            .expect("original proposal")
            .2
            .clone();
        let owner =
            p.c.journal
                .begin_account_root_replacement(p.c.pin.clone(), old.clone())
                .expect("fence original child");
        {
            let mut witness = p.c.witness.lock().expect("witness");
            assert!(matches!(
                witness.replace_account_root(
                    &old,
                    &p.c.f.local_device().authority_key,
                    &p.c.next_genesis,
                    &p.c.next,
                    p.c.f.responder.current_policy().expect("policy"),
                    170
                ),
                Err(DurableError::Protocol(Error::Validity))
            ));
        }
        let closed = if exact {
            let mut witness = p.c.witness.lock().expect("witness");
            assert_eq!(
                witness
                    .close_account_replacement(&old)
                    .expect("exact original closure"),
                WitnessState::Closed
            );
            let wire = witness
                .closed_account_replacement_receipt(&old)
                .expect("exact signed non-commit");
            let closed =
                p.c.pin
                    .verify_closed_account_replacement(&old, &wire)
                    .expect("exact pinned decision");
            p.registry
                .close_replacement(&closed)
                .expect("durable exact closure");
            Terminal::Exact(Box::new(closed))
        } else {
            let closed = super::super::closure::close_plan(&p);
            p.registry
                .close_preparation(&closed)
                .expect("permanent old target non-commit");
            Terminal::Plan(Box::new(closed))
        };
        assert!(matches!(
            p.registry
                .access()
                .expect("access")
                .current(p.expected.application()),
            Err(DurableError::Suspended)
        ));
        let (device, genesis) = fresh_target(&p);
        let plan = p
            .c
            .witness
            .lock()
            .expect("witness")
            .frozen_account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([246; 32]).expect("fresh operation"),
                &frozen,
                &genesis,
                &device,
                p.c.f.responder.current_policy().expect("policy"),
                170,
            )
            .expect("independently approved current target with same freeze");
        p.registry
            .begin_preparation(p.expected, plan.clone())
            .expect("new approved intent");
        p.registry
            .bind_preparation(plan.operation(), &frozen)
            .expect("same historical freeze");
        let next = p
            .registry
            .replacement(plan.operation())
            .expect("fresh bound proposal")
            .2
            .clone();
        let transition = match closed {
            Terminal::Exact(closed) => {
                AccountRootJournalTransition::from_closed_replacement(*closed, next.clone())
            }
            Terminal::Plan(closed) => {
                AccountRootJournalTransition::from_closed_preparation(*closed, next.clone())
            }
        }
        .expect("authenticated non-commit plus separate approval");
        Self {
            p,
            owner,
            transition,
            old,
            next,
            device,
            genesis,
            original,
        }
    }
    pub(super) fn resume(&mut self) {
        self.owner = AccountRootJournalRecovery::resume_transition(
            &self.p.c.path.join("state.redb"),
            self.p.c.key(),
            self.p.c.f.local_device(),
            self.p.c.identity,
            self.p.c.pin.clone(),
            &self.transition,
        )
        .expect("same transition, either side of original commit");
    }
    pub(super) fn assert_preserved(&self) {
        assert_eq!(
            rows(&self.owner.active.as_ref().expect("restricted owner").db),
            self.original
        );
    }
    pub(super) fn commit(&mut self) {
        let mut witness = self.p.c.witness.lock().expect("witness");
        assert_eq!(
            witness
                .replace_account_root(
                    &self.old,
                    &self.p.c.f.local_device().authority_key,
                    &self.p.c.next_genesis,
                    &self.p.c.next,
                    self.p.c.f.responder.current_policy().expect("policy"),
                    170
                )
                .expect("old operation permanently barred"),
            WitnessState::Closed
        );
        assert_eq!(
            witness
                .replace_account_root(
                    &self.next,
                    &self.p.c.f.local_device().authority_key,
                    &self.genesis,
                    &self.device,
                    self.p.c.f.responder.current_policy().expect("policy"),
                    170
                )
                .expect("fresh target committed at current time"),
            WitnessState::Committed
        );
        let receipt = witness
            .retired_account_receipt(&self.next)
            .expect("exact new retirement");
        let retired = self
            .p
            .c
            .pin
            .verify_retired_account(&self.next, &receipt)
            .expect("exact independent verification");
        assert_eq!(
            self.owner
                .retain_witness_retirement(&receipt)
                .expect("retain child decision"),
            AccountRootJournalState::WitnessCommitted
        );
        assert_eq!(
            self.p
                .registry
                .commit_replacement(&retired)
                .expect("select approved target"),
            State::Committed
        );
        let signer = crate::DeviceSigningKey::deterministic([232; 32], [233; 32])
            .expect("new target signer");
        let request = crate::AnchorRequest::new(
            &self.p.c.pin,
            self.genesis.subject(),
            crate::AnchorOperation::admit_authority(self.device.authority_binding())
                .expect("authority request"),
            &signer,
        )
        .expect("fresh authenticated request");
        let reply = witness
            .handle(request.as_bytes(), 170)
            .expect("actual current-time authority admission");
        assert_eq!(
            self.p
                .c
                .pin
                .verify_reply(&request, &reply)
                .expect("fresh reply")
                .outcome(),
            crate::AnchorOutcome::AuthorityCurrent
        );
        self.assert_preserved();
    }
}
impl Drop for Transition {
    fn drop(&mut self) {
        self.owner.close();
    }
}
fn retain_unacknowledged_and_pending(p: &mut Prepared) {
    let id =
        p.c.journal
            .next_message_id(&p.c.f.responder, p.session, 150)
            .expect("original operation");
    let wire =
        p.c.journal
            .send_message(
                &p.c.f.responder,
                p.session,
                id,
                b"original unacknowledged message",
                b"expired target",
                150,
            )
            .expect("real committed ciphertext");
    assert!(!wire.is_empty());
    assert_eq!(
        p.c.journal
            .resume_message(&p.c.f.responder, p.session, id, 150)
            .expect("actual retained original ciphertext"),
        wire
    );
    let mut image = p.c.journal.image().expect("actual original image");
    image.revision += 1;
    let active = p.c.journal.active.as_ref().expect("old operating owner");
    let next = seal(&active.key, &image).expect("actual pending ciphertext");
    let pending = PendingWrite::new(active, &image, &next).expect("original pending write");
    reserve(active, &pending).expect("durable pending intent");
}
fn fresh_target(p: &Prepared) -> (VerifiedDevice, crate::AnchorGenesis) {
    let path = p.c.path.parent().expect("owned root").join("successor-b");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("private independent target");
    let root = crate::RootSigningKey::deterministic([230; 32], [231; 32]).expect("fresh root");
    let signer =
        crate::DeviceSigningKey::deterministic([232; 32], [233; 32]).expect("fresh device key");
    let old = p.c.f.local_device();
    let description = crate::DeviceDescription::new(
        old.device_id(),
        old.generation(),
        old.description.family,
        crate::Validity::new(100, 200).expect("current interval"),
    )
    .expect("fresh device");
    let certificate = root
        .issue_device(description, signer.public_key().expect("public key"))
        .expect("fresh certificate");
    let roster = root
        .issue_roster(
            1,
            old.roster_validity,
            &[root.roster_entry(&certificate).expect("member")],
        )
        .expect("fresh roster");
    let device = crate::AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root public"),
        roster.checkpoint(),
        old.description.family,
    )
    .expect("independent approval")
    .verify_device(&certificate, roster.as_bytes(), 170)
    .expect("currently valid target");
    let identity = crate::durable::tests::retain_new_identity(&path.join("store-id"));
    let mut journal = DeviceJournal::provision_anchored(
        &path.join("state.redb"),
        JournalKey::provision(&path.join("key")).expect("separate target key"),
        &device,
        p.c.f.responder.current_policy().expect("policy"),
        identity,
        170,
    )
    .expect("independent target genesis");
    let genesis = journal
        .anchor_genesis(&device, p.c.f.responder.current_policy().expect("policy"))
        .expect("exact target genesis");
    journal.close();
    (device, genesis)
}
