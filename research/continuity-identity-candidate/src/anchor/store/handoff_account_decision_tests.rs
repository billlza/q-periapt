// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real server G/P/R metadata and real target journal; client root composition is separate.
use super::*;
use crate::anchor::store::policy_renewal::tests::Case as PolicyCase;
use crate::{
    AnchorAccountReplacementState as State,
    AnchorTransferredAccountReplacementApproval as Approval,
    AnchorTransferredAccountReplacementMaterials as Materials,
};
#[path = "handoff_account_decision_tests/cleanup.rs"]
mod cleanup;
#[path = "handoff_account_decision_tests/coverage.rs"]
mod coverage;
#[path = "handoff_account_decision_tests/process.rs"]
mod process;
#[path = "handoff_account_decision_tests/recovery.rs"]
mod recovery;
#[path = "handoff_account_decision_tests/validation.rs"]
mod validation;

struct RetirementCase {
    c: PolicyCase,
    root: PublicKey,
    f: TargetFixture,
    active: AnchorStore,
    history: AnchorHandoffHistory,
    retired: Vec<u8>,
    frozen: AnchorFrozenAccount,
}
impl RetirementCase {
    fn new(kind: Option<(&str, bool)>, legacy: bool) -> Self {
        let mut c = PolicyCase::new();
        if let Some((kind, applied)) = kind {
            super::adoption::pending(&mut c, kind, applied);
        }
        Self::from_case(c, legacy)
    }
    fn from_case(mut c: PolicyCase, legacy: bool) -> Self {
        let root = c
            .account
            .public_key()
            .expect("independent old account root");
        let legacy_freeze = if legacy {
            let request = AnchorAccountFreezeRequest::from_trusted_state(
                AnchorAccountFreezeId::from_trusted_state([201; 32]).expect("original operation"),
                root.clone(),
                &c.pin,
            )
            .expect("original independent approval");
            Some(
                c.store
                    .freeze_account(&request)
                    .expect("A freezes before Witness transfer"),
            )
        } else {
            None
        };
        let f = TargetFixture::from_store(&mut c.store, &c.server, &c.pin, 175, false);
        let mut target = f.provision();
        let ack = target.import_receipt().expect("B complete import");
        let retired = c
            .store
            .retire_handoff(&f.approval, ack.as_bytes(), || Ok(175))
            .expect("A retired")
            .as_bytes()
            .to_vec();
        let history = target
            .verify_source_retirement(&retired)
            .expect("verified A-B");
        let (mut active, _) = target.activate(&retired, f.signer()).expect("B active");
        let frozen = if let Some(frozen) = legacy_freeze {
            frozen
        } else {
            let request = AnchorAccountFreezeRequest::from_trusted_state(
                AnchorAccountFreezeId::from_trusted_state([201; 32]).expect("operation"),
                root.clone(),
                &f.pin,
            )
            .expect("B account scope");
            let proposal = active
                .transferred_account_freeze_proposal(&request, &history)
                .expect("complete original account");
            let approval = AnchorTransferredAccountFreezeApproval::from_trusted_state(
                proposal,
                &request,
                &history,
                [202; 32],
                Validity::new(180, 190).expect("freeze window"),
            )
            .expect("independent whole-account approval");
            let wire = active
                .freeze_transferred_account(&approval, || Ok(180))
                .expect("B account freeze");
            approval
                .verify_receipt(&history, &wire)
                .expect("original exact proof")
        };
        Self {
            c,
            root,
            f,
            active,
            history,
            retired,
            frozen,
        }
    }
    fn reopen(&mut self) {
        self.active.close();
        self.active = self
            .f
            .open()
            .activate(&self.retired, self.f.signer())
            .expect("same B owner")
            .0;
    }
    fn old_entry(&mut self) -> Vec<u8> {
        let image = self.active.image().expect("original current image");
        let mut bytes = Vec::new();
        encode_entry(
            image
                .entries
                .get(&self.c.subject.id(&image.namespace))
                .expect("original inherited subject"),
            &self.history,
            EntryFormat::COMPLETE,
            &mut bytes,
        )
        .expect("complete GPR fields");
        bytes
    }
}
struct Next {
    device: VerifiedDevice,
    signer: crate::DeviceSigningKey,
    policy: VerifiedSessionPolicy,
    genesis: AnchorGenesis,
    _journal: DeviceJournal,
    certificate: Vec<u8>,
    policy_wire: Vec<u8>,
}
fn next(c: &RetirementCase, seed: u8) -> Next {
    let (policy, policy_wire) = crate::anchor::store::policy_renewal::tests::policy_with_wire(
        &c.c.issuer,
        &c.c.runtime,
        &c.f.pin,
        2,
        260,
        185,
    );
    let root = crate::RootSigningKey::generate().expect("independent successor root");
    let signer = crate::DeviceSigningKey::generate().expect("independent successor device");
    let cert = root
        .issue_device(
            crate::DeviceDescription::new(
                [seed; 16],
                1,
                policy.family(),
                Validity::new(100, 400).expect("credential window"),
            )
            .expect("description"),
            signer.public_key().expect("public key"),
        )
        .expect("real credential");
    let roster = root
        .issue_roster(
            1,
            Validity::new(100, 400).expect("roster window"),
            &[root.roster_entry(&cert).expect("member")],
        )
        .expect("new complete roster");
    let pin = crate::AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root"),
        roster.checkpoint(),
        policy.family(),
    )
    .expect("independently retained new root");
    let device = pin
        .verify_device(&cert, roster.as_bytes(), 185)
        .expect("verified current device");
    let dir = c.c.server.join(format!("root-target-{seed}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("private target");
    let mut journal = DeviceJournal::provision_anchored(
        &dir.join("journal.redb"),
        JournalKey::provision(&dir.join("key")).expect("new wrapping"),
        &device,
        &policy,
        crate::JournalIdentity::generate().expect("new original journal"),
        185,
    )
    .expect("actual target journal");
    let genesis = journal
        .anchor_genesis(&device, &policy)
        .expect("actual target genesis");
    Next {
        device,
        signer,
        policy,
        genesis,
        _journal: journal,
        certificate: cert,
        policy_wire,
    }
}
fn materials<'a>(
    root: &'a PublicKey,
    next: &'a Next,
    history: &'a AnchorHandoffHistory,
) -> Materials<'a> {
    Materials {
        previous_root: root,
        genesis: &next.genesis,
        device: &next.device,
        policy: &next.policy,
        history,
    }
}
fn approve(c: &mut RetirementCase, n: &Next, seed: u8) -> Approval {
    let m = materials(&c.root, n, &c.history);
    let p = c
        .active
        .transferred_account_replacement_proposal(
            AnchorAccountReplacementId::from_trusted_state([seed; 32]).expect("root operation"),
            &c.frozen,
            &m,
            185,
        )
        .expect("frozen full account plus actual target");
    let a = Approval::from_trusted_state(
        p,
        &m,
        [seed.wrapping_add(1); 32],
        Validity::new(180, 200).expect("root approval window"),
    )
    .expect("independent target approval");
    assert_eq!(
        Approval::restore_trusted_state(&a.to_bytes().expect("retain"), &m)
            .expect("restore exact inputs"),
        a
    );
    a
}

#[test]
fn transferred_account_decision_retires_complete_pending_gpr_and_enrolls_only_exact_target() {
    for kind in ["G", "P", "R"] {
        for applied in [false, true] {
            let mut c = RetirementCase::new(Some((kind, applied)), false);
            let original = c.old_entry();
            let frozen = c.frozen.to_bytes().expect("immutable freeze");
            let n = next(&c, 220);
            let a = approve(&mut c, &n, 223);
            let m = materials(&c.root, &n, &c.history);
            let mut calls = 0;
            let d = c
                .active
                .replace_transferred_account_root(&a, &m, || {
                    calls += 1;
                    Ok(185)
                })
                .expect("atomic retirement and exact enrollment");
            assert_eq!(calls, 2);
            assert_eq!(d.state(), State::Committed);
            assert!(d.retirement().is_ok() && d.closure().is_err());
            assert_eq!(c.old_entry(), original);
            let image = c.active.image().expect("complete decision");
            assert_eq!(image.entries.len(), 2);
            assert_eq!(
                image
                    .account_freezes
                    .get(&a.proposal().previous_account())
                    .expect("original freeze")
                    .to_bytes()
                    .expect("bytes"),
                frozen
            );
            assert!(matches!(
                c.active.retired_account_receipt(a.proposal()),
                Err(DurableError::Suspended)
            ));
            assert!(c
                .f
                .pin
                .verify_retired_account(a.proposal(), d.as_bytes())
                .is_err());
            let q = AnchorRequest::new(
                &c.f.pin,
                n.genesis.subject(),
                AnchorOperation::query(),
                &n.signer,
            )
            .expect("current new-root query");
            let response = c
                .active
                .handle(q.as_bytes(), 185)
                .expect("new exact target can request fresh admission");
            c.f.pin
                .verify_reply(&q, &response)
                .expect("ordinary signed current reply");
            let before = fs::read(c.f.db_path()).expect("committed bytes");
            let mut retried = 0;
            let m = materials(&c.root, &n, &c.history);
            assert_eq!(
                c.active
                    .replace_transferred_account_root(&a, &m, || {
                        retried += 1;
                        Err(DurableError::Conflict)
                    })
                    .expect("historical retry")
                    .as_bytes(),
                d.as_bytes()
            );
            assert_eq!(retried, 0);
            assert_eq!(fs::read(c.f.db_path()).expect("no rewrite"), before);
            assert_eq!(
                c.active
                    .close_transferred_account_replacement(&a)
                    .expect("cannot close committed root")
                    .state(),
                State::Committed
            );
            c.reopen();
            assert_eq!(
                c.active
                    .transferred_account_decision(&a)
                    .expect("cold exact outcome")
                    .as_bytes(),
                d.as_bytes()
            );
            assert_eq!(c.old_entry(), original);
        }
    }
}

#[test]
fn transferred_account_decision_keeps_legacy_freeze_and_permanent_loser_before_winner() {
    for legacy in [false, true] {
        let mut c = RetirementCase::new(Some(("P", false)), legacy);
        let n = next(&c, 230);
        let losing = approve(&mut c, &n, 231);
        let winner = approve(&mut c, &n, 233);
        let before = c.old_entry();
        let closed = c
            .active
            .close_transferred_account_replacement(&losing)
            .expect("permanent independent close");
        assert_eq!(closed.state(), State::Closed);
        assert!(closed.closure().is_ok() && closed.retirement().is_err());
        let m = materials(&c.root, &n, &c.history);
        assert_eq!(
            c.active
                .replace_transferred_account_root(&losing, &m, || Err(DurableError::Conflict))
                .expect("closed stays closed without time")
                .as_bytes(),
            closed.as_bytes()
        );
        let committed = c
            .active
            .replace_transferred_account_root(&winner, &m, || Ok(185))
            .expect("separate exact approved winner");
        assert_eq!(committed.state(), State::Committed);
        assert_eq!(c.old_entry(), before);
        c.active.close();
        let mut observer = c.f.open();
        assert_eq!(
            observer
                .transferred_account_decision(&losing)
                .expect("key-free loser")
                .as_bytes(),
            closed.as_bytes()
        );
        assert_eq!(
            observer
                .transferred_account_decision(&winner)
                .expect("key-free winner")
                .as_bytes(),
            committed.as_bytes()
        );
    }
}
