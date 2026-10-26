// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original sealed prekeys and real P targets survive account retirement under B.
use super::*;
use crate::durable::write_intent::witness_handoff::tests::support::Case as WitnessCase;
use crate::{
    AnchorTransferredAccountReplacementApproval as Approval,
    AnchorTransferredAccountReplacementMaterials as Materials,
};
use std::os::unix::fs::DirBuilderExt;
#[path = "witness/process.rs"]
mod process;
#[path = "witness/recovery.rs"]
mod recovery;
#[path = "witness/validation.rs"]
mod validation;

struct Ready {
    c: WitnessCase,
    next: Successor,
    approval: Approval,
    plan: TransferredAccountRootJournalPlan,
}
impl Ready {
    fn new() -> Self {
        let mut c = WitnessCase::new(Some(2));
        c.journal.close();
        let mut selected = crate::WitnessJournalAdoption::prepare_original(
            &c.path(),
            c.key(),
            c.plan.clone(),
            || Ok(180),
        )
        .expect("actual selection");
        selected
            .adopt_authorization(&c.receipt)
            .expect("actual adopted B");
        selected.close();
        let next = successor(&c);
        let approval = approve(&mut c, &next);
        let plan = plan(&c, &approval, true);
        Self {
            c,
            next,
            approval,
            plan,
        }
    }
    fn open(&self) -> Result<AccountRootJournalRecovery, DurableError> {
        AccountRootJournalRecovery::resume_transferred_original(
            &self.c.path(),
            self.c.key(),
            &self.c.device,
            self.c.identity,
            self.plan.clone(),
        )
    }
    fn decide(&mut self, closed: bool) -> crate::AnchorTransferredAccountDecision {
        let history = self.c.history();
        let m = Materials {
            previous_root: &self.c.device.authority_key,
            genesis: &self.next.genesis,
            device: &self.next.device,
            policy: &self.next.policy,
            history: &history,
        };
        let target = self.c.target.as_mut().expect("current target");
        if closed {
            target.close_transferred_account_replacement(&self.approval)
        } else {
            target.replace_transferred_account_root(&self.approval, &m, || Ok(185))
        }
        .expect("actual permanent target outcome")
    }
}

struct Successor {
    device: crate::VerifiedDevice,
    policy: crate::VerifiedSessionPolicy,
    genesis: crate::AnchorGenesis,
    _journal: DeviceJournal,
    certificate: Vec<u8>,
    policy_wire: Vec<u8>,
    policy_root: crate::PublicKey,
}
fn successor(c: &WitnessCase) -> Successor {
    let pin = c.target.as_ref().expect("active B").pin().expect("B pin");
    let (issuer, wire, trust, runtime) = crate::tests::session_policy_fixture_with_anchor(
        &[crate::PrekeyQuality::OneTimeBoth],
        crate::AnchorRequirement::required(&pin),
    );
    let policy = trust
        .verify(wire.as_bytes(), runtime, 185)
        .expect("independent current target policy");
    let root = crate::RootSigningKey::generate().expect("independent new account root");
    let signer = crate::DeviceSigningKey::generate().expect("new device signer");
    let cert = root
        .issue_device(
            crate::DeviceDescription::new(
                [220; 16],
                1,
                policy.family(),
                crate::Validity::new(100, 400).expect("validity"),
            )
            .expect("device"),
            signer.public_key().expect("device key"),
        )
        .expect("certificate");
    let roster = root
        .issue_roster(
            1,
            crate::Validity::new(100, 400).expect("validity"),
            &[root.roster_entry(&cert).expect("member")],
        )
        .expect("roster");
    let device = crate::AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root"),
        roster.checkpoint(),
        policy.family(),
    )
    .expect("independent target pin")
    .verify_device(&cert, roster.as_bytes(), 185)
    .expect("target device");
    let dir = c.root.join("successor");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("private target directory");
    let mut journal = DeviceJournal::provision_anchored(
        &dir.join("journal.redb"),
        JournalKey::provision(&dir.join("key")).expect("separate target wrapping key"),
        &device,
        &policy,
        JournalIdentity::generate().expect("target journal identity"),
        185,
    )
    .expect("actual target journal");
    let genesis = journal
        .anchor_genesis(&device, &policy)
        .expect("actual target genesis");
    Successor {
        device,
        policy,
        genesis,
        _journal: journal,
        certificate: cert,
        policy_wire: wire.as_bytes().to_vec(),
        policy_root: issuer.public_key().expect("independent policy signer"),
    }
}
fn approve(c: &mut WitnessCase, next: &Successor) -> Approval {
    let history = c.history();
    let target = c.target.as_mut().expect("active B");
    let pin = target.pin().expect("B");
    let request = crate::AnchorAccountFreezeRequest::from_trusted_state(
        crate::AnchorAccountFreezeId::from_trusted_state([221; 32]).expect("freeze operation"),
        c.device.authority_key.clone(),
        &pin,
    )
    .expect("whole-account operator request");
    let snapshot = target
        .transferred_account_freeze_proposal(&request, &history)
        .expect("complete actual P state");
    let approval = crate::AnchorTransferredAccountFreezeApproval::from_trusted_state(
        snapshot,
        &request,
        &history,
        [222; 32],
        crate::Validity::new(181, 210).expect("operator interval"),
    )
    .expect("independent freeze authority");
    let wire = target
        .freeze_transferred_account(&approval, || Ok(185))
        .expect("whole-account fence");
    let frozen = approval
        .verify_receipt(&history, &wire)
        .expect("actual signed complete freeze");
    let m = Materials {
        previous_root: &c.device.authority_key,
        genesis: &next.genesis,
        device: &next.device,
        policy: &next.policy,
        history: &history,
    };
    let proposal = target
        .transferred_account_replacement_proposal(
            crate::AnchorAccountReplacementId::from_trusted_state([223; 32])
                .expect("root operation"),
            &frozen,
            &m,
            185,
        )
        .expect("exact successor proposal");
    Approval::from_trusted_state(
        proposal,
        &m,
        [224; 32],
        crate::Validity::new(181, 210).expect("operator interval"),
    )
    .expect("independent root recovery authority")
}
fn plan(c: &WitnessCase, approval: &Approval, selected: bool) -> TransferredAccountRootJournalPlan {
    let history = c.history();
    let logical = history
        .historical_pin(c.plan.scope().logical)
        .expect("independently retained original pin")
        .clone();
    TransferredAccountRootJournalPlan::new(
        logical,
        approval.clone(),
        history,
        selected.then(|| c.plan.clone()),
    )
    .expect("exact independently retained recovery plan")
}
fn control(c: &WitnessCase) -> Option<Vec<u8>> {
    let db = open_private_database(&c.path()).expect("same original journal");
    let tx = db.begin_read().expect("read");
    let table = image_table(&tx).expect("table");
    table
        .get(witness_handoff::ROW)
        .expect("selection")
        .map(|v| v.value().to_vec())
}

#[test]
fn transferred_root_journal_keeps_real_p_states_and_selected_witness_for_both_decisions() {
    for stage in [None, Some(0), Some(1), Some(2)] {
        for selection in 0..=2 {
            for closed in [false, true] {
                eprintln!(
                    "TRANSFERRED_ROOT_CASE stage={stage:?} selection={selection} closed={closed}"
                );
                let mut c = WitnessCase::new(stage);
                c.journal.close();
                let original = c.original_rows();
                let mut adopted = if selection == 0 {
                    None
                } else {
                    Some(
                        crate::WitnessJournalAdoption::prepare_original(
                            &c.path(),
                            c.key(),
                            c.plan.clone(),
                            || Ok(180),
                        )
                        .expect("actual original Witness selection"),
                    )
                };
                if selection == 2 {
                    adopted
                        .as_mut()
                        .expect("selected")
                        .adopt_authorization(&c.receipt)
                        .expect("original B authorization");
                }
                if let Some(owner) = &mut adopted {
                    owner.close();
                }
                let selected = control(&c);
                let next = successor(&c);
                let approval = approve(&mut c, &next);
                let plan = plan(&c, &approval, selection != 0);
                let mut owner = if selection == 0 {
                    AccountRootJournalRecovery::resume_transferred_original(
                        &c.path(),
                        c.key(),
                        &c.device,
                        c.identity,
                        plan.clone(),
                    )
                } else {
                    c.resume().begin_account_root_replacement(plan.clone())
                }
                .expect("same restricted root owner");
                assert_eq!(
                    owner.status().expect("fenced"),
                    AccountRootJournalState::LocalFenced
                );
                let history = c.history();
                let m = Materials {
                    previous_root: &c.device.authority_key,
                    genesis: &next.genesis,
                    device: &next.device,
                    policy: &next.policy,
                    history: &history,
                };
                let target = c.target.as_mut().expect("B");
                let result = if closed {
                    target.close_transferred_account_replacement(&approval)
                } else {
                    target.replace_transferred_account_root(&approval, &m, || Ok(185))
                }
                .expect("actual permanent server outcome");
                let expected = if closed {
                    AccountRootJournalState::WitnessClosed
                } else {
                    AccountRootJournalState::WitnessCommitted
                };
                assert_eq!(
                    owner
                        .retain_account_decision(result.as_bytes())
                        .expect("retain exact current-authority proof"),
                    expected
                );
                assert_eq!(
                    owner.account_decision().expect("original proof").as_bytes(),
                    result.as_bytes()
                );
                owner.close();
                assert_eq!(c.original_rows(), original);
                assert_eq!(control(&c), selected);
                let rejected = DeviceJournal::recover_anchor_genesis(
                    &c.path(),
                    c.key(),
                    &c.device,
                    &c.policy,
                    c.identity,
                );
                // An already installed P target first fails the ordinary pending-image
                // check, before it reaches either control fence. Both errors are exact
                // existing contracts; the restricted recovery above accepts that target.
                if stage == Some(2) {
                    assert!(
                        matches!(rejected, Err(DurableError::Conflict)),
                        "installed P ordinary reopen returned {:?}",
                        rejected.err()
                    );
                } else {
                    assert!(
                        matches!(rejected, Err(DurableError::Suspended)),
                        "fenced ordinary reopen returned {:?}",
                        rejected.err()
                    );
                }
                assert!(crate::WitnessJournalAdoption::resume_original(
                    &c.path(),
                    c.key(),
                    c.plan.clone()
                )
                .is_err());
                assert!(AccountRootJournalRecovery::resume_original(
                    &c.path(),
                    c.key(),
                    &c.device,
                    c.identity,
                    history.current_pin().clone(),
                    approval.proposal().clone()
                )
                .is_err());
                let mut recovered = AccountRootJournalRecovery::resume_transferred_original(
                    &c.path(),
                    c.key(),
                    &c.device,
                    c.identity,
                    plan,
                )
                .expect("cold same approved context");
                assert_eq!(recovered.status().expect("historical state"), expected);
                assert_eq!(
                    recovered
                        .retain_account_decision(result.as_bytes())
                        .expect("exact retry"),
                    expected
                );
                if closed {
                    assert!(recovered.retirement().is_err());
                } else {
                    assert_eq!(
                        recovered
                            .retirement()
                            .expect("historical retirement")
                            .proposal(),
                        approval.proposal()
                    );
                }
                recovered.close();
                assert_eq!(c.original_rows(), original);
                assert_eq!(control(&c), selected);
            }
        }
    }
}
