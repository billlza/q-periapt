// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use device_replacement::{exchange, journal};
#[path = "account_root_tests/process.rs"]
mod process;

struct Fixture {
    path: PathBuf,
    old: Device,
    next: Device,
    trust: AccountRootTrust,
    now: u64,
}
impl Fixture {
    fn new() -> Result<(Self, Witness)> {
        let path = directory()?;
        let mut owner = provision(&path)?;
        let pin = owner.prepare()?;
        let old = device(&path, pin.clone())?;
        let next_path = path.join("successor");
        fs::create_dir(&next_path)?;
        fs::set_permissions(&next_path, fs::Permissions::from_mode(0o700))?;
        let next = device(&next_path, pin)?;
        let now = crate::native_device::clock()?;
        owner.enroll(&old.trust, &old.request, now)?;
        let trust = AccountRootTrust {
            schema: "qperiapt-witness-account-root-trust/1".into(),
            operation: [101; 32],
            freeze_operation: [102; 32],
            previous_root: old.root.public_key()?.encode(),
            successor: next.trust.clone(),
        };
        Ok((
            Self {
                path,
                old,
                next,
                trust,
                now,
            },
            owner,
        ))
    }
    fn plan(&self, owner: &mut Witness) -> Result<AccountRootPlan> {
        owner.plan_account_root_replacement(&self.trust, &self.next.request, self.now)
    }
    fn unseen(&self) -> Result<(EnrollmentTrust, EnrollmentRequest)> {
        let validity = sdk::Validity::new(self.now, self.now + 600)?;
        let signer = sdk::DeviceSigningKey::generate()?;
        let certificate = self.old.root.issue_device(
            sdk::DeviceDescription::new([103; 16], 1, self.old.trust.account.family, validity)?,
            signer.public_key()?,
        )?;
        let roster = self.old.root.issue_roster(
            2,
            validity,
            &[self.old.root.roster_entry(&certificate)?],
        )?;
        let mut trust = self.old.trust.clone();
        trust.device = [103; 16];
        trust.certificate = certificate;
        trust.account.roster = Some(RosterSnapshot {
            checkpoint: roster.checkpoint().into(),
            bytes: roster.as_bytes().to_vec(),
        });
        journal(&self.path, "unseen", trust, self.now)
    }
    fn query_old(&self, owner: &mut Witness) -> Result<(sdk::AnchorOutcome, sdk::AnchorHead)> {
        exchange(
            owner,
            &self.old.pin,
            &self.old.request,
            &self.old.signer,
            sdk::AnchorOperation::query(),
            self.now,
        )
    }
}

fn decision(plan: &AccountRootDecision) -> Result<sdk::AnchorAccountReplacementProposal> {
    Ok(sdk::AnchorAccountReplacementProposal::from_trusted_state(
        &plan.proposal,
    )?)
}
fn committed(
    f: &Fixture,
    expected: &AccountRootDecision,
    outcome: AccountRootOutcome,
) -> Result<()> {
    let AccountRootOutcome::Committed { binding, receipt } = outcome else {
        return Err("expected committed root".into());
    };
    assert_eq!(binding, expected.binding);
    assert_eq!(
        f.old
            .pin
            .verify_retired_account(&decision(expected)?, &receipt)?
            .proposal(),
        &decision(expected)?
    );
    Ok(())
}

#[test]
fn original_plan_freeze_and_retirement_fence_unseen_old_devices() -> Result<()> {
    let (f, mut owner) = Fixture::new()?;
    let (unseen, unseen_request) = f.unseen()?;
    let plan = f.plan(&mut owner)?;
    assert_eq!(f.plan(&mut owner)?.plan, plan.plan);
    f.query_old(&mut owner)?;
    let frozen = owner.freeze_account_root(&plan)?;
    let selected = sdk::AnchorAccountReplacementPlan::from_trusted_state(&plan.plan)?;
    let snapshot = f
        .old
        .pin
        .verify_account_freeze(selected.request(), &frozen.receipt)?;
    assert_eq!(snapshot.subjects().count(), 1);
    assert!(f.query_old(&mut owner).is_err());
    assert!(owner.enroll(&unseen, &unseen_request, f.now).is_err());
    let retry = owner.freeze_account_root(&plan)?;
    assert_eq!(retry.freeze_binding, frozen.freeze_binding);
    let bound =
        owner.bind_account_root_replacement(&f.trust, &f.next.request, &plan, &frozen, f.now)?;
    assert!(matches!(
        owner.account_root_replacement_status(&bound)?,
        AccountRootOutcome::Unavailable { .. }
    ));
    committed(
        &f,
        &bound,
        owner.commit_account_root_replacement(
            &f.trust,
            &f.next.request,
            &plan,
            &frozen,
            &bound,
            f.now,
        )?,
    )?;
    drop(owner);
    let mut owner = open(&f.path)?;
    committed(&f, &bound, owner.account_root_replacement_status(&bound)?)?;
    committed(&f, &bound, owner.close_account_root_replacement(&bound)?)?;
    assert!(f.query_old(&mut owner).is_err());
    assert!(owner.enroll(&unseen, &unseen_request, f.now).is_err());
    exchange(
        &mut owner,
        &f.next.pin,
        &f.next.request,
        &f.next.signer,
        sdk::AnchorOperation::query(),
        f.now,
    )?;
    assert!(owner
        .commit_account_root_replacement(
            &f.trust,
            &f.next.request,
            &plan,
            &frozen,
            &bound,
            f.now + 601
        )
        .is_err());
    committed(&f, &bound, owner.account_root_replacement_status(&bound)?)?;
    Ok(())
}

#[test]
fn changed_scope_or_snapshot_cannot_redirect_the_approved_plan() -> Result<()> {
    let (f, mut owner) = Fixture::new()?;
    let plan = f.plan(&mut owner)?;
    let frozen = owner.freeze_account_root(&plan)?;
    for field in ["root", "operation", "freeze", "journal", "head", "policy"] {
        let mut trust = f.trust.clone();
        match field {
            "root" => trust.previous_root = f.next.root.public_key()?.encode(),
            "operation" => trust.operation = [111; 32],
            "freeze" => trust.freeze_operation = [112; 32],
            "journal" => trust.successor.journal = [113; 32],
            "head" => trust.successor.genesis_head = [114; 32],
            "policy" => trust.successor.account.family = [115; 32],
            _ => return Err("case".into()),
        }
        assert!(
            owner
                .bind_account_root_replacement(&trust, &f.next.request, &plan, &frozen, f.now)
                .is_err(),
            "{field}"
        );
    }
    let mut wrong: AccountRootFreeze = serde_json::from_slice(&serde_json::to_vec(&frozen)?)?;
    *wrong.receipt.last_mut().ok_or("receipt")? ^= 1;
    assert!(owner
        .bind_account_root_replacement(&f.trust, &f.next.request, &plan, &wrong, f.now)
        .is_err());
    let bound =
        owner.bind_account_root_replacement(&f.trust, &f.next.request, &plan, &frozen, f.now)?;
    let mut altered = bound.clone();
    altered.plan_binding = [116; 32];
    assert!(owner
        .commit_account_root_replacement(&f.trust, &f.next.request, &plan, &frozen, &altered, f.now)
        .is_err());
    committed(
        &f,
        &bound,
        owner.commit_account_root_replacement(
            &f.trust,
            &f.next.request,
            &plan,
            &frozen,
            &bound,
            f.now,
        )?,
    )?;
    Ok(())
}

#[test]
fn closing_plan_or_decision_is_permanent_and_never_unfreezes() -> Result<()> {
    for before_freeze in [true, false] {
        let (f, mut owner) = Fixture::new()?;
        let plan = f.plan(&mut owner)?;
        if before_freeze {
            let AccountRootOutcome::Closed { binding, receipt } =
                owner.close_account_root_plan(&plan)?
            else {
                return Err("closed plan".into());
            };
            assert_eq!(binding, plan.binding);
            f.old.pin.verify_closed_account_preparation(
                &sdk::AnchorAccountReplacementPlan::from_trusted_state(&plan.plan)?,
                &receipt,
            )?;
            assert!(owner.freeze_account_root(&plan).is_err());
            f.query_old(&mut owner)?;
        } else {
            let frozen = owner.freeze_account_root(&plan)?;
            let bound = owner.bind_account_root_replacement(
                &f.trust,
                &f.next.request,
                &plan,
                &frozen,
                f.now,
            )?;
            let AccountRootOutcome::Closed { binding, receipt } =
                owner.close_account_root_replacement(&bound)?
            else {
                return Err("closed decision".into());
            };
            assert_eq!(binding, bound.binding);
            f.old
                .pin
                .verify_closed_account_replacement(&decision(&bound)?, &receipt)?;
            assert!(f.query_old(&mut owner).is_err());
            assert!(owner
                .commit_account_root_replacement(
                    &f.trust,
                    &f.next.request,
                    &plan,
                    &frozen,
                    &bound,
                    f.now
                )
                .is_err());
            drop(owner);
            let mut owner = open(&f.path)?;
            assert!(matches!(
                owner.account_root_replacement_status(&bound)?,
                AccountRootOutcome::Closed { .. }
            ));
            assert!(f.query_old(&mut owner).is_err());
        }
    }
    Ok(())
}

#[test]
fn new_target_requires_permanent_original_closure_and_authenticated_same_freeze() -> Result<()> {
    let (f, mut owner) = Fixture::new()?;
    let plan = f.plan(&mut owner)?;
    let frozen = owner.freeze_account_root(&plan)?;
    let path = f.path.join("second-target");
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let next = device(&path, owner.prepare()?)?;
    let mut trust = f.trust.clone();
    trust.operation = [121; 32];
    trust.successor = next.trust.clone();
    let at = crate::native_device::clock()?;
    trust.successor.inputs(&f.old.pin, &next.request, at)?;
    assert!(owner
        .replan_frozen_account_root(&trust, &next.request, &plan, &frozen, at)
        .is_err());
    owner.close_account_root_plan(&plan)?;
    let mut changed = trust.clone();
    changed.operation = f.trust.operation;
    assert!(owner
        .replan_frozen_account_root(&changed, &next.request, &plan, &frozen, at)
        .is_err());
    changed = trust.clone();
    changed.freeze_operation = [122; 32];
    assert!(owner
        .replan_frozen_account_root(&changed, &next.request, &plan, &frozen, at)
        .is_err());
    let mut bad: AccountRootFreeze = serde_json::from_slice(&serde_json::to_vec(&frozen)?)?;
    *bad.receipt.last_mut().ok_or("original freeze proof")? ^= 1;
    assert!(owner
        .replan_frozen_account_root(&trust, &next.request, &plan, &bad, at)
        .is_err());
    let selected = owner.replan_frozen_account_root(&trust, &next.request, &plan, &frozen, at)?;
    assert!(
        selected == owner.replan_frozen_account_root(&trust, &next.request, &plan, &frozen, at)?
    );
    let observed = owner.freeze_account_root(&selected)?;
    assert_eq!(observed.freeze_binding, frozen.freeze_binding);
    let decision =
        owner.bind_account_root_replacement(&trust, &next.request, &selected, &observed, at)?;
    let AccountRootOutcome::Committed { receipt, .. } = owner.commit_account_root_replacement(
        &trust,
        &next.request,
        &selected,
        &observed,
        &decision,
        at,
    )?
    else {
        return Err("new selected root committed".into());
    };
    f.old
        .pin
        .verify_retired_account(&decision.as_sdk()?, &receipt)?;
    assert!(f.query_old(&mut owner).is_err());
    assert!(owner.freeze_account_root(&plan).is_err());
    Ok(())
}
