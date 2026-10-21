// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted local account-wide fence; data-plane requests cannot select a root.
use super::*;
mod types;
pub use types::{
    AccountRootDecision, AccountRootFreeze, AccountRootOutcome, AccountRootPlan, AccountRootTrust,
};

pub(super) fn plan(
    store: &mut sdk::AnchorStore,
    trust: &AccountRootTrust,
    request: &EnrollmentRequest,
    now: u64,
) -> Result<AccountRootPlan> {
    let pin = store.pin()?;
    let (operation, _, freeze) = trust.selected(&pin)?;
    let (genesis, next, policy) = trust.successor.inputs(&pin, request, now)?;
    AccountRootPlan::from_sdk(
        store.account_replacement_plan(operation, freeze, &genesis, &next, &policy, now)?,
    )
}

pub(super) fn freeze(
    store: &mut sdk::AnchorStore,
    plan: &AccountRootPlan,
) -> Result<AccountRootFreeze> {
    let selected = plan.as_sdk()?;
    // Explicitly closed plans cannot start a new freeze. Closure still cannot
    // cancel a freeze which was already in flight at another invocation.
    match store.closed_account_preparation(&selected) {
        Ok(_) => return Err("Original account root plan is permanently closed".into()),
        Err(sdk::DurableError::Absent) => {}
        Err(error) => return Err(error.into()),
    }
    let frozen = store.freeze_account(selected.request())?;
    #[cfg(test)]
    boundary("witness-account-root-frozen")?;
    Ok(AccountRootFreeze {
        plan_binding: plan.binding,
        freeze_binding: frozen.binding()?,
        receipt: store.account_freeze_receipt(selected.request())?,
    })
}

struct SelectedTarget {
    previous: sdk::PublicKey,
    genesis: sdk::AnchorGenesis,
    next: sdk::VerifiedDevice,
    policy: sdk::VerifiedSessionPolicy,
    proposal: sdk::AnchorAccountReplacementProposal,
}

fn selected_target(
    store: &mut sdk::AnchorStore,
    trust: &AccountRootTrust,
    request: &EnrollmentRequest,
    plan: &AccountRootPlan,
    frozen: &AccountRootFreeze,
    now: u64,
) -> Result<SelectedTarget> {
    let pin = store.pin()?;
    let original = plan.as_sdk()?;
    let (operation, previous, freeze) = trust.selected(&pin)?;
    if freeze != *original.request()
        || operation != original.operation()
        || frozen.plan_binding != plan.binding
    {
        return Err("Account root original plan selection differs".into());
    }
    let observed = pin.verify_account_freeze(original.request(), &frozen.receipt)?;
    if observed.binding()? != frozen.freeze_binding {
        return Err("Account root freeze binding differs".into());
    }
    let (genesis, next, policy) = trust.successor.inputs(&pin, request, now)?;
    let expected = store
        .frozen_account_replacement_plan(operation, &observed, &genesis, &next, &policy, now)?;
    if expected != original {
        return Err("Account root approved target differs".into());
    }
    let proposal = store
        .frozen_account_replacement_proposal(operation, &observed, &genesis, &next, &policy, now)?;
    Ok(SelectedTarget {
        previous,
        genesis,
        next,
        policy,
        proposal,
    })
}

pub(super) fn bind(
    store: &mut sdk::AnchorStore,
    trust: &AccountRootTrust,
    request: &EnrollmentRequest,
    plan: &AccountRootPlan,
    frozen: &AccountRootFreeze,
    now: u64,
) -> Result<AccountRootDecision> {
    AccountRootDecision::from_sdk(
        plan.binding,
        selected_target(store, trust, request, plan, frozen, now)?.proposal,
    )
}

pub(super) fn commit(
    store: &mut sdk::AnchorStore,
    trust: &AccountRootTrust,
    request: &EnrollmentRequest,
    plan: &AccountRootPlan,
    frozen: &AccountRootFreeze,
    decision: &AccountRootDecision,
    now: u64,
) -> Result<AccountRootOutcome> {
    let proposal = decision.as_sdk()?;
    if decision.plan_binding != plan.binding {
        return Err("Account root commit differs from original frozen decision".into());
    }
    let selected = selected_target(store, trust, request, plan, frozen, now)?;
    if proposal != selected.proposal {
        return Err("Account root commit differs from original frozen decision".into());
    }
    // Reuse verified inputs only inside this invocation. The store still checks
    // live admission and the original durable account scope before committing.
    store.replace_account_root(
        &proposal,
        &selected.previous,
        &selected.genesis,
        &selected.next,
        &selected.policy,
        now,
    )?;
    #[cfg(test)]
    boundary("witness-account-root-committed")?;
    status(store, decision)
}

pub(super) fn status(
    store: &mut sdk::AnchorStore,
    decision: &AccountRootDecision,
) -> Result<AccountRootOutcome> {
    let proposal = decision.as_sdk()?;
    Ok(match store.account_root_replacement_status(&proposal)? {
        sdk::AnchorAccountReplacementState::Unavailable => AccountRootOutcome::Unavailable {
            binding: decision.binding,
        },
        sdk::AnchorAccountReplacementState::Committed => AccountRootOutcome::Committed {
            binding: decision.binding,
            receipt: store.retired_account_receipt(&proposal)?,
        },
        sdk::AnchorAccountReplacementState::Closed => AccountRootOutcome::Closed {
            binding: decision.binding,
            receipt: store.closed_account_replacement_receipt(&proposal)?,
        },
    })
}

pub(super) fn close(
    store: &mut sdk::AnchorStore,
    decision: &AccountRootDecision,
) -> Result<AccountRootOutcome> {
    store.close_account_replacement(&decision.as_sdk()?)?;
    #[cfg(test)]
    boundary("witness-account-root-closed")?;
    status(store, decision)
}

pub(super) fn close_plan(
    store: &mut sdk::AnchorStore,
    plan: &AccountRootPlan,
) -> Result<AccountRootOutcome> {
    let selected = plan.as_sdk()?;
    Ok(match store.close_account_preparation(&selected)? {
        sdk::AnchorAccountReplacementState::Closed => {
            #[cfg(test)]
            boundary("witness-account-root-plan-closed")?;
            AccountRootOutcome::Closed {
                binding: plan.binding,
                receipt: store.closed_account_preparation_receipt(&selected)?,
            }
        }
        sdk::AnchorAccountReplacementState::Committed => {
            return Err(
                "Account root already committed; recover its original decision status".into(),
            )
        }
        sdk::AnchorAccountReplacementState::Unavailable => {
            return Err("Account root closure returned no terminal decision".into())
        }
    })
}
