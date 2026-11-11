// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent approval inputs; all mutations under test run in the compiled C child.
use super::*;
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Variant {
    Original,
    Transition,
    BoundTransition,
    Adoption,
}
impl Variant {
    pub(super) fn selected() -> Result<Self> {
        match std::env::var("QPC_ROOT_VARIANT").as_deref() {
            Ok("original") | Err(std::env::VarError::NotPresent) => Ok(Self::Original),
            Ok("transition") => Ok(Self::Transition),
            Ok("bound-transition") => Ok(Self::BoundTransition),
            Ok("adoption") => Ok(Self::Adoption),
            _ => Err("unknown root qualification variant".into()),
        }
    }
    pub(super) fn is_transition(self) -> bool {
        matches!(self, Self::Transition | Self::BoundTransition)
    }
    pub(super) fn processes(self) -> usize {
        match self {
            Self::Original | Self::Transition => 31,
            Self::BoundTransition => 32,
            Self::Adoption => 29,
        }
    }
    pub(super) fn marker(self) -> String {
        let (count, cuts) = match self {
            Self::Original | Self::Transition => (14, 8),
            Self::BoundTransition => (15, 9),
            Self::Adoption => (12, 7),
        };
        let route = match self {
            Self::Original => "",
            Self::Transition => " route=transition",
            Self::BoundTransition => " route=bound-transition",
            Self::Adoption => " route=adoption",
        };
        cut_marker(&format!("ROOT_C_LIFECYCLE processes={count} sigkill={cuts} witness_unknown=218 native_readbacks=3 original_revision=2 report_preserved=true cleanup_keeps_successor=true close_revokes_successor=true application_traffic=true{route}\n"))
    }
}
fn freeze(case: &setup::Case) -> Result<Vec<u8>> {
    let mut witness = case
        .witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness")?;
    witness.freeze_account(case.plan.request())?;
    Ok(witness.account_freeze_receipt(case.plan.request())?)
}
fn proposal(case: &setup::Case) -> Result<p::AnchorAccountReplacementProposal> {
    Ok(p::AnchorAccountReplacementProposal::from_trusted_state(
        &fixture::read(&case.public, "bound-proposal", 65536)?,
    )?)
}
fn commit(case: &setup::Case, proposal: &p::AnchorAccountReplacementProposal) -> Result<Vec<u8>> {
    let mut witness = case
        .witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness")?;
    witness.replace_account_root(
        proposal,
        &case.old.root.public_key()?,
        &case.target.genesis,
        &case.target.credential,
        &case.policy,
        fixture::now()?,
    )?;
    Ok(witness.retired_account_receipt(proposal)?)
}
pub(super) fn prepare(
    client: &Path,
    case: &mut setup::Case,
    variant: Variant,
    processes: &mut Vec<u32>,
) -> Result<()> {
    if variant == Variant::Adoption {
        return adopt(client, case, processes);
    }
    let freeze = freeze(case)?;
    fixture::store(&case.public, "freeze-receipt", &freeze)?;
    let plan = if variant.is_transition() {
        transition(client, case, variant, &freeze, processes)?
    } else {
        processes.push(stage(client, case, "freeze", true)?);
        processes.push(stage(client, case, "freeze-retry", false)?);
        case.plan.clone()
    };
    let proposal = proposal(case)?;
    case.pin.verify_account_freeze(plan.request(), &freeze)?;
    let mut registry = case.registry()?;
    let (application, state, retained) = registry.replacement(plan.operation())?;
    assert_eq!(application, case.checkpoint.application());
    assert_eq!(state, p::AccountAuthorityReplacementState::Pending);
    assert_eq!(retained, &proposal);
    assert_eq!(registry.preparation(plan.operation())?.2, &plan);
    if variant.is_transition() {
        assert_eq!(
            registry.preparation(case.plan.operation())?.1,
            p::AccountAuthorityReplacementState::Closed
        );
        assert_ne!(proposal.successor_account(), case.original_target);
        assert_eq!(
            proposal.successor_account(),
            case.target.credential.account_id()
        );
    }
    registry.close();
    fixture::store(
        &case.public,
        "retirement-receipt",
        &commit(case, &proposal)?,
    )?;
    processes.push(stage(client, case, "retain", true)?);
    processes.push(stage(client, case, "retain-retry", false)?);
    Ok(())
}
fn transition(
    client: &Path,
    case: &mut setup::Case,
    variant: Variant,
    freeze: &[u8],
    processes: &mut Vec<u32>,
) -> Result<p::AnchorAccountReplacementPlan> {
    if variant == Variant::BoundTransition {
        processes.push(stage(client, case, "freeze-original", true)?);
    }
    let (next, noncommit) = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.close_account_preparation(&case.plan)?;
        let frozen = witness.freeze_account(case.plan.request())?;
        (
            witness.frozen_account_replacement_plan(
                p::AnchorAccountReplacementId::from_trusted_state([157; 32])?,
                &frozen,
                &case.target.genesis,
                &case.target.credential,
                &case.policy,
                fixture::now()?,
            )?,
            witness.closed_account_preparation_receipt(&case.plan)?,
        )
    };
    let approved = p::ManagedAccountRootTransition::verify(
        &case.pin,
        &case.plan,
        next.clone(),
        &noncommit,
        freeze,
    )?;
    fixture::store(&case.public, "alternative-approved", &next.to_bytes()?)?;
    fixture::store(&case.public, "original-noncommit", &noncommit)?;
    fixture::store(&case.public, "alternative-receipt", freeze)?;
    processes.push(stage(client, case, "transition", true)?);
    case.recovery = setup::Recovery::Transition(Box::new(approved));
    processes.push(stage(client, case, "transition-retry", false)?);
    Ok(next)
}
fn adopt(client: &Path, case: &mut setup::Case, processes: &mut Vec<u32>) -> Result<()> {
    let (proposal, noncommit, retirement) = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        let competing = p::AnchorAccountFreezeRequest::from_trusted_state(
            p::AnchorAccountFreezeId::from_trusted_state([158; 32])?,
            case.old.root.public_key()?,
            &case.pin,
        )?;
        let frozen = witness.freeze_account(&competing)?;
        let proposal = witness.frozen_account_replacement_proposal(
            p::AnchorAccountReplacementId::from_trusted_state([159; 32])?,
            &frozen,
            &case.target.genesis,
            &case.target.credential,
            &case.policy,
            fixture::now()?,
        )?;
        witness.replace_account_root(
            &proposal,
            &case.old.root.public_key()?,
            &case.target.genesis,
            &case.target.credential,
            &case.policy,
            fixture::now()?,
        )?;
        witness.close_account_preparation(&case.plan)?;
        let noncommit = witness.closed_account_preparation_receipt(&case.plan)?;
        let retirement = witness.retired_account_receipt(&proposal)?;
        (proposal, noncommit, retirement)
    };
    let approved = p::ManagedAccountRootAdoption::verify(
        &case.pin,
        &case.plan,
        proposal.clone(),
        &noncommit,
        &retirement,
    )?;
    fixture::store(&case.public, "alternative-approved", &proposal.to_bytes()?)?;
    fixture::store(&case.public, "original-noncommit", &noncommit)?;
    fixture::store(&case.public, "alternative-receipt", &retirement)?;
    fixture::store(&case.public, "bound-proposal", &proposal.to_bytes()?)?;
    fixture::store(&case.public, "retirement-receipt", &retirement)?;
    processes.push(stage(client, case, "adopt", true)?);
    case.recovery = setup::Recovery::Adoption(Box::new(approved));
    processes.push(stage(client, case, "adopt-retry", false)?);
    let mut registry = case.registry()?;
    assert_eq!(
        registry.preparation(case.plan.operation())?.1,
        p::AccountAuthorityReplacementState::Closed
    );
    assert!(matches!(
        registry.preparation(proposal.operation()),
        Err(p::DurableError::Conflict)
    ));
    let (application, state, retained) = registry.replacement(proposal.operation())?;
    assert_eq!(application, case.checkpoint.application());
    assert_eq!(state, p::AccountAuthorityReplacementState::Committed);
    assert_eq!(retained, &proposal);
    registry.close();
    Ok(())
}
