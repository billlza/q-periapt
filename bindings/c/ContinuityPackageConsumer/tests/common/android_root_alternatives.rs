// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent approval and witness decisions; Android owns all controller mutations.
use crate::{android_root_owned::store, android_root_target::Target, fixture, p, Result};
use std::path::Path;
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Variant {
    Original,
    Transition,
    BoundTransition,
    Adoption,
    Noncommit,
}
impl Variant {
    pub fn name(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Transition => "transition",
            Self::BoundTransition => "bound-transition",
            Self::Adoption => "adoption",
            Self::Noncommit => "noncommit",
        }
    }
    pub fn processes(self) -> u64 {
        match self {
            Self::Original => 34,
            Self::Transition => 36,
            Self::BoundTransition => 37,
            Self::Adoption => 33,
            Self::Noncommit => 41,
        }
    }
    pub fn cuts(self) -> u64 {
        match self {
            Self::BoundTransition | Self::Noncommit => 7,
            Self::Adoption => 5,
            _ => 6,
        }
    }
}
pub(crate) struct Approval<'a> {
    pub inputs: &'a Path,
    pub witness: &'a fixture::WitnessFixture,
    pub plan: &'a p::AnchorAccountReplacementPlan,
    pub old_root: &'a p::RootSigningKey,
    pub target: &'a Target,
    pub policy: &'a p::VerifiedSessionPolicy,
    pub pin: &'a p::AnchorPin,
}
type Run<'a> = &'a dyn Fn(&str, &str) -> Result<Vec<u8>>;
pub(crate) fn prepare(
    case: Approval<'_>,
    variant: Variant,
    run: Run<'_>,
    cut: Run<'_>,
) -> Result<Vec<u8>> {
    if variant == Variant::Adoption {
        return adopt(&case, run, cut);
    }
    let freeze = {
        let mut witness = case
            .witness
            .store
            .lock()
            .map_err(|_| "independent freeze")?;
        witness.freeze_account(case.plan.request())?;
        witness.account_freeze_receipt(case.plan.request())?
    };
    store(case.inputs, "root-freeze", &freeze)?;
    assert_eq!(
        run("root-freeze-bad", "root-bad-freeze")?,
        102u32.to_be_bytes()
    );
    let bound = if variant == Variant::Original {
        let bound = cut("root-freeze-unknown", "root-bound")?;
        assert_eq!(run("root-freeze-replay", "root-bound-replayed")?, bound);
        bound
    } else {
        transition(&case, variant, &freeze, run, cut)?
    };
    let proposal = p::AnchorAccountReplacementProposal::from_trusted_state(&bound)?;
    assert_eq!(proposal.successor_account(), case.target.root.account_id()?);
    let receipt = {
        let mut witness = case
            .witness
            .store
            .lock()
            .map_err(|_| "independent commit")?;
        witness.replace_account_root(
            &proposal,
            &case.old_root.public_key()?,
            &case.target.genesis,
            &case.target.device,
            case.policy,
            fixture::now()?,
        )?;
        witness.retired_account_receipt(&proposal)?
    };
    store(case.inputs, "root-retirement", &receipt)?;
    let retained = cut("root-retain-unknown", "root-retained")?;
    assert_eq!(
        run("root-retain-replay", "root-retained-replayed")?,
        retained
    );
    Ok(retained)
}
fn transition(
    case: &Approval<'_>,
    variant: Variant,
    freeze: &[u8],
    run: Run<'_>,
    cut: Run<'_>,
) -> Result<Vec<u8>> {
    if variant == Variant::BoundTransition {
        let original = cut("root-freeze-original", "root-original-bound")?;
        let proposal = p::AnchorAccountReplacementProposal::from_trusted_state(&original)?;
        assert_ne!(proposal.successor_account(), case.target.root.account_id()?);
    }
    let (next, noncommit) = {
        let mut witness = case
            .witness
            .store
            .lock()
            .map_err(|_| "independent transition")?;
        witness.close_account_preparation(case.plan)?;
        let frozen = witness.freeze_account(case.plan.request())?;
        (
            witness.frozen_account_replacement_plan(
                p::AnchorAccountReplacementId::from_trusted_state([164; 32])?,
                &frozen,
                &case.target.genesis,
                &case.target.device,
                case.policy,
                fixture::now()?,
            )?,
            witness.closed_account_preparation_receipt(case.plan)?,
        )
    };
    p::ManagedAccountRootTransition::verify(case.pin, case.plan, next.clone(), &noncommit, freeze)?;
    store(case.inputs, "root-next-plan", &next.to_bytes()?)?;
    store(case.inputs, "root-noncommit", &noncommit)?;
    if variant == Variant::Noncommit {
        assert_eq!(
            run("root-noncommit-bad", "root-bad-noncommit")?,
            102u32.to_be_bytes()
        );
        assert_eq!(
            cut("root-noncommit-unknown", "root-noncommit-retained")?,
            4u32.to_be_bytes()
        );
        assert_eq!(
            run("root-noncommit-replay", "root-noncommit-replayed")?,
            4u32.to_be_bytes()
        );
    }
    let bound = cut("root-transition-unknown", "root-bound")?;
    assert_eq!(run("root-transition-replay", "root-bound-replayed")?, bound);
    Ok(bound)
}
fn adopt(case: &Approval<'_>, run: Run<'_>, cut: Run<'_>) -> Result<Vec<u8>> {
    let (proposal, noncommit, retirement) = {
        let mut witness = case
            .witness
            .store
            .lock()
            .map_err(|_| "independent winner")?;
        let competing = p::AnchorAccountFreezeRequest::from_trusted_state(
            p::AnchorAccountFreezeId::from_trusted_state([165; 32])?,
            case.old_root.public_key()?,
            case.pin,
        )?;
        let frozen = witness.freeze_account(&competing)?;
        let proposal = witness.frozen_account_replacement_proposal(
            p::AnchorAccountReplacementId::from_trusted_state([166; 32])?,
            &frozen,
            &case.target.genesis,
            &case.target.device,
            case.policy,
            fixture::now()?,
        )?;
        witness.replace_account_root(
            &proposal,
            &case.old_root.public_key()?,
            &case.target.genesis,
            &case.target.device,
            case.policy,
            fixture::now()?,
        )?;
        witness.close_account_preparation(case.plan)?;
        let noncommit = witness.closed_account_preparation_receipt(case.plan)?;
        let retirement = witness.retired_account_receipt(&proposal)?;
        (proposal, noncommit, retirement)
    };
    p::ManagedAccountRootAdoption::verify(
        case.pin,
        case.plan,
        proposal.clone(),
        &noncommit,
        &retirement,
    )?;
    store(case.inputs, "root-winner", &proposal.to_bytes()?)?;
    store(case.inputs, "root-noncommit", &noncommit)?;
    store(case.inputs, "root-retirement", &retirement)?;
    let checkpoint = cut("root-adopt-unknown", "root-retained")?;
    assert_eq!(
        run("root-adopt-replay", "root-retained-replayed")?,
        checkpoint
    );
    Ok(checkpoint)
}
