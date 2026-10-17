// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::root_replacement::alternative as alternatives;

fn input(
    original: &[u8],
    approved: &[u8],
    noncommit: &[u8],
    receipt: &[u8],
) -> alternatives::Alternative {
    alternatives::Alternative {
        struct_size: std::mem::size_of::<alternatives::Alternative>() as u32,
        original: original.as_ptr(),
        original_length: original.len(),
        approved: approved.as_ptr(),
        approved_length: approved.len(),
        noncommit: noncommit.as_ptr(),
        noncommit_length: noncommit.len(),
        receipt: receipt.as_ptr(),
        receipt_length: receipt.len(),
    }
}
#[test]
fn root_foreign_transition_resumes_the_exact_independently_approved_next_plan() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let mut case = Case::new()?;
    case.begin()?;
    let freeze = case.freeze()?;
    case.bind(&freeze)?;
    case.prepare_new_target()?;
    let mut sdk = fixture::sdk(&case.reference.initiator)?;
    let policy = fixture::protocol_policy(&case.reference.initiator, &sdk)?;
    let (next, noncommit) = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.close_account_preparation(&case.plan)?;
        let noncommit = witness.closed_account_preparation_receipt(&case.plan)?;
        let frozen = witness.account_freeze(case.plan.request())?;
        let next = witness.frozen_account_replacement_plan(
            p::AnchorAccountReplacementId::from_trusted_state([97; 32])?,
            &frozen,
            &case.target.genesis,
            &case.target.credential,
            &policy,
            fixture::now()?,
        )?;
        (next, noncommit)
    };
    policy.close();
    sdk.close();
    let original = case.plan.to_bytes()?;
    let approved = next.to_bytes()?;
    let options = input(&original, &approved, &noncommit, &freeze);
    let mut wire = vec![0; 65536];
    let mut written = 0;
    let mut error = diagnostic();
    #[repr(align(8))]
    struct Short(u32);
    let short = Short(4);
    assert_eq!(
        unsafe {
            alternatives::qpc_root_v1_transition(
                case.registry.0,
                std::ptr::addr_of!(short.0).cast(),
                wire.as_mut_ptr(),
                wire.len(),
                &mut written,
                &mut error,
            )
        },
        1
    );
    assert_eq!(state(&case)?, 2);
    let mut corrupt = freeze.clone();
    *corrupt.last_mut().ok_or("receipt")? ^= 1;
    let invalid = input(&original, &approved, &noncommit, &corrupt);
    assert_ne!(
        unsafe {
            alternatives::qpc_root_v1_transition(
                case.registry.0,
                &invalid,
                wire.as_mut_ptr(),
                wire.len(),
                &mut written,
                &mut error,
            )
        },
        0
    );
    assert_eq!(state(&case)?, 2);
    checked(
        unsafe {
            alternatives::qpc_root_v1_transition(
                case.registry.0,
                &options,
                wire.as_mut_ptr(),
                wire.len(),
                &mut written,
                &mut error,
            )
        },
        &error,
    )
    .map_err(|error| format!("apply transition: {error}"))?;
    let proposal = p::AnchorAccountReplacementProposal::from_trusted_state(
        wire.get(..written).ok_or("proposal")?,
    )?;
    assert_eq!(proposal.operation(), next.operation());
    case.reopen_registry()?;
    let path = case.old.path.to_str().ok_or("path")?.as_bytes();
    checked(
        unsafe {
            alternatives::qpc_root_v1_resume_transition(
                case.registry.0,
                path.as_ptr(),
                path.len(),
                &case.old.intent(),
                &case.scope(),
                &options,
                &mut error,
            )
        },
        &error,
    )
    .map_err(|error| format!("resume transition: {error}"))?;
    assert_eq!(state(&case)?, 2);
    case.retain(&case.commit(&proposal)?)?;
    case.activate()?;
    active(case.target.handle.0)?;
    cleanup::erase(&case)?;
    Ok(())
}
#[test]
fn root_foreign_adoption_resumes_actual_winner_without_a_local_winner_plan() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let mut case = Case::new()?;
    case.begin()?;
    let mut sdk = fixture::sdk(&case.reference.initiator)?;
    let policy = fixture::protocol_policy(&case.reference.initiator, &sdk)?;
    let (proposal, noncommit, receipt) = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        let competing = p::AnchorAccountFreezeRequest::from_trusted_state(
            p::AnchorAccountFreezeId::from_trusted_state([107; 32])?,
            case.old.root.public_key()?,
            &witness.pin()?,
        )?;
        let frozen = witness.freeze_account(&competing)?;
        let proposal = witness.frozen_account_replacement_proposal(
            p::AnchorAccountReplacementId::from_trusted_state([108; 32])?,
            &frozen,
            &case.target.genesis,
            &case.target.credential,
            &policy,
            fixture::now()?,
        )?;
        witness.replace_account_root(
            &proposal,
            &case.old.root.public_key()?,
            &case.target.genesis,
            &case.target.credential,
            &policy,
            fixture::now()?,
        )?;
        witness.close_account_preparation(&case.plan)?;
        (
            proposal.clone(),
            witness.closed_account_preparation_receipt(&case.plan)?,
            witness.retired_account_receipt(&proposal)?,
        )
    };
    policy.close();
    sdk.close();
    let original = case.plan.to_bytes()?;
    let approved = proposal.to_bytes()?;
    let options = input(&original, &approved, &noncommit, &receipt);
    let mut checkpoint = case.checkpoint;
    let mut error = diagnostic();
    let mut corrupt = receipt.clone();
    *corrupt.last_mut().ok_or("receipt")? ^= 1;
    let invalid = input(&original, &approved, &noncommit, &corrupt);
    assert_ne!(
        unsafe {
            alternatives::qpc_root_v1_adopt(case.registry.0, &invalid, &mut checkpoint, &mut error)
        },
        0
    );
    assert_eq!(state(&case)?, 1);
    assert_eq!(checkpoint.revision, case.checkpoint.revision);
    checked(
        unsafe {
            alternatives::qpc_root_v1_adopt(case.registry.0, &options, &mut checkpoint, &mut error)
        },
        &error,
    )?;
    assert_eq!(checkpoint.revision, case.checkpoint.revision + 1);
    assert_eq!(checkpoint.account, case.target.root.account_id()?);
    case.reopen_registry()?;
    let path = case.old.path.to_str().ok_or("path")?.as_bytes();
    checked(
        unsafe {
            alternatives::qpc_root_v1_resume_adoption(
                case.registry.0,
                path.as_ptr(),
                path.len(),
                &case.old.intent(),
                &case.scope(),
                &options,
                &mut error,
            )
        },
        &error,
    )?;
    assert_eq!(state(&case)?, 3);
    case.activate()?;
    active(case.target.handle.0)?;
    cleanup::erase(&case)?;
    Ok(())
}
