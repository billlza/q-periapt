// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent witness verifies public G/T approvals before prepare or closure.
use super::*;

pub(super) fn approve(
    case: &Case<'_>,
    issued: &issuer::Issued,
    bytes: &[u8],
    previous: &p::HistoricalSessionPolicy,
) -> Result<()> {
    let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(bytes)?;
    assert_eq!(proposal.operation(), issued.operation);
    assert_eq!(proposal.statement(), issued.grant.statement_digest());
    assert_eq!(proposal.transaction_statement(), issued.statement);
    assert_eq!(proposal.policy_continuation(), Some(issued.statement));
    assert_eq!(proposal.policy_renewal(), None);
    assert!(proposal.adopts_policy());
    let original = crate::receiver_policy::historical(case.inputs)?;
    let target = fixture::protocol_policy(&case.inputs.join("policy-target"), case.sdk)?;
    let materials = p::PolicyContinuationMaterials {
        original: &original,
        previous,
        target: &target,
        credential: &issued.grant,
    };
    let continuation = p::VerifiedPolicyContinuation::from_bytes(
        &fs::read(case.inputs.join("joint-approvals"))?,
        &issued.scope,
        &materials,
        fixture::now()?,
    )?;
    assert_eq!(
        case.witness
            .ok_or("required witness")?
            .configured
            .store
            .lock()
            .map_err(|_| "joint witness approval")?
            .prepare_policy_continuation(proposal, &continuation, &materials, fixture::now()?)?,
        p::AnchorCredentialRenewalState::Prepared
    );
    target.close();
    Ok(())
}

pub(super) fn close(case: &Case<'_>, prepared: &Prepared, bytes: &[u8]) -> Result<()> {
    let cancellation = p::AnchorCredentialRenewalCancellation::from_trusted_state(bytes)?;
    assert_eq!(cancellation.operation(), prepared.issued.operation);
    assert_eq!(
        cancellation.statement(),
        prepared.issued.grant.statement_digest()
    );
    assert_eq!(
        cancellation.transaction_statement(),
        prepared.issued.statement
    );
    assert_eq!(
        cancellation.policy_continuation(),
        Some(prepared.issued.statement)
    );
    assert!(cancellation.adopts_policy());
    let original = crate::receiver_policy::historical(case.inputs)?;
    let target = crate::receiver_policy::historical(&case.inputs.join("policy-target"))?;
    let pin = p::AccountPin::new(
        case.root.account_id()?,
        case.root.public_key()?,
        prepared.issued.roster,
        original.family(),
    )?;
    let grant = p::HistoricalCredentialRenewal::verify(
        &fs::read(case.inputs.join("credential-renewal"))?,
        &pin,
        original.checkpoint().digest(),
    )?;
    let materials = p::HistoricalPolicyContinuationMaterials {
        original: &original,
        previous: &original,
        target: &target,
        credential: &grant,
    };
    let continuation = p::HistoricalPolicyContinuation::from_bytes(
        &fs::read(case.inputs.join("joint-approvals"))?,
        &prepared.issued.scope,
        &materials,
    )?;
    assert_eq!(
        case.witness
            .ok_or("required witness")?
            .configured
            .store
            .lock()
            .map_err(|_| "joint witness closure")?
            .close_unprepared_policy_continuation(cancellation, &continuation, &materials)?,
        p::AnchorCredentialCancellationState::Closed
    );
    Ok(())
}

pub(super) fn commit_reply_loss(case: &Case<'_>) -> Result<()> {
    if let Some(tls) = case.tls {
        tls.arm(None)?;
    } else {
        let witness = case.witness.ok_or("signed witness")?;
        // The server retains a fixed prefix filename beside its marker. Give
        // each generation its own directory; never overwrite an earlier cut.
        let directory = case.output("joint-commit-fault");
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let mut marker = witness
            .hold_marker
            .lock()
            .map_err(|_| "joint Commit barrier")?;
        if marker.replace(directory.join("ready")).is_some() {
            return Err("unconsumed joint Commit barrier".into());
        }
        drop(marker);
        witness.arm(9)?;
    }
    Ok(())
}
