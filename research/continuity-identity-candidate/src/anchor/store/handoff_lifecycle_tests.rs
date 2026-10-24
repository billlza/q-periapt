// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn freeze_original(c: &mut Case, operations: [AnchorOperation; 4]) {
    let before = c
        .store
        .handoff_source_state()
        .expect("original pending lifecycle state");
    let plan = super::super::handoff::plan(c, 252);
    c.store
        .freeze_handoff(&plan, 150)
        .expect("global source freeze with pending work");
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .frozen_handoff_state(&plan)
            .expect("complete original export")
            .as_bytes(),
        before.as_bytes()
    );
    for operation in operations {
        let q = request(c, operation);
        assert!(matches!(
            c.store.handle(q.as_bytes(), 150),
            Err(AnchorError::Storage(DurableError::Suspended))
        ));
    }
    c.store
        .cancel_handoff(&plan)
        .expect("cancel without resetting original transaction");
    super::super::handoff_import::import_pending_then_cancel(c);
}

#[test]
fn source_handoff_keeps_original_pending_policy_and_blocks_all_four_policy_commands() {
    use crate::PolicyRenewalMaterials;
    let mut c = required_case();

    let original = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original")
        .1
        .clone();
    let identity = c._journal.identity().expect("original identity");
    let (issuer, _, _, runtime) = crate::tests::session_policy_fixture_with_budget(
        &[PrekeyQuality::OneTimeBoth],
        crate::AnchorRequirement::required(&c.pin),
        crate::ApplicationSendBudget::new(1024).expect("budget"),
    );
    let issued = issuer
        .issue_session_policy(
            &runtime,
            crate::SessionPolicyParameters::new(
                2,
                Validity::new(100, 300).expect("validity"),
                crate::AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth]).expect("modes"),
                crate::AnchorRequirement::required(&c.pin),
                crate::ApplicationSendBudget::new(1024).expect("budget"),
            )
            .expect("parameters"),
        )
        .expect("signed target policy");
    let target = crate::PolicyPin::new(
        issuer.policy_family().expect("family"),
        issuer.public_key().expect("policy key"),
        issued.checkpoint(),
    )
    .expect("independent policy pin")
    .verify(issued.as_bytes(), runtime, 150)
    .expect("verified target policy");
    let policy = c.peer.responder.current_policy().expect("original policy");
    let scope = crate::PolicyRenewalScope {
        operation: crate::PolicyRenewalId::generate().expect("P operation"),
        journal: identity,
        original_owner: crate::bootstrap::storage_owner(&original),
        original_credential: original.credential_digest(),
        current_credential: original.credential_digest(),
        current_roster: original.roster().checkpoint(),
        original_policy: policy.checkpoint(),
        previous_policy: policy.checkpoint(),
        previous_authorization: None,
    };
    let materials = PolicyRenewalMaterials {
        original: policy.historical(),
        previous: policy.historical(),
        target: &target,
        original_device: &original,
        current_device: &original,
    };
    let statement =
        crate::PolicyRenewalStatement::new(&scope, &materials, 150).expect("exact P statement");
    let root = crate::RootSigningKey::deterministic([94; 32], [95; 32])
        .expect("original account authority");
    let approval = crate::VerifiedPolicyRenewal::verify(
        &root
            .approve_policy_renewal(&statement)
            .expect("account approval"),
        &issuer
            .approve_policy_renewal(&statement)
            .expect("policy approval"),
        &scope,
        &materials,
        150,
    )
    .expect("independently authenticated P");

    let proposal = crate::AnchorPolicyRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        scope.operation,
        approval.statement_digest(),
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [253; 32]).expect("store-level policy target"),
    )
    .expect("original P descriptor");
    c.store
        .prepare_policy_renewal(proposal, &approval, &materials, 150)
        .expect("independently approved pending P");
    freeze_original(
        &mut c,
        [
            AnchorOperation::policy_renewal_status(&proposal),
            AnchorOperation::commit_policy_renewal(&proposal),
            AnchorOperation::close_policy_renewal(&proposal),
            AnchorOperation::acknowledge_policy_renewal(&proposal),
        ],
    );
    let q = request(&c, AnchorOperation::close_policy_renewal(&proposal));
    assert_eq!(
        apply_request(&mut c, &q)
            .policy_renewal_state(&proposal)
            .expect("same original P"),
        crate::AnchorPolicyRenewalState::Closed
    );
}

#[test]
fn source_handoff_keeps_original_pending_roster_and_blocks_all_four_roster_commands() {
    let mut c = required_case();
    let original = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original device")
        .1
        .clone();
    let (refreshed, _) = signed_device(&original, original.description.clone(), 2, 96, &[]);
    let policy = c.peer.responder.current_policy().expect("original policy");
    let proposal = crate::AnchorRosterRefreshProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        crate::RosterRefreshScope {
            operation: crate::RosterRefreshId::generate().expect("original R"),
            previous: original.roster().checkpoint(),
            target: refreshed.roster().checkpoint(),
            policy: policy.checkpoint(),
            policy_authorization: None,
        },
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [254; 32]).expect("store-level roster target"),
    )
    .expect("original R descriptor");
    c.store
        .prepare_roster_refresh(proposal, &original, &refreshed, policy, 150)
        .expect("actual original pending R");
    freeze_original(
        &mut c,
        [
            AnchorOperation::roster_refresh_status(&proposal),
            AnchorOperation::commit_roster_refresh(&proposal),
            AnchorOperation::close_roster_refresh(&proposal),
            AnchorOperation::acknowledge_roster_refresh(&proposal),
        ],
    );
    let q = request(&c, AnchorOperation::close_roster_refresh(&proposal));
    assert_eq!(
        apply_request(&mut c, &q)
            .roster_refresh_state(&proposal)
            .expect("same original R"),
        crate::AnchorRosterRefreshState::Closed
    );
}
