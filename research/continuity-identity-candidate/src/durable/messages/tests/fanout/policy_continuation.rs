// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    PolicyContinuationMaterials, PolicyContinuationScope, PolicyContinuationStatement, PolicyPin,
    PolicySigningKey, SessionPolicyParameters, VerifiedPolicyContinuation,
};

fn policy(
    original: &crate::VerifiedSessionPolicy,
    version: u64,
    until: u64,
) -> Arc<crate::VerifiedSessionPolicy> {
    let root = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy root");
    let issued = root
        .issue_session_policy(
            &original.runtime,
            SessionPolicyParameters::new(
                version,
                crate::Validity::new(100, until).expect("interval"),
                original.allowed_modes(),
                original.anchor_requirement(),
                original.application_send_budget(),
            )
            .expect("profile"),
        )
        .expect("signed policy");
    Arc::new(
        PolicyPin::new(
            original.family(),
            root.public_key().expect("key"),
            issued.checkpoint(),
        )
        .expect("independent pin")
        .verify(issued.as_bytes(), Arc::clone(&original.runtime), 170)
        .expect("actual owner"),
    )
}
fn adopt(
    n: &mut Network,
    previous: Option<(
        &crate::VerifiedCredentialRenewal,
        &VerifiedPolicyContinuation,
        &crate::VerifiedSessionPolicy,
    )>,
    target: &crate::VerifiedSessionPolicy,
    version: u64,
    until: u64,
) -> (crate::VerifiedCredentialRenewal, VerifiedPolicyContinuation) {
    let original = n.f.local.as_ref();
    let issuer =
        RootSigningKey::deterministic([20; 32], [21; 32]).expect("original local account root");
    let p0 =
        n.f.contexts
            .first()
            .expect("original first context")
            .original_policy();
    let certificate = issuer
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original certificate body");
    let grant = crate::durable::tests::grant(
        &issuer,
        &certificate,
        previous.map_or(original, |v| v.0.successor_device()),
        until,
        version,
        [u8::try_from(version + 80).expect("operation"); 32],
        p0.checkpoint().digest(),
    );
    let scope = PolicyContinuationScope {
        operation: grant.operation(),
        journal: n.sender.identity().expect("original journal"),
        original_owner: crate::bootstrap::storage_owner(original),
        original_credential: original.credential_digest(),
        previous_credential: grant.previous_device().credential_digest(),
        previous_roster: grant.previous_device().roster().checkpoint(),
        original_policy: p0.checkpoint(),
        previous_policy: previous.map_or(p0.checkpoint(), |v| v.2.checkpoint()),
        previous_authorization: previous.map(|v| v.1.statement_digest()),
    };
    let m = PolicyContinuationMaterials {
        original: p0,
        previous: previous.map_or(p0, |v| v.2.historical()),
        target,
        credential: &grant,
    };
    let statement =
        PolicyContinuationStatement::new(&scope, &m, 170).expect("current joint relationship");
    let policy_root =
        PolicySigningKey::deterministic([82; 32], [83; 32]).expect("independent policy root");
    let a = issuer
        .approve_policy_continuation(&statement)
        .expect("account approval");
    let p = policy_root
        .approve_policy_continuation(&statement)
        .expect("policy approval");
    let t = VerifiedPolicyContinuation::verify(&a, &p, &scope, &m, 170).expect("both signatures");
    let h = t.historical();
    let authority = crate::RetainedInstallationAuthority::active_installation(original, p0);
    let receipt = n
        .sender
        .commit_local_renewal(
            &authority,
            &crate::durable::LocalRenewalTarget {
                policy_renewal: None,
                grant: &grant,
                continuation: Some(&h),
            },
            target,
            170,
        )
        .expect("atomic journal transition");
    n.sender
        .acknowledge_local_credential_renewal(&authority, &receipt)
        .expect("component fixture supplies coordinator completion ACK");
    (grant, t)
}
fn contexts(n: &mut Network, p: Arc<crate::VerifiedSessionPolicy>) -> Vec<Arc<BootstrapContext>> {
    n.f.contexts
        .iter()
        .zip(&n.sessions)
        .map(|(context, session)| {
            n.sender
                .prepare_continued_context(
                    Arc::clone(context),
                    *session,
                    crate::BootstrapRole::Initiator,
                    Arc::clone(&p),
                    170,
                )
                .expect("exact original member under current T")
        })
        .collect()
}
fn targets<'a>(
    contexts: &'a [Arc<BootstrapContext>],
    sessions: &[[u8; 32]],
) -> Vec<FanoutTarget<'a>> {
    contexts
        .iter()
        .zip(sessions)
        .map(|(context, session)| FanoutTarget {
            context,
            session: *session,
        })
        .collect()
}

#[test]
fn policy_transition_preserves_mixed_terminal_fanout_and_checks_every_current_context() {
    let mut n = Network::new(8, false);
    let original_context = Arc::clone(n.f.contexts.first().expect("original first context"));
    let original = original_context.current_policy().expect("original runtime");
    let p1 = policy(original, 2, 250);
    let (g1, t1) = adopt(&mut n, None, &p1, 2, 240);
    let c1 = contexts(&mut n, Arc::clone(&p1));
    let first_targets = targets(&c1, &n.sessions);
    let batch = n.sender.next_fanout_id().expect("batch");
    let sent = n
        .sender
        .send_account_message(
            FanoutInput {
                id: batch,
                account: n.f.peers.first().expect("first peer").account_id(),
                targets: &first_targets,
                plaintext: b"one original complete account batch",
                associated_data: b"T",
            },
            170,
        )
        .expect("current T1 group");
    assert_eq!(sent.len(), 2);
    let p2 = policy(original, 3, 275);
    let (_g2, _t2) = adopt(&mut n, Some((&g1, &t1, &p1)), &p2, 3, 260);
    p1.check_mode(PrekeyQuality::ReusableBoth, 175)
        .expect("old P1 remains live");
    assert!(
        n.sender
            .resume_account_message(batch, &first_targets, 175)
            .is_err(),
        "old T1 cannot release any of the two members"
    );
    let c2 = contexts(&mut n, Arc::clone(&p2));
    let current_targets = targets(&c2, &n.sessions);
    // One stale member invalidates the entire aggregate even if the other one
    // already carries the current T2/P2 and matches its own original session.
    for stale in [0, 1] {
        let mixed: Vec<_> = n
            .sessions
            .iter()
            .enumerate()
            .map(|(i, session)| FanoutTarget {
                context: if i == stale {
                    c1.get(i).expect("original T1 context for each session")
                } else {
                    c2.get(i).expect("current T2 context for each session")
                },
                session: *session,
            })
            .collect();
        assert!(n.sender.resume_account_message(batch, &mixed, 175).is_err());
    }
    let first_current = c2.first().expect("first current context");
    let first_session = *n.sessions.first().expect("first session");
    let report = n
        .sender
        .begin_session_closure(first_current, first_session)
        .expect("explicit first member loss accounting");
    let closing = n
        .sender
        .resume_account_message(batch, &current_targets, 175)
        .expect("mixed closing and live members");
    assert!(matches!(
        closing.first().expect("first closing result").output,
        FanoutOutput::ResolutionPending
    ));
    let live = match &closing.get(1).expect("second closing result").output {
        FanoutOutput::Committed(w) => Some(w),
        _ => None,
    }
    .expect("second member remains exact committed output");
    let original_live = match &sent.get(1).expect("second original result").output {
        FanoutOutput::Committed(w) => Some(w),
        _ => None,
    }
    .expect("original second output");
    assert_eq!(live, original_live);
    n.sender
        .acknowledge_session_closure(first_current, first_session, report.report)
        .expect("host acknowledges original unknown outcome");
    let closed = n
        .sender
        .resume_account_message(batch, &current_targets, 175)
        .expect("terminal member does not become a live session");
    assert!(matches!(
        closed.first().expect("first closed result").output,
        FanoutOutput::DeliveryUnknown
    ));
    assert_eq!(
        match &closed.get(1).expect("second closed result").output {
            FanoutOutput::Committed(w) => Some(w),
            _ => None,
        }
        .expect("retained live output"),
        original_live
    );
    assert!(n
        .sender
        .next_message_id(first_current, first_session, 175)
        .is_err());
    assert!(n
        .sender
        .resume_account_message(batch, &first_targets, 175)
        .is_err());
    p2.close();
    assert!(
        n.sender
            .resume_account_message(batch, &current_targets, 175)
            .is_err(),
        "no member output from a closed current owner"
    );
    eprintln!("CONTINUED_FANOUT members=2 mixed_stale_refused=2 terminal_unknown_preserved=true live_wire_preserved=true");
}
