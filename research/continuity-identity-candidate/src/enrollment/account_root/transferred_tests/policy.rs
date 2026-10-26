// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual parent P request, two-root approval and retained child target.
use super::*;

fn issue_policy(f: &Fixture) -> (VerifiedSessionPolicy, Vec<u8>) {
    let wire = f
        .issuer
        .issue_session_policy(
            &f.runtime,
            SessionPolicyParameters::new(
                2,
                Validity::new(100, 250).expect("renewal interval"),
                f.policy.allowed_modes(),
                f.policy.anchor_requirement(),
                f.policy.application_send_budget(),
            )
            .expect("parameters"),
        )
        .expect("actual renewal policy");
    let verified = PolicyPin::new(
        f.policy.family(),
        f.issuer.public_key().expect("issuer"),
        wire.checkpoint(),
    )
    .expect("policy pin")
    .verify(wire.as_bytes(), Arc::clone(&f.runtime), 150)
    .expect("renewed policy");
    (verified, wire.as_bytes().to_vec())
}
fn client(f: &Fixture, owner: &mut DeviceEnrollment) -> AnchorClient {
    owner
        .policy_renewal_anchor_client(
            f.policy.historical(),
            f.pin.clone(),
            Box::new(Carrier(Arc::clone(&f.witness))),
            Duration::from_secs(3),
        )
        .expect("original P carrier")
}
pub(super) fn prepare_policy(f: &Fixture, stage: u8) -> (VerifiedSessionPolicy, Vec<u8>) {
    let mut owner = DeviceEnrollment::open(f.original.paths.clone(), f.original.intent.clone())
        .expect("same original parent");
    let carrier = client(f, &mut owner);
    let request = owner
        .witnessed_policy_renewal_request(
            PolicyRenewalId::generate().expect("original P identity"),
            f.policy.historical(),
            carrier,
        )
        .expect("actual public renewal request");
    let (target, wire) = issue_policy(f);
    let materials = request.materials(f.policy.historical(), f.policy.historical(), &target);
    let statement = PolicyRenewalStatement::new(request.scope(), &materials, 150)
        .expect("original P statement");
    let approved = VerifiedPolicyRenewal::verify(
        &f.original
            .root
            .approve_policy_renewal(&statement)
            .expect("account P approval"),
        &f.issuer
            .approve_policy_renewal(&statement)
            .expect("policy P approval"),
        request.scope(),
        &materials,
        150,
    )
    .expect("dual-root P approval");
    owner
        .stage_policy_renewal(
            &approved,
            approved.scope().operation,
            f.policy.historical(),
            &target,
            150,
        )
        .expect("real parent P intent");
    let carrier = client(f, &mut owner);
    let proposal = owner
        .prepare_witnessed_policy_renewal(
            f.policy.historical(),
            f.policy.historical(),
            &target,
            150,
            carrier,
        )
        .expect("actual sealed pending target");
    f.witness
        .lock()
        .expect("source")
        .prepare_policy_renewal(proposal, &approved, &materials, 150)
        .expect("independent server P approval");
    if stage >= 1 {
        let mut carrier = client(f, &mut owner);
        assert_eq!(
            carrier
                .exchange(
                    f.original.genesis.subject(),
                    AnchorOperation::commit_policy_renewal(&proposal)
                )
                .expect("actual P commit")
                .policy_renewal_state(&proposal)
                .expect("exact result"),
            AnchorPolicyRenewalState::Applied
        );
        if stage == 2 {
            assert_eq!(
                DeviceJournal::recover_policy_renewal(
                    f.original.paths.installation.files()[1],
                    JournalKey::open(&f.original.paths.wrapping).expect("original wrapping key"),
                    &f.original.device,
                    f.policy.historical(),
                    request.scope().journal,
                    proposal,
                    &mut carrier
                )
                .expect("install original target with pending still retained"),
                AnchorPolicyRenewalState::Applied
            );
        }
    }
    owner.close();
    (target, wire)
}
