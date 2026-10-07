// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture_with_credential_lifetimes, durable::tests::grant,
    VerifiedCredentialRenewal,
};

fn local(role: BootstrapRole) -> Local {
    let long = crate::tests::interval();
    let short = Validity::new(100, 160).expect("original peer expires");
    let credentials = match role {
        BootstrapRole::Initiator => [long, short],
        BootstrapRole::Responder => [short, long],
    };
    Local::with_fixture(
        fixture_with_credential_lifetimes(PrekeyQuality::OneTimeBoth, credentials),
        role,
    )
}
fn renewed(
    l: &Local,
    previous: Option<&VerifiedDevice>,
    version: u64,
    until: u64,
) -> VerifiedCredentialRenewal {
    let peer_role = match l.role {
        BootstrapRole::Initiator => BootstrapRole::Responder,
        BootstrapRole::Responder => BootstrapRole::Initiator,
    };
    let seed = if peer_role == BootstrapRole::Initiator {
        90
    } else {
        94
    };
    let root = RootSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("root");
    let original = l.f.initiator.device(peer_role);
    let certificate = root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original body");
    grant(
        &root,
        &certificate,
        previous.unwrap_or(original),
        until,
        version,
        [u8::try_from(version + 50).expect("fixture operation"); 32],
        l.f.initiator
            .current_policy()
            .expect("fixture policy owner")
            .checkpoint()
            .digest(),
    )
}
fn install(l: &mut Local, proof: &VerifiedCredentialRenewal) {
    l.service
        .admit_peer_credential_renewal(
            proof,
            proof.operation(),
            l.f.initiator
                .current_policy()
                .expect("fixture policy owner"),
            150,
        )
        .expect("atomic peer grant");
}
fn reopen_bundle(
    l: &mut Local,
    session: [u8; 32],
    role: BootstrapRole,
    now: u64,
) -> Result<crate::ReopenedPeer, DurableError> {
    l.service.reopen_peer_bundle(
        &l.f.bundle,
        l.f.policy_owner(BootstrapRole::Initiator),
        l.f.bundle_requirements(PrekeyQuality::OneTimeBoth),
        role,
        session,
        now,
    )
}

#[test]
fn expired_peer_reopens_exact_original_session_and_current_grant_fences_cached_view() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let mut l = local(role);
        let session = l.session;
        let before = l.service.stores().expect("stores").0.test_snapshot();
        let original_wire = l
            .service
            .stores()
            .expect("stores")
            .0
            .resume_message(&l.f.initiator, session, l.original_id, 150)
            .expect("original outbox");
        assert!(l
            .f
            .bundle
            .request_reopen(
                l.f.policy_owner(BootstrapRole::Initiator),
                l.f.bundle_requirements(PrekeyQuality::OneTimeBoth),
                role,
                session,
                170
            )
            .is_err());
        assert!(reopen_bundle(&mut l, session, role, 170).is_err());
        let first = renewed(&l, None, 2, 180);
        install(&mut l, &first);
        assert!(reopen_bundle(&mut l, [213; 32], role, 170).is_err());
        let wrong_role = if role == BootstrapRole::Initiator {
            BootstrapRole::Responder
        } else {
            BootstrapRole::Initiator
        };
        assert!(reopen_bundle(&mut l, session, wrong_role, 170).is_err());
        let peer = reopen_bundle(&mut l, session, role, 170).expect("continued original peer");
        assert_eq!(peer.session_id(), session);
        assert_eq!(peer.context().digest(), l.f.initiator.digest());
        for side in [BootstrapRole::Initiator, BootstrapRole::Responder] {
            assert_eq!(
                peer.context().device(side).credential_digest(),
                l.f.initiator.device(side).credential_digest()
            );
        }
        let context = Arc::clone(peer.context());
        assert!(l
            .service
            .admit_peer(Arc::clone(&context), role, 150)
            .is_err());
        let journal = l.service.stores().expect("stores").0;
        assert_eq!(
            journal
                .resume_message(&context, session, l.original_id, 170)
                .expect("same retained wire"),
            original_wire
        );
        assert!(journal.next_message_id(&context, [214; 32], 170).is_err());
        assert!(journal
            .archive_session_closure(&context, [214; 32])
            .is_err());
        let next = journal
            .next_message_id(&context, session, 170)
            .expect("continued next ID");
        assert_ne!(next, l.original_id);
        journal
            .send_message(
                &context,
                session,
                next,
                b"after original expiry",
                b"renewal",
                170,
            )
            .expect("durable new message");
        assert!(journal.next_message_id(&context, session, 180).is_err());
        let after = journal.test_snapshot();
        assert_eq!((after.id, after.owner), (before.id, before.owner));
        l.service.close();
        let device = l.f.initiator.device(role);
        let policy =
            l.f.initiator
                .current_policy()
                .expect("fixture policy owner");
        l.service = DeviceInstallation::open(paths(&l.root), &key(&l.root), device, policy, 170)
            .expect("original installation after restart")
            .activate(key(&l.root), device, policy, 170, None)
            .expect("original journal and archive owners");
        let restored =
            reopen_bundle(&mut l, session, role, 170).expect("persisted grant after restart");
        assert_eq!(
            l.service
                .stores()
                .expect("stores")
                .0
                .resume_message(restored.context(), session, l.original_id, 170)
                .expect("same persisted outbox"),
            original_wire
        );
        let second = renewed(&l, Some(first.successor_device()), 3, 190);
        install(&mut l, &second);
        let frozen = l.service.stores().expect("stores").0.test_snapshot();
        assert!(l
            .service
            .stores()
            .expect("stores")
            .0
            .next_message_id(&context, session, 175)
            .is_err());
        let fresh = reopen_bundle(&mut l, session, role, 175).expect("current grant view");
        l.service
            .stores()
            .expect("stores")
            .0
            .next_message_id(fresh.context(), session, 175)
            .expect("fresh view");
        let current = l.service.stores().expect("stores").0.test_snapshot();
        assert_eq!(
            (current.revision, current.digest),
            (frozen.revision, frozen.digest)
        );
        let seed = if role == BootstrapRole::Initiator {
            94
        } else {
            90
        };
        let revoked =
            crate::durable::tests::renewal_roster(second.successor_device(), seed, 4, false);
        l.service
            .stores()
            .expect("stores")
            .0
            .install_roster(&revoked, 175)
            .expect("observed revocation");
        assert!(l
            .service
            .stores()
            .expect("stores")
            .0
            .next_message_id(fresh.context(), session, 175)
            .is_err());
        assert!(reopen_bundle(&mut l, session, role, 175).is_err());
        // Cleanup remains available after revocation and does not release traffic.
        let report = l
            .service
            .stores()
            .expect("stores")
            .0
            .begin_session_closure(fresh.context(), session)
            .expect("revoked cleanup");
        l.service
            .stores()
            .expect("stores")
            .0
            .acknowledge_session_closure(fresh.context(), session, report.report)
            .expect("exact loss accounting");
        assert!(l
            .service
            .stores()
            .expect("stores")
            .0
            .next_message_id(fresh.context(), session, 175)
            .is_err());
    }
}

#[test]
fn retained_view_rechecks_policy_owner_close_and_preserves_original_journal_on_refusal() {
    let mut l = local(BootstrapRole::Initiator);
    let proof = renewed(&l, None, 2, 190);
    install(&mut l, &proof);
    let session = l.session;
    let peer = reopen_bundle(&mut l, session, BootstrapRole::Initiator, 170).expect("peer");
    let before = l.service.stores().expect("stores").0.test_snapshot();
    peer.context()
        .current_policy()
        .expect("fixture policy owner")
        .close();
    assert!(l
        .service
        .stores()
        .expect("stores")
        .0
        .next_message_id(peer.context(), session, 170)
        .is_err());
    let after = l.service.stores().expect("stores").0.test_snapshot();
    assert_eq!(
        (after.revision, after.digest),
        (before.revision, before.digest)
    );
}
