// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture_with_credential_lifetimes, durable::LocalRenewalTarget,
    PolicyContinuationMaterials, PolicyContinuationScope, PolicyContinuationStatement, PolicyPin,
    PolicySigningKey, SessionPolicyParameters, VerifiedCredentialRenewal,
    VerifiedPolicyContinuation,
};

fn policy(
    f: &Fixture,
    role: BootstrapRole,
    version: u64,
    until: u64,
    now: u64,
) -> Arc<crate::VerifiedSessionPolicy> {
    let original = f.policy_owner(role);
    let issuer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("original policy root");
    let issued = issuer
        .issue_session_policy(
            &original.runtime,
            SessionPolicyParameters::new(
                version,
                Validity::new(100, until).expect("interval"),
                original.allowed_modes(),
                original.anchor_requirement(),
                original.application_send_budget(),
            )
            .expect("same profile"),
        )
        .expect("actual signed policy");
    Arc::new(
        PolicyPin::new(
            original.family(),
            issuer.public_key().expect("root"),
            issued.checkpoint(),
        )
        .expect("independent policy pin")
        .verify(issued.as_bytes(), Arc::clone(&original.runtime), now)
        .expect("actual target owner"),
    )
}
fn short_fixture() -> Fixture {
    let mut f = fixture_with_credential_lifetimes(
        PrekeyQuality::OneTimeBoth,
        [Validity::new(100, 160).expect("original credentials"); 2],
    );
    let i = policy(&f, BootstrapRole::Initiator, 1, 160, 150);
    let r = policy(&f, BootstrapRole::Responder, 1, 160, 150);
    // Re-authenticate the original bundle under genuinely signed short P0
    // before any handshake. No current policy owner is manufactured.
    f.initiator = Arc::new(
        f.bundle
            .verify(i, f.bundle_requirements(PrekeyQuality::OneTimeBoth), 150)
            .expect("original initiator"),
    );
    f.responder = Arc::new(
        f.bundle
            .verify(r, f.bundle_requirements(PrekeyQuality::OneTimeBoth), 150)
            .expect("original responder"),
    );
    f
}
fn other(role: BootstrapRole) -> BootstrapRole {
    match role {
        BootstrapRole::Initiator => BootstrapRole::Responder,
        BootstrapRole::Responder => BootstrapRole::Initiator,
    }
}
fn root(role: BootstrapRole) -> RootSigningKey {
    let seed = if role == BootstrapRole::Initiator {
        90
    } else {
        94
    };
    RootSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("independent account root")
}
fn grant(
    f: &Fixture,
    role: BootstrapRole,
    previous: Option<&VerifiedDevice>,
    version: u64,
    until: u64,
) -> VerifiedCredentialRenewal {
    let issuer = root(role);
    let original = f.initiator.device(role);
    let certificate = issuer
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original body");
    crate::durable::tests::grant(
        &issuer,
        &certificate,
        previous.unwrap_or(original),
        until,
        version,
        [u8::try_from(100 + version).expect("operation"); 32],
        f.initiator.original_policy().checkpoint().digest(),
    )
}
fn joint(
    f: &Fixture,
    role: BootstrapRole,
    journal: JournalIdentity,
    g: &VerifiedCredentialRenewal,
    previous: Option<&VerifiedPolicyContinuation>,
    prior: &crate::HistoricalSessionPolicy,
    target: &crate::VerifiedSessionPolicy,
) -> VerifiedPolicyContinuation {
    let issuer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy root");
    let p0 = f.initiator.original_policy();
    let scope = PolicyContinuationScope {
        operation: g.operation(),
        journal,
        original_owner: crate::bootstrap::storage_owner(f.initiator.device(role)),
        original_credential: f.initiator.device(role).credential_digest(),
        previous_credential: g.previous_device().credential_digest(),
        previous_roster: g.previous_device().roster().checkpoint(),
        original_policy: p0.checkpoint(),
        previous_policy: prior.checkpoint(),
        previous_authorization: previous.map(VerifiedPolicyContinuation::statement_digest),
    };
    let m = PolicyContinuationMaterials {
        original: p0,
        previous: prior,
        target,
        credential: g,
    };
    let statement =
        PolicyContinuationStatement::new(&scope, &m, 170).expect("same exact continuation");
    let a = root(role)
        .approve_policy_continuation(&statement)
        .expect("account approval");
    let p = issuer
        .approve_policy_continuation(&statement)
        .expect("independent policy approval");
    VerifiedPolicyContinuation::verify(&a, &p, &scope, &m, 170).expect("complete T")
}
fn request(l: &Local, role: BootstrapRole, session: [u8; 32]) -> SessionReopenRequest {
    l.f.bundle
        .request_historical_reopen(
            Arc::new(l.f.initiator.original_policy().clone()),
            l.f.bundle_requirements(PrekeyQuality::OneTimeBoth),
            role,
            session,
            170,
        )
        .expect("authenticated history without a runtime")
}
fn commit(
    j: &mut DeviceJournal,
    original: &VerifiedDevice,
    p0: &crate::HistoricalSessionPolicy,
    target: &crate::VerifiedSessionPolicy,
    g: &VerifiedCredentialRenewal,
    t: &VerifiedPolicyContinuation,
    ack: bool,
) {
    let authority = crate::RetainedInstallationAuthority::active_installation(original, p0);
    let h = t.historical();
    let receipt = j
        .commit_local_renewal(
            &authority,
            &LocalRenewalTarget {
                policy_renewal: None,
                grant: g,
                continuation: Some(&h),
            },
            target,
            170,
        )
        .expect("atomic G/T/receipt");
    if ack {
        // This component fixture supplies the already-tested coordinator's
        // completion acknowledgement; it does not claim to exercise enrollment.
        j.acknowledge_local_credential_renewal(&authority, &receipt)
            .expect("completion acknowledged");
    }
}
#[test]
fn continued_original_session_recovers_old_ciphertext_and_exchanges_new_data_after_p0_expiry() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let mut l = Local::with_fixture(short_fixture(), role);
        let peer_role = other(role);
        let local_policy = policy(&l.f, role, 2, 190, 170);
        let peer_policy = policy(&l.f, peer_role, 2, 190, 170);
        let local_grant = grant(&l.f, role, None, 2, 185);
        let peer_grant = grant(&l.f, peer_role, None, 2, 185);
        let p0 = l.f.policy_owner(role);
        let peer_p0 = l.f.policy_owner(peer_role);
        let original = l.f.initiator.device(role);
        let peer_original = l.f.initiator.device(peer_role);
        let authority = crate::RetainedInstallationAuthority::active_installation(
            peer_original,
            peer_p0.as_ref(),
        );
        let original_wire = l
            .service
            .stores()
            .expect("stores")
            .0
            .resume_message(&l.f.initiator, l.session, l.original_id, 150)
            .expect("original cached ciphertext");
        l.service
            .admit_peer_credential_renewal(&peer_grant, peer_grant.operation(), &p0, 150)
            .expect("independent peer grant before joint policy commit");
        l.peer
            .install_peer_credential_renewal(
                &crate::installation::PolicyScope {
                    authority: &authority,
                    original_policy: peer_p0.historical(),
                    original_device: peer_original,
                },
                &local_grant,
                local_grant.operation(),
                &peer_p0,
                150,
            )
            .expect("independent local grant at peer");
        let local_journal = l
            .service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("original journal");
        let peer_journal = l.peer.identity().expect("peer journal");
        let local_t = joint(
            &l.f,
            role,
            local_journal,
            &local_grant,
            None,
            p0.historical(),
            &local_policy,
        );
        let peer_t = joint(
            &l.f,
            peer_role,
            peer_journal,
            &peer_grant,
            None,
            peer_p0.historical(),
            &peer_policy,
        );
        let before = l.service.stores().expect("stores").0.test_snapshot();
        let historical = request(&l, role, l.session);
        assert!(
            l.service
                .reopen_continued_peer(historical, Arc::clone(&local_policy), 170)
                .is_err(),
            "P1 alone cannot authorize retained state"
        );
        commit(
            l.service.stores().expect("stores").0,
            original,
            p0.historical(),
            &local_policy,
            &local_grant,
            &local_t,
            false,
        );
        let historical = request(&l, role, l.session);
        assert!(
            matches!(
                l.service
                    .reopen_continued_peer(historical, Arc::clone(&local_policy), 170),
                Err(DurableError::Suspended)
            ),
            "journal receipt must be confirmed first"
        );
        commit(
            l.service.stores().expect("stores").0,
            original,
            p0.historical(),
            &local_policy,
            &local_grant,
            &local_t,
            true,
        );
        commit(
            &mut l.peer,
            peer_original,
            peer_p0.historical(),
            &peer_policy,
            &peer_grant,
            &peer_t,
            true,
        );
        let exact = l.service.stores().expect("stores").0.test_snapshot();
        assert!(l
            .service
            .reopen_continued_peer(request(&l, role, [211; 32]), Arc::clone(&local_policy), 170)
            .is_err());
        assert!(l
            .service
            .reopen_continued_peer(
                request(&l, peer_role, l.session),
                Arc::clone(&local_policy),
                170
            )
            .is_err());
        let unrelated = policy(&l.f, role, 3, 195, 170);
        assert!(l
            .service
            .reopen_continued_peer(request(&l, role, l.session), unrelated, 170)
            .is_err());
        assert!(
            l.service
                .reopen_peer(request(&l, role, l.session), 170)
                .is_err(),
            "historical request still has no self-selected runtime"
        );
        let unchanged = l.service.stores().expect("stores").0.test_snapshot();
        assert_eq!(
            (unchanged.revision, unchanged.digest),
            (exact.revision, exact.digest)
        );
        let restored = l
            .service
            .reopen_continued_peer(request(&l, role, l.session), Arc::clone(&local_policy), 170)
            .expect("current P1 through exact original journal");
        let context = Arc::clone(restored.context());
        assert_eq!(context.digest(), l.f.initiator.digest());
        assert_eq!(context.original_policy().checkpoint(), p0.checkpoint());
        assert_eq!(
            context.current_policy().expect("actual P1").checkpoint(),
            local_policy.checkpoint()
        );
        assert_eq!(
            context.continued_policy_statement(),
            Some(local_t.statement_digest())
        );
        assert!(
            crate::InitiatorOperation::start(Arc::clone(&context), &l.f.signer_i, 150).is_err(),
            "continued context cannot bootstrap"
        );
        assert!(l
            .service
            .admit_peer(Arc::clone(&context), role, 170)
            .is_err());
        let peer_context = l
            .peer
            .prepare_continued_context(
                request(&l, peer_role, l.session).context,
                l.session,
                peer_role,
                Arc::clone(&peer_policy),
                170,
            )
            .expect("independently admitted other endpoint");
        let j = l.service.stores().expect("stores").0;
        assert_eq!(
            j.resume_message(&context, l.session, l.original_id, 170)
                .expect("same original output"),
            original_wire
        );
        let received = l
            .peer
            .receive_message(&peer_context, l.session, &original_wire, b"recovery", 170)
            .expect("real peer decrypts original message");
        assert_eq!(received.as_bytes(), b"unconfirmed original");
        let id = j
            .next_message_id(&context, l.session, 170)
            .expect("next original chain slot");
        let wire = j
            .send_message(
                &context,
                l.session,
                id,
                b"after both original expiries",
                b"continued",
                170,
            )
            .expect("current P1 durable send");
        let received = l
            .peer
            .receive_message(&peer_context, l.session, &wire, b"continued", 170)
            .expect("actual peer decryption");
        assert_eq!(received.as_bytes(), b"after both original expiries");
        let after = j.test_snapshot();
        assert_eq!((after.id, after.owner), (before.id, before.owner));
        assert!(
            j.next_message_id(&l.f.initiator, l.session, 150).is_err(),
            "cached P0 cannot return at an earlier time"
        );
        l.service.close();
        let recovered = DeviceInstallation::reopen_continued_session(
            paths(&l.root),
            key(&l.root),
            request(&l, role, l.session),
            Arc::clone(&local_policy),
            175,
            None,
        )
        .expect("original installation and archive reopened");
        let (mut service, ctx) = recovered.into_parts();
        assert_eq!(
            service
                .stores()
                .expect("same stores")
                .0
                .resume_message(&ctx, l.session, id, 175)
                .expect("same post-reopen output"),
            wire
        );
        let before_rekey = service
            .stores()
            .expect("stores")
            .0
            .rekey_progress(&ctx, l.session)
            .expect("original epoch state");
        let offer = if role == BootstrapRole::Initiator {
            Some(
                service
                    .stores()
                    .expect("stores")
                    .0
                    .prepare_rekey_offer(&ctx, l.session, &l.f.signer_i, 175)
                    .expect("real retained rekey offer under P1"),
            )
        } else {
            None
        };
        let before_transition = service
            .stores()
            .expect("stores")
            .0
            .rekey_progress(&ctx, l.session)
            .expect("pending rekey identity");
        let p2 = policy(&l.f, role, 3, 195, 175);
        let g2 = grant(&l.f, role, Some(local_grant.successor_device()), 3, 190);
        let t2 = joint(
            &l.f,
            role,
            local_journal,
            &g2,
            Some(&local_t),
            local_policy.historical(),
            &p2,
        );
        commit(
            service.stores().expect("stores").0,
            original,
            p0.historical(),
            &p2,
            &g2,
            &t2,
            true,
        );
        local_policy
            .check_mode(PrekeyQuality::OneTimeBoth, 175)
            .expect("P1 still live; failure must observe durable change");
        let j = service.stores().expect("stores").0;
        assert!(
            j.next_message_id(&ctx, l.session, 175).is_err(),
            "stale T1 cannot reserve output"
        );
        assert!(
            j.resume_message(&ctx, l.session, id, 175).is_err(),
            "stale T1 cannot replay cached ciphertext"
        );
        assert!(
            j.message_acknowledgement(&ctx, l.session, 175).is_err(),
            "stale T1 cannot release an ACK"
        );
        if offer.is_some() {
            assert!(
                j.prepare_rekey_offer(&ctx, l.session, &l.f.signer_i, 175)
                    .is_err(),
                "stale T1 cannot replay cached offer"
            );
            assert!(j
                .rekey_outbox(&ctx, l.session, 1, crate::RekeyFlight::Offer, 175)
                .is_err());
        }
        let fresh = service
            .reopen_continued_peer(request(&l, role, l.session), Arc::clone(&p2), 175)
            .expect("T2 current view of original session");
        let fresh = Arc::clone(fresh.context());
        assert_eq!(fresh.digest(), ctx.digest());
        let j = service.stores().expect("stores").0;
        assert_eq!(
            j.rekey_progress(&fresh, l.session)
                .expect("exact retained epoch state"),
            before_transition
        );
        assert_eq!(
            before_transition.confirmed_epoch,
            before_rekey.confirmed_epoch
        );
        assert_eq!(
            j.resume_message(&fresh, l.session, id, 175)
                .expect("original ciphertext under T2"),
            wire
        );
        if let Some(offer) = offer {
            assert_eq!(
                j.prepare_rekey_offer(&fresh, l.session, &l.f.signer_i, 175)
                    .expect("same reserved contribution, not new randomness"),
                offer
            );
            assert_eq!(
                j.rekey_outbox(&fresh, l.session, 1, crate::RekeyFlight::Offer, 175)
                    .expect("same cached flight"),
                offer
            );
        }
        let batch = j.next_fanout_id().expect("aggregate ID");
        let targets = [crate::FanoutTarget {
            context: &fresh,
            session: l.session,
        }];
        let group = j
            .send_account_message(
                crate::FanoutInput {
                    id: batch,
                    account: peer_original.account_id(),
                    targets: &targets,
                    plaintext: b"continued account message",
                    associated_data: b"group",
                },
                175,
            )
            .expect("current continued identities match complete roster");
        assert_eq!(group.len(), 1);
        assert!(
            j.resume_account_message(
                batch,
                &[crate::FanoutTarget {
                    context: &ctx,
                    session: l.session
                }],
                175
            )
            .is_err(),
            "old T cannot release an aggregate member"
        );
        let replay = j
            .resume_account_message(batch, &targets, 175)
            .expect("exact original batch");
        assert_eq!(replay.len(), group.len());
        let original_member = group.first().expect("one member");
        let replay_member = replay.first().expect("one replay member");
        assert_eq!(
            (
                replay_member.device,
                replay_member.session,
                replay_member.message
            ),
            (
                original_member.device,
                original_member.session,
                original_member.message
            )
        );
        let expected = match &original_member.output {
            crate::FanoutOutput::Committed(bytes) => Some(bytes),
            _ => None,
        }
        .expect("committed member");
        let actual = match &replay_member.output {
            crate::FanoutOutput::Committed(bytes) => Some(bytes),
            _ => None,
        }
        .expect("committed replay");
        assert_eq!(actual, expected);
        p2.close();
        assert!(
            j.resume_message(&fresh, l.session, id, 175).is_err(),
            "closing actual P2 withholds cached output"
        );
        assert!(
            j.resume_account_message(batch, &targets, 175).is_err(),
            "closing current P2 withholds aggregate output"
        );
        let independently_reopened_policy = policy(&l.f, role, 3, 195, 175);
        let second_view = service
            .reopen_continued_peer(
                request(&l, role, l.session),
                independently_reopened_policy,
                175,
            )
            .expect("independently verified current owner before closure");
        let second_view = Arc::clone(second_view.context());
        let j = service.stores().expect("stores").0;
        // Cleanup needs the original structural scope, even though this cached
        // policy owner is closed. It does not make that owner operational again.
        let report = j
            .begin_session_closure(&fresh, l.session)
            .expect("explicit loss accounting with a closed policy owner");
        let current_targets = [crate::FanoutTarget {
            context: &second_view,
            session: l.session,
        }];
        let waiting = j
            .resume_account_message(batch, &current_targets, 175)
            .expect("current aggregate view observes closing member");
        assert!(matches!(
            waiting.first().expect("member").output,
            crate::FanoutOutput::ResolutionPending
        ));
        j.acknowledge_session_closure(&fresh, l.session, report.report)
            .expect("host records unknown outcome");
        let terminal = j
            .resume_account_message(batch, &current_targets, 175)
            .expect("closed member never recreates output");
        assert!(matches!(
            terminal.first().expect("member").output,
            crate::FanoutOutput::DeliveryUnknown
        ));
        let seed = if peer_role == BootstrapRole::Initiator {
            90
        } else {
            94
        };
        let revoked =
            crate::durable::tests::renewal_roster(peer_grant.successor_device(), seed, 3, false);
        j.install_roster(&revoked, 175)
            .expect("independent current peer revocation");
        assert!(
            j.resume_account_message(batch, &current_targets, 175)
                .is_err(),
            "terminal members do not bypass current aggregate authority"
        );
        j.retire_fanout(
            batch,
            &[crate::FanoutTarget {
                context: &l.f.initiator,
                session: l.session,
            }],
        )
        .expect("original C0 context retires authenticated C1 batch without cached C1 authority");
        assert_eq!(
            j.fanout_status(batch).expect("exact retired aggregate"),
            crate::FanoutStatus::Retired
        );
        eprintln!("CONTINUED_SESSION role={role:?} old_wire_preserved=true peer_decrypted=true stale_t_refused=true pending_rekey_preserved=true fanout_current_credential=true closed_member_terminal=true original_context_cleanup=true");
    }
}

#[test]
fn continued_peer_renewal_requires_current_local_policy_even_while_p0_is_live() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let mut l = Local::with_role(false, role);
        let p0 = l.f.policy_owner(role);
        let p1 = policy(&l.f, role, 2, 250, 170);
        let g = grant(&l.f, role, None, 2, 240);
        let j = l.service.stores().expect("original stores").0;
        let t = joint(
            &l.f,
            role,
            j.identity().expect("original journal"),
            &g,
            None,
            p0.historical(),
            &p1,
        );
        commit(
            j,
            l.f.initiator.device(role),
            p0.historical(),
            &p1,
            &g,
            &t,
            false,
        );
        let peer = grant(&l.f, other(role), None, 2, 240);
        let pending = l
            .service
            .stores()
            .expect("pending stores")
            .0
            .test_snapshot();
        assert!(
            matches!(
                l.service
                    .admit_peer_credential_renewal(&peer, peer.operation(), &p1, 170),
                Err(DurableError::Suspended)
            ),
            "P1 cannot authorize peer mutation before local completion ACK"
        );
        let still_pending = l
            .service
            .stores()
            .expect("pending stores")
            .0
            .test_snapshot();
        assert_eq!(
            (pending.revision, pending.digest),
            (still_pending.revision, still_pending.digest)
        );
        commit(
            l.service.stores().expect("original stores").0,
            l.f.initiator.device(role),
            p0.historical(),
            &p1,
            &g,
            &t,
            true,
        );
        p0.check_mode(PrekeyQuality::OneTimeBoth, 170)
            .expect("old P0 is genuinely still live");
        let before = l.service.stores().expect("stores").0.test_snapshot();
        assert!(
            l.service
                .admit_peer_credential_renewal(&peer, peer.operation(), &p0, 170)
                .is_err(),
            "adopted T requires current P1 for peer mutation; live P0 is stale authority"
        );
        let after = l.service.stores().expect("stores").0.test_snapshot();
        assert_eq!(
            (after.id, after.owner, after.revision, after.digest),
            (before.id, before.owner, before.revision, before.digest)
        );
        assert_eq!(
            l.service
                .admit_peer_credential_renewal(&peer, peer.operation(), &p1, 170)
                .expect("current P1 admits independently approved peer G"),
            peer.successor_device().roster().checkpoint()
        );
        let p2 = policy(&l.f, role, 3, 270, 170);
        let g2 = grant(&l.f, role, Some(g.successor_device()), 3, 260);
        let t2 = joint(
            &l.f,
            role,
            l.service
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("original journal"),
            &g2,
            Some(&t),
            p1.historical(),
            &p2,
        );
        commit(
            l.service.stores().expect("stores").0,
            l.f.initiator.device(role),
            p0.historical(),
            &p2,
            &g2,
            &t2,
            true,
        );
        p1.check_mode(PrekeyQuality::OneTimeBoth, 170)
            .expect("old P1 still live after T2");
        let current = l.service.stores().expect("stores").0.test_snapshot();
        assert!(
            l.service
                .admit_peer_credential_renewal(&peer, peer.operation(), &p1, 170)
                .is_err(),
            "old P1 cannot retry even an already committed peer G after T2"
        );
        assert_eq!(
            l.service
                .admit_peer_credential_renewal(&peer, peer.operation(), &p2, 170)
                .expect("current P2 permits the original peer retry"),
            peer.successor_device().roster().checkpoint()
        );
        let retried = l.service.stores().expect("stores").0.test_snapshot();
        assert_eq!(
            (current.revision, current.digest),
            (retried.revision, retried.digest)
        );
        let issuer = root(other(role));
        let revoked = issuer
            .issue_roster(
                3,
                Validity::new(100, 200).expect("revocation interval"),
                &[],
            )
            .expect("peer account revocation");
        let pin = AccountPin::new(
            issuer.account_id().expect("peer account"),
            issuer.public_key().expect("peer root"),
            revoked.checkpoint(),
            p0.family(),
        )
        .expect("independent revocation checkpoint");
        let revoked = pin
            .verify_roster(revoked.as_bytes(), 170)
            .expect("authenticated peer revocation");
        l.service
            .stores()
            .expect("stores")
            .0
            .install_roster(&revoked, 170)
            .expect("observe peer revocation");
        let revoked_state = l.service.stores().expect("stores").0.test_snapshot();
        assert!(
            l.service
                .admit_peer_credential_renewal(&peer, peer.operation(), &p2, 170)
                .is_err(),
            "current local P2 cannot undo observed peer revocation"
        );
        let refused = l.service.stores().expect("stores").0.test_snapshot();
        assert_eq!(
            (revoked_state.revision, revoked_state.digest),
            (refused.revision, refused.digest)
        );
    }
}
