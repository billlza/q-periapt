// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-transaction admission and retirement at the durable witness boundary.
use super::*;

fn cancellation(
    c: &Case,
    grant: &VerifiedCredentialRenewal,
) -> crate::AnchorCredentialRenewalCancellation {
    let mut bytes = b"QPCRNC01".to_vec();
    bytes.extend_from_slice(&c.pin.binding());
    bytes.extend_from_slice(&c.subject.to_bytes());
    bytes.extend_from_slice(grant.operation().as_bytes());
    bytes.extend_from_slice(&grant.statement_digest());
    c.initial.encode(&mut bytes);
    crate::AnchorCredentialRenewalCancellation::from_trusted_state(&bytes)
        .expect("grant-only closure expectation")
}

#[test]
fn unprepared_grant_closure_and_roster_share_retirement_floor() {
    let mut c = Case::new();
    let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
    let next = same_credential_roster(&c, &c.device, 2);
    let rp = r_proposal(&c, &c.device, &next, &current, c.initial);
    assert_eq!(
        c.store
            .close_roster_refresh(rp, &c.device, &next, current.historical())
            .expect("close R2"),
        State::Closed
    );
    r_exchange(
        &mut c,
        &rp,
        AnchorOperation::acknowledge_roster_refresh(&rp),
    );
    let reused = grant(&c, &c.device, 2);
    let reused_cancel = cancellation(&c, &reused);
    let before = c.fingerprint();
    assert!(matches!(
        c.store
            .close_unprepared_credential_renewal(reused_cancel, &reused, &current),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert_eq!(c.fingerprint(), before);
    let g = grant(&c, &c.device, 3);
    let cancel = cancellation(&c, &g);
    assert_eq!(
        c.store
            .close_unprepared_credential_renewal(cancel, &g, &current)
            .expect("close G3"),
        crate::AnchorCredentialCancellationState::Closed
    );
    c.reopen();
    explicit_format(&mut c, b"QPANC020");
    let before = c.fingerprint();
    assert_eq!(
        c.store
            .close_unprepared_credential_renewal(cancel, &g, &current)
            .expect("same close"),
        crate::AnchorCredentialCancellationState::Closed
    );
    assert_eq!(c.fingerprint(), before);
    let next = same_credential_roster(&c, &c.device, 3);
    let rp = r_proposal(&c, &c.device, &next, &current, c.initial);
    assert!(
        matches!(
            c.store
                .prepare_roster_refresh(rp, &c.device, &next, &current, 150),
            Err(DurableError::Conflict)
        ),
        "grant-only closure needs its own ACK"
    );
    assert_eq!(c.fingerprint(), before);
    let request = AnchorRequest::new(
        &c.pin,
        c.subject,
        AnchorOperation::acknowledge_credential_cancellation(&cancel),
        &c.signer,
    )
    .expect("cancel ACK");
    let wire = c.store.handle(request.as_bytes(), 150).expect("witness");
    assert_eq!(
        c.pin
            .verify_reply(&request, &wire)
            .expect("fresh signature")
            .credential_cancellation_state(&cancel)
            .expect("exact cancellation"),
        crate::AnchorCredentialCancellationState::Acknowledged
    );
    c.reopen();
    let before = c.fingerprint();
    assert!(matches!(
        c.store
            .prepare_roster_refresh(rp, &c.device, &next, &current, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert_eq!(c.fingerprint(), before);
    let next = same_credential_roster(&c, &c.device, 4);
    let rp = r_proposal(&c, &c.device, &next, &current, c.initial);
    c.store
        .prepare_roster_refresh(rp, &c.device, &next, &current, 150)
        .expect("fresh R4");
}

#[test]
fn pending_roster_blocks_credential_until_ack_and_closed_version_stays_retired() {
    for applied in [false, true] {
        let mut c = Case::new();
        let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
        let next = same_credential_roster(&c, &c.device, 2);
        let rp = r_proposal(&c, &c.device, &next, &current, c.initial);
        c.store
            .prepare_roster_refresh(rp, &c.device, &next, &current, 150)
            .expect("prepared R");
        let previous = if applied { &next } else { &c.device };
        let g = grant(&c, previous, 3);
        let head = if applied { rp.target_head() } else { c.initial };
        let gp = g_proposal(&c, &g, head);
        let before = c.fingerprint();
        assert!(matches!(
            c.store.prepare_credential_renewal(gp, &g, &current, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(c.fingerprint(), before);
        let terminal = if applied {
            State::Applied
        } else {
            State::Closed
        };
        let op = if applied {
            AnchorOperation::commit_roster_refresh(&rp)
        } else {
            AnchorOperation::close_roster_refresh(&rp)
        };
        assert_eq!(r_exchange(&mut c, &rp, op), terminal);
        c.reopen();
        let before = c.fingerprint();
        assert!(matches!(
            c.store.prepare_credential_renewal(gp, &g, &current, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(c.fingerprint(), before, "terminal still requires ACK");
        assert_eq!(
            r_exchange_at(
                &mut c,
                &rp,
                AnchorOperation::roster_refresh_status(&rp),
                150
            ),
            terminal
        );
        assert_eq!(
            r_exchange_at(
                &mut c,
                &rp,
                AnchorOperation::acknowledge_roster_refresh(&rp),
                150
            ),
            State::Acknowledged
        );
        c.reopen();
        if !applied {
            let reused = grant(&c, &c.device, 2);
            let p = g_proposal(&c, &reused, c.initial);
            let before = c.fingerprint();
            assert!(matches!(
                c.store
                    .prepare_credential_renewal(p, &reused, &current, 150),
                Err(DurableError::Protocol(Error::Retired))
            ));
            assert_eq!(c.fingerprint(), before);
        }
        assert_eq!(
            c.store
                .prepare_credential_renewal(gp, &g, &current, 150)
                .expect("fresh G"),
            GState::Prepared
        );
        explicit_format(&mut c, b"QPANC020");
    }
}

#[test]
fn pending_credential_blocks_roster_until_ack_and_closed_version_stays_retired() {
    for applied in [false, true] {
        let mut c = Case::new();
        let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
        let g = grant(&c, &c.device, 2);
        let gp = g_proposal(&c, &g, c.initial);
        c.store
            .prepare_credential_renewal(gp, &g, &current, 150)
            .expect("prepared G");
        let previous = if applied {
            g.successor_device().clone()
        } else {
            c.device.clone()
        };
        let next = same_credential_roster(&c, &previous, 3);
        let head = if applied { gp.target_head() } else { c.initial };
        let rp = r_proposal(&c, &previous, &next, &current, head);
        let before = c.fingerprint();
        assert!(matches!(
            c.store
                .prepare_roster_refresh(rp, &previous, &next, &current, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(c.fingerprint(), before);
        let terminal = if applied {
            GState::Applied
        } else {
            GState::Closed
        };
        let op = if applied {
            AnchorOperation::commit_credential_renewal(&gp)
        } else {
            AnchorOperation::close_credential_renewal(&gp)
        };
        assert_eq!(g_exchange(&mut c, &gp, op), terminal);
        c.reopen();
        let before = c.fingerprint();
        assert!(matches!(
            c.store
                .prepare_roster_refresh(rp, &previous, &next, &current, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(c.fingerprint(), before, "terminal still requires ACK");
        assert_eq!(
            g_exchange_at(
                &mut c,
                &gp,
                AnchorOperation::credential_renewal_status(&gp),
                150
            ),
            terminal
        );
        assert_eq!(
            g_exchange_at(
                &mut c,
                &gp,
                AnchorOperation::acknowledge_credential_renewal(&gp),
                150
            ),
            GState::Acknowledged
        );
        c.reopen();
        if !applied {
            let reused = same_credential_roster(&c, &c.device, 2);
            let p = r_proposal(&c, &c.device, &reused, &current, c.initial);
            let before = c.fingerprint();
            assert!(matches!(
                c.store
                    .prepare_roster_refresh(p, &c.device, &reused, &current, 150),
                Err(DurableError::Protocol(Error::Retired))
            ));
            assert_eq!(c.fingerprint(), before);
        }
        assert_eq!(
            c.store
                .prepare_roster_refresh(rp, &previous, &next, &current, 150)
                .expect("fresh R"),
            State::Prepared
        );
        explicit_format(&mut c, b"QPANC020");
    }
}

#[test]
fn expired_composition_only_retains_history_or_closes_without_activation() {
    for applied in [false, true] {
        let mut c = Case::new();
        let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
        let g = grant(&c, &c.device, 2);
        let gp = g_proposal(&c, &g, c.initial);
        c.store
            .prepare_credential_renewal(gp, &g, &current, 150)
            .expect("G");
        g_exchange(&mut c, &gp, AnchorOperation::commit_credential_renewal(&gp));
        g_exchange(
            &mut c,
            &gp,
            AnchorOperation::acknowledge_credential_renewal(&gp),
        );
        let next = same_credential_roster(&c, g.successor_device(), 3);
        let rp = r_proposal(&c, g.successor_device(), &next, &current, gp.target_head());
        c.store
            .prepare_roster_refresh(rp, g.successor_device(), &next, &current, 150)
            .expect("R");
        if applied {
            assert_eq!(
                r_exchange(&mut c, &rp, AnchorOperation::commit_roster_refresh(&rp)),
                State::Applied
            );
        }
        c.reopen();
        let before = c.fingerprint();
        let request = AnchorRequest::new(
            &c.pin,
            c.subject,
            AnchorOperation::commit_roster_refresh(&rp),
            &c.signer,
        )
        .expect("attempt expired commit");
        let result = c.store.handle(request.as_bytes(), 700);
        if applied {
            let reply = c
                .pin
                .verify_reply(&request, &result.expect("historical reply"))
                .expect("fresh signature");
            assert_eq!(
                reply.roster_refresh_state(&rp).expect("R state"),
                State::Applied
            );
        } else {
            assert!(matches!(
                result,
                Err(AnchorError::Rejected(Error::Validity))
            ));
        }
        assert_eq!(c.fingerprint(), before);
        let terminal = if applied {
            State::Applied
        } else {
            State::Closed
        };
        assert_eq!(
            r_exchange_at(&mut c, &rp, AnchorOperation::close_roster_refresh(&rp), 700),
            terminal
        );
        assert_eq!(
            r_exchange_at(
                &mut c,
                &rp,
                AnchorOperation::acknowledge_roster_refresh(&rp),
                700
            ),
            State::Acknowledged
        );
        c.reopen();
        let authority = if applied { &next } else { g.successor_device() };
        let command = AnchorOperation::admit_authority(authority.authority_binding())
            .expect("exact current authority");
        assert_eq!(c.admission(command, 700), AnchorOutcome::AuthorityDenied);
        explicit_format(&mut c, b"QPANC020");
    }
}

#[test]
fn alternating_cycles_keep_actual_predecessor_and_reject_old_credential() {
    let mut c = Case::new();
    let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
    let mut previous = c.device.clone();
    let mut head = c.initial;
    for version in [2, 4, 6] {
        let g = grant(&c, &previous, version);
        let gp = g_proposal(&c, &g, head);
        c.store
            .prepare_credential_renewal(gp, &g, &current, 150)
            .expect("G");
        assert_eq!(
            g_exchange(&mut c, &gp, AnchorOperation::commit_credential_renewal(&gp)),
            GState::Applied
        );
        g_exchange(
            &mut c,
            &gp,
            AnchorOperation::acknowledge_credential_renewal(&gp),
        );
        c.reopen();
        let next = same_credential_roster(&c, g.successor_device(), version + 1);
        let rp = r_proposal(&c, g.successor_device(), &next, &current, gp.target_head());
        let stale = same_credential_roster(&c, &c.device, version + 1);
        let before = c.fingerprint();
        assert!(matches!(
            c.store
                .prepare_roster_refresh(rp, g.successor_device(), &stale, &current, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert_eq!(
            c.fingerprint(),
            before,
            "same-key C0 cannot replace current Cn"
        );
        c.store
            .prepare_roster_refresh(rp, g.successor_device(), &next, &current, 150)
            .expect("current credential refresh");
        assert_eq!(
            r_exchange(&mut c, &rp, AnchorOperation::commit_roster_refresh(&rp)),
            State::Applied
        );
        r_exchange(
            &mut c,
            &rp,
            AnchorOperation::acknowledge_roster_refresh(&rp),
        );
        c.reopen();
        explicit_format(&mut c, b"QPANC020");
        let stale_grant = grant(&c, g.successor_device(), version + 2);
        let stale_proposal = g_proposal(&c, &stale_grant, rp.target_head());
        let before = c.fingerprint();
        assert!(matches!(
            c.store
                .prepare_credential_renewal(stale_proposal, &stale_grant, &current, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(c.fingerprint(), before, "G cannot skip the intervening R");
        previous = next;
        head = rp.target_head();
    }
}
