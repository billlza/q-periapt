// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real witness persistence/signatures with explicit component-only head digests.
//! Enrollment/journal sealing must be qualified separately.
use super::*;
use crate::anchor::store::policy_renewal::tests::{credential_cycle::grant, policy, Case};
use crate::{
    AccountPin, AnchorCredentialRenewalProposal as GProposal,
    AnchorCredentialRenewalState as GState, RosterRefreshId, RosterRefreshScope,
    VerifiedCredentialRenewal,
};

fn same_credential_roster(c: &Case, previous: &VerifiedDevice, version: u64) -> VerifiedDevice {
    let certificate = c
        .account
        .issue_device(previous.description.clone(), previous.key.clone())
        .expect("same root-authorized credential");
    let roster = c
        .account
        .issue_roster(
            version,
            Validity::new(100, 600).expect("roster interval"),
            &[c.account.roster_entry(&certificate).expect("entry")],
        )
        .expect("signed roster");
    let pin = AccountPin::new(
        previous.account_id(),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        c.original.family(),
    )
    .expect("target pin");
    pin.verify_device(&certificate, roster.as_bytes(), 150)
        .expect("independently verified target")
}

fn g_proposal(c: &Case, grant: &VerifiedCredentialRenewal, head: AnchorHead) -> GProposal {
    GProposal::from_journal(
        c.pin.binding(),
        c.subject,
        grant.operation(),
        grant.statement_digest(),
        head,
        AnchorHead::from_trusted_state(head.fence(), head.revision() + 1, [91; 32])
            .expect("explicit component target"),
    )
    .expect("G proposal")
}

fn r_proposal(
    c: &Case,
    previous: &VerifiedDevice,
    next: &VerifiedDevice,
    current: &VerifiedSessionPolicy,
    head: AnchorHead,
) -> Proposal {
    r_policy_proposal(c, previous, next, current, head, None)
}
fn r_policy_proposal(
    c: &Case,
    previous: &VerifiedDevice,
    next: &VerifiedDevice,
    current: &VerifiedSessionPolicy,
    head: AnchorHead,
    authorization: Option<[u8; 32]>,
) -> Proposal {
    Proposal::from_journal(
        c.pin.binding(),
        c.subject,
        RosterRefreshScope {
            operation: RosterRefreshId::generate().expect("R operation"),
            previous: previous.roster().checkpoint(),
            target: next.roster().checkpoint(),
            policy: current.checkpoint(),
            policy_authorization: authorization,
        },
        head,
        AnchorHead::from_trusted_state(head.fence(), head.revision() + 1, [92; 32])
            .expect("explicit component target"),
    )
    .expect("R proposal")
}

fn g_exchange(c: &mut Case, p: &GProposal, op: AnchorOperation) -> GState {
    g_exchange_at(c, p, op, 150)
}
fn g_exchange_at(c: &mut Case, p: &GProposal, op: AnchorOperation, now: u64) -> GState {
    let request = AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("signed G request");
    let wire = c.store.handle(request.as_bytes(), now).expect("witness");
    c.pin
        .verify_reply(&request, &wire)
        .expect("fresh witness reply")
        .credential_renewal_state(p)
        .expect("original G outcome")
}

fn r_exchange(c: &mut Case, p: &Proposal, op: AnchorOperation) -> State {
    r_exchange_at(c, p, op, 150)
}
fn r_exchange_at(c: &mut Case, p: &Proposal, op: AnchorOperation, now: u64) -> State {
    let request = AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("signed R request");
    let wire = c.store.handle(request.as_bytes(), now).expect("witness");
    c.pin
        .verify_reply(&request, &wire)
        .expect("fresh witness reply")
        .roster_refresh_state(p)
        .expect("original R outcome")
}

fn explicit_format(c: &mut Case, tag: &[u8; 8]) {
    let image = c.store.image().expect("authenticated image");
    let key = &c.store.active.as_ref().expect("active witness").wrapping;
    let bytes = super::super::encode(key, &c.pin, &image).expect("encode");
    assert_eq!(&bytes[..8], tag);
    super::super::decode(key, &c.pin, &bytes).expect("roundtrip");
    if tag == b"QPANC020" {
        let mut old = bytes[..bytes.len() - 32].to_vec();
        old[..8].copy_from_slice(b"QPANC019");
        let mut mac = super::super::authenticator(key).expect("owned authenticator");
        mac.update(&old);
        old.extend_from_slice(&mac.finalize().into_bytes());
        assert!(matches!(
            super::super::decode(key, &c.pin, &old),
            Err(DurableError::Conflict)
        ));
    }
}

fn preserve_failure<T>(
    mut case: Case,
    result: Result<T, DurableError>,
) -> Result<(Case, T), DurableError> {
    match result {
        Ok(value) => Ok((case, value)),
        Err(error) => {
            case.store.close();
            let path = case._dir.keep();
            eprintln!(
                "Retained original witness component fixture: {}",
                path.display()
            );
            Err(error)
        }
    }
}

#[test]
fn credential_then_roster_keeps_current_credential_and_original_subject() -> Result<(), DurableError>
{
    let mut c = Case::new();
    let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
    let g = grant(&c, &c.device, 2);
    let gp = g_proposal(&c, &g, c.initial);
    assert_eq!(
        c.store
            .prepare_credential_renewal(gp, &g, &current, 150)?,
        GState::Prepared
    );
    assert_eq!(
        g_exchange(&mut c, &gp, AnchorOperation::commit_credential_renewal(&gp)),
        GState::Applied
    );
    assert_eq!(
        g_exchange(
            &mut c,
            &gp,
            AnchorOperation::acknowledge_credential_renewal(&gp)
        ),
        GState::Acknowledged
    );
    c.reopen();
    let next = same_credential_roster(&c, g.successor_device(), 3);
    let rp = r_proposal(&c, g.successor_device(), &next, &current, gp.target_head());
    let before = c.fingerprint();
    let result = c
        .store
        .prepare_roster_refresh(rp, g.successor_device(), &next, &current, 150);
    if result.is_err() {
        assert_eq!(c.fingerprint(), before);
    }
    let (mut c, prepared) = preserve_failure(c, result)?;
    assert_eq!(prepared, State::Prepared);
    explicit_format(&mut c, b"QPANC020");
    c.reopen();
    assert_eq!(
        r_exchange(&mut c, &rp, AnchorOperation::commit_roster_refresh(&rp)),
        State::Applied
    );
    assert_eq!(
        r_exchange(
            &mut c,
            &rp,
            AnchorOperation::acknowledge_roster_refresh(&rp)
        ),
        State::Acknowledged
    );
    c.reopen();
    explicit_format(&mut c, b"QPANC020");
    let image = c.store.image()?;
    let entry = image
        .entries
        .get(&c.subject.id(&c.pin.binding()))
        .expect("original subject");
    assert_eq!(entry.credential_owner, storage_owner(g.successor_device()));
    assert_eq!(entry.authority, next.authority_binding());
    assert_eq!(entry.head, rp.target_head());
    Ok(())
}

#[test]
fn roster_then_credential_uses_actual_predecessor() -> Result<(), DurableError> {
    let mut c = Case::new();
    let current = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
    let next = same_credential_roster(&c, &c.device, 2);
    let rp = r_proposal(&c, &c.device, &next, &current, c.initial);
    assert_eq!(
        c.store
            .prepare_roster_refresh(rp, &c.device, &next, &current, 150)?,
        State::Prepared
    );
    explicit_format(&mut c, b"QPANC010");
    assert_eq!(
        r_exchange(&mut c, &rp, AnchorOperation::commit_roster_refresh(&rp)),
        State::Applied
    );
    assert_eq!(
        r_exchange(
            &mut c,
            &rp,
            AnchorOperation::acknowledge_roster_refresh(&rp)
        ),
        State::Acknowledged
    );
    c.reopen();
    let g = grant(&c, &next, 3);
    let gp = g_proposal(&c, &g, rp.target_head());
    let before = c.fingerprint();
    let result = c
        .store
        .prepare_credential_renewal(gp, &g, &current, 150);
    if result.is_err() {
        assert_eq!(c.fingerprint(), before);
    }
    let (mut c, prepared) = preserve_failure(c, result)?;
    assert_eq!(prepared, GState::Prepared);
    explicit_format(&mut c, b"QPANC020");
    c.reopen();
    assert_eq!(
        g_exchange(&mut c, &gp, AnchorOperation::commit_credential_renewal(&gp)),
        GState::Applied
    );
    assert_eq!(
        g_exchange(
            &mut c,
            &gp,
            AnchorOperation::acknowledge_credential_renewal(&gp)
        ),
        GState::Acknowledged
    );
    c.reopen();
    explicit_format(&mut c, b"QPANC020");
    let image = c.store.image()?;
    let entry = image
        .entries
        .get(&c.subject.id(&c.pin.binding()))
        .expect("original subject");
    assert_eq!(entry.credential_owner, storage_owner(g.successor_device()));
    assert_eq!(entry.authority, g.successor_device().authority_binding());
    assert_eq!(entry.head, gp.target_head());
    Ok(())
}

mod crash;
mod policy_composition;
mod retirement;
