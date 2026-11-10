// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual original T/R coordination, independent of policy-only P.
use super::*;
use crate::enrollment::tests::policy_continuation as continuation;
use crate::{
    AnchorRosterRefreshProposal as RProposal, AnchorRosterRefreshState as RState, RosterRefreshId,
};
#[path = "witness_joint_roster_recovery_tests.rs"]
mod recovery;

fn original() -> Fixture {
    original_on(fixture_with_policy_expiry(Some(160)))
}
pub(in crate::enrollment::tests::witness_renewal) fn original_on(f: Fixture) -> Fixture {
    let mut active = activate(&f, 150).expect("original owner");
    let (service, _, device) = active.parts().expect("owners");
    service
        .stores()
        .expect("stores")
        .0
        .generate_prekey(
            &f.c.policy,
            device,
            PrekeyId::from_trusted_state([121; 32]).expect("prekey"),
            LeafKind::OneTimePq,
            Validity::new(100, 160).expect("original validity"),
            150,
        )
        .expect("real existing asset");
    active.close();
    f
}
pub(in crate::enrollment::tests::witness_renewal) fn adopt_t(
    f: &Fixture,
    previous: &VerifiedDevice,
    version: u64,
) -> (
    VerifiedCredentialRenewal,
    VerifiedSessionPolicy,
    VerifiedPolicyContinuation,
) {
    let g = grant(f, previous, version, 280);
    let p = continuation::policy(&f.c, 2, 300, 170);
    let scope = continuation::scope(&f.c, &g, f.id);
    let t = continuation::joint(&f.c, &g, &scope, &f.c.policy, &p);
    let proposal = prepare_policy(f, &g, Some(&t), &p);
    let mut owner = open(&f.c);
    let mut anchor = client(f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_policy_continuation(
                &proposal,
                f.c.policy.historical(),
                &p,
                170,
                &mut anchor,
            )
            .expect("original T applied and retired"),
        committed(&g, &proposal)
    );
    owner.close();
    (g, p, t)
}
pub(in crate::enrollment::tests::witness_renewal) fn roster(
    f: &Fixture,
    current: &VerifiedDevice,
    version: u64,
    now: u64,
) -> VerifiedDevice {
    let certificate =
        f.c.root
            .issue_device(current.description.clone(), current.key.clone())
            .expect("same current certificate");
    let roster =
        f.c.root
            .issue_roster(
                version,
                interval(),
                &[f.c.root.roster_entry(&certificate).expect("same member")],
            )
            .expect("independent root roster");
    AccountPin::new(
        current.account_id(),
        f.c.intent.root.clone(),
        roster.checkpoint(),
        f.c.policy.family(),
    )
    .expect("target pin")
    .verify_device(&certificate, roster.as_bytes(), now)
    .expect("actual target")
}
fn keep(f: Fixture, error: DurableError) -> DurableError {
    f.carrier.store.lock().expect("store").close();
    eprintln!(
        "Retained original T/R enrollment: {}",
        f.c._directory.keep().display()
    );
    eprintln!(
        "Retained original T/R witness: {}",
        Arc::try_unwrap(f._witness_dir)
            .expect("sole directory owner")
            .keep()
            .display()
    );
    error
}
fn prepare_r(
    f: &Fixture,
    previous: &VerifiedDevice,
    target: &VerifiedDevice,
    policy: &VerifiedSessionPolicy,
    now: u64,
) -> Result<RProposal, DurableError> {
    f.carrier.clock.store(now, Ordering::SeqCst);
    let before = disk(f);
    let mut owner = open(&f.c);
    // The existing G control client is already authorized for this same original
    // subject; this independently exercises R admission beyond its constructor.
    let anchor = client(f, &mut owner, now);
    let proposal = owner.prepare_witnessed_roster_refresh(
        RosterRefreshId::generate().expect("R ID"),
        f.c.policy.historical(),
        policy,
        target,
        now,
        anchor,
    )?;
    owner.close();
    let saved = disk(f);
    assert_eq!(saved.0, before.0);
    let pending = saved.1.as_ref().expect("actual R pending");
    if policy.checkpoint() != f.c.policy.checkpoint() {
        assert_eq!(pending.get(..8), Some(b"QPWINT11".as_slice()));
        DeviceJournal::assert_roster_credential_format(
            &JournalKey::open(&f.c.paths.wrapping).expect("original key"),
            &f.original,
            f.id,
            pending,
        );
    }
    let sealed = pending
        .get(341..pending.len().checked_sub(32).expect("MAC"))
        .expect("actual R target")
        .to_vec();
    assert_eq!(
        crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2", &sealed),
        proposal.target_head().digest()
    );
    assert_eq!(
        DeviceJournal::assert_roster_target_preserves_assets(
            &JournalKey::open(&f.c.paths.wrapping).expect("original key"),
            &f.original,
            &before.0,
            &sealed,
            proposal.scope(),
        ),
        1
    );
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_roster_refresh(proposal, previous, target, policy, now,)?,
        RState::Prepared
    );
    Ok(proposal)
}
fn refresh(
    f: &Fixture,
    previous: &VerifiedDevice,
    target: &VerifiedDevice,
    policy: &VerifiedSessionPolicy,
    now: u64,
) -> Result<(), DurableError> {
    let proposal = prepare_r(f, previous, target, policy, now)?;
    let sealed = target_r(&disk(f));
    let mut owner = open(&f.c);
    let mut anchor = owner.roster_refresh_anchor_client(
        f.c.policy.historical(),
        f.pin.clone(),
        Box::new(f.carrier.clone()),
        Duration::from_secs(3),
    )?;
    assert_eq!(
        owner.commit_witnessed_roster_refresh(
            &proposal,
            f.c.policy.historical(),
            policy,
            now,
            &mut anchor,
        )?,
        RState::Applied
    );
    owner.close();
    assert_eq!(disk(f), (sealed, None));
    Ok(())
}
fn target_r(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let pending = saved.1.as_ref().expect("original R pending");
    pending
        .get(341..pending.len().checked_sub(32).expect("MAC"))
        .expect("actual sealed R target")
        .to_vec()
}
fn r_client(f: &Fixture, owner: &mut DeviceEnrollment) -> AnchorClient {
    owner
        .roster_refresh_anchor_client(
            f.c.policy.historical(),
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("original R signer")
}
fn adopt_g(
    f: &Fixture,
    previous: &VerifiedDevice,
    version: u64,
    p: &VerifiedSessionPolicy,
) -> VerifiedCredentialRenewal {
    let g = grant(f, previous, version, 280 + version * 2);
    let proposal = prepare_policy(f, &g, None, p);
    let mut owner = open(&f.c);
    let mut anchor = client(f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_policy_continuation(
                &proposal,
                f.c.policy.historical(),
                p,
                170,
                &mut anchor,
            )
            .expect("original G retains T"),
        committed(&g, &proposal)
    );
    owner.close();
    g
}
fn active(f: &Fixture, policy: &VerifiedSessionPolicy, expected: &VerifiedDevice) {
    let before = disk(f);
    let mut owner = open(&f.c);
    let anchor = client(f, &mut owner, 170);
    let mut active = owner
        .activate_witnessed_policy_continuation(f.c.policy.historical(), policy, 170, anchor)
        .expect("current original T owner");
    let (service, signer, current) = active.parts().expect("original owners");
    signer.check_device(current).expect("same signing owner");
    assert_eq!(current.credential_digest(), expected.credential_digest());
    assert_eq!(
        current.roster().checkpoint(),
        expected.roster().checkpoint()
    );
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("journal"),
        f.id
    );
    active.close();
    assert_eq!(disk(f), before);
}

#[test]
fn original_joint_roster_control_client_retains_completed_t() -> Result<(), DurableError> {
    let f = original();
    let (_g, _p, _t) = adopt_t(&f, &f.original, 2);
    let before = disk(&f);
    let mut owner = open(&f.c);
    let result = owner.roster_refresh_anchor_client(
        f.c.policy.historical(),
        f.pin.clone(),
        Box::new(f.carrier.clone()),
        Duration::from_secs(3),
    );
    owner.close();
    assert_eq!(disk(&f), before);
    match result {
        Ok(_) => Ok(()),
        Err(error) => Err(keep(f, error)),
    }
}

#[test]
fn original_joint_roster_t_then_r_preserves_real_target_and_authority() -> Result<(), DurableError>
{
    let f = original();
    let (g, p, _t) = adopt_t(&f, &f.original, 2);
    let next = roster(&f, g.successor_device(), 3, 170);
    if let Err(error) = refresh(&f, g.successor_device(), &next, &p, 170) {
        return Err(keep(f, error));
    }
    active(&f, &p, &next);
    Ok(())
}

#[test]
fn original_joint_roster_r_then_t_preserves_prior_r_history() -> Result<(), DurableError> {
    let f = original();
    let next = roster(&f, &f.original, 2, 150);
    refresh(&f, &f.original, &next, &f.c.policy, 150)?;
    let mut owner = open(&f.c);
    let history = owner.witnessed_roster_refresh_progress()?;
    owner.close();
    let (g, p, _t) = adopt_t(&f, &next, 3);
    active(&f, &p, g.successor_device());
    let mut owner = open(&f.c);
    assert_eq!(owner.witnessed_roster_refresh_progress()?, history);
    owner.close();
    let next_r = roster(&f, g.successor_device(), 4, 170);
    refresh(&f, g.successor_device(), &next_r, &p, 170)?;
    active(&f, &p, &next_r);
    Ok(())
}

#[test]
fn original_joint_roster_alternating_g_r_retains_t_and_actual_predecessor() {
    let f = original();
    let (g, p, _) = adopt_t(&f, &f.original, 2);
    let mut previous = g.successor_device().clone();
    for version in [3, 5, 7] {
        let g = adopt_g(&f, &previous, version, &p);
        let next = roster(&f, g.successor_device(), version + 1, 170);
        refresh(&f, g.successor_device(), &next, &p, 170).expect("T/G/R cycle");
        active(&f, &p, &next);
        previous = next;
    }
}
