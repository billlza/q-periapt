// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment and actual sealed journal targets across G and R.
use super::*;
use crate::{
    AnchorRosterRefreshProposal as RProposal, AnchorRosterRefreshState as RState, RosterRefreshId,
};

fn original_with_prekey() -> Fixture {
    let f = fixture();
    let mut active = credential::activate(&f, 150).expect("original current owner");
    let (service, _, device) = active.parts().expect("original owners");
    service
        .stores()
        .expect("stores")
        .0
        .generate_prekey(
            &f.c.policy,
            device,
            PrekeyId::from_trusted_state([119; 32]).expect("existing prekey"),
            LeafKind::OneTimePq,
            Validity::new(100, 160).expect("original live interval"),
            150,
        )
        .expect("real original SDK asset");
    active.close();
    f
}
pub(super) fn with_existing_prekey() -> (Fixture, Approval) {
    let f = original_with_prekey();
    let a = approved_at(&f, &f.c.policy, 2, 300, 155);
    let p = prepared_at(&f, &a, &f.c.policy, 155);
    applied_at(&f, &a, p, 155);
    (f, a)
}

pub(super) fn roster_target(
    f: &Fixture,
    current: &VerifiedDevice,
    version: u64,
    now: u64,
) -> VerifiedDevice {
    let certificate =
        f.c.root
            .issue_device(current.description.clone(), current.key.clone())
            .expect("same current credential");
    let roster =
        f.c.root
            .issue_roster(
                version,
                interval(),
                &[f.c.root.roster_entry(&certificate).expect("current member")],
            )
            .expect("independent signed roster");
    AccountPin::new(
        current.account_id(),
        f.c.intent.root.clone(),
        roster.checkpoint(),
        current.description.family,
    )
    .expect("independent root pin")
    .verify_device(&certificate, roster.as_bytes(), now)
    .expect("current target")
}

fn prepare_roster(
    f: &Fixture,
    policy: &VerifiedSessionPolicy,
    previous: &VerifiedDevice,
    target: &VerifiedDevice,
    now: u64,
) -> Result<RProposal, DurableError> {
    f.carrier.clock.store(now, Ordering::SeqCst);
    let before = journal(f);
    let mut owner = open(&f.c);
    let client = policy_client(f, &mut owner);
    let p = owner.prepare_witnessed_roster_refresh(
        RosterRefreshId::generate().expect("R ID"),
        f.c.policy.historical(),
        policy,
        target,
        now,
        client,
    )?;
    owner.close();
    let saved = journal(f);
    assert_eq!(
        saved.0, before.0,
        "preparation does not replace the original head"
    );
    let pending = saved.1.as_ref().expect("original pending");
    let tag = if previous.credential_digest() == f.original.credential_digest() {
        b"QPWINT07"
    } else {
        b"QPWINT10"
    };
    assert_eq!(pending.get(..8), Some(tag.as_slice()));
    if tag == b"QPWINT10" {
        DeviceJournal::assert_roster_credential_format(
            &JournalKey::open(&f.c.paths.wrapping).expect("original key"),
            &f.original,
            f.id,
            pending,
        );
    }
    let sealed = pending
        .get(341..pending.len().checked_sub(32).expect("MAC"))
        .expect("actual sealed R target");
    assert_eq!(
        DeviceJournal::assert_roster_target_preserves_assets(
            &JournalKey::open(&f.c.paths.wrapping).expect("original wrapping key"),
            &f.original,
            &before.0,
            sealed,
            p.scope(),
        ),
        1,
        "real original prekey is retained byte-for-byte"
    );
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_roster_refresh(p, previous, target, policy, now,)?,
        RState::Prepared
    );
    Ok(p)
}
fn roster_target_image(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let pending = saved.1.as_ref().expect("actual R pending");
    pending
        .get(341..pending.len().checked_sub(32).expect("MAC"))
        .expect("actual sealed R target")
        .to_vec()
}
pub(super) fn refresh(
    f: &Fixture,
    policy: &VerifiedSessionPolicy,
    previous: &VerifiedDevice,
    target: &VerifiedDevice,
    now: u64,
) -> Result<(), DurableError> {
    let p = prepare_roster(f, policy, previous, target, now)?;
    let sealed = roster_target_image(&journal(f));
    let mut owner = open(&f.c);
    let mut client = policy_client(f, &mut owner);
    assert_eq!(
        owner.commit_witnessed_roster_refresh(
            &p,
            f.c.policy.historical(),
            policy,
            now,
            &mut client,
        )?,
        RState::Applied
    );
    owner.close();
    assert_eq!(
        journal(f),
        (sealed, None),
        "exact target, original pending retired"
    );
    Ok(())
}

fn preserve_failure(f: Fixture, error: DurableError) -> DurableError {
    f.carrier.store.lock().expect("witness").close();
    let owner = f.c._directory.keep();
    let witness = Arc::try_unwrap(f._witness_dir)
        .expect("sole fixture directory owner")
        .keep();
    eprintln!("Retained original enrollment/journal: {}", owner.display());
    eprintln!("Retained original witness: {}", witness.display());
    error
}

fn assert_original_owner(f: &Fixture, a: &Approval, device: &VerifiedDevice) {
    let before = journal(f);
    let mut active = activate(f, &a.target, 180).expect("original owner after G/R");
    let (service, signer, current) = active.parts().expect("owners");
    signer.check_device(current).expect("original signing key");
    assert_eq!(current.credential_digest(), device.credential_digest());
    assert_eq!(current.roster().checkpoint(), device.roster().checkpoint());
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
    assert_eq!(
        journal(f),
        before,
        "activation does not rewrite or recreate the journal"
    );
}

#[test]
fn original_credential_roster_g_then_r_preserves_actual_sealed_assets() -> Result<(), DurableError>
{
    let (f, a) = with_existing_prekey();
    let g = credential::grant(&f, &f.original, 2, 280);
    let p = prepared_g(&f, &a, &g);
    committed_g(&f, &a, &g, p);
    let target = roster_target(&f, g.successor_device(), 3, 180);
    let before = journal(&f);
    if let Err(error) = refresh(&f, &a.target, g.successor_device(), &target, 180) {
        assert_eq!(
            journal(&f),
            before,
            "refusal must preserve original journal and pending"
        );
        return Err(preserve_failure(f, error));
    }
    assert_original_owner(&f, &a, &target);
    Ok(())
}

#[test]
fn original_credential_roster_r_then_g_keeps_original_history() -> Result<(), DurableError> {
    let (f, a) = with_existing_prekey();
    let target = roster_target(&f, &f.original, 2, 155);
    refresh(&f, &a.target, &f.original, &target, 155)?;
    let g = credential::grant(&f, &target, 3, 280);
    let before = journal(&f);
    let mut owner = open(&f.c);
    let original_r = owner.witnessed_roster_refresh_progress()?;
    let result = owner.stage_credential_renewal(&g, g.operation(), &a.target, 180);
    owner.close();
    if let Err(error) = result {
        assert_eq!(
            journal(&f),
            before,
            "staging failure cannot change the actual journal"
        );
        return Err(preserve_failure(f, error));
    }
    let p = prepared_g(&f, &a, &g);
    committed_g(&f, &a, &g, p);
    assert_original_owner(&f, &a, g.successor_device());
    let mut owner = open(&f.c);
    assert_eq!(
        owner.witnessed_roster_refresh_progress()?,
        original_r,
        "G preserves exact R history"
    );
    Ok(())
}

#[path = "witness_credential_roster_recovery_tests.rs"]
mod recovery;
