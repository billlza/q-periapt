// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual complete-account G/R on every original enrolled member.
use super::*;
use crate::{AnchorRosterRefreshState, RosterRefreshId};

fn member(
    c: &AccountCase,
    index: usize,
) -> (
    &EnrollmentPaths,
    &EnrollmentIntent,
    &VerifiedDevice,
    JournalIdentity,
) {
    match index.checked_sub(1) {
        None => (&c.f.c.paths, &c.f.c.intent, &c.f.original, c.f.id),
        Some(i) => {
            let p = c.peers.get(i).expect("original member");
            (&p.paths, &p.intent, &p.device, p.id)
        }
    }
}
fn target_roster(c: &AccountCase, version: u64) -> crate::IssuedRoster {
    let entries = c
        .grants
        .iter()
        .map(|g| {
            let d = g.successor_device();
            let cert =
                c.f.c
                    .root
                    .issue_device(d.description.clone(), d.key.clone())
                    .expect("same current certificate");
            c.f.c.root.roster_entry(&cert).expect("same current member")
        })
        .collect::<Vec<_>>();
    c.f.c
        .root
        .issue_roster(version, interval(), &entries)
        .expect("independent complete roster")
}
fn device_at(c: &AccountCase, index: usize, roster: &crate::IssuedRoster) -> VerifiedDevice {
    let d = c
        .grants
        .get(index)
        .expect("original local G")
        .successor_device();
    let cert =
        c.f.c
            .root
            .issue_device(d.description.clone(), d.key.clone())
            .expect("same current certificate");
    AccountPin::new(
        d.account_id(),
        c.f.c.intent.root.clone(),
        roster.checkpoint(),
        c.f.c.policy.family(),
    )
    .expect("independently selected target")
    .verify_device(&cert, roster.as_bytes(), 170)
    .expect("verified same-C target")
}
fn snapshot(paths: &EnrollmentPaths) -> (Vec<u8>, Option<Vec<u8>>) {
    let db = open_private_database(paths.installation.files()[1]).expect("original journal");
    let tx = db.begin_read().expect("read");
    let table = tx.open_table(JOURNAL).expect("table");
    let image = table
        .get("image")
        .expect("lookup")
        .expect("original image")
        .value()
        .to_vec();
    let pending = table
        .get("pending")
        .expect("lookup")
        .map(|p| p.value().to_vec());
    (image, pending)
}
fn refresh(c: &AccountCase, index: usize, target: &VerifiedDevice) -> Result<(), DurableError> {
    let (paths, intent, original, _) = member(c, index);
    let grant = c.grants.get(index).expect("own G");
    let before = snapshot(paths);
    let mut owner = DeviceEnrollment::open(paths.clone(), intent.clone())?;
    let completed = owner
        .image()?
        .renewal
        .as_ref()
        .and_then(LocalRenewal::witnessed_completion)
        .expect("original complete account receipt")
        .clone();
    assert!(completed.account_binding.is_some());
    let anchor = owner.roster_refresh_anchor_client(
        c.f.c.policy.historical(),
        c.f.pin.clone(),
        Box::new(c.f.carrier.clone()),
        Duration::from_secs(3),
    )?;
    let proposal = owner.prepare_witnessed_roster_refresh(
        RosterRefreshId::generate().expect("R ID"),
        c.f.c.policy.historical(),
        &c.f.c.policy,
        target,
        170,
        anchor,
    )?;
    owner.close();
    let saved = snapshot(paths);
    assert_eq!(saved.0, before.0);
    let pending = saved.1.as_ref().expect("actual original pending");
    assert_eq!(pending.get(..8), Some(b"QPWINT10".as_slice()));
    let sealed = pending
        .get(341..pending.len().checked_sub(32).expect("MAC"))
        .expect("actual target");
    DeviceJournal::assert_roster_target_preserves_assets(
        &JournalKey::open(&paths.wrapping).expect("original key"),
        original,
        &before.0,
        sealed,
        proposal.scope(),
    );
    c.f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_roster_refresh(
            proposal,
            grant.successor_device(),
            target,
            &c.f.c.policy,
            170,
        )?;
    let mut owner = DeviceEnrollment::open(paths.clone(), intent.clone())?;
    let mut anchor = owner.roster_refresh_anchor_client(
        c.f.c.policy.historical(),
        c.f.pin.clone(),
        Box::new(c.f.carrier.clone()),
        Duration::from_secs(3),
    )?;
    assert_eq!(
        owner.commit_witnessed_roster_refresh(
            &proposal,
            c.f.c.policy.historical(),
            &c.f.c.policy,
            170,
            &mut anchor
        )?,
        AnchorRosterRefreshState::Applied
    );
    assert_eq!(
        owner
            .image()?
            .renewal
            .as_ref()
            .and_then(LocalRenewal::witnessed_completion),
        Some(&completed)
    );
    owner.close();
    assert_eq!(snapshot(paths), (sealed.to_vec(), None));
    Ok(())
}
fn preserve(c: AccountCase, error: DurableError) -> DurableError {
    c.f.carrier.store.lock().expect("witness").close();
    eprintln!(
        "Retained common-account original owner: {}",
        c.f.c._directory.keep().display()
    );
    for peer in c.peers {
        eprintln!(
            "Retained common-account original peer: {}",
            peer._directory.keep().display()
        );
    }
    eprintln!(
        "Retained common-account witness: {}",
        Arc::try_unwrap(c.f._witness_dir)
            .expect("directory owner")
            .keep()
            .display()
    );
    error
}
fn complete_account(members: usize) -> Result<(), DurableError> {
    let started = std::time::Instant::now();
    let progress = |phase: &str, index: usize| {
        eprintln!("COMMON_ACCOUNT_ROSTER_PROGRESS members={members} phase={phase} member={index} elapsed_ms={}", started.elapsed().as_millis());
    };
    progress("begin", 0);
    let c = AccountCase::with_members(true, 190, members);
    progress("identities", 0);
    for index in 0..members {
        let (paths, intent, _, _) = member(&c, index);
        session::renew(&c, index, paths, intent).close();
        progress("credential-renewed", index);
    }
    let roster = target_roster(&c, 3);
    progress("target-roster", 0);
    for index in 0..members {
        let target = device_at(&c, index, &roster);
        if let Err(error) = refresh(&c, index, &target) {
            return Err(preserve(c, error));
        }
        progress("roster-refreshed", index);
        let (paths, intent, original, id) = member(&c, index);
        let before = snapshot(paths);
        let mut owner = DeviceEnrollment::open(paths.clone(), intent.clone())?;
        let anchor = client(&c.f, &mut owner, 170);
        let mut active = owner.activate(&c.f.c.policy, 170, Some(anchor))?;
        let (service, signer, current) = active.parts()?;
        signer.check_device(current).expect("same original signer");
        assert_eq!(current.key, original.key);
        assert_eq!(current.roster().checkpoint(), roster.checkpoint());
        assert_eq!(current.credential_digest(), target.credential_digest());
        assert_eq!(service.stores()?.0.identity()?, id);
        active.close();
        assert_eq!(snapshot(paths), before);
        progress("owner-reopened", index);
    }
    progress("complete", members);
    eprintln!("COMMON_ACCOUNT_ROSTER members={members} original_installations={members} complete_G_then_R=true exact_receipt=true exact_target=true");
    Ok(())
}

#[test]
fn native_common_account_roster_three_original_owners_after_complete_g() -> Result<(), DurableError>
{
    complete_account(3)
}
#[test]
fn native_common_account_roster_capacity_original_owners_after_complete_g(
) -> Result<(), DurableError> {
    complete_account(crate::identity::MAX_DEVICES)
}

#[test]
fn native_common_account_peer_renewal_cannot_include_owning_device_as_companion() {
    let c = AccountCase::new(true);
    let before = snapshot(&c.f.c.paths);
    let mut owner = open(&c.f.c);
    let anchor = client(&c.f, &mut owner, 150);
    let mut active = owner
        .activate(&c.f.c.policy, 150, Some(anchor))
        .expect("original local owner");
    let primary = c.grants.get(1).expect("peer primary");
    let companions = [c.grant(0), c.grant(2)];
    assert!(matches!(
        active
            .parts()
            .expect("service")
            .0
            .admit_peer_account_credential_renewal(
                primary,
                &companions,
                primary.operation(),
                &c.f.c.policy,
                150
            ),
        Err(DurableError::Conflict)
    ));
    active.close();
    assert_eq!(
        snapshot(&c.f.c.paths),
        before,
        "own renewal belongs to original enrollment"
    );
}
