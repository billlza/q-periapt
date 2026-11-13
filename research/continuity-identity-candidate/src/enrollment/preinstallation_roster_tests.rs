// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn next_roster(
    c: &Case,
    certificate: &[u8],
    version: u64,
    now: u64,
    until: u64,
) -> (crate::IssuedRoster, AccountPin) {
    let listing = c
        .root
        .issue_roster(
            version,
            Validity::new(now, until).expect("interval"),
            &[c.root.roster_entry(certificate).expect("same member")],
        )
        .expect("new signed roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        listing.checkpoint(),
        c.policy.family(),
    )
    .expect("current pin");
    (listing, pin)
}

#[test]
fn unprepared_roster_refresh_preserves_original_then_extended_admission_and_rejects_policy_change()
{
    let (c, proof, journal, original) = setup();
    let mut owner = open(&c);
    let initial = owner.public_admission().expect("initial");
    let (listing, pin) = next_roster(&c, initial.certificate(), 2, 150, 200);
    assert_eq!(
        owner
            .refresh_roster(
                initial.checkpoint(),
                listing.as_bytes(),
                &pin,
                &c.policy,
                150
            )
            .expect("fresh roster"),
        EnrollmentStatus::Accepted(journal)
    );
    let before = row(&mut owner);
    owner.close();
    let mut owner = open(&c);
    owner
        .refresh_roster(
            initial.checkpoint(),
            listing.as_bytes(),
            &pin,
            &c.policy,
            150,
        )
        .expect("exact retry");
    assert_eq!(row(&mut owner), before);
    let refreshed = pin
        .verify_device(initial.certificate(), listing.as_bytes(), 150)
        .expect("actual refreshed predecessor");
    owner.close();
    let extended = target(&c, &refreshed, 47, None, 300, 210);
    let p2 = policy_continuation::policy(&c, 2, 400, 210);
    let mut owner = open(&c);
    owner
        .adopt_credential_extension(extended.inputs(), &extended.pin, &p2, 210)
        .expect("extension from refreshed state");
    let (listing, pin) = next_roster(&c, &extended.certificate, 4, 210, 300);
    let wrong_policy = policy_continuation::policy(&c, 3, 400, 210);
    let before = row(&mut owner);
    assert!(owner
        .refresh_roster(
            extended.roster.checkpoint(),
            listing.as_bytes(),
            &pin,
            &wrong_policy,
            210
        )
        .is_err());
    let mut owner = open(&c);
    assert_eq!(row(&mut owner), before);
    owner
        .refresh_roster(
            extended.roster.checkpoint(),
            listing.as_bytes(),
            &pin,
            &p2,
            210,
        )
        .expect("extended same-credential refresh");
    let public = owner.public_admission().expect("target metadata");
    assert_eq!(public.journal(), journal);
    assert_eq!(public.checkpoint(), listing.checkpoint());
    assert_eq!(public.certificate(), extended.certificate);
    assert!(
        matches!(owner.image().expect("image").phase,Phase::Accepted{request,..} if request==proof)
    );
    assert_eq!(original.device_id(), refreshed.device_id());
    owner.prepare(&p2, 210).expect("original installation");
    owner
        .activate(&p2, 210, None)
        .expect("actual owner")
        .close();
}

#[test]
fn selected_or_untracked_roster_refresh_never_retargets_or_fills_missing_children() {
    for selected in [false, true] {
        let (c, _, _, _) = setup();
        let mut owner = open(&c);
        let original = owner.public_admission().expect("original");
        let (listing, pin) = next_roster(&c, original.certificate(), 2, 150, 200);
        if selected {
            owner.prepare(&c.policy, 150).expect("selected");
            for path in c.paths.installation.files() {
                fs::rename(path, path.with_extension("retained")).expect("retain lost children");
            }
        } else {
            let mut image = owner.image().expect("legacy fixture");
            image.preparation = None;
            owner.save(&image).expect("legacy");
        }
        let before = row(&mut owner);
        assert!(owner
            .refresh_roster(
                original.checkpoint(),
                listing.as_bytes(),
                &pin,
                &c.policy,
                150
            )
            .is_err());
        assert_eq!(row(&mut open(&c)), before);
        for path in c.paths.installation.files() {
            assert!(!path.exists());
        }
    }
}

#[test]
fn every_unprepared_roster_commit_sync_fault_recovers_the_original_target() {
    let (c, _, _, _) = setup();
    let original = open(&c).public_admission().expect("original");
    let (listing, pin) = next_roster(&c, original.certificate(), 2, 150, 200);
    let (mut owner, _, count) = faulty(&c, false);
    owner
        .refresh_roster(
            original.checkpoint(),
            listing.as_bytes(),
            &pin,
            &c.policy,
            150,
        )
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!(barriers > 0);
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let (c, proof, journal, _) = setup();
            let original = open(&c).public_admission().expect("original");
            let (listing, pin) = next_roster(&c, original.certificate(), 2, 150, 200);
            let (mut owner, remaining, _) = faulty(&c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.refresh_roster(
                    original.checkpoint(),
                    listing.as_bytes(),
                    &pin,
                    &c.policy,
                    150,
                ),
                after,
            );
            assert!(owner.active.is_none());
            let mut owner = open(&c);
            assert_eq!(
                owner
                    .refresh_roster(
                        original.checkpoint(),
                        listing.as_bytes(),
                        &pin,
                        &c.policy,
                        150
                    )
                    .expect("original retry"),
                EnrollmentStatus::Accepted(journal)
            );
            assert!(
                matches!(owner.image().expect("image").phase,Phase::Accepted{request,..} if request==proof)
            );
        }
    }
}
