// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "preinstallation_codec_tests.rs"]
mod codec;
#[path = "preinstallation_process_tests.rs"]
mod process;
#[path = "preinstallation_roster_tests.rs"]
mod roster;
#[path = "preinstallation_witness_tests.rs"]
mod witness;
use crate::{
    CredentialRenewalAuthorization, CredentialRenewalId, CredentialRenewalMaterials,
    EnrollmentExtensionApproval, EnrollmentExtensionInputs, EnrollmentPreparationStatus, Validity,
    VerifiedCredentialRenewal,
};

struct Target {
    approval: EnrollmentExtensionApproval,
    certificate: Vec<u8>,
    roster: crate::IssuedRoster,
    pin: AccountPin,
}
impl Target {
    fn inputs(&self) -> EnrollmentExtensionInputs<'_> {
        EnrollmentExtensionInputs {
            approval: &self.approval,
            certificate: &self.certificate,
            issued_roster: self.roster.as_bytes(),
            issued_checkpoint: self.roster.checkpoint(),
            current_roster: self.roster.as_bytes(),
        }
    }
    fn device(&self, now: u64) -> VerifiedDevice {
        self.pin
            .verify_device(&self.certificate, self.roster.as_bytes(), now)
            .expect("current target")
    }
}
fn target(
    c: &Case,
    previous: &VerifiedDevice,
    id: u8,
    prior: Option<[u8; 32]>,
    until: u64,
    now: u64,
) -> Target {
    let certificate = c
        .root
        .issue_credential_extension(previous, until, now)
        .expect("independent root extension");
    let predecessor = previous.roster().checkpoint();
    let roster = c
        .root
        .issue_roster(
            predecessor.version() + 1,
            Validity::new(now, until).expect("target interval"),
            &[c.root.roster_entry(&certificate).expect("target member")],
        )
        .expect("target roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent current pin");
    let approval =
        EnrollmentExtensionApproval::from_trusted_state([id; 32], prior, predecessor, until)
            .expect("explicit approval");
    Target {
        approval,
        certificate,
        roster,
        pin,
    }
}
fn setup() -> (Case, Vec<u8>, JournalIdentity, VerifiedDevice) {
    let mut c = case();
    c.intent.description.validity = Validity::new(100, 160).expect("original interval");
    let (mut owner, request, journal) = accepted(&c);
    assert_eq!(
        owner.preparation_status().expect("progress"),
        EnrollmentPreparationStatus::Unprepared
    );
    let image = owner.image().expect("image");
    let original = owner.original_device_metadata(&image).expect("history");
    owner.close();
    (c, request, journal, original)
}
fn row(owner: &mut DeviceEnrollment) -> Vec<u8> {
    let image = owner.image().expect("image");
    encode(&owner.key().expect("key"), owner.binding, &image).expect("exact record")
}

#[test]
fn preinstallation_extension_after_credential_and_policy_expiry_reaches_real_owner_and_later_g() {
    let (c, proof, journal, original) = setup();
    let key = fs::read(&c.paths.signer).expect("original encrypted signer");
    let p2 = policy_continuation::policy(&c, 2, 400, 210);
    assert!(open(&c).prepare(&c.policy, 210).is_err());
    let next = target(&c, &original, 31, None, 300, 210);
    let mut owner = open(&c);
    let identity = owner.identity().expect("signing id");
    assert_eq!(
        owner
            .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
            .expect("adopt"),
        journal
    );
    let saved = row(&mut owner);
    assert_eq!(saved.get(..8), Some(b"QPENST19".as_slice()));
    owner.close();
    let mut owner = open(&c);
    assert_eq!(
        owner
            .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
            .expect("exact retry"),
        journal
    );
    assert_eq!(row(&mut owner), saved);
    let public = owner.public_admission().expect("retained public admission");
    assert_eq!(public.certificate(), next.certificate);
    assert_eq!(public.roster(), next.roster.as_bytes());
    assert_eq!(public.checkpoint(), next.roster.checkpoint());
    assert_eq!(public.journal(), journal);
    assert!(
        matches!(owner.image().expect("image").phase,Phase::Accepted{request,..} if request==proof)
    );
    owner.prepare(&p2, 210).expect("prepare original journal");
    assert_eq!(
        owner.preparation_status().expect("progress"),
        EnrollmentPreparationStatus::Selected
    );
    let mut active = owner.activate(&p2, 210, None).expect("current owner");
    let (service, signer, device) = active.parts().expect("owners");
    signer.check_device(device).expect("same complete key");
    assert_eq!(
        service.stores().expect("journal").0.test_snapshot().id,
        *journal.as_bytes()
    );
    assert_eq!(
        device.credential_digest(),
        next.device(210).credential_digest()
    );
    active.close();
    // G must bind the actual installation's first credential, not its older
    // registration history. Both the original credential and P1 have expired.
    let previous = next.device(210);
    let successor = c
        .root
        .issue_credential_extension(&previous, 350, 320)
        .expect("later G target");
    let listing = c
        .root
        .issue_roster(
            3,
            Validity::new(320, 350).expect("interval"),
            &[c.root.roster_entry(&successor).expect("member")],
        )
        .expect("roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        listing.checkpoint(),
        p2.family(),
    )
    .expect("pin");
    let authorization = CredentialRenewalAuthorization {
        operation: CredentialRenewalId::from_trusted_state([32; 32]).expect("G id"),
        previous: next.roster.checkpoint(),
        policy_digest: p2.checkpoint().digest(),
    };
    let grant = c
        .root
        .issue_credential_renewal(
            CredentialRenewalMaterials {
                original_credential: &next.certificate,
                previous_credential: &next.certificate,
                previous_roster: next.roster.as_bytes(),
                successor_credential: &successor,
                successor_roster: listing.as_bytes(),
            },
            &authorization,
            &pin,
            320,
        )
        .expect("G issuance");
    let grant =
        VerifiedCredentialRenewal::verify(grant.as_bytes(), &pin, p2.checkpoint().digest(), 320)
            .expect("G");
    open(&c)
        .stage_credential_renewal(&grant, grant.operation(), &p2, 320)
        .expect("existing G coordinator");
    let mut active = open(&c)
        .activate(&p2, 320, None)
        .expect("original installation after G");
    assert_eq!(
        active
            .parts()
            .expect("owners")
            .0
            .stores()
            .expect("journal")
            .0
            .test_snapshot()
            .id,
        *journal.as_bytes()
    );
    active.close();
    let mut owner = open(&c);
    assert_eq!(owner.identity().expect("identity"), identity);
    let public = owner.public_admission().expect("actual retained G target");
    assert_eq!(public.certificate(), successor);
    assert_eq!(public.roster(), listing.as_bytes());
    assert_eq!(public.journal(), journal);
    assert_eq!(
        owner
            .credential_extension_status()
            .expect("history")
            .expect("extension")
            .approval,
        next.approval
    );
    assert_eq!(fs::read(&c.paths.signer).expect("retained signer"), key);
}

#[test]
fn preinstallation_selection_survives_missing_children_and_refuses_retarget() {
    let (c, _, _, original) = setup();
    let next = target(&c, &original, 33, None, 190, 170);
    let mut owner = open(&c);
    owner.prepare(&c.policy, 150).expect("original selection");
    assert_eq!(
        owner.preparation_status().expect("progress"),
        EnrollmentPreparationStatus::Selected
    );
    for path in c.paths.installation.files() {
        fs::rename(path, path.with_extension("retained")).expect("preserve missing-file fixture");
    }
    let before = row(&mut owner);
    owner.close();
    assert!(open(&c)
        .adopt_credential_extension(next.inputs(), &next.pin, &c.policy, 170)
        .is_err());
    assert_eq!(row(&mut open(&c)), before);
    for path in c.paths.installation.files() {
        assert!(!path.exists());
    }
}

#[test]
fn legacy_accepted_state_cannot_infer_unprepared_from_absence_and_stays_usable() {
    let (c, _, _, original) = setup();
    let mut owner = open(&c);
    let mut old = owner.image().expect("image");
    old.preparation = None;
    owner
        .save(&old)
        .expect("explicit historical-format fixture");
    let before = row(&mut owner);
    assert_eq!(before.get(..8), Some(b"QPENST01".as_slice()));
    owner.close();
    assert_eq!(
        open(&c).preparation_status().expect("unknown history"),
        EnrollmentPreparationStatus::Untracked
    );
    let next = target(&c, &original, 34, None, 190, 170);
    assert!(matches!(
        open(&c).adopt_credential_extension(next.inputs(), &next.pin, &c.policy, 170),
        Err(DurableError::Suspended)
    ));
    let mut owner = open(&c);
    assert_eq!(row(&mut owner), before);
    owner
        .prepare(&c.policy, 150)
        .expect("existing preparation contract");
    owner
        .activate(&c.policy, 150, None)
        .expect("existing activation contract")
        .close();
    assert_eq!(
        open(&c).preparation_status().expect("active history"),
        EnrollmentPreparationStatus::Selected
    );
}

#[test]
fn preinstallation_retries_and_repeated_extensions_reject_old_heads_keys_and_policy_forks() {
    let (c, _, journal, original) = setup();
    let p2 = policy_continuation::policy(&c, 2, 400, 210);
    let first = target(&c, &original, 35, None, 300, 210);
    open(&c)
        .adopt_credential_extension(first.inputs(), &first.pin, &p2, 210)
        .expect("first");
    let second = target(
        &c,
        &first.device(210),
        36,
        Some(first.approval.operation()),
        350,
        220,
    );
    let fork = policy_continuation::policy(&c, 2, 390, 220);
    let before = row(&mut open(&c));
    assert!(open(&c)
        .adopt_credential_extension(second.inputs(), &second.pin, &fork, 220)
        .is_err());
    assert_eq!(row(&mut open(&c)), before);
    assert_eq!(
        open(&c)
            .adopt_credential_extension(second.inputs(), &second.pin, &p2, 220)
            .expect("second"),
        journal
    );
    let after = row(&mut open(&c));
    assert!(open(&c)
        .adopt_credential_extension(first.inputs(), &first.pin, &p2, 220)
        .is_err());
    assert_eq!(row(&mut open(&c)), after);
    let mut third = target(
        &c,
        &second.device(220),
        37,
        Some(first.approval.operation()),
        380,
        230,
    );
    assert!(open(&c)
        .adopt_credential_extension(third.inputs(), &third.pin, &p2, 230)
        .is_err());
    third.approval = EnrollmentExtensionApproval::from_trusted_state(
        [37; 32],
        Some(second.approval.operation()),
        second.roster.checkpoint(),
        380,
    )
    .expect("correct predecessor");
    let other = DeviceSigningKey::generate().expect("other test owner");
    let changed = c
        .root
        .issue_device(
            DeviceDescription::new(
                c.intent.description.id,
                1,
                p2.family(),
                Validity::new(100, 380).expect("interval"),
            )
            .expect("description"),
            other.public_key().expect("key"),
        )
        .expect("wrong-key certificate");
    let removed = c
        .root
        .issue_roster(4, Validity::new(230, 380).expect("interval"), &[])
        .expect("revoked target");
    let removed_pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        removed.checkpoint(),
        p2.family(),
    )
    .expect("pin");
    assert!(open(&c)
        .adopt_credential_extension(
            EnrollmentExtensionInputs {
                current_roster: removed.as_bytes(),
                ..third.inputs()
            },
            &removed_pin,
            &p2,
            230
        )
        .is_err());
    let substituted = c
        .root
        .issue_roster(
            4,
            Validity::new(230, 380).expect("interval"),
            &[c.root.roster_entry(&changed).expect("wrong-key member")],
        )
        .expect("wrong-key signed roster");
    let substituted_pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        substituted.checkpoint(),
        p2.family(),
    )
    .expect("wrong-key pin");
    substituted_pin
        .verify_device(&changed, substituted.as_bytes(), 230)
        .expect("otherwise valid root-issued device");
    assert!(open(&c)
        .adopt_credential_extension(
            EnrollmentExtensionInputs {
                certificate: &changed,
                issued_roster: substituted.as_bytes(),
                issued_checkpoint: substituted.checkpoint(),
                current_roster: substituted.as_bytes(),
                ..third.inputs()
            },
            &substituted_pin,
            &p2,
            230
        )
        .is_err());
    assert_eq!(row(&mut open(&c)), after);
}

#[test]
fn every_extension_commit_sync_fault_keeps_original_or_exact_adopted_target() {
    let (c, _, _, original) = setup();
    let p2 = policy_continuation::policy(&c, 2, 400, 210);
    let next = target(&c, &original, 38, None, 300, 210);
    let (mut owner, _, count) = faulty(&c, false);
    owner
        .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
        .expect("calibrate");
    let syncs = count.load(Ordering::SeqCst);
    assert!(syncs > 0);
    owner.close();
    for after in [false, true] {
        for cut in 1..=syncs {
            let (c, proof, journal, original) = setup();
            let p2 = policy_continuation::policy(&c, 2, 400, 210);
            let next = target(&c, &original, 39, None, 300, 210);
            let key = fs::read(&c.paths.signer).expect("signer");
            let (mut owner, remaining, _) = faulty(&c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.adopt_credential_extension(next.inputs(), &next.pin, &p2, 210),
                after,
            );
            assert!(owner.active.is_none());
            let mut recovered = open(&c);
            assert_eq!(
                recovered
                    .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
                    .expect("exact recovery"),
                journal
            );
            assert!(
                matches!(recovered.image().expect("image").phase,Phase::Accepted{request,..} if request==proof)
            );
            assert_eq!(fs::read(&c.paths.signer).expect("signer unchanged"), key);
        }
    }
}

#[test]
fn selection_sync_failure_never_creates_children_before_the_selection_is_durable() {
    let (c, _, _, _) = setup();
    let (mut owner, _, count) = faulty(&c, false);
    owner.prepare(&c.policy, 150).expect("calibrate selection");
    let syncs = count.load(Ordering::SeqCst);
    assert!(syncs > 0);
    owner.close();
    for after in [false, true] {
        for cut in 1..=syncs {
            let (c, _, _, original) = setup();
            let next = target(&c, &original, 44, None, 190, 170);
            let (mut owner, remaining, _) = faulty(&c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(owner.prepare(&c.policy, 150), after);
            assert!(owner.active.is_none());
            for path in c.paths.installation.files() {
                assert!(!path.exists(), "failed selection cannot publish children");
            }
            let mut recovered = open(&c);
            let progress = recovered
                .preparation_status()
                .expect("actual committed state");
            assert!(
                matches!(
                    progress,
                    EnrollmentPreparationStatus::Unprepared | EnrollmentPreparationStatus::Selected
                ),
                "unexpected selection outcome: {progress:?}"
            );
            if progress == EnrollmentPreparationStatus::Selected {
                assert!(recovered
                    .adopt_credential_extension(next.inputs(), &next.pin, &c.policy, 170)
                    .is_err());
                recovered = open(&c);
            }
            recovered
                .prepare(&c.policy, 150)
                .expect("same original preparation");
            recovered
                .activate(&c.policy, 150, None)
                .expect("same original installation")
                .close();
        }
    }
}

pub(super) fn after_commit(bytes: &[u8]) {
    process::after_commit(bytes);
}
