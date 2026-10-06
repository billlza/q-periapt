// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn original_journal_snapshot(c: &Case, original: &VerifiedDevice) -> (u64, [u8; 32]) {
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original metadata open");
    let snapshot = service.stores().expect("stores").0.test_snapshot();
    service.close();
    (snapshot.revision, snapshot.digest)
}

// Compare authenticated application state, complete index/config rows and
// immutable key files. redb may update allocator/transaction bookkeeping on a
// bare open/close even when the application's authenticated image is unchanged.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Assets {
    journal: (u64, [u8; 32]),
    enrollment: [u8; 32],
    signer: [u8; 32],
    wrapping: [u8; 32],
    installation: Vec<(String, [u8; 32])>,
    archives: Vec<([u8; 32], [u8; 32])>,
    inodes: Vec<u64>,
}
pub(super) fn assets(c: &Case, original: &VerifiedDevice) -> Assets {
    use redb::{ReadableDatabase, ReadableTable, TableDefinition};
    use std::os::unix::fs::MetadataExt;
    let paths = c.paths.installation.files();
    let installation = {
        let db = q_periapt_host_store::filesystem::open_private_database(paths[0])
            .expect("original installation file");
        let tx = db.begin_read().expect("installation read");
        let table = tx
            .open_table(TableDefinition::<&str, &[u8]>::new(
                "continuity_installation_v1",
            ))
            .expect("exact installation table");
        table
            .iter()
            .expect("all installation rows")
            .map(|entry| {
                let (key, value) = entry.expect("installation row");
                (
                    key.value().to_owned(),
                    crate::crypto::digest(b"test-logical-row", value.value()),
                )
            })
            .collect()
    };
    let archives = {
        let db = q_periapt_host_store::filesystem::open_private_database(paths[2])
            .expect("original archive file");
        let tx = db.begin_read().expect("archive read");
        let table = tx
            .open_table(TableDefinition::<&[u8; 32], &[u8]>::new(
                "continuity_session_archives_v1",
            ))
            .expect("exact archive table");
        table
            .iter()
            .expect("all archive rows")
            .map(|entry| {
                let (key, value) = entry.expect("archive row");
                (
                    *key.value(),
                    crate::crypto::digest(b"test-logical-row", value.value()),
                )
            })
            .collect()
    };
    Assets {
        journal: original_journal_snapshot(c, original),
        enrollment: crate::crypto::digest(b"test-logical-row", &row(&open(c))),
        signer: crate::crypto::digest(
            b"test-key-file",
            &fs::read(&c.paths.signer).expect("original signer"),
        ),
        wrapping: crate::crypto::digest(
            b"test-key-file",
            &fs::read(&c.paths.wrapping).expect("original wrapping key"),
        ),
        installation,
        archives,
        inodes: std::iter::once(c.paths.signer.as_path())
            .chain(std::iter::once(c.paths.wrapping.as_path()))
            .chain(paths)
            .map(|path| fs::metadata(path).expect("original inode").ino())
            .collect(),
    }
}

fn request(c: &Case) -> PolicyRenewalScope {
    open(c)
        .policy_renewal_scope(
            PolicyRenewalId::generate().expect("retained request operation"),
            c.policy.historical(),
        )
        .expect("scope from original enrollment and journal")
}

#[test]
fn original_request_scope_and_successor_come_from_actual_adoption_with_or_without_g() {
    for prior_g in [false, true] {
        let (c, original, journal) = local(180, if prior_g { 160 } else { 240 });
        let g = prior_g.then(|| renewal::grant(&c, &original, &original, 2, 240));
        if let Some(g) = &g {
            open(&c)
                .stage_credential_renewal(g, g.operation(), &c.policy, 170)
                .expect("real G intent");
            open(&c)
                .activate(&c.policy, 170, None)
                .expect("real G completion")
                .close();
        }
        let current = g.as_ref().map_or(&original, |g| g.successor_device());
        let before = assets(&c, &original);
        let mut owner = open(&c);
        let config = row(&owner);
        let mut expected = scope(&c, &original, current, journal);
        let observed = owner
            .policy_renewal_scope(expected.operation, c.policy.historical())
            .expect("original exact request");
        assert_eq!(observed, expected);
        assert_eq!(
            owner
                .policy_renewal_scope(expected.operation, c.policy.historical())
                .expect("same retained request identity"),
            expected
        );
        assert_eq!(row(&owner), config);
        owner.close();
        assert_eq!(
            assets(&c, &original),
            before,
            "all original application state and key files preserved"
        );
        let p1 = policy(&c, 2, 260, 190);
        let a = approved(&c, &original, current, &p1, &observed, 190);
        stage(&c, &a, &p1, 190);
        open(&c)
            .reconcile_policy_renewal(c.policy.historical(), &p1, 190)
            .expect("actual journal adoption");
        assert!(matches!(
            open(&c).policy_renewal_scope(a.scope().operation, c.policy.historical()),
            Err(DurableError::Conflict)
        ));
        expected.operation = PolicyRenewalId::generate().expect("new retained request");
        expected.previous_policy = p1.checkpoint();
        expected.previous_authorization = Some(a.statement_digest());
        assert_eq!(
            open(&c)
                .policy_renewal_scope(expected.operation, c.policy.historical())
                .expect("exact adopted predecessor"),
            expected
        );
        // Historical issuer metadata does not borrow the private signer or a
        // live policy. It still cannot release a signer/session/runtime owner.
        p1.close();
        c.policy.close();
        c.policy.runtime.close();
        let held = c.paths.signer.with_extension("scope-held");
        fs::rename(&c.paths.signer, &held).expect("private signer unavailable");
        assert_eq!(
            open(&c)
                .policy_renewal_scope(expected.operation, c.policy.historical())
                .expect("historical scope without runtime or signer"),
            expected
        );
        fs::rename(held, &c.paths.signer).expect("restore original signer");
    }
}

#[test]
fn unfinished_policy_or_credential_intent_cannot_issue_a_successor_scope() {
    for policy_pending in [false, true] {
        let (c, original, journal) = local(180, 200);
        if policy_pending {
            let p1 = policy(&c, 2, 260, 170);
            let a = approved(&c, &original, &original, &p1, &request(&c), 170);
            stage(&c, &a, &p1, 170);
        } else {
            let g = renewal::grant(&c, &original, &original, 2, 240);
            open(&c)
                .stage_credential_renewal(&g, g.operation(), &c.policy, 170)
                .expect("pending real G");
        }
        let before = files(&c);
        let config = row(&open(&c));
        assert!(matches!(
            open(&c).policy_renewal_scope(
                PolicyRenewalId::generate().expect("new operation"),
                c.policy.historical()
            ),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            open(&c).policy_renewal_request(
                PolicyRenewalId::generate().expect("new material request"),
                c.policy.historical()
            ),
            Err(DurableError::Suspended)
        ));
        assert_eq!(row(&open(&c)), config);
        assert!(files(&c) == before, "physical bytes differ");
        assert_eq!(
            open(&c).status().expect("original status"),
            EnrollmentStatus::Active(journal)
        );
    }
}

#[test]
fn request_after_real_joint_adoption_carries_exact_t_and_current_credential() {
    let (c, original, journal) = local(160, 160);
    let g = renewal::grant(&c, &original, &original, 2, 240);
    let p1 = policy(&c, 2, 260, 170);
    let t = super::super::policy_continuation::joint(
        &c,
        &g,
        &super::super::policy_continuation::scope(&c, &g, journal),
        &c.policy,
        &p1,
    );
    open(&c)
        .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
        .expect("joint G/T intent");
    open(&c)
        .reconcile_policy_continuation(c.policy.historical(), &p1, 170)
        .expect("joint G/T completion");
    let derived = request(&c);
    let mut expected = scope(&c, &original, g.successor_device(), journal);
    expected.operation = derived.operation;
    expected.previous_policy = p1.checkpoint();
    expected.previous_authorization = Some(t.statement_digest());
    assert_eq!(derived, expected);
}

#[test]
fn another_authentic_completed_approval_in_config_cannot_choose_request_predecessor() {
    let (c, original, journal) = local(160, 240);
    let p1 = policy(&c, 2, 260, 170);
    let actual = approved(&c, &original, &original, &p1, &request(&c), 170);
    stage(&c, &actual, &p1, 170);
    open(&c)
        .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("real adoption");
    let alternate = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, journal),
        170,
    );
    let mut owner = open(&c);
    let mut image = owner.image().expect("original completed image");
    let mut replacement = alternate.scope().operation.as_bytes().to_vec();
    replacement.extend_from_slice(&alternate.statement_digest());
    replacement.extend_from_slice(&alternate.target_policy().version().to_be_bytes());
    replacement.extend_from_slice(&alternate.target_policy().digest());
    replacement.extend_from_slice(&alternate.historical().journal_bytes());
    image.policy_completed = Some(
        super::super::super::policy_renewal::RetainedPolicyRenewal::decode(&mut Decoder::new(
            &replacement,
        ))
        .expect("second authentic completed record"),
    );
    owner
        .save(&image)
        .expect("MAC-valid substituted completion");
    owner.close();
    let before = assets(&c, &original);
    assert!(matches!(
        open(&c).policy_renewal_scope(
            PolicyRenewalId::generate().expect("new operation"),
            c.policy.historical()
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        assets(&c, &original),
        before,
        "actual journal approval and original assets preserved"
    );
}

#[test]
fn journal_roster_must_be_reconciled_before_request_and_next_policy_uses_that_head() {
    let (c, original, journal_id) = local(160, 240);
    let p1 = policy(&c, 2, 260, 170);
    let a = approved(&c, &original, &original, &p1, &request(&c), 170);
    stage(&c, &a, &p1, 170);
    open(&c)
        .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("original adoption");
    let (next, pin) = super::policy_roster::next_roster(&c, &original, 2, 280);
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original wrapping key"),
        &original,
        c.policy.historical(),
        None,
    )
    .expect("original journal");
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(next.as_bytes(), 175)
                .expect("pinned roster"),
            175,
        )
        .expect("independent journal advance");
    service.close();
    let before = assets(&c, &original);
    let next_operation = PolicyRenewalId::generate().expect("retained next operation");
    assert!(matches!(
        open(&c).policy_renewal_scope(next_operation, c.policy.historical()),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        assets(&c, &original),
        before,
        "stale-head refusal preserves original state"
    );
    open(&c)
        .refresh_roster(
            original.roster().checkpoint(),
            next.as_bytes(),
            &pin,
            &p1,
            205,
        )
        .expect("reconcile exact current head through original enrollment");
    assert!(matches!(
        open(&c).policy_renewal_scope(next_operation, c.policy.historical()),
        Err(DurableError::Suspended)
    ));
    open(&c)
        .reconcile_policy_renewal(c.policy.historical(), &p1, 205)
        .expect("complete exact roster update");
    let expected = open(&c)
        .policy_renewal_scope(next_operation, c.policy.historical())
        .expect("aligned actual head");
    assert_eq!(expected.current_roster, next.checkpoint());
    assert_eq!(expected.journal, journal_id);
    assert_eq!(expected.current_credential, original.credential_digest());
    assert_eq!(expected.previous_authorization, Some(a.statement_digest()));
    assert_eq!(expected.previous_policy, p1.checkpoint());
    let certificate = c
        .root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("unchanged credential");
    let current = pin
        .verify_device(&certificate, next.as_bytes(), 210)
        .expect("current member");
    let p2 = policy(&c, 3, 290, 210);
    let materials = PolicyRenewalMaterials {
        original: c.policy.historical(),
        previous: p1.historical(),
        target: &p2,
        original_device: &original,
        current_device: &current,
    };
    let statement =
        PolicyRenewalStatement::new(&expected, &materials, 210).expect("derived request");
    let issuer =
        PolicySigningKey::deterministic([82; 32], [83; 32]).expect("independent policy root");
    let second = VerifiedPolicyRenewal::verify(
        &c.root
            .approve_policy_renewal(&statement)
            .expect("account approval"),
        &issuer
            .approve_policy_renewal(&statement)
            .expect("policy approval"),
        &expected,
        &materials,
        210,
    )
    .expect("approved exact current request");
    stage(&c, &second, &p2, 210);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 210)
        .expect("original owner under derived request")
        .close();
    let revoked = c
        .root
        .issue_roster(
            3,
            Validity::new(100, 300).expect("revocation interval"),
            &[],
        )
        .expect("root-signed revocation");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        revoked.checkpoint(),
        c.policy.family(),
    )
    .expect("independent revoked head");
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        &original,
        c.policy.historical(),
        None,
    )
    .expect("original service metadata");
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(revoked.as_bytes(), 215)
                .expect("revoked roster"),
            215,
        )
        .expect("durable revocation");
    service.close();
    assert!(matches!(
        open(&c).policy_renewal_scope(
            PolicyRenewalId::generate().expect("new operation"),
            c.policy.historical()
        ),
        Err(DurableError::Conflict)
    ));
}

#[test]
fn issuer_scope_is_not_a_reservation_and_commit_refuses_later_roster_competition() {
    let (c, original, _) = local(160, 240);
    let expected = request(&c);
    let p1 = policy(&c, 2, 260, 170);
    let a = approved(&c, &original, &original, &p1, &expected, 170);
    stage(&c, &a, &p1, 170);
    let (next, pin) = super::policy_roster::next_roster(&c, &original, 2, 280);
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        &original,
        c.policy.historical(),
        None,
    )
    .expect("original journal");
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(next.as_bytes(), 175)
                .expect("independent current roster"),
            175,
        )
        .expect("competing actual update");
    service.close();
    let before = assets(&c, &original);
    assert!(matches!(
        open(&c).reconcile_policy_renewal(c.policy.historical(), &p1, 175),
        Err(DurableError::Conflict)
    ));
    assert_eq!(assets(&c, &original), before);
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("original unresolved intent"),
        pending(&a)
    );
    assert_eq!(
        open(&c)
            .pending_policy_renewal_approval(expected.operation)
            .expect("original exact approval"),
        a.as_bytes()
    );
    assert!(matches!(
        open(&c).policy_renewal_scope(
            PolicyRenewalId::generate().expect("new ID"),
            p1.historical()
        ),
        Err(DurableError::Suspended)
    ));
    eprintln!("POLICY_ONLY_REQUEST journal_derived=true actual_predecessor=true current_roster=true concurrent_update_denied=true original_pending_retained=true no_reservation=true");
}

#[test]
fn public_material_request_preserves_actual_identity_bytes_and_read_only_history() {
    for prior_g in [false, true] {
        let (c, original, journal) = local(180, if prior_g { 160 } else { 240 });
        let original_certificate = match open(&c).image().expect("original config").phase {
            Phase::Accepted { admission, .. } => Some(admission.certificate),
            Phase::Preparing | Phase::Requested(_) => None,
        }
        .expect("original accepted certificate");
        if prior_g {
            let g = renewal::grant(&c, &original, &original, 2, 240);
            open(&c)
                .stage_credential_renewal(&g, g.operation(), &c.policy, 170)
                .expect("original real G intent");
            open(&c)
                .activate(&c.policy, 170, None)
                .expect("actual G")
                .close();
        }
        let operation = PolicyRenewalId::generate().expect("actual independent operation");
        let before = assets(&c, &original);
        let expected = open(&c)
            .policy_renewal_scope(operation, c.policy.historical())
            .expect("actual scope");
        let request = open(&c)
            .policy_renewal_request(operation, c.policy.historical())
            .expect("matching identity materials");
        assert_eq!(request.scope(), &expected);
        assert_eq!(request.scope().journal, journal);
        assert_eq!(
            request.original_device().credential_digest(),
            expected.original_credential
        );
        assert_eq!(
            request.current_device().credential_digest(),
            expected.current_credential
        );
        assert_eq!(
            request.current_device().roster().checkpoint(),
            expected.current_roster
        );
        assert_eq!(request.original_roster(), original.roster().as_bytes());
        let image = open(&c).image().expect("exact retained config");
        let admission = match &image.phase {
            Phase::Accepted { admission, .. } => Some(admission),
            Phase::Preparing | Phase::Requested(_) => None,
        }
        .expect("expected original admitted configuration");
        assert_eq!(request.current_credential(), admission.certificate);
        assert_eq!(request.current_roster(), admission.roster);
        assert_eq!(request.original_credential(), original_certificate);
        assert_eq!(assets(&c, &original), before);
        let target = policy(&c, 2, 300, 190);
        let materials = request.materials(c.policy.historical(), c.policy.historical(), &target);
        assert!(crate::PolicyRenewalStatement::new(request.scope(), &materials, 190).is_ok());
        assert!(matches!(
            crate::PolicyRenewalStatement::new(request.scope(), &materials, 250),
            Err(Error::Validity)
        ));
        target.close();
        c.policy.close();
        c.policy.runtime.close();
        let held = c.paths.signer.with_extension("materials-held");
        fs::rename(&c.paths.signer, &held).expect("private signer unavailable");
        let retry = open(&c)
            .policy_renewal_request(operation, c.policy.historical())
            .expect("historical materials without signer/runtime");
        assert_eq!(retry.scope(), request.scope());
        assert_eq!(retry.original_credential(), request.original_credential());
        assert_eq!(retry.original_roster(), request.original_roster());
        assert_eq!(retry.current_credential(), request.current_credential());
        assert_eq!(retry.current_roster(), request.current_roster());
        fs::rename(held, &c.paths.signer).expect("restore owned signer");
        assert_eq!(assets(&c, &original), before);
    }
}
