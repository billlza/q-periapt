// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::policy_continuation::policy;
use super::*;
#[path = "policy_renewal_connection_tests.rs"]
mod connection;
#[path = "policy_renewal_credential_tests.rs"]
mod credential;
#[path = "credential_request_tests.rs"]
mod credential_request;
#[path = "policy_renewal_owner_tests.rs"]
mod owner;
#[path = "policy_renewal_roster_tests.rs"]
mod policy_roster;
#[path = "policy_renewal_recovery_tests.rs"]
mod recovery;
#[path = "policy_renewal_request_tests.rs"]
mod request;
#[path = "policy_renewal_resolution_tests.rs"]
mod resolution;
#[path = "roster_resolution_tests.rs"]
mod roster_resolution;
use crate::{
    HistoricalPolicyRenewal, PolicyRenewalId, PolicyRenewalMaterials, PolicyRenewalScope,
    PolicyRenewalStatement, PolicyRenewalStatus, PolicySigningKey, Validity, VerifiedPolicyRenewal,
};

fn local(policy_until: u64, credential_until: u64) -> (Case, VerifiedDevice, JournalIdentity) {
    let mut c = case();
    c.policy = policy(&c, 1, policy_until, 150);
    c.intent.description.validity = Validity::new(100, credential_until).expect("credential time");
    let (mut owner, _, journal) = accepted(&c);
    let image = owner.image().expect("accepted image");
    let original = owner
        .admitted(&image, &c.policy, 150)
        .expect("original C/R");
    owner
        .prepare(&c.policy, 150)
        .expect("original installation children");
    owner
        .activate(&c.policy, 150, None)
        .expect("original active service")
        .close();
    (c, original, journal)
}
fn scope(
    c: &Case,
    original: &VerifiedDevice,
    current: &VerifiedDevice,
    journal: JournalIdentity,
) -> PolicyRenewalScope {
    PolicyRenewalScope {
        operation: PolicyRenewalId::generate().expect("independent operation"),
        journal,
        original_owner: crate::bootstrap::storage_owner(original),
        original_credential: original.credential_digest(),
        current_credential: current.credential_digest(),
        current_roster: current.roster().checkpoint(),
        original_policy: c.policy.checkpoint(),
        previous_policy: c.policy.checkpoint(),
        previous_authorization: None,
    }
}
fn approved(
    c: &Case,
    original: &VerifiedDevice,
    current: &VerifiedDevice,
    target: &VerifiedSessionPolicy,
    scope: &PolicyRenewalScope,
    now: u64,
) -> VerifiedPolicyRenewal {
    let materials = PolicyRenewalMaterials {
        original: c.policy.historical(),
        previous: c.policy.historical(),
        target,
        original_device: original,
        current_device: current,
    };
    let statement =
        PolicyRenewalStatement::new(scope, &materials, now).expect("policy-only request");
    let issuer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("original policy root");
    let a = c
        .root
        .approve_policy_renewal(&statement)
        .expect("account approval");
    let p = issuer
        .approve_policy_renewal(&statement)
        .expect("policy approval");
    VerifiedPolicyRenewal::verify(&a, &p, scope, &materials, now).expect("independent approvals")
}
fn pending(approval: &VerifiedPolicyRenewal) -> PolicyRenewalStatus {
    PolicyRenewalStatus::Pending {
        operation: approval.scope().operation,
        statement: approval.statement_digest(),
        target: approval.target_policy(),
    }
}
pub(super) fn row(owner: &DeviceEnrollment) -> Vec<u8> {
    let tx = owner
        .active
        .as_ref()
        .expect("lease")
        .database
        .begin_read()
        .expect("read");
    tx.open_table(TABLE)
        .expect("table")
        .get("enrollment")
        .expect("get")
        .expect("row")
        .value()
        .to_vec()
}
fn files(c: &Case) -> Vec<Vec<u8>> {
    std::iter::once(c.paths.signer.as_path())
        .chain(c.paths.installation.files())
        .map(|p| fs::read(p).expect("original asset"))
        .collect()
}
fn stage(c: &Case, approval: &VerifiedPolicyRenewal, target: &VerifiedSessionPolicy, now: u64) {
    assert_eq!(
        open(c)
            .stage_policy_renewal(
                approval,
                approval.scope().operation,
                c.policy.historical(),
                target,
                now
            )
            .expect("durable policy-only intent"),
        pending(approval)
    );
}

#[test]
fn expired_p0_pending_reopens_with_exact_first_approvals_and_unchanged_assets() {
    let (c, original, journal) = local(160, 200);
    let target = policy(&c, 2, 230, 170);
    let expected = scope(&c, &original, &original, journal);
    let first = approved(&c, &original, &original, &target, &expected, 170);
    let again = approved(&c, &original, &original, &target, &expected, 170);
    assert_eq!(first.statement_digest(), again.statement_digest());
    assert_ne!(
        first.as_bytes(),
        again.as_bytes(),
        "distinct valid randomized signatures"
    );
    let before = files(&c);
    assert!(c
        .policy
        .check_mode(PrekeyQuality::OneTimeBoth, 170)
        .is_err());
    let mut owner = open(&c);
    let signer_id = owner.identity().expect("original signer identity");
    assert_eq!(
        owner.policy_renewal_status().expect("no policy intent"),
        PolicyRenewalStatus::Absent
    );
    owner.close();
    stage(&c, &first, &target, 170);
    let mut owner = open(&c);
    let saved = row(&owner);
    assert_eq!(saved.get(..8), Some(b"QPENST09".as_slice()));
    assert_eq!(
        owner
            .stage_policy_renewal(
                &again,
                expected.operation,
                c.policy.historical(),
                &target,
                175
            )
            .expect("same statement, retain first signatures"),
        pending(&first)
    );
    assert_eq!(row(&owner), saved);
    assert_eq!(
        owner
            .pending_policy_renewal_approval(expected.operation)
            .expect("exact original bytes"),
        first.as_bytes()
    );
    assert_eq!(owner.identity().expect("identity"), signer_id);
    assert_eq!(
        owner.credential_renewal_status().expect("G remains absent"),
        CredentialRenewalStatus::Absent
    );
    assert_eq!(
        owner.status().expect("original installation state"),
        EnrollmentStatus::Active(journal)
    );
    assert_eq!(files(&c), before);
    owner.close();
    // Metadata remains readable without a live policy/runtime or a private signer.
    target.close();
    let held = c.paths.signer.with_extension("held");
    fs::rename(&c.paths.signer, &held).expect("temporarily unavailable original signer");
    let mut owner = open(&c);
    assert_eq!(
        owner.policy_renewal_status().expect("historical status"),
        pending(&first)
    );
    assert_eq!(
        owner
            .pending_policy_renewal_approval(expected.operation)
            .expect("historical approvals"),
        first.as_bytes()
    );
    assert_eq!(row(&owner), saved);
    owner.close();
    fs::rename(held, &c.paths.signer).expect("restore original signer");
}

#[test]
fn pending_blocks_legacy_capabilities_and_mutations_before_touching_children() {
    let (c, original, journal) = local(180, 200);
    let target = policy(&c, 2, 230, 170);
    let approval = approved(
        &c,
        &original,
        &original,
        &target,
        &scope(&c, &original, &original, journal),
        170,
    );
    let g = renewal::grant(&c, &original, &original, 2, 240);
    stage(&c, &approval, &target, 170);
    let mut owner = open(&c);
    let saved = row(&owner);
    let image = owner.image().expect("pending image");
    let admission = match image.phase {
        Phase::Accepted { admission, .. } => Ok(admission),
        _ => Err("expected active admission"),
    }
    .expect("active phase");
    owner.close();
    let before = files(&c);
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.intent.root.clone(),
        admission.checkpoint,
        c.policy.family(),
    )
    .expect("pin");
    #[derive(Debug)]
    enum Entry {
        Accept,
        Refresh,
        Prepare,
        StageG,
        JointReconcile,
        HistoricalReconcile,
        ExpiredG,
    }
    for entry in [
        Entry::Accept,
        Entry::Refresh,
        Entry::Prepare,
        Entry::StageG,
        Entry::JointReconcile,
        Entry::HistoricalReconcile,
        Entry::ExpiredG,
    ] {
        let mut owner = open(&c);
        let result = match entry {
            Entry::Accept => owner
                .accept(
                    &admission.certificate,
                    &admission.roster,
                    &pin,
                    &c.policy,
                    170,
                )
                .map(|_| ()),
            Entry::Refresh => owner
                .refresh_roster(
                    admission.checkpoint,
                    &admission.roster,
                    &pin,
                    &c.policy,
                    170,
                )
                .map(|_| ()),
            Entry::Prepare => owner.prepare(&c.policy, 170).map(|_| ()),
            Entry::StageG => owner
                .stage_credential_renewal(&g, g.operation(), &c.policy, 170)
                .map(|_| ()),
            Entry::JointReconcile => owner
                .reconcile_policy_continuation(c.policy.historical(), &target, 170)
                .map(|_| ()),
            Entry::HistoricalReconcile => owner
                .recover_historical_policy_continuation(
                    g.operation(),
                    g.statement_digest(),
                    c.policy.historical(),
                    target.historical(),
                    170,
                )
                .map(|_| ()),
            Entry::ExpiredG => owner
                .reconcile_expired_credential_renewal(
                    g.operation(),
                    g.statement_digest(),
                    &c.policy,
                    250,
                )
                .map(|_| ()),
        };
        assert!(
            matches!(result, Err(DurableError::Suspended)),
            "{entry:?}: {result:?}"
        );
        assert!(
            matches!(owner.status(), Err(DurableError::Closed)),
            "failed owner closes"
        );
        assert_eq!(row(&open(&c)), saved, "{entry:?}");
        assert_eq!(files(&c), before, "{entry:?}");
    }
    assert!(matches!(
        open(&c).activate(&c.policy, 170, None),
        Err(DurableError::Suspended)
    ));
    assert_eq!(row(&open(&c)), saved);
    assert_eq!(files(&c), before);
    struct NoExchange(Arc<AtomicUsize>);
    impl AnchorTransport for NoExchange {
        fn exchange(&mut self, _: &[u8], _: std::time::Instant) -> std::io::Result<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
    let witness_key = RootSigningKey::generate().expect("independent witness fixture");
    let witness_pin = AnchorPin::new(
        crate::AnchorIdentity::generate().expect("witness ID"),
        witness_key.public_key().expect("public witness key"),
    );
    let exchanges = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        open(&c).anchor_client(
            &c.policy,
            170,
            witness_pin,
            Box::new(NoExchange(Arc::clone(&exchanges))),
            Duration::from_secs(1)
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        0,
        "Pending never contacted witness"
    );
    assert_eq!(row(&open(&c)), saved);
    assert_eq!(files(&c), before);
}

#[test]
fn completed_g_history_and_current_cr_survive_policy_only_staging() {
    let (c, original, journal) = local(180, 160);
    let g = renewal::grant(&c, &original, &original, 2, 240);
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &c.policy, 170)
        .expect("G intent");
    open(&c)
        .activate(&c.policy, 170, None)
        .expect("real original G commit")
        .close();
    let mut owner = open(&c);
    let before_image = owner.image().expect("G completion");
    let mut before_history = Vec::new();
    before_image
        .renewal
        .as_ref()
        .expect("G history")
        .encode(&mut before_history)
        .expect("old history bytes");
    let before_row = row(&owner);
    assert_eq!(before_row.get(..8), Some(b"QPENST02".as_slice()));
    let key = JournalKey::open(&c.paths.wrapping).expect("key");
    assert_eq!(
        encode(&key, owner.binding, &before_image).expect("legacy round trip"),
        before_row
    );
    owner.close();
    let before = files(&c);
    let target = policy(&c, 2, 260, 190);
    let current = g.successor_device();
    let approval = approved(
        &c,
        &original,
        current,
        &target,
        &scope(&c, &original, current, journal),
        190,
    );
    stage(&c, &approval, &target, 190);
    let mut owner = open(&c);
    let image = owner.image().expect("separate policy-only intent");
    let mut history = Vec::new();
    image
        .renewal
        .as_ref()
        .expect("preserved G history")
        .encode(&mut history)
        .expect("history bytes");
    assert_eq!(history, before_history);
    let (prior, next) = match (before_image.phase, image.phase) {
        (
            Phase::Accepted {
                admission: prior, ..
            },
            Phase::Accepted {
                admission: next, ..
            },
        ) => Ok((prior, next)),
        _ => Err("expected two active admissions"),
    }
    .expect("admission");
    assert_eq!(
        (
            next.certificate,
            next.roster,
            next.checkpoint,
            next.policy,
            next.journal
        ),
        (
            prior.certificate,
            prior.roster,
            prior.checkpoint,
            prior.policy,
            prior.journal
        )
    );
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("independent G status"),
        renewal::committed(&g)
    );
    assert_eq!(
        owner.policy_renewal_status().expect("policy status"),
        pending(&approval)
    );
    assert_eq!(files(&c), before);
}

#[test]
fn pending_rechecks_current_cr_target_and_runtime_and_refuses_other_operation() {
    let (c, original, journal) = local(160, 200);
    let target = policy(&c, 2, 230, 170);
    let expected = scope(&c, &original, &original, journal);
    let approval = approved(&c, &original, &original, &target, &expected, 170);
    let before = row(&open(&c));
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &approval,
            expected.operation,
            c.policy.historical(),
            &target,
            200
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert_eq!(
        row(&open(&c)),
        before,
        "stale typed approval cannot revive C/R"
    );
    stage(&c, &approval, &target, 170);
    let saved = row(&open(&c));
    let other_target = policy(&c, 3, 260, 170);
    let another = approved(&c, &original, &original, &other_target, &expected, 170);
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &another,
            expected.operation,
            c.policy.historical(),
            &other_target,
            170
        ),
        Err(DurableError::Conflict)
    ));
    let other_op = PolicyRenewalId::generate().expect("different operation");
    assert!(matches!(
        open(&c).pending_policy_renewal_approval(other_op),
        Err(DurableError::Conflict)
    ));
    target.close();
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &approval,
            expected.operation,
            c.policy.historical(),
            &target,
            170
        ),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("readable after close"),
        pending(&approval)
    );
    assert_eq!(row(&open(&c)), saved);
}

pub(super) fn replace_authenticated(c: &Case, bytes: &[u8]) {
    let key =
        JournalKey::open(&c.paths.wrapping).expect("wrapping capability for corruption fixture");
    let mut bytes = bytes.to_vec();
    let n = bytes.len().checked_sub(32).expect("MAC");
    let mut mac = auth(&key).expect("auth");
    mac.update(bytes.get(..n).expect("body"));
    bytes
        .get_mut(n..)
        .expect("MAC slot")
        .copy_from_slice(&mac.finalize().into_bytes());
    let db = open_private_database(&c.paths.configuration).expect("original config file");
    write(&db, &bytes).expect("retained malformed fixture");
}

#[test]
fn new_codec_rejects_substituted_approvals_tail_and_nonactive_phase() {
    let (c, original, journal) = local(160, 200);
    let target = policy(&c, 2, 230, 170);
    let expected = scope(&c, &original, &original, journal);
    let approval = approved(&c, &original, &original, &target, &expected, 170);
    let other = policy(&c, 3, 260, 170);
    let substitute = approved(&c, &original, &original, &other, &expected, 170);
    stage(&c, &approval, &target, 170);
    let saved = row(&open(&c));
    let retained = approval.historical().journal_bytes();
    let offset = saved
        .windows(retained.len())
        .position(|p| p == retained)
        .expect("exact retained bytes");
    let mut swapped = saved.clone();
    swapped
        .get_mut(offset..offset + retained.len())
        .expect("same-width material")
        .copy_from_slice(&substitute.historical().journal_bytes());
    let mut bad_signature = saved.clone();
    *bad_signature
        .get_mut(offset + retained.len() - 1)
        .expect("last signature byte") ^= 1;
    let mut inactive = saved.clone();
    *inactive.get_mut(72).expect("phase") = 2;
    let mut tail = saved.clone();
    tail.insert(tail.len() - 32, 0);
    for malformed in [swapped, bad_signature, inactive, tail] {
        replace_authenticated(&c, &malformed);
        assert!(DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err());
        replace_authenticated(&c, &saved);
        assert_eq!(row(&open(&c)), saved, "no implicit repair or replacement");
    }
    let mut owner = open(&c);
    let mut image = owner.image().expect("valid Pending");
    let (stage, admission) = match &mut image.phase {
        Phase::Accepted {
            stage, admission, ..
        } => Ok((stage, admission)),
        _ => Err("expected active phase"),
    }
    .expect("phase");
    *stage = AdmissionPhase::Refreshing {
        previous: admission.checkpoint,
    };
    assert!(matches!(
        encode(
            &JournalKey::open(&c.paths.wrapping).expect("key"),
            owner.binding,
            &image
        ),
        Err(DurableError::Corrupt)
    ));
}

#[test]
fn existing_g_pending_refuses_policy_only_intent_without_replacing_either_record() {
    let (c, original, journal) = local(180, 200);
    let g = renewal::grant(&c, &original, &original, 2, 240);
    let target = policy(&c, 2, 230, 170);
    let approval = approved(
        &c,
        &original,
        &original,
        &target,
        &scope(&c, &original, &original, journal),
        170,
    );
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &c.policy, 170)
        .expect("original G Pending");
    let saved = row(&open(&c));
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &approval,
            approval.scope().operation,
            c.policy.historical(),
            &target,
            170
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(row(&open(&c)), saved);
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("independent policy state"),
        PolicyRenewalStatus::Absent
    );
    let mut owner = open(&c);
    let mut image = owner.image().expect("original G Pending");
    let mut old_history = Vec::new();
    image
        .renewal
        .as_ref()
        .expect("G history")
        .encode(&mut old_history)
        .expect("old encoding");
    let mut independent = approval.scope().operation.as_bytes().to_vec();
    independent.extend_from_slice(&approval.statement_digest());
    independent.extend_from_slice(&approval.target_policy().version().to_be_bytes());
    independent.extend_from_slice(&approval.target_policy().digest());
    independent.extend_from_slice(&approval.historical().journal_bytes());
    let mut d = Decoder::new(&independent);
    image.policy_pending =
        Some(RetainedPolicyRenewal::decode(&mut d).expect("bounded policy record"));
    d.finish().expect("exact bytes");
    assert!(
        matches!(
            encode(
                &JournalKey::open(&c.paths.wrapping).expect("key"),
                owner.binding,
                &image
            ),
            Err(DurableError::Corrupt)
        ),
        "encoder refuses two pending domains"
    );
    owner.close();
    let base_end = saved.len() - 32 - old_history.len();
    let mut both = saved
        .get(..base_end)
        .expect("original common body")
        .to_vec();
    both.get_mut(..8)
        .expect("version")
        .copy_from_slice(b"QPENST09");
    both.extend_from_slice(b"QPENST02");
    both.extend_from_slice(&old_history);
    both.extend_from_slice(&independent);
    both.extend_from_slice(&[0; 32]);
    replace_authenticated(&c, &both);
    assert!(
        matches!(
            DeviceEnrollment::open(c.paths.clone(), c.intent.clone()),
            Err(DurableError::Corrupt)
        ),
        "decoder refuses two pending domains even with a valid configuration MAC"
    );
    replace_authenticated(&c, &saved);
    assert_eq!(row(&open(&c)), saved);
}

#[test]
fn policy_pending_refuses_unadopted_predecessor_and_foreign_journal() {
    let (c, original, journal) = local(160, 200);
    let target = policy(&c, 2, 230, 170);
    let mut expected = scope(&c, &original, &original, journal);
    expected.journal = JournalIdentity::generate().expect("foreign journal");
    let foreign = approved(&c, &original, &original, &target, &expected, 170);
    let before = row(&open(&c));
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &foreign,
            expected.operation,
            c.policy.historical(),
            &target,
            170
        ),
        Err(DurableError::Conflict)
    ));
    let p2 = policy(&c, 3, 260, 170);
    expected.journal = journal;
    expected.previous_policy = target.checkpoint();
    expected.previous_authorization = Some(foreign.statement_digest());
    let materials = PolicyRenewalMaterials {
        original: c.policy.historical(),
        previous: target.historical(),
        target: &p2,
        original_device: &original,
        current_device: &original,
    };
    let request = PolicyRenewalStatement::new(&expected, &materials, 170)
        .expect("valid signed relation is not adoption");
    let issuer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy root");
    let a = c
        .root
        .approve_policy_renewal(&request)
        .expect("account approval");
    let p = issuer
        .approve_policy_renewal(&request)
        .expect("policy approval");
    let unadopted =
        VerifiedPolicyRenewal::verify(&a, &p, &expected, &materials, 170).expect("typed relation");
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &unadopted,
            expected.operation,
            c.policy.historical(),
            &p2,
            170
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(row(&open(&c)), before);
}

#[test]
fn expired_target_and_expired_roster_are_independent_stage_failures() {
    for (credential_until, target_until, now) in [(240, 190, 190), (240, 260, 200)] {
        let (c, original, journal) = local(160, credential_until);
        let target = policy(&c, 2, target_until, 170);
        let approval = approved(
            &c,
            &original,
            &original,
            &target,
            &scope(&c, &original, &original, journal),
            170,
        );
        original
            .description
            .validity
            .check(now)
            .expect("credential remains current");
        if target_until == 190 {
            original
                .roster_validity
                .check(now)
                .expect("roster remains current");
        } else {
            target
                .check_mode(PrekeyQuality::OneTimeBoth, now)
                .expect("target remains current");
        }
        let saved = row(&open(&c));
        assert!(matches!(
            open(&c).stage_policy_renewal(
                &approval,
                approval.scope().operation,
                c.policy.historical(),
                &target,
                now
            ),
            Err(DurableError::Protocol(Error::Validity))
        ));
        assert_eq!(row(&open(&c)), saved);
    }
}

#[test]
fn policy_pending_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_POLICY_ONLY_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let original_policy = policy(&template, 1, 160, 150);
    let target = policy(&template, 2, 230, 170);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("independent root"))
            .expect("root"),
        DeviceDescription::new([7; 16], 1, original_policy.family(), interval()).expect("intent"),
    );
    let history = HistoricalPolicyRenewal::from_authority(
        &fs::read(root.join("public-approval")).expect("public approvals"),
        &intent.root,
        intent.description.family,
    )
    .expect("historical signatures");
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    let image = owner.image().expect("original state");
    let original = owner
        .original_device(&image, 170)
        .expect("original metadata/signer");
    let materials = PolicyRenewalMaterials {
        original: original_policy.historical(),
        previous: original_policy.historical(),
        target: &target,
        original_device: &original,
        current_device: &original,
    };
    let approval =
        VerifiedPolicyRenewal::from_bytes(history.as_bytes(), history.scope(), &materials, 170)
            .expect("current approval");
    owner
        .stage_policy_renewal(
            &approval,
            approval.scope().operation,
            original_policy.historical(),
            &target,
            170,
        )
        .expect("stage");
    Err("commit boundary did not stop the child")
}

#[test]
fn process_kill_after_policy_pending_commit_recovers_original_operation_and_bytes() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (c, original, journal) = local(160, 200);
    let target = policy(&c, 2, 230, 170);
    let approval = approved(
        &c,
        &original,
        &original,
        &target,
        &scope(&c, &original, &original, journal),
        170,
    );
    let before = files(&c);
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("root pin");
    fs::write(
        root.join("public-approval"),
        approval.historical().journal_bytes(),
    )
    .expect("public input");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "enrollment::tests::policy_renewal::policy_pending_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_POLICY_ONLY_CUT_ROOT", root)
            .env("QPERIAPT_ENROLLMENT_CUT_ROOT", root)
            .env("QPERIAPT_ENROLLMENT_CUT_PHASE", "4")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("real child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("committed").exists() {
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "child did not reach durable policy Pending"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child
        .0
        .kill()
        .expect("interrupt after durable commit, before successful response");
    assert!(!child.0.wait().expect("reap child").success());
    let mut owner = open(&c);
    assert_eq!(
        owner
            .policy_renewal_status()
            .expect("unknown commit readback"),
        pending(&approval)
    );
    assert_eq!(
        owner
            .pending_policy_renewal_approval(approval.scope().operation)
            .expect("original bytes"),
        approval.as_bytes()
    );
    let saved = row(&owner);
    assert_eq!(
        owner
            .stage_policy_renewal(
                &approval,
                approval.scope().operation,
                c.policy.historical(),
                &target,
                175
            )
            .expect("exact retry"),
        pending(&approval)
    );
    assert_eq!(row(&owner), saved);
    assert_eq!(files(&c), before);
    eprintln!("POLICY_ONLY_PENDING_PROCESS_CUT original_operation=true exact_approvals=true unchanged_cr_signer_children=true operational_owner_released=false");
}
