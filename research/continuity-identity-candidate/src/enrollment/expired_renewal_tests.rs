// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn journal(c: &Case, original: &VerifiedDevice, identity: JournalIdentity) -> crate::DeviceJournal {
    crate::DeviceJournal::open(
        c.paths
            .installation
            .files()
            .get(1)
            .copied()
            .expect("journal path"),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        original,
        identity,
    )
    .expect("original journal")
}
fn abandoned(proof: &VerifiedCredentialRenewal, now: u64) -> CredentialRenewalStatus {
    CredentialRenewalStatus::ExpiredUncommitted {
        operation: proof.operation(),
        statement: proof.statement_digest(),
        observed_head: proof.previous_device().roster().checkpoint(),
        observed_at: now,
    }
}
fn stage(c: &Case, proof: &VerifiedCredentialRenewal) {
    open(c)
        .stage_credential_renewal(proof, proof.operation(), &c.policy, 170)
        .expect("original intent");
}
fn reconcile(
    c: &Case,
    proof: &VerifiedCredentialRenewal,
    now: u64,
) -> Result<CredentialRenewalStatus, DurableError> {
    open(c).reconcile_expired_credential_renewal(
        proof.operation(),
        proof.statement_digest(),
        &c.policy,
        now,
    )
}

#[test]
fn expired_uncommitted_intent_has_explicit_terminal_fact_and_new_root_operation_recovers_same_installation(
) {
    let (c, _, original, id) = local();
    let first = grant(&c, &original, &original, 2, 180);
    let next = grant(&c, &original, &original, 3, 190);
    stage(&c, &first);
    assert!(matches!(
        open(&c).activate(&c.policy, 185, None),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert!(
        matches!(
            open(&c).stage_credential_renewal(&next, next.operation(), &c.policy, 185),
            Err(DurableError::Conflict)
        ),
        "an expired intent is never implicitly replaced"
    );
    assert_eq!(
        open(&c).credential_renewal_status().expect("still pending"),
        pending(&first)
    );
    let before = journal(&c, &original, id).test_snapshot();
    assert_eq!(
        reconcile(&c, &first, 185).expect("explicit exact-predecessor reconciliation"),
        abandoned(&first, 185)
    );
    let after = journal(&c, &original, id).test_snapshot();
    assert_eq!(
        (before.id, before.owner, before.revision),
        (after.id, after.owner, after.revision)
    );
    assert_eq!(
        reconcile(&c, &first, 195).expect("same historical outcome"),
        abandoned(&first, 185)
    );
    assert!(matches!(
        open(&c).activate(&c.policy, 185, None),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert!(
        open(&c)
            .stage_credential_renewal(&first, first.operation(), &c.policy, 170)
            .is_err(),
        "backdating cannot reactivate the abandoned grant"
    );
    assert!(
        open(&c)
            .stage_credential_renewal(&next, next.operation(), &c.policy, 184)
            .is_err(),
        "trusted-time floor persists"
    );
    let mut owner = open(&c);
    owner
        .stage_credential_renewal(&next, next.operation(), &c.policy, 185)
        .expect("independent new root intent from unchanged C0");
    assert_eq!(
        owner
            .reconcile_expired_credential_renewal(
                first.operation(),
                first.statement_digest(),
                &c.policy,
                185
            )
            .expect("last terminal is still retained while next is pending"),
        abandoned(&first, 185)
    );
    owner.close();
    let mut active = open(&c)
        .activate(&c.policy, 185, None)
        .expect("same original installation recovers");
    let (service, _, current) = active.parts().expect("owners");
    assert_eq!(
        current.credential_digest(),
        next.successor_device().credential_digest()
    );
    let recovered = service.stores().expect("stores").0.test_snapshot();
    assert_eq!((recovered.id, recovered.owner), (before.id, before.owner));
    active.close();
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("new completion"),
        committed(&next)
    );
    assert!(
        reconcile(&c, &first, 195).is_err(),
        "forgotten older terminal is never invented"
    );
    assert!(
        matches!(
            open(&c).activate(&c.policy, 184, None),
            Err(DurableError::Protocol(Error::Validity))
        ),
        "floor survives a later successful completion"
    );
}

fn later_roster(
    c: &Case,
    original: &VerifiedDevice,
    version: u64,
    kind: &str,
) -> crate::VerifiedRoster {
    let mut description = original.description.clone();
    if kind == "generation" {
        description.generation += 1;
    }
    let certificate = c
        .root
        .issue_device(description, original.key.clone())
        .expect("later credential");
    let entries = if kind == "revoked" {
        Vec::new()
    } else {
        vec![c.root.roster_entry(&certificate).expect("member")]
    };
    let roster = c
        .root
        .issue_roster(version, interval(), &entries)
        .expect("independent head");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("current pin");
    pin.verify_roster(roster.as_bytes(), 185)
        .expect("authenticated later head")
}
#[test]
fn an_expired_journal_commit_is_reconciled_as_committed_after_later_heads_without_releasing_authority(
) {
    for later in ["unchanged", "retained", "revoked", "generation"] {
        let (c, _, original, id) = local();
        let proof = grant(&c, &original, &original, 2, 180);
        cut_renewal(&c, &proof, "journal");
        if later != "unchanged" {
            journal(&c, &original, id)
                .install_roster(&later_roster(&c, proof.successor_device(), 3, later), 185)
                .expect("later authority");
        }
        assert_eq!(
            reconcile(&c, &proof, 185).expect("historical receipt wins over expiry"),
            committed(&proof)
        );
        assert_eq!(
            reconcile(&c, &proof, 195).expect("exact completed retry"),
            committed(&proof)
        );
        assert!(
            open(&c).activate(&c.policy, 185, None).is_err(),
            "completion is not current authority"
        );
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("historical fact retained"),
            committed(&proof)
        );
    }
}
#[test]
fn no_commit_requires_proven_predecessor_history_and_expired_original_operation() {
    let (c, _, original, _) = local();
    let proof = grant(&c, &original, &original, 2, 180);
    stage(&c, &proof);
    assert!(matches!(
        reconcile(&c, &proof, 175),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert!(open(&c)
        .reconcile_expired_credential_renewal(
            CredentialRenewalId::from_trusted_state([229; 32]).expect("different ID"),
            proof.statement_digest(),
            &c.policy,
            185
        )
        .is_err());
    assert!(open(&c)
        .reconcile_expired_credential_renewal(proof.operation(), [228; 32], &c.policy, 185)
        .is_err());
    let (_, issued, pin, runtime) =
        session_policy_fixture(&[PrekeyQuality::OneTimeBoth, PrekeyQuality::ReusableBoth]);
    let wrong = pin
        .verify(issued.as_bytes(), runtime, 150)
        .expect("different signed policy");
    assert!(open(&c)
        .reconcile_expired_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &wrong,
            185
        )
        .is_err());
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("unchanged intent"),
        pending(&proof)
    );
    {
        let later = "generation";
        let (c, _, original, id) = local();
        let proof = grant(&c, &original, &original, 2, 180);
        stage(&c, &proof);
        journal(&c, &original, id)
            .install_roster(&later_roster(&c, &original, 2, later), 185)
            .expect("later head without target commit");
        assert!(
            reconcile(&c, &proof, 185).is_err(),
            "receipt absence does not prove target never committed after another head"
        );
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("unresolved exact intent"),
            pending(&proof)
        );
    }
}
#[test]
fn every_expired_terminal_config_sync_fault_recovers_pending_or_original_fact_without_journal_mutation(
) {
    let (c, _, original, _) = local();
    let proof = grant(&c, &original, &original, 2, 180);
    stage(&c, &proof);
    let (mut owner, _, count) = faulty(&c, false);
    count.store(0, Ordering::SeqCst);
    owner
        .reconcile_expired_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &c.policy,
            185,
        )
        .expect("calibrate operation boundary");
    let syncs = count.load(Ordering::SeqCst);
    owner.close();
    assert!((1..=16).contains(&syncs));
    let mut faults = 0;
    let mut pending_outcomes = 0;
    let mut terminal_outcomes = 0;
    for cut in 1..=syncs {
        for after in [false, true] {
            let (c, _, original, id) = local();
            let proof = grant(&c, &original, &original, 2, 180);
            stage(&c, &proof);
            let before = journal(&c, &original, id).test_snapshot();
            let (mut owner, fault, _) = faulty(&c, after);
            fault.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.reconcile_expired_credential_renewal(
                    proof.operation(),
                    proof.statement_digest(),
                    &c.policy,
                    185,
                ),
                after,
            );
            assert!(owner.active.is_none());
            let status = open(&c)
                .credential_renewal_status()
                .expect("unknown outcome readback");
            if status == pending(&proof) {
                pending_outcomes += 1;
            } else {
                assert_eq!(status, abandoned(&proof, 185));
                terminal_outcomes += 1;
            }
            assert_eq!(
                reconcile(&c, &proof, 185).expect("same original request"),
                abandoned(&proof, 185)
            );
            let after = journal(&c, &original, id).test_snapshot();
            assert_eq!(
                (before.id, before.owner, before.revision),
                (after.id, after.owner, after.revision)
            );
            faults += 1;
        }
    }
    assert!(pending_outcomes > 0 && terminal_outcomes > 0);
    eprintln!("EXPIRED_RENEWAL_IO barriers={syncs} faults={faults} pending={pending_outcomes} terminal={terminal_outcomes}");
}

#[test]
fn expired_renewal_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let (_, issued, pin, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let policy = pin
        .verify(issued.as_bytes(), runtime, 150)
        .expect("original policy");
    let account_root =
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("independent root"))
            .expect("root");
    let intent = EnrollmentIntent::new(
        account_root,
        DeviceDescription::new(
            [7; 16],
            1,
            policy.family(),
            Validity::new(100, 160).expect("original interval"),
        )
        .expect("original intent"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original registration");
    let CredentialRenewalStatus::Pending {
        operation,
        statement,
    } = owner.credential_renewal_status().expect("original pending")
    else {
        return Err("child requires the retained exact intent");
    };
    owner
        .reconcile_expired_credential_renewal(operation, statement, &policy, 185)
        .expect("reconcile original operation");
    Err("requested expiration boundary did not suspend child")
}
#[test]
fn process_cuts_preserve_expired_terminal_fact_and_never_relabel_an_actual_commit() {
    for (boundary, committed_target, saved) in [
        ("expiry-before-save", false, false),
        ("expiry-after-save", false, true),
        ("expiry-completion", true, true),
    ] {
        let (c, _, original, _) = local();
        let proof = grant(&c, &original, &original, 2, 180);
        if committed_target {
            cut_renewal(&c, &proof, "journal");
        } else {
            stage(&c, &proof);
        }
        cut_renewal_entry(
            &c,
            &proof,
            boundary,
            "enrollment::tests::renewal::expired_renewal::expired_renewal_process_child",
        );
        let expected = if committed_target {
            committed(&proof)
        } else if saved {
            abandoned(&proof, 185)
        } else {
            pending(&proof)
        };
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("actual persisted fact"),
            expected
        );
        let final_status = if committed_target {
            committed(&proof)
        } else {
            abandoned(&proof, 185)
        };
        assert_eq!(
            reconcile(&c, &proof, 185).expect("exact recovery"),
            final_status
        );
        assert!(open(&c).activate(&c.policy, 185, None).is_err());
    }
}
#[test]
fn expired_second_intent_reconciles_unacknowledged_first_completion_before_no_commit_classification(
) {
    let (c, _, original, id) = local();
    let first = grant(&c, &original, &original, 2, 180);
    cut_renewal(&c, &first, "completion");
    let second = grant(&c, &original, first.successor_device(), 3, 190);
    stage(&c, &second);
    assert_eq!(
        reconcile(&c, &second, 195)
            .expect("T1 receipt is acknowledged, T2 predecessor remains exact"),
        abandoned(&second, 195)
    );
    assert_eq!(
        journal(&c, &original, id)
            .roster_checkpoint(original.account_id())
            .expect("head"),
        first.successor_device().roster().checkpoint()
    );
    let third = grant(&c, &original, first.successor_device(), 4, 199);
    let mut owner = open(&c);
    owner
        .stage_credential_renewal(&third, third.operation(), &c.policy, 195)
        .expect("new exact root grant from C1");
    owner
        .activate(&c.policy, 195, None)
        .expect("same original registration recovers")
        .close();
}
#[test]
fn bounded_terminal_retention_preserves_time_floor_across_multiple_abandoned_intents() {
    let (c, _, original, _) = local();
    let first = grant(&c, &original, &original, 2, 180);
    stage(&c, &first);
    assert_eq!(
        reconcile(&c, &first, 185).expect("first"),
        abandoned(&first, 185)
    );
    let second = grant(&c, &original, &original, 3, 190);
    open(&c)
        .stage_credential_renewal(&second, second.operation(), &c.policy, 185)
        .expect("second separate intent");
    assert_eq!(
        reconcile(&c, &second, 195).expect("second"),
        abandoned(&second, 195)
    );
    assert!(
        reconcile(&c, &first, 195).is_err(),
        "older terminal outside bounded retention is unknown"
    );
    assert!(open(&c)
        .stage_credential_renewal(&first, first.operation(), &c.policy, 170)
        .is_err());
    assert!(open(&c)
        .stage_credential_renewal(&first, first.operation(), &c.policy, 196)
        .is_err());
    let third = grant(&c, &original, &original, 4, 199);
    let mut owner = open(&c);
    owner
        .stage_credential_renewal(&third, third.operation(), &c.policy, 195)
        .expect("new live target");
    owner
        .activate(&c.policy, 195, None)
        .expect("same original registration")
        .close();
}

#[test]
fn authenticated_expired_receipt_cannot_drop_its_floor_or_forge_expiry_order() {
    for mutation in [0, 1, 2] {
        let (c, _, original, _) = local();
        let proof = grant(&c, &original, &original, 2, 180);
        stage(&c, &proof);
        reconcile(&c, &proof, 185).expect("actual terminal");
        let mut owner = open(&c);
        let image = owner.image().expect("roundtrip image");
        let key = JournalKey::open(&c.paths.wrapping).expect("original wrapping owner");
        let mut wire = encode(&key, owner.binding, &image).expect("canonical extended image");
        assert_eq!(wire.get(..8), Some(b"QPENST03".as_slice()));
        assert!(wire.len() <= MAX_RENEWAL_IMAGE);
        wire.truncate(wire.len() - 32);
        let length = wire.len();
        let (offset, value) = match mutation {
            0 => (length - 129, 0u64),  // Extended format cannot omit the time floor.
            1 => (length - 16, 186u64), // Claimed target expiry after the observation.
            _ => (length - 8, 184u64),  // The last terminal no longer matches its floor.
        };
        wire.get_mut(offset..offset + 8)
            .expect("fixed receipt field")
            .copy_from_slice(&value.to_be_bytes());
        let mut mac = auth(&key).expect("authenticated negative control");
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        write(
            &owner.active.as_ref().expect("same config owner").database,
            &wire,
        )
        .expect("authenticated malformed test state");
        assert!(matches!(
            owner.credential_renewal_status(),
            Err(DurableError::Corrupt)
        ));
        assert!(owner.active.is_none());
    }
}

#[test]
fn expired_intent_reconciles_roster_only_advancement_and_new_grant_still_uses_exact_current_head() {
    for later in ["retained", "revoked"] {
        let (c, _, original, id) = local();
        let proof = grant(&c, &original, &original, 2, 180);
        stage(&c, &proof);
        let roster = later_roster(&c, &original, 2, later);
        journal(&c, &original, id)
            .install_roster(&roster, 175)
            .expect("concurrent authority update");
        assert!(matches!(reconcile(&c,&proof,185),Ok(CredentialRenewalStatus::ExpiredUncommitted { .. })),
            "unchanged same-generation credential history proves the expired target never committed despite later roster head");
        if later == "retained" {
            let original_wire = c
                .root
                .issue_device(original.description.clone(), original.key.clone())
                .expect("same previous credential");
            let pin = AccountPin::new(
                original.account_id(),
                c.intent.root.clone(),
                roster.checkpoint(),
                c.policy.family(),
            )
            .expect("independent current roster pin");
            let previous = pin
                .verify_device(&original_wire, roster.as_bytes(), 150)
                .expect("historical credential under newer root roster");
            let next = grant(&c, &original, &previous, 3, 190);
            let mut owner = open(&c);
            owner
                .stage_credential_renewal(&next, next.operation(), &c.policy, 185)
                .expect("new root intent uses actual current predecessor");
            owner
                .activate(&c.policy, 185, None)
                .expect("same registration resumes across unrelated roster update")
                .close();
        } else {
            let next = grant(&c, &original, &original, 3, 190);
            let mut owner = open(&c);
            owner
                .stage_credential_renewal(&next, next.operation(), &c.policy, 185)
                .expect("retained metadata does not itself know a newer journal head");
            assert!(
                owner.activate(&c.policy, 185, None).is_err(),
                "historical NoCommit never reauthorizes a revoked device"
            );
        }
    }
}

#[test]
fn old_pending_config_with_pruned_receipt_never_turns_installed_target_history_into_no_commit() {
    for later in ["target", "revoked", "generation"] {
        let (c, _, original, id) = local();
        let proof = grant(&c, &original, &original, 2, 180);
        stage(&c, &proof);
        let mut owner = open(&c);
        let image = owner.image().expect("old pending snapshot");
        let key = JournalKey::open(&c.paths.wrapping).expect("key");
        let pending_wire =
            encode(&key, owner.binding, &image).expect("authenticated old configuration");
        owner
            .activate(&c.policy, 170, None)
            .expect("actual commit, config completion and receipt acknowledgement")
            .close();
        if later != "target" {
            journal(&c, &original, id)
                .install_roster(&later_roster(&c, proof.successor_device(), 3, later), 185)
                .expect("later authoritative state");
        }
        let mut restored = open(&c);
        write(
            &restored
                .active
                .as_ref()
                .expect("configuration lease")
                .database,
            &pending_wire,
        )
        .expect("simulate restoration of the older authenticated config only");
        restored.close();
        assert!(
            matches!(reconcile(&c, &proof, 185), Err(DurableError::Conflict)),
            "missing receipt plus successor or higher-generation history cannot prove NoCommit"
        );
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("unresolved rollback remains explicit"),
            pending(&proof)
        );
    }
}
