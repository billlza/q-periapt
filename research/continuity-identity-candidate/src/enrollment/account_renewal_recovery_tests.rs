// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original account intent recovery and authenticated format boundaries.
use super::*;

#[test]
fn earliest_companion_expiry_closes_only_an_uncommitted_complete_account_target() {
    for committed in [false, true] {
        let c = AccountCase::with_companion_expiry(false, 175);
        if committed {
            super::session::renew(&c, 0, &c.f.c.paths, &c.f.c.intent).close();
        } else {
            let mut owner = open(&c.f.c);
            c.stage(&mut owner);
            owner.close();
            assert!(matches!(
                open(&c.f.c).activate(&c.f.c.policy, 178, None),
                Err(DurableError::Protocol(Error::Validity))
            ));
        }
        let mut owner = open(&c.f.c);
        let outcome = owner
            .reconcile_expired_credential_renewal(
                c.grant(0).operation(),
                c.grant(0).statement_digest(),
                &c.f.c.policy,
                178,
            )
            .expect("classify earliest complete-target expiry");
        if committed {
            assert_eq!(outcome, renewal::committed(c.grant(0)));
        } else {
            assert_eq!(
                outcome,
                CredentialRenewalStatus::ExpiredUncommitted {
                    operation: c.grant(0).operation(),
                    statement: c.grant(0).statement_digest(),
                    observed_head: c.f.original.roster().checkpoint(),
                    observed_at: 178,
                }
            );
            owner.close();
            assert_eq!(
                open(&c.f.c)
                    .reconcile_expired_credential_renewal(
                        c.grant(0).operation(),
                        c.grant(0).statement_digest(),
                        &c.f.c.policy,
                        178
                    )
                    .expect("retained original disposition"),
                outcome
            );
            assert!(open(&c.f.c)
                .stage_account_credential_renewal(
                    c.grant(0),
                    &[c.grant(1), c.grant(2)],
                    c.grant(0).operation(),
                    &c.f.c.policy,
                    174
                )
                .is_err());
        }
    }
}

#[test]
fn a_later_single_local_renewal_supersedes_the_completed_group_without_losing_prior_ack() {
    for witnessed in [false, true] {
        let c = AccountCase::new(witnessed);
        let signer = fs::read(&c.f.c.paths.signer).expect("original signer");
        super::session::renew(&c, 0, &c.f.c.paths, &c.f.c.intent).close();
        let previous = c.grant(0).successor_device();
        let successor =
            c.f.c
                .root
                .issue_credential_extension(previous, 195, 175)
                .expect("next same-key credential");
        let peers = [c.grant(1), c.grant(2)];
        let mut entries = vec![c.f.c.root.roster_entry(&successor).expect("local member")];
        for peer in peers {
            entries.push(
                c.f.c
                    .root
                    .roster_entry(peer.successor_credential().expect("peer credential"))
                    .expect("unchanged peer"),
            );
        }
        let roster =
            c.f.c
                .root
                .issue_roster(3, interval(), &entries)
                .expect("next common roster");
        let pin = AccountPin::new(
            c.f.original.account_id(),
            c.f.c.intent.root.clone(),
            roster.checkpoint(),
            c.f.c.policy.family(),
        )
        .expect("new independent target");
        let operation = crate::CredentialRenewalId::generate().expect("next original operation");
        let issued =
            c.f.c
                .root
                .issue_credential_renewal(
                    CredentialRenewalMaterials {
                        original_credential: c.certificate(0),
                        previous_credential: c
                            .grant(0)
                            .successor_credential()
                            .expect("previous credential"),
                        successor_credential: &successor,
                        previous_roster: previous.roster().as_bytes(),
                        successor_roster: roster.as_bytes(),
                    },
                    &CredentialRenewalAuthorization {
                        operation,
                        previous: previous.roster().checkpoint(),
                        policy_digest: c.f.c.policy.checkpoint().digest(),
                    },
                    &pin,
                    175,
                )
                .expect("new single-device grant");
        let proof = VerifiedCredentialRenewal::verify(
            issued.as_bytes(),
            &pin,
            c.f.c.policy.checkpoint().digest(),
            175,
        )
        .expect("verify next G");
        let mut owner = open(&c.f.c);
        owner
            .stage_credential_renewal(&proof, operation, &c.f.c.policy, 175)
            .expect("ordinary next G retains prior completion");
        let encoded = encode(
            &JournalKey::open(&c.f.c.paths.wrapping).expect("key"),
            owner.binding,
            &owner.image().expect("pending"),
        )
        .expect("encode pending");
        assert_eq!(encoded.get(..8), Some(b"QPENST20".as_slice()));
        owner.close();
        let mut owner = open(&c.f.c);
        if witnessed {
            c.f.carrier.clock.store(175, Ordering::SeqCst);
            let anchor = client(&c.f, &mut owner, 175);
            let proposal = owner
                .prepare_witnessed_credential_renewal(&c.f.c.policy, 175, anchor)
                .expect("next original target");
            c.f.carrier
                .store
                .lock()
                .expect("witness")
                .prepare_credential_renewal(proposal, &proof, &c.f.c.policy, 175)
                .expect("next witness approval");
            let mut anchor = client(&c.f, &mut owner, 175);
            owner
                .commit_witnessed_credential_renewal(
                    operation,
                    proof.statement_digest(),
                    &c.f.c.policy,
                    175,
                    &mut anchor,
                )
                .expect("next exact completion");
        }
        let anchor = if witnessed {
            Some(client(&c.f, &mut owner, 175))
        } else {
            None
        };
        let mut active = owner
            .activate(&c.f.c.policy, 175, anchor)
            .expect("next owner");
        let (service, protected, current) = active.parts().expect("current owners");
        assert_eq!(
            current.credential_digest(),
            proof.successor_device().credential_digest()
        );
        protected
            .check_device(current)
            .expect("original protected key");
        assert_eq!(
            service
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("journal"),
            c.f.id
        );
        active.close();
        let mut owner = open(&c.f.c);
        let encoded = encode(
            &JournalKey::open(&c.f.c.paths.wrapping).expect("key"),
            owner.binding,
            &owner.image().expect("completed"),
        )
        .expect("encode completed");
        assert_ne!(encoded.get(..8), Some(b"QPENST20".as_slice()));
        assert_eq!(
            owner
                .credential_renewal_status()
                .expect("latest completion"),
            renewal::committed(&proof)
        );
        assert_eq!(fs::read(&c.f.c.paths.signer).expect("same signer"), signer);
    }
}

#[test]
fn account_renewal_preserves_complete_receipt_under_previously_adopted_policy() {
    let c = AccountCase::new(false);
    let p1 = crate::enrollment::tests::policy_continuation::policy(&c.f.c, 2, 280, 150);
    let mut owner = open(&c.f.c);
    let scope = owner
        .policy_renewal_scope(
            crate::PolicyRenewalId::generate().expect("policy operation"),
            c.f.c.policy.historical(),
        )
        .expect("original policy scope");
    let materials = crate::PolicyRenewalMaterials {
        original: c.f.c.policy.historical(),
        previous: c.f.c.policy.historical(),
        target: &p1,
        original_device: &c.f.original,
        current_device: &c.f.original,
    };
    let statement = crate::PolicyRenewalStatement::new(&scope, &materials, 150)
        .expect("independent policy statement");
    let issuer =
        crate::PolicySigningKey::deterministic([82; 32], [83; 32]).expect("fixture policy root");
    let account_approval =
        c.f.c
            .root
            .approve_policy_renewal(&statement)
            .expect("account approval");
    let policy_approval = issuer
        .approve_policy_renewal(&statement)
        .expect("policy approval");
    let approval = crate::VerifiedPolicyRenewal::verify(
        &account_approval,
        &policy_approval,
        &scope,
        &materials,
        150,
    )
    .expect("both approvals");
    owner
        .stage_policy_renewal(
            &approval,
            scope.operation,
            c.f.c.policy.historical(),
            &p1,
            150,
        )
        .expect("policy intent");
    owner
        .activate_policy_renewal(c.f.c.policy.historical(), &p1, 150)
        .expect("P1 adoption")
        .close();
    let mut owner = open(&c.f.c);
    owner
        .stage_account_credential_renewal(
            c.grant(0),
            &[c.grant(1), c.grant(2)],
            c.grant(0).operation(),
            &p1,
            170,
        )
        .expect("complete G collection under adopted P1");
    owner
        .activate_policy_renewal(c.f.c.policy.historical(), &p1, 170)
        .expect("complete account renewal after P1")
        .close();
    let mut owner = open(&c.f.c);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("historical group completion"),
        renewal::committed(c.grant(0))
    );
    owner
        .activate_policy_renewal(c.f.c.policy.historical(), &p1, 170)
        .expect("reopen original owner under same G and P1")
        .close();
    let mut owner = open(&c.f.c);
    let image = owner.image().expect("actual completed configuration");
    let key = JournalKey::open(&c.f.c.paths.wrapping).expect("original wrapping key");
    let original = encode(&key, owner.binding, &image).expect("current encoded state");
    let mut old_account = Vec::new();
    image
        .renewal
        .as_ref()
        .and_then(LocalRenewal::account)
        .expect("original account collection")
        .encode(&mut old_account)
        .expect("original collection bytes");
    let prefix = original.len() - 32 - 33 - old_account.len();
    let binding = c
        .grant(0)
        .companion_binding(&[&c.alternate, c.grant(2)])
        .expect("genuine alternate companion")
        .expect("nonempty collection");
    // Make the configuration internally consistent with a DIFFERENT complete
    // root-approved collection. The independently retained journal fact must
    // still reject this substitution after its ordinary ACK has been pruned.
    let mut substituted = original
        .get(..prefix)
        .expect("existing configuration body")
        .to_vec();
    substituted.extend_from_slice(c.grant(0).operation().as_bytes());
    substituted.extend_from_slice(&c.grant(0).statement_digest());
    substituted.extend_from_slice(&binding);
    substituted.extend_from_slice(&2u16.to_be_bytes());
    for grant in [&c.alternate, c.grant(2)] {
        substituted.extend_from_slice(
            &u32::try_from(grant.as_bytes().len())
                .expect("grant length")
                .to_be_bytes(),
        );
        substituted.extend_from_slice(grant.as_bytes());
    }
    substituted.push(1);
    substituted.extend_from_slice(&binding);
    substituted.extend_from_slice(&[0; 32]); // Replaced by the corruption fixture's authentic MAC.
    owner.close();
    crate::enrollment::tests::policy_renewal::replace_authenticated(&c.f.c, &substituted);
    let mut owner = open(&c.f.c);
    let changed = owner
        .image()
        .expect("structurally valid authenticated alternate configuration");
    owner
        .account_grants(&changed, c.grant(0), &c.f.original)
        .expect("all alternate root grants are genuine");
    assert!(matches!(
        owner.activate_policy_renewal(c.f.c.policy.historical(), &p1, 170),
        Err(DurableError::Conflict)
    ));
}

#[test]
fn required_account_group_and_independent_policy_compose_in_both_orders() {
    use crate::enrollment::tests::witness_renewal::independent_policy::operational as policy;
    for group_first in [false, true] {
        let c = AccountCase::new(true);
        if group_first {
            super::session::renew(&c, 0, &c.f.c.paths, &c.f.c.intent).close();
        }
        let at = if group_first { 170 } else { 150 };
        let approval = policy::approved_at(&c.f, &c.f.c.policy, 2, 280, at);
        let proposal = policy::prepared_at(&c.f, &approval, &c.f.c.policy, at);
        policy::applied_at(&c.f, &approval, proposal, at);
        policy::activate(&c.f, &approval.target, at)
            .expect("P1 original owner")
            .close();
        if !group_first {
            let mut owner = open(&c.f.c);
            owner
                .stage_account_credential_renewal(
                    c.grant(0),
                    &[c.grant(1), c.grant(2)],
                    c.grant(0).operation(),
                    &approval.target,
                    170,
                )
                .expect("complete G after P1");
            let anchor = client(&c.f, &mut owner, 170);
            let proposal = owner
                .prepare_witnessed_policy_continuation(
                    c.f.c.policy.historical(),
                    &approval.target,
                    170,
                    anchor,
                )
                .expect("group sealed under retained P1");
            owner.close();
            c.f.carrier.clock.store(170, Ordering::SeqCst);
            c.f.carrier
                .store
                .lock()
                .expect("witness")
                .prepare_policy_renewed_credential_renewal(
                    proposal,
                    c.grant(0),
                    c.f.c.policy.historical(),
                    &approval.target,
                    170,
                )
                .expect("independent group witness approval");
            let mut owner = open(&c.f.c);
            let mut anchor = client(&c.f, &mut owner, 170);
            assert_eq!(
                owner
                    .commit_witnessed_policy_continuation(
                        &proposal,
                        c.f.c.policy.historical(),
                        &approval.target,
                        170,
                        &mut anchor
                    )
                    .expect("group completion under retained P1"),
                renewal::committed(c.grant(0))
            );
        }
        let mut active =
            policy::activate(&c.f, &approval.target, 170).expect("same original C1/P1 owner");
        let (service, signer, current) = active.parts().expect("controlled owners");
        assert_eq!(
            current.credential_digest(),
            c.grant(0).successor_device().credential_digest()
        );
        signer.check_device(current).expect("original signing key");
        assert_eq!(
            service
                .stores()
                .expect("original stores")
                .0
                .identity()
                .expect("same journal"),
            c.f.id
        );
        active.close();
        assert_eq!(
            open(&c.f.c)
                .credential_renewal_status()
                .expect("retained complete G"),
            renewal::committed(c.grant(0))
        );
    }
}

#[test]
fn account_renewal_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let (_, issued, policy_pin, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let policy = policy_pin
        .verify(issued.as_bytes(), runtime, 150)
        .expect("original policy");
    let account_root =
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("independent root"))
            .expect("root");
    let intent = EnrollmentIntent::new(
        account_root.clone(),
        DeviceDescription::new(
            [7; 16],
            1,
            policy.family(),
            Validity::new(100, 160).expect("original interval"),
        )
        .expect("original intent"),
    );
    let target = fs::read(root.join("trusted-target")).expect("independent target");
    let mut d = Decoder::new(&target);
    let checkpoint =
        RosterCheckpoint::from_trusted_state(d.u64().expect("version"), d.array().expect("digest"))
            .expect("checkpoint");
    d.finish().expect("exact target");
    let pin = AccountPin::new(
        crate::identity::account_id(&account_root),
        account_root,
        checkpoint,
        policy.family(),
    )
    .expect("current pin");
    let grants: [VerifiedCredentialRenewal; 3] = (0..3)
        .map(|index| {
            VerifiedCredentialRenewal::verify(
                &fs::read(root.join(format!("public-grant-{index}"))).expect("public grant"),
                &pin,
                policy.checkpoint().digest(),
                170,
            )
            .expect("verified grant")
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "three verified grants")
        .expect("fixture shape");
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    owner
        .stage_account_credential_renewal(
            &grants[0],
            &[&grants[1], &grants[2]],
            grants[0].operation(),
            &policy,
            170,
        )
        .expect("exact complete intent");
    owner
        .activate(&policy, 170, None)
        .expect("original active")
        .close();
    Err("requested account renewal boundary did not suspend child")
}

#[test]
fn real_process_cuts_preserve_complete_account_target_at_each_cross_store_boundary() {
    use crate::durable::tests::ChildGuard;
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let mut cuts = 0;
    for stage in ["intent", "journal", "completion", "acknowledgement"] {
        let c = AccountCase::new(false);
        let root =
            c.f.c
                .paths
                .configuration
                .parent()
                .expect("original directory");
        fs::write(root.join("trusted-root"), c.f.c.intent.root.encode()).expect("root pin");
        let target = c.grant(0).successor_device().roster().checkpoint();
        let mut bytes = target.version().to_be_bytes().to_vec();
        bytes.extend_from_slice(&target.digest());
        fs::write(root.join("trusted-target"), bytes).expect("target pin");
        for (index, grant) in c.grants.iter().enumerate() {
            fs::write(root.join(format!("public-grant-{index}")), grant.as_bytes())
                .expect("public grant");
        }
        let signer = fs::read(&c.f.c.paths.signer).expect("protected original signer");
        let mut child = ChildGuard(Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "enrollment::tests::witness_renewal::account_renewal::recovery::account_renewal_process_child", "--nocapture"])
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", root).env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", stage)
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("child"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("renewal-ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "child did not reach {stage}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().expect("actual process interruption");
        assert_eq!(
            child.0.wait().expect("reap original owner").signal(),
            Some(9)
        );
        c.verify_active(c.activate(open(&c.f.c)));
        let mut owner = open(&c.f.c);
        assert_eq!(
            owner
                .stage_account_credential_renewal(
                    c.grant(0),
                    &[c.grant(2), &c.resigned],
                    c.grant(0).operation(),
                    &c.f.c.policy,
                    170
                )
                .expect("same completed collection"),
            renewal::committed(c.grant(0))
        );
        assert_eq!(
            fs::read(&c.f.c.paths.signer).expect("same original signer"),
            signer
        );
        cuts += 1;
    }
    assert_eq!(cuts, 4);
    eprintln!("ACCOUNT_ENROLLMENT_PROCESS cuts={cuts} original_complete_set=true");
}

#[test]
fn completed_account_receipt_survives_later_peer_generation_change_before_enrollment_completion() {
    let c = AccountCase::new(false);
    let mut owner = open(&c.f.c);
    c.stage(&mut owner);
    owner.close();
    let mut journal = DeviceJournal::open(
        c.f.c.paths.installation.files()[1],
        JournalKey::open(&c.f.c.paths.wrapping).expect("original wrapping key"),
        &c.f.original,
        c.f.id,
    )
    .expect("original journal");
    let authority =
        crate::RetainedInstallationAuthority::active_installation(&c.f.original, &c.f.c.policy);
    let target = crate::durable::LocalRenewalTarget {
        grant: c.grant(0),
        companions: c.grants.get(1..).expect("all companion grants"),
        continuation: None,
        policy_renewal: None,
    };
    // The enrollment intent is already durable. Stop after the actual journal
    // commit, before enrollment completion, then admit a legitimate later head.
    let receipt = journal
        .commit_local_renewal(&authority, &target, &c.f.c.policy, 170)
        .expect("exact account commit");
    assert!(receipt.account_binding.is_some());
    let changed = c.grant(1).successor_device();
    let mut description = changed.description.clone();
    description.generation += 1;
    let replacement =
        c.f.c
            .root
            .issue_device(description, changed.key.clone())
            .expect("later generation");
    let local = c
        .grant(0)
        .successor_credential()
        .expect("local successor bytes");
    let third = c
        .grant(2)
        .successor_credential()
        .expect("third successor bytes");
    let entries = [local, replacement.as_slice(), third]
        .map(|cert| c.f.c.root.roster_entry(cert).expect("later member"));
    let later =
        c.f.c
            .root
            .issue_roster(3, interval(), &entries)
            .expect("later signed roster");
    let pin = AccountPin::new(
        c.f.original.account_id(),
        c.f.c.intent.root.clone(),
        later.checkpoint(),
        c.f.c.policy.family(),
    )
    .expect("later independent pin");
    journal
        .install_roster(
            &pin.verify_roster(later.as_bytes(), 175)
                .expect("verified later head"),
            175,
        )
        .expect("observe later peer generation");
    journal.close();
    let mut owner = open(&c.f.c);
    owner
        .activate(&c.f.c.policy, 175, None)
        .expect("current local owner after historical reconciliation")
        .close();
    owner = open(&c.f.c);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("retained historical commit"),
        renewal::committed(c.grant(0))
    );
    assert_eq!(
        owner
            .stage_account_credential_renewal(
                c.grant(0),
                &[c.grant(1), c.grant(2)],
                c.grant(0).operation(),
                &c.f.c.policy,
                175
            )
            .expect("historical complete request retry"),
        renewal::committed(c.grant(0))
    );
}

#[test]
fn account_enrollment_sync_failures_keep_the_original_complete_intent_and_commit() {
    let mut faults = 0;
    for completing in [false, true] {
        let c = AccountCase::new(false);
        if completing {
            let mut owner = open(&c.f.c);
            c.stage(&mut owner);
            owner.close();
        }
        let (mut owner, _, count) = faulty(&c.f.c, false);
        count.store(0, Ordering::SeqCst);
        let barriers = if completing {
            let mut active = owner
                .activate(&c.f.c.policy, 170, None)
                .expect("completion baseline");
            let count = count.load(Ordering::SeqCst);
            active.close();
            count
        } else {
            c.stage(&mut owner);
            let count = count.load(Ordering::SeqCst);
            owner.close();
            count
        };
        assert!((1..=16).contains(&barriers));
        for cut in 1..=barriers {
            for after in [false, true] {
                let c = AccountCase::new(false);
                let key = fs::read(&c.f.c.paths.signer).expect("original protected key");
                if completing {
                    let mut owner = open(&c.f.c);
                    c.stage(&mut owner);
                    owner.close();
                }
                let (mut owner, remaining, _) = faulty(&c.f.c, after);
                remaining.store(cut, Ordering::SeqCst);
                if completing {
                    assert_sync_failure(owner.activate(&c.f.c.policy, 170, None), after);
                } else {
                    assert_sync_failure(
                        owner.stage_account_credential_renewal(
                            c.grant(0),
                            &[c.grant(1), c.grant(2)],
                            c.grant(0).operation(),
                            &c.f.c.policy,
                            170,
                        ),
                        after,
                    );
                    owner.close();
                }
                let mut owner = open(&c.f.c);
                let state = owner
                    .stage_account_credential_renewal(
                        c.grant(0),
                        &[c.grant(2), &c.resigned],
                        c.grant(0).operation(),
                        &c.f.c.policy,
                        170,
                    )
                    .expect("same semantic retry");
                assert!(
                    state == renewal::pending(c.grant(0))
                        || state == renewal::committed(c.grant(0))
                );
                c.verify_active(c.activate(owner));
                assert_eq!(
                    fs::read(&c.f.c.paths.signer).expect("same protected key"),
                    key
                );
                faults += 1;
            }
        }
    }
    assert!(faults >= 4);
    eprintln!("ACCOUNT_ENROLLMENT_SYNC faults={faults} complete_original_set=true");
}

#[test]
fn account_format_retains_legacy_bounds_and_rejects_omitted_or_excessive_companions() {
    let c = AccountCase::new(false);
    let mut owner = open(&c.f.c);
    c.stage(&mut owner);
    let image = owner.image().expect("authenticated original intent");
    let key = JournalKey::open(&c.f.c.paths.wrapping).expect("wrapping key");
    let wire = encode(&key, owner.binding, &image).expect("new image");
    assert_eq!(
        encode(
            &key,
            owner.binding,
            &decode_image(&wire, &key, owner.binding).expect("decode")
        )
        .expect("encode roundtrip"),
        wire
    );
    let mut account = Vec::new();
    image
        .renewal
        .as_ref()
        .and_then(LocalRenewal::account)
        .expect("original collection")
        .encode(&mut account)
        .expect("collection");
    let start = wire.len() - 32 - 1 - account.len();
    assert_eq!(
        wire.get(start..start + account.len())
            .expect("complete account metadata"),
        account.as_slice()
    );
    let remac = |body: Vec<u8>| {
        let mut mac = auth(&key).expect("auth");
        mac.update(&body);
        let mut result = body;
        result.extend_from_slice(&mac.finalize().into_bytes());
        result
    };
    for count in [0u16, 32, u16::MAX] {
        let mut body = wire
            .get(..wire.len() - 32)
            .expect("authenticated body")
            .to_vec();
        body.get_mut(start + 96..start + 98)
            .expect("count field")
            .copy_from_slice(&count.to_be_bytes());
        assert!(decode_image(&remac(body), &key, owner.binding).is_err());
    }
    // Removing the new wrapper cannot make an old reader ignore its appended
    // complete-set metadata, even with an otherwise authentic local image.
    assert!(decode_image(
        &remac(wire.get(8..wire.len() - 32).expect("wrapped body").to_vec()),
        &key,
        owner.binding
    )
    .is_err());
    let mut changed = wire
        .get(..wire.len() - 32)
        .expect("authenticated body")
        .to_vec();
    *changed.get_mut(start + 64).expect("binding field") ^= 1;
    let bad =
        decode_image(&remac(changed), &key, owner.binding).expect("authenticated structural image");
    assert!(owner
        .account_grants(&bad, c.grant(0), &c.f.original)
        .is_err());
}
