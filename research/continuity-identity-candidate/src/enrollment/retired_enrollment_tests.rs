// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrolled-device retirement, exact file identity and I/O recovery.
use super::*;
use crate::enrollment::tests::policy_continuation;

#[test]
fn retired_inventory_reports_and_erases_adopted_and_carried_policy_at_all_three_cuts() {
    use crate::{
        retired_device, AnchorCredentialRenewalState as State, AnchorError, AnchorOperation,
        AnchorRequest, AnchorSubject, RetiredInstallationRecovery,
    };
    use std::{io::Write, os::unix::fs::DirBuilderExt};
    for carry in [false, true] {
        for stage in 0..3 {
            let f = fixture_with_policy_expiry(Some(160));
            let g1 = grant(&f, &f.original, 2, 180);
            let p1 = policy_continuation::policy(&f.c, 2, 190, 170);
            let scope = policy_continuation::scope(&f.c, &g1, f.id);
            let t1 = policy_continuation::joint(&f.c, &g1, &scope, &f.c.policy, &p1);
            let first = prepare_policy(&f, &g1, Some(&t1), &p1);
            let g2 = grant(&f, g1.successor_device(), 3, 185);
            let (proposal, grant) = if carry {
                let mut owner = open(&f.c);
                let mut anchor = client(&f, &mut owner, 170);
                assert_eq!(
                    owner
                        .commit_witnessed_policy_continuation(
                            &first,
                            f.c.policy.historical(),
                            &p1,
                            170,
                            &mut anchor,
                        )
                        .expect("complete original adoption before later credential renewal"),
                    committed(&g1, &first)
                );
                owner.close();
                (prepare_policy(&f, &g2, None, &p1), &g2)
            } else {
                (first, &g1)
            };
            assert_eq!(proposal.adopts_policy(), !carry);
            assert_eq!(proposal.policy_continuation(), Some(t1.statement_digest()));
            let prepared = disk(&f);
            let mut owner = open(&f.c);
            let mut anchor = client(&f, &mut owner, 170);
            owner.close();
            if stage > 0 {
                assert_eq!(
                    anchor
                        .exchange(
                            proposal.subject(),
                            AnchorOperation::commit_credential_renewal(&proposal)
                        )
                        .expect("original witness commit")
                        .credential_renewal_state(&proposal)
                        .expect("exact decision"),
                    State::Applied
                );
            }
            if stage == 2 {
                assert_eq!(
                    DeviceJournal::recover_credential_renewal(
                        f.c.paths.installation.files()[1],
                        JournalKey::open(&f.c.paths.wrapping).expect("original key"),
                        &f.original,
                        f.c.policy.historical(),
                        f.id,
                        proposal,
                        &mut anchor,
                    )
                    .expect("install exact original target without ACK"),
                    State::Applied
                );
            }
            let before = disk(&f);
            assert_eq!(
                before.1, prepared.1,
                "retain complete original bound intent"
            );
            assert_eq!(before.0 == prepared.0, stage != 2);
            let predecessor = if stage == 0 {
                grant.previous_device()
            } else {
                grant.successor_device()
            };
            let previous_policy = if !carry && stage == 0 {
                f.c.policy.historical()
            } else {
                p1.historical()
            };
            let signer = DeviceSigningKey::generate().expect("fresh replacement signer");
            let mut description = grant.successor_device().description.clone();
            description.generation += 1;
            description.validity = Validity::new(100, 200).expect("replacement validity");
            let certificate =
                f.c.root
                    .issue_device(description, signer.public_key().expect("fresh public key"))
                    .expect("fresh generation");
            let roster =
                f.c.root
                    .issue_roster(
                        4,
                        Validity::new(100, 200).expect("roster validity"),
                        &[f.c.root.roster_entry(&certificate).expect("new member")],
                    )
                    .expect("replacement roster");
            let next = AccountPin::new(
                f.original.account_id(),
                f.c.root.public_key().expect("root"),
                roster.checkpoint(),
                p1.family(),
            )
            .expect("independent current pin")
            .verify_device(&certificate, roster.as_bytes(), 170)
            .expect("current replacement identity");
            let root =
                f.c.paths
                    .wrapping
                    .parent()
                    .expect("original private directory");
            let dir = root.join("retired-policy-replacement");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("private replacement path");
            let mut next_journal = DeviceJournal::provision_anchored(
                &dir.join("state.redb"),
                JournalKey::provision(&dir.join("key")).expect("fresh wrapping"),
                &next,
                &p1,
                JournalIdentity::generate().expect("fresh identity"),
                170,
            )
            .expect("fresh genesis journal");
            let genesis = next_journal
                .anchor_genesis(&next, &p1)
                .expect("actual genesis");
            next_journal.close();
            let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy)
                .expect("original subject");
            let proofs = [(subject, predecessor.roster().checkpoint(), previous_policy)];
            let (replacement, retired) = {
                let mut witness = f.carrier.store.lock().expect("independent controller");
                let replacement = witness
                    .device_replacement_proposal(&genesis, &next, &p1, &proofs, 170)
                    .expect("all original state bound");
                witness
                    .replace_device(&replacement, &genesis, &next, &p1, &proofs, 170)
                    .expect("atomic replacement");
                let wire = witness
                    .retired_subject_receipt(&replacement, subject)
                    .expect("permanent retirement");
                let retired = f
                    .pin
                    .verify_retired_subject(&replacement, subject, &wire)
                    .expect("original retirement proof");
                (replacement, retired)
            };
            let mut registration = open(&f.c);
            let saved = registration.image().expect("original registration");
            let old_signer = registration
                .signer(saved.identity, false)
                .expect("original persistent signer");
            registration.close();
            for op in [
                AnchorOperation::commit_credential_renewal(&proposal),
                AnchorOperation::credential_renewal_status(&proposal),
                AnchorOperation::close_credential_renewal(&proposal),
                AnchorOperation::acknowledge_credential_renewal(&proposal),
            ] {
                let request = AnchorRequest::new(&f.pin, subject, op, &old_signer)
                    .expect("original signed operation");
                assert!(matches!(
                    f.carrier
                        .store
                        .lock()
                        .expect("witness")
                        .handle(request.as_bytes(), 170),
                    Err(AnchorError::Rejected(Error::Scope))
                ));
            }
            drop(old_signer);
            let signer_before = fs::read(&f.c.paths.signer).expect("original encrypted signer");
            let mut retired_enrollment = crate::RetiredDeviceEnrollment::open(
                f.c.paths.clone(),
                f.c.intent.clone(),
                f.pin.clone(),
                retired,
            )
            .expect("original restricted enrollment");
            let cleanup = retired_enrollment
                .installation()
                .expect("original independent installation");
            let inventory = cleanup.proposal().expect("complete original inventory");
            let wire = {
                let mut witness = f.carrier.store.lock().expect("controller");
                witness
                    .retain_retired_cleanup(&inventory)
                    .expect("independent exact inventory");
                witness
                    .retired_cleanup_receipt(&inventory)
                    .expect("inventory proof")
            };
            let retained = cleanup
                .verify_retained(&f.pin, &wire)
                .expect("exact inventory");
            assert_eq!(
                disk(&f),
                before,
                "capture cannot apply or remove the bound intent"
            );
            assert_eq!(
                inventory.stored_image_digest() == retired.observed_head().digest(),
                stage != 1
            );
            let expected = cleanup
                .prepare_report(&retained)
                .expect("complete G/T report");
            let wire = {
                let mut witness = f.carrier.store.lock().expect("controller");
                witness
                    .retain_retired_report(&expected)
                    .expect("independent report");
                witness
                    .retired_report_receipt(&expected)
                    .expect("report proof")
            };
            let report = cleanup
                .report(&retained, &f.pin, &wire)
                .expect("verified full report");
            assert!(matches!(report.intent(), retired_device::Intent::Write {
                transaction: retired_device::Transaction::Credential { operation, statement, policy: Some((adopt, policy)) }, ..
            } if operation == grant.operation().as_bytes() && *statement == grant.statement_digest()
                && *adopt != carry && *policy == t1.statement_digest()));
            let roles: Vec<_> = report.views().iter().map(|v| v.role).collect();
            use retired_device::ViewRole::{Authoritative, SupersededSource, UncommittedTarget};
            assert_eq!(
                roles,
                match stage {
                    0 => vec![Authoritative, UncommittedTarget],
                    1 => vec![SupersededSource, Authoritative],
                    _ => vec![Authoritative],
                }
            );
            let mut file = fs::File::create_new(root.join("retired-policy-host-report.bin"))
                .expect("host record");
            file.write_all(report.as_bytes())
                .expect("complete original report");
            file.sync_all().expect("durable host report");
            fs::File::open(root)
                .expect("parent")
                .sync_all()
                .expect("durable host name");
            let verified = f
                .pin
                .verify_retired_report(&retained, &expected, &wire)
                .expect("independent retention");
            let report_retention_wire = wire.clone();
            cleanup
                .prepare_host_acknowledgement(report.as_bytes(), &verified)
                .expect("original host-accounted intent");
            let wire = {
                let mut witness = f.carrier.store.lock().expect("controller");
                witness
                    .acknowledge_retired_report(&expected)
                    .expect("independent host ACK");
                assert_eq!(
                    witness
                        .retired_subject_observation(&replacement, subject)
                        .expect("unchanged frozen G/T"),
                    retired
                );
                witness
                    .retired_report_acknowledgement_receipt(&expected)
                    .expect("purpose21")
            };
            assert_eq!(
                disk(&f),
                before,
                "no mutation before explicit journal erasure"
            );
            cleanup
                .erase_journal(&f.pin, &wire)
                .expect("erase exact adopted/carried original inventory");
            assert!(
                fs::read(&f.c.paths.signer).expect("signer unchanged before explicit preparation")
                    == signer_before
            );
            if !carry && stage == 0 {
                assert!(retired_enrollment
                    .prepare_signer_erasure(&report_retention_wire)
                    .is_err());
                assert!(
                    fs::read(&f.c.paths.signer).expect("purpose20 cannot erase signer")
                        == signer_before
                );
                retired_enrollment = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("same retirement after wrong-purpose refusal");
                let mut changed = wire.clone();
                *changed.last_mut().expect("signature") ^= 1;
                assert!(retired_enrollment.prepare_signer_erasure(&changed).is_err());
                assert!(
                    fs::read(&f.c.paths.signer).expect("bad signature cannot erase signer")
                        == signer_before
                );
                retired_enrollment = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("original valid ACK can still proceed");
            }
            if !carry && stage == 0 {
                retired_enrollment.close();
                retired_enrollment_configuration_cuts(&f, retired, &wire, &signer_before);
                retired_enrollment = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("same retirement after all metadata cuts");
            }
            retired_enrollment
                .prepare_signer_erasure(&wire)
                .expect("original acknowledged signing file plan");
            assert_eq!(
                retired_enrollment
                    .signer_erasure_status()
                    .expect("original seed bytes remain"),
                crate::SigningFileErasureState::Retained
            );
            retired_enrollment.close();
            assert!(matches!(
                DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()),
                Err(DurableError::Suspended)
            ));
            let mut retired_enrollment = crate::RetiredDeviceEnrollment::open(
                f.c.paths.clone(),
                f.c.intent.clone(),
                f.pin.clone(),
                retired,
            )
            .expect("same original file plan after restart");
            if !carry && stage == 0 {
                retired_enrollment.close();
                // Missing paths and foreign inodes must not be selected as a new original.
                let held = f.c.paths.signer.with_extension("held-original");
                fs::rename(&f.c.paths.signer, &held).expect("retain missing original");
                let mut absent = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("independent file plan survives missing signer");
                assert!(absent.erase_signer().is_err());
                assert!(!f.c.paths.signer.exists());
                assert!(fs::read(&held).expect("original preserved") == signer_before);
                let foreign = f.c.paths.signer.with_extension("foreign");
                DeviceSigningKey::provision(
                    &foreign,
                    &JournalKey::open(&f.c.paths.wrapping).expect("test wrapping"),
                    saved.identity,
                )
                .expect("independent foreign key with same public file ID")
                .close();
                let foreign_bytes = fs::read(&foreign).expect("foreign ciphertext");
                fs::rename(&foreign, &f.c.paths.signer).expect("foreign inode at mutable basename");
                let mut swapped = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("original plan");
                assert!(matches!(
                    swapped.erase_signer(),
                    Err(DurableError::Conflict)
                ));
                assert!(
                    fs::read(&f.c.paths.signer).expect("foreign inode untouched") == foreign_bytes
                );
                fs::rename(&f.c.paths.signer, &foreign).expect("keep foreign asset");
                fs::rename(&held, &f.c.paths.signer).expect("restore original inode");
                fs::write(&f.c.paths.signer, &foreign_bytes)
                    .expect("foreign ciphertext in original test inode");
                let mut changed = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("original fingerprint");
                assert!(matches!(
                    changed.erase_signer(),
                    Err(DurableError::Conflict)
                ));
                assert!(
                    fs::read(&f.c.paths.signer).expect("foreign ciphertext untouched")
                        == foreign_bytes
                );
                // Even a forged local MAC/fingerprint cannot erase a different public key
                // using the real host ACK for this original credential and journal.
                let db = open_private_database(&f.c.paths.configuration)
                    .expect("closed original enrollment");
                let enrollment_table =
                    TableDefinition::<&str, &[u8]>::new("continuity_enrollment_v1");
                let original_marker = {
                    let read = db.begin_read().expect("read");
                    let table = read.open_table(enrollment_table).expect("table");
                    let row = table
                        .get("retirement")
                        .expect("retirement")
                        .expect("marker");
                    row.value().to_vec()
                };
                let old_hash = digest(
                    b"Q-PERIAPT-CONTINUITY-RETIRED-SIGNER-FILE/v1",
                    &signer_before,
                );
                let new_hash = digest(
                    b"Q-PERIAPT-CONTINUITY-RETIRED-SIGNER-FILE/v1",
                    &foreign_bytes,
                );
                let offsets: Vec<_> = original_marker
                    .windows(32)
                    .enumerate()
                    .filter_map(|(i, b)| (b == old_hash).then_some(i))
                    .collect();
                assert_eq!(offsets.len(), 1);
                let mut forged = original_marker.clone();
                let offset = *offsets.first().expect("unique fingerprint");
                forged
                    .get_mut(offset..offset + 32)
                    .expect("fingerprint")
                    .copy_from_slice(&new_hash);
                forged.truncate(forged.len() - 32);
                let key = JournalKey::open(&f.c.paths.wrapping).expect("known test wrapping file");
                let mut mac = auth(&key).expect("test MAC");
                mac.update(&forged);
                forged.extend_from_slice(&mac.finalize().into_bytes());
                let tx = transaction(&db).expect("transaction");
                tx.open_table(enrollment_table)
                    .expect("table")
                    .insert("retirement", forged.as_slice())
                    .expect("forged local metadata");
                tx.commit().expect("test state");
                drop(db);
                let mut forged_owner = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("independent ACK remains valid but does not authorize foreign signer");
                assert!(matches!(
                    forged_owner.erase_signer(),
                    Err(DurableError::Conflict)
                ));
                assert!(
                    fs::read(&f.c.paths.signer).expect("foreign seeds still untouched")
                        == foreign_bytes
                );
                let db =
                    open_private_database(&f.c.paths.configuration).expect("closed enrollment");
                let tx = transaction(&db).expect("transaction");
                tx.open_table(enrollment_table)
                    .expect("table")
                    .insert("retirement", original_marker.as_slice())
                    .expect("restore original metadata");
                tx.commit().expect("restore");
                drop(db);
                fs::write(&f.c.paths.signer, &signer_before)
                    .expect("restore original test ciphertext");
                use crate::crypto::{inject_signer_io, SignerIoFault, SignerIoStage};
                let mut faults: Vec<_> = (0..=8).map(SignerIoFault::Prefix).collect();
                for point in [
                    SignerIoStage::HeaderWrite,
                    SignerIoStage::HeaderSync,
                    SignerIoStage::Truncate,
                    SignerIoStage::TerminalSync,
                    SignerIoStage::DirectorySync,
                ] {
                    for after in [false, true] {
                        faults.push(SignerIoFault::Boundary(point, after));
                    }
                }
                for fault in faults {
                    fs::write(&f.c.paths.signer, &signer_before)
                        .expect("restore exact test source in original inode");
                    fs::File::open(&f.c.paths.signer)
                        .expect("test file")
                        .sync_all()
                        .expect("durable test input");
                    let mut attempt = crate::RetiredDeviceEnrollment::open(
                        f.c.paths.clone(),
                        f.c.intent.clone(),
                        f.pin.clone(),
                        retired,
                    )
                    .expect("same acknowledged file plan");
                    let cut = inject_signer_io(fault);
                    assert!(matches!(attempt.erase_signer(), Err(DurableError::Io(_))));
                    assert!(cut.fired(), "must reach the selected actual file I/O cut");
                    drop(cut);
                    assert!(matches!(
                        attempt.signer_erasure_status(),
                        Err(DurableError::Closed)
                    ));
                    let mut recovered = crate::RetiredDeviceEnrollment::open(
                        f.c.paths.clone(),
                        f.c.intent.clone(),
                        f.pin.clone(),
                        retired,
                    )
                    .expect("same original decision after I/O failure");
                    let actual = fs::read(&f.c.paths.signer).expect("original file survives");
                    let status = recovered
                        .signer_erasure_status()
                        .expect("authenticated original or terminal");
                    assert_eq!(
                        status == crate::SigningFileErasureState::Erased,
                        actual == b"QPSRET01"
                    );
                    recovered
                        .erase_signer()
                        .expect("complete the original acknowledged erasure");
                    assert_eq!(fs::read(&f.c.paths.signer).expect("terminal"), b"QPSRET01");
                }
                eprintln!("RETIRED_SIGNER_FILE_IO header_prefix_cuts=9 boundary_cuts=10 no_early_success=true same_inode_recovery=true");
                retired_enrollment_process_cuts(
                    &f,
                    &replacement,
                    retired,
                    &signer_before,
                    &foreign_bytes,
                );
                retired_enrollment = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("original terminal retry");
            }
            retired_enrollment
                .erase_signer()
                .expect("logical original signing-file erasure");
            assert_eq!(
                fs::read(&f.c.paths.signer).expect("terminal file"),
                b"QPSRET01"
            );
            assert!(DeviceSigningKey::open(
                &f.c.paths.signer,
                &JournalKey::open(&f.c.paths.wrapping).expect("wrapping remains"),
                saved.identity
            )
            .is_err());
            let mut retired_enrollment = crate::RetiredDeviceEnrollment::open(
                f.c.paths.clone(),
                f.c.intent.clone(),
                f.pin.clone(),
                retired,
            )
            .expect("historical owner without signing file seed");
            assert_eq!(
                retired_enrollment
                    .signer_erasure_status()
                    .expect("durable exact terminal"),
                crate::SigningFileErasureState::Erased
            );
            retired_enrollment
                .erase_signer()
                .expect("idempotent terminal reconciliation");
            let mut reopened = RetiredInstallationRecovery::open(
                f.c.paths.installation.clone(),
                JournalKey::open(&f.c.paths.wrapping).expect("original key"),
                retired,
            )
            .expect("same independent metadata");
            assert_eq!(
                reopened
                    .journal_erasure_status(&f.pin)
                    .expect("authenticated terminal"),
                retired_device::JournalErasureState::Erased
            );
            eprintln!("RETIRED_G_POLICY carry={carry} stage={stage} real_enrollment=true report_exact_intent=true original_rows_unchanged_before_ack=true erased_after_purpose21=true");
        }
    }
}

fn retired_enrollment_configuration_cuts(
    f: &Fixture,
    retired: crate::AnchorRetiredSubject,
    ack: &[u8],
    signer: &[u8],
) {
    use crate::durable::tests::{assert_sync_failure, fault_database_path};
    let with_marker = fs::read(&f.c.paths.configuration).expect("clean original marker snapshot");
    let definition = TableDefinition::<&str, &[u8]>::new("continuity_enrollment_v1");
    let db = open_private_database(&f.c.paths.configuration).expect("original configuration");
    let tx = transaction(&db).expect("test transaction");
    tx.open_table(definition)
        .expect("table")
        .remove("retirement")
        .expect("pre-marker test state");
    tx.commit().expect("test setup");
    drop(db);
    let without_marker = fs::read(&f.c.paths.configuration).expect("clean initial enrollment");
    for preparing in [false, true] {
        let baseline = if preparing {
            &with_marker
        } else {
            &without_marker
        };
        // Restore identical CLOSED physical history before every cut so redb's
        // free-page history cannot change the measured barrier count.
        fs::write(&f.c.paths.configuration, baseline).expect("restore exact clean test history");
        let (db, _, count, _) = fault_database_path(&f.c.paths.configuration, false);
        count.store(0, Ordering::SeqCst);
        let mut owner = crate::RetiredDeviceEnrollment::open_in_database(
            f.c.paths.clone(),
            f.c.intent.clone(),
            f.pin.clone(),
            retired,
            db,
        )
        .expect("calibrate same original metadata");
        if preparing {
            owner
                .prepare_signer_erasure(ack)
                .expect("calibrate signer plan");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        owner.close();
        for after in [false, true] {
            for cut in 1..=barriers {
                fs::write(&f.c.paths.configuration, baseline).expect("same closed history");
                let (db, remaining, count, _) =
                    fault_database_path(&f.c.paths.configuration, after);
                count.store(0, Ordering::SeqCst);
                remaining.store(cut, Ordering::SeqCst);
                let opened = crate::RetiredDeviceEnrollment::open_in_database(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                    db,
                );
                if preparing {
                    let mut owner = opened.expect("existing retirement marker");
                    assert_sync_failure(owner.prepare_signer_erasure(ack), after);
                    assert!(matches!(
                        owner.signer_erasure_status(),
                        Err(DurableError::Closed)
                    ));
                } else {
                    assert_sync_failure(opened, after);
                }
                assert_eq!(count.load(Ordering::SeqCst), cut);
                assert!(
                    fs::read(&f.c.paths.signer).expect("signer untouched by metadata commit")
                        == signer
                );
                let mut recovered = crate::RetiredDeviceEnrollment::open(
                    f.c.paths.clone(),
                    f.c.intent.clone(),
                    f.pin.clone(),
                    retired,
                )
                .expect("recover exact original metadata decision");
                recovered
                    .prepare_signer_erasure(ack)
                    .expect("same complete acknowledged file plan");
                assert_eq!(
                    recovered
                        .signer_erasure_status()
                        .expect("no premature erasure"),
                    crate::SigningFileErasureState::Retained
                );
                recovered.close();
            }
        }
        eprintln!("RETIRED_ENROLLMENT_METADATA_SYNC signer_plan={preparing} barriers={barriers} before_after_faults={}", barriers * 2);
    }
    fs::write(&f.c.paths.configuration, with_marker)
        .expect("return to original marker before plan");
}

fn retired_enrollment_process_cuts(
    f: &Fixture,
    replacement: &crate::AnchorDeviceReplacementProposal,
    retired: crate::AnchorRetiredSubject,
    original: &[u8],
    foreign: &[u8],
) {
    use crate::durable::tests::ChildGuard;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = f.c.paths.wrapping.parent().expect("root");
    let context = root.join("retirement-child-context");
    fs::create_dir(&context).expect("public child context");
    fs::write(context.join("pin-id"), f.pin.identity().as_bytes()).expect("instance");
    fs::write(context.join("pin-key"), f.pin.public_key().encode()).expect("public pin");
    fs::write(context.join("root-key"), f.c.intent.root.encode())
        .expect("original root public key");
    let mut intent = Vec::new();
    f.c.intent.encode(&mut intent);
    fs::write(context.join("intent"), intent).expect("original public intent");
    fs::write(
        context.join("replacement"),
        replacement.to_bytes().expect("replacement bytes"),
    )
    .expect("expected replacement");
    let receipt = f
        .carrier
        .store
        .lock()
        .expect("controller")
        .retired_subject_receipt(replacement, retired.subject())
        .expect("retirement proof");
    fs::write(context.join("retired"), receipt).expect("public proof");
    for (index, (stage, substitute)) in [
        ("HeaderSync-before", false),
        ("HeaderSync-after", false),
        ("Truncate-after", false),
        ("TerminalSync-after", false),
        ("HeaderSync-after", true),
    ]
    .into_iter()
    .enumerate()
    {
        fs::write(&f.c.paths.signer, original).expect("restore original closed test inode");
        fs::File::open(&f.c.paths.signer)
            .expect("signer")
            .sync_all()
            .expect("durable test source");
        let cut_dir = root.join(format!("retirement-cut-{index}"));
        fs::create_dir(&cut_dir).expect("cut directory");
        let log = fs::File::create_new(cut_dir.join("child.log")).expect("log");
        let mut child = ChildGuard(Command::new(std::env::current_exe().expect("binary"))
            .args(["--exact", "enrollment::tests::witness_renewal::policy_transaction::retirement::retired_enrollment_signer_process_child", "--nocapture"])
            .env("QPERIAPT_RETIRED_ENROLLMENT_CHILD", root)
            .env("QPERIAPT_SIGNER_CUT_ROOT", &cut_dir).env("QPERIAPT_SIGNER_CUT_STAGE", stage)
            .stdout(Stdio::from(log.try_clone().expect("clone"))).stderr(Stdio::from(log))
            .spawn().expect("owned child"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !cut_dir.join("signer-ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "signer cut deadline: {}",
                cut_dir.join("child.log").display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!cut_dir.join("returned").exists());
        if substitute {
            let held = root.join("admitted-signer-held");
            fs::rename(&f.c.paths.signer, &held).expect("move only original admitted test inode");
            fs::write(&f.c.paths.signer, foreign).expect("independent foreign basename");
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&f.c.paths.signer, fs::Permissions::from_mode(0o600))
                .expect("private foreign file");
            let mut release =
                fs::File::create_new(cut_dir.join("signer-resume")).expect("resume owned child");
            release.write_all(b"resume").expect("resume");
            release.sync_all().expect("resume durable");
            loop {
                if let Some(status) = child.0.try_wait().expect("child status") {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(fs::read_to_string(cut_dir.join("returned"))
                .expect("explicit failure")
                .starts_with("error:"));
            assert!(fs::read(&f.c.paths.signer).expect("foreign file survives") == foreign);
            assert_eq!(
                fs::read(&held).expect("only admitted original erased"),
                b"QPSRET01"
            );
            fs::rename(&f.c.paths.signer, cut_dir.join("foreign-preserved"))
                .expect("preserve foreign asset");
            fs::rename(held, &f.c.paths.signer).expect("restore original terminal name");
        } else {
            child.0.kill().expect("kill owned child");
            assert!(!child.0.wait().expect("reap").success());
            let mut recovered = crate::RetiredDeviceEnrollment::open(
                f.c.paths.clone(),
                f.c.intent.clone(),
                f.pin.clone(),
                retired,
            )
            .expect("recover without live signer or runtime");
            let expected = if stage.starts_with("HeaderSync") {
                crate::SigningFileErasureState::Retained
            } else {
                crate::SigningFileErasureState::Erased
            };
            assert_eq!(
                recovered
                    .signer_erasure_status()
                    .expect("actual original file"),
                expected
            );
            recovered
                .erase_signer()
                .expect("finish original acknowledged decision");
        }
    }
    eprintln!("RETIRED_ENROLLMENT_PROCESS owned_cuts=4 no_early_success=true basename_substitution_preserved=true");
}

#[test]
fn retired_enrollment_signer_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_RETIRED_ENROLLMENT_CHILD") else {
        return;
    };
    let root = Path::new(&root);
    let context = root.join("retirement-child-context");
    let pin = AnchorPin::new(
        crate::AnchorIdentity::from_trusted_state(
            fs::read(context.join("pin-id"))
                .expect("instance")
                .try_into()
                .expect("width"),
        )
        .expect("identity"),
        PublicKey::decode(&fs::read(context.join("pin-key")).expect("pin public"))
            .expect("public pin"),
    );
    let public =
        PublicKey::decode(&fs::read(context.join("root-key")).expect("root")).expect("root public");
    let bytes = fs::read(context.join("intent")).expect("intent");
    let mut d = Decoder::new(&bytes);
    let account = d.array::<32>().expect("account");
    assert_eq!(account, crate::identity::account_id(&public));
    let description = DeviceDescription {
        id: d.array().expect("device"),
        generation: d.u64().expect("generation"),
        validity: crate::Validity::new(d.u64().expect("from"), d.u64().expect("until"))
            .expect("validity"),
        family: d.array().expect("family"),
    };
    d.finish().expect("complete intent");
    let replacement = crate::AnchorDeviceReplacementProposal::from_trusted_state(
        &fs::read(context.join("replacement")).expect("replacement"),
    )
    .expect("expected proposal");
    let (subject, _) = replacement
        .predecessor_checkpoints()
        .next()
        .expect("only original subject");
    let retired = pin
        .verify_retired_subject(
            &replacement,
            subject,
            &fs::read(context.join("retired")).expect("retirement"),
        )
        .expect("independent original retirement");
    let mut owner = crate::RetiredDeviceEnrollment::open(
        crate::enrollment::tests::paths(root),
        EnrollmentIntent::new(public, description),
        pin,
        retired,
    )
    .expect("original restricted metadata");
    let result = owner.erase_signer();
    let cut = PathBuf::from(std::env::var_os("QPERIAPT_SIGNER_CUT_ROOT").expect("cut root"));
    fs::write(
        cut.join("returned"),
        match result {
            Ok(()) => "ok".to_owned(),
            Err(e) => format!("error:{e}"),
        },
    )
    .expect("caller-visible result");
}

#[test]
fn retired_enrollment_consumes_live_owner_without_releasing_another_signer() {
    use crate::AnchorSubject;
    use std::os::unix::fs::DirBuilderExt;
    let f = fixture();
    let device = activate(&f, 150).expect("actual active enrolled service");
    let original_file = fs::read(&f.c.paths.signer).expect("original signer file");
    let root = f.c.paths.wrapping.parent().expect("root");
    let next_dir = root.join("live-retirement-successor");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&next_dir)
        .expect("private successor directory");
    let signer = DeviceSigningKey::generate().expect("fresh successor signer");
    let mut description = f.original.description.clone();
    description.generation += 1;
    description.validity = crate::Validity::new(100, 300).expect("new validity");
    let cert =
        f.c.root
            .issue_device(description, signer.public_key().expect("public"))
            .expect("new generation");
    let roster =
        f.c.root
            .issue_roster(
                10,
                crate::Validity::new(100, 300).expect("roster validity"),
                &[f.c.root.roster_entry(&cert).expect("member")],
            )
            .expect("new roster");
    let next = AccountPin::new(
        f.original.account_id(),
        f.c.root.public_key().expect("root"),
        roster.checkpoint(),
        f.c.policy.family(),
    )
    .expect("independent pin")
    .verify_device(&cert, roster.as_bytes(), 150)
    .expect("new current identity");
    let mut journal = DeviceJournal::provision_anchored(
        &next_dir.join("state.redb"),
        JournalKey::provision(&next_dir.join("key")).expect("fresh wrapping key"),
        &next,
        &f.c.policy,
        JournalIdentity::generate().expect("new journal"),
        150,
    )
    .expect("new genesis journal");
    let genesis = journal
        .anchor_genesis(&next, &f.c.policy)
        .expect("actual genesis");
    journal.close();
    let subject =
        AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
    let prior = [(
        subject,
        f.original.roster().checkpoint(),
        f.c.policy.historical(),
    )];
    let retired = {
        let mut store = f.carrier.store.lock().expect("independent controller");
        let replacement = store
            .device_replacement_proposal(&genesis, &next, &f.c.policy, &prior, 150)
            .expect("complete predecessor");
        store
            .replace_device(&replacement, &genesis, &next, &f.c.policy, &prior, 150)
            .expect("atomic replacement");
        let wire = store
            .retired_subject_receipt(&replacement, subject)
            .expect("original proof");
        f.pin
            .verify_retired_subject(&replacement, subject, &wire)
            .expect("verified retirement")
    };
    assert!(
        crate::RetiredDeviceEnrollment::open(
            f.c.paths.clone(),
            f.c.intent.clone(),
            f.pin.clone(),
            retired
        )
        .is_err(),
        "live original enrollment lease must exclude a parallel cleanup owner"
    );
    let mut retired_owner = device
        .retire(f.pin.clone(), retired)
        .expect("consume original service/signer, retain enrollment lease");
    assert!(fs::read(&f.c.paths.signer).expect("report precedes file erasure") == original_file);
    let original = retired_owner
        .installation()
        .expect("restricted original installation")
        .proposal()
        .expect("saved inventory");
    assert!(matches!(
        retired_owner.erase_signer(),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()),
        Err(DurableError::Suspended)
    ));
    let mut resumed = crate::RetiredDeviceEnrollment::open(
        f.c.paths.clone(),
        f.c.intent.clone(),
        f.pin.clone(),
        retired,
    )
    .expect("reopen historical owner");
    assert_eq!(
        resumed
            .installation()
            .expect("same installation")
            .proposal()
            .expect("same inventory"),
        original
    );
    assert!(fs::read(&f.c.paths.signer).expect("no unacknowledged seed removal") == original_file);
}
