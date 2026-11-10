// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh retired cohorts preserve P-bound G as its own report transaction kind.
use super::*;
use crate::{
    retired_device::{Intent, Transaction, ViewRole},
    AnchorOperation, AnchorSubject,
};
use std::os::unix::fs::DirBuilderExt;

#[test]
fn required_policy_credential_cycle_retirement_reports_exact_independent_p_at_three_cuts() {
    for stage in 0..3 {
        let (f, a) = adopted();
        let g = credential::grant(&f, &f.original, 2, 280);
        let p = prepared_g(&f, &a, &g);
        let mut owner = open(&f.c);
        let mut client = credential::client(&f, &mut owner, 180);
        owner.close();
        if stage > 0 {
            assert_eq!(
                client
                    .exchange(p.subject(), AnchorOperation::commit_credential_renewal(&p))
                    .expect("original witness commit")
                    .credential_renewal_state(&p)
                    .expect("exact G"),
                crate::AnchorCredentialRenewalState::Applied
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
                    p,
                    &mut client
                )
                .expect("install original sealed G without ACK"),
                crate::AnchorCredentialRenewalState::Applied
            );
        }
        let before = journal(&f);
        let previous = if stage == 0 {
            g.previous_device()
        } else {
            g.successor_device()
        };
        let signer = DeviceSigningKey::generate().expect("fresh replacement key");
        let mut description = g.successor_device().description.clone();
        description.generation += 1;
        description.validity = Validity::new(100, 320).expect("replacement interval");
        let certificate =
            f.c.root
                .issue_device(description, signer.public_key().expect("fresh public key"))
                .expect("root-approved replacement");
        let roster =
            f.c.root
                .issue_roster(
                    4,
                    Validity::new(100, 400).expect("roster validity"),
                    &[f.c.root.roster_entry(&certificate).expect("new generation")],
                )
                .expect("root roster");
        let next = AccountPin::new(
            f.original.account_id(),
            f.c.root.public_key().expect("account root"),
            roster.checkpoint(),
            a.target.family(),
        )
        .expect("independent pin")
        .verify_device(&certificate, roster.as_bytes(), 180)
        .expect("current replacement");
        let dir =
            f.c.paths
                .wrapping
                .parent()
                .expect("root")
                .join("independent-policy-replacement");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("fresh private path");
        let mut journal = DeviceJournal::provision_anchored(
            &dir.join("journal"),
            JournalKey::provision(&dir.join("key")).expect("fresh wrapping"),
            &next,
            &a.target,
            JournalIdentity::generate().expect("fresh identity"),
            180,
        )
        .expect("replacement journal");
        let genesis = journal
            .anchor_genesis(&next, &a.target)
            .expect("actual replacement genesis");
        journal.close();
        let subject =
            AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("original subject");
        let predecessors = [(
            subject,
            previous.roster().checkpoint(),
            a.target.historical(),
        )];
        let retired = {
            let mut witness = f.carrier.store.lock().expect("independent witness");
            let replacement = witness
                .device_replacement_proposal(&genesis, &next, &a.target, &predecessors, 180)
                .expect("exact original P and G state");
            witness
                .replace_device(&replacement, &genesis, &next, &a.target, &predecessors, 180)
                .expect("independent atomic replacement");
            let wire = witness
                .retired_subject_receipt(&replacement, subject)
                .expect("retirement proof");
            f.pin
                .verify_retired_subject(&replacement, subject, &wire)
                .expect("exact old subject retired")
        };
        let mut owner = crate::RetiredDeviceEnrollment::open(
            f.c.paths.clone(),
            f.c.intent.clone(),
            f.pin.clone(),
            retired,
        )
        .expect("restricted original enrollment");
        let cleanup = owner.installation().expect("original retired installation");
        let inventory = cleanup.proposal().expect("complete original inventory");
        let wire = {
            let mut witness = f.carrier.store.lock().expect("witness");
            witness
                .retain_retired_cleanup(&inventory)
                .expect("retain inventory");
            witness.retired_cleanup_receipt(&inventory).expect("proof")
        };
        let retained = cleanup
            .verify_retained(&f.pin, &wire)
            .expect("authenticated inventory");
        let expected = cleanup
            .prepare_report(&retained)
            .expect("report new credential/policy composition");
        let wire = {
            let mut witness = f.carrier.store.lock().expect("witness");
            witness
                .retain_retired_report(&expected)
                .expect("independent report binding");
            witness
                .retired_report_receipt(&expected)
                .expect("report proof")
        };
        let report = cleanup
            .report(&retained, &f.pin, &wire)
            .expect("complete authenticated report");
        assert!(report.as_bytes().starts_with(b"QPRDMD03"));
        assert!(
            matches!(report.intent(),Intent::Write {transaction:Transaction::CredentialUnderPolicy{operation,statement,policy},..}
            if operation==g.operation().as_bytes() && *statement==g.statement_digest() && *policy==a.proof.statement_digest())
        );
        let roles: Vec<_> = report.views().iter().map(|v| v.role).collect();
        assert_eq!(
            roles,
            match stage {
                0 => vec![ViewRole::Authoritative, ViewRole::UncommittedTarget],
                1 => vec![ViewRole::SupersededSource, ViewRole::Authoritative],
                _ => vec![ViewRole::Authoritative],
            }
        );
        assert_eq!(
            super::super::journal(&f),
            before,
            "report cannot apply, erase or relabel original G"
        );
    }
}
