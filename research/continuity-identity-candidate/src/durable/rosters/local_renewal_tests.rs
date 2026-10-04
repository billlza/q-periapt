// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture,
    durable::tests::{assert_sync_failure, directory, fault_store, new_store, reopen},
    PrekeyQuality, RootSigningKey,
};
use std::sync::atomic::Ordering;

#[test]
fn every_local_transition_and_receipt_ack_io_cut_keeps_atomic_original_commit_fact() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let original = f.initiator_device();
    let root = RootSigningKey::deterministic([90; 32], [91; 32]).expect("original root");
    let certificate = root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original body");
    let grant = crate::durable::rosters::tests::renewal::grant(
        &root,
        &certificate,
        original,
        300,
        2,
        [231; 32],
        f.initiator.policy().checkpoint().digest(),
    );
    let authority =
        crate::RetainedInstallationAuthority::active_installation(original, f.initiator.policy());
    let mut faults = 0;
    let mut present = 0;
    let mut absent = 0;
    for acknowledging in [false, true] {
        let folder = directory();
        let path = folder.path().canonicalize().expect("path");
        new_store(&path, original).close();
        if acknowledging {
            reopen(&path, original)
                .commit_local_credential_renewal(
                    &authority,
                    &grant,
                    grant.operation(),
                    f.initiator.policy(),
                    150,
                )
                .expect("committed target");
        }
        let (mut journal, _, count, _) = fault_store(&path, original, false);
        let receipt = LocalRenewalCommit::for_grant(&grant);
        count.store(0, Ordering::SeqCst);
        if acknowledging {
            journal
                .acknowledge_local_credential_renewal(&authority, &receipt)
                .expect("ack baseline");
        } else {
            journal
                .commit_local_credential_renewal(
                    &authority,
                    &grant,
                    grant.operation(),
                    f.initiator.policy(),
                    150,
                )
                .expect("commit baseline");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((4..=32).contains(&barriers));
        journal.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let folder = directory();
                let path = folder.path().canonicalize().expect("path");
                new_store(&path, original).close();
                if acknowledging {
                    reopen(&path, original)
                        .commit_local_credential_renewal(
                            &authority,
                            &grant,
                            grant.operation(),
                            f.initiator.policy(),
                            150,
                        )
                        .expect("commit first");
                }
                let (mut journal, remaining, _, _) = fault_store(&path, original, after);
                remaining.store(cut, Ordering::SeqCst);
                if acknowledging {
                    assert_sync_failure(
                        journal.acknowledge_local_credential_renewal(&authority, &receipt),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        journal.commit_local_credential_renewal(
                            &authority,
                            &grant,
                            grant.operation(),
                            f.initiator.policy(),
                            150,
                        ),
                        after,
                    );
                }
                assert!(journal.active.is_none());
                faults += 1;
                let mut recovered = reopen(&path, original);
                let image = recovered.image().expect("recovered same image");
                let saved = get(&image, &image.local_account).expect("local roster");
                if let Some(actual) = saved.local_commit {
                    present += 1;
                    assert_eq!(actual, receipt);
                    assert_eq!(
                        saved.roster.checkpoint(),
                        grant.successor_device().roster().checkpoint()
                    );
                } else {
                    absent += 1;
                    let expected = if acknowledging {
                        grant.successor_device().roster().checkpoint()
                    } else {
                        original.roster().checkpoint()
                    };
                    assert_eq!(saved.roster.checkpoint(), expected);
                }
                if acknowledging {
                    recovered
                        .acknowledge_local_credential_renewal(&authority, &receipt)
                        .expect("same durable completion ack");
                } else {
                    assert_eq!(
                        recovered
                            .commit_local_credential_renewal(
                                &authority,
                                &grant,
                                grant.operation(),
                                f.initiator.policy(),
                                150
                            )
                            .expect("same original operation"),
                        receipt
                    );
                }
                let final_image = recovered.image().expect("complete image");
                assert_eq!(final_image.revision, if acknowledging { 3 } else { 2 });
                assert_eq!(final_image.owner, crate::bootstrap::storage_owner(original));
            }
        }
    }
    assert!(present > 0 && absent > 0);
    eprintln!("LOCAL_RENEWAL_JOURNAL_IO faults={faults} receipt_present={present} receipt_absent={absent}");
}
