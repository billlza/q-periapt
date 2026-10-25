// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{io::Write, os::unix::fs::OpenOptionsExt, sync::atomic::Ordering};

#[test]
fn enrollment_witness_selection_metadata_survives_signer_absence_without_reprovisioning() {
    let f = Fixture::new();
    let original = fs::read(&f.c.paths.signer).expect("original protected signer");
    fs::remove_file(&f.c.paths.signer).expect("owned fixture signer loss");
    let mut owner = f.transfer.adopt_parent(&f.c, 180);
    assert_eq!(
        owner
            .witness_handoff_status(f.c.policy.historical(), f.transfer.plan.clone())
            .expect("keyless original metadata"),
        WitnessJournalAdoptionState::Adopted
    );
    assert!(owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            f.carrier(),
            Duration::from_secs(3)
        )
        .is_err());
    assert!(
        !f.c.paths.signer.exists(),
        "must not recreate a missing signer"
    );
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert_eq!(f.transfer.requests.load(Ordering::SeqCst), 0);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&f.c.paths.signer)
        .expect("restore owned original protected bytes");
    file.write_all(&original).expect("exact original signer");
    file.sync_all().expect("restoration durability");
    drop(file);
    let mut owner = open(&f.c);
    let client = f.transfer.client(&mut owner, &f.c);
    owner
        .activate(&f.c.policy, 190, Some(client))
        .expect("original owner restored")
        .close();
}

#[test]
fn enrollment_witness_selection_refuses_foreign_plan_bad_receipt_and_mac_valid_parent_change() {
    let f = Fixture::new();
    let other = Fixture::new();
    let mut owner = open(&f.c);
    assert!(owner
        .prepare_witness_handoff(f.c.policy.historical(), other.transfer.plan.clone(), || Ok(
            180
        ))
        .is_err());
    let mut owner = open(&f.c);
    owner
        .prepare_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), || Ok(180))
        .expect("original prepare");
    let mut bad = f.transfer.receipt.clone();
    *bad.get_mut(100).expect("signature byte") ^= 1;
    assert!(owner
        .adopt_witness_handoff(f.c.policy.historical(), f.transfer.plan.clone(), &bad)
        .is_err());
    let mut owner = f.transfer.adopt_parent(&f.c, 180);
    owner.close();
    let replace = |bytes: Option<&[u8]>| {
        let db = open_private_database(&f.c.paths.configuration).expect("closed owned parent");
        let tx = transaction(&db).expect("owned mutation");
        let mut table = tx.open_table(TABLE).expect("parent table");
        let original = table
            .get("witness-handoff")
            .expect("row")
            .expect("original selection")
            .value()
            .to_vec();
        if let Some(bytes) = bytes {
            table
                .insert("witness-handoff", bytes)
                .expect("replace exact row");
        }
        drop(table);
        tx.commit().expect("owned test mutation");
        original
    };
    let original = replace(None);
    let mut changed = original.clone();
    changed
        .get_mut(72..80)
        .expect("prepared timestamp")
        .copy_from_slice(&181u64.to_be_bytes());
    let end = changed.len().checked_sub(32).expect("MAC");
    let key = JournalKey::open(&f.c.paths.wrapping).expect("owned fixture storage key");
    let mut mac = auth(&key).expect("parent authenticator");
    mac.update(b"Q-PERIAPT-ENROLLMENT-WITNESS-SELECTION/v1");
    mac.update(changed.get(..end).expect("body"));
    changed
        .get_mut(end..)
        .expect("MAC")
        .copy_from_slice(&mac.finalize().into_bytes());
    replace(Some(&changed));
    let mut owner = open(&f.c);
    assert!(owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            f.transfer.plan.clone(),
            f.carrier(),
            Duration::from_secs(3)
        )
        .is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert_eq!(f.transfer.requests.load(Ordering::SeqCst), 0);
    replace(Some(&original));
    let mut owner = open(&f.c);
    let client = f.transfer.client(&mut owner, &f.c);
    owner
        .activate(&f.c.policy, 190, Some(client))
        .expect("exact restored metadata")
        .close();
}
