// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use redb::{ReadableDatabase, TableDefinition};

#[test]
fn replacement_accepts_expired_identity_with_disjoint_current_roster_without_clock_override(
) -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    schema6(&mut host.store)?;
    host.store.enable_device_replacements()?;
    host.prepare_enrollment_root(&token)?;
    let mut original = host.invite_enrollment(&token, crate::enrollment::random()?)?;
    let account = host.store.account("alice")?.ok_or("account")?;
    let at = crate::enrollment::now()?;
    drop(host);
    let snapshot = super::super::historical::expired_snapshot(&path, &mut original, &account, at)?;
    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    let root = host.enrollment_root(&token)?;
    let pin = sdk::AccountPin::new(
        root.account,
        sdk::PublicKey::decode(&root.public_key)?,
        snapshot.current.checkpoint(),
        root.family,
    )?;
    assert!(pin
        .verify_historical_device(&snapshot.certificate, snapshot.current.as_bytes())
        .is_err());
    assert!(pin
        .verify_device(
            &snapshot.certificate,
            snapshot.current.as_bytes(),
            crate::enrollment::now()?
        )
        .is_err());
    let input = input(&mut host, &token, &original)?;
    let (next, _, response) = replacement(&mut host, &path, &token, &input)?;
    assert!(next.valid_from >= at);
    assert_eq!(next.generation, 2);
    let receipt: IssuedEnrollment = serde_json::from_slice(&response)?;
    assert_eq!(receipt.checkpoint.version, 3);
    verify(&host.enrollment_root(&token)?, &receipt)?;
    assert_eq!(
        host.issue_enrollment(&token, original.operation)?,
        snapshot.first
    );
    Ok(())
}

#[test]
fn replacement_missing_intent_is_corruption_not_ordinary_enrollment() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    schema6(&mut host.store)?;
    host.store.enable_device_replacements()?;
    host.prepare_enrollment_root(&token)?;
    let (old, _, _) = issued(&mut host, &path, &token)?;
    let input = input(&mut host, &token, &old)?;
    let next = host.invite_device_replacement(&token, &input)?;
    let before = host.enrollment_root(&token)?;
    drop(host);
    let db = q_periapt_host_store::filesystem::open_private_database(&path.join("accounts.redb"))?;
    let operations: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_operations");
    let mut record: serde_json::Value = {
        let tx = db.begin_read()?;
        let table = tx.open_table(operations)?;
        serde_json::from_slice(
            table
                .get(next.operation.as_slice())?
                .ok_or("operation")?
                .value(),
        )?
    };
    record
        .as_object_mut()
        .ok_or("object")?
        .remove("replacement")
        .ok_or("replacement")?;
    let mut tx = db.begin_write()?;
    tx.set_durability(redb::Durability::Immediate)?;
    tx.set_two_phase_commit(true);
    tx.open_table(operations)?.insert(
        next.operation.as_slice(),
        serde_json::to_vec(&record)?.as_slice(),
    )?;
    tx.commit()?;
    drop(db);
    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(host.enrollment_root(&token)?, before);
    assert!(matches!(
        host.enrollment_status(&token, next.operation),
        Err(Error::Internal)
    ));
    // Internal corruption poisons this store owner, rather than silently using a
    // generation2 operation as a legacy, unconstrained invitation.
    assert!(host.enrollment_root(&token).is_err());
    Ok(())
}
