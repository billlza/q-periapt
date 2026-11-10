// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signed historical fixtures, never a clock override in the real host path.
use super::*;
use redb::{ReadableDatabase, TableDefinition};
use serde_json::json;

#[test]
fn credential_extension_uses_expired_signed_history_without_changing_the_host_clock() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    host.store.enable_enrollment([42; 32])?;
    host.store.enable_enrollment_reapproval()?;
    host.store.enable_enrollment_extensions()?;
    host.prepare_enrollment_root(&token)?;
    let mut original = host.invite_enrollment(&token, crate::enrollment::random()?)?;
    let account = host.store.account("alice")?.ok_or("account")?;
    let at = crate::enrollment::now()?;
    drop(host);
    let super::super::historical::Snapshot {
        first,
        roster,
        current,
        certificate,
    } = super::super::historical::expired_snapshot(&path, &mut original, &account, at)?;

    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    let info = host.enrollment_root(&token)?;
    let pin = sdk::AccountPin::new(
        info.account,
        sdk::PublicKey::decode(&info.public_key)?,
        roster.checkpoint(),
        info.family,
    )?;
    assert!(pin
        .verify_device(&certificate, roster.as_bytes(), crate::enrollment::now()?)
        .is_err());
    let current_pin = sdk::AccountPin::new(
        info.account,
        sdk::PublicKey::decode(&info.public_key)?,
        current.checkpoint(),
        info.family,
    )?;
    assert!(current_pin
        .verify_historical_device(&certificate, current.as_bytes())
        .is_err());
    let mut input = extension(&mut host, &token, &original)?;
    input.valid_until = at + 3600;
    let result = host.extend_enrollment_credential(&token, &input)?;
    let next = verify_extension(&host.enrollment_root(&token)?, &result)?;
    assert_eq!(next.request, input);
    assert_eq!(next.checkpoint.version, 3);
    assert_eq!(host.issue_enrollment(&token, original.operation)?, first);
    assert_eq!(host.extend_enrollment_credential(&token, &input)?, result);
    Ok(())
}

#[test]
fn credential_extension_does_not_restore_a_member_removed_from_the_current_root() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    host.store.enable_enrollment([42; 32])?;
    host.store.enable_enrollment_reapproval()?;
    host.store.enable_enrollment_extensions()?;
    host.prepare_enrollment_root(&token)?;
    let (original, _, first) = issued(&mut host, &path, &token)?;
    let account = host.store.account("alice")?.ok_or("account")?;
    drop(host);
    // Explicitly construct a consistent, signed revoked-host fixture. The
    // public device-revocation endpoint is separate work, not simulated here.
    let db = q_periapt_host_store::filesystem::open_private_database(&path.join("accounts.redb"))?;
    let roots: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_roots");
    let mut root: serde_json::Value = {
        let tx = db.begin_read()?;
        let table = tx.open_table(roots)?;
        serde_json::from_slice(
            table
                .get(account.application_id.as_slice())?
                .ok_or("root")?
                .value(),
        )?
    };
    let identity: [u8; 32] = serde_json::from_value(root["signing_id"].clone())?;
    let stem = URL_SAFE_NO_PAD.encode(identity);
    let wrapping = sdk::JournalKey::open(&path.join(format!("enrollment-{stem}.wrap")))?;
    let signer = sdk::RootSigningKey::open(
        &path.join(format!("enrollment-{stem}.signer")),
        &wrapping,
        sdk::SigningKeyId::from_trusted_state(identity)?,
    )?;
    let at = crate::enrollment::now()?;
    let roster = signer.issue_roster(2, sdk::Validity::new(at, at + 3600)?, &[])?;
    root["members"] = json!([]);
    root["roster"] = json!({"checkpoint":crate::enrollment::Checkpoint::from(roster.checkpoint()),"bytes":URL_SAFE_NO_PAD.encode(roster.as_bytes())});
    let mut tx = db.begin_write()?;
    tx.set_durability(redb::Durability::Immediate)?;
    tx.set_two_phase_commit(true);
    tx.open_table(roots)?.insert(
        account.application_id.as_slice(),
        serde_json::to_vec(&root)?.as_slice(),
    )?;
    tx.commit()?;
    drop(db);
    drop(signer);
    drop(wrapping);
    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    let input = extension(&mut host, &token, &original)?;
    let before = host.enrollment_root(&token)?;
    assert!(matches!(
        host.extend_enrollment_credential(&token, &input),
        Err(Error::Conflict("Device is no longer a current member"))
    ));
    assert_eq!(host.enrollment_root(&token)?, before);
    assert_eq!(host.issue_enrollment(&token, original.operation)?, first);
    Ok(())
}
