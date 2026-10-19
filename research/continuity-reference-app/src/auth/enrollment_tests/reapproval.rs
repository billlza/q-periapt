// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::Checkpoint;
use redb::ReadableTable;

#[test]
fn roster_conflict_reapproval_preserves_original_device_request_and_signing_files() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    host.store.enable_enrollment([42; 32])?;
    host.prepare_enrollment_root(&session)?;
    let a = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let b = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, wa) = request(&path, &a)?;
    let (paths, wb) = request(&path, &b)?;
    host.approve_enrollment(&session, a.operation, &wa)?;
    host.approve_enrollment(&session, b.operation, &wb)?;
    let ra: IssuedEnrollment =
        serde_json::from_slice(&host.issue_enrollment(&session, a.operation)?)?;
    assert!(host.issue_enrollment(&session, b.operation).is_err());
    let expected = host.enrollment_root(&session)?.roster.map(|r| r.checkpoint);
    let correlation = crate::enrollment::random()?;
    assert!(host
        .reapprove_enrollment(&session, b.operation, correlation, expected, &wb)
        .is_err());
    let original = host.enrollment_status(&session, b.operation)?;
    host.store.enable_enrollment_reapproval()?;
    host.store.enable_enrollment_reapproval()?;
    assert_eq!(host.enrollment_status(&session, b.operation)?, original);
    let client_dir = path.join(URL_SAFE_NO_PAD.encode(b.operation));
    let wrap = fs::read(client_dir.join("wrap.key"))?;
    let signer = fs::read(client_dir.join("signer.key"))?;
    let next = host.reapprove_enrollment(&session, b.operation, correlation, expected, &wb)?;
    assert_eq!(next.device, b.device);
    assert_eq!(next.generation, b.generation);
    assert_eq!(next.valid_from, b.valid_from);
    assert_eq!(next.valid_until, b.valid_until);
    assert_ne!(next.operation, b.operation);
    assert!(
        matches!(host.enrollment_status(&session, b.operation)?, EnrollmentStatus::Reapproved { successor } if successor == next)
    );
    assert!(host.issue_enrollment(&session, b.operation).is_err());
    assert!(host.cancel_enrollment(&session, b.operation).is_err());
    drop(host);
    let mut host = reopen(&path)?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(
        host.reapprove_enrollment(&session, b.operation, correlation, expected, &wb)?,
        next
    );
    let mut client = sdk::DeviceEnrollment::open(paths, b.intent()?)?;
    let identity = client.identity()?;
    assert_eq!(client.request(crate::enrollment::now()?)?, wb);
    client.close();
    let response = host.issue_enrollment(&session, next.operation)?;
    assert_eq!(host.issue_enrollment(&session, next.operation)?, response);
    let issued: IssuedEnrollment = serde_json::from_slice(&response)?;
    let current = host.enrollment_root(&session)?;
    verify(&current, &ra)?;
    verify(&current, &issued)?;
    let roster = current.roster.as_ref().ok_or("roster")?;
    assert_eq!(roster.checkpoint.version, 2);
    let pin = sdk::AccountPin::new(
        current.account,
        sdk::PublicKey::decode(&current.public_key)?,
        roster.checkpoint.as_sdk()?,
        current.family,
    )?;
    let device = pin.verify_device(
        &issued.certificate,
        &roster.bytes,
        crate::enrollment::now()?,
    )?;
    let wrapping = sdk::JournalKey::open(&client_dir.join("wrap.key"))?;
    sdk::DeviceSigningKey::open(&client_dir.join("signer.key"), &wrapping, identity)?
        .check_device(&device)?;
    assert!(
        fs::read(client_dir.join("wrap.key"))? == wrap,
        "original wrapping bytes changed"
    );
    assert!(
        fs::read(client_dir.join("signer.key"))? == signer,
        "original signing bytes changed"
    );
    Ok(())
}

#[test]
fn reapproval_is_scoped_idempotent_and_cannot_branch_retarget_or_revive_terminal_grants() -> Result
{
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    let mut bob = authenticator();
    register(&mut host, &mut bob, "bob")?;
    let (other, _) = login(&mut host, &mut bob, "bob")?;
    host.store.enable_enrollment([42; 32])?;
    host.prepare_enrollment_root(&session)?;
    let legacy = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, legacy_wire) = request(&path, &legacy)?;
    host.approve_enrollment(&session, legacy.operation, &legacy_wire)?;
    host.cancel_enrollment(&session, legacy.operation)?;
    host.store.enable_enrollment_reapproval()?;
    assert!(host
        .reapprove_enrollment(
            &session,
            legacy.operation,
            crate::enrollment::random()?,
            None,
            &legacy_wire
        )
        .is_err());
    let original = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, wire) = request(&path, &original)?;
    let nonce = crate::enrollment::random()?;
    let changed = Checkpoint {
        version: 7,
        digest: [9; 32],
    };
    assert!(host
        .reapprove_enrollment(&other, original.operation, nonce, None, &wire)
        .is_err());
    assert!(host
        .reapprove_enrollment(&session, original.operation, nonce, Some(changed), &wire)
        .is_err());
    assert!(host
        .reapprove_enrollment(
            &session,
            original.operation,
            original.request_id,
            None,
            &wire
        )
        .is_err());
    assert!(host
        .reapprove_enrollment(&session, original.operation, nonce, None, &legacy_wire)
        .is_err());
    let next = host.reapprove_enrollment(&session, original.operation, nonce, None, &wire)?;
    assert_eq!(
        host.reapprove_enrollment(&session, original.operation, nonce, None, &wire)?,
        next
    );
    assert!(host
        .reapprove_enrollment(&session, original.operation, nonce, Some(changed), &wire)
        .is_err());
    assert!(host
        .reapprove_enrollment(&session, original.operation, nonce, None, &legacy_wire)
        .is_err());
    assert!(host
        .reapprove_enrollment(
            &session,
            original.operation,
            crate::enrollment::random()?,
            None,
            &wire
        )
        .is_err());
    let next_nonce = crate::enrollment::random()?;
    let last = host.reapprove_enrollment(&session, next.operation, next_nonce, None, &wire)?;
    // Retrying an older decision yields its immediate original successor, not a silent fast-forward.
    assert_eq!(
        host.reapprove_enrollment(&session, original.operation, nonce, None, &wire)?,
        next
    );
    assert!(
        matches!(host.enrollment_status(&session, next.operation)?, EnrollmentStatus::Reapproved { successor } if successor == last)
    );
    host.suspend_enrollment_root(&session)?;
    assert_eq!(
        host.reapprove_enrollment(&session, next.operation, next_nonce, None, &wire)?,
        last
    );
    assert!(host
        .reapprove_enrollment(
            &session,
            last.operation,
            crate::enrollment::random()?,
            None,
            &wire
        )
        .is_err());
    assert!(host.issue_enrollment(&session, last.operation).is_err());
    host.cancel_enrollment(&session, last.operation)?;
    assert!(host
        .reapprove_enrollment(
            &session,
            last.operation,
            crate::enrollment::random()?,
            None,
            &wire
        )
        .is_err());
    host.sessions.get_mut(&session).ok_or("session")?.deadline = Instant::now();
    assert!(host
        .reapprove_enrollment(&session, original.operation, nonce, None, &wire)
        .is_err());
    Ok(())
}

// Construct historical authorization inputs in a private test database. The
// server still checks the real current clock; this is not real-time expiry evidence.
fn historical_invitation(path: &Path, id: [u8; 32], expire_credential: bool) -> Result<Invitation> {
    let db = q_periapt_host_store::filesystem::open_private_database(&path.join("accounts.redb"))?;
    let mut tx = db.begin_write()?;
    tx.set_durability(redb::Durability::Immediate)?;
    tx.set_two_phase_commit(true);
    let invitation;
    {
        let definition: redb::TableDefinition<&[u8], &[u8]> =
            redb::TableDefinition::new("enrollment_operations");
        let mut table = tx.open_table(definition)?;
        let bytes = table
            .get(id.as_slice())?
            .ok_or("original operation")?
            .value()
            .to_vec();
        let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
        let now = crate::enrollment::now()?;
        record["invitation"]["deadline"] = (now - 2).into();
        if expire_credential {
            record["invitation"]["valid_from"] = (now - 100).into();
            record["invitation"]["valid_until"] = (now - 1).into();
        }
        invitation = serde_json::from_value(record["invitation"].clone())?;
        table.insert(id.as_slice(), serde_json::to_vec(&record)?.as_slice())?;
    }
    tx.commit()?;
    Ok(invitation)
}

#[test]
fn explicit_reapproval_refreshes_only_host_deadline_and_refuses_expired_credential_scope() -> Result
{
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    host.store.enable_enrollment([42; 32])?;
    host.store.enable_enrollment_reapproval()?;
    host.prepare_enrollment_root(&session)?;
    let a = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, wire) = request(&path, &a)?;
    host.approve_enrollment(&session, a.operation, &wire)?;
    let expired = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    drop(host);
    historical_invitation(&path, a.operation, false)?;
    let expired = historical_invitation(&path, expired.operation, true)?;
    let (_, old_wire) = request_at(&path, &expired, expired.valid_from)?;
    sdk::VerifiedEnrollmentRequest::verify(&old_wire, &expired.intent()?, expired.valid_from)?;
    let mut host = reopen(&path)?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    assert!(host.issue_enrollment(&session, a.operation).is_err());
    assert!(host
        .reapprove_enrollment(
            &session,
            expired.operation,
            crate::enrollment::random()?,
            None,
            &old_wire
        )
        .is_err());
    assert!(matches!(
        host.enrollment_status(&session, expired.operation)?,
        EnrollmentStatus::Invited { .. }
    ));
    let next = host.reapprove_enrollment(
        &session,
        a.operation,
        crate::enrollment::random()?,
        None,
        &wire,
    )?;
    assert_eq!(next.valid_from, a.valid_from);
    assert_eq!(next.valid_until, a.valid_until);
    assert!(next.deadline > crate::enrollment::now()? && next.deadline <= next.valid_until);
    let issued: IssuedEnrollment =
        serde_json::from_slice(&host.issue_enrollment(&session, next.operation)?)?;
    verify(&host.enrollment_root(&session)?, &issued)?;
    assert!(host
        .reapprove_enrollment(
            &session,
            next.operation,
            crate::enrollment::random()?,
            Some(issued.checkpoint),
            &wire
        )
        .is_err());
    Ok(())
}
