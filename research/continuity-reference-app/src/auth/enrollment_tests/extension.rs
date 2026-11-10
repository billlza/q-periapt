// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::crash::{kill_at, Work};
mod historical;
use super::*;
use crate::enrollment::{CredentialExtensionRequest, IssuedCredentialExtension};

pub(super) fn issued(
    host: &mut Service,
    path: &Path,
    token: &str,
) -> Result<(Invitation, Vec<u8>, Vec<u8>)> {
    let original = host.invite_enrollment(token, crate::enrollment::random()?)?;
    let (_, proof) = request(path, &original)?;
    host.approve_enrollment(token, original.operation, &proof)?;
    let result = host.issue_enrollment(token, original.operation)?;
    Ok((original, proof, result))
}

pub(super) fn extension(
    host: &mut Service,
    token: &str,
    original: &Invitation,
) -> Result<CredentialExtensionRequest> {
    Ok(CredentialExtensionRequest {
        request_id: crate::enrollment::random()?,
        enrollment: original.operation,
        previous_extension: None,
        predecessor: host
            .enrollment_root(token)?
            .roster
            .ok_or("roster")?
            .checkpoint,
        valid_until: original.valid_until + 3600,
    })
}

fn verify_extension(root: &RootInfo, wire: &[u8]) -> Result<IssuedCredentialExtension> {
    let value: IssuedCredentialExtension = serde_json::from_slice(wire)?;
    let roster = root.roster.as_ref().ok_or("roster")?;
    assert_eq!(value.root_revision, root.revision);
    assert_eq!(value.checkpoint, roster.checkpoint);
    assert_eq!(value.roster, roster.bytes);
    sdk::AccountPin::new(
        root.account,
        sdk::PublicKey::decode(&root.public_key)?,
        roster.checkpoint.as_sdk()?,
        root.family,
    )?
    .verify_device(&value.certificate, &roster.bytes, crate::enrollment::now()?)?;
    Ok(value)
}

#[test]
fn credential_extension_preserves_original_account_issuance_and_exact_successor_chain() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    host.store.enable_enrollment([42; 32])?;
    host.prepare_enrollment_root(&token)?;
    let (original, proof, first) = issued(&mut host, &path, &token)?;
    let client = path.join(URL_SAFE_NO_PAD.encode(original.operation));
    let wrap = fs::read(client.join("wrap.key"))?;
    let signing = fs::read(client.join("signer.key"))?;
    let input = extension(&mut host, &token, &original)?;
    let account = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
    assert!(host.extend_enrollment_credential(&token, &input).is_err());
    assert!(host.store.enable_enrollment_extensions().is_err());
    host.store.enable_enrollment_reapproval()?;
    host.store.enable_enrollment_extensions()?;
    host.store.enable_enrollment_extensions()?;
    let result = host.extend_enrollment_credential(&token, &input)?;
    let next = verify_extension(&host.enrollment_root(&token)?, &result)?;
    assert_eq!(next.request, input);
    assert_eq!(next.checkpoint.version, 2);
    assert_eq!(host.issue_enrollment(&token, original.operation)?, first);
    drop(host);
    let mut host = reopen(&path)?;
    assert_eq!(
        serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
        account
    );
    // Compare before login: real passkey authentication advances its counter.
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(host.extend_enrollment_credential(&token, &input)?, result);
    let mut second = input.clone();
    second.request_id = crate::enrollment::random()?;
    second.previous_extension = Some(input.request_id);
    second.predecessor = next.checkpoint;
    second.valid_until += 3600;
    let last = host.extend_enrollment_credential(&token, &second)?;
    assert_eq!(
        verify_extension(&host.enrollment_root(&token)?, &last)?
            .checkpoint
            .version,
        3
    );
    assert_eq!(host.extend_enrollment_credential(&token, &input)?, result);
    assert_eq!(host.issue_enrollment(&token, original.operation)?, first);
    assert_eq!(fs::read(client.join("wrap.key"))?, wrap);
    assert_eq!(fs::read(client.join("signer.key"))?, signing);
    // Root-issued new validity does not alter the original device request.
    sdk::VerifiedEnrollmentRequest::verify(&proof, &original.intent()?, crate::enrollment::now()?)?;
    host.suspend_enrollment_root(&token)?;
    assert_eq!(host.extend_enrollment_credential(&token, &input)?, result);
    second.request_id = crate::enrollment::random()?;
    assert!(host.extend_enrollment_credential(&token, &second).is_err());
    Ok(())
}

#[test]
fn credential_extension_refuses_missing_approval_retarget_and_stale_predecessors() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    let mut other = authenticator();
    register(&mut host, &mut other, "bob")?;
    let (bob, _) = login(&mut host, &mut other, "bob")?;
    host.store.enable_enrollment([42; 32])?;
    host.store.enable_enrollment_reapproval()?;
    host.store.enable_enrollment_extensions()?;
    host.prepare_enrollment_root(&token)?;
    let (original, _, _) = issued(&mut host, &path, &token)?;
    let input = extension(&mut host, &token, &original)?;
    let before = host.enrollment_root(&token)?;
    assert!(host
        .extend_enrollment_credential("invalid", &input)
        .is_err());
    assert!(host.extend_enrollment_credential(&bob, &input).is_err());
    let pending = host.invite_enrollment(&token, crate::enrollment::random()?)?;
    let mut unissued = input.clone();
    unissued.enrollment = pending.operation;
    assert!(host
        .extend_enrollment_credential(&token, &unissued)
        .is_err());
    host.cancel_enrollment(&token, pending.operation)?;
    assert!(host
        .extend_enrollment_credential(&token, &unissued)
        .is_err());
    for until in [
        original.valid_until,
        crate::enrollment::now()? - 1,
        0,
        u64::MAX,
    ] {
        let mut bad = input.clone();
        bad.valid_until = until;
        assert!(host.extend_enrollment_credential(&token, &bad).is_err());
    }
    let mut bad = input.clone();
    bad.predecessor.version += 1;
    assert!(host.extend_enrollment_credential(&token, &bad).is_err());
    bad = input.clone();
    bad.previous_extension = Some([19; 32]);
    assert!(host.extend_enrollment_credential(&token, &bad).is_err());
    bad = input.clone();
    bad.request_id = [0; 32];
    assert!(host.extend_enrollment_credential(&token, &bad).is_err());
    assert_eq!(host.enrollment_root(&token)?, before);
    let result = host.extend_enrollment_credential(&token, &input)?;
    let next = verify_extension(&host.enrollment_root(&token)?, &result)?;
    bad = input.clone();
    bad.valid_until += 1;
    assert!(host.extend_enrollment_credential(&token, &bad).is_err());
    bad = input.clone();
    bad.request_id = crate::enrollment::random()?;
    assert!(host.extend_enrollment_credential(&token, &bad).is_err());
    bad.predecessor = next.checkpoint;
    assert!(host.extend_enrollment_credential(&token, &bad).is_err());
    assert_eq!(
        host.enrollment_root(&token)?
            .roster
            .ok_or("roster")?
            .checkpoint,
        next.checkpoint
    );
    host.sessions.get_mut(&token).ok_or("session")?.deadline = Instant::now();
    assert!(host.extend_enrollment_credential(&token, &input).is_err());
    Ok(())
}

#[test]
fn credential_extension_kills_commit_roster_and_response_together() -> Result {
    for boundary in [
        "credential-extension-before-commit",
        "credential-extension-after-commit",
    ] {
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
        let input = extension(&mut host, &token, &original)?;
        let before = host.enrollment_root(&token)?;
        drop(host);
        let cut = kill_at(&path, boundary, Work::Extend(input.clone()))?;
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        if boundary.ends_with("before-commit") {
            assert_eq!(host.enrollment_root(&token)?, before);
        }
        let recovered = host.extend_enrollment_credential(&token, &input)?;
        if boundary.ends_with("after-commit") {
            assert_eq!(recovered, cut);
        }
        assert_eq!(
            host.extend_enrollment_credential(&token, &input)?,
            recovered
        );
        assert_eq!(
            verify_extension(&host.enrollment_root(&token)?, &recovered)?
                .checkpoint
                .version,
            2
        );
        assert_eq!(host.issue_enrollment(&token, original.operation)?, first);
    }
    Ok(())
}

#[test]
fn credential_extension_upgrade_kills_preserve_accounts_and_explicit_schema_admission() -> Result {
    for boundary in [
        "extension-upgrade-before-commit",
        "extension-upgrade-after-commit",
    ] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        host.store.enable_enrollment([42; 32])?;
        host.store.enable_enrollment_reapproval()?;
        host.prepare_enrollment_root(&token)?;
        let (original, _, first) = issued(&mut host, &path, &token)?;
        let input = extension(&mut host, &token, &original)?;
        let account = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
        drop(host);
        kill_at(&path, boundary, Work::ExtensionUpgrade)?;
        let mut host = reopen(&path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            account
        );
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        assert_eq!(host.issue_enrollment(&token, original.operation)?, first);
        if boundary.ends_with("before-commit") {
            assert!(host.extend_enrollment_credential(&token, &input).is_err());
        }
        host.store.enable_enrollment_extensions()?;
        let result = host.extend_enrollment_credential(&token, &input)?;
        verify_extension(&host.enrollment_root(&token)?, &result)?;
    }
    Ok(())
}
