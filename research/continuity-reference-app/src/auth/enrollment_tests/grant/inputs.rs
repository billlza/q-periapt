// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn retained_grant_requires_account_and_independently_selected_host_history() -> Result {
    let mut c = Case::new()?;
    c.host.store.enable_credential_grants()?;
    let mut bob = authenticator();
    register(&mut c.host, &mut bob, "bob")?;
    let (other, _) = login(&mut c.host, &mut bob, "bob")?;
    assert!(matches!(
        c.host.issue_credential_grant("invalid", &c.input),
        Err(Error::Unauthorized)
    ));
    assert!(c.host.issue_credential_grant(&other, &c.input).is_err());
    let before = c.host.enrollment_root(&c.token)?;
    let mut variants = Vec::new();
    let mut bad = c.input.clone();
    bad.retained.application = [99; 32];
    variants.push(bad);
    let mut bad = c.input.clone();
    bad.retained.previous_certificate[20] ^= 1;
    variants.push(bad);
    let mut bad = c.input.clone();
    bad.retained.previous_roster[20] ^= 1;
    variants.push(bad);
    let mut bad = c.input.clone();
    bad.retained.previous_checkpoint.digest[0] ^= 1;
    variants.push(bad);
    let mut bad = c.input.clone();
    bad.target_checkpoint.digest[0] ^= 1;
    variants.push(bad);
    let mut bad = c.input.clone();
    bad.successor_extension = [99; 32];
    variants.push(bad);
    let mut bad = c.input.clone();
    bad.original_extension = Some(c.input.successor_extension);
    variants.push(bad);
    let mut bad = c.input.clone();
    bad.previous_extension = Some(c.input.successor_extension);
    variants.push(bad);
    for bad in variants {
        assert!(c.host.issue_credential_grant(&c.token, &bad).is_err());
        assert!(matches!(
            c.host.cancel_credential_grant(&c.token, &bad),
            Err(Error::Conflict("Original retained grant is absent"))
        ));
    }
    assert_eq!(c.host.enrollment_root(&c.token)?, before);
    let bytes = c.issue()?;
    let mut retarget = c.input.clone();
    retarget.retained.journal[0] ^= 1;
    assert!(matches!(
        c.host.issue_credential_grant(&c.token, &retarget),
        Err(Error::Conflict("Original retained grant request differs"))
    ));
    assert_eq!(c.issue()?, bytes);
    c.host.sessions.get_mut(&c.token).ok_or("session")?.deadline = Instant::now();
    assert!(matches!(
        c.host.issue_credential_grant(&c.token, &c.input),
        Err(Error::Unauthorized)
    ));
    Ok(())
}

#[test]
fn retained_grant_failed_reserved_decision_requires_exact_explicit_cancel() -> Result {
    let mut c = Case::new()?;
    c.host.store.enable_credential_grants()?;
    let mut incorrect_owner = c.input.clone();
    incorrect_owner.retained.original_owner[0] ^= 1;
    assert!(matches!(
        c.host.issue_credential_grant(&c.token, &incorrect_owner),
        Err(Error::Conflict(
            "Reported original owner differs from credential"
        ))
    ));
    assert!(matches!(
        c.host.issue_credential_grant(&c.token, &c.input),
        Err(Error::Conflict("Original retained grant request differs"))
    ));
    assert!(c.host.cancel_credential_grant(&c.token, &c.input).is_err());
    c.host.cancel_credential_grant(&c.token, &incorrect_owner)?;
    c.host.cancel_credential_grant(&c.token, &incorrect_owner)?;
    assert!(matches!(
        c.host.issue_credential_grant(&c.token, &incorrect_owner),
        Err(Error::Conflict("Original retained grant is closed"))
    ));
    assert!(c.issue().is_err());
    c.input.retained.operation = crate::enrollment::random()?;
    c.issue()?;
    Ok(())
}

#[test]
fn retained_grant_wire_requires_explicit_selections_and_bounded_context() -> Result {
    let mut c = Case::new()?;
    c.host.store.enable_credential_grants()?;
    let value = serde_json::to_value(&c.input)?;
    for key in ["original_extension", "previous_extension"] {
        let mut bad = value.clone();
        bad.as_object_mut().ok_or("object")?.remove(key);
        assert!(serde_json::from_value::<CredentialGrantRequest>(bad).is_err());
    }
    let mut bad = value;
    bad["allow_reset"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CredentialGrantRequest>(bad).is_err());
    let mut bad = c.input.clone();
    bad.retained.original_roster = vec![1; 16385];
    assert!(c.host.issue_credential_grant(&c.token, &bad).is_err());
    let mut bad = c.input.clone();
    bad.retained.current_policy.digest[0] ^= 1;
    assert!(c.host.issue_credential_grant(&c.token, &bad).is_err());
    // Reported journal/current-policy context is not a separate signature claim.
    // The SDK grant is specifically tied to the original credential and policy.
    let bytes = c.issue()?;
    let issued: IssuedCredentialGrant = serde_json::from_slice(&bytes)?;
    assert!(sdk::VerifiedCredentialRenewal::verify(
        &issued.grant,
        &c.pin()?,
        [99; 32],
        crate::enrollment::now()?,
    )
    .is_err());
    Ok(())
}
