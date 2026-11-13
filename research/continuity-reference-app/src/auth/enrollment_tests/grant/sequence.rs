// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn retained_grant_follows_multiple_extensions_of_an_already_extended_installation() -> Result {
    let mut c = Case::with_extended_installation(true)?;
    c.host.store.enable_credential_grants()?;
    let original = c.input.retained.clone();
    assert!(c.input.original_extension.is_some());
    for cycle in 0..2 {
        let bytes = c.issue()?;
        let issued: IssuedCredentialGrant = serde_json::from_slice(&bytes)?;
        let grant = sdk::VerifiedCredentialRenewal::verify(
            &issued.grant,
            &c.pin()?,
            original.original_policy.digest,
            crate::enrollment::now()?,
        )?;
        if cycle == 1 {
            // Issuer suspension fences new signatures. It is not a signed
            // roster revocation of this already-issued, still-current G.
            c.host.suspend_enrollment_root(&c.token)?;
        }
        let current = c.host.enrollment_root(&c.token)?;
        let inputs = crate::native_device::CredentialRecoveryInputs {
            approval: &c.input,
            issued: &issued,
            companions: None,
            current: &current,
            original_policy: &c.historical,
            policy: &c.policy,
        };
        assert_eq!(
            grant.original_storage_owner(),
            c.input.retained.original_owner
        );
        NativeDevice::open(
            &c.path.join("device"),
            &c.path.join("wrap.key"),
            c.invitation.clone(),
        )?
        .activate_credential_recovery(&inputs, None, None, crate::enrollment::now()?)?
        .close();
        let mut device = NativeDevice::open(
            &c.path.join("device"),
            &c.path.join("wrap.key"),
            c.invitation.clone(),
        )?;
        let next = device.credential_renewal_request(
            crate::enrollment::random()?,
            &c.historical,
            None,
            None,
        )?;
        device.close();
        assert_eq!(next.original_certificate, original.original_certificate);
        assert_eq!(next.original_owner, original.original_owner);
        assert_eq!(next.journal, original.journal);
        assert_eq!(next.previous_checkpoint, c.input.target_checkpoint);
        assert_ne!(next.previous_certificate, original.previous_certificate);
        if cycle == 0 {
            let extension = CredentialExtensionRequest {
                request_id: crate::enrollment::random()?,
                enrollment: c.invitation.operation,
                previous_extension: Some(c.input.successor_extension),
                predecessor: c.input.target_checkpoint,
                valid_until: c.invitation.valid_until + 10800,
            };
            let target: IssuedCredentialExtension = serde_json::from_slice(
                &c.host.extend_enrollment_credential(&c.token, &extension)?,
            )?;
            c.input.retained = next;
            c.input.previous_extension = Some(c.input.successor_extension);
            c.input.successor_extension = extension.request_id;
            c.input.target_checkpoint = target.checkpoint;
        }
    }
    assert_eq!(
        c.host.issue_enrollment(&c.token, c.invitation.operation)?,
        c.first
    );
    Ok(())
}
