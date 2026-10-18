// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Root-authorized public peer changes for independent lifecycle verification.
use crate::{fixture::save, Result};
use q_periapt_continuity_identity_candidate::{
    AccountPin, CredentialRenewalAuthorization, CredentialRenewalId, CredentialRenewalMaterials,
    RootSigningKey, Validity, VerifiedCredentialRenewal, VerifiedDevice,
};
use std::path::Path;

pub(super) struct Scope {
    pub policy: [u8; 32],
    pub family: [u8; 32],
    pub local: bool,
    pub short_roster: bool,
}

pub(super) fn publish(
    output: &Path,
    root: &RootSigningKey,
    original: &[u8],
    previous: &VerifiedDevice,
    previous_roster: &[u8],
    scope: Scope,
) -> Result<Vec<VerifiedCredentialRenewal>> {
    let Scope {
        policy,
        family,
        local,
        short_roster,
    } = scope;
    let prefix = if local { "local" } else { "peer" };
    let first = root.issue_credential_extension(previous, 300, 170)?;
    let first_roster = root.issue_roster(
        2,
        Validity::new(100, if short_roster { 180 } else { 390 })?,
        &[root.roster_entry(&first)?],
    )?;
    let first_pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        first_roster.checkpoint(),
        family,
    )?;
    let id1 = CredentialRenewalId::generate()?;
    let authorization = CredentialRenewalAuthorization {
        operation: id1,
        previous: previous.roster().checkpoint(),
        policy_digest: policy,
    };
    let materials = || CredentialRenewalMaterials {
        original_credential: original,
        previous_credential: original,
        successor_credential: &first,
        previous_roster,
        successor_roster: first_roster.as_bytes(),
    };
    let first_now = if short_roster { 170 } else { 210 };
    let grant =
        root.issue_credential_renewal(materials(), &authorization, &first_pin, first_now)?;
    let replay =
        root.issue_credential_renewal(materials(), &authorization, &first_pin, first_now)?;
    let first_verified =
        VerifiedCredentialRenewal::verify(grant.as_bytes(), &first_pin, policy, first_now)?;
    save(output, &format!("{prefix}-renewal-1"), grant.as_bytes())?;
    save(
        output,
        &format!("{prefix}-renewal-1-resigned"),
        replay.as_bytes(),
    )?;
    save(
        output,
        &format!("{prefix}-renewal-1-operation"),
        id1.as_bytes(),
    )?;
    save(
        output,
        &format!("{prefix}-renewal-1-statement"),
        &first_verified.statement_digest(),
    )?;
    let mut target = first_roster.checkpoint().version().to_be_bytes().to_vec();
    target.extend_from_slice(&first_roster.checkpoint().digest());
    save(output, &format!("pin-{prefix}-renewal-1-target"), &target)?;
    let next = first_verified.successor_device();
    let second =
        root.issue_credential_extension(next, 350, if short_roster { 170 } else { 250 })?;
    let second_roster =
        root.issue_roster(3, Validity::new(100, 390)?, &[root.roster_entry(&second)?])?;
    let second_pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        second_roster.checkpoint(),
        family,
    )?;
    let id2 = CredentialRenewalId::generate()?;
    let authorization = CredentialRenewalAuthorization {
        operation: id2,
        previous: first_roster.checkpoint(),
        policy_digest: policy,
    };
    let second_grant = root.issue_credential_renewal(
        CredentialRenewalMaterials {
            original_credential: original,
            previous_credential: &first,
            successor_credential: &second,
            previous_roster: first_roster.as_bytes(),
            successor_roster: second_roster.as_bytes(),
        },
        &authorization,
        &second_pin,
        310,
    )?;
    let verified =
        VerifiedCredentialRenewal::verify(second_grant.as_bytes(), &second_pin, policy, 310)?;
    save(
        output,
        &format!("{prefix}-renewal-2"),
        second_grant.as_bytes(),
    )?;
    save(
        output,
        &format!("{prefix}-renewal-2-operation"),
        id2.as_bytes(),
    )?;
    save(
        output,
        &format!("{prefix}-renewal-2-statement"),
        &verified.statement_digest(),
    )?;
    let mut target = second_roster.checkpoint().version().to_be_bytes().to_vec();
    target.extend_from_slice(&second_roster.checkpoint().digest());
    save(output, &format!("pin-{prefix}-renewal-2-target"), &target)?;
    let revoked = root.issue_roster(4, Validity::new(100, 390)?, &[])?;
    let reappeared =
        root.issue_roster(5, Validity::new(100, 390)?, &[root.roster_entry(&second)?])?;
    let fork = root.issue_roster(3, Validity::new(100, 390)?, &[])?;
    for (name, roster) in [
        ("revoked", revoked),
        ("reappeared", reappeared),
        ("fork", fork),
    ] {
        save(
            output,
            &format!("{prefix}-{name}-roster"),
            roster.as_bytes(),
        )?;
        let mut target = roster.checkpoint().version().to_be_bytes().to_vec();
        target.extend_from_slice(&roster.checkpoint().digest());
        save(output, &format!("pin-{prefix}-{name}-target"), &target)?;
    }
    let mut grants = vec![first_verified, verified];
    if local {
        grants.push(alternate(
            output,
            root,
            original,
            previous,
            previous_roster,
            policy,
            family,
        )?);
    }
    Ok(grants)
}

// A distinct independently authorized operation follows the actual original
// predecessor after an uncommitted target expires. It is not the C1->C2 grant.
fn alternate(
    output: &Path,
    root: &RootSigningKey,
    original: &[u8],
    previous: &VerifiedDevice,
    previous_roster: &[u8],
    policy: [u8; 32],
    family: [u8; 32],
) -> Result<VerifiedCredentialRenewal> {
    let next = root.issue_credential_extension(previous, 360, 170)?;
    let roster = root.issue_roster(6, Validity::new(100, 390)?, &[root.roster_entry(&next)?])?;
    let pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let operation = CredentialRenewalId::generate()?;
    let grant = root.issue_credential_renewal(
        CredentialRenewalMaterials {
            original_credential: original,
            previous_credential: original,
            successor_credential: &next,
            previous_roster,
            successor_roster: roster.as_bytes(),
        },
        &CredentialRenewalAuthorization {
            operation,
            previous: previous.roster().checkpoint(),
            policy_digest: policy,
        },
        &pin,
        310,
    )?;
    let verified = VerifiedCredentialRenewal::verify(grant.as_bytes(), &pin, policy, 310)?;
    save(output, "local-renewal-alternate", grant.as_bytes())?;
    save(
        output,
        "local-renewal-alternate-operation",
        operation.as_bytes(),
    )?;
    save(
        output,
        "local-renewal-alternate-statement",
        &verified.statement_digest(),
    )?;
    let mut target = roster.checkpoint().version().to_be_bytes().to_vec();
    target.extend_from_slice(&roster.checkpoint().digest());
    save(output, "pin-local-renewal-alternate-target", &target)?;
    Ok(verified)
}
