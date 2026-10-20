// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared public account material for model and actual session fixtures.
use q_periapt_continuity_identity_candidate::{
    AccountPin, CredentialRenewalAuthorization, CredentialRenewalId, CredentialRenewalMaterials,
    DeviceDescription, DeviceSigningKey, IssuedRoster, RootSigningKey, RosterCheckpoint, Validity,
    VerifiedCredentialRenewal, VerifiedDevice,
};
use std::{fs, io::Write, path::Path};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct Published {
    pub initial_roster: Vec<u8>,
    pub checkpoint: RosterCheckpoint,
    pub local_grants: Vec<VerifiedCredentialRenewal>,
    pub local_rosters: Vec<VerifiedDevice>,
}

fn save(path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path.join(name))?
        .write_all(bytes)?;
    Ok(())
}

fn publish_roster(
    path: &Path,
    root: &RootSigningKey,
    version: u64,
    certificates: &[Vec<u8>],
) -> Result<IssuedRoster> {
    let entries = certificates
        .iter()
        .map(|cert| root.roster_entry(cert))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let roster = root.issue_roster(version, Validity::new(100, 390)?, &entries)?;
    save(path, &format!("roster-{version}"), roster.as_bytes())?;
    let mut checkpoint = version.to_be_bytes().to_vec();
    checkpoint.extend_from_slice(&roster.checkpoint().digest());
    save(path, &format!("checkpoint-{version}"), &checkpoint)?;
    Ok(roster)
}

fn pin(root: &RootSigningKey, roster: &IssuedRoster, family: [u8; 32]) -> Result<AccountPin> {
    Ok(AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?)
}

pub(crate) fn publish(
    path: &Path,
    root: &RootSigningKey,
    original: Vec<Vec<u8>>,
    family: [u8; 32],
    policy: [u8; 32],
) -> Result<Published> {
    let count = u8::try_from(original.len())?;
    if count != 3 && count != 32 {
        return Err("fixture member count must be 3 or 32".into());
    }
    fs::create_dir(path)?;
    save(path, "root", &root.public_key()?.encode())?;
    save(path, "account", &root.account_id()?)?;
    save(path, "family", &family)?;
    save(path, "policy", &policy)?;
    for (index, certificate) in original.iter().enumerate() {
        save(path, &format!("credential-1-{}", index + 1), certificate)?;
    }
    let mut previous = original.clone();
    let mut previous_roster = publish_roster(path, root, 1, &previous)?;
    let mut published = Published {
        initial_roster: previous_roster.as_bytes().to_vec(),
        checkpoint: previous_roster.checkpoint(),
        local_grants: Vec::new(),
        local_rosters: Vec::new(),
    };
    // Same-credential membership removal before any G exercises the initial
    // R control without inventing a credential-renewal receipt.
    let before_g = publish_roster(
        path,
        root,
        9,
        original
            .get(..original.len() - 1)
            .ok_or("fixture members")?,
    )?;
    published
        .local_rosters
        .push(pin(root, &before_g, family)?.verify_historical_device(
            original.first().ok_or("original local credential")?,
            before_g.as_bytes(),
        )?);
    for cycle in [1u64, 2] {
        let prior_pin = pin(root, &previous_roster, family)?;
        let at = if cycle == 1 { 210 } else { 310 };
        let until = if cycle == 1 { 300 } else { 350 };
        let mut next = Vec::new();
        for (index, certificate) in previous.iter().enumerate() {
            let old =
                prior_pin.verify_historical_device(certificate, previous_roster.as_bytes())?;
            let member_until = if cycle == 1 && index == 2 { 275 } else { until };
            let extended = root.issue_credential_extension(&old, member_until, at)?;
            save(
                path,
                &format!("credential-{}-{}", cycle + 1, index + 1),
                &extended,
            )?;
            next.push(extended);
        }
        let roster = publish_roster(path, root, cycle + 1, &next)?;
        let current_pin = pin(root, &roster, family)?;
        for (index, ((first, old), new)) in original.iter().zip(&previous).zip(&next).enumerate() {
            let materials = || CredentialRenewalMaterials {
                original_credential: first,
                previous_credential: old,
                successor_credential: new,
                previous_roster: previous_roster.as_bytes(),
                successor_roster: roster.as_bytes(),
            };
            let authorization = CredentialRenewalAuthorization {
                operation: CredentialRenewalId::generate()?,
                previous: previous_roster.checkpoint(),
                policy_digest: policy,
            };
            let issued =
                root.issue_credential_renewal(materials(), &authorization, &current_pin, at)?;
            let checked =
                VerifiedCredentialRenewal::verify(issued.as_bytes(), &current_pin, policy, at)?;
            let label = format!("grant-{cycle}-{}", index + 1);
            save(path, &label, issued.as_bytes())?;
            save(
                path,
                &format!("{label}-statement"),
                &checked.statement_digest(),
            )?;
            save(
                path,
                &format!("{label}-operation"),
                checked.operation().as_bytes(),
            )?;
            if cycle == 1 && index == 0 {
                let resigned =
                    root.issue_credential_renewal(materials(), &authorization, &current_pin, at)?;
                save(path, "grant-1-1-resigned", resigned.as_bytes())?;
            }
            if index == 2 {
                let alternate = root.issue_credential_renewal(
                    materials(),
                    &CredentialRenewalAuthorization {
                        operation: CredentialRenewalId::generate()?,
                        previous: previous_roster.checkpoint(),
                        policy_digest: policy,
                    },
                    &current_pin,
                    at,
                )?;
                save(
                    path,
                    &format!("grant-{cycle}-3-other-operation"),
                    alternate.as_bytes(),
                )?;
            }
            if cycle == 2 && index == 1 {
                let alternate = root.issue_credential_renewal(
                    CredentialRenewalMaterials {
                        original_credential: old,
                        ..materials()
                    },
                    &authorization,
                    &current_pin,
                    at,
                )?;
                save(path, "grant-2-2-rebound-origin", alternate.as_bytes())?;
            }
            if index == 0 {
                published.local_grants.push(checked);
            }
        }
        previous = next;
        previous_roster = roster;
    }
    let retained = previous
        .get(..previous.len() - 1)
        .ok_or("fixture membership")?
        .to_vec();
    let removed = publish_roster(path, root, 4, &retained)?;
    let removed_pin = pin(root, &removed, family)?;
    let current_local = previous.first().ok_or("original local certificate")?;
    published
        .local_rosters
        .push(removed_pin.verify_historical_device(current_local, removed.as_bytes())?);
    // The root can sign these inputs, but retained history must reject the old
    // generation's resurrection and any later generation rollback.
    publish_roster(path, root, 5, &previous)?;
    let signing = DeviceSigningKey::generate()?;
    let replacement = root.issue_device(
        DeviceDescription::new([count; 16], 2, family, Validity::new(100, 380)?)?,
        signing.public_key()?,
    )?;
    let mut replaced = retained.clone();
    replaced.push(replacement);
    let replacement = publish_roster(path, root, 6, &replaced)?;
    published.local_rosters.push(
        pin(root, &replacement, family)?
            .verify_historical_device(current_local, replacement.as_bytes())?,
    );
    publish_roster(path, root, 7, &previous)?;
    // A complete later G uses the actually installed removal roster, not R3.
    let next = retained
        .iter()
        .map(|cert| {
            let previous = removed_pin.verify_historical_device(cert, removed.as_bytes())?;
            root.issue_credential_extension(&previous, 380, 355)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let following = publish_roster(path, root, 18, &next)?;
    let following_pin = pin(root, &following, family)?;
    for (index, ((first, old), new)) in original.iter().zip(&retained).zip(&next).enumerate() {
        let issued = root.issue_credential_renewal(
            CredentialRenewalMaterials {
                original_credential: first,
                previous_credential: old,
                successor_credential: new,
                previous_roster: removed.as_bytes(),
                successor_roster: following.as_bytes(),
            },
            &CredentialRenewalAuthorization {
                operation: CredentialRenewalId::generate()?,
                previous: removed.checkpoint(),
                policy_digest: policy,
            },
            &following_pin,
            355,
        )?;
        save(path, &format!("grant-18-{}", index + 1), issued.as_bytes())?;
        if index == 0 {
            published
                .local_grants
                .push(VerifiedCredentialRenewal::verify(
                    issued.as_bytes(),
                    &following_pin,
                    policy,
                    355,
                )?);
        }
    }
    // An alternative to the uncommitted first target must name the retained
    // original roster, not pretend that either earlier renewal was installed.
    let original_pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        published.checkpoint,
        family,
    )?;
    let fresh = original
        .iter()
        .map(|cert| {
            let device = original_pin.verify_historical_device(cert, &published.initial_roster)?;
            root.issue_credential_extension(&device, 350, 280)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let fresh_roster = publish_roster(path, root, 8, &fresh)?;
    let fresh_pin = pin(root, &fresh_roster, family)?;
    for (index, (old, new)) in original.iter().zip(&fresh).enumerate() {
        let issued = root.issue_credential_renewal(
            CredentialRenewalMaterials {
                original_credential: old,
                previous_credential: old,
                successor_credential: new,
                previous_roster: &published.initial_roster,
                successor_roster: fresh_roster.as_bytes(),
            },
            &CredentialRenewalAuthorization {
                operation: CredentialRenewalId::generate()?,
                previous: published.checkpoint,
                policy_digest: policy,
            },
            &fresh_pin,
            280,
        )?;
        save(path, &format!("grant-8-{}", index + 1), issued.as_bytes())?;
    }
    if count == 32 {
        for batch in 1u16..=7 {
            let mut members = Vec::new();
            for offset in 1u16..=32 {
                let mut identity = [0u8; 16];
                identity[..2].copy_from_slice(&(batch * 32 + offset).to_be_bytes());
                let signer = DeviceSigningKey::generate()?;
                members.push(root.issue_device(
                    DeviceDescription::new(identity, 1, family, Validity::new(100, 380)?)?,
                    signer.public_key()?,
                )?);
            }
            publish_roster(path, root, u64::from(batch) + 9, &members)?;
        }
        let mut identity = [0u8; 16];
        identity[..2].copy_from_slice(&257u16.to_be_bytes());
        let signer = DeviceSigningKey::generate()?;
        let overflow = root.issue_device(
            DeviceDescription::new(identity, 1, family, Validity::new(100, 380)?)?,
            signer.public_key()?,
        )?;
        publish_roster(path, root, 17, &[overflow])?;
    }
    Ok(published)
}
