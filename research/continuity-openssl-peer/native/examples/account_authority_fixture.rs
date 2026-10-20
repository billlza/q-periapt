// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public native-signed account transitions for independent state validation.
use q_periapt_continuity_identity_candidate::{
    AccountPin, CredentialRenewalAuthorization, CredentialRenewalId, CredentialRenewalMaterials,
    DeviceDescription, DeviceSigningKey, IssuedRoster, RootSigningKey, Validity,
    VerifiedCredentialRenewal,
};
use std::{fs, io::Write, path::Path};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const FAMILY: [u8; 32] = [84; 32];
const POLICY: [u8; 32] = [83; 32];

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

fn pin(root: &RootSigningKey, roster: &IssuedRoster) -> Result<AccountPin> {
    Ok(AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        FAMILY,
    )?)
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("expected new output directory and member count (3 or 32)".into());
    }
    let path = Path::new(&args[1]);
    let count: u8 = args[2].parse()?;
    if count != 3 && count != 32 {
        return Err("fixture member count must be 3 or 32".into());
    }
    fs::create_dir(path)?;
    let root = RootSigningKey::generate()?;
    save(path, "root", &root.public_key()?.encode())?;
    save(path, "account", &root.account_id()?)?;
    save(path, "family", &FAMILY)?;
    save(path, "policy", &POLICY)?;
    let mut original = Vec::new();
    for id in 1..=count {
        let signing = DeviceSigningKey::generate()?;
        let certificate = root.issue_device(
            DeviceDescription::new([id; 16], 1, FAMILY, Validity::new(100, 200)?)?,
            signing.public_key()?,
        )?;
        save(path, &format!("credential-1-{id}"), &certificate)?;
        original.push(certificate);
    }
    let mut previous = original.clone();
    let mut previous_roster = publish_roster(path, &root, 1, &previous)?;
    for cycle in [1u64, 2] {
        let prior_pin = pin(&root, &previous_roster)?;
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
        let roster = publish_roster(path, &root, cycle + 1, &next)?;
        let current_pin = pin(&root, &roster)?;
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
                policy_digest: POLICY,
            };
            let issued =
                root.issue_credential_renewal(materials(), &authorization, &current_pin, at)?;
            let checked =
                VerifiedCredentialRenewal::verify(issued.as_bytes(), &current_pin, POLICY, at)?;
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
            if cycle == 1 && index == 2 {
                let alternate = root.issue_credential_renewal(
                    materials(),
                    &CredentialRenewalAuthorization {
                        operation: CredentialRenewalId::generate()?,
                        previous: previous_roster.checkpoint(),
                        policy_digest: POLICY,
                    },
                    &current_pin,
                    at,
                )?;
                save(path, "grant-1-3-other-operation", alternate.as_bytes())?;
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
        }
        previous = next;
        previous_roster = roster;
    }
    let retained = previous
        .get(..previous.len() - 1)
        .ok_or("fixture membership")?
        .to_vec();
    publish_roster(path, &root, 4, &retained)?;
    // The root can sign these inputs, but retained history must reject the old
    // generation's resurrection and any later generation rollback.
    publish_roster(path, &root, 5, &previous)?;
    let signing = DeviceSigningKey::generate()?;
    let replacement = root.issue_device(
        DeviceDescription::new([count; 16], 2, FAMILY, Validity::new(100, 380)?)?,
        signing.public_key()?,
    )?;
    let mut replaced = retained;
    replaced.push(replacement);
    publish_roster(path, &root, 6, &replaced)?;
    publish_roster(path, &root, 7, &previous)?;
    if count == 32 {
        for batch in 1u16..=7 {
            let mut members = Vec::new();
            for offset in 1u16..=32 {
                let mut identity = [0u8; 16];
                identity[..2].copy_from_slice(&(batch * 32 + offset).to_be_bytes());
                let signer = DeviceSigningKey::generate()?;
                members.push(root.issue_device(
                    DeviceDescription::new(identity, 1, FAMILY, Validity::new(100, 380)?)?,
                    signer.public_key()?,
                )?);
            }
            publish_roster(path, &root, u64::from(batch) + 9, &members)?;
        }
        let mut identity = [0u8; 16];
        identity[..2].copy_from_slice(&257u16.to_be_bytes());
        let signer = DeviceSigningKey::generate()?;
        let overflow = root.issue_device(
            DeviceDescription::new(identity, 1, FAMILY, Validity::new(100, 380)?)?,
            signer.public_key()?,
        )?;
        publish_roster(path, &root, 17, &[overflow])?;
    }
    Ok(())
}
