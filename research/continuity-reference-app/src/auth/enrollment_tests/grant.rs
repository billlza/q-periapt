// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real host issuance and an SDK-owned installation. No fixture clock override.
use super::*;
use crate::{
    credential_grant::{CredentialGrantRequest, IssuedCredentialGrant},
    enrollment::{CredentialExtensionRequest, IssuedCredentialExtension},
    native_device::NativeDevice,
    policy_publisher::{Anchor, BootstrapMode, Publisher, Request},
};
use std::path::PathBuf;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};

mod crash;
mod inputs;
mod sequence;
mod witness;

struct Case {
    path: PathBuf,
    host: Service,
    auth: WebauthnAuthenticator<SoftPasskey>,
    token: String,
    invitation: Invitation,
    first: Vec<u8>,
    input: CredentialGrantRequest,
    policy: sdk::VerifiedSessionPolicy,
    historical: sdk::HistoricalSessionPolicy,
}
impl Case {
    fn new() -> Result<Self> {
        Self::with_extended_installation(false)
    }
    fn with_extended_installation(extended: bool) -> Result<Self> {
        Self::with_profile(extended, None)
    }
    fn with_profile(extended: bool, witness: Option<&witness::Server>) -> Result<Self> {
        let (dir, mut host) = service()?;
        let path = dir.keep().canonicalize()?;
        eprintln!("Retained grant private fixture: {}", path.display());
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        let mut publisher = Publisher::provision(
            &path.join("publisher.redb"),
            [90; 32],
            crate::test_support::sdk_input()?,
        )?;
        let family = publisher.prepare()?.family;
        let at = crate::enrollment::now()?;
        publisher.issue(
            [91; 32],
            Request {
                bootstrap_mode: BootstrapMode::ReusableBoth,
                valid_from: at,
                valid_until: at + 7200,
                send_budget: 8,
                anchor: match witness {
                    None => Anchor::LocalOnly {},
                    Some(server) => Anchor::Required {
                        identity: *server.pin.identity().as_bytes(),
                        key: server.pin.public_key().encode().to_vec(),
                    },
                },
            },
            at,
        )?;
        let (pins, materials) = publisher.export([91; 32])?;
        let (policy, witness_pin) = pins.verify(&materials, family, at)?;
        assert_eq!(witness_pin.is_some(), witness.is_some());
        let (historical, _) = pins.verify_historical(&materials, family)?;
        host.store.enable_enrollment(family)?;
        host.store.enable_enrollment_reapproval()?;
        host.store.enable_enrollment_extensions()?;
        host.prepare_enrollment_root(&token)?;
        let invitation = host.invite_enrollment(&token, crate::enrollment::random()?)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join("device"))?;
        drop(sdk::JournalKey::provision(&path.join("wrap.key"))?);
        let mut device = NativeDevice::begin(
            &path.join("device"),
            &path.join("wrap.key"),
            invitation.clone(),
            crate::enrollment::now()?,
        )?;
        let proof = device.request(crate::enrollment::now()?)?;
        host.approve_enrollment(&token, invitation.operation, &proof)?;
        let first = host.issue_enrollment(&token, invitation.operation)?;
        let issued: IssuedEnrollment = serde_json::from_slice(&first)?;
        let mut selected_certificate = issued.certificate.clone();
        let mut current = host.enrollment_root(&token)?;
        device.accept(&issued, &current, &policy, crate::enrollment::now()?)?;
        let original_extension = if extended {
            let selection = CredentialExtensionRequest {
                request_id: crate::enrollment::random()?,
                enrollment: invitation.operation,
                previous_extension: None,
                predecessor: current.roster.as_ref().ok_or("roster")?.checkpoint,
                valid_until: invitation.valid_until + 3600,
            };
            let issued: IssuedCredentialExtension =
                serde_json::from_slice(&host.extend_enrollment_credential(&token, &selection)?)?;
            selected_certificate = issued.certificate.clone();
            current = host.enrollment_root(&token)?;
            device.extend(
                &selection,
                &issued,
                &current,
                &policy,
                crate::enrollment::now()?,
            )?;
            Some(selection.request_id)
        } else {
            None
        };
        let preparation = device.prepare(&current, &policy, crate::enrollment::now()?)?;
        if let Some(server) = witness {
            let sdk::InstallationPreparation::RequiresEnrollment(genesis) = preparation else {
                return Err("Witness genesis is required".into());
            };
            let roster = current.roster.as_ref().ok_or("roster")?;
            let pin = sdk::AccountPin::new(
                current.account,
                sdk::PublicKey::decode(&current.public_key)?,
                roster.checkpoint.as_sdk()?,
                family,
            )?;
            let device = pin.verify_device(
                &selected_certificate,
                &roster.bytes,
                crate::enrollment::now()?,
            )?;
            server.store.lock().map_err(|_| "witness lock")?.enroll(
                &genesis,
                &device,
                &policy,
                crate::enrollment::now()?,
            )?;
        }
        device
            .activate(
                &current,
                &policy,
                witness_pin.clone(),
                witness.map(|s| s.address),
                crate::enrollment::now()?,
            )?
            .close();
        let mut device = NativeDevice::open(
            &path.join("device"),
            &path.join("wrap.key"),
            invitation.clone(),
        )?;
        let retained = device.credential_renewal_request(
            crate::enrollment::random()?,
            &historical,
            witness_pin,
            witness.map(|s| s.address),
        )?;
        device.close();
        let extension = CredentialExtensionRequest {
            request_id: crate::enrollment::random()?,
            enrollment: invitation.operation,
            previous_extension: original_extension,
            predecessor: current.roster.ok_or("roster")?.checkpoint,
            valid_until: invitation.valid_until + if extended { 7200 } else { 3600 },
        };
        let next: IssuedCredentialExtension =
            serde_json::from_slice(&host.extend_enrollment_credential(&token, &extension)?)?;
        let input = CredentialGrantRequest {
            retained,
            original_extension,
            previous_extension: original_extension,
            successor_extension: extension.request_id,
            target_checkpoint: next.checkpoint,
        };
        Ok(Self {
            path,
            host,
            auth,
            token,
            invitation,
            first,
            input,
            policy,
            historical,
        })
    }
    fn issue(&mut self) -> Result<Vec<u8>> {
        Ok(self.host.issue_credential_grant(&self.token, &self.input)?)
    }
    fn pin(&mut self) -> Result<sdk::AccountPin> {
        let root = self.host.enrollment_root(&self.token)?;
        Ok(sdk::AccountPin::new(
            root.account,
            sdk::PublicKey::decode(&root.public_key)?,
            root.roster.ok_or("roster")?.checkpoint.as_sdk()?,
            root.family,
        )?)
    }
    fn open_owner(&self) -> Result<sdk::DeviceEnrollment> {
        let d = self.path.join("device");
        Ok(sdk::DeviceEnrollment::open(
            sdk::EnrollmentPaths::new(
                &self.path.join("wrap.key"),
                &d.join("device.key"),
                &d.join("enrollment.redb"),
                sdk::InstallationPaths::new(
                    &d.join("installation.redb"),
                    &d.join("journal.redb"),
                    &d.join("archives.redb"),
                )?,
            )?,
            self.invitation.intent()?,
        )?)
    }
}

#[test]
fn retained_grant_preserves_original_identity_and_recovers_exact_issued_bytes() -> Result {
    let mut c = Case::new()?;
    let before = c.host.enrollment_root(&c.token)?;
    let signing = fs::read(c.path.join("device/device.key"))?;
    let wrapping = fs::read(c.path.join("wrap.key"))?;
    assert!(c.issue().is_err()); // Explicit schema admission, never auto-upgrade.
    c.host.store.enable_credential_grants()?;
    c.host.store.enable_credential_grants()?;
    let bytes = c.issue()?;
    let issued: IssuedCredentialGrant = serde_json::from_slice(&bytes)?;
    let grant = sdk::VerifiedCredentialRenewal::verify(
        &issued.grant,
        &c.pin()?,
        c.input.retained.original_policy.digest,
        crate::enrollment::now()?,
    )?;
    assert_eq!(
        grant.original_storage_owner(),
        c.input.retained.original_owner
    );
    assert_eq!(grant.statement_digest(), issued.statement);
    assert_eq!(issued.journal, c.input.retained.journal);
    // Certificate extension by itself cannot open the retained installation.
    let mut native = NativeDevice::open(
        &c.path.join("device"),
        &c.path.join("wrap.key"),
        c.invitation.clone(),
    )?;
    assert!(native
        .refresh_current(&before, &c.policy, crate::enrollment::now()?)
        .is_err());
    let mut owner = c.open_owner()?;
    owner.stage_credential_renewal(
        &grant,
        grant.operation(),
        &c.policy,
        crate::enrollment::now()?,
    )?;
    owner
        .activate(&c.policy, crate::enrollment::now()?, None)?
        .close();
    let mut owner = c.open_owner()?;
    let public = owner.public_admission()?;
    assert_eq!(*public.journal().as_bytes(), c.input.retained.journal);
    assert_eq!(public.checkpoint(), c.input.target_checkpoint.as_sdk()?);
    c.pin()?.verify_device(
        public.certificate(),
        public.roster(),
        crate::enrollment::now()?,
    )?;
    owner.close();
    assert_eq!(fs::read(c.path.join("device/device.key"))?, signing);
    assert_eq!(fs::read(c.path.join("wrap.key"))?, wrapping);
    assert_eq!(c.host.enrollment_root(&c.token)?, before);
    assert_eq!(c.issue()?, bytes);
    assert_eq!(
        c.host.issue_enrollment(&c.token, c.invitation.operation)?,
        c.first
    );
    assert!(c.host.cancel_credential_grant(&c.token, &c.input).is_err());
    c.host.suspend_enrollment_root(&c.token)?;
    drop(c.host);
    let mut host = reopen(&c.path)?;
    let (token, _) = login(&mut host, &mut c.auth, "alice")?;
    assert_eq!(host.issue_credential_grant(&token, &c.input)?, bytes);
    // Historical response retrieval does not need the account signing key.
    for entry in fs::read_dir(&c.path)? {
        let file = entry?.path();
        if file.extension().and_then(|s| s.to_str()) == Some("signer") {
            fs::rename(&file, file.with_extension("signer.retained"))?;
        }
    }
    assert_eq!(host.issue_credential_grant(&token, &c.input)?, bytes);
    Ok(())
}
