// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local expiry of an approved target preserves the original registration and traffic.
use crate::{fixture, p, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub(crate) struct Case<'a> {
    pub root: &'a p::RootSigningKey,
    pub original: &'a p::VerifiedEnrollmentRequest,
    pub device: &'a p::VerifiedDevice,
    pub certificate: &'a [u8],
    pub roster: &'a p::IssuedRoster,
    pub policy: &'a p::VerifiedSessionPolicy,
    pub validity: p::Validity,
    pub base: &'a Path,
    pub inputs: &'a Path,
    pub responder: &'a Path,
}
fn status(
    proof: &p::VerifiedCredentialRenewal,
    phase: u32,
    checkpoint: Option<p::RosterCheckpoint>,
    at: u64,
) -> Vec<u8> {
    let mut out = phase.to_be_bytes().to_vec();
    out.extend_from_slice(proof.operation().as_bytes());
    out.extend_from_slice(&proof.statement_digest());
    if let Some(cp) = checkpoint {
        out.extend_from_slice(&cp.version().to_be_bytes());
        out.extend_from_slice(&cp.digest());
    } else {
        out.extend_from_slice(&[0; 40]);
    }
    out.extend_from_slice(&at.to_be_bytes());
    out
}
impl Case<'_> {
    fn issue(
        &self,
        prefix: &str,
        version: u64,
        roster_until: u64,
    ) -> Result<p::VerifiedCredentialRenewal> {
        let family = fixture::array(self.inputs, "family")?;
        let until = self
            .validity
            .until()
            .checked_add(1200)
            .ok_or("credential expiry overflow")?;
        let successor = self.root.issue_device(
            p::DeviceDescription::new(
                self.device.device_id(),
                self.device.generation(),
                family,
                p::Validity::new(self.validity.from(), until)?,
            )?,
            self.original.public_key().clone(),
        )?;
        let roster = self.root.issue_roster(
            version,
            p::Validity::new(self.validity.from(), roster_until)?,
            &[self.root.roster_entry(&successor)?],
        )?;
        let pin = p::AccountPin::new(
            self.root.account_id()?,
            self.root.public_key()?,
            roster.checkpoint(),
            family,
        )?;
        let operation = p::CredentialRenewalId::generate()?;
        let now = fixture::now()?;
        let grant = self.root.issue_credential_renewal(
            p::CredentialRenewalMaterials {
                original_credential: self.certificate,
                previous_credential: self.certificate,
                successor_credential: &successor,
                previous_roster: self.roster.as_bytes(),
                successor_roster: roster.as_bytes(),
            },
            &p::CredentialRenewalAuthorization {
                operation,
                previous: self.roster.checkpoint(),
                policy_digest: self.policy.checkpoint().digest(),
            },
            &pin,
            now,
        )?;
        let proof = p::VerifiedCredentialRenewal::verify(
            grant.as_bytes(),
            &pin,
            self.policy.checkpoint().digest(),
            now,
        )?;
        for (name, bytes) in [
            ("grant", grant.as_bytes().to_vec()),
            ("operation", operation.as_bytes().to_vec()),
            ("statement", proof.statement_digest().to_vec()),
            ("version", version.to_be_bytes().to_vec()),
            ("digest", roster.checkpoint().digest().to_vec()),
        ] {
            publish_private_bytes(&self.inputs.join(format!("{prefix}{name}")), &bytes)?;
        }
        Ok(proof)
    }
    pub fn run(&self, run: &impl Fn(&str, &str) -> Result<Vec<u8>>) -> Result<()> {
        let identity = run("credential-local-identity", "local-original")?;
        assert_eq!(identity.len(), 96);
        let next: [u8; 32] = identity.get(64..).ok_or("next message")?.try_into()?;
        publish_private_bytes(&self.inputs.join("local-next-message"), &next)?;
        let until = fixture::now()?
            .checked_add(30)
            .ok_or("target expiry overflow")?;
        let first = self.issue("local-first-", 2, until)?;
        let second = self.issue("local-second-", 3, self.validity.until())?;
        assert_ne!(first.operation(), second.operation());
        assert_eq!(
            run("credential-local-rejected", "local-rejected")?,
            102u32.to_be_bytes()
        );
        let pending = status(&first, 1, None, 0);
        for name in ["local-staged", "local-stage-replayed"] {
            assert_eq!(run("credential-local-stage", name)?, pending);
        }
        assert_eq!(
            run(
                "credential-local-next-stage-blocked",
                "local-replacement-blocked"
            )?,
            211u32.to_be_bytes()
        );
        let deadline = Instant::now() + Duration::from_secs(40);
        while fixture::now()? < until {
            if Instant::now() >= deadline {
                return Err("local target-roster expiry deadline".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let at = fixture::now()?;
        assert!(at >= until && at < self.validity.until() && at < self.policy.validity().until());
        let mut observation = until.to_be_bytes().to_vec();
        observation.extend_from_slice(&at.to_be_bytes());
        observation.extend_from_slice(&self.validity.until().to_be_bytes());
        observation.extend_from_slice(&self.policy.validity().until().to_be_bytes());
        publish_private_bytes(&self.base.join("local-expiry-observation"), &observation)?;
        assert_eq!(
            run(
                "credential-local-expired-activate",
                "local-expired-activate"
            )?,
            104u32.to_be_bytes()
        );
        assert_eq!(run("credential-local-pending", "local-pending")?, pending);
        let expired = run("credential-local-reconcile", "local-expired")?;
        assert_eq!(expired.len(), 116);
        let observed = u64::from_be_bytes(expired.get(108..).ok_or("observed time")?.try_into()?);
        assert!(observed >= at && observed < self.validity.until());
        assert_eq!(
            expired,
            status(&first, 3, Some(self.roster.checkpoint()), observed)
        );
        assert_eq!(
            run("credential-local-reconcile", "local-expired-replayed")?,
            expired
        );
        assert_eq!(
            run("credential-local-needs-approval", "local-needs-approval")?,
            104u32.to_be_bytes()
        );
        assert_eq!(
            run("credential-local-next-stage", "local-next-staged")?,
            status(&second, 1, None, 0)
        );
        assert_eq!(
            run("credential-local-reconcile", "local-retained-terminal")?,
            expired
        );
        assert_eq!(
            run("credential-local-next-activate", "local-next-active")?,
            identity.get(..64).ok_or("identity")?
        );
        let committed = status(
            &second,
            2,
            Some(second.successor_device().roster().checkpoint()),
            0,
        );
        let mut receiver = fixture::Peer::open(self.responder)?;
        let admitted = receiver.service.parts()?.0.admit_peer_credential_renewal(
            &second,
            second.operation(),
            self.policy,
            fixture::now()?,
        )?;
        assert_eq!(admitted, second.successor_device().roster().checkpoint());
        receiver.close();
        let mut checkpoint = admitted.version().to_be_bytes().to_vec();
        checkpoint.extend_from_slice(&admitted.digest());
        publish_private_bytes(&self.base.join("local-peer-admitted"), &checkpoint)?;
        assert_eq!(run("credential-local-active", "local-active")?, identity);
        let session = fixture::array::<32>(self.inputs, "connection-session")?;
        let old = fixture::array::<32>(self.inputs, "connection-message")?;
        let old_effect = self
            .responder
            .join(format!("application-{}", fixture::hex(&old)));
        let before = fs::read(&old_effect)?;
        let (mut server, address) =
            fixture::spawn(self.responder, 85, "restore-current-application")?;
        fs::write(self.inputs.join("connection-address"), address.to_string())?;
        let mut sent = session.to_vec();
        sent.extend_from_slice(&next);
        let delivery = run("credential-local-send", "local-sent");
        let finished = fixture::wait(&mut server);
        let log = fs::read(self.responder.join("peer-85.log"))?;
        publish_private_bytes(&self.base.join("local-receiver.log"), &log)?;
        assert!(
            finished?.success(),
            "local receiver: {}",
            String::from_utf8_lossy(&log)
        );
        assert_eq!(delivery?, sent);
        assert_eq!(fs::read(old_effect)?, before);
        fixture::effect(
            self.responder,
            session,
            p::MessageId::from_trusted_state(next)?,
            b"persisted before process exit",
        )?;
        publish_private_bytes(
            &self.base.join("local-effect"),
            &fs::read(
                self.responder
                    .join(format!("application-{}", fixture::hex(&next))),
            )?,
        )?;
        let count = fs::read_dir(self.responder)?
            .collect::<std::io::Result<Vec<_>>>()?
            .iter()
            .filter(|p| p.file_name().to_string_lossy().starts_with("application-"))
            .count();
        assert_eq!(count, 2);
        publish_private_bytes(&self.base.join("local-effect-count"), &2u32.to_be_bytes())?;
        assert_eq!(
            run("credential-local-next-status", "local-next-status")?,
            committed
        );
        assert_eq!(
            run("credential-local-next-expiry", "local-next-expiry")?,
            committed
        );
        assert_eq!(
            run("credential-local-next-reopen", "local-next-reopened")?,
            identity.get(..64).ok_or("identity")?
        );
        Ok(())
    }
}
