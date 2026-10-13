// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently approved credential renewal of the original managed registration.
use crate::{fixture, p, witness, witness_tls_faults, ConfigurationProcess, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct Renewal<'a> {
    pub(crate) root: &'a p::RootSigningKey,
    pub(crate) original: &'a p::VerifiedDevice,
    pub(crate) public_key: &'a p::PublicKey,
    pub(crate) validity: p::Validity,
    pub(crate) certificate: &'a [u8],
    pub(crate) roster: &'a p::IssuedRoster,
    pub(crate) reference: &'a Path,
    pub(crate) witness: &'a witness::Witness,
    pub(crate) tls: Option<&'a witness_tls_faults::FaultWitness>,
}

impl Renewal<'_> {
    pub(super) fn exchanges(&self) -> Result<Vec<witness::Capture>> {
        Ok(if let Some(tls) = self.tls {
            tls.captured
                .lock()
                .map_err(|_| "TLS capture")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.record.request().to_vec(),
                    reply: r.record.reply().to_vec(),
                    delivered: r.delivered,
                })
                .collect()
        } else {
            self.witness
                .captured
                .lock()
                .map_err(|_| "TCP capture")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.request.clone(),
                    reply: r.reply.clone(),
                    delivered: r.delivered,
                })
                .collect()
        })
    }
    pub(crate) fn run(&self, case: &crate::first_connection::Case<'_>) -> Result<()> {
        case.invoke(
            "credential-identity",
            &case.base.join("credential-original-identity"),
        )?;
        let identity = fs::read(case.base.join("credential-original-identity"))?;
        assert_eq!(identity.len(), 64);
        assert!(identity
            .get(..32)
            .ok_or("signing identity")?
            .iter()
            .any(|v| *v != 0));
        assert_eq!(
            identity.get(32..),
            fs::read(case.base.join("genesis"))?.get(4..36)
        );
        let now = fixture::now()?;
        let until = self.validity.until();
        assert!(
            now < until,
            "prepare independent grant before original credential expiry"
        );
        let mut sdk = fixture::sdk(self.reference)?;
        let policy = fixture::protocol_policy(self.reference, &sdk)?;
        let proof = self.issue(case, &policy, now)?;
        let deadline = Instant::now() + Duration::from_secs(120);
        while fixture::now()? < until {
            if Instant::now() >= deadline {
                return Err("credential expiry deadline".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let at = fixture::now()?;
        assert!(at < policy.validity().until());
        case.invoke("credential-expired", &case.base.join("credential-expired"))?;
        assert_eq!(
            fs::read(case.base.join("credential-expired"))?,
            104i32.to_ne_bytes()
        );
        case.invoke(
            "credential-expired-request",
            &case.base.join("credential-expired-request"),
        )?;
        assert_eq!(
            fs::read(case.base.join("credential-expired-request"))?,
            104i32.to_ne_bytes()
        );
        let mut observation = until.to_be_bytes().to_vec();
        observation.extend_from_slice(&at.to_be_bytes());
        observation.extend_from_slice(&policy.validity().until().to_be_bytes());
        publish_private_bytes(
            &case.base.join("credential-expiry-observation"),
            &observation,
        )?;
        println!("\nINDEPENDENT_CONFIGURATION_EXPIRED_CREDENTIAL_PASS language={} carrier={} profile={} old_activation_refused=true fresh_request_refused=true", case.language, case.carrier.ok_or("credential carrier")?, case.profile);
        self.stage(case, &proof, &policy)?;
        self.commit(case, &proof, &identity)?;
        admit_peer(case)?;
        policy.close();
        sdk.close();
        Ok(())
    }
    fn issue(
        &self,
        case: &crate::first_connection::Case<'_>,
        policy: &p::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<p::VerifiedCredentialRenewal> {
        let family = fixture::array(case.source, "family")?;
        let until = self.validity.until();
        let successor = self.root.issue_device(
            p::DeviceDescription::new(
                self.original.device_id(),
                self.original.generation(),
                family,
                p::Validity::new(
                    self.validity.from(),
                    until.checked_add(600).ok_or("credential clock overflow")?,
                )?,
            )?,
            self.public_key.clone(),
        )?;
        let target = self.root.issue_roster(
            2,
            p::Validity::new(
                self.validity.from(),
                until.checked_add(600).ok_or("roster clock overflow")?,
            )?,
            &[self.root.roster_entry(&successor)?],
        )?;
        let pin = p::AccountPin::new(
            self.root.account_id()?,
            self.root.public_key()?,
            target.checkpoint(),
            family,
        )?;
        let operation = p::CredentialRenewalId::generate()?;
        let grant = self.root.issue_credential_renewal(
            p::CredentialRenewalMaterials {
                original_credential: self.certificate,
                previous_credential: self.certificate,
                successor_credential: &successor,
                previous_roster: self.roster.as_bytes(),
                successor_roster: target.as_bytes(),
            },
            &p::CredentialRenewalAuthorization {
                operation,
                previous: self.roster.checkpoint(),
                policy_digest: policy.checkpoint().digest(),
            },
            &pin,
            now,
        )?;
        let proof = p::VerifiedCredentialRenewal::verify(
            grant.as_bytes(),
            &pin,
            policy.checkpoint().digest(),
            now,
        )?;
        for (name, bytes) in [
            ("credential-renewal", grant.as_bytes().to_vec()),
            ("credential-operation", operation.as_bytes().to_vec()),
            ("credential-statement", proof.statement_digest().to_vec()),
            (
                "renewal-version",
                target.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("renewal-digest", target.checkpoint().digest().to_vec()),
            ("renewed-certificate", successor),
            ("renewed-roster", target.as_bytes().to_vec()),
        ] {
            publish_private_bytes(&case.source.join(name), &bytes)?;
        }
        Ok(proof)
    }
    fn stage(
        &self,
        case: &crate::first_connection::Case<'_>,
        proof: &p::VerifiedCredentialRenewal,
        policy: &p::VerifiedSessionPolicy,
    ) -> Result<()> {
        let operation = proof.operation();
        case.invoke(
            "credential-stage-refused",
            &case.base.join("credential-refused"),
        )?;
        assert_eq!(
            fs::read(case.base.join("credential-refused"))?,
            102i32.to_ne_bytes()
        );
        for label in ["credential-staged", "credential-stage-replayed"] {
            case.invoke("credential-stage", &case.base.join(label))?;
            status(&fs::read(case.base.join(label))?, proof, 1)?;
        }
        case.invoke(
            "credential-prepare",
            &case.source.join("credential-proposal"),
        )?;
        case.invoke(
            "credential-prepare",
            &case.base.join("credential-proposal-replayed"),
        )?;
        let proposal = fs::read(case.source.join("credential-proposal"))?;
        assert_eq!(
            proposal,
            fs::read(case.base.join("credential-proposal-replayed"))?
        );
        let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&proposal)?;
        assert_eq!(proposal.operation(), operation);
        assert_eq!(proposal.statement(), proof.statement_digest());
        assert!(matches!(
            self.witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness store")?
                .prepare_credential_renewal(proposal, proof, policy, fixture::now()?)?,
            p::AnchorCredentialRenewalState::Prepared
        ));
        Ok(())
    }
    fn commit(
        &self,
        case: &crate::first_connection::Case<'_>,
        proof: &p::VerifiedCredentialRenewal,
        identity: &[u8],
    ) -> Result<()> {
        let unmanaged = ConfigurationProcess {
            client: case.client,
            profile: case.profile,
            source: case.source,
            target: case.target,
            registry: None,
        };
        let before = self.exchanges()?.len();
        case.invoke(
            "credential-commit-closed",
            &case.base.join("credential-closed"),
        )?;
        unmanaged.run(
            "credential-commit-unmanaged",
            &case.base.join("credential-unmanaged"),
            case.carrier,
        )?;
        assert_eq!(
            fs::read(case.base.join("credential-closed"))?,
            202i32.to_ne_bytes()
        );
        assert_eq!(
            fs::read(case.base.join("credential-unmanaged"))?,
            211i32.to_ne_bytes()
        );
        let refused = self.exchanges()?;
        let refused = refused.get(before..).ok_or("refusal capture")?;
        no_commit(refused)?;
        write_exchanges(&case.base.join("credential-refusal-transcript"), refused)?;
        let before = self.exchanges()?.len();
        if let Some(tls) = self.tls {
            tls.arm(None)?;
        } else {
            let mut held = self.witness.hold_marker.lock().map_err(|_| "TCP hold")?;
            if held
                .replace(case.base.join("credential-commit-error-ready"))
                .is_some()
            {
                return Err("unconsumed credential commit barrier".into());
            }
            drop(held);
            self.witness.arm(9)?;
        }
        case.invoke(
            "credential-commit-unknown",
            &case.base.join("credential-unknown"),
        )?;
        assert_eq!(
            fs::read(case.base.join("credential-unknown"))?,
            218i32.to_ne_bytes()
        );
        let observed = self.exchanges()?;
        let commits: Vec<_> = observed
            .get(before..)
            .ok_or("commit capture")?
            .iter()
            .filter(|r| r.request.get(204) == Some(&5))
            .collect();
        assert_eq!(commits.len(), 1);
        let committed = commits.first().ok_or("committed exchange")?;
        assert!(!committed.delivered);
        assert_eq!(committed.reply.get(204), Some(&8));
        publish_private_bytes(
            &case.base.join("credential-commit-request"),
            &committed.request,
        )?;
        publish_private_bytes(&case.base.join("credential-commit-reply"), &committed.reply)?;
        let before = observed.len();
        for (mode, label) in [
            ("credential-reconcile", "credential-recovered"),
            ("credential-commit", "credential-terminal-replayed"),
        ] {
            unmanaged.run(mode, &case.base.join(label), case.carrier)?;
            status(&fs::read(case.base.join(label))?, proof, 2)?;
        }
        let after = self.exchanges()?;
        let historical = after.get(before..).ok_or("history capture")?;
        no_commit(historical)?;
        assert!(!historical.is_empty());
        write_exchanges(&case.base.join("credential-history-transcript"), historical)?;
        unmanaged.run(
            "credential-activation-unmanaged",
            &case.base.join("credential-activation-unmanaged"),
            case.carrier,
        )?;
        assert_eq!(
            fs::read(case.base.join("credential-activation-unmanaged"))?,
            211i32.to_ne_bytes()
        );
        case.invoke(
            "credential-activate",
            &case.base.join("credential-current-activation"),
        )?;
        assert_eq!(
            fs::read(case.base.join("credential-current-activation"))?,
            identity
        );
        case.invoke(
            "credential-identity",
            &case.base.join("credential-renewed-identity"),
        )?;
        assert_eq!(
            fs::read(case.base.join("credential-renewed-identity"))?,
            identity
        );
        let mut counts = 1u32.to_be_bytes().to_vec();
        counts.extend_from_slice(&u32::try_from(historical.len())?.to_be_bytes());
        counts.extend_from_slice(&0u32.to_be_bytes());
        publish_private_bytes(&case.base.join("credential-dispatch-observation"), &counts)?;
        Ok(())
    }
}
fn no_commit(records: &[witness::Capture]) -> Result<()> {
    if records.iter().any(|r| r.request.get(204) == Some(&5)) {
        return Err("historical or refused operation dispatched a new credential commit".into());
    }
    Ok(())
}
pub(super) fn write_exchanges(path: &Path, records: &[witness::Capture]) -> Result<()> {
    if records.len() > 128 {
        return Err("credential exchange capture bound".into());
    }
    let mut bytes = Vec::with_capacity(records.len() * 7334);
    for record in records {
        assert_eq!(record.request.len(), 3674);
        assert_eq!(record.reply.len(), 3659);
        bytes.push(u8::from(record.delivered));
        bytes.extend_from_slice(&record.request);
        bytes.extend_from_slice(&record.reply);
    }
    // A refused operation can fail before any exchange; an empty capture proves no dispatch.
    publish_private_bytes(path, &bytes)?;
    Ok(())
}
pub(super) fn status(bytes: &[u8], proof: &p::VerifiedCredentialRenewal, phase: u32) -> Result<()> {
    assert_eq!(bytes.len(), 120);
    assert_eq!(bytes.get(..4), Some(phase.to_ne_bytes().as_slice()));
    assert_eq!(
        bytes.get(4..36),
        Some(proof.operation().as_bytes().as_slice())
    );
    assert_eq!(bytes.get(36..68), Some(proof.statement_digest().as_slice()));
    if phase == 1 {
        assert_eq!(bytes.get(72..112), Some([0u8; 40].as_slice()));
    } else {
        let checkpoint = proof.successor_device().roster().checkpoint();
        assert_eq!(
            bytes.get(72..80),
            Some(checkpoint.version().to_ne_bytes().as_slice())
        );
        assert_eq!(bytes.get(80..112), Some(checkpoint.digest().as_slice()));
    }
    Ok(())
}
fn admit_peer(case: &crate::first_connection::Case<'_>) -> Result<()> {
    admit_peer_kind(case, false)
}
pub(super) fn admit_policy_peer(case: &crate::first_connection::Case<'_>) -> Result<()> {
    admit_peer_kind(case, true)
}
fn admit_peer_kind(case: &crate::first_connection::Case<'_>, independent: bool) -> Result<()> {
    let client = std::env::var_os("QPC_CONFIGURATION_RECEIVER").ok_or("receiver executable")?;
    let mut command = Command::new(client);
    command.arg(match case.carrier {
        Some("signed") => "--witness",
        Some("tls") => "--witness-tls",
        _ => return Err("credential witness carrier".into()),
    });
    command.arg(fs::read_to_string(case.source.join("witness-address"))?);
    command
        .arg(if independent {
            "independent-peer-admit"
        } else {
            "credential-peer-admit"
        })
        .arg(case.receiver)
        .arg(case.source);
    command.stdout(Stdio::from(fs::File::create(
        case.base.join("credential-peer.stdout"),
    )?));
    command.stderr(Stdio::from(fs::File::create(
        case.base.join("credential-peer.stderr"),
    )?));
    let mut child = fixture::OwnedChild(command.spawn()?);
    let status = fixture::wait(&mut child)?;
    let stderr = fs::read(case.base.join("credential-peer.stderr"))?;
    assert!(
        status.success() && stderr.is_empty(),
        "credential peer admission: {status}; {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(
        fs::read(case.base.join("credential-peer.stdout"))?,
        if independent {
            b"independent-peer-admitted\n".as_slice()
        } else {
            b"credential-peer-admitted\n".as_slice()
        }
    );
    Ok(())
}

pub(crate) fn export_public(source: &Path, base: &Path, target: &Path) -> Result<()> {
    for (name, input) in [
        ("credential-renewal.bin", "credential-renewal"),
        ("credential-operation.bin", "credential-operation"),
        ("credential-statement.bin", "credential-statement"),
        ("credential-proposal.bin", "credential-proposal"),
        ("target-version.bin", "renewal-version"),
        ("target-digest.bin", "renewal-digest"),
        ("original-certificate.bin", "grant-certificate"),
        ("original-roster.bin", "grant-roster"),
        ("renewed-certificate.bin", "renewed-certificate"),
        ("renewed-roster.bin", "renewed-roster"),
        ("policy-root.bin", "policy-root"),
        ("original-policy.bin", "protocol-policy"),
        ("policy-version.bin", "policy-version"),
        ("policy-digest.bin", "policy-digest"),
    ] {
        publish_private_bytes(&target.join(name), &fs::read(source.join(input))?)?;
    }
    for name in [
        "credential-original-identity",
        "credential-renewed-identity",
        "credential-expired",
        "credential-expired-request",
        "credential-expiry-observation",
        "credential-refused",
        "credential-staged",
        "credential-stage-replayed",
        "credential-proposal-replayed",
        "credential-closed",
        "credential-unmanaged",
        "credential-unknown",
        "credential-commit-request",
        "credential-commit-reply",
        "credential-recovered",
        "credential-terminal-replayed",
        "credential-activation-unmanaged",
        "credential-current-activation",
        "credential-dispatch-observation",
        "credential-refusal-transcript",
        "credential-history-transcript",
    ] {
        publish_private_bytes(
            &target.join(format!("{name}.bin")),
            &fs::read(base.join(name))?,
        )?;
    }
    for name in [
        "credential-original-identity",
        "credential-renewed-identity",
        "credential-expired",
        "credential-expired-request",
        "credential-refused",
        "credential-staged",
        "credential-stage-replayed",
        "credential-proposal-replayed",
        "credential-closed",
        "credential-unmanaged",
        "credential-unknown",
        "credential-recovered",
        "credential-terminal-replayed",
        "credential-activation-unmanaged",
        "credential-current-activation",
        "credential-peer",
    ] {
        for extension in ["stdout", "stderr"] {
            let name = format!("{name}.{extension}");
            publish_private_bytes(&target.join(&name), &fs::read(base.join(name))?)?;
        }
    }
    Ok(())
}
