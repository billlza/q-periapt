// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Renewal of one actual managed Android installation across fresh processes.
use crate::{
    android_credential_traffic, android_witness::witness, fixture, p, witness_tls_faults, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::path::Path;

pub(crate) struct Renewal<'a> {
    pub(crate) root: &'a p::RootSigningKey,
    pub(crate) original: &'a p::VerifiedDevice,
    pub(crate) public_key: &'a p::PublicKey,
    pub(crate) validity: p::Validity,
    pub(crate) certificate: &'a [u8],
    pub(crate) roster: &'a p::IssuedRoster,
    pub(crate) policy: &'a p::VerifiedSessionPolicy,
    pub(crate) inputs: &'a Path,
    pub(crate) base: &'a Path,
    pub(crate) receiver: &'a Path,
    pub(crate) receiver_root: &'a p::RootSigningKey,
    pub(crate) carrier: &'a str,
    pub(crate) witness: &'a witness::Witness,
    pub(crate) tls: Option<&'a witness_tls_faults::FaultWitness>,
}
impl Renewal<'_> {
    fn exchanges(&self) -> Result<Vec<witness::Capture>> {
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
    fn issue(&self) -> Result<p::VerifiedCredentialRenewal> {
        let family = fixture::array(self.inputs, "family")?;
        let validity = p::Validity::new(
            self.validity.from(),
            self.validity
                .until()
                .checked_add(600)
                .ok_or("expiry overflow")?,
        )?;
        let successor = self.root.issue_device(
            p::DeviceDescription::new(
                self.original.device_id(),
                self.original.generation(),
                family,
                validity,
            )?,
            self.public_key.clone(),
        )?;
        let target = self
            .root
            .issue_roster(2, validity, &[self.root.roster_entry(&successor)?])?;
        let pin = p::AccountPin::new(
            self.root.account_id()?,
            self.root.public_key()?,
            target.checkpoint(),
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
                successor_roster: target.as_bytes(),
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
            ("credential-renewal", grant.as_bytes().to_vec()),
            ("credential-operation", operation.as_bytes().to_vec()),
            ("credential-statement", proof.statement_digest().to_vec()),
            (
                "renewal-version",
                target.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("renewal-digest", target.checkpoint().digest().to_vec()),
        ] {
            publish_private_bytes(&self.inputs.join(name), &bytes)?;
        }
        Ok(proof)
    }
    pub(crate) fn run(&self, run: &impl Fn(&str, &str) -> Result<Vec<u8>>) -> Result<()> {
        let identity = run("credential-identity", "credential-original-identity")?;
        assert_eq!(identity.len(), 64);
        assert!(identity
            .get(..32)
            .ok_or("signing identity")?
            .iter()
            .any(|v| *v != 0));
        assert_eq!(
            identity.get(32..).ok_or("journal identity")?,
            std::fs::read(self.base.join("genesis"))?
                .get(4..36)
                .ok_or("genesis journal")?
        );
        assert_eq!(run("credential-status", "credential-absent")?, vec![0; 116]);
        let traffic = android_credential_traffic::Traffic::begin(self, run)?;
        let proof = self.issue()?;
        assert_eq!(
            run("credential-stage-refused", "credential-refused")?,
            102u32.to_be_bytes()
        );
        for label in ["credential-staged", "credential-stage-replayed"] {
            status(&run("credential-stage", label)?, &proof, 1)?;
        }
        let proposal = run("credential-prepare", "credential-proposal")?;
        assert_eq!(
            proposal,
            run("credential-prepare", "credential-proposal-replayed")?
        );
        let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&proposal)?;
        assert_eq!(proposal.operation(), proof.operation());
        assert_eq!(proposal.statement(), proof.statement_digest());
        assert!(matches!(
            self.witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness store")?
                .prepare_credential_renewal(proposal, &proof, self.policy, fixture::now()?)?,
            p::AnchorCredentialRenewalState::Prepared
        ));
        let before = self.exchanges()?.len();
        assert_eq!(
            run("credential-commit-closed", "credential-closed")?,
            202u32.to_be_bytes()
        );
        assert_eq!(
            run("credential-commit-unmanaged", "credential-unmanaged")?,
            211u32.to_be_bytes()
        );
        let exchanges = self.exchanges()?;
        let refused = exchanges.get(before..).ok_or("refusal capture")?;
        no_commit(refused)?;
        write_exchanges(&self.base.join("credential-refusal-transcript"), refused)?;
        let before = exchanges.len();
        if let Some(tls) = self.tls {
            tls.arm(None)?;
        } else {
            let mut held = self.witness.hold_marker.lock().map_err(|_| "TCP hold")?;
            if held
                .replace(self.base.join("credential-commit-error-ready"))
                .is_some()
            {
                return Err("unconsumed credential commit barrier".into());
            }
            drop(held);
            self.witness.arm(9)?;
        }
        assert_eq!(
            run("credential-commit-unknown", "credential-unknown")?,
            218u32.to_be_bytes()
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
            &self.base.join("credential-commit-request"),
            &committed.request,
        )?;
        publish_private_bytes(&self.base.join("credential-commit-reply"), &committed.reply)?;
        let before = observed.len();
        for (mode, label) in [
            ("credential-reconcile", "credential-recovered"),
            ("credential-commit-replay", "credential-terminal-replayed"),
        ] {
            status(&run(mode, label)?, &proof, 2)?;
        }
        let after = self.exchanges()?;
        let historical = after.get(before..).ok_or("history capture")?;
        no_commit(historical)?;
        assert!(!historical.is_empty());
        write_exchanges(&self.base.join("credential-history-transcript"), historical)?;
        assert_eq!(
            run(
                "credential-activate-unmanaged",
                "credential-activation-unmanaged"
            )?,
            211u32.to_be_bytes()
        );
        assert_eq!(
            run("credential-activate", "credential-current-activation")?,
            identity
        );
        assert_eq!(
            run("credential-identity", "credential-renewed-identity")?,
            identity
        );
        let mut counts = 1u32.to_be_bytes().to_vec();
        counts.extend_from_slice(&u32::try_from(historical.len())?.to_be_bytes());
        counts.extend_from_slice(&0u32.to_be_bytes());
        publish_private_bytes(&self.base.join("credential-dispatch-observation"), &counts)?;
        traffic.resume(self, run)?;
        crate::android_remote_credential::run(self, run)?;
        Ok(())
    }
}
fn status(bytes: &[u8], proof: &p::VerifiedCredentialRenewal, phase: u32) -> Result<()> {
    assert_eq!(bytes.len(), 116);
    assert_eq!(bytes.get(..4), Some(phase.to_be_bytes().as_slice()));
    assert_eq!(
        bytes.get(4..36),
        Some(proof.operation().as_bytes().as_slice())
    );
    assert_eq!(bytes.get(36..68), Some(proof.statement_digest().as_slice()));
    if phase == 1 {
        assert_eq!(bytes.get(68..108), Some([0; 40].as_slice()));
    } else {
        let expected = proof.successor_device().roster().checkpoint();
        assert_eq!(
            bytes.get(68..76),
            Some(expected.version().to_be_bytes().as_slice())
        );
        assert_eq!(bytes.get(76..108), Some(expected.digest().as_slice()));
    }
    assert_eq!(bytes.get(108..), Some([0; 8].as_slice()));
    Ok(())
}
fn no_commit(records: &[witness::Capture]) -> Result<()> {
    if records.iter().any(|r| r.request.get(204) == Some(&5)) {
        return Err("historical or refused operation dispatched a new credential commit".into());
    }
    Ok(())
}
fn write_exchanges(path: &Path, records: &[witness::Capture]) -> Result<()> {
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
    publish_private_bytes(path, &bytes)?;
    Ok(())
}
