// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual public issuer request and G under independently retained P.
use crate::{
    credential_request,
    first_connection::Case,
    first_credential::{self, Renewal},
    fixture, p, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{fs, path::PathBuf};

impl Renewal<'_> {
    fn issue_after_policy(
        &self,
        case: &Case<'_>,
        policy: &p::VerifiedSessionPolicy,
    ) -> Result<p::VerifiedCredentialRenewal> {
        let operation = p::CredentialRenewalId::generate()?;
        publish_private_bytes(
            &case.source.join("credential-operation"),
            operation.as_bytes(),
        )?;
        let output = case.base.join("credential-request");
        case.invoke("policy-credential-request", &output)?;
        case.invoke(
            "policy-credential-request",
            &case.base.join("credential-request-replayed"),
        )?;
        assert_eq!(
            fs::read(&output)?,
            fs::read(case.base.join("credential-request-replayed"))?
        );
        let request = credential_request::read_credential_request(&output, false)?;
        let preceding =
            crate::policy_request::read_request(&case.source.join("renewal-request"), false)?;
        assert_eq!(request.operation, operation);
        assert_eq!(request.journal, preceding.scope.journal);
        assert_eq!(request.original_owner, preceding.scope.original_owner);
        assert_eq!(
            request.original_policy,
            preceding.scope.original_policy.digest()
        );
        assert_eq!(request.current_policy, policy.checkpoint());
        let authorization: [u8; 32] = fs::read(case.base.join("renewal-statement"))?
            .try_into()
            .map_err(|_| "P statement width")?;
        assert_eq!(request.authorization, Some(authorization));
        publish_private_bytes(&case.source.join("renewal-statement"), &authorization)?;
        assert_eq!(request.account, self.root.account_id()?);
        assert_eq!(request.original, self.roster.checkpoint());
        assert_eq!(request.previous, self.roster.checkpoint());
        assert_eq!(request.validity, self.validity);
        assert_eq!(request.original_c, self.certificate);
        assert_eq!(request.previous_c, self.certificate);
        assert_eq!(request.original_r, self.roster.as_bytes());
        assert_eq!(request.previous_r, self.roster.as_bytes());
        let validity = p::Validity::new(
            request.validity.from(),
            request
                .validity
                .until()
                .checked_add(600)
                .ok_or("G validity overflow")?,
        )?;
        let successor = self.root.issue_device(
            p::DeviceDescription::new(
                self.original.device_id(),
                self.original.generation(),
                policy.family(),
                validity,
            )?,
            self.public_key.clone(),
        )?;
        let roster = self.root.issue_roster(
            request
                .previous
                .version()
                .checked_add(1)
                .ok_or("G roster overflow")?,
            validity,
            &[self.root.roster_entry(&successor)?],
        )?;
        let pin = p::AccountPin::new(
            request.account,
            self.root.public_key()?,
            roster.checkpoint(),
            policy.family(),
        )?;
        let grant = self.root.issue_credential_renewal(
            p::CredentialRenewalMaterials {
                original_credential: &request.original_c,
                previous_credential: &request.previous_c,
                successor_credential: &successor,
                previous_roster: &request.previous_r,
                successor_roster: roster.as_bytes(),
            },
            &p::CredentialRenewalAuthorization {
                operation,
                previous: request.previous,
                policy_digest: request.original_policy,
            },
            &pin,
            fixture::now()?,
        )?;
        let proof = p::VerifiedCredentialRenewal::verify(
            grant.as_bytes(),
            &pin,
            request.original_policy,
            fixture::now()?,
        )?;
        for (name, bytes) in [
            ("credential-renewal", grant.as_bytes().to_vec()),
            ("credential-statement", proof.statement_digest().to_vec()),
            (
                "renewal-version",
                roster.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("renewal-digest", roster.checkpoint().digest().to_vec()),
            ("renewed-certificate", successor),
            ("renewed-roster", roster.as_bytes().to_vec()),
        ] {
            publish_private_bytes(&case.source.join(name), &bytes)?;
        }
        Ok(proof)
    }

    pub(crate) fn run_after_policy(&self, case: &Case<'_>) -> Result<()> {
        let mut sdk = fixture::sdk(self.reference)?;
        let original = crate::first_policy::historical(case.source)?;
        let target = fixture::protocol_policy(&case.source.join("policy-target"), &sdk)?;
        let proof = self.issue_after_policy(case, &target)?;
        let invoke = |mode: &str, label: &str| -> Result<Vec<u8>> {
            let path = case.base.join(label);
            case.invoke(mode, &path)?;
            Ok(fs::read(path)?)
        };
        let identity = invoke("credential-identity", "credential-original-identity")?;
        assert_eq!(identity.len(), 64);
        assert_eq!(
            invoke("policy-credential-status", "credential-absent")?,
            [0; 120]
        );
        assert_eq!(
            invoke("policy-credential-stage-refused", "credential-refused")?,
            102u32.to_ne_bytes()
        );
        assert_eq!(
            invoke("policy-credential-status", "credential-after-refusal")?,
            [0; 120]
        );
        for label in ["credential-staged", "credential-stage-replayed"] {
            first_credential::status(&invoke("policy-credential-stage", label)?, &proof, 1)?;
        }
        let bytes = invoke("policy-credential-prepare", "credential-proposal")?;
        assert_eq!(
            bytes,
            invoke("policy-credential-prepare", "credential-proposal-replayed")?
        );
        assert_eq!(bytes.len(), 329);
        assert_eq!(bytes.get(..8), Some(b"QPCRNP03".as_slice()));
        let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&bytes)?;
        assert_eq!(proposal.operation(), proof.operation());
        assert_eq!(proposal.statement(), proof.statement_digest());
        assert_eq!(
            proposal.policy_renewal(),
            Some(fixture::array(case.source, "renewal-statement")?)
        );
        assert_eq!(proposal.policy_continuation(), None);
        assert_eq!(
            self.witness
                .configured
                .store
                .lock()
                .map_err(|_| "G witness approval")?
                .prepare_policy_renewed_credential_renewal(
                    proposal,
                    &proof,
                    &original,
                    &target,
                    fixture::now()?
                )?,
            p::AnchorCredentialRenewalState::Prepared
        );
        let before = self.exchanges()?.len();
        if let Some(tls) = self.tls {
            tls.arm(None)?;
        } else {
            let mut held = self
                .witness
                .hold_marker
                .lock()
                .map_err(|_| "G commit barrier")?;
            if held
                .replace(case.base.join("credential-commit-error-ready"))
                .is_some()
            {
                return Err("unconsumed G commit barrier".into());
            }
            drop(held);
            self.witness.arm(9)?;
        }
        assert_eq!(
            invoke("policy-credential-commit-unknown", "credential-unknown")?,
            218u32.to_ne_bytes()
        );
        let captures = self.exchanges()?;
        let commits: Vec<_> = captures
            .get(before..)
            .ok_or("G capture start")?
            .iter()
            .filter(|r| r.request.get(204) == Some(&5))
            .collect();
        assert_eq!(commits.len(), 1);
        let commit = commits.first().ok_or("G commit capture")?;
        assert!(!commit.delivered);
        assert_eq!(commit.reply.get(204), Some(&8));
        publish_private_bytes(
            &case.base.join("credential-lost-commit-request"),
            &commit.request,
        )?;
        publish_private_bytes(
            &case.base.join("credential-lost-commit-reply"),
            &commit.reply,
        )?;
        let before = captures.len();
        for (mode, label) in [
            ("policy-credential-reconcile", "credential-recovered"),
            ("policy-credential-commit", "credential-commit-replayed"),
            ("policy-credential-close", "credential-close-applied"),
        ] {
            first_credential::status(&invoke(mode, label)?, &proof, 2)?;
        }
        let captures = self.exchanges()?;
        let history = captures.get(before..).ok_or("G history capture")?;
        assert!(
            !history.is_empty()
                && history
                    .iter()
                    .all(|r| r.delivered && !matches!(r.request.get(204), Some(5 | 7)))
        );
        first_credential::write_exchanges(
            &case.base.join("credential-historical-transcript"),
            history,
        )?;
        assert_eq!(
            invoke("policy-credential-activate", "credential-renewed-identity")?,
            identity
        );
        let next_operation = p::CredentialRenewalId::generate()?;
        publish_private_bytes(
            &case.source.join("credential-next-operation"),
            next_operation.as_bytes(),
        )?;
        invoke("policy-credential-next-request", "credential-next-request")?;
        let next = credential_request::read_credential_request(
            &case.base.join("credential-next-request"),
            false,
        )?;
        assert_eq!(next.operation, next_operation);
        assert_eq!(next.original_c, self.certificate);
        assert_eq!(next.original_r, self.roster.as_bytes());
        assert_eq!(
            next.previous_c,
            fs::read(case.source.join("renewed-certificate"))?
        );
        assert_eq!(
            next.previous_r,
            fs::read(case.source.join("renewed-roster"))?
        );
        assert_eq!(
            next.previous,
            proof.successor_device().roster().checkpoint()
        );
        assert_eq!(next.original_policy, original.checkpoint().digest());
        assert_eq!(next.current_policy, target.checkpoint());
        assert_eq!(next.authorization, proposal.policy_renewal());
        target.close();
        sdk.close();
        first_credential::admit_policy_peer(case)?;
        Ok(())
    }
}

pub(crate) fn export_public(case: &Case<'_>) -> Result<()> {
    let target = PathBuf::from(
        std::env::var_os("QPERIAPT_MANAGED_CONFIGURATION_EVIDENCE")
            .ok_or("P/G evidence directory")?,
    )
    .join(format!(
        "{}-{}",
        case.carrier.ok_or("P/G witness carrier")?,
        case.profile
    ))
    .join("credential");
    fixture::create_private_directory(&target)?;
    for name in [
        "credential-request",
        "credential-request-replayed",
        "credential-next-request",
        "credential-original-identity",
        "credential-absent",
        "credential-refused",
        "credential-after-refusal",
        "credential-staged",
        "credential-stage-replayed",
        "credential-proposal",
        "credential-proposal-replayed",
        "credential-unknown",
        "credential-recovered",
        "credential-commit-replayed",
        "credential-close-applied",
        "credential-renewed-identity",
    ] {
        for suffix in ["", ".stdout", ".stderr"] {
            let name = format!("{name}{suffix}");
            publish_private_bytes(&target.join(&name), &fs::read(case.base.join(name))?)?;
        }
    }
    for name in [
        "credential-lost-commit-request",
        "credential-lost-commit-reply",
        "credential-historical-transcript",
        "credential-peer.stdout",
        "credential-peer.stderr",
    ] {
        publish_private_bytes(&target.join(name), &fs::read(case.base.join(name))?)?;
    }
    for name in [
        "credential-operation",
        "credential-next-operation",
        "credential-statement",
        "credential-renewal",
        "renewal-version",
        "renewal-digest",
        "renewal-statement",
        "renewed-certificate",
        "renewed-roster",
        "grant-certificate",
        "grant-roster",
    ] {
        publish_private_bytes(
            &target.join(format!("{name}.bin")),
            &fs::read(case.source.join(name))?,
        )?;
    }
    Ok(())
}
