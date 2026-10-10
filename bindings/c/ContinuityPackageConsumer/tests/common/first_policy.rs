// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::policy_request::read_request;
use crate::{fixture, p, run, run_carrier, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{fs, os::unix::fs::DirBuilderExt, path::Path};

pub(crate) struct Renewal<'a> {
    pub(crate) account_root: &'a p::RootSigningKey,
    pub(crate) policy_root: &'a p::PolicySigningKey,
    pub(crate) certificate: &'a [u8],
    pub(crate) roster: &'a p::IssuedRoster,
    pub(crate) reference: &'a Path,
    pub(crate) witness: Option<&'a fixture::WitnessFixture>,
}
impl Renewal<'_> {
    pub(crate) fn run(&self, case: &crate::first_connection::Case<'_>) -> Result<()> {
        let Self {
            account_root,
            policy_root,
            certificate,
            roster,
            reference,
            witness,
        } = *self;
        let source = case.source;
        let invoke = |mode: &str, output: &Path| {
            run_carrier(
                case.client,
                mode,
                case.profile,
                source,
                case.target,
                output,
                case.carrier,
            )
        };
        let operation = p::PolicyRenewalId::generate()?;
        publish_private_bytes(&source.join("renewal-operation"), operation.as_bytes())?;
        invoke("policy-request", &source.join("renewal-request"))?;
        invoke(
            "policy-request",
            &case.base.join("renewal-request-replayed"),
        )?;
        let original_request = fs::read(source.join("renewal-request"))?;
        assert_eq!(
            fs::read(case.base.join("renewal-request-replayed"))?,
            original_request
        );
        let request = read_request(&source.join("renewal-request"))?;
        assert_eq!(request.scope.operation, operation);
        assert_eq!(request.account, account_root.account_id()?);
        assert_eq!(request.original_checkpoint, roster.checkpoint());
        assert_eq!(request.scope.current_roster, roster.checkpoint());
        assert_eq!(request.original_c, certificate);
        assert_eq!(request.current_c, certificate);
        assert_eq!(request.original_r, roster.as_bytes());
        assert_eq!(request.current_r, roster.as_bytes());
        let family = fixture::array(source, "family")?;
        let account = p::AccountPin::new(
            account_root.account_id()?,
            account_root.public_key()?,
            roster.checkpoint(),
            family,
        )?;
        let device = account.verify_historical_device(certificate, roster.as_bytes())?;
        let mut sdk = fixture::sdk(reference)
            .map_err(|e| format!("independent policy operator SDK lease: {e}"))?;
        let original = historical(source)?;
        assert_eq!(request.scope.original_policy, original.checkpoint());
        assert_eq!(request.scope.previous_policy, original.checkpoint());
        assert_eq!(request.scope.previous_authorization, None);
        let issued = policy_root.issue_session_policy(
            sdk.runtime()?.as_ref(),
            p::SessionPolicyParameters::new(
                2,
                p::Validity::new(
                    original.validity().from(),
                    original
                        .validity()
                        .until()
                        .checked_add(600)
                        .ok_or("clock overflow")?,
                )?,
                original.allowed_modes(),
                original.anchor_requirement(),
                original.application_send_budget(),
            )?,
        )?;
        let inputs = source.join("policy-target");
        fs::DirBuilder::new().mode(0o700).create(&inputs)?;
        for name in [
            "sdk-policy",
            "sdk-signature",
            "sdk-root",
            "family",
            "policy-root",
            "tls-cert",
            "tls-key",
        ] {
            let bytes = zeroize::Zeroizing::new(fs::read(source.join(name))?);
            publish_private_bytes(&inputs.join(name), &bytes)?;
        }
        if case.profile == "recoverable" {
            for name in ["recovery-scope", "recovery-root", "recovery-enrollment"] {
                publish_private_bytes(&inputs.join(name), &fs::read(source.join(name))?)?;
            }
        }
        for (name, bytes) in [
            (
                "policy-version",
                issued.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("policy-digest", issued.checkpoint().digest().to_vec()),
            ("protocol-policy", issued.as_bytes().to_vec()),
        ] {
            publish_private_bytes(&inputs.join(name), &bytes)?;
        }
        let mut target = case.target.as_os_str().to_os_string();
        target.push(".policy-target");
        let target = std::path::PathBuf::from(target);
        assert!(!target.exists());
        run(
            case.client,
            "policy-target-create",
            case.profile,
            &inputs,
            &target,
            &case.base.join("policy-target-created"),
        )?;
        let target_policy = p::PolicyPin::new(
            family,
            policy_root.public_key()?,
            issued.checkpoint(),
        )?
        .verify(issued.as_bytes(), sdk.runtime()?, fixture::now()?)?;
        let materials = p::PolicyRenewalMaterials {
            original: &original,
            previous: &original,
            target: &target_policy,
            original_device: &device,
            current_device: &device,
        };
        let statement =
            p::PolicyRenewalStatement::new(&request.scope, &materials, fixture::now()?)?;
        let approved = p::VerifiedPolicyRenewal::verify(
            &account_root.approve_policy_renewal(&statement)?,
            &policy_root.approve_policy_renewal(&statement)?,
            &request.scope,
            &materials,
            fixture::now()?,
        )?;
        publish_private_bytes(&source.join("renewal-approvals"), approved.as_bytes())?;
        publish_private_bytes(&case.base.join("renewal-statement"), &statement.digest())?;
        invoke("policy-stage-refused", &case.base.join("policy-refused"))?;
        assert_eq!(
            fs::read(case.base.join("policy-refused"))?,
            102u32.to_ne_bytes()
        );
        invoke("policy-request", &case.base.join("policy-after-refusal"))?;
        assert_eq!(
            fs::read(case.base.join("policy-after-refusal"))?,
            original_request
        );
        let mut observed = None;
        let mut steps = vec![
            ("policy-stage", "staged", 1u32),
            ("policy-stage", "stage-replayed", 1),
        ];
        if witness.is_none() {
            steps.extend([
                ("policy-reconcile", "committed", 2),
                ("policy-reconcile", "commit-replayed", 2),
            ]);
        }
        for (mode, label, phase) in steps {
            let output = case.base.join(format!("policy-{label}"));
            invoke(mode, &output)?;
            let bytes = fs::read(&output)?;
            assert_eq!(bytes.len(), 160);
            assert_eq!(bytes.get(..4), Some(phase.to_ne_bytes().as_slice()));
            assert_eq!(bytes.get(8..40), Some(operation.as_bytes().as_slice()));
            assert_eq!(bytes.get(40..72), Some(statement.digest().as_slice()));
            assert_eq!(
                bytes.get(72..80),
                Some(issued.checkpoint().version().to_ne_bytes().as_slice())
            );
            assert_eq!(
                bytes.get(80..112),
                Some(issued.checkpoint().digest().as_slice())
            );
            if label.ends_with("replayed") {
                assert_eq!(Some(&bytes), observed.as_ref());
            }
            observed = Some(bytes);
        }
        if let Some(witness) = witness {
            let proposal_path = source.join("renewal-proposal");
            invoke("policy-witness-prepare", &proposal_path)?;
            let bytes = fs::read(&proposal_path)?;
            for (mode, label) in [
                ("policy-witness-prepare", "proposal-replayed"),
                ("policy-witness-recover", "proposal-recovered"),
            ] {
                let output = case.base.join(label);
                invoke(mode, &output)?;
                assert_eq!(fs::read(output)?, bytes);
            }
            let proposal = p::AnchorPolicyRenewalProposal::from_trusted_state(&bytes)?;
            assert_eq!(proposal.operation(), operation);
            assert_eq!(proposal.statement(), statement.digest());
            assert_eq!(
                witness
                    .store
                    .lock()
                    .map_err(|_| "witness lock")?
                    .prepare_policy_renewal(proposal, &approved, &materials, fixture::now()?)?,
                p::AnchorPolicyRenewalState::Prepared
            );
            for (mode, label) in [
                ("policy-witness-commit", "witness-applied"),
                ("policy-witness-reconcile", "witness-reconciled"),
            ] {
                let output = case.base.join(label);
                invoke(mode, &output)?;
                assert_eq!(fs::read(output)?, 2u32.to_ne_bytes());
            }
        }
        target_policy.close();
        sdk.close();
        Ok(())
    }
}

pub(crate) fn historical(path: &Path) -> Result<p::HistoricalSessionPolicy> {
    let pin = p::PolicyPin::new(
        fixture::array(path, "family")?,
        p::PublicKey::decode(&fixture::read(path, "policy-root", 8192)?)?,
        p::PolicyCheckpoint::from_trusted_state(
            u64::from_be_bytes(fixture::array(path, "policy-version")?),
            fixture::array(path, "policy-digest")?,
        )?,
    )?;
    Ok(pin.verify_historical(&fixture::read(path, "protocol-policy", 8192)?)?)
}
