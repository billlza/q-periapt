// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete account changes through the real CLI, clock and optional TCP witness.
use super::*;
use q_periapt_continuity_reference_app::{
    credential_grant::{CredentialGrantRequest, IssuedCredentialGrant},
    native_device::RetainedCredentialRequest,
};
use serde_json::{json, Value};

fn value(args: &[OsString]) -> Result<Value> {
    Ok(serde_json::from_slice(&invoke(args, true)?)?)
}

struct AccountRecovery {
    c: Case,
    grant: sdk::VerifiedCredentialRenewal,
    policy: sdk::VerifiedSessionPolicy,
    accepted: Value,
    signing: Vec<u8>,
    wrapping: Vec<u8>,
    endpoint: OsString,
}
impl AccountRecovery {
    fn open(server: Option<&witness_support::Server>) -> Result<Self> {
        let c = Case::open_with_profile(1200, 2400, server)?;
        let accepted = c.accept()?;
        let signing = fs::read(c.path.join("device/device.key"))?;
        let wrapping = fs::read(c.path.join("wrap.key"))?;
        // The companions are explicit fixture identities. The local enrollment,
        // journal, process recovery and witness traffic are the actual consumer.
        let mut certificates = vec![c.issued.certificate.clone()];
        for id in [71, 72] {
            certificates.push(c.root.issue_device(
                sdk::DeviceDescription::new(
                    [id; 16],
                    1,
                    c.invitation.family,
                    sdk::Validity::new(c.start, c.start + 1200)?,
                )?,
                sdk::DeviceSigningKey::generate()?.public_key()?,
            )?);
        }
        let previous = c.root.issue_roster(
            2,
            sdk::Validity::new(c.start, c.start + 2400)?,
            &certificates
                .iter()
                .map(|cert| c.root.roster_entry(cert))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )?;
        let mut current = c.current.clone();
        current.roster = Some(RosterSnapshot {
            checkpoint: previous.checkpoint().into(),
            bytes: previous.as_bytes().to_vec(),
        });
        write(&c.path.join("shared-previous.json"), &current)?;
        let preparation = c.call(
            "prepare",
            &[
                "shared-previous.json",
                "policy-pins.json",
                "policy-materials.json",
            ],
        )?;
        let previous_pin = sdk::AccountPin::new(
            current.account,
            c.root.public_key()?,
            previous.checkpoint(),
            c.invitation.family,
        )?;
        let (pins, materials) = c.publisher.export([65; 32])?;
        let (policy, _) = pins.verify(&materials, c.invitation.family, clock()?)?;
        let endpoint = match server {
            None => OsString::from("none"),
            Some(server) => {
                let subject: Vec<u8> = serde_json::from_value(preparation["subject"].clone())?;
                let genesis = sdk::AnchorGenesis::from_trusted_state(
                    sdk::AnchorSubject::from_trusted_state(&subject)?,
                    serde_json::from_value(preparation["head"].clone())?,
                )?;
                let original = previous_pin.verify_device(
                    &c.issued.certificate,
                    previous.as_bytes(),
                    clock()?,
                )?;
                server.store.lock().map_err(|_| "witness lock")?.enroll(
                    &genesis,
                    &original,
                    &policy,
                    clock()?,
                )?;
                server.address.to_string().into()
            }
        };
        let mut activate = c.args(
            "activate",
            &[
                "shared-previous.json",
                "policy-pins.json",
                "policy-materials.json",
            ],
        );
        activate.push(endpoint.clone());
        invoke(&activate, true)?;
        let mut request = c.args("renewal-request", &[]);
        request.extend([
            URL_SAFE_NO_PAD.encode([141; 32]).into(),
            c.path.join("policy-pins.json").into_os_string(),
            c.path.join("policy-materials.json").into_os_string(),
            endpoint.clone(),
            c.path.join("shared-request.json").into_os_string(),
        ]);
        invoke(&request, true)?;
        let retained: RetainedCredentialRequest =
            serde_json::from_slice(&fs::read(c.path.join("shared-request.json"))?)?;
        let mut successors = Vec::new();
        for certificate in &certificates {
            let original =
                previous_pin.verify_device(certificate, previous.as_bytes(), clock()?)?;
            successors.push(c.root.issue_credential_extension(
                &original,
                c.start + 1800,
                clock()?,
            )?);
        }
        let target = c.root.issue_roster(
            3,
            sdk::Validity::new(c.start, c.start + 2400)?,
            &successors
                .iter()
                .map(|cert| c.root.roster_entry(cert))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )?;
        let target_pin = sdk::AccountPin::new(
            current.account,
            c.root.public_key()?,
            target.checkpoint(),
            c.invitation.family,
        )?;
        let mut grants = Vec::new();
        for (index, (certificate, successor)) in certificates.iter().zip(&successors).enumerate() {
            let operation = [141 + u8::try_from(index)?; 32];
            let signed = c.root.issue_credential_renewal(
                sdk::CredentialRenewalMaterials {
                    original_credential: certificate,
                    previous_credential: certificate,
                    successor_credential: successor,
                    previous_roster: previous.as_bytes(),
                    successor_roster: target.as_bytes(),
                },
                &sdk::CredentialRenewalAuthorization {
                    operation: sdk::CredentialRenewalId::from_trusted_state(operation)?,
                    previous: previous.checkpoint(),
                    policy_digest: policy.checkpoint().digest(),
                },
                &target_pin,
                clock()?,
            )?;
            let grant = sdk::VerifiedCredentialRenewal::verify(
                signed.as_bytes(),
                &target_pin,
                policy.checkpoint().digest(),
                clock()?,
            )?;
            grants.push(IssuedCredentialGrant {
                enrollment: if index == 0 {
                    c.invitation.operation
                } else {
                    operation
                },
                operation,
                journal: if index == 0 {
                    retained.journal
                } else {
                    operation
                },
                root_revision: 1,
                statement: grant.statement_digest(),
                checkpoint: target.checkpoint().into(),
                grant: signed.as_bytes().to_vec(),
            });
        }
        let [local, first, second]: [IssuedCredentialGrant; 3] =
            grants.try_into().map_err(|_| "three fixture grants")?;
        let approval = CredentialGrantRequest {
            retained,
            original_extension: None,
            previous_extension: None,
            successor_extension: [144; 32],
            target_checkpoint: target.checkpoint().into(),
        };
        current.roster = Some(RosterSnapshot {
            checkpoint: target.checkpoint().into(),
            bytes: target.as_bytes().to_vec(),
        });
        write(&c.path.join("shared-approval.json"), &approval)?;
        write(&c.path.join("shared-issued.json"), &local)?;
        write(&c.path.join("shared-current.json"), &current)?;
        let collection = json!({
            "schema": "qperiapt-account-credential-grants/1",
            "grants": [&first, &second],
        });
        write(&c.path.join("companions.json"), &collection)?;
        write(
            &c.path.join("reordered.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/1",
                "grants": [&second, &first],
            }),
        )?;
        write(
            &c.path.join("missing.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/1", "grants": [&first],
            }),
        )?;
        write(
            &c.path.join("duplicate.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/1", "grants": [&first, &first],
            }),
        )?;
        let mut forged = serde_json::to_value(&first)?;
        forged["statement"] = serde_json::to_value([99u8; 32])?;
        write(
            &c.path.join("forged.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/1", "grants": [forged, &second],
            }),
        )?;
        let mut wrong_target = serde_json::to_value(&first)?;
        wrong_target["root_revision"] = json!(2);
        write(
            &c.path.join("wrong-target.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/1",
                "grants": [wrong_target, &second],
            }),
        )?;
        write(
            &c.path.join("over-limit.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/1",
                "grants": vec![&first; sdk::MAX_DEVICES],
            }),
        )?;
        write(
            &c.path.join("empty.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/1", "grants": [],
            }),
        )?;
        write(
            &c.path.join("wrong-schema.json"),
            &json!({
                "schema": "qperiapt-account-credential-grants/2", "grants": [],
            }),
        )?;
        let grant = sdk::VerifiedCredentialRenewal::verify(
            &local.grant,
            &target_pin,
            policy.checkpoint().digest(),
            clock()?,
        )?;
        Ok(Self {
            c,
            grant,
            policy,
            accepted,
            signing,
            wrapping,
            endpoint,
        })
    }
    fn args(&self, command: &str, companions: Option<&str>) -> Vec<OsString> {
        let mut args = recovery::recovery_args(
            &self.c,
            command,
            "shared-approval.json",
            "shared-issued.json",
            "shared-current.json",
        );
        args[11] = self.endpoint.clone();
        if command == "renewal-witness-prepare" {
            args.push(self.c.path.join("shared-proposal.json").into_os_string());
        }
        if let Some(file) = companions {
            args.push("--companion-grants".into());
            args.push(self.c.path.join(file).into_os_string());
        }
        args
    }
}

#[test]
fn account_cli_keeps_complete_original_collection_after_lost_local_response() -> Result<()> {
    account_recovery(None)
}
#[test]
fn account_cli_keeps_complete_original_collection_with_independent_witness_approval() -> Result<()>
{
    let mut server = witness_support::Server::start()?;
    account_recovery(Some(&server))?;
    assert!(server.close()? > 0);
    Ok(())
}
fn account_recovery(server: Option<&witness_support::Server>) -> Result<()> {
    let f = AccountRecovery::open(server)?;
    for (companions, reason) in [
        ("missing.json", "Protocol(Checkpoint)"),
        ("duplicate.json", "Conflict"),
        (
            "forged.json",
            "Companion grant differs from its signed decision",
        ),
        (
            "wrong-target.json",
            "Companion grant selects a different account target",
        ),
        ("empty.json", "Expected account grant collection"),
        ("wrong-schema.json", "Expected account grant collection"),
        ("over-limit.json", "Expected account grant collection"),
    ] {
        let error = String::from_utf8(invoke(&f.args("renewal-stage", Some(companions)), false)?)?;
        assert!(error.contains(reason), "{companions}: {error}");
        assert_eq!(f.c.call("renewal-status", &[])?["state"], "Absent");
    }
    let stage = f.args("renewal-stage", Some("companions.json"));
    let pending = value(&stage)?;
    assert_eq!(pending["state"], "Pending");
    assert_eq!(
        value(&f.args("renewal-stage", Some("reordered.json")))?,
        pending
    );
    // A later caller must not silently downgrade or partially replace the set.
    for companions in [None, Some("missing.json"), Some("forged.json")] {
        invoke(&f.args("renewal-activate", companions), false)?;
        assert_eq!(f.c.call("renewal-status", &[])?, pending);
    }
    if let Some(server) = server {
        invoke(&f.args("renewal-activate", Some("companions.json")), false)?;
        assert_eq!(f.c.call("renewal-status", &[])?, pending);
        let prepare = f.args("renewal-witness-prepare", Some("reordered.json"));
        assert_eq!(value(&prepare)?["state"], "RequiresWitnessApproval");
        let exported: Value =
            serde_json::from_slice(&fs::read(f.c.path.join("shared-proposal.json"))?)?;
        let proposal = sdk::AnchorCredentialRenewalProposal::from_trusted_state(
            &URL_SAFE_NO_PAD.decode(exported["proposal"].as_str().ok_or("proposal")?)?,
        )?;
        server
            .store
            .lock()
            .map_err(|_| "witness lock")?
            .prepare_credential_renewal(proposal, &f.grant, &f.policy, clock()?)?;
    }
    let activate = f.args("renewal-activate", Some("companions.json"));
    witness::lose_response(&f.c, &activate, "shared-lost-response.stderr")?;
    let committed = f.c.call("renewal-status", &[])?;
    assert_eq!(committed["state"], "Committed");
    let active = value(&f.args("renewal-activate", Some("reordered.json")))?;
    assert_eq!(active["state"], "Active");
    assert_eq!(active["journal"], f.accepted["journal"]);
    assert_eq!(value(&stage)?, committed);
    invoke(&f.args("renewal-activate", None), false)?;
    assert_eq!(f.c.call("renewal-status", &[])?, committed);
    assert_eq!(
        f.c.call("status", &[])?["signing_id"],
        f.accepted["signing_id"]
    );
    assert_eq!(fs::read(f.c.path.join("device/device.key"))?, f.signing);
    assert_eq!(fs::read(f.c.path.join("wrap.key"))?, f.wrapping);
    Ok(())
}
