// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original Android traffic survives expired P0 and independently approved P2.
use crate::{
    android_witness::witness, fixture, independent_inputs, issue_grant, p, run_foreign,
    witness_tls_faults, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    cell::Cell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
};
#[path = "android_policy_renewal/continuation.rs"]
pub(crate) mod continuation;
#[path = "android_policy_renewal/credential.rs"]
mod credential;
#[path = "android_policy_renewal/flow.rs"]
mod flow;
#[path = "android_policy_renewal/joint.rs"]
mod joint;
#[path = "android_policy_renewal/local_roster.rs"]
mod local_roster;
#[path = "android_policy_renewal/roster.rs"]
mod roster;
#[path = "android_policy_renewal/traffic.rs"]
mod traffic;

const POLICY_SECONDS: u64 = 180;

#[test]
fn fixed() -> Result<()> {
    run_profile("fixed")
}
#[test]
fn recoverable() -> Result<()> {
    run_profile("recoverable")
}
fn run_profile(profile: &str) -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("policy cases")?);
    let driver = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("policy driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    for carrier in ["local", "signed", "tls"] {
        exercise(&output, &driver, profile, carrier, None)?;
    }
    Ok(())
}
#[derive(Clone)]
pub(crate) struct Case<'a> {
    pub(crate) driver: &'a Path,
    pub(crate) profile: &'a str,
    pub(crate) carrier: &'a str,
    pub(crate) base: &'a Path,
    pub(crate) namespace: &'a str,
    pub(crate) inputs: &'a Path,
    pub(crate) reference: &'a fixture::Setup,
    pub(crate) root: &'a p::RootSigningKey,
    pub(crate) intent: &'a p::EnrollmentIntent,
    pub(crate) certificate: &'a [u8],
    pub(crate) roster: &'a p::IssuedRoster,
    pub(crate) validity: p::Validity,
    pub(crate) policy: &'a p::VerifiedSessionPolicy,
    pub(crate) sdk: &'a q_periapt_host_store::PolicyStore,
    pub(crate) witness: Option<&'a witness::Witness>,
    pub(crate) tls: Option<&'a witness_tls_faults::FaultWitness>,
    pub(crate) calls: Cell<u64>,
}
impl Case<'_> {
    fn output(&self, label: &str) -> PathBuf {
        self.base.join(format!("{}{label}", self.namespace))
    }
    fn run(&self, mode: &str, label: &str) -> Result<Vec<u8>> {
        let value = run_foreign(
            self.driver,
            self.profile,
            self.inputs,
            self.base,
            mode,
            &format!("{}{label}", self.namespace),
        )?;
        self.calls
            .set(self.calls.get().checked_add(1).ok_or("process census")?);
        Ok(value)
    }
    fn captures(&self) -> Result<Vec<witness::Capture>> {
        if let Some(tls) = self.tls {
            Ok(tls
                .captured
                .lock()
                .map_err(|_| "TLS records")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.record.request().to_vec(),
                    reply: r.record.reply().to_vec(),
                    delivered: r.delivered,
                })
                .collect())
        } else if let Some(witness) = self.witness {
            Ok(witness
                .captured
                .lock()
                .map_err(|_| "witness records")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.request.clone(),
                    reply: r.reply.clone(),
                    delivered: r.delivered,
                })
                .collect())
        } else {
            Ok(Vec::new())
        }
    }
}
enum Maintenance {
    Roster { closed: bool },
    Credential,
    Joint { committed: bool },
    JointCycle,
}
fn exercise(
    output: &Path,
    driver: &Path,
    profile: &str,
    carrier: &str,
    maintenance: Option<Maintenance>,
) -> Result<()> {
    let base = output.join(format!("{carrier}-{profile}"));
    fs::DirBuilder::new().mode(0o700).create(&base)?;
    let inputs = base.join("inputs");
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
    let mut witness = if carrier == "local" {
        None
    } else {
        Some(witness::Witness::start()?)
    };
    let configured = witness.as_ref().map(|w| &w.configured);
    let reference = fixture::setup_expiring_policy(configured, POLICY_SECONDS)?;
    let (root, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let policy = fixture::protocol_policy(&inputs, &sdk)?;
    publish_private_bytes(
        &inputs.join("witness-carrier"),
        if configured.is_some() {
            b"signed"
        } else {
            b"local"
        },
    )?;
    if let Some(witness) = configured {
        let pin = witness.store.lock().map_err(|_| "witness pin")?.pin()?;
        publish_private_bytes(&inputs.join("witness-id"), pin.identity().as_bytes())?;
        publish_private_bytes(&inputs.join("witness-public"), &pin.public_key().encode())?;
        publish_private_bytes(
            &inputs.join("witness-address"),
            witness.address.to_string().as_bytes(),
        )?;
    }
    publish_private_bytes(
        &inputs.join("authority-id"),
        p::AccountAuthorityIdentity::generate()?.as_bytes(),
    )?;
    publish_private_bytes(&inputs.join("authority-application"), &[141; 32])?;
    let run = |mode: &str, label: &str| run_foreign(driver, profile, &inputs, &base, mode, label);
    let request = run("policy-create", "original.request")?;
    let (certificate, roster) = issue_grant(&inputs, &root, &intent, validity, &request)?;
    if configured.is_some() {
        let checkpoint = run("authority-create", "authority-created")?;
        assert_eq!(checkpoint.len(), 72);
        publish_private_bytes(&inputs.join("authority-checkpoint"), &checkpoint)?;
    }
    let prepared = run("policy-prepare", "prepared")?;
    assert_eq!(prepared.len(), 164);
    let journal = p::JournalIdentity::from_trusted_state(
        prepared
            .get(4..36)
            .ok_or("prepared journal width")?
            .try_into()?,
    )?;
    if let Some(witness) = configured {
        assert_eq!(
            prepared.get(..4).ok_or("prepared status width")?,
            2u32.to_be_bytes()
        );
        let subject = p::AnchorSubject::from_trusted_state(
            prepared.get(36..132).ok_or("prepared subject width")?,
        )?;
        let genesis = p::AnchorGenesis::from_trusted_state(
            subject,
            prepared
                .get(132..)
                .ok_or("prepared genesis width")?
                .try_into()?,
        )?;
        let pin = p::AccountPin::new(
            root.account_id()?,
            root.public_key()?,
            roster.checkpoint(),
            fixture::array(&inputs, "family")?,
        )?;
        let device = pin.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
        assert_eq!(
            subject,
            p::AnchorSubject::for_device(journal, &device, policy.as_ref())?
        );
        witness.store.lock().map_err(|_| "witness store")?.enroll(
            &genesis,
            &device,
            &policy,
            fixture::now()?,
        )?;
        publish_private_bytes(&inputs.join("witness-subject"), &subject.to_bytes())?;
    } else {
        assert_eq!(
            prepared.get(..4).ok_or("prepared status width")?,
            1u32.to_be_bytes()
        );
        assert!(prepared
            .get(36..)
            .ok_or("prepared local suffix width")?
            .iter()
            .all(|b| *b == 0));
    }
    let mut tls = if carrier == "tls" {
        let witness = witness.as_ref().ok_or("TLS witness")?;
        let tls = witness_tls_faults::FaultWitness::start(
            Arc::clone(&witness.configured.store),
            [
                inputs.as_path(),
                reference.initiator.as_path(),
                reference.responder.as_path(),
            ],
            witness._directory.path().join("witness.redb"),
        )?;
        fs::write(inputs.join("witness-address"), tls.address.to_string())?;
        fs::write(inputs.join("witness-carrier"), b"tls")?;
        Some(tls)
    } else {
        None
    };
    let case = Case {
        driver,
        profile,
        carrier,
        base: &base,
        namespace: "",
        inputs: &inputs,
        reference: &reference,
        root: &root,
        intent: &intent,
        certificate: &certificate,
        roster: &roster,
        validity,
        policy: &policy,
        sdk: &sdk,
        witness: if carrier == "local" {
            None
        } else {
            witness.as_ref()
        },
        tls: tls.as_ref(),
        calls: Cell::new(if carrier == "local" { 2 } else { 3 }),
    };
    assert_eq!(case.run("policy-activate", "activated.request")?, request);
    let identity = case.run("policy-identity", "original.identity")?;
    assert_eq!(identity.len(), 64);
    assert_eq!(
        identity.get(32..).ok_or("identity journal width")?,
        journal.as_bytes()
    );
    let traffic = traffic::Traffic::begin(&case)?;
    traffic.renew_receiver(&case)?;
    if let Some(Maintenance::JointCycle) = maintenance {
        joint::repeat(&case, &identity, &traffic)?;
    } else if let Some(Maintenance::Joint { committed }) = maintenance {
        joint::exercise(&case, &identity, &traffic, committed)?;
    } else {
        flow::renew(&case, &identity)?;
        match maintenance {
            Some(Maintenance::Roster { closed }) => {
                if case.witness.is_some() {
                    roster::advance(&case, &identity, closed)?;
                } else {
                    assert!(!closed);
                    local_roster::advance(&case, &identity)?;
                }
            }
            Some(Maintenance::Credential) => credential::renew(&case, &identity)?,
            Some(Maintenance::Joint { .. } | Maintenance::JointCycle) => {
                unreachable!("joint route handled separately")
            }
            None => {}
        }
        traffic.resume(&case)?;
    }
    assert_eq!(case.run("policy-identity", "final.identity")?, identity);
    let calls = case.calls.get();
    publish_private_bytes(&base.join("policy-process-count"), &calls.to_be_bytes())?;
    policy.close();
    sdk.close();
    if let Some(tls) = tls.as_mut() {
        tls.finish()?;
    }
    if let Some(witness) = witness.as_mut() {
        witness.join()?;
    }
    if let Some(Maintenance::JointCycle) = maintenance {
        println!("qualified joint policy cycle {carrier}/{profile}: {calls} foreign processes; two applied G/T generations, three real policy expiries, original identity session message and one effect");
    } else if let Some(Maintenance::Joint { committed }) = maintenance {
        if carrier == "local" {
            println!("qualified joint policy {profile}: {calls} foreign processes; committed={committed}, expired original and target, exact historical outcome, original identity and one effect");
        } else {
            println!("qualified witnessed joint policy {carrier}/{profile}: {calls} foreign processes; committed={committed}, expired original and target, exact historical outcome, original identity");
        }
    } else {
        println!("qualified policy renewal {carrier}/{profile}: {calls} foreign processes; expired P0, independent P2, original identity session message and one effect");
    }
    Ok(())
}

fn roster_profile(profile: &str, carrier: &str, closed: bool) -> Result<()> {
    let parent = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("roster policy cases")?);
    let output = parent.join(format!(
        "{carrier}-{profile}-{}",
        if closed { "closed" } else { "applied" }
    ));
    let driver =
        PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("roster policy driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    exercise(
        &output,
        &driver,
        profile,
        carrier,
        Some(Maintenance::Roster { closed }),
    )
}
#[test]
fn roster_signed_fixed_applied() -> Result<()> {
    roster_profile("fixed", "signed", false)
}
#[test]
fn roster_signed_fixed_closed() -> Result<()> {
    roster_profile("fixed", "signed", true)
}
#[test]
fn roster_tls_fixed_applied() -> Result<()> {
    roster_profile("fixed", "tls", false)
}
#[test]
fn roster_tls_fixed_closed() -> Result<()> {
    roster_profile("fixed", "tls", true)
}
#[test]
fn roster_signed_recoverable_applied() -> Result<()> {
    roster_profile("recoverable", "signed", false)
}
#[test]
fn roster_signed_recoverable_closed() -> Result<()> {
    roster_profile("recoverable", "signed", true)
}
#[test]
fn roster_tls_recoverable_applied() -> Result<()> {
    roster_profile("recoverable", "tls", false)
}
#[test]
fn roster_tls_recoverable_closed() -> Result<()> {
    roster_profile("recoverable", "tls", true)
}

#[test]
fn roster_local_fixed() -> Result<()> {
    roster_profile("fixed", "local", false)
}
#[test]
fn roster_local_recoverable() -> Result<()> {
    roster_profile("recoverable", "local", false)
}

fn credential_profile(profile: &str, carrier: &str) -> Result<()> {
    let output =
        PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("credential policy cases")?);
    let driver =
        PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("credential policy driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    exercise(
        &output,
        &driver,
        profile,
        carrier,
        Some(Maintenance::Credential),
    )
}
#[test]
fn credential_local_fixed() -> Result<()> {
    credential_profile("fixed", "local")
}
#[test]
fn credential_signed_fixed() -> Result<()> {
    credential_profile("fixed", "signed")
}
#[test]
fn credential_tls_fixed() -> Result<()> {
    credential_profile("fixed", "tls")
}
#[test]
fn credential_local_recoverable() -> Result<()> {
    credential_profile("recoverable", "local")
}
#[test]
fn credential_signed_recoverable() -> Result<()> {
    credential_profile("recoverable", "signed")
}
#[test]
fn credential_tls_recoverable() -> Result<()> {
    credential_profile("recoverable", "tls")
}
