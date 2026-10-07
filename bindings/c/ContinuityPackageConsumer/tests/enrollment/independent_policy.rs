// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real C request export, independent approval, exact restart/retry and original journal adoption.
use super::*;

fn foreign_policy_case(case: &str) -> Result<()> {
    if let Some(client) = PolicyClient::selected()? {
        eprintln!("FOREIGN_POLICY_LIFECYCLE language={} case={case} original_request=true exact_proposal=true native_outcomes=true C_registration_and_raw_controls=true shared_native_engine=true", client.language);
    }
    Ok(())
}

fn run_policy_transport(path: &Path, label: &str, args: &[OsString]) -> Result<String> {
    match PolicyClient::selected()? {
        Some(client) => {
            let output = run_client(&client.executable, path, label, args)?;
            eprintln!(
                "FOREIGN_POLICY_TRANSPORT language={} label={label}",
                client.language
            );
            Ok(output)
        }
        None => run(path, label, args),
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Input<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.offset.checked_add(N).ok_or("input offset")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated public record")?
            .try_into()?;
        self.offset = end;
        Ok(value)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_ne_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_ne_bytes(self.array()?))
    }
    fn roster(&mut self) -> Result<p::RosterCheckpoint> {
        Ok(p::RosterCheckpoint::from_trusted_state(
            self.u64()?,
            self.array()?,
        )?)
    }
    fn policy(&mut self) -> Result<p::PolicyCheckpoint> {
        Ok(p::PolicyCheckpoint::from_trusted_state(
            self.u64()?,
            self.array()?,
        )?)
    }
    fn record(&mut self) -> Result<Vec<u8>> {
        let n = usize::try_from(self.u32()?)?;
        let bytes = self.array::<8192>()?;
        if n == 0 || n > 8192 || bytes.get(n..).ok_or("record tail")?.iter().any(|x| *x != 0) {
            return Err("noncanonical public record".into());
        }
        Ok(bytes.get(..n).ok_or("record length")?.to_vec())
    }
}
struct Request {
    scope: p::PolicyRenewalScope,
    account: [u8; 32],
    original_checkpoint: p::RosterCheckpoint,
    original_c: Vec<u8>,
    original_r: Vec<u8>,
    current_c: Vec<u8>,
    current_r: Vec<u8>,
}
fn read_request(path: &Path) -> Result<Request> {
    let bytes = fs::read(path.join("independent-request"))?;
    assert_eq!(bytes.len(), 33176);
    let mut r = Input {
        bytes: &bytes,
        offset: 0,
    };
    let operation = p::PolicyRenewalId::from_trusted_state(r.array()?)?;
    let journal = p::JournalIdentity::from_trusted_state(r.array()?)?;
    let original_owner = r.array()?;
    let original_credential = r.array()?;
    let current_credential = r.array()?;
    let current_roster = r.roster()?;
    let original_policy = r.policy()?;
    let previous_policy = r.policy()?;
    let authorization = r.array()?;
    let previous_authorization = match r.u32()? {
        0 if authorization == [0; 32] => None,
        1 if authorization != [0; 32] => Some(authorization),
        _ => return Err("optional policy authorization".into()),
    };
    assert_eq!(r.u32()?, 0);
    let scope = p::PolicyRenewalScope {
        operation,
        journal,
        original_owner,
        original_credential,
        current_credential,
        current_roster,
        original_policy,
        previous_policy,
        previous_authorization,
    };
    let result = Request {
        scope,
        account: r.array()?,
        original_checkpoint: r.roster()?,
        original_c: r.record()?,
        original_r: r.record()?,
        current_c: r.record()?,
        current_r: r.record()?,
    };
    assert_eq!(r.offset, bytes.len());
    Ok(result)
}
fn invoke(c: &Registered, label: &str, mode: &str) -> Result<String> {
    let args = c.arguments(command(&c.path, &format!("independent-policy-{mode}")));
    match PolicyClient::selected()? {
        Some(client) if !matches!(mode, "stage-dirty-tail" | "witness-wrong-kind") => {
            let output = run_client(&client.executable, &c.path, label, &args)?;
            eprintln!(
                "FOREIGN_POLICY_CALL language={} mode={mode} label={label}",
                client.language
            );
            Ok(output)
        }
        // These native raw-buffer controls cannot be represented by a valid
        // typed wrapper value. Keep the original C controls and assertions.
        _ => run(&c.path, label, &args),
    }
}
fn enrollment_row(c: &Registered) -> Result<Vec<u8>> {
    use redb::{ReadableDatabase, TableDefinition};
    let db = open_private_database(&c.path.join("enrollment.redb"))?;
    let tx = db.begin_read()?;
    let table = tx.open_table(TableDefinition::<&str, &[u8]>::new(
        "continuity_enrollment_v1",
    ))?;
    let row = table.get("enrollment")?.ok_or("original enrollment row")?;
    Ok(row.value().to_vec())
}
fn expected_status(
    phase: u32,
    request: &Request,
    statement: [u8; 32],
    target: p::PolicyCheckpoint,
) -> String {
    let zero = hex(&[0; 32]);
    format!(
        "{phase}\n0\n{}\n{}\n{}\n{}\n0\n{zero}\n0\n",
        hex(request.scope.operation.as_bytes()),
        hex(&statement),
        target.version(),
        hex(&target.digest())
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
struct Prepared {
    c: Registered,
    request: Request,
    statement: [u8; 32],
    target: p::PolicyCheckpoint,
    alternative: Vec<u8>,
}
fn prepare() -> Result<Prepared> {
    let policy_root = p::PolicySigningKey::generate()?;
    let c = registered_with_policy(600, Some(&policy_root))?;
    prepare_for(c, policy_root)
}
fn prepare_for(c: Registered, policy_root: p::PolicySigningKey) -> Result<Prepared> {
    let operation = p::PolicyRenewalId::generate()?;
    fixture::store(&c.path, "independent-operation", operation.as_bytes())?;
    let before = enrollment_row(&c)?;
    assert_eq!(
        invoke(
            &c,
            "independent-request",
            if c.witness.is_some() {
                "witness-request"
            } else {
                "request"
            }
        )?,
        "request-saved\n"
    );
    assert!(
        enrollment_row(&c)? == before,
        "request changed authenticated enrollment"
    );
    let request = read_request(&c.path)?;
    assert_eq!(request.account, c.root.account_id()?);
    assert_eq!(request.scope.operation, operation);
    assert_eq!(request.scope.journal.as_bytes(), &c.accepted.2);
    assert_eq!(request.original_checkpoint, c.roster.checkpoint());
    assert_eq!(request.scope.current_roster, c.roster.checkpoint());
    assert_eq!(request.original_c, c.certificate);
    assert_eq!(request.current_c, c.certificate);
    assert_eq!(request.original_r, c.roster.as_bytes());
    assert_eq!(request.current_r, c.roster.as_bytes());
    let pin = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        c.roster.checkpoint(),
        c.family,
    )?;
    let original_device = pin.verify_historical_device(&request.original_c, &request.original_r)?;
    let current_device = pin.verify_historical_device(&request.current_c, &request.current_r)?;
    let mut sdk = fixture::sdk(&c.path)?;
    let original = fixture::protocol_policy(&c.path, &sdk)?;
    assert_eq!(request.scope.original_policy, original.checkpoint());
    assert_eq!(request.scope.previous_policy, original.checkpoint());
    assert_eq!(request.scope.previous_authorization, None);
    let target_path = c.path.join("independent-sdk");
    fs::DirBuilder::new().mode(0o700).create(&target_path)?;
    for name in ["sdk-policy", "sdk-signature", "sdk-root"] {
        fixture::store(&target_path, name, &fs::read(c.path.join(name))?)?;
    }
    let mut target_sdk = PolicyStore::provision(
        &target_path.join("sdk.redb"),
        &fixture::read(&target_path, "sdk-policy", 4096)?,
        &fixture::read(&target_path, "sdk-signature", 8192)?,
        &fixture::read(&target_path, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    let target_runtime = target_sdk.runtime()?;
    let issued = policy_root.issue_session_policy(
        &target_runtime,
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
    for (name, bytes) in [
        ("family", c.family.to_vec()),
        ("policy-root", policy_root.public_key()?.encode()),
        (
            "policy-version",
            issued.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("policy-digest", issued.checkpoint().digest().to_vec()),
        ("protocol-policy", issued.as_bytes().to_vec()),
    ] {
        fixture::store(&target_path, name, &bytes)?;
    }
    let target_policy = p::PolicyPin::new(
        c.family,
        policy_root.public_key()?,
        issued.checkpoint(),
    )?
    .verify(issued.as_bytes(), target_sdk.runtime()?, fixture::now()?)?;
    let materials = p::PolicyRenewalMaterials {
        original: original.historical(),
        previous: original.historical(),
        target: &target_policy,
        original_device: &original_device,
        current_device: &current_device,
    };
    let statement = p::PolicyRenewalStatement::new(&request.scope, &materials, fixture::now()?)?;
    let approvals = p::VerifiedPolicyRenewal::verify(
        &c.root.approve_policy_renewal(&statement)?,
        &policy_root.approve_policy_renewal(&statement)?,
        &request.scope,
        &materials,
        fixture::now()?,
    )?;
    let alternative = p::VerifiedPolicyRenewal::verify(
        &c.root.approve_policy_renewal(&statement)?,
        &policy_root.approve_policy_renewal(&statement)?,
        &request.scope,
        &materials,
        fixture::now()?,
    )?;
    assert_ne!(
        approvals.as_bytes(),
        alternative.as_bytes(),
        "control must use distinct valid signatures"
    );
    fixture::store(&c.path, "independent-first-approvals", approvals.as_bytes())?;
    fixture::store(&c.path, "independent-approvals", approvals.as_bytes())?;
    fixture::store(&c.path, "independent-statement", &statement.digest())?;
    target_policy.close();
    target_sdk.close();
    original.close();
    sdk.close();
    Ok(Prepared {
        c,
        request,
        statement: statement.digest(),
        target: issued.checkpoint(),
        alternative: alternative.as_bytes().to_vec(),
    })
}
#[test]
fn c_independent_policy_request_restarts_exact_stage_and_adopts_original_journal() -> Result<()> {
    let f = prepare()?;
    let c = &f.c;
    let signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
    let wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
    let pending = expected_status(1, &f.request, f.statement, f.target);
    let committed = expected_status(2, &f.request, f.statement, f.target);
    assert_eq!(invoke(c, "independent-stage", "stage")?, pending);
    assert_eq!(
        invoke(c, "independent-pending", "pending")?,
        "pending-exact\n"
    );
    assert_eq!(
        invoke(c, "independent-refused-request", "request-refused")?,
        "request-refused:215\n"
    );
    fs::write(c.path.join("independent-approvals"), &f.alternative)?;
    assert_eq!(invoke(c, "independent-stage-retry", "stage")?, pending);
    assert_eq!(
        invoke(c, "independent-original-signatures", "pending")?,
        "pending-exact\n"
    );
    let before = enrollment_row(c)?;
    assert_eq!(
        invoke(c, "independent-unresolved", "resolve-pending")?,
        "pending-unresolved:215\n"
    );
    assert!(
        enrollment_row(c)? == before,
        "historical query committed a pending target"
    );
    assert_eq!(invoke(c, "independent-commit", "reconcile")?, committed);
    assert_eq!(invoke(c, "independent-commit-status", "status")?, committed);
    assert_eq!(invoke(c, "independent-commit-retry", "stage")?, committed);
    assert_eq!(
        invoke(c, "independent-activate", "activate")?,
        "independent-device-active\n"
    );
    assert_eq!(
        state(&run(
            &c.path,
            "independent-original-status",
            &command(&c.path, "status")
        )?)?,
        (5, c.accepted.1, c.accepted.2)
    );
    assert!(
        fs::read(c.path.join("signer.key"))? == *signer,
        "original signer changed"
    );
    assert!(
        fs::read(c.path.join("wrap.key"))? == *wrapping,
        "original wrapping key changed"
    );
    // Historical readback must not reopen the operational runtime or signer.
    for name in [
        "sdk.redb",
        "sdk-policy",
        "sdk-signature",
        "sdk-root",
        "tls-cert",
        "tls-key",
        "signer.key",
    ] {
        let path = c.path.join(name);
        fs::rename(&path, path.with_extension("held"))?;
    }
    assert_eq!(invoke(c, "independent-history", "resolve")?, committed);
    lease(&c.path, false)?;
    foreign_policy_case("local-lifecycle")?;
    eprintln!("C_INDEPENDENT_POLICY request_from_original=true signed_inputs_reverified=true pending_exact_retry=true first_approvals_retained=true actual_commit=true original_device_transfer=true historical_without_runtime_tls_signer=true");
    Ok(())
}
#[test]
fn c_independent_policy_rejects_changed_requests_without_publishing_or_mutating_intent(
) -> Result<()> {
    let f = prepare()?;
    for (mode, code) in [
        ("stage-corrupt-scope", 103),
        ("stage-corrupt-certificate", 102),
        ("stage-dirty-tail", 1),
        ("stage-cancelled", 302),
    ] {
        let before = enrollment_row(&f.c)?;
        assert_eq!(
            invoke(&f.c, &format!("independent-{mode}"), mode)?,
            format!("stage-refused:{code}\n")
        );
        assert!(
            enrollment_row(&f.c)? == before,
            "refused stage changed original intent"
        );
    }
    eprintln!("C_INDEPENDENT_POLICY_ERRORS scope=true signature=true tail=true cancellation=true output_untouched=true ownership_checked=true original_intent=true");
    Ok(())
}

#[test]
fn c_independent_policy_restores_original_tls_session_after_lost_application_receipt() -> Result<()>
{
    let mut c = registered(600)?;
    let issuer = c
        ._setup
        .policy_issuer
        .take()
        .ok_or("original policy issuer")?;
    let f = prepare_for(c, issuer)?;
    let c = &f.c;
    let peer = peer_bundle(&c._setup, &c.path, &c.root, &c.certificate, &c.roster)?;
    let bundle = fs::read(peer.join("bootstrap.bundle"))?;
    let signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
    let wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
    let (mut server, address) = fixture::spawn(&c._setup.responder, 91, "bootstrap")?;
    let initiation = p::InitiationId::generate()?;
    let session = decode_id(
        run_policy_transport(
            &c.path,
            "independent-traffic-connect",
            &[
                "--enrollment-parent".into(),
                c.path.as_os_str().into(),
                "1".into(),
                "connect".into(),
                peer.as_os_str().into(),
                address.to_string().into(),
                fixture::hex(initiation.as_bytes()).into(),
            ],
        )?
        .trim_end(),
    )?;
    assert!(fixture::wait(&mut server)?.success());
    let args = |continued: bool, operation: &str, tail: Vec<OsString>| {
        let mut args = vec![
            if continued {
                "--independent-policy-parent"
            } else {
                "--enrollment-parent"
            }
            .into(),
            c.path.as_os_str().into(),
            "1".into(),
            "--session".into(),
            fixture::hex(&session).into(),
            operation.into(),
            peer.as_os_str().into(),
        ];
        args.extend(tail);
        args
    };
    let message = decode_id(
        run_policy_transport(
            &c.path,
            "independent-traffic-next",
            &args(false, "next", vec![fixture::hex(&session).into()]),
        )?
        .trim_end(),
    )?;
    assert_eq!(
        invoke(c, "independent-traffic-stage", "stage")?,
        expected_status(1, &f.request, f.statement, f.target)
    );
    assert_eq!(
        invoke(c, "independent-traffic-reconcile", "reconcile")?,
        expected_status(2, &f.request, f.statement, f.target)
    );
    let (mut server, address) = fixture::spawn(&c._setup.responder, 92, "crash-after-application")?;
    assert_eq!(
        run_policy_transport(
            &c.path,
            "independent-traffic-unknown",
            &args(
                true,
                "uncertain-send",
                vec![
                    address.to_string().into(),
                    fixture::hex(&session).into(),
                    fixture::hex(&message).into()
                ]
            )
        )?,
        "delivery-unknown-committed\n"
    );
    assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
    fixture::effect(
        &c._setup.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    let effect = c
        ._setup
        .responder
        .join(format!("application-{}", fixture::hex(&message)));
    let before = fs::metadata(&effect)?;
    assert_eq!(
        run_policy_transport(
            &c.path,
            "independent-traffic-pending-reopen",
            &args(
                true,
                "status",
                vec![fixture::hex(&session).into(), fixture::hex(&message).into()]
            )
        )?,
        "2\n"
    );
    let (mut server, address) = fixture::spawn(&c._setup.responder, 93, "application")?;
    assert_eq!(
        run_policy_transport(
            &c.path,
            "independent-traffic-retry",
            &args(
                true,
                "send",
                vec![
                    address.to_string().into(),
                    fixture::hex(&session).into(),
                    fixture::hex(&message).into()
                ]
            )
        )?,
        "consumed\n"
    );
    assert!(fixture::wait(&mut server)?.success());
    fixture::effect(
        &c._setup.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    assert_eq!(
        run_policy_transport(
            &c.path,
            "independent-traffic-ack",
            &args(
                true,
                "status",
                vec![fixture::hex(&session).into(), fixture::hex(&message).into()]
            )
        )?,
        "3\n"
    );
    use std::os::unix::fs::MetadataExt;
    let after = fs::metadata(&effect)?;
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        )
    );
    let effects = fs::read_dir(&c._setup.responder)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("application-")
        })
        .count();
    assert_eq!(
        effects, 1,
        "original retry created another application effect"
    );
    assert_eq!(fs::read(peer.join("bootstrap.bundle"))?, bundle);
    assert_eq!(
        fixture::array::<32>(&c._setup.responder, "session")?,
        session
    );
    assert!(fs::read(c.path.join("signer.key"))? == *signer);
    assert!(fs::read(c.path.join("wrap.key"))? == *wrapping);
    assert_eq!(
        state(&run_policy_transport(
            &c.path,
            "independent-traffic-original-identity",
            &command(&c.path, "status")
        )?)?,
        (5, c.accepted.1, c.accepted.2)
    );
    foreign_policy_case("local-tls-session-recovery")?;
    eprintln!("C_INDEPENDENT_POLICY_TRAFFIC original_tls_session=true original_message=true receiver_effect_once=true unknown_commit_preserved=true acknowledged_after_process_reopen=true original_signer_journal_keys=true native_peer=true");
    Ok(())
}

#[path = "independent_policy_language.rs"]
mod public_bindings;

#[path = "witness_independent_policy.rs"]
mod witnessed;
