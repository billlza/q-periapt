// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Two real G/T generations through one original foreign installation and session.
use super::*;

fn copy_inputs(source: &Path, target: &Path, original: bool) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| "input name")?;
        if original
            && (name == "policy-target"
                || name.starts_with("credential-")
                || name.starts_with("joint-")
                || name.starts_with("renewal-")
                || name.starts_with("renewed-"))
        {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            assert!(
                original && name == "peer",
                "unexpected nested fixture inputs"
            );
            copy_inputs(&entry.path(), &target.join(name), false)?;
        } else {
            assert!(kind.is_file(), "non-regular fixture input");
            let bytes = zeroize::Zeroizing::new(fixture::read(source, &name, 65536)?);
            publish_private_bytes(&target.join(name), &bytes)?;
        }
    }
    Ok(())
}

fn issue_next(
    case: &Case<'_>,
    first: &issuer::Issued,
    identity: &[u8],
    previous_inputs: &Path,
) -> Result<Prepared> {
    let expected = fs::read(case.base.join("joint-final-request"))?;
    let first_request = crate::credential_request::read_credential_request(
        &case.base.join("joint-final-request"),
        true,
    )?;
    publish_private_bytes(
        &case.inputs.join("credential-operation"),
        first_request.operation.as_bytes(),
    )?;
    for label in ["joint-request", "joint-request-replayed"] {
        assert_eq!(case.run("policy-joint-request", label)?, expected);
    }
    if case.witness.is_some() {
        assert_eq!(
            case.run(
                "policy-joint-request-local-refused",
                "joint-request-local-refused"
            )?,
            216u32.to_be_bytes()
        );
    }
    let request =
        crate::credential_request::read_credential_request(&case.output("joint-request"), true)?;
    assert_eq!(
        request.journal.as_bytes(),
        identity.get(32..).ok_or("journal")?
    );
    assert_eq!(request.original_c, case.certificate);
    assert_eq!(request.original_r, case.roster.as_bytes());
    assert_eq!(request.authorization, Some(first.statement));
    assert_eq!(request.previous, first.roster);
    assert_eq!(
        request.previous_c,
        fs::read(previous_inputs.join("renewed-certificate"))?
    );
    assert_eq!(
        request.previous_r,
        fs::read(previous_inputs.join("renewed-roster"))?
    );
    let previous = crate::receiver_policy::historical(&case.inputs.join("policy-previous"))?;
    let issued = issuer::approve_request(case, &request, &previous)?;
    assert_ne!(issued.operation, first.operation);
    assert_ne!(issued.statement, first.statement);
    assert_eq!(issued.scope.previous_authorization, Some(first.statement));
    let (pending, applied) = statuses(&issued);
    let (_, old) = statuses(first);
    assert_eq!(case.run("policy-joint-status", "joint-before-stage")?, old);
    for (mode, label, code) in [
        (
            "policy-joint-stage-next-refused",
            "joint-bad-approval",
            102u32,
        ),
        (
            "policy-joint-stage-next-missing",
            "joint-missing-predecessor",
            105,
        ),
        (
            "policy-joint-stage-next-predecessor",
            "joint-bad-predecessor",
            103,
        ),
    ] {
        assert_eq!(case.run(mode, label)?, code.to_be_bytes());
        assert_eq!(
            case.run("policy-joint-status", &format!("{label}-status"))?,
            old
        );
    }
    for label in ["joint-staged", "joint-stage-replayed"] {
        assert_eq!(case.run("policy-joint-stage-next", label)?, pending);
    }
    assert_eq!(
        case.run("policy-joint-status", "joint-pending-reopened")?,
        pending
    );
    Ok(Prepared {
        issued,
        pending,
        applied,
        original_until: first.until,
        original_at: fixture::now()?,
    })
}

pub(super) fn exercise(case: &Case<'_>, identity: &[u8], traffic: &traffic::Traffic) -> Result<()> {
    // Keep the original application message unresolved until both generations
    // have committed. The first generation still activates and refreshes its peer.
    let first = super::first(case, identity, traffic, true, false)?;
    let inputs = case.base.join("cycle-inputs");
    copy_inputs(case.inputs, &inputs, true)?;
    let previous = inputs.join("policy-previous");
    fs::DirBuilder::new().mode(0o700).create(&previous)?;
    for name in [
        "family",
        "policy-root",
        "policy-version",
        "policy-digest",
        "protocol-policy",
    ] {
        publish_private_bytes(
            &previous.join(name),
            &fs::read(case.inputs.join("policy-target").join(name))?,
        )?;
    }
    publish_private_bytes(
        &inputs.join("previous-policy-authorization"),
        &first.statement,
    )?;
    let next = Case {
        inputs: &inputs,
        namespace: "cycle-",
        ..case.clone()
    };
    let prepared = issue_next(&next, &first, identity, case.inputs)?;
    if next.witness.is_some() {
        let previous = crate::receiver_policy::historical(&previous)?;
        witness::applied(&next, &prepared, identity, traffic, &previous, true)?;
    } else {
        assert_eq!(
            next.run("policy-joint-reconcile", "joint-committed")?,
            prepared.applied
        );
        assert_eq!(
            next.run("policy-joint-status", "joint-committed-reopened")?,
            prepared.applied
        );
        for label in ["joint-activated", "joint-activated-reopened"] {
            assert_eq!(next.run("policy-joint-activate", label)?, identity);
        }
        credential::admit_peer(&next)?;
        traffic.resume_with(&next, "policy-joint-peer-retry")?;
    }
    let at = wait_expiry(prepared.issued.until)?;
    let mut times = prepared.issued.until.to_be_bytes().to_vec();
    times.extend_from_slice(&at.to_be_bytes());
    publish_private_bytes(&next.output("expiry-observation"), &times)?;
    assert_eq!(
        next.run("policy-joint-current-expired", "joint-expired-current")?,
        104u32.to_be_bytes()
    );
    let start = next.captures()?.len();
    for index in 0..2 {
        let mode = if next.witness.is_some() {
            "policy-joint-witness-reconcile"
        } else {
            "policy-joint-history"
        };
        assert_eq!(
            next.run(mode, &format!("joint-history-{index}"))?,
            prepared.applied
        );
        assert_eq!(
            next.run(
                "policy-joint-status",
                &format!("joint-history-status-{index}")
            )?,
            prepared.applied
        );
    }
    if next.witness.is_some() {
        witness::history(&next, start, "joint-expired-history-transcript", true)?;
    }
    next_request(&next, identity, &prepared.issued, true)?;
    case.calls.set(next.calls.get());
    Ok(())
}

fn route(profile: &str, carrier: &str) -> Result<()> {
    let parent = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("joint cycle cases")?);
    let output = parent.join(format!("{carrier}-{profile}"));
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let driver = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("joint cycle driver")?);
    super::super::exercise(
        &output,
        &driver,
        profile,
        carrier,
        Some(Maintenance::JointCycle),
    )
}
#[test]
fn local_fixed() -> Result<()> {
    route("fixed", "local")
}
#[test]
fn local_recoverable() -> Result<()> {
    route("recoverable", "local")
}
#[test]
fn signed_fixed() -> Result<()> {
    route("fixed", "signed")
}
#[test]
fn signed_recoverable() -> Result<()> {
    route("recoverable", "signed")
}
#[test]
fn tls_fixed() -> Result<()> {
    route("fixed", "tls")
}
#[test]
fn tls_recoverable() -> Result<()> {
    route("recoverable", "tls")
}
