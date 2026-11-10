// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual C constructors and revoked cleanup over the native encrypted witness.
pub(super) use super::common_tls::{provision, TlsWitness};
use super::*;

pub(super) fn run_tls(
    path: &Path,
    label: &str,
    mode: &str,
    tail: &[String],
    address: SocketAddr,
    expected: i32,
) -> Result<String> {
    finish(
        start_carrier(path, label, mode, tail, Some(address), "--witness-tls")?,
        expected,
    )
}
pub(super) fn serve_tls(
    path: &Path,
    label: &str,
    mode: &str,
    address: SocketAddr,
) -> Result<(Process, SocketAddr)> {
    listening(start_carrier(
        path,
        label,
        "serve",
        &[mode.to_owned()],
        Some(address),
        "--witness-tls",
    )?)
}

#[test]
fn c_tls_witness_connects_and_revoked_cleanup_keeps_original_authority() -> Result<()> {
    // Provision and enroll using the retained fixture, then remove the plain
    // listener before any C TLS action. The selected C path cannot fall back.
    let mut original = Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&original.configured))?;
    original.join()?;
    let left = &setup.initiator;
    let right = &setup.responder;
    let mut witness = TlsWitness::start(Arc::clone(&original.configured.store), [left, right])?;
    let address = witness.address;
    fs::rename(
        left.join("witness-tls-key"),
        left.join("saved-witness-tls-key"),
    )?;
    assert_eq!(
        run_tls(left, "tls-missing-key", "reject-open", &[], address, 0)?,
        "rejected:500\n"
    );
    fs::rename(
        left.join("saved-witness-tls-key"),
        left.join("witness-tls-key"),
    )?;
    assert_eq!(witness.admitted.load(Ordering::Acquire), 0);
    fs::write(left.join("witness-tls-name"), b"wrong.test")?;
    assert_eq!(
        run_tls(left, "tls-wrong-name", "reject-open", &[], address, 0)?,
        "rejected:218\n"
    );
    fs::write(left.join("witness-tls-name"), b"localhost")?;
    assert_eq!(witness.admitted.load(Ordering::Acquire), 0);
    let certificate = fixture::read(left, "witness-tls-cert", 8192)?;
    let secret = zeroize::Zeroizing::new(fixture::read(left, "witness-tls-key", 8192)?);
    fs::copy(
        right.join("witness-tls-cert"),
        left.join("witness-tls-cert"),
    )?;
    fs::copy(right.join("witness-tls-key"), left.join("witness-tls-key"))?;
    assert_eq!(
        run_tls(left, "tls-wrong-subject", "reject-open", &[], address, 0)?,
        "rejected:218\n"
    );
    fs::write(left.join("witness-tls-cert"), certificate)?;
    fs::write(left.join("witness-tls-key"), secret.as_slice())?;
    assert_eq!(witness.admitted.load(Ordering::Acquire), 0);
    assert_eq!(
        run_tls(left, "tls-owner-kind", "recover-kind", &[], address, 0)?,
        "operational-owner-not-recovery\n"
    );
    let (receiver, endpoint) = serve_tls(right, "tls-bootstrap-server", "bootstrap", address)?;
    let initiation = p::InitiationId::generate()?;
    let session = id(run_tls(
        left,
        "tls-bootstrap-client",
        "connect",
        &[endpoint.to_string(), fixture::hex(initiation.as_bytes())],
        address,
        0,
    )?)?;
    assert!(
        finish(receiver, 0)?.contains(&format!("served:1:0:0:0\n{session}\n{}\n", "0".repeat(64)))
    );
    let message = id(run_tls(
        right,
        "tls-next",
        "next",
        std::slice::from_ref(&session),
        address,
        0,
    )?)?;
    let (receiver, endpoint) = serve_tls(left, "tls-message-server", "message", address)?;
    assert_eq!(
        run_tls(
            right,
            "tls-send",
            "send",
            &[endpoint.to_string(), session.clone(), message.clone()],
            address,
            0
        )?,
        "consumed\n"
    );
    assert!(finish(receiver, 0)?.contains(&format!("served:2:0:1:1\n{session}\n{message}\n")));
    let mut expected = bytes(&session)?.to_vec();
    expected.extend_from_slice(&bytes(&message)?);
    expected.extend_from_slice(b"persisted before process exit");
    assert_eq!(
        fixture::read(left, &format!("application-{message}"), 4096)?,
        expected
    );
    let mut policy = fixture::sdk(right)?;
    let before = policy.runtime()?.trusted_state();
    let (disabled, signature) = setup.issuer.policy(2, false)?;
    policy.replace_policy(before, &disabled, &signature)?;
    policy.close();
    assert_eq!(
        run_tls(right, "tls-revoked", "reject-open", &[], address, 0)?,
        "rejected:603\n"
    );
    assert_eq!(
        run_tls(
            right,
            "tls-cleanup-cancel",
            "recover-cancel",
            std::slice::from_ref(&session),
            address,
            0
        )?,
        "cancelled-cleanup-not-frozen\n"
    );
    assert_eq!(
        run_tls(
            right,
            "tls-freeze",
            "recover-freeze",
            std::slice::from_ref(&session),
            address,
            77
        )?,
        ""
    );
    assert_eq!(
        run_tls(
            right,
            "tls-ack",
            "recover-ack-crash",
            std::slice::from_ref(&session),
            address,
            77
        )?,
        ""
    );
    assert_eq!(
        run_tls(
            right,
            "tls-retire",
            "recover-finish",
            std::slice::from_ref(&session),
            address,
            0
        )?,
        "original-report-closed-retired\n"
    );
    assert_eq!(
        run_tls(right, "tls-archive", "recover-archive", &[], address, 0)?,
        "archive-closed-metadata-only\n"
    );
    let failures = witness.finish()?;
    assert_eq!(
        failures.len(),
        2,
        "unexpected TLS server failures: {failures:?}"
    );
    assert!(witness.admitted.load(Ordering::Acquire) > 0);
    let root = right.parent().ok_or("TLS fixture root")?;
    fixture::store(root,"c-witness-tls-public-result.json",format!(concat!(
        "{{\"schema_version\":2,\"language\":\"{}\",\"completed\":true,\"carrier\":\"q-periapt-anchor/1\",",
        "\"session\":\"{}\",\"message\":\"{}\",\"witness_exchanges\":{},",
        "\"rejected_connections\":2,\"sdk_revoked_cleanup\":true,\"release_claim_eligible\":false}}\n"),
        installed_language()?,session,message,witness.admitted.load(Ordering::Acquire)).as_bytes())?;
    Ok(())
}
