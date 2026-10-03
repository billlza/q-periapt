// SPDX-License-Identifier: Apache-2.0 OR MIT
//! TLS cleanup of a reserved original batch; reservation loss is a signed-TCP fixture.
use super::*;
use std::sync::Arc;

fn plain_count(plain: &witness::Witness) -> Result<usize> {
    Ok(plain
        .captured
        .lock()
        .map_err(|_| "plain witness capture lock")?
        .len())
}
fn encrypted<T>(
    plain: &witness::Witness,
    tls: &witness_tls::TlsWitness,
    phases: &mut String,
    label: &str,
    admitted: bool,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let before_plain = plain_count(plain)?;
    let before = tls.admitted.load(Ordering::Acquire);
    let result = action()?;
    let after = tls.admitted.load(Ordering::Acquire);
    assert_eq!(
        plain_count(plain)?,
        before_plain,
        "foreign TLS action used the plaintext witness"
    );
    assert_eq!(
        after > before,
        admitted,
        "TLS action admission differs: {label}"
    );
    phases.push_str(&format!("{label} {before} {after} 0\n"));
    Ok(result)
}

#[test]
fn account_cleanup_keeps_original_authority_over_mutual_tls() -> Result<()> {
    let mut plain = witness::Witness::start()?;
    let (setup, second) = fixture::setup_devices(Some(&plain.configured), None, None, true)?;
    let second = second.ok_or("second original TLS member")?;
    let root = &setup.initiator;
    let mut tls = witness_tls::TlsWitness::start(
        Arc::clone(&plain.configured.store),
        [root.as_path(), setup.responder.as_path(), second.as_path()],
    )?;
    let endpoint = Carrier::Tls(tls.address);
    let mut phases = String::new();
    let sessions = encrypted(&plain, &tls, &mut phases, "bootstrap", true, || {
        connect(&setup, &second, endpoint)
    })?;
    // Native setup/readback is separate from the measured foreign TLS phases.
    common::prepare(&setup, &second, Some(&plain.configured), sessions.clone())?;
    let batch = fixture::hex(&fixture::array::<32>(root, "cleanup-batch")?);
    let account = fixture::hex(&fixture::array::<32>(root, "cleanup-account")?);
    let id = [OsString::from(&batch)];
    let send = [
        root.join("peer-0").into_os_string(),
        fixture::hex(sessions.first().ok_or("first session")?).into(),
        root.join("peer-1").into_os_string(),
        fixture::hex(sessions.get(1).ok_or("second session")?).into(),
        account.into(),
        batch.clone().into(),
        "0".into(),
        "127.0.0.1:9".into(),
        "witness-unknown".into(),
    ];
    let mut lost = String::new();
    assert_eq!(
        lost_advance(&plain, "reservation", &mut lost, || run(
            root,
            "reserve-lost",
            "account-send",
            &send,
            Some(Carrier::Signed(plain.configured.address))
        ))?,
        "account-refused:218\n"
    );
    common::observe(root, Some(&plain.configured))?;
    common::revoke(root)?;
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "missing", false, || run(
            root,
            "missing",
            "recover-account-reject",
            &id,
            None
        ))?,
        "account-selection-refused:216\n"
    );
    let pin = fixture::array::<32>(root, "witness-id")?;
    fs::write(
        root.join("witness-id"),
        p::AnchorIdentity::generate()?.as_bytes(),
    )?;
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "wrong-pin", false, || run(
            root,
            "wrong-pin",
            "recover-account-reject",
            &id,
            Some(endpoint)
        ))?,
        "account-selection-refused:211\n"
    );
    fs::write(root.join("witness-id"), pin)?;
    fs::write(root.join("witness-tls-name"), b"wrong.test")?;
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "wrong-name", false, || run(
            root,
            "wrong-name",
            "recover-account-reject",
            &id,
            Some(endpoint)
        ))?,
        "account-selection-refused:218\n"
    );
    fs::write(root.join("witness-tls-name"), b"localhost")?;
    let cert = fixture::read(root, "witness-tls-cert", 8192)?;
    let key = zeroize::Zeroizing::new(fixture::read(root, "witness-tls-key", 8192)?);
    fs::copy(
        setup.responder.join("witness-tls-cert"),
        root.join("witness-tls-cert"),
    )?;
    fs::copy(
        setup.responder.join("witness-tls-key"),
        root.join("witness-tls-key"),
    )?;
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "wrong-subject", false, || run(
            root,
            "wrong-subject",
            "recover-account-reject",
            &id,
            Some(endpoint)
        ))?,
        "account-selection-refused:218\n"
    );
    fs::write(root.join("witness-tls-cert"), cert)?;
    fs::write(root.join("witness-tls-key"), key.as_slice())?;
    let frozen = encrypted(&plain, &tls, &mut phases, "freeze", true, || {
        run(
            root,
            "freeze",
            "recover-account-freeze",
            &id,
            Some(endpoint),
        )
    })?;
    let report = frozen
        .strip_prefix("account-frozen:")
        .and_then(|v| v.strip_suffix('\n'))
        .ok_or("TLS account frozen report")?;
    common::bytes_id(report)?;
    common::compare(root, Some(&plain.configured))?;
    let original = fixture::read(root, "c-account-loss-report", 1048576)?;
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "acknowledge", true, || run(
            root,
            "ack",
            "recover-account-ack",
            &id,
            Some(endpoint)
        ))?,
        format!("account-acknowledged:{report}\n")
    );
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "retirement", true, || run(
            root,
            "retire",
            "recover-account-retire",
            &id,
            Some(endpoint)
        ))?,
        "account-retired\n"
    );
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "retired", true, || run(
            root,
            "retired",
            "recover-account-retired",
            &id,
            Some(endpoint)
        ))?,
        "account-selection-refused:112\n"
    );
    common::terminal(root, Some(&plain.configured))?;
    assert_eq!(
        encrypted(&plain, &tls, &mut phases, "retired-missing", false, || run(
            root,
            "retired-missing",
            "recover-account-reject",
            &id,
            None
        ))?,
        "account-selection-refused:216\n"
    );
    let errors = tls.finish()?;
    assert_eq!(
        errors.len(),
        2,
        "unexpected TLS connection failures: {errors:?}"
    );
    assert_eq!(
        encrypted(
            &plain,
            &tls,
            &mut phases,
            "retired-unavailable",
            false,
            || run(
                root,
                "retired-unavailable",
                "recover-account-reject",
                &id,
                Some(endpoint)
            )
        )?,
        "account-selection-refused:218\n"
    );
    assert_eq!(
        fixture::read(root, "c-account-loss-report", 1048576)?,
        original
    );
    plain.join()?;
    assert_eq!(plain.fault.load(Ordering::Acquire), 0);
    let records = plain
        .captured
        .lock()
        .map_err(|_| "plain witness capture lock")?;
    let lost = records
        .iter()
        .filter(|row| !row.delivered)
        .collect::<Vec<_>>();
    assert_eq!(lost.len(), 1);
    let lost = lost.first().ok_or("reservation loss missing")?;
    assert!(records.iter().any(|retry| retry.delivered
        && retry.reply.get(204) == Some(&3)
        && retry.request.get(140..172) == lost.request.get(140..172)
        && retry.request.get(172..204) != lost.request.get(172..204)));
    fixture::store(root, "account-tls-phases", phases.as_bytes())?;
    retain_tls_authorities(&setup, &second)?;
    let result = format!("{{\"schema_version\":1,\"language\":\"{}\",\"completed\":true,\"batch\":\"{batch}\",\"report\":\"{report}\",\"carrier\":\"q-periapt-anchor/1\",\"reservation_carrier\":\"signed-tcp\",\"witness_exchanges\":{},\"rejected_connections\":2,\"release_claim_eligible\":false}}\n", language()?, tls.admitted.load(Ordering::Acquire));
    fixture::store(root, "account-tls-result.json", result.as_bytes())?;
    Ok(())
}
