// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual foreign original-command reconciliation after committed encrypted replies are lost.
use super::*;
use std::sync::Arc;
use witness_tls_faults::FaultWitness;

fn phase(
    original: &witness::Witness,
    tls: &FaultWitness,
    label: &str,
    stages: &mut String,
    lose: bool,
    action: impl FnOnce() -> Result<String>,
) -> Result<String> {
    let before_plain = original
        .captured
        .lock()
        .map_err(|_| "plain capture lock")?
        .len();
    let start = tls.captured.lock().map_err(|_| "TLS capture lock")?.len();
    if lose {
        tls.arm()?;
    }
    let output = action()?;
    let rows = tls.captured.lock().map_err(|_| "TLS capture lock")?;
    assert_eq!(
        original
            .captured
            .lock()
            .map_err(|_| "plain capture lock")?
            .len(),
        before_plain
    );
    let lost = rows
        .iter()
        .enumerate()
        .skip(start)
        .filter(|(_, row)| !row.delivered)
        .collect::<Vec<_>>();
    assert_eq!(lost.len(), usize::from(lose));
    if lose {
        let (index, row) = lost.first().ok_or("missing encrypted reply loss")?;
        assert!(row.advanced && row.encrypted_reply_bytes > 0);
        stages.push_str(&format!("{label} {start} {} {index}\n", rows.len()));
    }
    Ok(output)
}

#[test]
fn account_cleanup_reconciles_four_committed_tls_reply_losses() -> Result<()> {
    let mut original = witness::Witness::start()?;
    let (setup, second) = fixture::setup_devices(Some(&original.configured), None, None, true)?;
    let second = second.ok_or("second TLS account member")?;
    let root = &setup.initiator;
    let mut tls = FaultWitness::start(
        Arc::clone(&original.configured.store),
        [root.as_path(), setup.responder.as_path(), second.as_path()],
        original._directory.path().join("witness.redb"),
    )?;
    let endpoint = Carrier::Tls(tls.address);
    let sessions = connect(&setup, &second, endpoint)?;
    common::prepare(
        &setup,
        &second,
        Some(&original.configured),
        sessions.clone(),
    )?;
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
    let mut stages = String::new();
    assert_eq!(
        phase(&original, &tls, "reservation", &mut stages, true, || run(
            root,
            "reserve-lost",
            "account-send",
            &send,
            Some(endpoint)
        ))?,
        "account-refused:218\n"
    );
    assert_eq!(
        phase(&original, &tls, "reserved", &mut stages, false, || run(
            root,
            "reserve-reconciled",
            "account-status",
            &id,
            Some(endpoint)
        ))?,
        format!("account-status:1\n{}\n", "0".repeat(64))
    );
    // Native readback follows the foreign TLS reconciliation, not vice versa.
    common::observe(root, Some(&original.configured))?;
    common::revoke(root)?;
    assert_eq!(
        run(root, "missing", "recover-account-reject", &id, None)?,
        "account-selection-refused:216\n"
    );
    let pin = fixture::array::<32>(root, "witness-id")?;
    fs::write(
        root.join("witness-id"),
        p::AnchorIdentity::generate()?.as_bytes(),
    )?;
    assert_eq!(
        run(
            root,
            "wrong-pin",
            "recover-account-reject",
            &id,
            Some(endpoint)
        )?,
        "account-selection-refused:211\n"
    );
    fs::write(root.join("witness-id"), pin)?;
    assert_eq!(
        phase(&original, &tls, "freeze", &mut stages, true, || run(
            root,
            "freeze-lost",
            "recover-account-witness-freeze",
            &id,
            Some(endpoint)
        ))?,
        "account-freeze-outcome-unavailable\n"
    );
    let frozen = phase(
        &original,
        &tls,
        "freeze-reconciled",
        &mut stages,
        false,
        || {
            run(
                root,
                "freeze-reconciled",
                "recover-account-freeze-reconcile",
                &id,
                Some(endpoint),
            )
        },
    )?;
    let report = frozen
        .strip_prefix("account-frozen:")
        .and_then(|v| v.strip_suffix('\n'))
        .ok_or("TLS loss report output")?;
    common::bytes_id(report)?;
    common::compare(root, Some(&original.configured))?;
    let saved = fixture::read(root, "c-account-loss-report", 1048576)?;
    assert_eq!(
        phase(&original, &tls, "acknowledge", &mut stages, true, || run(
            root,
            "ack-lost",
            "recover-account-witness-ack",
            &id,
            Some(endpoint)
        ))?,
        "account-acknowledgement-outcome-unavailable\n"
    );
    assert_eq!(
        phase(
            &original,
            &tls,
            "ack-reconciled",
            &mut stages,
            false,
            || run(
                root,
                "ack-reconciled",
                "recover-account-ack-reconcile",
                &id,
                Some(endpoint)
            )
        )?,
        format!("account-acknowledged:{report}\n")
    );
    assert_eq!(
        phase(&original, &tls, "retirement", &mut stages, true, || run(
            root,
            "retire-lost",
            "recover-account-witness-retire",
            &id,
            Some(endpoint)
        ))?,
        "account-retirement-outcome-unavailable\n"
    );
    assert_eq!(
        phase(
            &original,
            &tls,
            "retire-reconciled",
            &mut stages,
            false,
            || run(
                root,
                "retire-reconciled",
                "recover-account-retire-reconcile",
                &id,
                Some(endpoint)
            )
        )?,
        "account-retired\n"
    );
    assert_eq!(
        phase(&original, &tls, "retired", &mut stages, false, || run(
            root,
            "retired",
            "recover-account-retired",
            &id,
            Some(endpoint)
        ))?,
        "account-selection-refused:112\n"
    );
    common::terminal(root, Some(&original.configured))?;
    assert_eq!(
        run(root, "retired-missing", "recover-account-reject", &id, None)?,
        "account-selection-refused:216\n"
    );
    tls.finish()?;
    assert_eq!(
        run(
            root,
            "retired-unavailable",
            "recover-account-reject",
            &id,
            Some(endpoint)
        )?,
        "account-selection-refused:218\n"
    );
    original.join()?;
    assert_eq!(
        fixture::read(root, "c-account-loss-report", 1048576)?,
        saved
    );
    let records = tls.captured.lock().map_err(|_| "TLS final capture lock")?;
    assert_eq!(records.iter().filter(|row| !row.delivered).count(), 4);
    let mut ledger = String::new();
    for (index, row) in records.iter().enumerate() {
        use std::fmt::Write as _;
        writeln!(
            ledger,
            "{index} {} {} {}",
            u8::from(row.advanced),
            u8::from(row.delivered),
            row.encrypted_reply_bytes
        )?;
    }
    fixture::store(root, "account-tls-loss-exchanges", ledger.as_bytes())?;
    fixture::store(root, "account-tls-loss-stages", stages.as_bytes())?;
    retain_tls_authorities(&setup, &second)?;
    let result=format!("{{\"schema_version\":1,\"language\":\"{}\",\"completed\":true,\"batch\":\"{batch}\",\"report\":\"{report}\",\"carrier\":\"q-periapt-anchor/1\",\"lost_advances\":4,\"witness_exchanges\":{},\"release_claim_eligible\":false}}\n",language()?,records.len());
    fixture::store(root, "account-tls-loss-result.json", result.as_bytes())?;
    Ok(())
}
