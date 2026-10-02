// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete-account recovery through actual foreign owners and the original witness.
#[path = "common/account_cleanup.rs"]
mod common;
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "account_witness/tls.rs"]
mod tls;
#[path = "common/witness.rs"]
mod witness;
#[path = "common/witness_tls.rs"]
mod witness_tls;
use q_periapt_continuity_identity_candidate as p;
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn language() -> Result<&'static str> {
    match std::env::var("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") {
        Err(std::env::VarError::NotPresent) => Ok("C"),
        Ok(value) if value == "C" => Ok("C"),
        Ok(value) if value == "Swift" => Ok("Swift"),
        Ok(value) if value == "Kotlin" => Ok("Kotlin"),
        _ => Err("unqualified account witness language".into()),
    }
}
#[derive(Clone, Copy)]
enum Carrier {
    Signed(SocketAddr),
    Tls(SocketAddr),
}
impl Carrier {
    fn arguments(self) -> [OsString; 2] {
        let (flag, address) = match self {
            Self::Signed(address) => ("--witness", address),
            Self::Tls(address) => ("--witness-tls", address),
        };
        [flag.into(), address.to_string().into()]
    }
}
fn arguments(
    mode: &str,
    path: &Path,
    tail: &[OsString],
    endpoint: Option<Carrier>,
) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(endpoint) = endpoint {
        args.extend(endpoint.arguments());
    }
    args.extend([mode.into(), path.as_os_str().to_owned()]);
    args.extend_from_slice(tail);
    args
}
fn run(
    path: &Path,
    label: &str,
    mode: &str,
    tail: &[OsString],
    endpoint: Option<Carrier>,
) -> Result<String> {
    common::client(path, label, &arguments(mode, path, tail, endpoint))
}
fn server(path: &Path, endpoint: Carrier) -> Result<(common::Process, SocketAddr)> {
    let mut process = common::start_client(
        path,
        "account-server",
        &arguments("serve", path, &["bootstrap".into()], Some(endpoint)),
    )?;
    let until = Instant::now() + Duration::from_secs(25);
    loop {
        if let Some(line) = process.output()?.lines().next() {
            let port = line
                .strip_prefix("listening:")
                .ok_or("account server readiness")?
                .parse::<u16>()?;
            if port == 0 {
                return Err("zero account server port".into());
            }
            return Ok((process, SocketAddr::from(([127, 0, 0, 1], port))));
        }
        if process.child.0.try_wait()?.is_some() || Instant::now() >= until {
            return Err("account server did not become ready".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn lost_advance(
    witness: &witness::Witness,
    label: &str,
    stages: &mut String,
    action: impl FnOnce() -> Result<String>,
) -> Result<String> {
    let start = witness
        .captured
        .lock()
        .map_err(|_| "witness capture lock")?
        .len();
    witness.arm(1)?;
    let output = action()?;
    let records = witness
        .captured
        .lock()
        .map_err(|_| "witness capture lock")?;
    let lost = records
        .iter()
        .enumerate()
        .skip(start)
        .filter(|(_, row)| !row.delivered)
        .collect::<Vec<_>>();
    assert_eq!(lost.len(), 1);
    let (at, record) = lost.first().ok_or("missing lost advance")?;
    assert_eq!(record.reply.get(204), Some(&2));
    stages.push_str(&format!("{label} {start} {} {at}\n", records.len()));
    Ok(output)
}

fn connect(setup: &fixture::Setup, second: &Path, endpoint: Carrier) -> Result<Vec<[u8; 32]>> {
    let root = &setup.initiator;
    let (server0, address0) = server(&setup.responder, endpoint)?;
    let (server1, address1) = server(second, endpoint)?;
    let peers = [root.join("peer-0"), root.join("peer-1")];
    let connect = run(
        root,
        "connect",
        "account-connect",
        &[
            peers.first().ok_or("first peer")?.as_os_str().to_owned(),
            peers.get(1).ok_or("second peer")?.as_os_str().to_owned(),
            address0.to_string().into(),
            address1.to_string().into(),
            fixture::hex(p::InitiationId::generate()?.as_bytes()).into(),
            fixture::hex(p::InitiationId::generate()?.as_bytes()).into(),
        ],
        Some(endpoint),
    )?;
    let sessions = connect
        .lines()
        .map(common::bytes_id)
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(sessions.len(), 2);
    for (index, ((process, session), receiver)) in [server0, server1]
        .into_iter()
        .zip(&sessions)
        .zip([setup.responder.as_path(), second])
        .enumerate()
    {
        let output = process.finish()?;
        assert!(output.contains(&format!(
            "served:1:0:0:0\n{}\n{}\n",
            fixture::hex(session),
            "0".repeat(64)
        )));
        fixture::store(
            root,
            &format!("account-server-{index}.stdout"),
            output.as_bytes(),
        )?;
        fixture::store(
            root,
            &format!("account-server-{index}.stderr"),
            &fs::read(receiver.join("cleanup-account-server.stderr"))?,
        )?;
    }
    Ok(sessions)
}

#[test]
fn account_cleanup_requires_original_witness_and_reconciles_lost_advances() -> Result<()> {
    let mut witness = witness::Witness::start()?;
    let endpoint = Carrier::Signed(witness.configured.address);
    let (setup, second) = fixture::setup_devices(Some(&witness.configured), None, None, true)?;
    let second = second.ok_or("second original member")?;
    let root = &setup.initiator;
    let sessions = connect(&setup, &second, endpoint)?;
    let peers = [root.join("peer-0"), root.join("peer-1")];
    common::prepare(&setup, &second, Some(&witness.configured), sessions.clone())?;
    let batch = fixture::hex(&fixture::array::<32>(root, "cleanup-batch")?);
    let account = fixture::hex(&fixture::array::<32>(root, "cleanup-account")?);
    let id = [OsString::from(&batch)];
    let send = [
        peers.first().ok_or("first peer")?.as_os_str().to_owned(),
        fixture::hex(sessions.first().ok_or("first session")?).into(),
        peers.get(1).ok_or("second peer")?.as_os_str().to_owned(),
        fixture::hex(sessions.get(1).ok_or("second session")?).into(),
        account.into(),
        batch.clone().into(),
        "0".into(),
        "127.0.0.1:9".into(),
        "witness-unknown".into(),
    ];
    let mut stages = String::new();
    assert_eq!(
        lost_advance(&witness, "reservation", &mut stages, || run(
            root,
            "reserve-lost",
            "account-send",
            &send,
            Some(endpoint)
        ))?,
        "account-refused:218\n"
    );
    common::observe(root, Some(&witness.configured))?;
    assert_eq!(fixture::read(root, "cleanup-observed", 64)?, b"reserved\n");
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
    witness.arm(2)?;
    assert_eq!(
        run(
            root,
            "bad-signature",
            "recover-account-reject",
            &id,
            Some(endpoint)
        )?,
        "account-selection-refused:218\n"
    );
    assert_eq!(
        lost_advance(&witness, "freeze", &mut stages, || run(
            root,
            "freeze-lost",
            "recover-account-witness-freeze",
            &id,
            Some(endpoint)
        ))?,
        "account-freeze-outcome-unavailable\n"
    );
    let frozen = run(
        root,
        "freeze-reconciled",
        "recover-account-freeze-reconcile",
        &id,
        Some(endpoint),
    )?;
    let report = frozen
        .strip_prefix("account-frozen:")
        .and_then(|s| s.strip_suffix('\n'))
        .ok_or("frozen report output")?;
    common::bytes_id(report)?;
    common::compare(root, Some(&witness.configured))?;
    let original = fixture::read(root, "c-account-loss-report", 1048576)?;
    assert_eq!(
        lost_advance(&witness, "acknowledge", &mut stages, || run(
            root,
            "ack-lost",
            "recover-account-witness-ack",
            &id,
            Some(endpoint)
        ))?,
        "account-acknowledgement-outcome-unavailable\n"
    );
    assert_eq!(
        run(
            root,
            "ack-reconciled",
            "recover-account-ack-reconcile",
            &id,
            Some(endpoint)
        )?,
        format!("account-acknowledged:{report}\n")
    );
    assert_eq!(
        lost_advance(&witness, "retirement", &mut stages, || run(
            root,
            "retire-lost",
            "recover-account-witness-retire",
            &id,
            Some(endpoint)
        ))?,
        "account-retirement-outcome-unavailable\n"
    );
    assert_eq!(
        run(
            root,
            "retire-reconciled",
            "recover-account-retire-reconcile",
            &id,
            Some(endpoint)
        )?,
        "account-retired\n"
    );
    assert_eq!(
        run(
            root,
            "retired",
            "recover-account-retired",
            &id,
            Some(endpoint)
        )?,
        "account-selection-refused:112\n"
    );
    common::terminal(root, Some(&witness.configured))?;
    assert_eq!(
        run(root, "retired-missing", "recover-account-reject", &id, None)?,
        "account-selection-refused:216\n"
    );
    witness.join()?;
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
    assert_eq!(
        fixture::read(root, "c-account-loss-report", 1048576)?,
        original
    );
    assert_eq!(witness.fault.load(Ordering::Acquire), 0);
    let records = witness
        .captured
        .lock()
        .map_err(|_| "witness capture lock")?;
    let lost = records.iter().filter(|r| !r.delivered).collect::<Vec<_>>();
    assert_eq!(lost.len(), 4);
    for row in lost {
        assert!(records.iter().any(|retry| retry.delivered
            && retry.reply.get(204) == Some(&3)
            && retry.request.get(140..172) == row.request.get(140..172)
            && retry.request.get(172..204) != row.request.get(172..204)));
    }
    let mut transcript = Vec::new();
    for row in records.iter() {
        transcript.push(u8::from(row.delivered));
        transcript.extend_from_slice(&row.request);
        transcript.extend_from_slice(&row.reply);
    }
    fixture::store(root, "account-witness-transcript", &transcript)?;
    fixture::store(root, "account-witness-stages", stages.as_bytes())?;
    let result = format!("{{\"schema_version\":1,\"language\":\"{}\",\"completed\":true,\"batch\":\"{batch}\",\"report\":\"{report}\",\"witness_exchanges\":{},\"lost_advances\":4,\"release_claim_eligible\":false}}\n", language()?, records.len());
    fixture::store(root, "account-witness-result.json", result.as_bytes())?;
    Ok(())
}
