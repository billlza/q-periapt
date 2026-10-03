// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete foreign delivery under the original required TLS witness after receiver exit.
use super::*;
use std::sync::Arc;
use tls::encrypted;

#[test]
fn account_delivery_reconciles_original_members_with_tls_witness() -> Result<()> {
    execute(false)
}

#[test]
fn own_account_delivery_reconciles_original_members_with_tls_witness() -> Result<()> {
    execute(true)
}

fn execute(same_account: bool) -> Result<()> {
    let mut plain = witness::Witness::start()?;
    let (setup, second) =
        fixture::setup_devices(Some(&plain.configured), None, None, true, same_account)?;
    let second = second.ok_or("second account recipient")?;
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
    let account = fixture::array::<32>(&setup.responder, "local-account")?;
    assert_eq!(account, fixture::array::<32>(&second, "local-account")?);
    assert_eq!(
        account == fixture::array::<32>(root, "local-account")?,
        same_account
    );
    let batch = encrypted(&plain, &tls, &mut phases, "batch", true, || {
        run(root, "delivery-next", "account-next", &[], Some(endpoint))
    })?;
    let batch = batch.strip_suffix('\n').ok_or("delivery batch framing")?;
    common::bytes_id(batch)?;
    let send = |index: usize, address: SocketAddr, mode: &str| -> Result<Vec<OsString>> {
        Ok(vec![
            root.join("peer-0").into_os_string(),
            fixture::hex(sessions.first().ok_or("first session")?).into(),
            root.join("peer-1").into_os_string(),
            fixture::hex(sessions.get(1).ok_or("second session")?).into(),
            fixture::hex(&account).into(),
            batch.into(),
            index.to_string().into(),
            address.to_string().into(),
            mode.into(),
        ])
    };
    let refused_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    refused_listener.set_nonblocking(true)?;
    encrypted(&plain, &tls, &mut phases, "refusal", true, || {
        assert_eq!(
            run(
                root,
                "delivery-omit",
                "account-send",
                &send(0, refused_listener.local_addr()?, "omit")?,
                Some(endpoint)
            )?,
            "account-refused:106\n"
        );
        assert_eq!(
            run(
                root,
                "delivery-absent",
                "account-status",
                &[batch.into()],
                Some(endpoint)
            )?,
            format!("account-status:0\n{}\n", "0".repeat(64))
        );
        assert_eq!(
            run(
                root,
                "delivery-still-next",
                "account-next",
                &[],
                Some(endpoint)
            )?,
            format!("{batch}\n")
        );
        match refused_listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("incomplete account reached the application listener".into()),
        }
        fixture::store(root, "account-delivery-refusal-network", b"not-connected\n")?;
        Ok(())
    })?;
    drop(refused_listener);
    let (output, crashed, exit) = encrypted(&plain, &tls, &mut phases, "unknown", true, || {
        let (receiver, address) =
            server(&setup.responder, "delivery-crash", "crash-after", endpoint)?;
        let output = run(
            root,
            "delivery-unknown",
            "account-send",
            &send(0, address, "unknown")?,
            Some(endpoint),
        )?;
        let (crashed, exit) = receiver.finish_with_exit(77)?;
        Ok((output, crashed, exit))
    })?;
    assert_eq!(output, "account-refused:311\n");
    assert_eq!(crashed.lines().count(), 1);
    fixture::store(root, "account-delivery-crash-exit", &exit.to_be_bytes())?;
    let original = fs::read_dir(&setup.responder)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("application-")
        })
        .collect::<Vec<_>>();
    assert_eq!(original.len(), 1);
    let leaf = original
        .first()
        .ok_or("receiver application record")?
        .file_name();
    let name = leaf.to_str().ok_or("application name")?;
    let message = common::bytes_id(
        name.strip_prefix("application-")
            .ok_or("application prefix")?,
    )?;
    fixture::effect(
        &setup.responder,
        *sessions.first().ok_or("original session")?,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    // Retain the actual first application bytes before any receiver restart.
    fixture::store(root, "account-delivery-original-message", &message)?;
    fixture::store(
        root,
        "account-delivery-original-application",
        &fixture::read(&setup.responder, name, 65536)?,
    )?;
    let state = encrypted(&plain, &tls, &mut phases, "status", true, || {
        run(
            root,
            "delivery-unknown-status",
            "account-status",
            &[batch.into()],
            Some(endpoint),
        )
    })?;
    assert_eq!(state, format!("account-status:2\n{}\n", "0".repeat(64)));
    for (index, path) in [setup.responder.as_path(), second.as_path()]
        .into_iter()
        .enumerate()
    {
        let (output, received) = encrypted(
            &plain,
            &tls,
            &mut phases,
            &format!("delivery{index}"),
            true,
            || {
                let (receiver, address) = server(path, "delivery-retry", "message", endpoint)?;
                let output = run(
                    root,
                    &format!("delivery-member-{index}"),
                    "account-send",
                    &send(index, address, "deliver")?,
                    Some(endpoint),
                )?;
                Ok((output, receiver.finish()?))
            },
        )?;
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines.first(), Some(&"account-delivered:1:1"));
        let session = common::bytes_id(lines.get(1).ok_or("delivered session")?)?;
        let delivered = common::bytes_id(lines.get(2).ok_or("delivered message")?)?;
        assert_eq!(Some(&session), sessions.get(index));
        assert_eq!(
            *lines.get(3).ok_or("delivered device")?,
            fixture::hex(&fixture::array::<16>(path, "local-device")?)
        );
        if index == 0 {
            assert_eq!(message, delivered);
        }
        let received = received.lines().collect::<Vec<_>>();
        assert_eq!(received.len(), 4);
        // Application persistence preceded exit, but native consumption did not.
        // Pending delivery repeats the idempotent callback, then returns duplicate=false.
        assert_eq!(
            received.get(1),
            Some(&if index == 0 {
                "served:2:0:1:0"
            } else {
                "served:2:0:1:1"
            })
        );
        assert_eq!(
            *received.get(2).ok_or("receiver session")?,
            fixture::hex(&session)
        );
        assert_eq!(
            *received.get(3).ok_or("receiver message")?,
            fixture::hex(&delivered)
        );
        fixture::effect(
            path,
            session,
            p::MessageId::from_trusted_state(delivered)?,
            b"persisted before process exit",
        )?;
        let retained = encrypted(
            &plain,
            &tls,
            &mut phases,
            &format!("retained{index}"),
            true,
            || {
                run(
                    root,
                    &format!("delivery-retained-{index}"),
                    "account-send",
                    &send(index, SocketAddr::from(([127, 0, 0, 1], 9)), "retained")?,
                    Some(endpoint),
                )
            },
        )?;
        assert_eq!(
            retained,
            output.replacen("account-delivered:1:1", "account-delivered:1:0", 1)
        );
    }
    assert!(tls.finish()?.is_empty());
    plain.join()?;
    retain_tls_authorities(&setup, &second)?;
    retain_account_identities(&setup, &second)?;
    fixture::store(root, "account-delivery-phases", phases.as_bytes())?;
    let admissions = tls.admitted.load(Ordering::Acquire);
    let layout = if same_account { "own" } else { "peer" };
    let result = format!("{{\"schema_version\":2,\"language\":\"{}\",\"account_layout\":\"{layout}\",\"completed\":true,\"carrier\":\"q-periapt-anchor/1\",\"witness_admissions\":{admissions},\"batch\":\"{batch}\",\"release_claim_eligible\":false}}\n", language()?);
    fixture::store(root, "account-delivery-result.json", result.as_bytes())?;
    Ok(())
}
