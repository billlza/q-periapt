// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

#[path = "stage4/witness.rs"]
mod witness;
#[path = "stage4/worker.rs"]
mod worker;
use worker::ChildGuard;

const BROKER: &str = "stage4::broker_child";

fn anchor_client(path: &Path, control: &Path) -> Result<Option<p::AnchorClient>> {
    if !control.join("witness-id").exists() {
        return Ok(None);
    }
    let pin = p::AnchorPin::new(
        p::AnchorIdentity::from_trusted_state(array(control, "witness-id")?)?,
        p::PublicKey::decode(&fs::read(control.join("witness-public"))?)?,
    );
    let address = fs::read_to_string(control.join("witness-address"))?.parse()?;
    let signer = p::DeviceSigningKey::open(
        &path.join("signer.key"),
        &key(path)?,
        p::SigningKeyId::from_trusted_state(array(path, "signer-id")?)?,
    )?;
    let anchor = p::AnchorClient::new(
        pin,
        signer,
        Box::new(p::AnchorTcpTransport::new(address)),
        Duration::from_secs(4),
    )?;
    Ok(Some(anchor))
}

fn reopen_device(path: &Path, control: &Path) -> Result<Peer> {
    Peer::open_with_anchor(path, anchor_client(path, control)?, now()?)
}

#[test]
fn broker_child() -> Result<()> {
    let Some(control) = std::env::var_os("QPERIAPT_STAGE4_CONTROL") else {
        return Ok(());
    };
    let control = Path::new(&control);
    let path = PathBuf::from(std::env::var_os("QPERIAPT_STAGE4_DEVICE").ok_or("device")?);
    let session = array(control, "session")?;
    let offer = fs::read(control.join("offer"))?;
    let action = std::env::var("QPERIAPT_STAGE4_ACTION")?;
    // Local selection opens no device signing owner. Required Witness retains
    // the original purpose-7 client in this trusted journal process.
    if matches!(action.as_str(), "bind" | "select" | "select-unknown") {
        let policy_store = sdk(&path)?;
        let ctx = context(&path, &policy_store, now()?)?;
        let device = ctx.device(role(&path)?);
        let policy = ctx.current_policy()?;
        let wrapping = key(&path)?;
        let owner = p::DeviceInstallation::open(paths(&path)?, &wrapping, device, policy, now()?)?;
        let mut service = owner.activate(
            wrapping,
            device,
            policy,
            now()?,
            anchor_client(&path, control)?,
        )?;
        let journal = service.stores()?.0;
        let result = if action == "bind" {
            journal
                .stage4_bind(&ctx, session, &offer, now()?)
                .map(|_| Vec::new())
        } else {
            journal.stage4_select(&ctx, session, &offer, now()?, |peer, ctx, policy| {
                worker::encapsulate(&path, peer, ctx, policy)
            })
        };
        return record_return(control, &action, result);
    }
    let mut owner = reopen_device(&path, control)?;
    let a = owner.actor()?;
    if matches!(
        action.as_str(),
        "reject-unselected" | "reject-loser" | "reject-expired"
    ) {
        let proposed = if action == "reject-expired" {
            control.join("selected-body")
        } else {
            control.join("attempt-a/unsigned-body")
        };
        let time = if action == "reject-expired" {
            u64::MAX
        } else {
            now()?
        };
        let result = a.journal.stage4_sign_selected(
            a.context,
            session,
            &offer,
            &fs::read(proposed)?,
            a.signer,
            time,
        );
        match action.as_str() {
            "reject-unselected" => assert!(matches!(result, Err(p::DurableError::Suspended))),
            "reject-loser" => assert!(matches!(result, Err(p::DurableError::Conflict))),
            _ => assert!(matches!(
                result,
                Err(p::DurableError::Protocol(p::Error::Validity))
            )),
        }
        store(control, &format!("returned-{action}"), b"refused")?;
        return Ok(());
    }
    let result = match action.as_str() {
        "legacy" => a
            .journal
            .respond_rekey_offer(a.context, session, &offer, a.signer, now()?),
        "sign" | "sign-unknown" => a.journal.stage4_sign_selected(
            a.context,
            session,
            &offer,
            &fs::read(control.join("selected-body"))?,
            a.signer,
            now()?,
        ),
        _ => return Err("unknown broker command".into()),
    };
    record_return(control, &action, result)
}

fn record_return(
    control: &Path,
    action: &str,
    result: std::result::Result<Vec<u8>, p::DurableError>,
) -> Result<()> {
    if action.ends_with("-unknown") {
        match result {
            Err(p::DurableError::Anchor(e))
                if matches!(&*e, p::AnchorClientError::Transport(_)) => {}
            Err(e) => return Err(e.into()),
            Ok(_) => return Err("lost reply incorrectly returned success".into()),
        }
    } else {
        result?;
    }
    store(control, &format!("returned-{action}"), b"returned")?;
    Ok(())
}

fn run_broker(
    path: &Path,
    control: &Path,
    action: &str,
    hook: Option<(&str, &str, bool)>,
) -> Result<()> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(["--exact", BROKER, "--nocapture", "--test-threads=1"])
        .env("QPERIAPT_STAGE4_CONTROL", control)
        .env("QPERIAPT_STAGE4_PROVIDER", control.join("provider-bodies"))
        .env("QPERIAPT_STAGE4_DEVICE", path)
        .env("QPERIAPT_STAGE4_ACTION", action);
    let log_path = control.join(format!(
        "broker-{action}-{}.log",
        hook.map_or("return", |(_, s, _)| s)
    ));
    let log = fs::File::create_new(&log_path)?;
    cmd.stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    let mut cut_marker = None;
    if let Some((variable, name, stop)) = hook {
        let dir = control.join(name);
        create_private_directory(&dir)?;
        if variable == "QPERIAPT_STAGE4_INPUT_CUT" {
            for file in ["offer", "session"] {
                fs::copy(control.join(file), dir.join(file))?;
            }
        }
        if stop {
            store(&dir, "stop", b"cut")?;
        }
        cmd.env(variable, &dir);
        if stop {
            let name = match variable {
                "QPERIAPT_STAGE4_INPUT_CUT" => "input-cut",
                "QPERIAPT_STAGE4_PROPOSAL" => "unsigned-body",
                "QPERIAPT_STAGE4_SIGNED" => "signed-wire",
                _ => return Err("unrecognized cut".into()),
            };
            cut_marker = Some(dir.join(name));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut child = ChildGuard(cmd.spawn()?);
    if let Some(marker) = cut_marker {
        while !marker.is_file() {
            if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
                return Err(
                    format!("missing {action} cut: {}", fs::read_to_string(&log_path)?).into(),
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!control.join(format!("returned-{action}")).exists());
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
    } else {
        if !child.wait_bounded(deadline)?.success() {
            return Err(fs::read_to_string(&log_path)?.into());
        }
        assert!(control.join(format!("returned-{action}")).exists());
    }
    Ok(())
}

fn establish(i: &mut Peer, r: &mut Peer) -> Result<[u8; 32]> {
    let (a, b) = (i.actor()?, r.actor()?);
    let request = p::InitiationId::generate()?;
    let initial = a
        .journal
        .initiate(Arc::clone(a.context), request, a.signer, now()?)?;
    let reply =
        b.journal
            .respond_from_inventory(Arc::clone(b.context), &initial, b.signer, now()?)?;
    let done = a
        .journal
        .accept_reply(Arc::clone(a.context), request, &reply, now()?)?;
    let session = done.session_id();
    assert_eq!(
        b.journal.finish(
            Arc::clone(b.context),
            &initial,
            done.final_message(),
            now()?
        )?,
        session
    );
    assert_eq!(
        a.journal
            .activate_initiator_messages(Arc::clone(a.context), request, now()?)?,
        session
    );
    assert_eq!(
        b.journal
            .activate_responder_messages(Arc::clone(b.context), &initial, now()?)?,
        session
    );
    Ok(session)
}

fn select_saved(peer: &mut Peer, id: [u8; 32], offer: &[u8]) -> Result<Vec<u8>> {
    let a = peer.actor()?;
    Ok(a.journal
        .stage4_select(a.context, id, offer, now()?, |_, _, _| {
            Err(io::Error::other("KEM reran after durable body selection").into())
        })?)
}

fn traffic(sender: &mut Peer, receiver: &mut Peer, session: [u8; 32]) -> Result<()> {
    let (a, b) = (sender.actor()?, receiver.actor()?);
    for _ in 0..3 {
        let mut bytes = [0; 128];
        getrandom::fill(&mut bytes)?;
        let id = a.journal.next_message_id(a.context, session, now()?)?;
        let frame =
            a.journal
                .send_message(a.context, session, id, &bytes, b"application", now()?)?;
        let delivered =
            b.journal
                .receive_message(b.context, session, &frame, b"application", now()?)?;
        assert_eq!(delivered.message_id(), id);
        assert_eq!(delivered.as_bytes(), bytes);
        b.journal.consume_message(b.context, session, id, now()?)?;
        let ack = b
            .journal
            .message_acknowledgement(b.context, session, now()?)?;
        a.journal
            .accept_message_acknowledgement(a.context, session, &ack, now()?)?;
    }
    Ok(())
}

fn evidence(profile: &str, entries: &[(&str, &[u8])]) -> Result<()> {
    if let Some(out) = std::env::var_os("QPERIAPT_STAGE4_EVIDENCE") {
        let dir = Path::new(&out).join(profile);
        create_private_directory(&dir)?;
        for &(name, bytes) in entries {
            store(&dir, name, bytes)?;
        }
    }
    Ok(())
}

fn exercise(witnessed: bool, legacy: bool) -> Result<()> {
    let scratch = temporary_directory("stage4-recovery-study")?;
    let control = scratch.path().canonicalize()?;
    let witness = if witnessed {
        Some(witness::Server::start(&control)?)
    } else {
        None
    };
    if let Some(server) = &witness {
        let pin = server.configured.pin()?;
        store(&control, "witness-id", pin.identity().as_bytes())?;
        store(&control, "witness-public", &pin.public_key().encode())?;
        store(
            &control,
            "witness-address",
            server.configured.address.to_string().as_bytes(),
        )?;
    }
    let setup = setup_with_witness(witness.as_ref().map(|s| &s.configured))?;
    let mut i = reopen_device(&setup.initiator, &control)?;
    let mut r = reopen_device(&setup.responder, &control)?;
    let session = establish(&mut i, &mut r)?;
    let a = i.actor()?;
    let offer = a
        .journal
        .prepare_rekey_offer(a.context, session, a.signer, now()?)?;
    store(&control, "provider-bodies", b"")?;
    store(&control, "session", &session)?;
    store(&control, "offer", &offer)?;
    r.close();
    drop(r);
    run_broker(
        &setup.responder,
        &control,
        if legacy { "legacy" } else { "bind" },
        Some(("QPERIAPT_STAGE4_INPUT_CUT", "input", true)),
    )?;
    let snapshot = fs::read_to_string(control.join("input/input-cut"))?;
    let (tag, coins) = if legacy { (4, 245) } else { (10, 0) };
    assert_eq!(snapshot,format!("current_phase=0 pending_phase={tag} encapsulation_token_bytes={coins} exact_offer=true normalized_prior_equal=true wrong_key_rejected=true\n"));
    let mut r = reopen_device(&setup.responder, &control)?;
    let a = r.actor()?;
    let status = a.journal.rekey_response_status(a.context, session)?;
    let wire;
    let mut pre = Vec::new();
    let mut proof = String::new();
    if legacy {
        assert_eq!(status, p::RekeyResponseStatus::EncapsulationReserved);
        wire = a
            .journal
            .respond_rekey_offer(a.context, session, &offer, a.signer, now()?)?;
    } else {
        assert_eq!(status, p::RekeyResponseStatus::InputBound);
        assert!(matches!(
            a.journal.stage4_sign_selected(
                a.context,
                session,
                &offer,
                b"unselected",
                a.signer,
                now()?
            ),
            Err(p::DurableError::Suspended)
        ));
        r.close();
        drop(r);
        run_broker(
            &setup.responder,
            &control,
            "select",
            Some(("QPERIAPT_STAGE4_PROPOSAL", "attempt-a", true)),
        )?;
        let rejected = fs::read(control.join("attempt-a/unsigned-body"))?;
        let mut recovered = reopen_device(&setup.responder, &control)?;
        let a = recovered.actor()?;
        assert_eq!(
            a.journal.rekey_response_status(a.context, session)?,
            p::RekeyResponseStatus::InputBound
        );
        assert!(matches!(
            a.journal
                .stage4_sign_selected(a.context, session, &offer, &rejected, a.signer, now()?),
            Err(p::DurableError::Suspended)
        ));
        recovered.close();
        drop(recovered);
        run_broker(&setup.responder, &control, "reject-unselected", None)?;
        assert!(fs::read(control.join("provider-bodies"))?.is_empty());
        let loss = witness.as_ref().map(|s| s.arm());
        run_broker(
            &setup.responder,
            &control,
            if witnessed {
                "select-unknown"
            } else {
                "select"
            },
            Some(("QPERIAPT_STAGE4_PROPOSAL", "attempt-b", false)),
        )?;
        let expected = fs::read(control.join("attempt-b/unsigned-body"))?;
        assert_ne!(rejected, expected);
        r = reopen_device(&setup.responder, &control)?;
        if let (Some(server), Some(start)) = (&witness, loss) {
            proof.push_str(&witness::describe(5, server.check_reconciliation(start)?));
        }
        assert_eq!(select_saved(&mut r, session, &offer)?, expected);
        let a = r.actor()?;
        assert_eq!(
            a.journal.rekey_response_status(a.context, session)?,
            p::RekeyResponseStatus::SignatureReserved
        );
        assert!(matches!(
            a.journal
                .stage4_sign_selected(a.context, session, &offer, &rejected, a.signer, now()?),
            Err(p::DurableError::Conflict)
        ));
        store(&control, "selected-body", &expected)?;
        r.close();
        drop(r);
        run_broker(&setup.responder, &control, "reject-loser", None)?;
        run_broker(&setup.responder, &control, "reject-expired", None)?;
        assert!(fs::read(control.join("provider-bodies"))?.is_empty());
        run_broker(
            &setup.responder,
            &control,
            "sign",
            Some(("QPERIAPT_STAGE4_SIGNED", "before-ready", true)),
        )?;
        pre = fs::read(control.join("before-ready/signed-wire"))?;
        // A real peer verifies the copied signature and accepts the selected body
        // while the responder's original ready write has never started.
        let a = i.actor()?;
        let early_final =
            a.journal
                .accept_rekey_response(a.context, session, &pre, a.signer, now()?)?;
        r = reopen_device(&setup.responder, &control)?;
        let a = r.actor()?;
        assert_eq!(
            a.journal.rekey_response_status(a.context, session)?,
            p::RekeyResponseStatus::SignatureReserved
        );
        assert_eq!(select_saved(&mut r, session, &offer)?, expected);
        r.close();
        drop(r);
        let loss = witness.as_ref().map(|s| s.arm());
        run_broker(
            &setup.responder,
            &control,
            if witnessed { "sign-unknown" } else { "sign" },
            Some(("QPERIAPT_STAGE4_SIGNED", "replayed", false)),
        )?;
        assert_eq!(pre, fs::read(control.join("replayed/signed-wire"))?);
        r = reopen_device(&setup.responder, &control)?;
        if let (Some(server), Some(start)) = (&witness, loss) {
            proof.push_str(&witness::describe(6, server.check_reconciliation(start)?));
        }
        let a = r.actor()?;
        assert_eq!(
            a.journal.rekey_response_status(a.context, session)?,
            p::RekeyResponseStatus::Committed
        );
        wire = a.journal.stage4_sign_selected(
            a.context,
            session,
            &offer,
            &expected,
            a.signer,
            now()?,
        )?;
        assert_eq!(pre, wire);
        let frame = [
            &u32::try_from(expected.len())?.to_be_bytes()[..],
            expected.as_slice(),
        ]
        .concat();
        assert_eq!(
            fs::read(control.join("provider-bodies"))?,
            [frame.as_slice(), frame.as_slice()].concat()
        );

        let a = i.actor()?;
        assert_eq!(
            a.journal
                .accept_rekey_response(a.context, session, &wire, a.signer, now()?)?,
            early_final
        );
    }
    let a = i.actor()?;
    let b = r.actor()?;
    let final_wire =
        a.journal
            .accept_rekey_response(a.context, session, &wire, a.signer, now()?)?;
    let receipt = b
        .journal
        .finish_rekey(b.context, session, &final_wire, b.signer, now()?)?;
    assert_eq!(
        a.journal
            .accept_rekey_receipt(a.context, session, &receipt, now()?)?,
        1
    );
    assert_eq!(
        b.journal
            .rekey_progress(b.context, session)?
            .confirmed_epoch,
        1
    );
    i.close();
    r.close();
    drop((i, r));
    let mut i = reopen_device(&setup.initiator, &control)?;
    let mut r = reopen_device(&setup.responder, &control)?;
    if !legacy {
        let a = r.actor()?;
        let body = fs::read(control.join("selected-body"))?;
        assert_eq!(
            a.journal
                .stage4_sign_selected(a.context, session, &offer, &body, a.signer, now()?)?,
            wire
        );
    }
    traffic(&mut i, &mut r, session)?;
    traffic(&mut r, &mut i, session)?;
    let label = if legacy {
        "legacy-local"
    } else if witnessed {
        "candidate-witness"
    } else {
        "candidate-local"
    };
    let mut records = vec![
        ("input-cut.txt", snapshot.as_bytes()),
        ("recovered-response.bin", wire.as_slice()),
    ];
    let inputs;
    if !legacy {
        inputs = (
            fs::read(control.join("provider-bodies"))?,
            fs::read(control.join("attempt-a/unsigned-body"))?,
            fs::read(control.join("selected-body"))?,
        );
        records.extend([
            ("provider-bodies.bin", inputs.0.as_slice()),
            ("discarded-body.bin", inputs.1.as_slice()),
            ("selected-body.bin", inputs.2.as_slice()),
            ("before-ready.bin", pre.as_slice()),
        ]);
    }
    if witnessed {
        records.push(("witness.txt", proof.as_bytes()));
    }
    evidence(label, &records)?;
    println!("STAGE4 profile={label} pending_phase={tag} reservation_bytes={coins} signed_wire_bytes={} honest_deliveries=6 confirmed_epoch=1",wire.len());
    if let Some(w) = witness {
        w.stop()?;
    }
    Ok(())
}

#[test]
fn legacy_input_snapshot() -> Result<()> {
    exercise(false, true)
}
#[test]
fn local_selected_response_survives_process_cuts() -> Result<()> {
    exercise(false, false)
}
#[test]
fn witnessed_selected_response_survives_both_lost_advances() -> Result<()> {
    exercise(true, false)
}
