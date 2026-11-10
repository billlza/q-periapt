// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original reverse message survives a receiver crash inside its host callback.
use super::*;

fn peer_command(
    case: &setup::Case,
    peer: &Path,
    session: [u8; 32],
    operation: &str,
) -> Result<Command> {
    let mut command =
        Command::new(std::env::var_os("QPERIAPT_C_CLIENT").ok_or("installed peer required")?);
    command
        .args([
            "--witness",
            &case.witness.configured.address.to_string(),
            "--device-parent",
        ])
        .arg(&case.reference.responder)
        .arg("2")
        .args(["--session", &fixture::hex(&session), operation])
        .arg(peer);
    Ok(command)
}
fn receiver(
    client: &Path,
    case: &setup::Case,
    peer: &Path,
    logs: &Path,
    stage: &str,
) -> Result<(Process, String)> {
    let mut command = Command::new(client);
    command
        .arg(case.command_mode(&format!("traffic-receive-{stage}")))
        .arg(&case.public)
        .arg(&case.old.path)
        .arg(&case.target.path)
        .arg(&case.registry_path)
        .arg(case.witness.configured.address.to_string())
        .arg(peer)
        .arg("127.0.0.1:9");
    let mut process = spawn(&mut command, logs, &format!("root-receive-{stage}"))?;
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let stdout = fs::read_to_string(&process.stdout)?;
        if let Some((line, _)) = stdout.split_once('\n') {
            let port: u16 = line
                .strip_prefix("root-listening:")
                .ok_or("root receive readiness")?
                .parse()?;
            assert_ne!(port, 0);
            return Ok((process, format!("127.0.0.1:{port}")));
        }
        if process.child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "root receiver did not listen: {stdout}; {}",
                fs::read_to_string(&process.stderr)?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn reply_id(output: &str) -> Result<[u8; 32]> {
    if output.len() != 65 || !output.ends_with('\n') {
        return Err("reply ID encoding".into());
    }
    let mut result = [0; 32];
    for (index, value) in result.iter_mut().enumerate() {
        let at = index * 2;
        *value = u8::from_str_radix(output.get(at..at + 2).ok_or("reply ID width")?, 16)?;
    }
    assert_eq!(output, format!("{}\n", fixture::hex(&result)));
    Ok(result)
}
pub(super) fn exercise(
    client: &Path,
    case: &setup::Case,
    left: &Path,
    right: &Path,
    public: &Path,
    logs: &Path,
) -> Result<Vec<u32>> {
    let session = fixture::array(public, "session")?;
    let mut ids = Vec::new();
    let mut next = peer_command(case, right, session, "next")?;
    next.arg(fixture::hex(&session));
    let mut next = spawn(&mut next, logs, "peer-reply-next")?;
    ids.push(next.child.0.id());
    fixture::store(
        public,
        "peer-process-reply-next",
        &u64::from(next.child.0.id()).to_be_bytes(),
    )?;
    let message = reply_id(&finish(&mut next, 0)?)?;
    assert_eq!(
        message.get(..16).ok_or("reply position")?,
        &[1u64.to_be_bytes(), [0; 8]].concat()
    );
    assert_ne!(message, fixture::array::<32>(public, "message-after")?);
    fixture::store(public, "reply-message", &message)?;
    for stage in ["cut", "recover"] {
        let (mut root, address) = receiver(client, case, left, logs, stage)?;
        ids.push(root.child.0.id());
        let mut send = peer_command(
            case,
            right,
            session,
            if stage == "cut" {
                "uncertain-send"
            } else {
                "send"
            },
        )?;
        send.arg(address)
            .arg(fixture::hex(&session))
            .arg(fixture::hex(&message));
        let mut send = spawn(&mut send, logs, &format!("peer-reply-{stage}"))?;
        ids.push(send.child.0.id());
        fixture::store(
            public,
            &format!("peer-process-reply-{stage}"),
            &u64::from(send.child.0.id()).to_be_bytes(),
        )?;
        if stage == "cut" {
            let deadline = Instant::now() + Duration::from_secs(25);
            while !public.join("cut-receiver").exists()
                || !case.cut_ready("receiver", &root.stdout)?
            {
                if root.child.0.try_wait()?.is_some() || Instant::now() >= deadline {
                    return Err(format!(
                        "root receive cut absent: {}",
                        fs::read_to_string(&root.stderr)?
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(
                u64::from_be_bytes(fixture::array(public, "cut-receiver")?),
                u64::from(root.child.0.id())
            );
            root.child.0.kill()?;
            require_forced_exit(fixture::wait(&mut root.child)?);
            assert!(fs::read(&root.stderr)?.is_empty());
            let stdout = fs::read_to_string(&root.stdout)?;
            assert_eq!(
                stdout.split_once('\n').ok_or("root cut readiness")?.1,
                case.cut_output("receiver")
            );
        } else {
            assert_eq!(
                finish(&mut root, 0)?
                    .split_once('\n')
                    .ok_or("root readiness")?
                    .1,
                "root-stage-pass:traffic-receive-recover\n"
            );
        }
        assert_eq!(
            u64::from_be_bytes(fixture::array(
                &case.public,
                &format!("process-traffic-receive-{stage}")
            )?),
            u64::from(root.child.0.id())
        );
        assert_eq!(
            finish(&mut send, 0)?,
            if stage == "cut" {
                "delivery-unknown-committed\n"
            } else {
                "consumed\n"
            }
        );
        effect(
            public,
            session,
            message,
            public,
            &format!("effect-reply-{stage}"),
        )?;
    }
    assert_eq!(
        fs::read(public.join("effect-reply-cut"))?,
        fs::read(public.join("effect-reply-recover"))?
    );
    let entries = fs::read_dir(public)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("application-"))
            .count(),
        1
    );
    let marker = cut_marker("ROOT_C_REVERSE processes=5 receiver_sigkill=1 original_reply_recovered=true application_records=1 epoch=1\n");
    fixture::store(public, "reverse-result", marker.as_bytes())?;
    print!("{marker}");
    Ok(ids)
}
