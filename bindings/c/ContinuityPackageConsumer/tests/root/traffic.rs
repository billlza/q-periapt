// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real post-cutover C traffic, an unknown delivery, process loss and rekey.
use super::*;
#[path = "traffic/inbound.rs"]
mod inbound;
#[path = "traffic/setup.rs"]
mod inputs;

const STAGES: [&str; 5] = ["connect", "send-cut", "recover", "rekey", "after-rekey"];
struct Process {
    child: fixture::OwnedChild,
    stdout: PathBuf,
    stderr: PathBuf,
}
fn spawn(command: &mut Command, path: &Path, name: &str) -> Result<Process> {
    let stdout = path.join(format!("{name}.stdout"));
    let stderr = path.join(format!("{name}.stderr"));
    let file = |p: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p)
    };
    Ok(Process {
        child: fixture::OwnedChild(
            command
                .stdout(Stdio::from(file(&stdout)?))
                .stderr(Stdio::from(file(&stderr)?))
                .spawn()?,
        ),
        stdout,
        stderr,
    })
}
fn finish(process: &mut Process, code: i32) -> Result<String> {
    let status = fixture::wait(&mut process.child)?;
    let stderr = fs::read_to_string(&process.stderr)?;
    assert!(
        status.code() == Some(code) && stderr.is_empty(),
        "traffic {status}: {stderr}"
    );
    Ok(fs::read_to_string(&process.stdout)?)
}
fn server(
    case: &setup::Case,
    peer: &Path,
    logs: &Path,
    stage: &str,
    session: Option<[u8; 32]>,
) -> Result<(Process, String)> {
    let client = std::env::var_os("QPERIAPT_C_CLIENT").ok_or("installed C server required")?;
    let mut command = Command::new(client);
    command
        .args([
            "--witness",
            &case.witness.configured.address.to_string(),
            "--device-parent",
        ])
        .arg(&case.reference.responder)
        .arg("2");
    if let Some(id) = session {
        command.args(["--session", &fixture::hex(&id)]);
    }
    let mode = match stage {
        "connect" => "bootstrap",
        "send-cut" => "crash-after",
        "rekey" => "rekey",
        _ => "message",
    };
    command.arg("serve").arg(peer).arg(mode);
    if stage == "rekey" {
        command.arg(fixture::hex(&session.ok_or("rekey session")?));
    }
    let mut process = spawn(&mut command, logs, &format!("peer-{stage}"))?;
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let stdout = fs::read_to_string(&process.stdout)?;
        if let Some((line, _)) = stdout.split_once('\n') {
            let port: u16 = line
                .strip_prefix("listening:")
                .ok_or("root peer readiness")?
                .parse()?;
            assert_ne!(port, 0);
            return Ok((process, format!("127.0.0.1:{port}")));
        }
        if process.child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "root peer did not listen: {stdout}; {}",
                fs::read_to_string(&process.stderr)?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn cut_sender(process: &mut Process, public: &Path) -> Result<()> {
    let marker = public.join("cut-sender");
    let deadline = Instant::now() + Duration::from_secs(40);
    while !marker.exists() {
        if let Some(status) = process.child.0.try_wait()? {
            return Err(format!(
                "root sender exited before cut: {status}; {}",
                fs::read_to_string(&process.stderr)?
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err("root sender cut timeout".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        u64::from_be_bytes(fixture::array(public, "cut-sender")?),
        u64::from(process.child.0.id())
    );
    process.child.0.kill()?;
    assert_eq!(fixture::wait(&mut process.child)?.signal(), Some(9));
    assert!(fs::read(&process.stdout)?.is_empty() && fs::read(&process.stderr)?.is_empty());
    Ok(())
}
fn effect(
    peer: &Path,
    session: [u8; 32],
    message: [u8; 32],
    public: &Path,
    label: &str,
) -> Result<()> {
    let value = fixture::read(
        peer,
        &format!("application-{}", fixture::hex(&message)),
        128,
    )?;
    let mut expected = session.to_vec();
    expected.extend_from_slice(&message);
    expected.extend_from_slice(b"persisted before process exit");
    assert_eq!(value, expected);
    fixture::store(public, label, &value)?;
    Ok(())
}
pub(super) fn exercise(client: &Path, case: &setup::Case) -> Result<Vec<u32>> {
    let public = case.public.join("traffic");
    let logs = case.public.parent().ok_or("root parent")?.join("traffic");
    for path in [&public, &logs] {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let (left, right) = inputs::peers(case)?;
    let mut ids = Vec::new();
    for name in ["reject-peer", "authorize-peer"] {
        let mode = format!("traffic-{name}");
        let mut command = Command::new(client);
        command
            .arg(&mode)
            .arg(&case.public)
            .arg(&case.old.path)
            .arg(&case.target.path)
            .arg(&case.registry_path)
            .arg(case.witness.configured.address.to_string())
            .arg(&left)
            .arg("127.0.0.1:9");
        let mut process = spawn(&mut command, &logs, &format!("sender-{name}"))?;
        ids.push(process.child.0.id());
        assert_eq!(
            finish(&mut process, 0)?,
            format!("root-stage-pass:{mode}\n")
        );
        assert_eq!(
            u64::from_be_bytes(fixture::array(&case.public, &format!("process-{mode}"))?),
            u64::from(process.child.0.id())
        );
    }
    let mut session = None;
    for stage in STAGES {
        let (mut receiver, address) = server(case, &right, &logs, stage, session)?;
        ids.push(receiver.child.0.id());
        fixture::store(
            &public,
            &format!("peer-process-{stage}"),
            &u64::from(receiver.child.0.id()).to_be_bytes(),
        )?;
        let mode = format!("traffic-{stage}");
        let mut command = Command::new(client);
        command
            .arg(&mode)
            .arg(&case.public)
            .arg(&case.old.path)
            .arg(&case.target.path)
            .arg(&case.registry_path)
            .arg(case.witness.configured.address.to_string())
            .arg(&left)
            .arg(address);
        let mut sender = spawn(&mut command, &logs, &format!("sender-{stage}"))?;
        ids.push(sender.child.0.id());
        if stage == "send-cut" {
            cut_sender(&mut sender, &public)?;
        } else {
            assert_eq!(finish(&mut sender, 0)?, format!("root-stage-pass:{mode}\n"));
        }
        assert_eq!(
            u64::from_be_bytes(fixture::array(&case.public, &format!("process-{mode}"))?),
            u64::from(sender.child.0.id())
        );
        let output = finish(&mut receiver, if stage == "send-cut" { 77 } else { 0 })?;
        let rest = output.split_once('\n').ok_or("root peer readiness line")?.1;
        let sid = fixture::array(&public, "session")?;
        session = Some(sid);
        let message = if stage == "connect" {
            [0; 32]
        } else {
            fixture::array(
                &public,
                if stage == "after-rekey" {
                    "message-after"
                } else {
                    "message-before"
                },
            )?
        };
        match stage {
            "send-cut" => {
                assert!(rest.is_empty());
                effect(&right, sid, message, &public, "effect-before-recovery")?;
            }
            "rekey" => assert_eq!(rest, "server-rekey-1\n"),
            _ => {
                let (kind, calls, created) = match stage {
                    "connect" => (1, 0, 0),
                    "recover" => (2, 1, 0),
                    _ => (2, 1, 1),
                };
                assert_eq!(
                    rest,
                    format!(
                        "served:{kind}:0:{calls}:{created}\n{}\n{}\n",
                        fixture::hex(&sid),
                        fixture::hex(&message)
                    )
                );
                if stage != "connect" {
                    effect(&right, sid, message, &public, &format!("effect-{stage}"))?;
                }
            }
        }
    }
    assert_eq!(
        fs::read(public.join("effect-before-recovery"))?,
        fs::read(public.join("effect-recover"))?
    );
    let entries = fs::read_dir(&right)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("application-"))
            .count(),
        2
    );
    ids.extend(inbound::exercise(
        client, case, &left, &right, &public, &logs,
    )?);
    let marker = b"ROOT_C_TRAFFIC sender_processes=7 peer_processes=5 sender_sigkill=1 peer_exit_after_effect=77 unknown_peer_refused=201 independent_peer_association=1 original_message_recovered=true application_records=2 rekey_epoch=1\n";
    fixture::store(&public, "result", marker)?;
    print!("{}", std::str::from_utf8(marker)?);
    Ok(ids)
}
