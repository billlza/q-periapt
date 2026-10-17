// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{android_credential_traffic, peer_bundle, receiver_policy, receiver_process};
use std::{
    ffi::OsString,
    net::SocketAddr,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(super) struct Traffic {
    session: [u8; 32],
    message: [u8; 32],
    effect: Vec<u8>,
}
fn start(
    case: &Case<'_>,
    mode: &str,
    session: Option<[u8; 32]>,
    renewed: bool,
) -> Result<(receiver_process::Server, SocketAddr)> {
    start_named(case, mode, session, renewed, mode)
}
fn start_named(
    case: &Case<'_>,
    mode: &str,
    session: Option<[u8; 32]>,
    renewed: bool,
    label: &str,
) -> Result<(receiver_process::Server, SocketAddr)> {
    let mut args: Vec<OsString> = Vec::new();
    if case.carrier != "local" {
        args.extend([
            if case.carrier == "signed" {
                "--witness"
            } else {
                "--witness-tls"
            }
            .into(),
            fs::read_to_string(case.inputs.join("witness-address"))?.into(),
        ]);
    }
    args.extend([
        if renewed {
            "--independent-policy-parent"
        } else {
            "--enrollment-parent"
        }
        .into(),
        case.reference.responder.as_os_str().into(),
        "2".into(),
    ]);
    if let Some(session) = session {
        args.extend(["--session".into(), fixture::hex(&session).into()]);
    }
    args.extend([
        "serve".into(),
        case.reference.responder.as_os_str().into(),
        mode.into(),
    ]);
    if mode == "rekey" {
        // --session selects the reopened owner; serve rekey separately takes
        // the exact session whose rekey request the listener must accept.
        args.push(fixture::hex(&session.ok_or("rekey receiver session")?).into());
    }
    receiver_process::start_selected(
        &android_credential_traffic::executable()?,
        None,
        case.base,
        &format!("{}policy-{label}", case.namespace),
        &args,
    )
}
fn create_receiver_target(inputs: &Path, target: &Path, output: &Path) -> Result<()> {
    let client = PathBuf::from(
        std::env::var_os("QPC_CONFIGURATION_TARGET_CLIENT")
            .ok_or("installed target configuration client")?,
    );
    if !client.is_absolute() || !client.is_file() {
        return Err("target configuration executable".into());
    }
    let stdout = output.with_extension("stdout");
    let stderr = output.with_extension("stderr");
    let mut child = fixture::OwnedChild(
        Command::new(client)
            .args(["policy-target-create", "fixed"])
            .arg(inputs)
            .arg(target)
            .arg(output)
            .stdin(Stdio::null())
            .stdout(Stdio::from(fs::File::create(&stdout)?))
            .stderr(Stdio::from(fs::File::create(&stderr)?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err("receiver target creation deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "receiver target failed: {}",
        String::from_utf8_lossy(&fs::read(&stderr)?)
    );
    assert!(fs::read(stderr)?.is_empty());
    assert_eq!(fs::read(stdout)?, b"QPC_CONFIGURATION_POLICY_TARGET\n");
    Ok(())
}
impl Traffic {
    pub(super) fn retained(case: &Case<'_>) -> Result<Self> {
        let session = fixture::array(case.inputs, "connection-session")?;
        let message = fixture::array(case.inputs, "connection-message")?;
        let effect = fs::read(case.base.join("roster-effect-before"))?;
        assert_eq!(
            effect,
            [
                session.as_slice(),
                message.as_slice(),
                b"persisted before process exit"
            ]
            .concat()
        );
        assert_eq!(
            effect,
            fs::read(
                case.reference
                    .responder
                    .join(format!("application-{}", fixture::hex(&message)))
            )?
        );
        Ok(Self {
            session,
            message,
            effect,
        })
    }
    pub(super) fn begin(case: &Case<'_>) -> Result<Self> {
        receiver_policy::prepare_receiver_metadata(case.reference)?;
        peer_bundle::peer_bundle_at(
            &case.reference.responder,
            &case.inputs.join("peer"),
            case.root,
            case.certificate,
            case.roster,
            case.witness.map(|w| &w.configured),
        )?;
        if case.witness.is_some() {
            assert_eq!(
                case.run("policy-peer-unassociated", "policy-peer-unassociated")?,
                201u32.to_be_bytes()
            );
            publish_private_bytes(&case.inputs.join("authority-peer-application"), &[134; 32])?;
            for (target, source) in [
                ("approved-certificate", "local-certificate"),
                ("approved-roster", "local-roster"),
            ] {
                publish_private_bytes(
                    &case.inputs.join("peer").join(target),
                    &fixture::read(&case.reference.responder, source, 65536)?,
                )?;
            }
            let associated = case.run("authority-peer-associate", "policy-peer-associated")?;
            assert_eq!(associated.len(), 72);
            assert_eq!(
                associated
                    .get(..32)
                    .ok_or("association application width")?,
                &[134; 32]
            );
            assert_eq!(
                associated
                    .get(32..40)
                    .ok_or("association generation width")?,
                &1u64.to_be_bytes()
            );
            assert_eq!(
                associated.get(40..).ok_or("association account width")?,
                &fixture::array::<32>(&case.reference.responder, "local-account")?
            );
        }
        publish_private_bytes(
            &case.inputs.join("connection-initiation"),
            p::InitiationId::generate()?.as_bytes(),
        )?;
        let (server, address) = start(case, "bootstrap", None, false)?;
        publish_private_bytes(
            &case.inputs.join("connection-address"),
            address.to_string().as_bytes(),
        )?;
        let session: [u8; 32] = case
            .run("policy-peer-connect", "policy-connected")?
            .try_into()
            .map_err(|_| "session width")?;
        android_credential_traffic::received(server, 0, Some((session, [0; 32])))?;
        publish_private_bytes(&case.inputs.join("connection-session"), &session)?;
        let (server, address) = start(case, "crash-after", Some(session), false)?;
        fs::write(case.inputs.join("connection-address"), address.to_string())?;
        let unknown = case.run("policy-peer-uncertain", "policy-message-unknown")?;
        android_credential_traffic::received(server, 77, None)?;
        assert_eq!(unknown.len(), 64);
        assert_eq!(unknown.get(..32).ok_or("unknown session width")?, &session);
        let message: [u8; 32] = unknown
            .get(32..)
            .ok_or("unknown message width")?
            .try_into()?;
        publish_private_bytes(&case.inputs.join("connection-message"), &message)?;
        let effect = fs::read(
            case.reference
                .responder
                .join(format!("application-{}", fixture::hex(&message))),
        )?;
        assert_eq!(
            effect,
            [unknown.as_slice(), b"persisted before process exit"].concat()
        );
        publish_private_bytes(&case.base.join("policy-effect-before"), &effect)?;
        Ok(Self {
            session,
            message,
            effect,
        })
    }
    pub(super) fn renew_receiver(&self, case: &Case<'_>) -> Result<()> {
        receiver_policy::renew_receiver_before_expiry(
            &receiver_policy::ReceiverPolicy {
                source: case.inputs,
                receiver: &case.reference.responder,
                base: case.base,
                carrier: if case.carrier == "local" {
                    None
                } else {
                    Some(case.carrier)
                },
            },
            case.reference,
            case.witness.map(|w| &w.configured),
            &create_receiver_target,
        )
    }
    pub(super) fn resume(&self, case: &Case<'_>) -> Result<()> {
        self.resume_with(case, "policy-peer-retry")
    }
    pub(super) fn resume_with(&self, case: &Case<'_>, operation: &str) -> Result<()> {
        let (server, address) = start(case, "message", Some(self.session), true)?;
        fs::write(case.inputs.join("connection-address"), address.to_string())?;
        assert_eq!(
            case.run(operation, "policy-message-acknowledged")?,
            [self.session.as_slice(), self.message.as_slice()].concat()
        );
        android_credential_traffic::received(server, 0, Some((self.session, self.message)))?;
        let effect = fs::read(
            case.reference
                .responder
                .join(format!("application-{}", fixture::hex(&self.message))),
        )?;
        assert_eq!(effect, self.effect);
        fixture::effect(
            &case.reference.responder,
            self.session,
            p::MessageId::from_trusted_state(self.message)?,
            b"persisted before process exit",
        )?;
        let count = fs::read_dir(&case.reference.responder)?
            .collect::<std::io::Result<Vec<_>>>()?
            .iter()
            .filter(|e| e.file_name().to_string_lossy().starts_with("application-"))
            .count();
        assert_eq!(count, 1);
        publish_private_bytes(&case.output("policy-effect-after"), &effect)?;
        Ok(())
    }
    pub(super) fn rekey_and_send(&self, case: &Case<'_>) -> Result<()> {
        let (server, address) = start(case, "rekey", Some(self.session), true)?;
        fs::write(case.inputs.join("connection-address"), address.to_string())?;
        assert_eq!(case.run("policy-peer-rekey", "policy-rekeyed")?, [1]);
        assert_eq!(receiver_process::finish(server, 0)?, "server-rekey-1\n");
        let (server, address) = start_named(
            case,
            "fresh-message",
            Some(self.session),
            true,
            "fresh-message",
        )?;
        fs::write(case.inputs.join("connection-address"), address.to_string())?;
        let sent = case.run("policy-peer-send", "policy-fresh-message")?;
        assert_eq!(sent.len(), 64);
        assert_eq!(sent.get(..32), Some(self.session.as_slice()));
        let message: [u8; 32] = sent.get(32..).ok_or("fresh message")?.try_into()?;
        assert_ne!(message, self.message);
        android_credential_traffic::received_new(server, self.session, message)?;
        let effect = fs::read(
            case.reference
                .responder
                .join(format!("application-{}", fixture::hex(&message))),
        )?;
        assert_eq!(
            effect,
            [sent.as_slice(), b"continued after pending recovery"].concat()
        );
        assert_eq!(
            fs::read(
                case.reference
                    .responder
                    .join(format!("application-{}", fixture::hex(&self.message)))
            )?,
            self.effect
        );
        let count = fs::read_dir(&case.reference.responder)?
            .collect::<std::io::Result<Vec<_>>>()?
            .iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("application-")
            })
            .count();
        assert_eq!(count, 2);
        publish_private_bytes(&case.output("policy-fresh-effect"), &effect)?;
        publish_private_bytes(&case.output("policy-effect-count"), &2_u32.to_be_bytes())?;
        Ok(())
    }
}
