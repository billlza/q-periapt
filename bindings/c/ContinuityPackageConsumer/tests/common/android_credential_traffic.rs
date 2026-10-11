// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Keep the original session and uncertain application operation across renewal.
use crate::{android_credential::Renewal, fixture, p, peer_bundle, receiver_process, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
};

pub(crate) struct Traffic {
    session: [u8; 32],
    message: [u8; 32],
    effect: Vec<u8>,
}
pub(crate) fn executable() -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os("QPC_CONFIGURATION_RECEIVER").ok_or("explicit installed C receiver")?,
    );
    if !path.is_absolute() || !path.is_file() {
        return Err("installed C receiver path".into());
    }
    Ok(path)
}
pub(crate) fn witness_args(case: &Renewal<'_>) -> Result<Vec<OsString>> {
    Ok(vec![
        match case.carrier {
            "signed" => "--witness",
            "tls" => "--witness-tls",
            _ => return Err("credential traffic witness carrier".into()),
        }
        .into(),
        fs::read_to_string(case.inputs.join("witness-address"))?.into(),
    ])
}
fn start(
    case: &Renewal<'_>,
    mode: &str,
    session: Option<[u8; 32]>,
) -> Result<(receiver_process::Server, SocketAddr)> {
    start_labelled(case, mode, session, &format!("credential-{mode}"))
}
pub(crate) fn start_labelled(
    case: &Renewal<'_>,
    mode: &str,
    session: Option<[u8; 32]>,
    label: &str,
) -> Result<(receiver_process::Server, SocketAddr)> {
    let mut args = witness_args(case)?;
    args.extend([
        "--enrollment-parent".into(),
        case.receiver.as_os_str().into(),
        "2".into(),
    ]);
    if let Some(session) = session {
        args.extend(["--session".into(), fixture::hex(&session).into()]);
    }
    args.extend([
        "serve".into(),
        case.receiver.as_os_str().into(),
        mode.into(),
    ]);
    receiver_process::start_selected(&executable()?, None, case.base, label, &args)
}
pub(crate) fn received(
    server: receiver_process::Server,
    code: i32,
    event: Option<([u8; 32], [u8; 32])>,
) -> Result<()> {
    let output = receiver_process::finish(server, code)?;
    if let Some((session, message)) = event {
        let (kind, calls) = if message == [0; 32] { (1, 0) } else { (2, 1) };
        assert_eq!(
            output,
            format!(
                "served:{kind}:0:{calls}:0\n{}\n{}\n",
                fixture::hex(&session),
                fixture::hex(&message)
            )
        );
    } else {
        assert!(output.is_empty());
    }
    Ok(())
}
impl Traffic {
    pub(crate) fn begin(
        case: &Renewal<'_>,
        run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        crate::android_remote_credential::receiver_metadata(case)?;
        peer_bundle::peer_bundle_at(
            case.receiver,
            &case.inputs.join("peer"),
            case.root,
            case.certificate,
            case.roster,
            Some(&case.witness.configured),
        )?;
        assert_eq!(
            run(
                "credential-peer-unassociated",
                "credential-peer-unassociated"
            )?,
            201u32.to_be_bytes()
        );
        publish_private_bytes(&case.inputs.join("authority-peer-application"), &[134; 32])?;
        for (target, source) in [
            ("approved-certificate", "local-certificate"),
            ("approved-roster", "local-roster"),
        ] {
            publish_private_bytes(
                &case.inputs.join("peer").join(target),
                &fixture::read(case.receiver, source, 65536)?,
            )?;
        }
        let associated = run("authority-peer-associate", "credential-peer-associated")?;
        assert_eq!(associated.len(), 72);
        assert_eq!(associated.get(..32), Some([134; 32].as_slice()));
        assert_eq!(associated.get(32..40), Some(1u64.to_be_bytes().as_slice()));
        assert_eq!(
            associated.get(40..),
            Some(fixture::array::<32>(case.receiver, "local-account")?.as_slice())
        );
        let initiation = p::InitiationId::generate()?;
        publish_private_bytes(
            &case.inputs.join("connection-initiation"),
            initiation.as_bytes(),
        )?;
        let (server, address) = start(case, "bootstrap", None)?;
        publish_private_bytes(
            &case.inputs.join("connection-address"),
            address.to_string().as_bytes(),
        )?;
        let session: [u8; 32] = run("credential-peer-connect", "credential-connected")?
            .try_into()
            .map_err(|_| "original session width")?;
        received(server, 0, Some((session, [0; 32])))?;
        publish_private_bytes(&case.inputs.join("connection-session"), &session)?;
        let (server, address) = start(case, "crash-after", Some(session))?;
        fs::write(case.inputs.join("connection-address"), address.to_string())?;
        let uncertain = run("credential-peer-uncertain", "credential-uncertain")?;
        received(server, 77, None)?;
        assert_eq!(uncertain.len(), 64);
        assert_eq!(uncertain.get(..32), Some(session.as_slice()));
        let message: [u8; 32] = uncertain.get(32..).ok_or("original message")?.try_into()?;
        publish_private_bytes(&case.inputs.join("connection-message"), &message)?;
        let effect = fs::read(
            case.receiver
                .join(format!("application-{}", fixture::hex(&message))),
        )?;
        publish_private_bytes(&case.base.join("credential-effect-before"), &effect)?;
        Ok(Self {
            session,
            message,
            effect,
        })
    }
    pub(crate) fn resume(
        self,
        case: &Renewal<'_>,
        run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let mut command = Command::new(executable()?);
        command.args(witness_args(case)?);
        command
            .arg("credential-peer-admit")
            .arg(case.receiver)
            .arg(case.inputs);
        command.stdout(Stdio::from(fs::File::create(
            case.base.join("credential-peer-admit.stdout"),
        )?));
        command.stderr(Stdio::from(fs::File::create(
            case.base.join("credential-peer-admit.stderr"),
        )?));
        let mut child = fixture::OwnedChild(command.spawn()?);
        let status = fixture::wait(&mut child)?;
        let diagnostic = fs::read_to_string(case.base.join("credential-peer-admit.stderr"))?;
        assert!(
            status.success() && diagnostic.is_empty(),
            "peer renewal admission {status}: {diagnostic}"
        );
        assert_eq!(
            fs::read(case.base.join("credential-peer-admit.stdout"))?,
            b"credential-peer-admitted\n"
        );
        let (server, address) = start(case, "message", Some(self.session))?;
        fs::write(case.inputs.join("connection-address"), address.to_string())?;
        let acknowledged = run("credential-peer-retry", "credential-acknowledged")?;
        received(server, 0, Some((self.session, self.message)))?;
        assert_eq!(
            acknowledged,
            fs::read(case.base.join("credential-uncertain"))?
        );
        let effect = fs::read(
            case.receiver
                .join(format!("application-{}", fixture::hex(&self.message))),
        )?;
        assert_eq!(effect, self.effect);
        fixture::effect(
            case.receiver,
            self.session,
            p::MessageId::from_trusted_state(self.message)?,
            b"persisted before process exit",
        )?;
        let effects = fs::read_dir(case.receiver)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("application-")
            })
            .count();
        assert_eq!(effects, 1);
        publish_private_bytes(&case.base.join("credential-effect-after"), &effect)?;
        publish_private_bytes(
            &case.base.join("credential-effect-count"),
            &1u32.to_be_bytes(),
        )?;
        Ok(())
    }
}
