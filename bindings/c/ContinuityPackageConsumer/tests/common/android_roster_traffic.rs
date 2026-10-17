// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original traffic over a same-credential roster change, using installed C endpoints.
use crate::{
    android_credential_traffic, fixture, p, peer_bundle, receiver_policy, receiver_process, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    os::unix::fs::DirBuilderExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct Case<'a> {
    pub(crate) base: &'a Path,
    pub(crate) inputs: &'a Path,
    pub(crate) reference: &'a fixture::Setup,
    pub(crate) witness: Option<&'a fixture::WitnessFixture>,
}
impl Case<'_> {
    fn network_args(&self) -> Result<Vec<OsString>> {
        let carrier = fs::read_to_string(self.inputs.join("witness-carrier"))?;
        match carrier.as_str() {
            "local" if self.witness.is_none() => Ok(Vec::new()),
            "signed" | "tls" if self.witness.is_some() => Ok(vec![
                if carrier == "signed" {
                    "--witness"
                } else {
                    "--witness-tls"
                }
                .into(),
                fs::read_to_string(self.inputs.join("witness-address"))?.into(),
            ]),
            _ => Err("explicit roster traffic witness configuration".into()),
        }
    }
    pub(crate) fn mode(&self, action: &str) -> String {
        format!(
            "{}-{action}",
            if self.witness.is_some() {
                "roster-witness-peer"
            } else {
                "roster-peer"
            }
        )
    }
}
pub(crate) struct Traffic {
    session: [u8; 32],
    message: [u8; 32],
    effect: Vec<u8>,
}
fn start(
    case: &Case<'_>,
    mode: &str,
    session: Option<[u8; 32]>,
) -> Result<(receiver_process::Server, SocketAddr)> {
    let base = case.base;
    let receiver = case.reference.responder.as_path();
    let mut args = case.network_args()?;
    args.extend([
        "--enrollment-parent".into(),
        receiver.as_os_str().into(),
        "2".into(),
    ]);
    if let Some(session) = session {
        args.extend(["--session".into(), fixture::hex(&session).into()]);
    }
    args.extend(["serve".into(), receiver.as_os_str().into(), mode.into()]);
    receiver_process::start_selected(
        &android_credential_traffic::executable()?,
        None,
        base,
        &format!("roster-{mode}"),
        &args,
    )
}
impl Traffic {
    pub(crate) fn begin(
        case: &Case<'_>,
        root: &p::RootSigningKey,
        certificate: &[u8],
        roster: &p::IssuedRoster,
        run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let base = case.base;
        let inputs = case.inputs;
        let reference = case.reference;
        receiver_policy::prepare_receiver_metadata(reference)?;
        peer_bundle::peer_bundle_at(
            &reference.responder,
            &inputs.join("peer"),
            root,
            certificate,
            roster,
            case.witness,
        )?;
        if case.witness.is_some() {
            assert_eq!(
                run(&case.mode("unassociated"), "roster-peer-unassociated")?,
                201u32.to_be_bytes()
            );
            publish_private_bytes(&inputs.join("authority-peer-application"), &[134; 32])?;
            for (target, name) in [
                ("approved-certificate", "local-certificate"),
                ("approved-roster", "local-roster"),
            ] {
                publish_private_bytes(
                    &inputs.join("peer").join(target),
                    &fixture::read(&reference.responder, name, 65536)?,
                )?;
            }
            let associated = run("authority-peer-associate", "roster-peer-associated")?;
            assert_eq!(associated.len(), 72);
            assert_eq!(associated.get(..32).ok_or("peer application")?, [134; 32]);
            assert_eq!(
                associated.get(32..40).ok_or("peer revision")?,
                1u64.to_be_bytes()
            );
            assert_eq!(
                associated.get(40..).ok_or("peer account")?,
                fixture::array::<32>(&reference.responder, "local-account")?
            );
        }
        publish_private_bytes(
            &inputs.join("connection-initiation"),
            p::InitiationId::generate()?.as_bytes(),
        )?;
        let (server, address) = start(case, "bootstrap", None)?;
        publish_private_bytes(
            &inputs.join("connection-address"),
            address.to_string().as_bytes(),
        )?;
        let session: [u8; 32] = run(&case.mode("connect"), "roster-connected")?
            .try_into()
            .map_err(|_| "session width")?;
        android_credential_traffic::received(server, 0, Some((session, [0; 32])))?;
        publish_private_bytes(&inputs.join("connection-session"), &session)?;
        let (server, address) = start(case, "crash-after", Some(session))?;
        fs::write(inputs.join("connection-address"), address.to_string())?;
        let unknown = run(&case.mode("uncertain"), "roster-unknown")?;
        android_credential_traffic::received(server, 77, None)?;
        assert_eq!(unknown.len(), 64);
        assert_eq!(unknown.get(..32).ok_or("unknown session")?, session);
        let message: [u8; 32] = unknown.get(32..).ok_or("unknown message")?.try_into()?;
        publish_private_bytes(&inputs.join("connection-message"), &message)?;
        let effect = fs::read(
            reference
                .responder
                .join(format!("application-{}", fixture::hex(&message))),
        )?;
        assert_eq!(
            effect,
            [unknown.as_slice(), b"persisted before process exit"].concat()
        );
        publish_private_bytes(&base.join("roster-effect-before"), &effect)?;
        Ok(Self {
            session,
            message,
            effect,
        })
    }
    pub(crate) fn resume(
        self,
        case: &Case<'_>,
        root: &p::RootSigningKey,
        target: &p::IssuedRoster,
        run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let base = case.base;
        let inputs = case.inputs;
        let receiver = case.reference.responder.as_path();
        admit_peer(case, root, target, false)?;
        let (server, address) = start(case, "message", Some(self.session))?;
        fs::write(inputs.join("connection-address"), address.to_string())?;
        assert_eq!(
            run(&case.mode("retry"), "roster-acknowledged")?,
            [self.session.as_slice(), self.message.as_slice()].concat()
        );
        android_credential_traffic::received(server, 0, Some((self.session, self.message)))?;
        let after =
            fs::read(receiver.join(format!("application-{}", fixture::hex(&self.message))))?;
        assert_eq!(after, self.effect);
        fixture::effect(
            receiver,
            self.session,
            p::MessageId::from_trusted_state(self.message)?,
            b"persisted before process exit",
        )?;
        let count = fs::read_dir(receiver)?
            .collect::<std::io::Result<Vec<_>>>()?
            .iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("application-")
            })
            .count();
        assert_eq!(count, 1);
        publish_private_bytes(&base.join("roster-effect-after"), &after)?;
        Ok(())
    }
}

pub(crate) fn admit_peer(
    case: &Case<'_>,
    root: &p::RootSigningKey,
    target: &p::IssuedRoster,
    continued: bool,
) -> Result<()> {
    let base = case.base;
    let inputs = case.inputs;
    let receiver = case.reference.responder.as_path();
    let public = base.join("roster-peer-target");
    fs::DirBuilder::new().mode(0o700).create(&public)?;
    for (name, bytes) in [
        ("root", root.public_key()?.encode().to_vec()),
        ("account", root.account_id()?.to_vec()),
        ("family", fixture::array::<32>(inputs, "family")?.to_vec()),
        (
            "version",
            target.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("digest", target.checkpoint().digest().to_vec()),
        ("roster", target.as_bytes().to_vec()),
    ] {
        publish_private_bytes(&public.join(name), &bytes)?;
    }
    let stdout = base.join("roster-peer-admitted.stdout");
    let stderr = base.join("roster-peer-admitted.stderr");
    let mut child = fixture::OwnedChild(
        Command::new(android_credential_traffic::executable()?)
            .args(case.network_args()?)
            .arg(if continued {
                "--independent-policy-parent"
            } else {
                "--enrollment-parent"
            })
            .arg(receiver)
            .arg("2")
            .arg("peer-roster-admit")
            .arg(receiver)
            .arg(&public)
            .arg("admit")
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
            return Err("remote roster admission deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "receiver roster admission: {}",
        String::from_utf8_lossy(&fs::read(&stderr)?)
    );
    assert!(fs::read(stderr)?.is_empty());
    assert_eq!(fs::read(stdout)?, b"peer-roster-admitted\n");
    Ok(())
}
