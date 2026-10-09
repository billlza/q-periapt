// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One original registration/session/message through first-use configuration.
use crate::{fixture, p, peer_bundle, receiver_process, run_carrier, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub(crate) struct Case<'a> {
    pub(crate) client: &'a Path,
    pub(crate) source: &'a Path,
    pub(crate) target: &'a Path,
    pub(crate) base: &'a Path,
    pub(crate) receiver: &'a Path,
    pub(crate) language: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) carrier: Option<&'static str>,
}
enum Receiver {
    Native(fixture::OwnedChild),
    Witnessed(receiver_process::Server),
}
impl Case<'_> {
    pub(crate) fn prepare(
        &self,
        root: &p::RootSigningKey,
        certificate: &[u8],
        roster: &p::IssuedRoster,
        witness: Option<&fixture::WitnessFixture>,
    ) -> Result<()> {
        peer_bundle::peer_bundle_at(
            self.receiver,
            &self.source.join("peer"),
            root,
            certificate,
            roster,
            witness,
        )?;
        Ok(())
    }
    fn sender(&self, mode: &str, output: &str) -> Result<()> {
        run_carrier(
            self.client,
            mode,
            self.profile,
            self.source,
            self.target,
            &self.base.join(output),
            self.carrier,
        )
    }
    fn start(
        &self,
        attempt: u8,
        mode: &str,
        session: Option<[u8; 32]>,
    ) -> Result<(Receiver, SocketAddr)> {
        let Some(carrier) = self.carrier else {
            let (child, address) = fixture::spawn(self.receiver, attempt, mode)?;
            return Ok((Receiver::Native(child), address));
        };
        let executable = PathBuf::from(
            std::env::var_os("QPC_CONFIGURATION_RECEIVER")
                .ok_or("explicit configuration receiver required")?,
        );
        if !executable.is_absolute() || !executable.is_file() {
            return Err("configuration receiver path".into());
        }
        let mut args: Vec<OsString> = vec![
            match carrier {
                "signed" => "--witness",
                "tls" => "--witness-tls",
                _ => return Err("receiver witness carrier".into()),
            }
            .into(),
            fs::read_to_string(self.source.join("witness-address"))?.into(),
        ];
        if let Some(session) = session {
            args.extend(["--session".into(), fixture::hex(&session).into()]);
        }
        let mode = match mode {
            "bootstrap" => "bootstrap",
            "crash-after-application" => "crash-after",
            "application" => "message",
            _ => return Err("receiver mode".into()),
        };
        args.extend([
            "serve".into(),
            self.receiver.as_os_str().into(),
            mode.into(),
        ]);
        let (child, address) = receiver_process::start_selected(
            &executable,
            None,
            self.base,
            &format!("configuration-{attempt}"),
            &args,
        )?;
        Ok((Receiver::Witnessed(child), address))
    }
    fn finish(
        &self,
        receiver: Receiver,
        code: i32,
        event: Option<([u8; 32], [u8; 32])>,
    ) -> Result<()> {
        match receiver {
            Receiver::Native(mut child) => {
                assert_eq!(fixture::wait(&mut child)?.code(), Some(code));
                if let Some((session, message)) = event {
                    if message == [0; 32] {
                        assert_eq!(fixture::array::<32>(self.receiver, "session")?, session);
                    }
                }
            }
            Receiver::Witnessed(child) => {
                let output = receiver_process::finish(child, code)?;
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
            }
        }
        Ok(())
    }
    pub(crate) fn run_with_policy(
        &self,
        original: &[u8],
        renew: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let initiation = p::InitiationId::generate()?;
        publish_private_bytes(
            &self.source.join("connection-initiation"),
            initiation.as_bytes(),
        )?;
        let (server, address) = self.start(81, "bootstrap", None)?;
        publish_private_bytes(
            &self.source.join("connection-address"),
            address.to_string().as_bytes(),
        )?;
        self.sender("connect", "connected")?;
        let session: [u8; 32] = fs::read(self.base.join("connected"))?
            .try_into()
            .map_err(|_| "session width")?;
        self.finish(server, 0, Some((session, [0; 32])))?;
        publish_private_bytes(&self.source.join("connection-session"), &session)?;
        let (server, address) = self.start(82, "crash-after-application", Some(session))?;
        fs::write(self.source.join("connection-address"), address.to_string())?;
        self.sender("uncertain-send", "uncertain")?;
        self.finish(server, 77, None)?;
        let uncertain = fs::read(self.base.join("uncertain"))?;
        assert_eq!(uncertain.len(), 64);
        assert_eq!(uncertain.get(..32).ok_or("session prefix")?, &session);
        let message: [u8; 32] = uncertain.get(32..).ok_or("message suffix")?.try_into()?;
        publish_private_bytes(&self.source.join("connection-message"), &message)?;
        let effect_path = self
            .receiver
            .join(format!("application-{}", fixture::hex(&message)));
        let effect = fs::read(&effect_path)?;
        publish_private_bytes(&self.base.join("effect-public"), &effect)?;
        renew()?;
        let (server, address) = self.start(83, "application", Some(session))?;
        fs::write(self.source.join("connection-address"), address.to_string())?;
        self.sender("retry-policy", "acknowledged")?;
        self.finish(server, 0, Some((session, message)))?;
        assert_eq!(fs::read(self.base.join("acknowledged"))?, uncertain);
        assert_eq!(fs::read(&effect_path)?, effect);
        fixture::effect(
            self.receiver,
            session,
            p::MessageId::from_trusted_state(message)?,
            b"persisted before process exit",
        )?;
        let effects = fs::read_dir(self.receiver)?
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
        self.sender("resume", "after-traffic.request")?;
        assert_eq!(fs::read(self.base.join("after-traffic.request"))?, original);
        println!("\nINDEPENDENT_CONFIGURATION_POLICY_RENEWAL_PASS language={} carrier={} profile={} original_session=true original_message=true uncertain_before_update=true acknowledged=true effects=1", self.language, self.carrier.unwrap_or("local"), self.profile);
        println!("\nINDEPENDENT_CONFIGURATION_CONNECTION_PASS language={} carrier={} profile={} fresh_installation=true original_registration=true explicit_peer=true original_session=true original_message=true receiver_exit_after_effect=true acknowledged=true effects=1",self.language,self.carrier.unwrap_or("local"),self.profile);
        Ok(())
    }
}
