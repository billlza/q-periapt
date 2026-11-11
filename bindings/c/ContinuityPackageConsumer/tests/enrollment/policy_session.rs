// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One original session and message retained through policy-owner transitions.
use super::*;

pub(super) struct Traffic {
    peer: PathBuf,
    bundle: Vec<u8>,
    session: [u8; 32],
    message: [u8; 32],
    effect: PathBuf,
    original_effect: Option<fs::Metadata>,
}

impl Traffic {
    pub(super) fn connect(c: &Registered) -> Result<Self> {
        let peer = peer_bundle(&c._setup, &c.path, &c.root, &c.certificate, &c.roster)?;
        let bundle = fixture::read(&peer, "bootstrap.bundle", p::MAX_BOOTSTRAP_BUNDLE_BYTES)?;
        for name in POLICY_DOCUMENT_FILES {
            assert_eq!(
                fs::read(c._setup.responder.join(name))?,
                fs::read(c.path.join(name))?
            );
        }
        let (mut server, address) = fixture::spawn(&c._setup.responder, 81, "bootstrap")?;
        let initiation = p::InitiationId::generate()?;
        let session = decode_id(
            run(
                &c.path,
                "traffic-connect",
                &[
                    "--enrollment-parent".into(),
                    c.path.as_os_str().into(),
                    "1".into(),
                    "connect".into(),
                    peer.as_os_str().into(),
                    address.to_string().into(),
                    fixture::hex(initiation.as_bytes()).into(),
                ],
            )?
            .trim_end(),
        )?;
        assert!(fixture::wait(&mut server)?.success());
        assert_eq!(
            fixture::array::<32>(&c._setup.responder, "session")?,
            session
        );
        let message = decode_id(
            run(
                &c.path,
                "traffic-original-next",
                &[
                    "--enrollment-parent".into(),
                    c.path.as_os_str().into(),
                    "1".into(),
                    "--session".into(),
                    fixture::hex(&session).into(),
                    "next".into(),
                    peer.as_os_str().into(),
                    fixture::hex(&session).into(),
                ],
            )?
            .trim_end(),
        )?;
        let effect = c
            ._setup
            .responder
            .join(format!("application-{}", fixture::hex(&message)));
        Ok(Self {
            peer,
            bundle,
            session,
            message,
            effect,
            original_effect: None,
        })
    }

    fn arguments(
        &self,
        c: &Registered,
        continued: bool,
        operation: &str,
        tail: Vec<OsString>,
    ) -> Vec<OsString> {
        let mut values = vec![
            if continued {
                "--continued-enrollment-parent"
            } else {
                "--enrollment-parent"
            }
            .into(),
            c.path.as_os_str().into(),
            "1".into(),
            "--session".into(),
            fixture::hex(&self.session).into(),
            operation.into(),
            self.peer.as_os_str().into(),
        ];
        values.extend(tail);
        values
    }

    pub(super) fn committed(&self, c: &Registered, continued: bool, label: &str) -> Result<()> {
        assert_eq!(
            run(
                &c.path,
                label,
                &self.arguments(
                    c,
                    continued,
                    "status",
                    vec![
                        fixture::hex(&self.session).into(),
                        fixture::hex(&self.message).into(),
                    ]
                )
            )?,
            "2\n"
        );
        Ok(())
    }

    pub(super) fn lose_reply(&mut self, c: &Registered, continued: bool) -> Result<()> {
        assert!(self.original_effect.is_none(), "one original lost reply");
        let (mut server, address) =
            fixture::spawn(&c._setup.responder, 82, "crash-after-application")?;
        assert_eq!(
            run(
                &c.path,
                "traffic-uncertain-send",
                &self.arguments(
                    c,
                    continued,
                    "uncertain-send",
                    vec![
                        address.to_string().into(),
                        fixture::hex(&self.session).into(),
                        fixture::hex(&self.message).into(),
                    ]
                )
            )?,
            "delivery-unknown-committed\n"
        );
        assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
        fixture::effect(
            &c._setup.responder,
            self.session,
            p::MessageId::from_trusted_state(self.message)?,
            b"persisted before process exit",
        )?;
        self.committed(c, continued, "traffic-committed-message-reopen")?;
        self.original_effect = Some(fs::metadata(&self.effect)?);
        Ok(())
    }

    pub(super) fn finish(self, c: &Registered) -> Result<()> {
        let (mut server, address) = fixture::spawn(&c._setup.responder, 83, "application")?;
        assert_eq!(
            run(
                &c.path,
                "traffic-send",
                &self.arguments(
                    c,
                    true,
                    "send",
                    vec![
                        address.to_string().into(),
                        fixture::hex(&self.session).into(),
                        fixture::hex(&self.message).into(),
                    ]
                )
            )?,
            "consumed\n"
        );
        assert!(fixture::wait(&mut server)?.success());
        fixture::effect(
            &c._setup.responder,
            self.session,
            p::MessageId::from_trusted_state(self.message)?,
            b"persisted before process exit",
        )?;
        if let Some(original) = &self.original_effect {
            use std::os::unix::fs::MetadataExt;
            let recovered = fs::metadata(&self.effect)?;
            assert_eq!(original.dev(), recovered.dev());
            assert_eq!(original.ino(), recovered.ino());
            assert_eq!(original.len(), recovered.len());
            assert_eq!(original.mtime(), recovered.mtime());
            assert_eq!(original.mtime_nsec(), recovered.mtime_nsec());
        }
        assert_eq!(
            run(
                &c.path,
                "traffic-ack-reopen",
                &self.arguments(
                    c,
                    true,
                    "status",
                    vec![
                        fixture::hex(&self.session).into(),
                        fixture::hex(&self.message).into(),
                    ]
                )
            )?,
            "3\n"
        );
        let effects = fs::read_dir(&c._setup.responder)?
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
        assert_eq!(
            fixture::read(
                &self.peer,
                "bootstrap.bundle",
                p::MAX_BOOTSTRAP_BUNDLE_BYTES
            )?,
            self.bundle
        );
        assert_eq!(
            fixture::array::<32>(&c._setup.responder, "session")?,
            self.session
        );
        Ok(())
    }
}
