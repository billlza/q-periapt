// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original C application session across required independent P/R and receiver exit.
use super::*;
#[path = "witness_roster_fanout.rs"]
mod fanout;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;

use crate::receiver_process::{finish, start_selected, Server};

fn start(path: &Path, label: &str, args: &[OsString]) -> Result<(Server, SocketAddr)> {
    start_selected(&executable()?, None, path, label, args)
}

fn event(session: [u8; 32], message: [u8; 32], calls: u8, created: u8) -> String {
    format!(
        "served:{}:0:{calls}:{created}\n{}\n{}\n",
        if message == [0; 32] { 1 } else { 2 },
        hex(&session),
        hex(&message)
    )
}
fn client_args(
    c: &Registered,
    peer: &Path,
    renewed: bool,
    session: Option<[u8; 32]>,
    mode: &str,
    tail: &[String],
) -> Vec<OsString> {
    let mut args = vec![
        if renewed {
            "--independent-policy-parent"
        } else {
            "--enrollment-parent"
        }
        .into(),
        c.path.as_os_str().into(),
        "1".into(),
    ];
    if let Some(session) = session {
        args.extend(["--session".into(), hex(&session).into()]);
    }
    args.extend([mode.into(), peer.as_os_str().into()]);
    args.extend(tail.iter().map(OsString::from));
    c.arguments(args)
}
fn peer_args(
    c: &Registered,
    session: Option<[u8; 32]>,
    mode: &str,
    tail: &[String],
) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(session) = session {
        args.extend(["--session".into(), hex(&session).into()]);
    }
    args.extend([mode.into(), c._setup.responder.as_os_str().into()]);
    args.extend(tail.iter().map(OsString::from));
    c.arguments(args)
}
fn effect_identity(path: &Path) -> Result<(u64, u64, u64, i64, i64)> {
    let m = fs::metadata(path)?;
    Ok((m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
}
fn message_status(
    c: &Registered,
    peer: &Path,
    label: &str,
    renewed: bool,
    session: [u8; 32],
    message: [u8; 32],
    expected: u8,
) -> Result<()> {
    assert_eq!(
        run(
            &c.path,
            label,
            &client_args(
                c,
                peer,
                renewed,
                Some(session),
                "status",
                &[hex(&session), hex(&message)]
            )
        )?,
        format!("{expected}\n")
    );
    Ok(())
}

#[test]
fn c_required_policy_roster_preserves_unknown_delivery_then_rekeys_original_tls_session(
) -> Result<()> {
    for tls in [false, true] {
        let mut w = witness::Witness::start()?;
        let mut c = registered_with_anchor_inputs(
            600,
            None,
            300,
            None,
            p::BootstrapRole::Initiator,
            Some(&w.configured),
        )?;
        let policy_root = c
            ._setup
            .policy_issuer
            .take()
            .ok_or("original policy issuer")?;
        let peer = peer_bundle_with_witness(
            &c._setup,
            &c.path,
            &c.root,
            &c.certificate,
            &c.roster,
            Some(&w.configured),
        )?;
        let original_bundle = fs::read(peer.join("bootstrap.bundle"))?;
        let original_signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
        let original_wrap = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
        let mut encrypted = if tls {
            Some(witness_tls::TlsWitness::start(
                Arc::clone(&w.configured.store),
                [&c.path, &c._setup.responder],
            )?)
        } else {
            None
        };
        if let Some(server) = &encrypted {
            c.witness.as_mut().ok_or("configured witness")?.address = server.address;
            c.witness_tls = true;
        }
        let (server, address) = start(
            &c._setup.responder,
            "bootstrap",
            &peer_args(&c, None, "serve", &["bootstrap".into()]),
        )?;
        let initiation = p::InitiationId::generate()?;
        let session = decode_id(
            run(
                &c.path,
                "traffic-bootstrap",
                &client_args(
                    &c,
                    &peer,
                    false,
                    None,
                    "connect",
                    &[address.to_string(), hex(initiation.as_bytes())],
                ),
            )?
            .trim_end(),
        )?;
        assert_eq!(finish(server, 0)?, event(session, [0; 32], 0, 0));
        let message = decode_id(
            run(
                &c.path,
                "traffic-original-message",
                &client_args(&c, &peer, false, Some(session), "next", &[hex(&session)]),
            )?
            .trim_end(),
        )?;
        let (server, address) = start(
            &c._setup.responder,
            "receiver-exit",
            &peer_args(&c, Some(session), "serve", &["crash-after".into()]),
        )?;
        assert_eq!(
            run(
                &c.path,
                "traffic-unknown-before-P-R",
                &client_args(
                    &c,
                    &peer,
                    false,
                    Some(session),
                    "uncertain-send",
                    &[address.to_string(), hex(&session), hex(&message)]
                )
            )?,
            "delivery-unknown-committed\n"
        );
        assert_eq!(finish(server, 77)?, "");
        fixture::effect(
            &c._setup.responder,
            session,
            p::MessageId::from_trusted_state(message)?,
            b"persisted before process exit",
        )?;
        let effect = c
            ._setup
            .responder
            .join(format!("application-{}", hex(&message)));
        let effect_before = effect_identity(&effect)?;
        message_status(
            &c,
            &peer,
            "traffic-original-committed",
            false,
            session,
            message,
            2,
        )?;

        let f = super::super::staged(c, policy_root)?;
        let proposal = super::super::proposal(&f.c)?;
        super::super::approve(&f, &w, proposal)?;
        assert_eq!(
            invoke(&f.c, "traffic-P-commit", "witness-commit")?,
            "witness-state:2\n"
        );
        message_status(
            &f.c,
            &peer,
            "traffic-P-original-committed",
            true,
            session,
            message,
            2,
        )?;
        let pin = p::AccountPin::new(
            f.c.root.account_id()?,
            f.c.root.public_key()?,
            f.c.roster.checkpoint(),
            f.c.family,
        )?;
        let previous = pin.verify_historical_device(&f.c.certificate, f.c.roster.as_bytes())?;
        let target = issue_target(&f.c, 2)?;
        let operation = p::RosterRefreshId::generate()?;
        fixture::store(&f.c.path, "roster-operation", operation.as_bytes())?;
        fixture::store(&f.c.path, "roster-policy-source", &[1])?;
        let r = RCase {
            c: f.c,
            previous,
            target,
            policy: f.target,
            authorization: Some(f.statement),
            operation,
        };
        let proposal = prepare(&r)?;
        approve(&r, &w, proposal)?;
        if tls {
            assert_eq!(
                invoke_r(&r.c, "traffic-R-commit", "commit")?,
                "roster-state:2\n"
            );
        } else {
            w.arm(39)?;
            assert_eq!(
                invoke_r(&r.c, "traffic-R-ACK-loss", "commit-lost")?,
                "roster-refused:218\n"
            );
            assert_eq!(w.fault.load(Ordering::Acquire), 0);
            assert_eq!(
                invoke_r(&r.c, "traffic-R-original-terminal", "progress")?,
                expected(&r, 3, false)
            );
            assert_eq!(
                invoke_r(&r.c, "traffic-R-recover", "reconcile")?,
                "roster-state:2\n"
            );
        }
        assert_eq!(
            invoke_r(&r.c, "traffic-R-retired", "progress")?,
            expected(&r, 3, true)
        );
        let c = &r.c;
        message_status(
            c,
            &peer,
            "traffic-R-original-committed",
            true,
            session,
            message,
            2,
        )?;
        let (server, address) = start(
            &c._setup.responder,
            "original-retry",
            &peer_args(c, Some(session), "serve", &["message".into()]),
        )?;
        assert_eq!(
            run(
                &c.path,
                "traffic-retry-after-P-R",
                &client_args(
                    c,
                    &peer,
                    true,
                    Some(session),
                    "send",
                    &[address.to_string(), hex(&session), hex(&message)]
                )
            )?,
            "consumed\n"
        );
        assert_eq!(finish(server, 0)?, event(session, message, 1, 0));
        assert_eq!(effect_identity(&effect)?, effect_before);
        fixture::effect(
            &c._setup.responder,
            session,
            p::MessageId::from_trusted_state(message)?,
            b"persisted before process exit",
        )?;
        message_status(
            c,
            &peer,
            "traffic-original-acknowledged",
            true,
            session,
            message,
            3,
        )?;

        let (server, address) = start(
            &c._setup.responder,
            "original-rekey",
            &peer_args(c, Some(session), "serve", &["rekey".into(), hex(&session)]),
        )?;
        assert_eq!(
            run(
                &c.path,
                "traffic-rekey-after-P-R",
                &client_args(
                    c,
                    &peer,
                    true,
                    Some(session),
                    "rekey",
                    &[address.to_string(), hex(&session)]
                )
            )?,
            "rekey-1-confirmed\n"
        );
        assert_eq!(finish(server, 0)?, "server-rekey-1\n");
        let fresh = decode_id(
            run(
                &c.path,
                "traffic-next-after-rekey",
                &client_args(c, &peer, true, Some(session), "next", &[hex(&session)]),
            )?
            .trim_end(),
        )?;
        assert_ne!(fresh, message);
        let (server, address) = start(
            &c._setup.responder,
            "post-rekey-message",
            &peer_args(c, Some(session), "serve", &["message".into()]),
        )?;
        assert_eq!(
            run(
                &c.path,
                "traffic-send-after-rekey",
                &client_args(
                    c,
                    &peer,
                    true,
                    Some(session),
                    "send",
                    &[address.to_string(), hex(&session), hex(&fresh)]
                )
            )?,
            "consumed\n"
        );
        assert_eq!(finish(server, 0)?, event(session, fresh, 1, 1));
        fixture::effect(
            &c._setup.responder,
            session,
            p::MessageId::from_trusted_state(fresh)?,
            b"persisted before process exit",
        )?;
        let reverse = decode_id(
            run(
                &c._setup.responder,
                "traffic-reverse-id",
                &peer_args(c, Some(session), "next", &[hex(&session)]),
            )?
            .trim_end(),
        )?;
        let (server, address) = start(
            &c.path,
            "reverse-listener",
            &client_args(c, &peer, true, Some(session), "serve", &["message".into()]),
        )?;
        assert_eq!(
            run(
                &c._setup.responder,
                "traffic-reverse-send",
                &peer_args(
                    c,
                    Some(session),
                    "send",
                    &[address.to_string(), hex(&session), hex(&reverse)]
                )
            )?,
            "consumed\n"
        );
        assert_eq!(finish(server, 0)?, event(session, reverse, 1, 1));
        fixture::effect(
            &peer,
            session,
            p::MessageId::from_trusted_state(reverse)?,
            b"persisted before process exit",
        )?;
        assert_eq!(fs::read(peer.join("bootstrap.bundle"))?, original_bundle);
        assert_eq!(fs::read(c.path.join("signer.key"))?, *original_signer);
        assert_eq!(fs::read(c.path.join("wrap.key"))?, *original_wrap);
        assert_eq!(effect_identity(&effect)?, effect_before);
        if let Some(server) = &mut encrypted {
            assert!(server.admitted.load(Ordering::Acquire) > 0);
            assert!(server.finish()?.is_empty());
        }
        w.join()?;
    }
    eprintln!("C_REQUIRED_P_R_TRAFFIC cases=2 TCP_TLS_witness=true original_session=true original_message=true receiver_exit_77=true effect_not_repeated=true R_ACK_loss=true rekey_1=true bidirectional_after_rekey=true unchanged_bootstrap_and_owner_keys=true");
    Ok(())
}
