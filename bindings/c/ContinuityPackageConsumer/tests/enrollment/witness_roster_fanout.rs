// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete-account C delivery through the original enrolled and renewed owners.
use super::*;
use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};

struct Group {
    c: Registered,
    peers: [PathBuf; 2],
    recipients: [PathBuf; 2],
    sessions: [[u8; 32]; 2],
    account: [u8; 32],
    renewed: bool,
    result_client: Option<AccountResultClient>,
    peer_roster_client: Option<PolicyClient>,
}
struct AccountResultClient {
    executable: PathBuf,
    language: &'static str,
}
impl AccountResultClient {
    fn selected() -> Result<Option<Self>> {
        match (
            std::env::var_os("QPERIAPT_ACCOUNT_RESULT_CLIENT"),
            std::env::var_os("QPERIAPT_ACCOUNT_RESULT_LANGUAGE"),
        ) {
            (None, None) => Ok(None),
            (Some(path), Some(language)) => {
                let executable = PathBuf::from(path);
                if !executable.is_absolute() || !executable.is_file() {
                    return Err("foreign account result executable is not an absolute file".into());
                }
                let language = match language.to_str() {
                    Some("Swift") => "Swift",
                    Some("Kotlin") => "Kotlin",
                    _ => return Err("unqualified account result language".into()),
                };
                Ok(Some(Self {
                    executable,
                    language,
                }))
            }
            _ => Err("foreign account result client and language must be selected together".into()),
        }
    }
}
impl Group {
    fn traffic(&self, label: &str, args: &[OsString]) -> Result<String> {
        match &self.peer_roster_client {
            Some(client) => {
                let output = run_client(&client.executable, &self.c.path, label, args)?;
                eprintln!(
                    "FOREIGN_ACCOUNT_TRAFFIC language={} label={label} parent={}",
                    client.language,
                    if self.renewed {
                        "independent-policy"
                    } else {
                        "original"
                    }
                );
                Ok(output)
            }
            None => run(&self.c.path, label, args),
        }
    }
    fn peer_roster_inputs(&self, label: &str, args: &[OsString]) -> Result<()> {
        let client = self
            .peer_roster_client
            .as_ref()
            .ok_or("foreign peer roster client")?;
        let command = args
            .iter()
            .position(|v| v == "peer-roster-admit")
            .ok_or("peer roster command")?;
        let mut validation = args.to_vec();
        *validation.get_mut(command + 3).ok_or("peer roster mode")? = "validate".into();
        validation.truncate(command + 4);
        assert_eq!(
            run(&self.c.path, &format!("{label}-raw-inputs"), &validation)?,
            "peer-roster-inputs-refused\n"
        );
        eprintln!(
            "FOREIGN_PEER_ROSTER_RAW_CONTROL language={} label={label}",
            client.language
        );
        Ok(())
    }
    fn peer_roster(&self, label: &str, args: &[OsString]) -> Result<String> {
        match &self.peer_roster_client {
            Some(client) => {
                self.peer_roster_inputs(label, args)?;
                let output = run_client(&client.executable, &self.c.path, label, args)?;
                eprintln!(
                    "FOREIGN_PEER_ROSTER_CALL language={} label={label}",
                    client.language
                );
                Ok(output)
            }
            None => run(&self.c.path, label, args),
        }
    }
    fn account_recovery(&self, label: &str, mode: &str, id: [u8; 32]) -> Result<String> {
        let args = self.c.arguments(vec![
            mode.into(),
            self.c.path.as_os_str().into(),
            hex(&id).into(),
        ]);
        match &self.result_client {
            Some(client) => {
                let output = run_client(&client.executable, &self.c.path, label, &args)?;
                if matches!(mode, "recover-member-freeze" | "recover-member-ack") {
                    eprintln!(
                        "FOREIGN_MEMBER_CLOSURE language={} mode={mode} label={label}",
                        client.language
                    );
                }
                Ok(output)
            }
            None => run(&self.c.path, label, &args),
        }
    }
    fn args(&self, mode: &str, tail: &[OsString]) -> Vec<OsString> {
        let mut args = vec![
            if self.renewed {
                "--independent-policy-parent"
            } else {
                "--enrollment-parent"
            }
            .into(),
            self.c.path.as_os_str().into(),
            "1".into(),
            mode.into(),
            self.c.path.as_os_str().into(),
        ];
        args.extend_from_slice(tail);
        self.c.arguments(args)
    }
    fn send(
        &self,
        label: &str,
        batch: [u8; 32],
        selected: usize,
        address: SocketAddr,
        mode: &str,
        original: Option<[u8; 32]>,
    ) -> Result<String> {
        let [peer0, peer1] = &self.peers;
        let [session0, session1] = self.sessions;
        let mut tail = vec![
            peer0.as_os_str().into(),
            hex(&session0).into(),
            peer1.as_os_str().into(),
            hex(&session1).into(),
            hex(&self.account).into(),
            hex(&batch).into(),
            selected.to_string().into(),
            address.to_string().into(),
            mode.into(),
        ];
        if let Some(original) = original {
            tail.push(hex(&original).into());
        }
        self.traffic(label, &self.args("account-send", &tail))
    }
    fn status(&self, label: &str, batch: [u8; 32]) -> Result<()> {
        assert_eq!(
            self.traffic(label, &self.args("account-status", &[hex(&batch).into()]))?,
            format!("account-status:2\n{}\n", hex(&[0; 32]))
        );
        Ok(())
    }
}
fn remote_args(
    c: &Registered,
    path: &Path,
    session: Option<[u8; 32]>,
    mode: &str,
) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(session) = session {
        args.extend(["--session".into(), hex(&session).into()]);
    }
    args.extend(["serve".into(), path.as_os_str().into(), mode.into()]);
    c.arguments(args)
}
fn delivered(text: &str, session: [u8; 32], device: [u8; 16], exchanges: u32) -> Result<[u8; 32]> {
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some(format!("account-delivered:1:{exchanges}").as_str())
    );
    assert_eq!(
        decode_id(lines.next().ok_or("delivered session")?)?,
        session
    );
    let message = decode_id(lines.next().ok_or("delivered message")?)?;
    assert_eq!(lines.next(), Some(hex(&device).as_str()));
    assert!(lines.next().is_none());
    Ok(message)
}
fn only_effect(path: &Path) -> Result<([u8; 32], PathBuf)> {
    let records = fs::read_dir(path)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|e| e.file_name().to_string_lossy().starts_with("application-"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let file = records.first().ok_or("original effect")?.path();
    let id = file
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("application-"))
        .ok_or("effect name")?;
    Ok((decode_id(id)?, file))
}

#[test]
fn c_required_p_r_keeps_partial_account_batch_and_original_member_results() -> Result<()> {
    account_scenario(false)
}
#[test]
fn c_required_peer_revocation_reconciles_every_original_account_member_before_retirement(
) -> Result<()> {
    account_scenario(true)
}
#[derive(Clone, Copy, Debug)]
enum PeerUpdateCut {
    Unprocessed,
    LostReply,
    CancelInFlight,
    KillProcess,
}
#[test]
fn c_peer_roster_unknown_commit_cancel_and_kill_recover_original_target_without_current_sdk(
) -> Result<()> {
    for cut in [
        PeerUpdateCut::Unprocessed,
        PeerUpdateCut::LostReply,
        PeerUpdateCut::CancelInFlight,
        PeerUpdateCut::KillProcess,
    ] {
        account_scenario_with_cut(true, Some(cut), &[false])?;
    }
    let error_scope = if PolicyClient::selected_for("PEER_ROSTER")?.is_some() {
        "typed_error_results=true"
    } else {
        "unchanged_error_output=true"
    };
    eprintln!("C_PEER_ROSTER_INTERRUPTION cases=4 signed_TCP=true unprocessed_and_processed_loss=true inflight_cancel=true actual_process_kill=true {error_scope} original_sealed_target=true historical_account_recovery=true distinct_member_outcomes=true");
    Ok(())
}
#[test]
fn c_peer_roster_tls_unprocessed_openssl_request_recovers_exact_target() -> Result<()> {
    account_scenario_with_cut(true, Some(PeerUpdateCut::Unprocessed), &[true])?;
    eprintln!("C_PEER_ROSTER_TLS_UNPROCESSED cases=1 endpoint=OpenSSL mutual_TLS=true complete_authorized_frame=true no_store_handle=true unchanged_witness_image=true original_target=true fresh_recovery_challenge=true complete_account_results=true no_plaintext_fallback=true");
    Ok(())
}
#[derive(Clone, Copy)]
enum PeerTls<'a> {
    Native(&'a witness_tls_faults::FaultWitness),
    OpenSsl(&'a crate::openssl_host::Host),
}
impl PeerTls<'_> {
    fn captures(self) -> Result<Vec<witness::Capture>> {
        Ok(match self {
            Self::Native(server) => server
                .captured
                .lock()
                .map_err(|_| "TLS captures")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.record.request().to_vec(),
                    reply: r.record.reply().to_vec(),
                    delivered: r.delivered,
                })
                .collect(),
            Self::OpenSsl(server) => server
                .captured
                .lock()
                .map_err(|_| "OpenSSL captures")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.request.clone(),
                    reply: r.reply.clone(),
                    delivered: true,
                })
                .collect(),
        })
    }
    fn arm(self, cut: PeerUpdateCut, marker: &Path) -> Result<()> {
        match self {
            Self::Native(server) => {
                if matches!(cut, PeerUpdateCut::Unprocessed) {
                    return Err("native TLS pre-processing hook is not available".into());
                }
                server.arm(
                    matches!(
                        cut,
                        PeerUpdateCut::CancelInFlight | PeerUpdateCut::KillProcess
                    )
                    .then_some(marker),
                )
            }
            Self::OpenSsl(server) => {
                if !matches!(cut, PeerUpdateCut::Unprocessed) {
                    return Err("OpenSSL scenario must select pre-processing loss".into());
                }
                server
                    .drop_advance
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| "OpenSSL prior fault unconsumed")?;
                Ok(())
            }
        }
    }
}
fn account_scenario(revoke: bool) -> Result<()> {
    account_scenario_with_cut(revoke, None, &[false, true])
}
#[test]
fn c_peer_roster_tls_committed_reply_loss_cancel_and_kill_recover_original_target() -> Result<()> {
    for cut in [
        PeerUpdateCut::LostReply,
        PeerUpdateCut::CancelInFlight,
        PeerUpdateCut::KillProcess,
    ] {
        account_scenario_with_cut(true, Some(cut), &[true])?;
    }
    eprintln!("C_PEER_ROSTER_TLS_INTERRUPTION cases=3 mutual_TLS=true processed_loss=true inflight_cancel=true actual_process_kill=true original_sealed_target=true historical_account_recovery=true distinct_member_outcomes=true no_plaintext_fallback=true");
    Ok(())
}
fn account_scenario_with_cut(
    revoke: bool,
    cut: Option<PeerUpdateCut>,
    profiles: &[bool],
) -> Result<()> {
    for &tls in profiles {
        let mut w = witness::Witness::start()?;
        let (setup, second) =
            fixture::setup_devices(Some(&w.configured), None, None, true, false, true)?;
        let second = second.ok_or("second recipient")?;
        let mut c = registered_from_setup(
            setup,
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
        let recipients = [c._setup.responder.clone(), second];
        let peers = [c.path.join("peer-0"), c.path.join("peer-1")];
        for (remote, peer) in recipients.iter().zip(&peers) {
            peer_bundle_at(
                remote,
                peer,
                &c.root,
                &c.certificate,
                &c.roster,
                Some(&w.configured),
            )?;
        }
        let account = fixture::array::<32>(
            recipients.first().ok_or("first recipient")?,
            "local-account",
        )?;
        assert_eq!(
            account,
            fixture::array(
                recipients.get(1).ok_or("second recipient")?,
                "local-account"
            )?
        );
        let original_bundles = peers
            .iter()
            .map(|p| fs::read(p.join("bootstrap.bundle")))
            .collect::<std::io::Result<Vec<_>>>()?;
        let signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
        let wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
        let [remote0, remote1] = &recipients;
        let mut encrypted = if tls && cut.is_none() {
            Some(witness_tls::TlsWitness::start(
                Arc::clone(&w.configured.store),
                [&c.path, remote0, remote1],
            )?)
        } else {
            None
        };
        let mut encrypted_fault =
            if tls && cut.is_some() && !matches!(cut, Some(PeerUpdateCut::Unprocessed)) {
                Some(witness_tls_faults::FaultWitness::start(
                    Arc::clone(&w.configured.store),
                    [&c.path, remote0, remote1],
                    w._directory.path().join("witness.redb"),
                )?)
            } else {
                None
            };
        let mut independent_tls = if tls && matches!(cut, Some(PeerUpdateCut::Unprocessed)) {
            Some(crate::openssl_host::Host::start(
                &c.path,
                [&c.path, remote0, remote1],
                Arc::clone(&w.configured.store),
                true,
            )?)
        } else {
            None
        };
        if let Some(server) = &independent_tls {
            c.witness.as_mut().ok_or("witness")?.address = server.address;
            c.witness_tls = true;
        }
        if let Some(server) = &encrypted {
            c.witness.as_mut().ok_or("witness")?.address = server.address;
            c.witness_tls = true;
        }
        if let Some(server) = &encrypted_fault {
            c.witness.as_mut().ok_or("witness")?.address = server.address;
            c.witness_tls = true;
        }
        // Registration above used the fixture's original signed carrier. From
        // this boundary both sessions and every lifecycle/recovery call must
        // use the configured encrypted endpoint exclusively.
        let plain_before_tls = calls(&w)?;
        let mut established = Vec::new();
        for (index, (remote, peer)) in recipients.iter().zip(&peers).enumerate() {
            let (server, address) = start(
                remote,
                "group-bootstrap",
                &remote_args(&c, remote, None, "bootstrap"),
            )?;
            let session = decode_id(
                run(
                    &c.path,
                    &format!("group-connect-{index}"),
                    &client_args(
                        &c,
                        peer,
                        false,
                        None,
                        "connect",
                        &[
                            address.to_string(),
                            hex(p::InitiationId::generate()?.as_bytes()),
                        ],
                    ),
                )?
                .trim_end(),
            )?;
            assert_eq!(finish(server, 0)?, event(session, [0; 32], 0, 0));
            established.push(session);
        }
        let sessions: [[u8; 32]; 2] = established
            .try_into()
            .map_err(|_| "two established sessions")?;
        assert_ne!(sessions.first(), sessions.get(1));
        let mut g = Group {
            c,
            peers,
            recipients,
            sessions,
            account,
            renewed: false,
            result_client: AccountResultClient::selected()?,
            peer_roster_client: PolicyClient::selected_for("PEER_ROSTER")?,
        };
        if let Some(peer) = &g.peer_roster_client {
            let result = g
                .result_client
                .as_ref()
                .ok_or("foreign peer roster needs complete foreign account recovery")?;
            if peer.executable != result.executable || peer.language != result.language {
                return Err("foreign peer roster and account recovery identities differ".into());
            }
        }
        let batch = decode_id(
            g.traffic("group-next", &g.args("account-next", &[]))?
                .trim_end(),
        )?;
        let [session0, session1] = g.sessions;
        let [remote0, remote1] = &g.recipients;
        let device0 = fixture::array::<16>(remote0, "local-device")?;
        let device1 = fixture::array::<16>(remote1, "local-device")?;
        assert_ne!(device0, device1);
        let (server, address) = start(
            remote0,
            "group-first-delivery",
            &remote_args(&g.c, remote0, Some(session0), "message"),
        )?;
        let first = delivered(
            &g.send("group-first-send", batch, 0, address, "deliver", None)?,
            session0,
            device0,
            1,
        )?;
        assert_eq!(finish(server, 0)?, event(session0, first, 1, 1));
        let (server, address) = start(
            remote1,
            "group-second-exit",
            &remote_args(&g.c, remote1, Some(session1), "crash-after"),
        )?;
        assert_eq!(
            g.send("group-second-unknown", batch, 1, address, "unknown", None)?,
            "account-refused:311\n"
        );
        assert_eq!(finish(server, 77)?, "");
        let (second, effect1) = only_effect(remote1)?;
        let (observed_first, effect0) = only_effect(remote0)?;
        assert_eq!(first, observed_first);
        let effects_before = [effect_identity(&effect0)?, effect_identity(&effect1)?];
        g.status("group-partial-before-updates", batch)?;

        let f = super::super::super::staged(g.c, policy_root)?;
        let proposal = super::super::super::proposal(&f.c)?;
        super::super::super::approve(&f, &w, proposal)?;
        assert_eq!(
            invoke(&f.c, "group-P-commit", "witness-commit")?,
            "witness-state:2\n"
        );
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
        assert_eq!(
            invoke_r(&r.c, "group-R-commit", "commit")?,
            "roster-state:2\n"
        );
        assert_eq!(
            invoke_r(&r.c, "group-R-retired", "progress")?,
            expected(&r, 3, true)
        );
        g.c = r.c;
        g.renewed = true;
        g.status("group-partial-after-updates", batch)?;
        let unused = SocketAddr::from(([127, 0, 0, 1], 1));
        let witness_observations = || -> Result<usize> {
            if let Some(server) = &independent_tls {
                return Ok(server
                    .captured
                    .lock()
                    .map_err(|_| "OpenSSL captures")?
                    .len());
            }
            if let Some(server) = &encrypted_fault {
                return Ok(server.captured.lock().map_err(|_| "TLS captures")?.len());
            }
            match &encrypted {
                Some(server) => Ok(server.admitted.load(Ordering::Acquire)),
                None => calls(&w),
            }
        };
        let witness_before_retained = witness_observations()?;
        assert_eq!(
            delivered(
                &g.send("group-first-retained", batch, 0, unused, "retained", None)?,
                session0,
                device0,
                0
            )?,
            first
        );
        assert_eq!(
            delivered(
                &g.send(
                    "group-reverse-order-retained",
                    batch,
                    0,
                    unused,
                    "reverse-retained",
                    None
                )?,
                session0,
                device0,
                0
            )?,
            first
        );
        assert!(
            witness_observations()? > witness_before_retained,
            "zero application exchanges must not mean skipped witness admission"
        );
        let saved = snapshot(&g.c)?;
        for (mode, code, original) in [
            ("unary", 215, Some(second)),
            ("changed-input", 211, None),
            ("omit-retained", 211, None),
            ("cancel-peer", 302, None),
        ] {
            assert_eq!(
                g.send(
                    &format!("group-refuse-{mode}"),
                    batch,
                    1,
                    unused,
                    mode,
                    original
                )?,
                format!("account-refused:{code}\n")
            );
            assert_eq!(
                snapshot(&g.c)?,
                saved,
                "refused member release changed original journal"
            );
        }
        if revoke {
            revoked_recovery(
                &g,
                batch,
                [first, second],
                [device0, device1],
                &mut w,
                cut,
                encrypted_fault
                    .as_ref()
                    .map(PeerTls::Native)
                    .or_else(|| independent_tls.as_ref().map(PeerTls::OpenSsl)),
            )?;
        } else {
            let remote1 = g.recipients.get(1).ok_or("second recipient")?;
            let (server, address) = start(
                remote1,
                "group-original-second-retry",
                &remote_args(&g.c, remote1, Some(session1), "message"),
            )?;
            assert_eq!(
                delivered(
                    &g.send(
                        "group-original-second-send",
                        batch,
                        1,
                        address,
                        "deliver",
                        None
                    )?,
                    session1,
                    device1,
                    1
                )?,
                second
            );
            assert_eq!(finish(server, 0)?, event(session1, second, 1, 0));
            assert_eq!(
                delivered(
                    &g.send("group-second-retained", batch, 1, unused, "retained", None)?,
                    session1,
                    device1,
                    0
                )?,
                second
            );
        }
        assert_eq!(
            [effect_identity(&effect0)?, effect_identity(&effect1)?],
            effects_before
        );
        for ((remote, session), message) in g.recipients.iter().zip(g.sessions).zip([first, second])
        {
            fixture::effect(
                remote,
                session,
                p::MessageId::from_trusted_state(message)?,
                b"persisted before process exit",
            )?;
            assert_eq!(only_effect(remote)?.0, message);
        }
        for (peer, bytes) in g.peers.iter().zip(original_bundles) {
            assert_eq!(fs::read(peer.join("bootstrap.bundle"))?, bytes);
        }
        assert_eq!(fs::read(g.c.path.join("signer.key"))?, *signer);
        assert_eq!(fs::read(g.c.path.join("wrap.key"))?, *wrapping);
        let next = decode_id(
            run(
                &g.c.path,
                "group-next-distinct",
                &g.args("account-next", &[]),
            )?
            .trim_end(),
        )?;
        assert_ne!(next, batch);
        if let Some(server) = &mut encrypted {
            assert!(server.admitted.load(Ordering::Acquire) > 0);
            assert!(server.finish()?.is_empty());
        }
        if let Some(server) = &mut encrypted_fault {
            assert_eq!(
                calls(&w)?,
                plain_before_tls,
                "no plaintext witness fallback after TLS selection"
            );
            eprintln!("PEER_ROSTER_TLS_CARRIER registration_plain_records={plain_before_tls} subsequent_plain_records=0");
            server.finish()?;
        }
        if let Some(server) = &mut independent_tls {
            assert_eq!(
                calls(&w)?,
                plain_before_tls,
                "no signed-TCP fallback from independent TLS"
            );
            assert!(server.finish()? > 0);
            eprintln!("PEER_ROSTER_OPENSSL_CARRIER subsequent_plain_records=0 TLS13=true X25519MLKEM768=true alpn=q-periapt-anchor/1");
        }
        w.join()?;
        if let Some(client) = &g.peer_roster_client {
            eprintln!("FOREIGN_PEER_ROSTER language={} carrier={} cut={cut:?} exact_target=true original_parent=true complete_foreign_results=true C_registration_P_R_and_raw_controls=true",
                client.language, if tls { "mutual-TLS" } else { "signed-TCP" });
        }
        if let Some(client) = &g.result_client {
            eprintln!("FOREIGN_ACCOUNT_RECONCILIATION language={} carrier={} cut={cut:?} members=2 original_ids=true complete_results=true consumed_vs_unknown=true durable_host_report=true retired=true foreign_member_closure=true C_setup=true",
                client.language, if tls { "mutual-TLS" } else { "signed-TCP" });
        }
    }
    if cut.is_none() && revoke {
        eprintln!("C_REQUIRED_PEER_REVOCATION cases=2 recipients=2 actual_second_revocation=true TCP_TLS_witness=true partial_confirmed_unknown=true complete_original_reconciliation=true synced_full_reports=true metadata_retired=true");
    } else if cut.is_none() {
        eprintln!("C_REQUIRED_P_R_FANOUT cases=2 recipients=2 TCP_TLS_witness=true original_batch=true partial_confirmed_unknown=true receiver_exit_77=true retained_no_application_exchange=true witness_still_checked=true original_member_retry=true aggregate_bypass_denied=true unchanged_effects=true");
    }
    Ok(())
}

fn revoked_recovery(
    g: &Group,
    batch: [u8; 32],
    messages: [[u8; 32]; 2],
    devices: [[u8; 16]; 2],
    witness: &mut witness::Witness,
    cut: Option<PeerUpdateCut>,
    tls: Option<PeerTls<'_>>,
) -> Result<()> {
    let root =
        g.c._setup
            .responder_issuer
            .as_ref()
            .ok_or("independent recipient roster issuer")?;
    let first = g.recipients.first().ok_or("retained recipient")?;
    let certificate = fixture::read(first, "local-certificate", 8192)?;
    let now = fixture::now()?;
    let roster = root.issue_roster(
        2,
        p::Validity::new(
            now.checked_sub(1).ok_or("clock")?,
            now.checked_add(300).ok_or("clock")?,
        )?,
        &[root.roster_entry(&certificate)?],
    )?;
    let public = g.c.path.join("peer-roster-revocation");
    fs::create_dir(&public)?;
    fs::set_permissions(&public, fs::Permissions::from_mode(0o700))?;
    for (name, bytes) in [
        ("root", root.public_key()?.encode()),
        ("account", root.account_id()?.to_vec()),
        ("family", g.c.family.to_vec()),
        (
            "version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("digest", roster.checkpoint().digest().to_vec()),
        ("roster", roster.as_bytes().to_vec()),
    ] {
        fixture::store(&public, name, &bytes)?;
    }
    let before = snapshot(&g.c)?;
    assert_eq!(
        g.peer_roster(
            "peer-roster-pre-cancel",
            &g.args(
                "peer-roster-admit",
                &[public.as_os_str().into(), "cancel".into()]
            )
        )?,
        "peer-roster-cancelled\n"
    );
    assert_eq!(
        snapshot(&g.c)?,
        before,
        "cancelled public peer roster cannot mutate original journal"
    );
    let expected = |states: [u32; 2]| {
        let mut members = devices
            .into_iter()
            .zip(g.sessions)
            .zip(messages)
            .zip(states)
            .map(|(((d, s), m), state)| (d, s, m, state))
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.0);
        let mut text = format!("QPC-C-RECONCILIATION/1\nbatch {}\nmembers 2\n", hex(&batch));
        for (i, (d, s, m, state)) in members.iter().enumerate() {
            text.push_str(&format!(
                "member {i} {} {} {} {state}\n",
                hex(d),
                hex(s),
                hex(m)
            ));
        }
        text
    };
    let recover = |label: &str, mode: &str, id: [u8; 32]| g.account_recovery(label, mode, id);
    let committed = if let Some(cut) = cut {
        interrupt_peer_update(g, witness, &public, batch, cut, &expected([2, 1]), tls)?
    } else {
        let [peer0, peer1] = &g.peers;
        let [session0, session1] = g.sessions;
        assert_eq!(
            g.peer_roster(
                "peer-roster-revoke",
                &g.args(
                    "peer-roster-admit",
                    &[
                        public.as_os_str().into(),
                        "suspend".into(),
                        peer0.as_os_str().into(),
                        hex(&session0).into(),
                        peer1.as_os_str().into(),
                        hex(&session1).into(),
                        hex(&g.account).into(),
                        hex(&batch).into(),
                    ]
                )
            )?,
            "account-refused:103\npeer-roster-admitted\n"
        );
        let committed = snapshot(&g.c)?;
        assert_ne!(
            before, committed,
            "authentic revocation changed current peer roster"
        );
        assert_eq!(
            g.peer_roster(
                "peer-roster-exact-retry",
                &g.args(
                    "peer-roster-admit",
                    &[public.as_os_str().into(), "admit".into()]
                )
            )?,
            "peer-roster-admitted\n"
        );
        assert_eq!(
            snapshot(&g.c)?,
            committed,
            "exact target retains original image"
        );
        committed
    };
    assert_eq!(
        recover(
            "peer-roster-original-results",
            "recover-account-results",
            batch
        )?,
        expected([2, 1])
    );
    assert_eq!(
        snapshot(&g.c)?,
        committed,
        "read-only complete outcomes preserve original operation"
    );
    for (i, session) in g.sessions.into_iter().enumerate() {
        assert_eq!(
            recover(
                &format!("peer-roster-freeze-{i}"),
                "recover-member-freeze",
                session
            )?,
            "member-frozen\n"
        );
        let report = fixture::read(
            &g.c.path,
            &format!("c-member-loss-{}", hex(&session)),
            1048576,
        )?;
        let report = String::from_utf8(report)?;
        assert!(report.starts_with("QPC-C-LOSS/1\nreport "));
        assert!(report
            .lines()
            .nth(2)
            .ok_or("member report header")?
            .starts_with(&format!("header {} ", hex(&session))));
        if i == 0 {
            assert!(!report.contains("\nunconfirmed "));
        } else {
            assert!(report.contains(&format!(
                "\nunconfirmed 0 0 {} ",
                hex(messages.get(1).ok_or("second message")?)
            )));
        }
        assert_eq!(
            recover(
                &format!("peer-roster-frozen-results-{i}"),
                "recover-account-results",
                batch
            )?,
            expected(if i == 0 { [2, 1] } else { [2, 3] })
        );
        assert_eq!(
            recover(
                &format!("peer-roster-accounted-{i}"),
                "recover-member-ack",
                session
            )?,
            "member-accounted\n"
        );
        assert_eq!(
            fixture::read(
                &g.c.path,
                &format!("c-member-loss-{}", hex(&session)),
                1048576
            )?,
            report.as_bytes()
        );
    }
    assert_eq!(
        recover(
            "peer-roster-complete-retirement",
            "recover-account-settled-retire",
            batch
        )?,
        expected([2, 4])
    );
    assert_eq!(
        fixture::read(&g.c.path, "c-account-reconciliation", 1048576)?,
        expected([2, 4]).as_bytes()
    );
    assert_eq!(
        recover(
            "peer-roster-retired-reopen",
            "recover-account-retired",
            batch
        )?,
        "account-selection-refused:112\n"
    );
    Ok(())
}

fn ordinary_target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Result<Vec<u8>> {
    let pending = saved.1.as_ref().ok_or("original ordinary pending intent")?;
    assert_eq!(pending.get(..8), Some(b"QPWINT01".as_slice()));
    let length = u32::from_be_bytes(pending.get(152..156).ok_or("target length")?.try_into()?);
    let target = pending
        .get(156..pending.len().checked_sub(32).ok_or("intent MAC")?)
        .ok_or("sealed target")?;
    assert_eq!(usize::try_from(length)?, target.len());
    Ok(target.to_vec())
}
fn kill_held_update(g: &Group, args: &[OsString], marker: &Path) -> Result<()> {
    let stdout = g.c.path.join("peer-roster-killed.stdout");
    let stderr = g.c.path.join("peer-roster-killed.stderr");
    let output = |path: &Path| {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
    };
    let executable = if let Some(client) = &g.peer_roster_client {
        g.peer_roster_inputs("peer-roster-killed", args)?;
        client.executable.clone()
    } else {
        executable()?
    };
    let mut child = fixture::OwnedChild(
        Command::new(executable)
            .args(args)
            .stdout(Stdio::from(output(&stdout)?))
            .stderr(Stdio::from(output(&stderr)?))
            .spawn()?,
    );
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match fs::read(marker) {
            Ok(bytes) => {
                assert_eq!(bytes, b"1");
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if child.0.try_wait()?.is_some() || Instant::now() >= until {
            return Err(format!(
                "C peer-roster did not reach processed reply barrier: {}",
                fs::read_to_string(&stderr)?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        child.0.try_wait()?.is_none(),
        "kill only the observed live original C owner"
    );
    child.0.kill()?;
    assert_eq!(fixture::wait(&mut child)?.signal(), Some(9));
    assert!(fs::read(&stdout)?.is_empty());
    assert!(fs::read(&stderr)?.is_empty());
    if let Some(client) = &g.peer_roster_client {
        eprintln!(
            "FOREIGN_PEER_ROSTER_KILLED language={} signal=9 actual_processed_barrier=true",
            client.language
        );
    }
    Ok(())
}
fn interrupt_peer_update(
    g: &Group,
    witness: &mut witness::Witness,
    public: &Path,
    batch: [u8; 32],
    cut: PeerUpdateCut,
    expected: &str,
    tls: Option<PeerTls<'_>>,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let marker = g.c.path.join("peer-roster-held-advance");
    let opcode = match cut {
        PeerUpdateCut::Unprocessed => 42,
        PeerUpdateCut::LostReply => 22,
        PeerUpdateCut::CancelInFlight | PeerUpdateCut::KillProcess => {
            if tls.is_none() {
                let mut held = witness.hold_marker.lock().map_err(|_| "held marker lock")?;
                assert!(held.is_none());
                *held = Some(marker.clone());
            }
            3
        }
    };
    let mode = match cut {
        PeerUpdateCut::CancelInFlight => "cancel-active",
        PeerUpdateCut::KillProcess => "admit",
        _ => "lost",
    };
    let mut tail = vec![public.as_os_str().into(), mode.into()];
    if matches!(cut, PeerUpdateCut::CancelInFlight) {
        tail.push(marker.as_os_str().into());
    }
    let args = g.args("peer-roster-admit", &tail);
    let before = snapshot(&g.c)?;
    let witness_image = if matches!(tls, Some(PeerTls::OpenSsl(_))) {
        Some(witness_tls_faults::snapshot(
            &witness._directory.path().join("witness.redb"),
        )?)
    } else {
        None
    };
    let first = if let Some(tls) = tls {
        let first = tls.captures()?.len();
        tls.arm(cut, &marker)?;
        first
    } else {
        let first = calls(witness)?;
        witness.arm(opcode)?;
        first
    };
    if matches!(cut, PeerUpdateCut::KillProcess) {
        kill_held_update(g, &args, &marker)?;
    } else {
        assert_eq!(
            g.peer_roster("peer-roster-interrupted", &args)?,
            if matches!(cut, PeerUpdateCut::CancelInFlight) {
                "peer-roster-cancelled-after-advance\n"
            } else {
                "peer-roster-outcome-unavailable\n"
            }
        );
    }
    if tls.is_some()
        && matches!(
            cut,
            PeerUpdateCut::CancelInFlight | PeerUpdateCut::KillProcess
        )
    {
        let released = marker.with_extension("released");
        fixture::publish_marker(
            released.parent().ok_or("TLS release parent")?,
            released
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("TLS release name")?,
        )?;
    }
    if let Some(PeerTls::OpenSsl(server)) = tls {
        assert!(
            !server.drop_advance.load(Ordering::Acquire),
            "intended OpenSSL request cut consumed"
        );
        let dropped = server
            .unprocessed
            .lock()
            .map_err(|_| "OpenSSL unprocessed")?;
        assert_eq!(dropped.len(), 1);
        assert_eq!(
            dropped.first().ok_or("unprocessed TLS frame")?.get(204),
            Some(&2)
        );
        assert!(
            witness_image.as_ref().ok_or("before witness image")?
                == &witness_tls_faults::snapshot(&witness._directory.path().join("witness.redb"))?
        );
    } else if let Some(PeerTls::Native(tls)) = tls {
        let records = tls.captured.lock().map_err(|_| "TLS captures")?;
        let lost = records
            .get(first..)
            .ok_or("new TLS captures")?
            .iter()
            .filter(|r| !r.delivered)
            .collect::<Vec<_>>();
        assert_eq!(
            lost.len(),
            1,
            "one actual encrypted reply interruption before recovery"
        );
        let lost = lost.first().ok_or("lost encrypted response")?;
        assert!(lost.advanced && lost.encrypted_reply_bytes > 0);
        assert_eq!(lost.record.request().get(204), Some(&2));
        assert_eq!(lost.record.reply().get(204), Some(&2));
    } else {
        assert_eq!(
            witness.fault.load(Ordering::Acquire),
            0,
            "actual intended fault consumed"
        );
    }
    let interrupted = snapshot(&g.c)?;
    assert_eq!(
        interrupted.0, before.0,
        "unknown reply does not install a different local image"
    );
    let target = ordinary_target(&interrupted)?;
    // Remove only this fixture's live independent SDK resource. Historical cleanup
    // still requires the exact original journal, archives, signer and witness.
    fs::rename(
        g.c.path.join("independent-sdk"),
        g.c.path.join("independent-sdk-held"),
    )?;
    assert_eq!(
        g.account_recovery(
            "peer-roster-historical-original-recovery",
            "recover-account-results",
            batch,
        )?,
        expected
    );
    let recovered = snapshot(&g.c)?;
    assert_eq!(
        recovered,
        (target, None),
        "same original sealed target is recovered before complete member results"
    );
    {
        let records = if let Some(tls) = tls {
            tls.captures()?
        } else {
            witness
                .captured
                .lock()
                .map_err(|_| "capture")?
                .iter()
                .map(|r| witness::Capture {
                    request: r.request.clone(),
                    reply: r.reply.clone(),
                    delivered: r.delivered,
                })
                .collect::<Vec<_>>()
        };
        let advances = records
            .get(first..)
            .ok_or("new captures")?
            .iter()
            .filter(|r| r.request.get(204) == Some(&2))
            .collect::<Vec<_>>();
        let outcomes = advances
            .iter()
            .map(|r| r.reply.get(204).copied())
            .collect::<Option<Vec<_>>>()
            .ok_or("bounded reply outcomes")?;
        let expected_outcomes: &[u8] = if matches!(cut, PeerUpdateCut::Unprocessed) {
            &[2]
        } else {
            &[2, 3]
        };
        assert_eq!(
            outcomes, expected_outcomes,
            "one Advanced followed only by exact prior-command confirmation"
        );
        let original = advances.first().ok_or("original advance")?;
        for (i, record) in advances.iter().enumerate() {
            assert_eq!(
                record.request.get(4..172),
                original.request.get(4..172),
                "same authority, subject and command"
            );
            assert_eq!(
                record.request.get(204..301),
                original.request.get(204..301),
                "same full Advance operation and target"
            );
            assert_eq!(
                record.reply.get(172..204),
                record.request.get(140..172),
                "reply bound to original command"
            );
            assert_eq!(
                record.reply.get(205..286),
                original.reply.get(205..286),
                "same target head and retained last command"
            );
            assert_eq!(
                record.delivered,
                matches!(cut, PeerUpdateCut::Unprocessed) || i == 1
            );
            if i > 0 {
                assert_ne!(
                    record.request.get(172..204),
                    original.request.get(172..204),
                    "new request challenge, not replayed attempt"
                );
            }
        }
        let unprocessed = match tls {
            Some(PeerTls::OpenSsl(server)) => &server.unprocessed,
            _ => &witness.unprocessed,
        };
        let mut unprocessed = unprocessed.lock().map_err(|_| "unprocessed")?;
        assert_eq!(
            unprocessed.len(),
            usize::from(matches!(cut, PeerUpdateCut::Unprocessed))
        );
        if let Some(request) = unprocessed.first() {
            assert_eq!(request.get(4..172), original.request.get(4..172));
            assert_eq!(request.get(204..301), original.request.get(204..301));
            assert_ne!(request.get(172..204), original.request.get(172..204));
        }
        // Acknowledge only the dropped records whose exact identity and fresh
        // recovery challenge were checked above; fixture shutdown rejects leftovers.
        unprocessed.clear();
        eprintln!("PEER_ROSTER_COMMAND kind={cut:?} processed_outcomes={outcomes:?} unchanged_command_and_target=true fresh_challenge=true");
    }

    fs::rename(
        g.c.path.join("independent-sdk-held"),
        g.c.path.join("independent-sdk"),
    )?;
    assert_eq!(
        g.peer_roster(
            "peer-roster-exact-retry-after-cut",
            &g.args(
                "peer-roster-admit",
                &[public.as_os_str().into(), "admit".into()]
            )
        )?,
        "peer-roster-admitted\n"
    );
    assert_eq!(
        snapshot(&g.c)?,
        recovered,
        "exact target retry did not reseal the recovered image"
    );
    eprintln!(
        "PEER_ROSTER_CUT kind={cut:?} original_target=true no_current_sdk_during_recovery=true"
    );
    Ok(recovered)
}
