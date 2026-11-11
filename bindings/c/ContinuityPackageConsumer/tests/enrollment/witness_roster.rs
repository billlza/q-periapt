// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real C R coordination through original enrollment, current P and network witness.
use super::*;
#[path = "witness_roster_traffic.rs"]
mod traffic;
struct RCase {
    c: Registered,
    previous: p::VerifiedDevice,
    target: p::VerifiedDevice,
    policy: p::PolicyCheckpoint,
    authorization: Option<[u8; 32]>,
    operation: p::RosterRefreshId,
}
fn invoke_r(c: &Registered, label: &str, mode: &str) -> Result<String> {
    let args = c.arguments(command(&c.path, &format!("witnessed-roster-{mode}")));
    match PolicyClient::selected_for("ROSTER")? {
        Some(client) if mode != "wrong-kind" => {
            let output = run_client(&client.executable, &c.path, label, &args)?;
            eprintln!(
                "FOREIGN_ROSTER_CALL language={} mode={mode} label={label}",
                client.language
            );
            Ok(output)
        }
        // Invalid native proposal grammar cannot be expressed by a typed value.
        _ => run(&c.path, label, &args),
    }
}
fn issue_target(c: &Registered, version: u64) -> Result<p::VerifiedDevice> {
    let roster = c.root.issue_roster(
        version,
        c.roster_validity,
        &[c.root.roster_entry(&c.certificate)?],
    )?;
    let pin = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        roster.checkpoint(),
        c.family,
    )?;
    for (name, bytes) in [
        ("roster-target", roster.as_bytes().to_vec()),
        (
            "roster-target-version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "roster-target-digest",
            roster.checkpoint().digest().to_vec(),
        ),
    ] {
        fs::write(c.path.join(name), bytes)?;
    }
    Ok(pin.verify_device(&c.certificate, roster.as_bytes(), fixture::now()?)?)
}
fn setup(
    w: &witness::Witness,
    adopted: bool,
    tls: bool,
) -> Result<(RCase, Option<witness_tls::TlsWitness>)> {
    let root = p::PolicySigningKey::generate()?;
    let mut c = registered_with_anchor_inputs(
        600,
        Some(&root),
        300,
        None,
        p::BootstrapRole::Initiator,
        Some(&w.configured),
    )?;
    let server = if tls {
        Some(witness_tls::TlsWitness::start(
            Arc::clone(&w.configured.store),
            [c.path.as_path()],
        )?)
    } else {
        None
    };
    if let Some(server) = &server {
        c.witness.as_mut().ok_or("configured witness")?.address = server.address;
        c.witness_tls = true;
    }
    let (c, policy, authorization) = if adopted {
        let f = staged(c, root)?;
        let p = super::proposal(&f.c)?;
        super::approve(&f, w, p)?;
        assert_eq!(
            invoke(&f.c, "original-P-adoption", "witness-commit")?,
            "witness-state:2\n"
        );
        (f.c, f.target, Some(f.statement))
    } else {
        let mut sdk = fixture::sdk(&c.path)?;
        let p = fixture::protocol_policy(&c.path, &sdk)?;
        let checkpoint = p.checkpoint();
        p.close();
        sdk.close();
        (c, checkpoint, None)
    };
    let pin = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        c.roster.checkpoint(),
        c.family,
    )?;
    let previous = pin.verify_historical_device(&c.certificate, c.roster.as_bytes())?;
    let target = issue_target(&c, 2)?;
    let operation = p::RosterRefreshId::generate()?;
    fixture::store(&c.path, "roster-operation", operation.as_bytes())?;
    fixture::store(&c.path, "roster-policy-source", &[u8::from(adopted)])?;
    Ok((
        RCase {
            c,
            previous,
            target,
            policy,
            authorization,
            operation,
        },
        server,
    ))
}
fn proposal(c: &Registered) -> Result<p::AnchorRosterRefreshProposal> {
    Ok(p::AnchorRosterRefreshProposal::from_trusted_state(
        &fixture::read(&c.path, "roster-proposal", 417)?,
    )?)
}
fn target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Result<Vec<u8>> {
    let p = saved.1.as_ref().ok_or("pending R")?;
    assert_eq!(p.get(..8), Some(b"QPWINT07".as_slice()));
    Ok(p.get(341..p.len().checked_sub(32).ok_or("MAC")?)
        .ok_or("saved target")?
        .to_vec())
}
fn expected(r: &RCase, phase: u32, retired: bool) -> String {
    format!(
        "{phase}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        u32::from(retired),
        hex(r.operation.as_bytes()),
        r.previous.roster().checkpoint().version(),
        hex(&r.previous.roster().checkpoint().digest()),
        r.target.roster().checkpoint().version(),
        hex(&r.target.roster().checkpoint().digest()),
        r.policy.version(),
        hex(&r.policy.digest()),
        u32::from(r.authorization.is_some()),
        hex(&r.authorization.unwrap_or([0; 32]))
    )
}
fn approve(r: &RCase, w: &witness::Witness, p: p::AnchorRosterRefreshProposal) -> Result<()> {
    assert_eq!(
        p.scope(),
        &p::RosterRefreshScope {
            operation: r.operation,
            previous: r.previous.roster().checkpoint(),
            target: r.target.roster().checkpoint(),
            policy: r.policy,
            policy_authorization: r.authorization
        }
    );
    let path = if r.authorization.is_some() {
        r.c.path.join("independent-sdk")
    } else {
        r.c.path.clone()
    };
    let mut sdk = fixture::sdk(&path)?;
    let policy = fixture::protocol_policy(&path, &sdk)?;
    assert_eq!(
        w.configured
            .store
            .lock()
            .map_err(|_| "witness")?
            .prepare_roster_refresh(p, &r.previous, &r.target, &policy, fixture::now()?)?,
        p::AnchorRosterRefreshState::Prepared
    );
    policy.close();
    sdk.close();
    Ok(())
}
fn prepare(r: &RCase) -> Result<p::AnchorRosterRefreshProposal> {
    assert_eq!(
        invoke_r(
            &r.c,
            &format!("R-prepare-{}", hex(r.operation.as_bytes())),
            "prepare"
        )?,
        "roster-prepared\n"
    );
    assert_eq!(
        invoke_r(
            &r.c,
            &format!("R-exact-inspection-{}", hex(r.operation.as_bytes())),
            "recover"
        )?,
        "roster-exact-preparation\n"
    );
    assert_eq!(
        invoke_r(
            &r.c,
            &format!("R-reserved-{}", hex(r.operation.as_bytes())),
            "progress"
        )?,
        expected(r, 2, false)
    );
    proposal(&r.c)
}
#[test]
fn c_roster_retains_exact_terminal_and_original_owner_under_p0_and_independent_p_tcp_tls(
) -> Result<()> {
    for tls in [false, true] {
        for adopted in [false, true] {
            for closed in [false, true] {
                let mut w = witness::Witness::start()?;
                let (mut r, mut tls_server) = setup(&w, adopted, tls)?;
                if adopted {
                    let before = enrollment_row(&r.c)?;
                    assert_eq!(
                        invoke_r(&r.c, "R-no-policy-fallback", "prepare-wrong-policy")?,
                        "roster-refused:103\n"
                    );
                    assert_eq!(enrollment_row(&r.c)?, before);
                }
                let p = prepare(&r)?;
                let saved = snapshot(&r.c)?;
                assert_eq!(
                    invoke_r(&r.c, "R-unavailable", "reconcile")?,
                    "roster-state:5\n"
                );
                assert_eq!(snapshot(&r.c)?, saved);
                assert_eq!(
                    invoke_r(&r.c, "R-no-local-abandon", "abandon-refused")?,
                    "roster-abandon-refused\n"
                );
                for (mode, code) in [("substitute", 211), ("wrong-kind", 101), ("cancelled", 302)] {
                    assert_eq!(
                        invoke_r(&r.c, &format!("R-{mode}"), mode)?,
                        format!("roster-refused:{code}\n")
                    );
                }
                approve(&r, &w, p)?;
                assert_eq!(
                    invoke_r(&r.c, "R-prepared", "reconcile")?,
                    "roster-state:1\n"
                );
                let signer = Zeroizing::new(fs::read(r.c.path.join("signer.key"))?);
                let wrapping = Zeroizing::new(fs::read(r.c.path.join("wrap.key"))?);
                assert_eq!(
                    invoke_r(&r.c, "R-terminal", if closed { "close" } else { "commit" })?,
                    format!("roster-state:{}\n", if closed { 3 } else { 2 })
                );
                assert_eq!(
                    snapshot(&r.c)?,
                    (if closed { saved.0 } else { target(&saved)? }, None)
                );
                assert_eq!(
                    invoke_r(&r.c, "R-retired", "progress")?,
                    expected(&r, if closed { 4 } else { 3 }, true)
                );
                assert_eq!(
                    invoke_r(&r.c, "R-retired-substitution", "substitute")?,
                    "roster-refused:211\n"
                );
                if adopted {
                    assert_eq!(
                        invoke(&r.c, "R-current-owner", "activate")?,
                        "independent-device-active\n"
                    );
                } else {
                    let activated = run(
                        &r.c.path,
                        "R-P0-owner",
                        &r.c.arguments(command(&r.c.path, "activate")),
                    )?;
                    let mut lines = activated.lines();
                    assert_eq!(lines.next(), Some("enrollment-active"));
                    assert_ne!(decode_id(lines.next().ok_or("next account ID")?)?, [0; 32]);
                    assert!(lines.next().is_none());
                    let active = state(&run(
                        &r.c.path,
                        "R-P0-original-status",
                        &r.c.arguments(command(&r.c.path, "status")),
                    )?)?;
                    assert_eq!(active.1, r.c.accepted.1);
                    assert_eq!(active.2, r.c.accepted.2);
                }
                assert_eq!(fs::read(r.c.path.join("signer.key"))?, *signer);
                assert_eq!(fs::read(r.c.path.join("wrap.key"))?, *wrapping);
                // A later issuer request must expose the actual roster, not the old
                // request's pre-R pin. It does not itself reserve or adopt a new P.
                if !closed {
                    let operation = p::PolicyRenewalId::generate()?;
                    if adopted {
                        // The C fixture uses create-new outputs. Retain the first
                        // policy operation/request rather than overwrite its evidence.
                        for name in ["independent-operation", "independent-request"] {
                            fs::rename(
                                r.c.path.join(name),
                                r.c.path.join(format!("{name}-before-roster")),
                            )?;
                        }
                    }
                    fs::write(r.c.path.join("independent-operation"), operation.as_bytes())?;
                    let before = enrollment_row(&r.c)?;
                    assert_eq!(
                        invoke(&r.c, "P-request-after-R", "witness-request")?,
                        "request-saved\n"
                    );
                    let request = read_request(&r.c.path)?;
                    assert_eq!(request.scope.current_roster, r.target.roster().checkpoint());
                    assert_eq!(request.scope.previous_policy, r.policy);
                    assert_eq!(request.scope.previous_authorization, r.authorization);
                    assert_eq!(enrollment_row(&r.c)?, before);
                }
                // Exercise next R after either terminal without guessing its predecessor.
                if adopted && !tls {
                    if !closed {
                        r.previous = r.target.clone();
                    }
                    for name in [
                        "roster-proposal",
                        "roster-operation",
                        "roster-target",
                        "roster-target-version",
                        "roster-target-digest",
                    ] {
                        fs::rename(
                            r.c.path.join(name),
                            r.c.path.join(format!("{name}-first-retired")),
                        )?;
                    }
                    r.target = issue_target(&r.c, 3)?;
                    r.operation = p::RosterRefreshId::generate()?;
                    fs::write(r.c.path.join("roster-operation"), r.operation.as_bytes())?;
                    let q = prepare(&r)?;
                    approve(&r, &w, q)?;
                    assert_eq!(invoke_r(&r.c, "R-successor", "commit")?, "roster-state:2\n");
                    assert_eq!(
                        invoke_r(&r.c, "R-successor-progress", "progress")?,
                        expected(&r, 3, true)
                    );
                }
                for name in [
                    "sdk.redb",
                    "sdk-policy",
                    "sdk-signature",
                    "sdk-root",
                    "tls-cert",
                    "tls-key",
                    "signer.key",
                ] {
                    let p = r.c.path.join(name);
                    fs::rename(&p, p.with_extension("held"))?;
                }
                if adopted {
                    fs::rename(
                        r.c.path.join("independent-sdk"),
                        r.c.path.join("independent-sdk-held"),
                    )?;
                }
                assert_eq!(
                    invoke_r(&r.c, "R-history-without-live-owners", "progress")?,
                    expected(&r, if adopted && !tls || !closed { 3 } else { 4 }, true)
                );
                if let Some(server) = &mut tls_server {
                    assert!(server.admitted.load(Ordering::Acquire) > 0);
                    assert!(server.finish()?.is_empty());
                }
                w.join()?;
            }
        }
    }
    eprintln!("C_ROSTER_LIFECYCLE cases=8 TCP_TLS=true P0_independent_P=true exact_target=true original_owner=true next_R=true next_P_request=true");
    Ok(())
}
#[test]
fn c_roster_processed_commit_and_ack_losses_recover_original_target_without_current_runtime(
) -> Result<()> {
    for (closed, cut) in [(false, 36u8), (false, 39u8), (true, 39u8)] {
        let mut w = witness::Witness::start()?;
        let (r, _) = setup(&w, true, false)?;
        let p = prepare(&r)?;
        let saved = snapshot(&r.c)?;
        approve(&r, &w, p)?;
        w.arm(cut)?;
        assert_eq!(
            invoke_r(
                &r.c,
                "R-lost",
                if closed { "close-lost" } else { "commit-lost" }
            )?,
            "roster-refused:218\n"
        );
        assert_eq!(w.fault.load(Ordering::Acquire), 0);
        assert!(snapshot(&r.c)?.1.is_some());
        if cut == 39 {
            assert_eq!(
                invoke_r(&r.c, "R-durable-terminal", "progress")?,
                expected(&r, if closed { 4 } else { 3 }, false)
            );
        }
        let before = calls(&w)?;
        assert_eq!(
            invoke_r(&r.c, "R-full-proposal-guard", "substitute")?,
            "roster-refused:211\n"
        );
        assert_eq!(calls(&w)?, before);
        for name in [
            "sdk.redb",
            "sdk-policy",
            "sdk-signature",
            "sdk-root",
            "tls-cert",
            "tls-key",
        ] {
            let p = r.c.path.join(name);
            fs::rename(&p, p.with_extension("held"))?;
        }
        fs::rename(
            r.c.path.join("independent-sdk"),
            r.c.path.join("independent-sdk-held"),
        )?;
        for label in ["R-historical-recovery", "R-exact-retired-retry"] {
            assert_eq!(
                invoke_r(&r.c, label, "reconcile")?,
                format!("roster-state:{}\n", if closed { 3 } else { 2 })
            );
        }
        assert_eq!(
            snapshot(&r.c)?,
            (if closed { saved.0 } else { target(&saved)? }, None)
        );
        assert_eq!(
            invoke_r(&r.c, "R-completed-original", "progress")?,
            expected(&r, if closed { 4 } else { 3 }, true)
        );
        assert!(w
            .captured
            .lock()
            .map_err(|_| "captures")?
            .iter()
            .any(|r| !r.delivered && r.request.get(204) == Some(&(cut - 20))));
        w.join()?;
    }
    eprintln!("C_ROSTER_REPLY_LOSS cases=3 actual_processed_reply=true preserved_pending=true no_current_runtime=true original_result=true");
    Ok(())
}
#[test]
fn c_roster_failed_initial_head_query_retains_unprepared_intent_and_can_abandon_without_witness_terminal(
) -> Result<()> {
    let mut w = witness::Witness::start()?;
    let (r, _) = setup(&w, true, false)?;
    let before = snapshot(&r.c)?;
    w.arm(21)?;
    assert_eq!(
        invoke_r(&r.c, "R-head-query-loss", "prepare-lost")?,
        "roster-refused:218\n"
    );
    assert_eq!(w.fault.load(Ordering::Acquire), 0);
    assert_eq!(snapshot(&r.c)?, before);
    assert_eq!(
        invoke_r(&r.c, "R-staged-original", "progress")?,
        expected(&r, 1, false)
    );
    assert_eq!(
        invoke_r(&r.c, "R-no-local-target", "recover-absent")?,
        "roster-local-absence\n"
    );
    for name in [
        "sdk.redb",
        "sdk-policy",
        "sdk-signature",
        "sdk-root",
        "tls-cert",
        "tls-key",
        "signer.key",
    ] {
        let p = r.c.path.join(name);
        fs::rename(&p, p.with_extension("held"))?;
    }
    fs::rename(
        r.c.path.join("independent-sdk"),
        r.c.path.join("independent-sdk-held"),
    )?;
    let called = calls(&w)?;
    assert_eq!(
        invoke_r(&r.c, "R-local-abandon", "abandon")?,
        expected(&r, 5, false)
    );
    assert_eq!(
        invoke_r(&r.c, "R-local-abandon-retry", "abandon")?,
        expected(&r, 5, false)
    );
    assert_eq!(calls(&w)?, called);
    assert_eq!(snapshot(&r.c)?, before);
    w.join()?;
    eprintln!("C_ROSTER_UNPREPARED actual_query_failure=true no_target=true local_abandonment_distinct=true no_signer_runtime_or_network=true");
    Ok(())
}
