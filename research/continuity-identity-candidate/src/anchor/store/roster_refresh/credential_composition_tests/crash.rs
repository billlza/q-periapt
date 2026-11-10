// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kill the same witness after commit and before a signed response can escape.
use super::*;
use std::{
    fs,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn lose_response(c: &mut Case, op: AnchorOperation) -> u64 {
    let request =
        AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("original device request");
    fs::write(c.server.join("request.bin"), request.as_bytes()).expect("original request");
    let revision = c.fingerprint().0 + 1;
    c.store.close();
    let log = fs::File::create(c.server.join("child.log")).expect("child log");
    let mut child = crate::durable::tests::ChildGuard(
        Command::new(std::env::current_exe().expect("frozen executable"))
            .args([
                "--exact",
                "anchor::store::policy_renewal::tests::independent_policy_request_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_INDEPENDENT_POLICY_SERVER_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_CRASH_REVISION", revision.to_string())
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned witness child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "durable witness boundary not reached; inspect child.log"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !c.server.join("returned-reply").exists(),
        "no response before kill"
    );
    child.0.kill().expect("SIGKILL owned process");
    assert!(!child.0.wait().expect("reap").success());
    c.reopen();
    assert_eq!(c.fingerprint().0, revision);
    revision
}

#[test]
fn g_then_r_process_loss_recovers_original_commit_close_and_ack() {
    for cut in 0..4 {
        let mut c = Case::new();
        // The existing child handles at 170. Retain independent P first so this
        // checks actual current policy admission, never a clock rollback.
        let a = c.approval(&c.original, None, &c.target);
        let pp = c.proposal(&a, c.initial, 94);
        c.prepare(pp, &a).expect("P");
        c.exchange(&pp, AnchorOperation::commit_policy_renewal(&pp), 170);
        c.exchange(&pp, AnchorOperation::acknowledge_policy_renewal(&pp), 170);
        let g = grant(&c, &c.device, 2);
        let gp = g_proposal(&c, &g, pp.target_head())
            .with_retained_policy_renewal(&a.historical())
            .expect("P bound");
        c.store
            .prepare_policy_renewed_credential_renewal(gp, &g, &c.original, &c.target, 170)
            .expect("G");
        g_exchange_at(
            &mut c,
            &gp,
            AnchorOperation::commit_credential_renewal(&gp),
            170,
        );
        g_exchange_at(
            &mut c,
            &gp,
            AnchorOperation::acknowledge_credential_renewal(&gp),
            170,
        );
        let next = same_credential_roster(&c, g.successor_device(), 3);
        let p = r_policy_proposal(
            &c,
            g.successor_device(),
            &next,
            &c.target,
            gp.target_head(),
            Some(a.statement_digest()),
        );
        c.store
            .prepare_roster_refresh(p, g.successor_device(), &next, &c.target, 170)
            .expect("R");
        if cut >= 2 {
            let op = if cut == 2 {
                AnchorOperation::commit_roster_refresh(&p)
            } else {
                AnchorOperation::close_roster_refresh(&p)
            };
            r_exchange_at(&mut c, &p, op, 170);
        }
        let (op, expected) = match cut {
            0 => (AnchorOperation::commit_roster_refresh(&p), State::Applied),
            1 => (AnchorOperation::close_roster_refresh(&p), State::Closed),
            _ => (
                AnchorOperation::acknowledge_roster_refresh(&p),
                State::Acknowledged,
            ),
        };
        let revision = lose_response(&mut c, op);
        assert_eq!(r_exchange_at(&mut c, &p, op, 700), expected);
        assert_eq!(c.fingerprint().0, revision, "exact retry is read-only");
        explicit_format(&mut c, b"QPANC020");
    }
    eprintln!("ROSTER_AFTER_CREDENTIAL_CRASH kills=4 original_witness=true historical_retry=true");
}

#[test]
fn r_then_g_process_loss_recovers_original_commit_close_and_ack() {
    for cut in 0..4 {
        let mut c = Case::new();
        let a = c.approval(&c.original, None, &c.target);
        let pp = c.proposal(&a, c.initial, 94);
        c.prepare(pp, &a).expect("P");
        c.exchange(&pp, AnchorOperation::commit_policy_renewal(&pp), 170);
        c.exchange(&pp, AnchorOperation::acknowledge_policy_renewal(&pp), 170);
        let next = same_credential_roster(&c, &c.device, 2);
        let rp = r_policy_proposal(
            &c,
            &c.device,
            &next,
            &c.target,
            pp.target_head(),
            Some(a.statement_digest()),
        );
        c.store
            .prepare_roster_refresh(rp, &c.device, &next, &c.target, 170)
            .expect("R");
        r_exchange_at(
            &mut c,
            &rp,
            AnchorOperation::commit_roster_refresh(&rp),
            170,
        );
        r_exchange_at(
            &mut c,
            &rp,
            AnchorOperation::acknowledge_roster_refresh(&rp),
            170,
        );
        let g = grant(&c, &next, 3);
        let p = g_proposal(&c, &g, rp.target_head())
            .with_retained_policy_renewal(&a.historical())
            .expect("P bound");
        c.store
            .prepare_policy_renewed_credential_renewal(p, &g, &c.original, &c.target, 170)
            .expect("G");
        if cut >= 2 {
            let op = if cut == 2 {
                AnchorOperation::commit_credential_renewal(&p)
            } else {
                AnchorOperation::close_credential_renewal(&p)
            };
            g_exchange_at(&mut c, &p, op, 170);
        }
        let (op, expected) = match cut {
            0 => (
                AnchorOperation::commit_credential_renewal(&p),
                GState::Applied,
            ),
            1 => (
                AnchorOperation::close_credential_renewal(&p),
                GState::Closed,
            ),
            _ => (
                AnchorOperation::acknowledge_credential_renewal(&p),
                GState::Acknowledged,
            ),
        };
        let revision = lose_response(&mut c, op);
        assert_eq!(g_exchange_at(&mut c, &p, op, 700), expected);
        assert_eq!(c.fingerprint().0, revision, "exact retry is read-only");
        explicit_format(&mut c, b"QPANC020");
    }
    eprintln!("CREDENTIAL_AFTER_ROSTER_CRASH kills=4 original_witness=true historical_retry=true");
}
