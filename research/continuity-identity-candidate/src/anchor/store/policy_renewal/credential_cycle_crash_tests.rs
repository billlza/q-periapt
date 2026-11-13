// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kill the real witness after durable mutation and before the reply escapes.
use super::*;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn retained_policy_credential_process_loss_preserves_commit_close_and_ack() {
    for cut in 0..4 {
        let mut c = Case::new();
        let (a, p) = adopted(&mut c);
        let g = grant(&c, &c.device, 2);
        let p = proposal(&c, &a, &g, p.target_head());
        c.store
            .prepare_policy_renewed_credential_renewal(p, &g, &c.original, &c.target, 180)
            .expect("prepare exact G");
        if cut >= 2 {
            let op = if cut == 2 {
                AnchorOperation::commit_credential_renewal(&p)
            } else {
                AnchorOperation::close_credential_renewal(&p)
            };
            let expected = if cut == 2 {
                GState::Applied
            } else {
                GState::Closed
            };
            assert_eq!(exchange(&mut c, &p, op, 180), expected);
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
        let request =
            AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("original signed request");
        fs::write(c.server.join("request.bin"), request.as_bytes())
            .expect("retain original request");
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
                .expect("owned witness process"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !c.server.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "original cut not reached: {cut}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !c.server.join("returned-reply").exists(),
            "reply cannot escape before cut"
        );
        child.0.kill().expect("SIGKILL owned witness");
        assert!(!child.0.wait().expect("reap").success());
        c.reopen();
        assert_eq!(c.fingerprint().0, revision);
        assert_eq!(exchange(&mut c, &p, op, 500), expected);
        assert_eq!(
            c.fingerprint().0,
            revision,
            "no second mutation on original retry"
        );
        explicit_format(&mut c);
    }
}
