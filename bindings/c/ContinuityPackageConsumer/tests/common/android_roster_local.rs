// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh local roster adapter call chain; no peer-traffic or witness qualification.
use crate::{fixture, independent_inputs, issue_grant, run_foreign, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

use crate::android_roster_traffic as traffic;

#[test]
fn original_roster_advance() -> Result<()> {
    exercise(false)
}
#[test]
fn remote_roster_advance() -> Result<()> {
    exercise(true)
}
fn exercise(remote: bool) -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("roster cases")?);
    let driver = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("roster driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    for profile in ["fixed", "recoverable"] {
        let base = output.join(profile);
        let inputs = base.join("inputs");
        fs::DirBuilder::new().mode(0o700).create(&base)?;
        fs::DirBuilder::new().mode(0o700).create(&inputs)?;
        let reference = fixture::setup_expiring_policy(None, 1800)?;
        let (root, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
        publish_private_bytes(&inputs.join("witness-carrier"), b"local")?;
        let run =
            |mode: &str, label: &str| run_foreign(&driver, profile, &inputs, &base, mode, label);
        let request = run("policy-create", "original.request")?;
        let (certificate, original) = issue_grant(&inputs, &root, &intent, validity, &request)?;
        let target = root.issue_roster(2, validity, &[root.roster_entry(&certificate)?])?;
        for (name, value) in [
            ("renewal-roster", target.as_bytes().to_vec()),
            ("renewal-version", 2u64.to_be_bytes().to_vec()),
            ("renewal-digest", target.checkpoint().digest().to_vec()),
        ] {
            publish_private_bytes(&inputs.join(name), &value)?;
        }
        let prepared = run("policy-prepare", "prepared")?;
        assert_eq!(prepared.len(), 164);
        assert_eq!(run("policy-activate", "activated.request")?, request);
        let identity = run("policy-identity", "original.identity")?;
        assert_eq!(identity.len(), 64);
        assert_eq!(
            identity.get(32..).ok_or("identity journal")?,
            prepared.get(4..36).ok_or("prepared journal")?
        );
        let traffic_case = traffic::Case {
            base: &base,
            inputs: &inputs,
            reference: &reference,
            witness: None,
        };
        let traffic = traffic::Traffic::begin(&traffic_case, &root, &certificate, &original, &run)?;
        if remote {
            crate::android_roster_peer::advance(&traffic_case, &run)?;
        }
        for (mode, label, expected) in [
            ("roster-refused", "bad-signature", 102u32),
            ("roster-cancelled", "cancelled", 302u32),
        ] {
            assert_eq!(run(mode, label)?, expected.to_be_bytes());
            assert_eq!(
                run("roster-identity", &format!("{label}-identity"))?,
                identity
            );
        }
        let refreshed = run("roster-refresh", "refreshed")?;
        assert_eq!(refreshed.len(), 148);
        assert_eq!(
            refreshed.get(..4).ok_or("status phase")?,
            6u32.to_be_bytes()
        );
        assert_eq!(refreshed.get(4..68).ok_or("status identity")?, identity);
        let previous = [
            original.checkpoint().version().to_be_bytes().as_slice(),
            original.checkpoint().digest().as_slice(),
        ]
        .concat();
        let current = [
            target.checkpoint().version().to_be_bytes().as_slice(),
            target.checkpoint().digest().as_slice(),
        ]
        .concat();
        assert_eq!(refreshed.get(68..108).ok_or("previous roster")?, previous);
        assert_eq!(refreshed.get(108..).ok_or("target roster")?, current);
        assert_eq!(run("roster-refresh", "refreshed-replay")?, refreshed);
        assert_eq!(
            run("roster-resolve-pending", "pending-resolution")?,
            215u32.to_be_bytes()
        );
        assert_eq!(run("roster-activate", "activated.identity")?, identity);
        traffic.resume(&traffic_case, &root, &target, &run)?;
        if remote {
            crate::android_roster_peer::revoke(&traffic_case, &run)?;
        }
        assert_eq!(run("roster-identity", "final.identity")?, identity);
        let calls = if remote { 23 } else { 16 };
        println!("qualified local roster adapter {profile}: {calls} Java processes; original identity journal session message and one effect across local R2 advancement");
    }
    Ok(())
}
