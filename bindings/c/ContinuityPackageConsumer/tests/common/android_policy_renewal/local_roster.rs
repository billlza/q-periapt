// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local R under explicitly selected P2 after original P0 has actually expired.
use super::*;

pub(super) fn advance(case: &Case<'_>, identity: &[u8]) -> Result<()> {
    assert!(case.witness.is_none());
    assert!(fixture::now()? >= case.policy.validity().until());
    let target = case.root.issue_roster(
        2,
        case.validity,
        &[case.root.roster_entry(case.certificate)?],
    )?;
    for (name, bytes) in [
        ("renewal-roster", target.as_bytes().to_vec()),
        (
            "renewal-version",
            target.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", target.checkpoint().digest().to_vec()),
    ] {
        publish_private_bytes(&case.inputs.join(name), &bytes)?;
    }
    let run = |mode: &str, label: &str| {
        case.run(
            &format!("roster-selected-{mode}"),
            &format!("roster-{label}"),
        )
    };
    for (mode, label, expected) in [
        ("original-expired", "original-expired", 104u32),
        ("unselected", "no-policy-fallback", 1),
        ("refused", "bad-signature", 102),
        ("cancelled", "cancelled", 302),
    ] {
        assert_eq!(run(mode, label)?, expected.to_be_bytes());
        assert_eq!(run("identity", &format!("{label}-identity"))?, identity);
    }
    let refreshed = run("refresh", "refreshed")?;
    assert_eq!(refreshed.len(), 148);
    assert_eq!(
        refreshed.get(..4).ok_or("roster phase")?,
        6u32.to_be_bytes()
    );
    assert_eq!(refreshed.get(4..68).ok_or("roster identity")?, identity);
    for (range, checkpoint) in [
        (68..108, case.roster.checkpoint()),
        (108..148, target.checkpoint()),
    ] {
        let expected = [
            checkpoint.version().to_be_bytes().as_slice(),
            checkpoint.digest().as_slice(),
        ]
        .concat();
        assert_eq!(refreshed.get(range).ok_or("roster checkpoint")?, expected);
    }
    assert_eq!(run("refresh", "refreshed-replayed")?, refreshed);
    assert_eq!(
        run("resolve-pending", "pending-resolution")?,
        215u32.to_be_bytes()
    );
    assert_eq!(run("activate", "activated-identity")?, identity);
    crate::android_roster_traffic::admit_peer(
        &crate::android_roster_traffic::Case {
            base: case.base,
            inputs: case.inputs,
            reference: case.reference,
            witness: None,
        },
        case.root,
        &target,
        true,
    )?;
    publish_private_bytes(
        &case.base.join("roster-local-completed"),
        &target.checkpoint().version().to_be_bytes(),
    )?;
    Ok(())
}
