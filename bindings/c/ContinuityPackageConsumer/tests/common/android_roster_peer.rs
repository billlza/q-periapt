// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent remote root issues R2; Android retains its original peer materials.
use crate::{android_roster_traffic, fixture, p, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;

pub(crate) fn advance(
    case: &android_roster_traffic::Case<'_>,
    run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
) -> Result<()> {
    let root = case
        .reference
        .responder_issuer
        .as_ref()
        .ok_or("remote account issuer")?;
    let peer = case.inputs.join("peer");
    assert_eq!(
        root.account_id()?,
        fixture::array::<32>(&peer, "responder-account")?
    );
    assert_eq!(
        root.public_key()?.encode(),
        fixture::read(&peer, "responder-root", 1985)?
    );
    let previous = u64::from_be_bytes(fixture::array(&peer, "responder-roster-version")?);
    let certificate = fixture::read(&case.reference.responder, "local-certificate", 8192)?;
    let now = fixture::now()?;
    let target = root.issue_roster(
        previous.checked_add(1).ok_or("remote roster version")?,
        p::Validity::new(now, now.checked_add(1200).ok_or("remote roster validity")?)?,
        &[root.roster_entry(&certificate)?],
    )?;
    let checkpoint = target.checkpoint();
    for (name, bytes) in [
        ("remote-roster", target.as_bytes().to_vec()),
        (
            "remote-roster-version",
            checkpoint.version().to_be_bytes().to_vec(),
        ),
        ("remote-roster-digest", checkpoint.digest().to_vec()),
    ] {
        publish_private_bytes(&case.inputs.join(name), &bytes)?;
    }
    for (mode, label, expected) in [
        ("roster-bad", "remote-roster-bad", 102u32),
        ("roster-checkpoint", "remote-roster-checkpoint", 105),
        ("roster-cancelled", "remote-roster-cancelled", 302),
    ] {
        assert_eq!(run(&case.mode(mode), label)?, expected.to_be_bytes());
    }
    let admitted = run(&case.mode("roster-admit"), "remote-roster-admitted")?;
    assert_eq!(admitted.len(), 72);
    assert_eq!(
        admitted.get(..8).ok_or("remote version")?,
        checkpoint.version().to_be_bytes()
    );
    assert_eq!(
        admitted.get(8..40).ok_or("remote digest")?,
        checkpoint.digest()
    );
    publish_private_bytes(
        &case.inputs.join("remote-roster-next"),
        admitted.get(40..).ok_or("remote next slot")?,
    )?;
    assert_eq!(
        run(&case.mode("roster-reopen"), "remote-roster-reopened")?,
        admitted
    );
    // The original bootstrap bundle and pins stay unchanged across admission.
    assert_eq!(
        u64::from_be_bytes(fixture::array(&peer, "responder-roster-version")?),
        previous
    );
    Ok(())
}

pub(crate) fn revoke(
    case: &android_roster_traffic::Case<'_>,
    run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
) -> Result<()> {
    let root = case
        .reference
        .responder_issuer
        .as_ref()
        .ok_or("remote account issuer")?;
    let now = fixture::now()?;
    let removed = root.issue_roster(
        3,
        p::Validity::new(now, now.checked_add(1200).ok_or("revocation time")?)?,
        &[],
    )?;
    let checkpoint = removed.checkpoint();
    for (name, bytes) in [
        ("remote-roster-revoked", removed.as_bytes().to_vec()),
        (
            "remote-roster-revoked-version",
            checkpoint.version().to_be_bytes().to_vec(),
        ),
        ("remote-roster-revoked-digest", checkpoint.digest().to_vec()),
    ] {
        publish_private_bytes(&case.inputs.join(name), &bytes)?;
    }
    let expected = [
        checkpoint.version().to_be_bytes().as_slice(),
        checkpoint.digest().as_slice(),
    ]
    .concat();
    assert_eq!(
        run(&case.mode("roster-revoke"), "remote-roster-revoked")?,
        expected
    );
    assert_eq!(
        run(
            &case.mode("roster-revoked-reopen"),
            "remote-roster-revoked-reopened"
        )?,
        expected
    );
    Ok(())
}
