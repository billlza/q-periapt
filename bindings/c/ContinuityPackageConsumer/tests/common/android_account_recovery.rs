// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original Java first-use installation, complete results and authenticated index restore.
use crate::Result;
use std::{fs, path::Path};

#[test]
fn first_use() -> Result<()> {
    super::run_profiles(true)
}

pub(super) fn run(
    base: &Path,
    inputs: &Path,
    run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
) -> Result<()> {
    let next = run("account-next", "recovery-next-before")?;
    let result = run("recovery-account-query", "recovery-original-results")?;
    let operation = fs::read(inputs.join("account-operation"))?;
    assert_eq!(result.len(), 204);
    assert_eq!(result.get(..32).ok_or("operation")?, operation);
    assert_eq!(result.get(32..36).ok_or("members")?, 2u32.to_be_bytes());
    let sessions = fs::read(base.join("sessions"))?;
    let mut original = Vec::new();
    for index in 0..2 {
        let delivered = fs::read(base.join(format!("cancel-resumed-{index}")))?;
        let member = result
            .get(36 + index * 84..36 + (index + 1) * 84)
            .ok_or("reconciled member")?;
        // Compare the complete set independently of caller target ordering.
        original.push(delivered.get(..80).ok_or("delivery identity")?.to_vec());
        assert_eq!(member.get(80..).ok_or("member state")?, 2u32.to_be_bytes());
    }
    original.sort();
    for (index, expected) in original.iter().enumerate() {
        assert_eq!(
            result
                .get(36 + index * 84..116 + index * 84)
                .ok_or("canonical member")?,
            expected
        );
    }
    for index in 0..2 {
        let session = sessions
            .get(index * 32..(index + 1) * 32)
            .ok_or("original session")?;
        fs::write(inputs.join("recovery-session"), session)?;
        let frozen = run(
            "recovery-session-freeze",
            &format!("recovery-frozen-{index}"),
        )?;
        assert_eq!(frozen.len(), 32);
        assert_eq!(
            run("recovery-session-ack", &format!("recovery-ack-{index}"))?,
            frozen
        );
        let archive = run(
            "recovery-session-retire",
            &format!("recovery-retired-{index}"),
        )?;
        assert_eq!(archive.len(), 362);
        assert_eq!(
            run(
                "recovery-archive-tamper",
                &format!("recovery-tamper-{index}")
            )?,
            208u32.to_be_bytes()
        );
        assert_eq!(
            run(
                "recovery-archive-restore",
                &format!("recovery-restored-{index}")
            )?,
            archive
        );
    }
    assert_eq!(
        run("recovery-account-retire", "recovery-final-results")?,
        result
    );
    assert_eq!(
        run("recovery-account-retired", "recovery-account-retired")?,
        112u32.to_be_bytes()
    );
    assert_eq!(run("account-next", "recovery-next-after")?, next);
    Ok(())
}
