// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public wrapper failures use typed native errors; C-only raw-buffer controls
//! remain in the separately qualified C test, never weakened or skipped here.
use super::*;

#[test]
fn public_wrapper_rejects_request_substitution_and_pre_cancelled_stage() -> Result<()> {
    let f = prepare()?;
    assert_eq!(
        invoke(&f.c, "public-original-stage", "stage")?,
        expected_status(1, &f.request, f.statement, f.target)
    );
    for (mode, code) in [
        ("stage-corrupt-scope", 103),
        ("stage-corrupt-certificate", 102),
        ("stage-cancelled", 302),
    ] {
        let before = enrollment_row(&f.c)?;
        assert_eq!(
            invoke(&f.c, &format!("public-{mode}"), mode)?,
            format!("stage-refused:{code}\n")
        );
        assert!(
            enrollment_row(&f.c)? == before,
            "public wrapper failure replaced the original intent"
        );
    }
    foreign_policy_case("local-refusals")?;
    eprintln!("PUBLIC_POLICY_REFUSALS scope=true signature=true cancellation=true typed_native_errors=true original_pending_unchanged=true");
    Ok(())
}
