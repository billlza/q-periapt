// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete foreign retirement through the shared public native replacement fixture.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;

#[test]
fn c_retired_enrollment_preserves_complete_report_and_original_erasure_across_processes(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = std::path::PathBuf::from(
        std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("C retirement executable missing")?,
    );
    fixture::retirement::exercise(Some(&client))
}
