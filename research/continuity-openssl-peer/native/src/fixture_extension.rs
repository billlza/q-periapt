// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit test-authority outputs; original issuance is retained independently.
use super::*;
use q_periapt_continuity_identity_candidate::IssuedRoster;

pub(super) fn publish_original_policy(
    directory: &Path,
    authority: &PolicySigningKey,
    runtime: &Arc<Runtime>,
    witness: Option<&Arc<crate::witness::Witness>>,
    budget: u16,
) -> Result<()> {
    let issued = authority.issue_session_policy(
        runtime,
        SessionPolicyParameters::new(
            1,
            Validity::new(100, 160)?,
            AllowedPrekeyModes::new(&[PrekeyQuality::ReusableBoth])?,
            witness.map_or_else(AnchorRequirement::local_only, |w| {
                AnchorRequirement::required(&w.pin)
            }),
            ApplicationSendBudget::new(budget)?,
        )?,
    )?;
    let mut head = issued.checkpoint().version().to_be_bytes().to_vec();
    head.extend_from_slice(&issued.checkpoint().digest());
    save(directory, "original-policy", issued.as_bytes())?;
    save(directory, "original-pin-policy-head", &head)
}

pub(super) fn credential(
    directory: &Path,
    root: &RootSigningKey,
    original: Vec<u8>,
    family: [u8; 32],
    times: Times,
) -> Result<(Vec<u8>, IssuedRoster)> {
    let roster = root.issue_roster(
        1,
        Validity::new(100, 160)?,
        &[root.roster_entry(&original)?],
    )?;
    let pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let previous = pin.verify_device(&original, roster.as_bytes(), NOW)?;
    if times.bootstrap != 210
        || pin
            .verify_device(&original, roster.as_bytes(), times.bootstrap)
            .is_ok()
    {
        return Err("extension fixture must cross the original credential expiry".into());
    }
    save(directory, "original-i-credential", &original)?;
    save(directory, "original-i-roster", roster.as_bytes())?;
    let mut head = roster.checkpoint().version().to_be_bytes().to_vec();
    head.extend_from_slice(&roster.checkpoint().digest());
    save(directory, "original-i-checkpoint", &head)?;
    let mut clocks = times.bootstrap.to_be_bytes().to_vec();
    clocks.extend_from_slice(&times.traffic.to_be_bytes());
    save(directory, "extension-clocks", &clocks)?;
    let certificate = root.issue_credential_extension(&previous, 300, times.bootstrap)?;
    let roster = root.issue_roster(
        2,
        Validity::new(times.bootstrap, 300)?,
        &[root.roster_entry(&certificate)?],
    )?;
    Ok((certificate, roster))
}
