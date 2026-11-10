// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public Android enrollment for independently authorized replacement account roots.
use crate::{
    android_root_owned::{prepared, store},
    fixture, independent_inputs, issue_grant, p, Result,
};
use std::{fs, os::unix::fs::DirBuilderExt, path::Path};
pub(crate) struct Target {
    pub root: p::RootSigningKey,
    pub certificate: Vec<u8>,
    pub roster: p::IssuedRoster,
    pub device: p::VerifiedDevice,
    pub genesis: p::AnchorGenesis,
}
pub(crate) fn create(
    source: &Path,
    inputs: &Path,
    policy: &p::VerifiedSessionPolicy,
    name: &str,
    run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
) -> Result<Target> {
    let selected = inputs.join(name);
    fs::DirBuilder::new().mode(0o700).create(&selected)?;
    let (root, intent, validity) = independent_inputs(source, &selected)?;
    let request = run(&format!("{name}-create"), &format!("{name}.request"))?;
    let (certificate, roster) = issue_grant(&selected, &root, &intent, validity, &request)?;
    let device = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        policy.family(),
    )?
    .verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
    let genesis = prepared(
        &run(&format!("{name}-prepare"), &format!("{name}.prepared"))?,
        &device,
        policy,
    )?;
    store(inputs, &format!("{name}-account"), &root.account_id()?)?;
    Ok(Target {
        root,
        certificate,
        roster,
        device,
        genesis,
    })
}
