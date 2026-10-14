// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configured Android recovery preserves one real unknown delivery and R2 intent.
use crate::{
    android_roster_traffic, android_witness::witness, fixture, independent_inputs, issue_grant, p,
    run_foreign, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes as retain;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    time::{Duration, Instant},
};

const POLICY_SECONDS: u64 = 180;

#[path = "android_pending_write/accounting.rs"]
mod accounting;
#[path = "android_pending_write/flow.rs"]
mod flow;
#[path = "android_pending_write/transport.rs"]
mod transport;
use accounting::{roster_metadata, ExpectedEffect, Request};

#[test]
fn signed_fixed_unapplied() -> Result<()> {
    flow::exercise("signed", "fixed", false)
}
#[test]
fn signed_fixed_applied() -> Result<()> {
    flow::exercise("signed", "fixed", true)
}
#[test]
fn signed_recoverable_unapplied() -> Result<()> {
    flow::exercise("signed", "recoverable", false)
}
#[test]
fn signed_recoverable_applied() -> Result<()> {
    flow::exercise("signed", "recoverable", true)
}
#[test]
fn tls_fixed_unapplied() -> Result<()> {
    flow::exercise("tls", "fixed", false)
}
#[test]
fn tls_fixed_applied() -> Result<()> {
    flow::exercise("tls", "fixed", true)
}
#[test]
fn tls_recoverable_unapplied() -> Result<()> {
    flow::exercise("tls", "recoverable", false)
}
#[test]
fn tls_recoverable_applied() -> Result<()> {
    flow::exercise("tls", "recoverable", true)
}
