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
#[path = "android_pending_write/cancellation.rs"]
mod cancellation;
#[path = "android_pending_write/flow.rs"]
mod flow;
#[path = "android_pending_write/process_loss.rs"]
mod process_loss;
#[path = "android_pending_write/transport.rs"]
mod transport;
use accounting::{roster_metadata, ExpectedEffect, Request};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cut {
    None,
    Cancellation,
    ProcessLoss,
}
impl Cut {
    fn suffix(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Cancellation => "-query-cancel",
            Self::ProcessLoss => "-process-loss",
        }
    }
    fn query_count(self) -> usize {
        match self {
            Self::None => 2,
            Self::Cancellation => 3,
            Self::ProcessLoss => 4,
        }
    }
}

pub(crate) fn exercise_query_cancel(carrier: &str, profile: &str, applied: bool) -> Result<()> {
    flow::exercise_with_cut(carrier, profile, applied, Cut::Cancellation)
}
pub(crate) fn exercise_process_loss(carrier: &str, profile: &str, applied: bool) -> Result<()> {
    flow::exercise_with_cut(carrier, profile, applied, Cut::ProcessLoss)
}

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
