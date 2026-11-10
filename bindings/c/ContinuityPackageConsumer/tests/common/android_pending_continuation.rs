// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{android_pending_write, Result};

#[test]
fn signed_fixed_unapplied() -> Result<()> {
    android_pending_write::exercise_continuation("signed", "fixed", false)
}
#[test]
fn tls_recoverable_applied() -> Result<()> {
    android_pending_write::exercise_continuation("tls", "recoverable", true)
}
