// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared by signed witness and TLS carriers, independent of operational SDK authority.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Shared one-way cancellation signal. Cancellation cannot undo a journal commit.
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicBool>);
impl Default for Cancellation {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
}
impl Cancellation {
    /// Stop further dispatch; the owner and exact pending operation remain available.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Whether cancellation has been requested; there is no reset operation.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
