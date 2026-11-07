//! Explicit reclamation of versioned, unpublished publication attempts.
use std::{fmt, io, path::Path};

/// Work bounds for one maintenance traversal, not operational storage limits.
#[derive(Clone, Copy, Debug)]
pub struct PublicationCleanupLimits {
    /// Maximum visited payload files and directories, including the root.
    pub entries: usize,
    /// Maximum payload depth; the payload root has depth one.
    pub depth: usize,
    /// Maximum sum of regular-file lengths admitted in the traversal.
    pub bytes: u64,
}
impl Default for PublicationCleanupLimits {
    fn default() -> Self {
        Self {
            entries: 1024,
            depth: 32,
            bytes: 256 * 1024 * 1024,
        }
    }
}
impl PublicationCleanupLimits {
    fn validate(self) -> Result<(), PublicationMaintenanceError> {
        if self.entries == 0
            || self.entries > 4096
            || self.depth == 0
            || self.depth > 64
            || self.bytes > 4 * 1024 * 1024 * 1024
        {
            return Err(PublicationMaintenanceError::Limit);
        }
        Ok(())
    }
}

/// A successful observation or the durable result of the original cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationCleanupOutcome {
    /// No payload and no cleanup intent were present. This does not prove that
    /// publication succeeded and never authorizes recreating a formal target.
    NoPayload,
    /// Original cleanup completed; retries return the original retained totals.
    Reclaimed {
        /// Original number of payload entries, including its root.
        entries: u64,
        /// Original sum of regular-file lengths, not physical erasure evidence.
        bytes: u64,
    },
}

/// Maintenance refuses unbound/legacy state, live owners, excess work or I/O failure.
#[derive(Debug)]
pub enum PublicationMaintenanceError {
    /// The original private scope, version, identity or record differs.
    Invalid,
    /// A publisher or payload owner still holds an exclusive lease.
    Busy,
    /// The explicit work budget cannot admit the whole remaining payload.
    Limit,
    /// The platform adapter is unavailable.
    Unsupported,
    /// Original I/O/backend failure. Payload removal may have partially completed;
    /// retain the same control record and retry this original attempt.
    Io(io::Error),
}
impl fmt::Display for PublicationMaintenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("publication maintenance scope or record differs"),
            Self::Busy => f.write_str("publication maintenance has an active owner"),
            Self::Limit => f.write_str("publication maintenance work budget exceeded"),
            Self::Unsupported => f.write_str("publication maintenance adapter unavailable"),
            Self::Io(error) => write!(f, "publication maintenance I/O failed: {error}"),
        }
    }
}
impl std::error::Error for PublicationMaintenanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for PublicationMaintenanceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reclaim only a versioned attempt's unpublished payload under its original lease.
///
/// `attempt` is the private control directory, never the formal destination.
/// Old prefix-only residues, incomplete metadata and missing/replaced leases are
/// refused. The normal operational-store opener still rejects empty files.
/// No published target is followed or deleted. All remaining payload entries are
/// admitted and their file leases acquired before any deletion. An I/O failure
/// may follow partial cleanup: reopen this same attempt; its durable intent and
/// receipt preserve the original operation's totals. Completed control records
/// remain retained. This is not physical erasure or hostile same-UID isolation.
pub fn reclaim_private_publication(
    attempt: &Path,
    limits: PublicationCleanupLimits,
) -> Result<PublicationCleanupOutcome, PublicationMaintenanceError> {
    limits.validate()?;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        windows
    ))]
    {
        attempt::reclaim(attempt, limits)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        windows
    )))]
    {
        let _ = attempt;
        Err(PublicationMaintenanceError::Unsupported)
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
))]
mod attempt;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
))]
mod record;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
))]
mod tree;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
))]
pub(in crate::filesystem) use attempt::ManagedAttempt;
