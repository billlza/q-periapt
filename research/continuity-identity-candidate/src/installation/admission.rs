// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{AnchorClient, JournalAccountAuthority};

/// Explicit original witness and account-registry owners for installation admission.
/// The descriptor grants no authority by itself: activation and reopening check
/// the original journal, current registry and required witness before release.
///
/// Existing unmanaged callers can continue to pass `Option<AnchorClient>`.
/// A journal already bound to a registry rejects that form; supply its original
/// managed descriptor again. Missing or closed state never selects another route.
pub struct InstallationAdmission {
    pub(crate) anchor: Option<AnchorClient>,
    pub(crate) account: Option<JournalAccountAuthority>,
}

impl InstallationAdmission {
    /// Carry the independently selected original registry and witness together.
    /// Initial activation may durably bind an unbound witnessed journal before
    /// returning its service. Session reopening requires the binding to exist
    /// already; it never adopts a registry or repairs missing storage.
    ///
    /// Keep the registry owner live for the service's entire lifetime. A cloned
    /// account descriptor cannot keep a closed parent alive. An activation error
    /// may follow a durable binding; retry the exact original admission.
    pub fn managed(anchor: AnchorClient, account: JournalAccountAuthority) -> Self {
        Self {
            anchor: Some(anchor),
            account: Some(account),
        }
    }
}

impl From<Option<AnchorClient>> for InstallationAdmission {
    fn from(anchor: Option<AnchorClient>) -> Self {
        Self {
            anchor,
            account: None,
        }
    }
}
