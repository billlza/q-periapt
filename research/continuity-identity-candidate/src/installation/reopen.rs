// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{BootstrapContext, BootstrapRole, SessionReopenRequest};
use std::sync::Arc;

/// Existing service and its exact restored session identity. Admission remains
/// mandatory at every subsequent protocol operation; no key bytes are exposed.
pub struct ReopenedSession {
    service: DeviceService,
    context: Arc<BootstrapContext>,
    role: BootstrapRole,
    session: [u8; 32],
}
impl ReopenedSession {
    /// Original session selected by the caller and verified against durable state.
    pub fn session_id(&self) -> [u8; 32] {
        self.session
    }
    /// Verified local role in that existing session.
    pub fn role(&self) -> BootstrapRole {
        self.role
    }
    /// Transfer the same exclusive service lease and authenticated context owners.
    pub fn into_parts(self) -> (DeviceService, Arc<BootstrapContext>) {
        (self.service, self.context)
    }
}
impl DeviceInstallation {
    /// Reopen only an Active installation and a live established message session.
    /// Missing children, unfinished bootstrap, closure, wrong bindings, revoked
    /// membership or unavailable required witness return no operational owner.
    /// This entry never provisions, activates Creating state or replaces an archive.
    pub fn reopen_session(
        paths: InstallationPaths,
        key: JournalKey,
        request: SessionReopenRequest,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<ReopenedSession, DurableError> {
        let SessionReopenRequest {
            context,
            role,
            session,
        } = request;
        context.check_session_identity(now)?;
        let device = context.device(role);
        let policy = context.policy();
        let mut installation = Self::open_bound(paths, &key, device, policy)?;
        if installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        let (mut journal, mut archives) =
            installation.open_children(key, device, policy, anchor)?;
        archives.require(&journal, &context, session)?;
        journal.check_reopened_session(&context, session, role, now)?;
        context.check_session_identity(now)?;
        Ok(ReopenedSession {
            service: DeviceService {
                active: Some(ServiceOwners {
                    journal,
                    archives,
                    installation,
                }),
            },
            context,
            role,
            session,
        })
    }
}
