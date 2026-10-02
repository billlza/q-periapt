// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{BootstrapContext, BootstrapRole, SessionReopenRequest};
use std::sync::Arc;

/// Original established peer session checked against an already owned device
/// service. This retains public identity owners, not a separate journal lease or
/// durable permission; every operation still requires current native admission.
pub struct ReopenedPeer {
    context: Arc<BootstrapContext>,
    role: BootstrapRole,
    session: [u8; 32],
}
impl ReopenedPeer {
    /// Exact original message-session identity selected by the caller.
    pub fn session_id(&self) -> [u8; 32] {
        self.session
    }
    /// Independently selected local role, verified against the original record.
    pub fn role(&self) -> BootstrapRole {
        self.role
    }
    /// Borrow verified public context ownership for the existing native engines.
    /// This object cannot reopen storage or bypass a closed/revoked service.
    pub fn context(&self) -> &Arc<BootstrapContext> {
        &self.context
    }
}

impl DeviceService {
    /// Restore another existing peer under this service's original installation,
    /// journal and archive leases. No second installation is opened. Exact local
    /// owner, policy, witness profile, session, role and archive must match;
    /// current identity, rosters, send budget and witness are rechecked.
    /// This does not create a peer session or admit a fresh bootstrap. A later
    /// operation must recheck authority; retaining this descriptor is not a grant.
    pub fn reopen_peer(
        &mut self,
        request: SessionReopenRequest,
        now: u64,
    ) -> Result<ReopenedPeer, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        let SessionReopenRequest {
            context,
            role,
            session,
        } = request;
        context.check_session_identity(now)?;
        if owners.installation.status()? != InstallationStatus::Active
            || scope(
                &owners.installation.paths,
                owners.installation.identity,
                owners.installation.key_binding,
                context.device(role),
                context.policy(),
            )? != owners.installation.scope
        {
            return Err(DurableError::Conflict);
        }
        owners
            .archives
            .require(&owners.journal, &context, session)?;
        owners
            .journal
            .check_reopened_session(&context, session, role, now)?;
        context.check_session_identity(now)?;
        Ok(ReopenedPeer {
            context,
            role,
            session,
        })
    }
}

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
        let (journal, archives) = installation.open_children(key, device, policy, anchor)?;
        let mut service = DeviceService {
            active: Some(ServiceOwners {
                journal,
                archives,
                installation,
            }),
        };
        let peer = service.reopen_peer(
            SessionReopenRequest {
                context,
                role,
                session,
            },
            now,
        )?;
        Ok(ReopenedSession {
            service,
            context: peer.context,
            role: peer.role,
            session: peer.session,
        })
    }
}
