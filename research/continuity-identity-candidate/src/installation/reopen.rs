// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{BootstrapContext, BootstrapRole, SessionReopenRequest};
use std::sync::Arc;

/// Fresh verified public peer context checked against one active device service.
/// Admission creates no session, reservation or durable roster. The first actual
/// bootstrap still checks current authority and reserves its original operation.
pub struct BootstrapPeer {
    context: Arc<BootstrapContext>,
    role: BootstrapRole,
}
impl BootstrapPeer {
    /// Local role checked against the original installation owner.
    pub fn role(&self) -> BootstrapRole {
        self.role
    }
    /// Borrow verified public input ownership for the existing native bootstrap.
    /// Retaining this descriptor does not extend time or runtime authorization.
    pub fn context(&self) -> &Arc<BootstrapContext> {
        &self.context
    }
}

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

impl ServiceOwners {
    fn check_peer_binding(
        &mut self,
        context: &BootstrapContext,
        role: BootstrapRole,
    ) -> Result<(), DurableError> {
        if self.installation.status()? != InstallationStatus::Active
            || scope(
                &self.installation.paths,
                self.installation.identity,
                self.installation.key_binding,
                context.device(role),
                context.policy(),
            )? != self.installation.scope
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}

impl DeviceService {
    /// Admit a freshly verified public context under this original active service.
    /// The caller verifies its bundle against independently retained pins first.
    /// Current advertisement, credential, policy/runtime and installed roster
    /// checks apply; an unknown peer account uses its verified initial snapshot
    /// only for this preview. No roster is installed or advanced, and no session,
    /// prekey or operation is reserved. The original witness must freshly admit
    /// the unchanged journal. A later bootstrap repeats all operation-time checks.
    pub fn admit_peer(
        &mut self,
        context: Arc<BootstrapContext>,
        role: BootstrapRole,
        now: u64,
    ) -> Result<BootstrapPeer, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        context.check(now)?;
        owners.check_peer_binding(&context, role)?;
        owners.journal.check_bootstrap_peer(&context, role, now)?;
        context.check(now)?;
        Ok(BootstrapPeer { context, role })
    }

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
        owners.check_peer_binding(&context, role)?;
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
