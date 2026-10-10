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
    fn local_identity(&self) -> ([u8; 32], [u8; 16]) {
        (
            self.original_device.account_id(),
            self.original_device.device_id(),
        )
    }
    fn check_peer_binding(
        &mut self,
        context: &BootstrapContext,
        role: BootstrapRole,
    ) -> Result<(), DurableError> {
        context.check_storage_binding(
            *self.installation.identity.as_bytes(),
            self.authority.owner,
            Some(role),
        )?;
        if self.installation.status()? != InstallationStatus::Active
            || self.local_identity()
                != (
                    context.device(role).account_id(),
                    context.device(role).device_id(),
                )
            || scope_for_owner(
                &self.installation.paths,
                self.installation.identity,
                self.installation.key_binding,
                context.role_storage_owner(role),
                context.original_policy(),
            )? != self.installation.scope
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}

impl DeviceService {
    /// Durably adopt an independently approved, authenticated retirement of a
    /// known peer account at this installation's pinned witness. Verification of
    /// the receipt alone has no side effects; this explicit call fences cached
    /// and fresh old-root operations while retaining historical record identities.
    ///
    /// Retain the original proposal and receipt on failure. Reopen the original
    /// owner and repeat this exact operation with current local authorization;
    /// failure can follow commit. A conflicting original operation is refused.
    /// This does not activate the successor, select an application-account mapping,
    /// retire the local account or transfer trust to another witness.
    pub fn retire_peer_account(
        &mut self,
        retirement: &crate::AnchorRetiredAccount,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<(), DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        if owners.installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        owners.journal.retire_peer_account(
            &PolicyScope {
                authority: &owners.authority,
                original_policy: &owners.original_policy,
                original_device: &owners.original_device,
            },
            retirement,
            policy,
            now,
        )
    }

    /// Install an independently authenticated monotonic roster for a known remote
    /// account through this original active device service and its current policy.
    /// The local account must use its original enrollment R transaction instead.
    /// An unknown account, different root/family, rollback or same-version fork
    /// is refused; a canonical identical head keeps the first retained bytes.
    ///
    /// The account authority and canonical target checkpoint identify this public
    /// head update. Retain the original signed target on failure, reopen the same
    /// owner and retry it with current authorization. I/O or witness failure may
    /// follow commit and never proves no-commit. A later head refuses the old retry;
    /// it does not report whether that older attempt once committed. Success means
    /// the target is currently installed, not that this invocation first wrote it.
    /// Revoked/expired local authority cannot use a cached identical target. No
    /// session, batch or message authority is returned by this operation.
    pub fn admit_peer_roster(
        &mut self,
        roster: &crate::VerifiedRoster,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<crate::RosterCheckpoint, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        if owners.installation.status()? != InstallationStatus::Active
            || roster.account_id() == owners.local_identity().0
        {
            return Err(DurableError::Conflict);
        }
        owners.journal.install_peer_roster(
            &PolicyScope {
                authority: &owners.authority,
                original_policy: &owners.original_policy,
                original_device: &owners.original_device,
            },
            roster,
            policy,
            now,
        )
    }

    /// Atomically admit an independently verified peer credential renewal bound
    /// to this installation's original P0. The original operation must be retained
    /// by the caller. The same target is only an exact original-operation readback;
    /// another current head, observed revocation or conflicting operation fails.
    /// This cannot renew the local device or change its installation policy.
    /// After policy continuation, current P1, the exact completed authorization and current
    /// local membership are required; a previously live P0 is not a fallback.
    /// A root-signed same-account roster can revoke this local device. That
    /// observed checkpoint remains committed even if the final local admission
    /// then fails. Query original durable progress; an error does not mean NoCommit.
    /// It does not by itself produce a continued peer or release application data.
    pub fn admit_peer_credential_renewal(
        &mut self,
        renewal: &crate::VerifiedCredentialRenewal,
        operation: crate::CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<crate::RosterCheckpoint, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        let successor = renewal.successor_device();
        if owners.installation.status()? != InstallationStatus::Active
            || owners.local_identity() == (successor.account_id(), successor.device_id())
        {
            return Err(DurableError::Conflict);
        }
        owners.journal.install_peer_credential_renewal(
            &PolicyScope {
                authority: &owners.authority,
                original_policy: &owners.original_policy,
                original_device: &owners.original_device,
            },
            renewal,
            operation,
            policy,
            now,
        )
    }
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
        let context = owners
            .journal
            .prepare_bootstrap_context(context, role, now)?;
        owners.check_peer_binding(&context, role)?;
        context.check(now)?;
        Ok(BootstrapPeer { context, role })
    }

    /// Authenticate an original public bundle and restore only its exact existing
    /// session through this active service. Expired historical credentials require
    /// a current root renewal grant already committed in the original journal.
    /// Original independent pins, policy owner, local installation and archive
    /// remain mandatory. A returned context cannot bootstrap another session.
    pub fn reopen_peer_bundle(
        &mut self,
        bundle: &crate::BootstrapBundle,
        policy: Arc<crate::VerifiedSessionPolicy>,
        required: crate::BootstrapRequirements<'_>,
        role: BootstrapRole,
        session: [u8; 32],
        now: u64,
    ) -> Result<ReopenedPeer, DurableError> {
        let request = bundle.historical_reopen(policy, required, role, session, now)?;
        self.reopen_peer(request, now)
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
        let context = owners
            .journal
            .prepare_reopened_context(context, session, role, now)?;
        Self::finish_peer_reopen(owners, context, role, session, now)
    }
    /// Restore only the selected original established session under current P1
    /// and the exact joint or policy-only authorization completed in this journal.
    /// The caller independently verifies P1. No caller-supplied T or owner hash
    /// overrides durable state. New bootstrap/prekey permission is not granted.
    pub fn reopen_continued_peer(
        &mut self,
        request: SessionReopenRequest,
        policy: Arc<crate::VerifiedSessionPolicy>,
        now: u64,
    ) -> Result<ReopenedPeer, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        let SessionReopenRequest {
            context,
            role,
            session,
        } = request;
        let context = owners
            .journal
            .prepare_continued_context(context, session, role, policy, now)?;
        Self::finish_peer_reopen(owners, context, role, session, now)
    }
    fn finish_peer_reopen(
        owners: &mut ServiceOwners,
        context: Arc<BootstrapContext>,
        role: BootstrapRole,
        session: [u8; 32],
        now: u64,
    ) -> Result<ReopenedPeer, DurableError> {
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
    /// Open the same Active installation and original archive under completed
    /// policy continuation. Historical P0 authenticates storage; P1
    /// admits current operations only after the journal checks exact authorization, session,
    /// local role and current membership. No expired P0 runtime is reconstructed.
    /// Required protection additionally needs the original witness carrier and
    /// fresh exact G/T admission. This never falls back to local protection.
    pub fn reopen_continued_session(
        paths: InstallationPaths,
        key: JournalKey,
        request: SessionReopenRequest,
        policy: Arc<crate::VerifiedSessionPolicy>,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<ReopenedSession, DurableError> {
        let mut service = Self::reconcile_original_enrollment(
            paths,
            key,
            request.context.device(request.role),
            request.context.original_policy(),
            anchor,
        )?;
        let peer = service.reopen_continued_peer(request, policy, now)?;
        Ok(ReopenedSession {
            service,
            context: peer.context,
            role: peer.role,
            session: peer.session,
        })
    }
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
        let policy = context.current_policy()?;
        let mut installation = Self::open_bound(paths, &key, device, policy)?;
        if installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        let (journal, archives) = installation.open_children(key, device, policy, anchor)?;
        let mut service = DeviceService {
            active: Some(ServiceOwners {
                original_device: device.clone(),
                authority: crate::RetainedInstallationAuthority::active_installation(
                    device, policy,
                ),
                original_policy: policy.historical().clone(),
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
