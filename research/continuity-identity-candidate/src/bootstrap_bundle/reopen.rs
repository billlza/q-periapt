// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{BootstrapRole, HistoricalSessionPolicy};

/// Authenticated historical identity awaiting admission by its original durable
/// installation. It exposes no context, journal, key or operational authority.
pub struct SessionReopenRequest {
    pub(crate) context: Arc<BootstrapContext>,
    pub(crate) role: BootstrapRole,
    pub(crate) session: [u8; 32],
}

fn snapshot_start(
    policy: &HistoricalSessionPolicy,
    required: &BootstrapRequirements<'_>,
    m: &BootstrapMaterials<'_>,
    now: u64,
) -> Result<u64, Error> {
    let mut start = policy.validity().from();
    for (expected, certificate, roster) in [
        (
            required.initiator,
            m.initiator_credential,
            m.initiator_roster,
        ),
        (
            required.responder,
            m.responder_credential,
            m.responder_roster,
        ),
    ] {
        start = start.max(expected.account.snapshot_start(certificate, roster)?);
    }
    for bytes in [
        Some(m.signed_classical),
        Some(m.last_resort_pq),
        m.one_time_classical,
        m.one_time_pq,
    ]
    .into_iter()
    .flatten()
    {
        start = start.max(LeafProof::decode(bytes)?.untrusted_start());
    }
    if start > now {
        return Err(Error::Validity);
    }
    Ok(start)
}

impl BootstrapBundle {
    /// Authenticate the original public snapshot for an explicitly selected,
    /// already established session. Independent pins and the same live policy
    /// owner remain mandatory. This never admits a new bootstrap or repairs state.
    ///
    /// Advertisement and snapshot-roster expiry may be historical; credentials,
    /// policy and runtime must still be valid now. DeviceInstallation::reopen_session
    /// must match the authenticated context to existing durable state and check
    /// current roster authority, signed budget, archives and any required witness.
    pub fn request_reopen(
        &self,
        policy: Arc<VerifiedSessionPolicy>,
        required: BootstrapRequirements<'_>,
        role: BootstrapRole,
        session: [u8; 32],
        now: u64,
    ) -> Result<SessionReopenRequest, Error> {
        let request = self.historical_reopen(policy, required, role, session, now)?;
        request.context.check_session_identity(now)?;
        Ok(request)
    }
    /// Authenticate an original transcript using an independently pinned signed
    /// historical policy, with no runtime owner or current permission. This request
    /// cannot activate a device or start a bootstrap. Its owning journal must
    /// independently admit a current continuation before operational use.
    pub fn request_historical_reopen(
        &self,
        policy: Arc<HistoricalSessionPolicy>,
        required: BootstrapRequirements<'_>,
        role: BootstrapRole,
        session: [u8; 32],
        now: u64,
    ) -> Result<SessionReopenRequest, Error> {
        crate::codec::nonzero(&session)?;
        let (quality, materials) = codec::decode(&self.wire)?;
        if quality != required.quality {
            return Err(Error::Scope);
        }
        let start = snapshot_start(&policy, &required, &materials, now)?;
        let AuthenticatedMaterials {
            initiator,
            responder,
            selection,
        } = authenticate_materials(materials, &required, start)?;
        // Reuse the original-input verifier, including all signatures, pins and
        // interval intersections. No VerifiedSessionPolicy is manufactured.
        let context = BootstrapContext::from_historical_inputs(
            policy,
            initiator,
            responder,
            selection,
            required.directory,
            start,
        )?;
        Ok(SessionReopenRequest {
            context: Arc::new(context),
            role,
            session,
        })
    }
    pub(crate) fn historical_reopen(
        &self,
        policy: Arc<VerifiedSessionPolicy>,
        required: BootstrapRequirements<'_>,
        role: BootstrapRole,
        session: [u8; 32],
        now: u64,
    ) -> Result<SessionReopenRequest, Error> {
        crate::codec::nonzero(&session)?;
        let (quality, m) = codec::decode(&self.wire)?;
        if quality != required.quality {
            return Err(Error::Scope);
        }
        policy.check_mode(quality, now)?;
        let start = snapshot_start(policy.historical(), &required, &m, now)?;
        // All intervals must overlap. Signed manifest containment implies its
        // start cannot exceed a verified leaf's start. The ordinary verifier
        // authenticates every input and checks every interval at this instant;
        // untrusted hints cannot skip a signature, pin, membership or time check.
        let context = Arc::new(self.verify(policy, required, start)?);
        Ok(SessionReopenRequest {
            context,
            role,
            session,
        })
    }
}
