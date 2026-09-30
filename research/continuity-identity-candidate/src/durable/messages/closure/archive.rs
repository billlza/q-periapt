// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated cleanup-only admission after the original verified objects are gone.
use super::*;
use crate::{durable::anchoring::cleanup_signer_binding, AnchorClient};

const ARCHIVE_BYTES: usize = 362;
const BODY_BYTES: usize = ARCHIVE_BYTES - 32;
const TAG: &[u8; 8] = b"QPCSCA01";

fn authenticator(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let mut derived = ZeroizingBytes::<32>::zeroed();
    Hkdf::<Sha256>::new(None, key.0.as_bytes())
        .expand(
            b"Q-PERIAPT-CONTINUITY-SESSION-CLOSURE-ARCHIVE-KEY/v1",
            derived.as_mut_bytes(),
        )
        .map_err(|_| Error::Provider)?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| Error::Provider.into())
}
struct Scope {
    journal: [u8; 32],
    binding: Binding,
    protection: Protection,
    signer: [u8; 32],
}
impl Scope {
    fn encode(&self) -> Vec<u8> {
        let b = &self.binding;
        let mut bytes = TAG.to_vec();
        for value in [self.journal, b.owner, b.local_account, b.session, b.context] {
            bytes.extend_from_slice(&value);
        }
        bytes.push(b.role);
        bytes.extend_from_slice(&b.peer_account);
        bytes.extend_from_slice(&b.peer_device);
        bytes.extend_from_slice(&b.peer_generation.to_be_bytes());
        self.protection.encode(&mut bytes);
        bytes.extend_from_slice(&self.signer);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, DurableError> {
        if bytes.len() != BODY_BYTES {
            return Err(Error::Encoding.into());
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *TAG {
            return Err(Error::Encoding.into());
        }
        let journal = d.array()?;
        let binding = Binding {
            owner: d.array()?,
            local_account: d.array()?,
            session: d.array()?,
            context: d.array()?,
            role: d.array::<1>()?[0],
            peer_account: d.array()?,
            peer_device: d.array()?,
            peer_generation: d.u64()?,
        };
        let protection = Protection::decode(&mut d)?;
        let signer = d.array()?;
        d.finish()?;
        for value in [
            journal,
            binding.owner,
            binding.local_account,
            binding.session,
            binding.context,
            binding.peer_account,
            signer,
        ] {
            crate::codec::nonzero(&value)?;
        }
        crate::codec::nonzero(&binding.peer_device)?;
        crate::codec::generation(binding.peer_generation)?;
        if !matches!(binding.role, 1 | 2) {
            return Err(Error::Encoding.into());
        }
        Ok(Self {
            journal,
            binding,
            protection,
            signer,
        })
    }
    fn check(&self, image: &Image) -> Result<(), DurableError> {
        if image.id != self.journal || image.protection != self.protection {
            return Err(DurableError::Conflict);
        }
        self.binding.check(image)?;
        Ok(())
    }
}

/// Fixed-size public metadata authenticated by a domain-separated local wrapping
/// key. Retain it before dropping the original verified context. It is not a new
/// policy, device credential, bootstrap context or rollback-protection capability.
/// Bytes alone cannot open a journal; the independent store ID and key are required.
/// Account/device linkage is public in this archive and may be privacy sensitive.
pub struct SessionClosureArchive([u8; ARCHIVE_BYTES]);
impl SessionClosureArchive {
    /// Parse the exact bounded grammar. Authentication occurs only when opening
    /// the existing journal with its wrapping key and independently retained ID.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DurableError> {
        let wire: [u8; ARCHIVE_BYTES] = bytes.try_into().map_err(|_| Error::Encoding)?;
        Scope::decode(&wire[..BODY_BYTES])?;
        Ok(Self(wire))
    }
    /// Public archival bytes. Persist them durably with the application's session
    /// identity; this method itself does not write or acknowledge persistence.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn check_index(
        &self,
        journal: JournalIdentity,
        session: [u8; 32],
    ) -> Result<(), DurableError> {
        let scope = Scope::decode(&self.0[..BODY_BYTES])?;
        if scope.journal != journal.0 || scope.binding.session != session {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn authenticate(
        &self,
        key: &JournalKey,
        expected: JournalIdentity,
    ) -> Result<Scope, DurableError> {
        let (body, tag) = self.0.split_at(BODY_BYTES);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let scope = Scope::decode(body)?;
        if scope.journal != expected.0 {
            return Err(DurableError::Conflict);
        }
        Ok(scope)
    }
}
impl DeviceJournal {
    pub(crate) fn verify_closure_archive(
        &self,
        session: [u8; 32],
        context: [u8; 32],
        archive: &SessionClosureArchive,
    ) -> Result<(), DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let scope = archive.authenticate(&active.key, JournalIdentity(active.id))?;
        if scope.binding.session != session
            || scope.binding.context != context
            || scope.binding.owner != active.owner
            || scope.protection != active.protection
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }

    /// Prepare cleanup-only metadata for an exact intended session while its
    /// original verified context is retained. Persist this archive before message
    /// activation to avoid losing cleanup scope in a crash after activation.
    /// Preparation does not admit, activate, freeze or mutate any session. Opening
    /// still requires that exact session in authenticated storage or its already
    /// sealed write intent. Export after policy close is allowed; no new operational
    /// authority results, and required witness checks still apply.
    pub fn archive_session_closure(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<SessionClosureArchive, DurableError> {
        let image = self.image()?;
        let binding = self.closure_archive_binding(&image, context, session)?;
        let devices = context.devices();
        let device = if binding.role == 1 {
            devices[0]
        } else {
            devices[1]
        };
        let scope = Scope {
            journal: image.id,
            binding,
            protection: image.protection,
            signer: cleanup_signer_binding(&device.key),
        };
        let mut wire = scope.encode();
        self.check_release(&image)?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let mut auth = authenticator(&active.key)?;
        auth.update(&wire);
        wire.extend_from_slice(&auth.finalize().into_bytes());
        SessionClosureArchive::from_bytes(&wire)
    }
}

/// Exclusive owner of one existing session's local closure. It exposes only
/// status, freeze/report, acknowledgement and owner shutdown; no bootstrap,
/// message, rekey, prekey or journal-provisioning authority can be obtained.
/// Reopening preserves all original storage/witness requirements and never uses
/// archived metadata as a fresh operational BootstrapContext.
pub struct SessionClosureJournal {
    journal: DeviceJournal,
    scope: Scope,
}
impl SessionClosureJournal {
    /// Reopen an existing local-only journal using an authenticated cleanup archive.
    /// Missing/invalid storage fails; required-witness journals cannot use this path.
    pub fn open(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        archive: &SessionClosureArchive,
    ) -> Result<Self, DurableError> {
        Self::open_inner(path, key, expected, archive, None)
    }
    /// Reopen with the original pinned witness and exact device signer. Their
    /// availability remains required after local policy expiry or revocation.
    /// A witness refusal never authorizes a local-only fallback.
    pub fn open_anchored(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        archive: &SessionClosureArchive,
        client: AnchorClient,
    ) -> Result<Self, DurableError> {
        Self::open_inner(path, key, expected, archive, Some(client))
    }
    fn open_inner(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        archive: &SessionClosureArchive,
        client: Option<AnchorClient>,
    ) -> Result<Self, DurableError> {
        let scope = archive.authenticate(&key, expected)?;
        match (scope.protection, client.is_some()) {
            (Protection::Local, false) | (Protection::Required { .. }, true) => {}
            (Protection::Required { .. }, false) => return Err(DurableError::AnchorRequired),
            _ => return Err(DurableError::Conflict),
        }
        let db = open_private_database(path)?;
        let (image, pending) = write_intent::load_snapshot(&db, &key, scope.binding.owner)?;
        // Admit only an existing exact session or its original sealed activation
        // transaction. Preparation alone grants no permission to create that state.
        match scope.check(&image) {
            Ok(()) => {}
            Err(DurableError::Absent) if pending.is_some() => {
                let target = pending
                    .as_ref()
                    .ok_or(DurableError::Absent)?
                    .authenticated_target(&key, scope.binding.owner)?;
                scope.check(&target)?;
            }
            Err(error) => return Err(error),
        }
        // An aggregate intent may also belong to another operation. Only its
        // already authenticated original command is reconciled, without new work.
        let mut active = Active {
            db,
            key,
            owner: image.owner,
            id: image.id,
            protection: image.protection,
            anchor: None,
        };
        if let Some(client) = client {
            active.attach_closure_archive(client, scope.signer)?;
        }
        if let Some(pending) = pending {
            write_intent::reconcile(&mut active, &pending)?;
        }
        let current = load(&active.db, &active.key, active.owner)?;
        scope.check(&current)?;
        active.check_current(&current)?;
        Ok(Self {
            journal: DeviceJournal {
                active: Some(active),
            },
            scope,
        })
    }
    /// Inspect only the retained session's local closure status.
    pub fn status(&mut self) -> Result<SessionClosureStatus, DurableError> {
        let image = self.journal.image()?;
        self.scope.check(&image)?;
        self.journal.closure_status(image, &self.scope.binding)
    }
    /// Permanently freeze the session and return its complete immutable loss report.
    /// A still-reserved fanout cannot be split through this independent API.
    pub fn begin(&mut self) -> Result<SessionClosure, DurableError> {
        let image = self.journal.image()?;
        self.scope.check(&image)?;
        self.journal.begin_closure(image, &self.scope.binding)
    }
    /// Erase logical private state only after durable host accounting of the exact
    /// complete report. Unknown effects require reconciliation under the same ID.
    pub fn acknowledge(&mut self, report: SessionClosureId) -> Result<(), DurableError> {
        let image = self.journal.image()?;
        self.scope.check(&image)?;
        self.journal
            .acknowledge_closure(image, &self.scope.binding, report)
    }
    /// Drop the exclusive lease, wrapping key and attached witness signing owner.
    /// This owner shutdown does not itself freeze or terminalize the session.
    pub fn close(&mut self) {
        self.journal.close();
    }
}
