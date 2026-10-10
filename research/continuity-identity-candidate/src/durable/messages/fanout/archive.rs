// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Whole-batch cleanup from the persisted original session archive index.
use super::*;
use crate::{durable::anchoring::cleanup_signer_binding, AnchorClient, SessionArchiveStore};

struct Binding {
    id: FanoutId,
    account: [u8; 32],
    metadata: [u8; 32],
    members: Vec<Member>,
    archives: Vec<SessionClosureArchive>,
}
fn metadata(batch: &Batch) -> [u8; 32] {
    digest(&label(b"account-fanout-metadata/v1"), &batch.metadata())
}
impl Binding {
    fn retain(
        image: &Image,
        key: &JournalKey,
        batch: Batch,
        index: &mut SessionArchiveStore,
        authority: Option<&crate::RetainedInstallationAuthority>,
    ) -> Result<(Self, [u8; 32]), DurableError> {
        let mut archives = Vec::with_capacity(batch.members.len());
        let mut signer = None;
        // The authenticated batch chooses the complete set. No caller-supplied
        // subset, duplicate or replacement can change aggregate membership.
        for member in &batch.members {
            let archive = index.get(member.session).map_err(|error| match error {
                DurableError::Absent => DurableError::ArchiveRequired,
                error => error,
            })?;
            let current = archive.authenticate_fanout_member(
                key,
                JournalIdentity(image.id),
                image,
                batch.account,
                member,
            )?;
            if let Some(authority) = authority {
                archive.check_installation(
                    key,
                    JournalIdentity(image.id),
                    authority.owner,
                    authority.policy,
                    authority.witness,
                )?;
            }
            if signer.is_some_and(|saved| saved != current) {
                return Err(DurableError::Conflict);
            }
            signer = Some(current);
            archives.push(archive);
        }
        let binding = Self {
            id: batch.id,
            account: batch.account,
            metadata: metadata(&batch),
            members: batch.members,
            archives,
        };
        Ok((binding, signer.ok_or(DurableError::Corrupt)?))
    }
    fn check(&self, image: &Image, key: &JournalKey) -> Result<Option<Batch>, DurableError> {
        for (member, archive) in self.members.iter().zip(&self.archives) {
            archive.authenticate_fanout_member(
                key,
                JournalIdentity(image.id),
                image,
                self.account,
                member,
            )?;
        }
        match codec::get(image, self.id) {
            Ok(batch) if metadata(&batch) == self.metadata => Ok(Some(batch)),
            Err(DurableError::Protocol(Error::Retired)) => {
                // Retirement preserves every original session/archive binding.
                // Reserved abandonment retains one exact whole-batch report;
                // committed members instead retain their separate settled facts.
                let mut report = None;
                let mut abandoned = 0;
                for member in &self.members {
                    let record = image
                        .records
                        .get(&record_id(&member.session))
                        .ok_or(DurableError::Corrupt)?;
                    if record.phase == DurableStatus::MessagesAbandoned {
                        let terminal = Retired::decode(&record.payload)?;
                        if terminal.batch == Some(self.id) {
                            if terminal.pending != Some(member.message)
                                || report.is_some_and(|saved| saved != terminal.report)
                            {
                                return Err(DurableError::Conflict);
                            }
                            report = Some(terminal.report);
                            abandoned += 1;
                            continue;
                        }
                    }
                    codec::check_settled_member(image, member)?;
                }
                if abandoned != 0 && abandoned != self.members.len() {
                    return Err(DurableError::Conflict);
                }
                Ok(None)
            }
            Ok(_) => Err(DurableError::Conflict),
            Err(error) => Err(error),
        }
    }
}

/// Exclusive cleanup-only owner for one existing whole fanout batch. It loads
/// every member's original authenticated archive from the bounded index, without
/// creating verified device/policy/context objects or accepting a recipient subset.
/// No bootstrap, data, control, key generation or storage provisioning is exposed.
pub struct FanoutAbandonmentJournal {
    journal: DeviceJournal,
    binding: Binding,
}
impl FanoutAbandonmentJournal {
    /// Reopen a local-only batch using its independently retained journal and batch
    /// identities plus the original archive index. Missing/invalid state fails.
    pub fn open(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        batch: FanoutId,
        archives: &mut SessionArchiveStore,
    ) -> Result<Self, DurableError> {
        Self::open_inner(path, key, expected, batch, archives, None, None)
    }
    /// Reopen with the original pinned witness and enrolled signing owner. Local
    /// policy expiry does not weaken witness enrollment or permit a local fallback.
    pub fn open_anchored(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        batch: FanoutId,
        archives: &mut SessionArchiveStore,
        client: AnchorClient,
    ) -> Result<Self, DurableError> {
        Self::open_inner(path, key, expected, batch, archives, Some(client), None)
    }
    // Standalone callers above already supply their independent journal identity
    // and key. An installation owner additionally checks every authenticated
    // archive against its retained authority BEFORE any pending write is resolved.
    pub(crate) fn open_installed(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        id: FanoutId,
        archives: &mut SessionArchiveStore,
        client: Option<AnchorClient>,
        authority: &crate::RetainedInstallationAuthority,
    ) -> Result<Self, DurableError> {
        Self::open_inner(path, key, expected, id, archives, client, Some(authority))
    }
    fn open_inner(
        path: &Path,
        key: JournalKey,
        expected: JournalIdentity,
        id: FanoutId,
        archives: &mut SessionArchiveStore,
        client: Option<AnchorClient>,
        authority: Option<&crate::RetainedInstallationAuthority>,
    ) -> Result<Self, DurableError> {
        archives.check_identity(expected)?;
        let db = open_private_database(path)?;
        let (image, pending) = write_intent::load_cleanup_snapshot(&db, &key, expected)?;
        if let Some(authority) = authority {
            let required = match image.protection {
                Protection::Local => None,
                Protection::Required {
                    policy, witness, ..
                } => Some((policy, witness)),
            };
            // Even absence/retirement must describe this installation. Reject a
            // differently scoped journal before any witness query or write.
            authority.check(image.owner, required)?;
        }
        match (image.protection, client.is_some()) {
            (Protection::Local, false) | (Protection::Required { .. }, true) => {}
            (Protection::Required { .. }, false) => return Err(DurableError::AnchorRequired),
            _ => return Err(DurableError::Conflict),
        }
        let signer = client
            .as_ref()
            .map(|client| {
                client
                    .signer_public_key()
                    .map(|key| cleanup_signer_binding(&key))
            })
            .transpose()?;
        let mut active = Active {
            db,
            key,
            owner: image.owner,
            id: image.id,
            protection: image.protection,
            anchor: None,
            account_authority: None,
            enrollment_completion: None,
        };
        if let Some(client) = client {
            active.attach_retained_cleanup_subject(client)?;
        }
        let target = pending
            .as_ref()
            .map(|pending| pending.authenticated_target(&active.key, active.owner))
            .transpose()?;
        let (admitted, batch) = match codec::get(&image, id) {
            Ok(batch) => (&image, batch),
            Err(DurableError::Absent) if target.is_some() => {
                let target = target.as_ref().ok_or(DurableError::Corrupt)?;
                // Only a previously sealed exact reservation can provide missing
                // membership. An unrelated intent grants no permission to invent it.
                let batch = codec::get(target, id).map_err(|error| match error {
                    DurableError::Absent | DurableError::Protocol(Error::Retired) => {
                        DurableError::Suspended
                    }
                    error => error,
                })?;
                (target, batch)
            }
            Err(error @ (DurableError::Absent | DurableError::Protocol(Error::Retired))) => {
                if pending.is_some() {
                    return Err(DurableError::Suspended);
                }
                // These are affirmative lifecycle dispositions: stale local state
                // alone must not report absence/retirement under required protection.
                active.check_current(&image)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let (binding, original_signer) =
            Binding::retain(admitted, &active.key, batch, archives, authority)?;
        if signer.is_some_and(|signer| signer != original_signer) {
            return Err(DurableError::Conflict);
        }
        if let Some(target) = &target {
            binding.check(target, &active.key)?;
        }
        // All exact membership/archive checks precede any recovery write.
        if let Some(pending) = pending {
            write_intent::reconcile(&mut active, &pending)?;
        }
        let current = load(&active.db, &active.key, active.owner)?;
        binding.check(&current, &active.key)?;
        active.check_current(&current)?;
        Ok(Self {
            journal: DeviceJournal {
                active: Some(active),
            },
            binding,
        })
    }
    fn current(&mut self) -> Result<(Image, Option<Batch>), DurableError> {
        let image = self.journal.image()?;
        let key = &self
            .journal
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .key;
        let batch = self.binding.check(&image, key)?;
        Ok((image, batch))
    }
    /// Query local aggregate state; commitment does not imply peer consumption.
    pub fn status(&mut self) -> Result<FanoutStatus, DurableError> {
        let (_, batch) = self.current()?;
        Ok(batch.map_or(FanoutStatus::Retired, |batch| batch.status()))
    }
    /// Read every original committed or accounted-abandoned member through the
    /// retained batch/archive binding. This needs no current traffic authority
    /// and releases no ciphertext. Reserved or unacknowledged abandonment uses
    /// its complete loss-report path instead; retired metadata is explicit.
    pub fn reconcile_members(&mut self) -> Result<FanoutReconciliation, DurableError> {
        let (image, batch) = self.current()?;
        let Some(batch) = batch else {
            self.journal.check_release(&image)?;
            return Err(Error::Retired.into());
        };
        if !matches!(
            batch.state,
            BatchState::Committed(_) | BatchState::Abandoned(_)
        ) {
            return Err(DurableError::Suspended);
        }
        let members = batch
            .members
            .iter()
            .map(|member| {
                let state = match codec::record_output(&image, &batch, member)? {
                    FanoutOutput::Committed(_) => FanoutMemberState::Committed,
                    FanoutOutput::Acknowledged => FanoutMemberState::Acknowledged,
                    FanoutOutput::ResolutionPending => FanoutMemberState::ResolutionPending,
                    FanoutOutput::DeliveryUnknown => FanoutMemberState::DeliveryUnknown,
                    FanoutOutput::HistoryRetired => FanoutMemberState::HistoryRetired,
                    FanoutOutput::ReservationAbandoned => FanoutMemberState::ReservationAbandoned,
                };
                Ok(FanoutMemberStatus {
                    device: member.device,
                    session: member.session,
                    message: member.message,
                    state,
                })
            })
            .collect::<Result<Vec<_>, DurableError>>()?;
        self.journal.check_release(&image)?;
        Ok(FanoutReconciliation {
            batch: batch.id,
            members,
        })
    }
    /// Irreversibly freeze every member and return the complete immutable loss
    /// report. Committed batches cannot be reclassified as reserved abandonment.
    pub fn begin(&mut self) -> Result<FanoutAbandonment, DurableError> {
        let (image, batch) = self.current()?;
        self.journal
            .begin_fanout_cleanup(image, batch.ok_or(Error::Retired)?)
    }
    /// Only after durable, deduplicated host accounting of the complete report,
    /// erase every member's logical private state in one aggregate transition.
    pub fn acknowledge(&mut self, report: FanoutAbandonmentId) -> Result<(), DurableError> {
        let (image, batch) = self.current()?;
        self.journal
            .acknowledge_fanout_cleanup(image, batch.ok_or(Error::Retired)?, report)
    }
    /// Retire only metadata once every original member is separately settled, or
    /// the complete reserved abandonment has been acknowledged. Original sessions,
    /// bootstrap/one-time claims and the monotonic counter remain. An unknown
    /// commit requires reopening; an authenticated Retired result proves retirement.
    pub fn retire_metadata(&mut self) -> Result<(), DurableError> {
        let (image, batch) = self.current()?;
        if let Some(batch) = batch {
            if !matches!(
                batch.state,
                BatchState::Committed(_) | BatchState::Abandoned(_)
            ) {
                return Err(DurableError::Suspended);
            }
            self.journal.retire_fanout_cleanup(image, batch)?;
            #[cfg(all(test, unix))]
            tests::after_stage("fanout-archive-retired");
            Ok(())
        } else {
            self.journal.check_release(&image)
        }
    }
    /// Drop the private-key owner, database lease and witness client. Index
    /// ownership remains with its caller; owner shutdown does not abandon a batch.
    pub fn close(&mut self) {
        self.journal.close();
    }
}
