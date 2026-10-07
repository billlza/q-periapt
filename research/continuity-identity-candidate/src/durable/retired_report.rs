// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete metadata of a permanently retired device, never an operational owner.
use super::*;
use crate::{
    AnchorHead, AnchorRetiredCleanupProposal, AnchorRetiredReportProposal, LeafKind,
    RosterCheckpoint, Validity,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Meaning of an authenticated image relative to the permanently frozen witness head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewRole {
    /// The exact image committed at the witness before retirement.
    Authoritative,
    /// The stored source precedes the already committed sealed target.
    SupersededSource,
    /// The sealed target was retained locally but never became the frozen head.
    UncommittedTarget,
}
/// Public flights retained by a bootstrap operation. These are not delivery receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapFlights {
    /// Hash of the retained initial flight, if materialized.
    pub initial: Option<[u8; 32]>,
    /// Hash of the retained reply, without a peer confirmation claim.
    pub reply: Option<[u8; 32]>,
    /// Hash of the retained final confirmation flight.
    pub final_confirmation: Option<[u8; 32]>,
    /// Original transcript-bound session identity.
    pub session: Option<[u8; 32]>,
}
/// An uncommitted reservation, including its original aggregate identity when present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reservation {
    /// Original reservation and input lengths; no input content or hash.
    pub input: ReservedAbandonment,
    /// Original aggregate identity, or independent reservation.
    pub fanout: Option<FanoutId>,
}
/// A retained receive identity. Consumed holes are distinct from lost plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedDelivery {
    /// Original message correlation identity.
    pub message: MessageId,
    /// Original position within the receiving epoch.
    pub index: u64,
}
/// Complete retained live-epoch accounting. Older removed history is not reconstructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Epoch {
    /// Send/receive floors, outstanding ciphertext identities and unconsumed deliveries.
    pub accounting: AbandonedEpoch,
    /// Already consumed IDs above the contiguous consumed prefix; never report these as lost input.
    pub consumed_out_of_order: Vec<ConsumedDelivery>,
    /// Uncommitted input in this epoch, when retained.
    pub reservation: Option<Reservation>,
    /// Whether this local sending epoch was already closed.
    pub send_closed: bool,
}
/// Counts still retained after a previous host-acknowledged session closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalEpoch {
    /// Original retained epoch number.
    pub epoch: u64,
    /// Committed send count, excluding any reservation.
    pub sent: u64,
    /// Authenticated peer-consumed prefix retained before prior closure.
    pub acknowledged: u64,
    /// Whether prior closure discarded an uncommitted reservation.
    pub reservation_abandoned: bool,
}
/// Existing session metadata; whole-device reporting does not start a new session closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Private state remains locally, without operational access.
    Live {
        /// Every epoch still represented by this record, in ascending order.
        epochs: Vec<Epoch>,
        /// Original independent session closure report, if already pending.
        previous_closure: Option<SessionClosureId>,
    },
    /// Existing keyless metadata from a prior acknowledged closure.
    Terminal {
        /// Previously retained closure report identity; it is never replaced here.
        report: [u8; 32],
        /// Original aggregate identity.
        batch: Option<FanoutId>,
        /// Original abandoned reservation, when retained.
        pending: Option<MessageId>,
        /// Every epoch still represented by this record, in ascending order.
        epochs: Vec<TerminalEpoch>,
    },
}
/// Original session and authenticated peer binding, without a live context or secret state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    /// Original bootstrap operation owning this record.
    pub source: BootstrapOperationId,
    /// Original transcript-bound session identity.
    pub session: [u8; 32],
    /// Original bootstrap role: 1 initiator, 2 responder.
    pub role: u8,
    /// Authenticated original peer account.
    pub peer_account: [u8; 32],
    /// Authenticated original peer device.
    pub peer_device: [u8; 16],
    /// Authenticated original peer device generation.
    pub peer_generation: u64,
    /// Observed local rekey progress; no recovery-security claim.
    pub progress: RekeyProgress,
    /// Original retained disposition, without an inferred success.
    pub state: SessionState,
}
/// Reserved members have no committed ciphertext; all other outcomes retain their meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberState {
    /// Input reserved without committed ciphertext.
    Reserved,
    /// Previously retained outcome of a locally committed or abandoned member.
    Retained(FanoutMemberState),
}
/// Full original fanout recipient identity and outcome, without dispatchable bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    /// Original credential-bound recipient device.
    pub device: [u8; 16],
    /// Original credential-bound recipient generation.
    pub generation: u64,
    /// Original recipient credential digest.
    pub credential: [u8; 32],
    /// Original context or record-intent binding.
    pub context: [u8; 32],
    /// Original transcript-bound session identity.
    pub session: [u8; 32],
    /// Original bootstrap role: 1 initiator, 2 responder.
    pub role: u8,
    /// Original message correlation identity.
    pub message: MessageId,
    /// Original retained disposition, without an inferred success.
    pub state: MemberState,
    /// Exact retained ciphertext fingerprint, when still present.
    pub ciphertext_digest: Option<[u8; 32]>,
}
/// Metadata projected only through the corresponding authenticated record parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordMetadata {
    /// Original bootstrap identity, flights and prior cancellation metadata.
    Bootstrap {
        /// Original bootstrap operation, context, role and durable phase.
        entry: BootstrapEntry,
        /// Original host request identity.
        request: Option<InitiationId>,
        /// Known public flights and session identity.
        flights: BootstrapFlights,
        /// Existing cancellation receipt, never manufactured by reporting.
        cancellation: Option<Box<BootstrapCancellation>>,
    },
    /// Original public prekey identity and disposition.
    Prekey {
        /// Original host request identity.
        request: PrekeyId,
        /// Original signed leaf kind.
        kind: LeafKind,
        /// Original signed leaf validity interval.
        validity: Validity,
        /// Generated public leaf fingerprint, if one existed.
        public_fingerprint: Option<[u8; 32]>,
        /// Original bootstrap operation owning this record.
        source: Option<BootstrapOperationId>,
    },
    /// Original message-session accounting and independently authenticated peer binding.
    Session(Session),
    /// Canonical public signed roster/renewal history, containing no private journal payload.
    Roster {
        /// Original account owning this roster or recipient set.
        account: [u8; 32],
        /// Authenticated roster checkpoint.
        checkpoint: RosterCheckpoint,
        /// Canonical roster, credential and policy-history grammar, with public signatures only.
        public_history: Vec<u8>,
    },
    /// Complete original aggregate and recipient outcomes.
    Fanout {
        /// Original aggregate identity.
        batch: FanoutId,
        /// Original account owning this roster or recipient set.
        account: [u8; 32],
        /// Original recipient-set checkpoint.
        roster: RosterCheckpoint,
        /// Original aggregate phase; committed never implies peer consumption.
        status: FanoutStatus,
        /// Every original member, including reserved and previously settled members.
        members: Vec<Member>,
    },
}
/// One actual authenticated journal record. No caller-selected subset is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordMetadataEntry {
    /// Original authenticated journal record identity.
    pub id: [u8; 32],
    /// Original context or record-intent binding.
    pub context: [u8; 32],
    /// Original durable local phase.
    pub phase: DurableStatus,
    /// All original account authority references.
    pub authorities: Vec<[u8; 32]>,
    /// Permanently retained public one-time key claims.
    pub one_time_claims: Vec<[u8; 32]>,
    /// Original prekey inventory references.
    pub inventory_references: Vec<[u8; 32]>,
    /// Kind-specific metadata projected through the validated grammar.
    pub metadata: RecordMetadata,
}
/// One complete source or target image. Uncommitted-target records are candidate outcomes only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View {
    /// Meaning of this image relative to the permanently frozen witness head.
    pub role: ViewRole,
    /// Authenticated image head; interpret according to the view role.
    pub head: AnchorHead,
    /// Original local account identity.
    pub local_account: [u8; 32],
    /// Original monotonic next aggregate ordinal; not permission to allocate work.
    pub next_fanout_ordinal: u64,
    /// Every actual authenticated record, in canonical record-identity order.
    pub records: Vec<RecordMetadataEntry>,
}
/// Public original operation binding of an authenticated pending write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    /// Ordinary aggregate journal write.
    Ordinary,
    /// Original credential renewal and optional policy continuation.
    Credential {
        /// Original independently retained operation identity.
        operation: [u8; 32],
        /// Original signed authorization statement digest.
        statement: [u8; 32],
        /// Optional policy statement: true adopts it, false retains prior adoption.
        policy: Option<(bool, [u8; 32])>,
    },
    /// Independent policy-only renewal.
    Policy {
        /// Original independently retained operation identity.
        operation: [u8; 32],
        /// Original signed authorization statement digest.
        statement: [u8; 32],
    },
    /// Canonical original roster-refresh scope bytes.
    Roster(Vec<u8>),
}
/// The complete local pending record is separately fingerprinted by the inventory proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Intent {
    /// The exact authenticated inventory contained no pending record.
    None,
    /// Original sealed write without applying its target.
    Write {
        /// Original expected source head.
        expected: AnchorHead,
        /// Original sealed target head.
        target: AnchorHead,
        /// Original transaction family and public authorization binding.
        transaction: Transaction,
    },
    /// Original canonical target-free cancellation; it is not a successful ACK.
    Cancellation(Vec<u8>),
}
/// Immutable complete report. Its ID is private-keyed; it is neither an erasure permit
/// nor evidence of physical removal, remote delivery, or post-compromise recovery.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{retired_device::Report, DeviceService};
/// fn operating_service(report: Report) -> DeviceService { report }
/// ```
pub struct Report {
    proposal: AnchorRetiredReportProposal,
    intent: Intent,
    views: Vec<View>,
    bytes: Vec<u8>,
}
impl Report {
    /// Exact independently retained inventory and report identity.
    pub fn proposal(&self) -> &AnchorRetiredReportProposal {
        &self.proposal
    }
    /// Original pending operation, without a commit or cancellation claim.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    /// Complete authenticated views with explicit witness-commit meaning.
    pub fn views(&self) -> &[View] {
        &self.views
    }
    /// Canonical QPRDMD01 public metadata. Persist the complete bytes with the proposal.
    /// They contain account/device linkage and lengths; treat them as private host metadata.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(in crate::durable) fn new(
        key: &JournalKey,
        inventory: &AnchorRetiredCleanupProposal,
        intent: Intent,
        views: Vec<View>,
    ) -> Result<Self, DurableError> {
        let bytes = canonical(inventory, &intent, &views)?;
        let mut derived = ZeroizingBytes::<32>::zeroed();
        hkdf::Hkdf::<Sha256>::new(None, key.0.as_bytes())
            .expand(
                b"Q-PERIAPT-CONTINUITY-RETIRED-DEVICE-REPORT-KEY/v1",
                derived.as_mut_bytes(),
            )
            .map_err(|_| Error::Provider)?;
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
            .map_err(|_| Error::Provider)?;
        mac.update(&bytes);
        let proposal = AnchorRetiredReportProposal::from_report(
            inventory.clone(),
            mac.finalize().into_bytes().into(),
        )?;
        Ok(Self {
            proposal,
            intent,
            views,
            bytes,
        })
    }
}

struct Encoder(Vec<u8>);
impl Encoder {
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    fn raw(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    fn number(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }
    fn size(&mut self, value: usize) -> Result<(), DurableError> {
        self.number(u64::try_from(value).map_err(|_| DurableError::Capacity)?);
        Ok(())
    }
    fn blob(&mut self, value: &[u8]) -> Result<(), DurableError> {
        self.size(value.len())?;
        self.raw(value);
        Ok(())
    }
    fn option(&mut self, value: Option<&[u8]>) {
        self.byte(u8::from(value.is_some()));
        if let Some(v) = value {
            self.raw(v);
        }
    }
    fn digest(&mut self, value: &Option<[u8; 32]>) {
        self.option(value.as_ref().map(|v| v.as_slice()));
    }
    fn optional_number(&mut self, value: Option<u64>) {
        self.byte(u8::from(value.is_some()));
        if let Some(v) = value {
            self.number(v);
        }
    }
    fn list(&mut self, values: &[[u8; 32]]) -> Result<(), DurableError> {
        self.size(values.len())?;
        for v in values {
            self.raw(v);
        }
        Ok(())
    }
    fn head(&mut self, head: AnchorHead) {
        self.number(head.fence());
        self.number(head.revision());
        self.raw(&head.digest());
    }
    fn checkpoint(&mut self, checkpoint: RosterCheckpoint) {
        self.number(checkpoint.version());
        self.raw(&checkpoint.digest());
    }
    fn flights(&mut self, flights: &BootstrapFlights) {
        for v in [
            &flights.initial,
            &flights.reply,
            &flights.final_confirmation,
            &flights.session,
        ] {
            self.digest(v);
        }
    }
    fn progress(&mut self, progress: RekeyProgress) {
        self.number(progress.confirmed_epoch);
        self.number(progress.sending_epoch);
        self.number(progress.receiving_epoch);
        self.optional_number(progress.pending_epoch);
    }
    fn epoch(&mut self, epoch: &Epoch) -> Result<(), DurableError> {
        let a = &epoch.accounting;
        for v in [
            a.epoch,
            a.acknowledged_before,
            a.sent,
            a.consumed_before,
            a.received,
        ] {
            self.number(v);
        }
        self.optional_number(a.peer_sent);
        match a.resolution {
            EpochResolutionStatus::Unrequested => self.byte(0),
            EpochResolutionStatus::Pending(id) => {
                self.byte(1);
                self.raw(id.as_bytes());
            }
            EpochResolutionStatus::Acknowledged(id) => {
                self.byte(2);
                self.raw(id.as_bytes());
            }
        }
        self.size(a.unconfirmed.len())?;
        for m in &a.unconfirmed {
            self.raw(m.message_id().as_bytes());
            self.raw(m.ciphertext_digest());
        }
        self.size(a.deliveries.len())?;
        for m in &a.deliveries {
            self.raw(m.message.as_bytes());
            self.number(m.index);
            self.size(m.plaintext_bytes)?;
        }
        self.size(a.skipped.len())?;
        for v in &a.skipped {
            self.number(*v);
        }
        self.size(epoch.consumed_out_of_order.len())?;
        for m in &epoch.consumed_out_of_order {
            self.raw(m.message.as_bytes());
            self.number(m.index);
        }
        self.byte(u8::from(epoch.reservation.is_some()));
        if let Some(r) = &epoch.reservation {
            self.raw(r.input.message.as_bytes());
            self.size(r.input.plaintext_bytes)?;
            self.size(r.input.associated_data_bytes)?;
            self.option(r.fanout.as_ref().map(|id| id.as_bytes().as_slice()));
        }
        self.byte(u8::from(epoch.send_closed));
        Ok(())
    }
    fn session(&mut self, session: &Session) -> Result<(), DurableError> {
        self.raw(session.source.as_bytes());
        self.raw(&session.session);
        self.byte(session.role);
        self.raw(&session.peer_account);
        self.raw(&session.peer_device);
        self.number(session.peer_generation);
        self.progress(session.progress);
        match &session.state {
            SessionState::Live {
                epochs,
                previous_closure,
            } => {
                self.byte(1);
                self.option(previous_closure.as_ref().map(|id| id.as_bytes().as_slice()));
                self.size(epochs.len())?;
                for epoch in epochs {
                    self.epoch(epoch)?;
                }
            }
            SessionState::Terminal {
                report,
                batch,
                pending,
                epochs,
            } => {
                self.byte(2);
                self.raw(report);
                self.option(batch.as_ref().map(|id| id.as_bytes().as_slice()));
                self.option(pending.as_ref().map(|id| id.as_bytes().as_slice()));
                self.size(epochs.len())?;
                for e in epochs {
                    self.number(e.epoch);
                    self.number(e.sent);
                    self.number(e.acknowledged);
                    self.byte(u8::from(e.reservation_abandoned));
                }
            }
        }
        Ok(())
    }
    fn record(&mut self, record: &RecordMetadataEntry) -> Result<(), DurableError> {
        self.raw(&record.id);
        self.raw(&record.context);
        self.byte(record.phase as u8);
        for list in [
            &record.authorities,
            &record.one_time_claims,
            &record.inventory_references,
        ] {
            self.list(list)?;
        }
        match &record.metadata {
            RecordMetadata::Bootstrap {
                entry,
                request,
                flights,
                cancellation,
            } => {
                self.byte(1);
                self.raw(entry.operation.as_bytes());
                self.raw(&entry.context);
                self.byte(entry.role as u8);
                self.byte(entry.status as u8);
                self.option(request.as_ref().map(|id| id.as_bytes().as_slice()));
                self.flights(flights);
                self.byte(u8::from(cancellation.is_some()));
                if let Some(c) = cancellation {
                    self.byte(c.previous as u8);
                    self.raw(&c.report);
                    self.list(&c.one_time_claims)?;
                    self.size(c.inventory.len())?;
                    for item in &c.inventory {
                        self.raw(item.request.as_bytes());
                        self.byte(item.kind as u8);
                        self.byte(match item.disposition {
                            BootstrapPrekeyDisposition::AbandonedByCancellation => 1,
                            BootstrapPrekeyDisposition::AlreadyConsumed => 2,
                            BootstrapPrekeyDisposition::ReusableUnchanged => 3,
                        });
                    }
                }
            }
            RecordMetadata::Prekey {
                request,
                kind,
                validity,
                public_fingerprint,
                source,
            } => {
                self.byte(2);
                self.raw(request.as_bytes());
                self.byte(*kind as u8);
                self.number(validity.from());
                self.number(validity.until());
                self.digest(public_fingerprint);
                self.option(source.as_ref().map(|id| id.as_bytes().as_slice()));
            }
            RecordMetadata::Session(s) => {
                self.byte(3);
                self.session(s)?;
            }
            RecordMetadata::Roster {
                account,
                checkpoint,
                public_history,
            } => {
                self.byte(4);
                self.raw(account);
                self.checkpoint(*checkpoint);
                self.blob(public_history)?;
            }
            RecordMetadata::Fanout {
                batch,
                account,
                roster,
                status,
                members,
            } => {
                self.byte(5);
                self.raw(batch.as_bytes());
                self.raw(account);
                self.checkpoint(*roster);
                match status {
                    FanoutStatus::Reserved => self.byte(1),
                    FanoutStatus::Committed => self.byte(2),
                    FanoutStatus::Abandoning(id) => {
                        self.byte(3);
                        self.raw(id.as_bytes());
                    }
                    FanoutStatus::Abandoned(id) => {
                        self.byte(4);
                        self.raw(id.as_bytes());
                    }
                    _ => return Err(DurableError::Corrupt),
                }
                self.size(members.len())?;
                for m in members {
                    self.raw(&m.device);
                    self.number(m.generation);
                    self.raw(&m.credential);
                    self.raw(&m.context);
                    self.raw(&m.session);
                    self.byte(m.role);
                    self.raw(m.message.as_bytes());
                    self.byte(match m.state {
                        MemberState::Reserved => 0,
                        MemberState::Retained(FanoutMemberState::Committed) => 1,
                        MemberState::Retained(FanoutMemberState::Acknowledged) => 2,
                        MemberState::Retained(FanoutMemberState::ResolutionPending) => 3,
                        MemberState::Retained(FanoutMemberState::DeliveryUnknown) => 4,
                        MemberState::Retained(FanoutMemberState::HistoryRetired) => 5,
                        MemberState::Retained(FanoutMemberState::ReservationAbandoned) => 6,
                    });
                    self.digest(&m.ciphertext_digest);
                }
            }
        }
        Ok(())
    }
}
fn canonical(
    inventory: &AnchorRetiredCleanupProposal,
    intent: &Intent,
    views: &[View],
) -> Result<Vec<u8>, DurableError> {
    let mut out = Encoder(b"QPRDMD01".to_vec());
    out.raw(&inventory.to_bytes());
    match intent {
        Intent::None => out.byte(0),
        Intent::Cancellation(wire) => {
            out.byte(1);
            out.blob(wire)?;
        }
        Intent::Write {
            expected,
            target,
            transaction,
        } => {
            out.byte(2);
            out.head(*expected);
            out.head(*target);
            match transaction {
                Transaction::Ordinary => out.byte(0),
                Transaction::Credential {
                    operation,
                    statement,
                    policy,
                } => {
                    out.byte(1);
                    out.raw(operation);
                    out.raw(statement);
                    out.byte(u8::from(policy.is_some()));
                    if let Some((adopts, digest)) = policy {
                        out.byte(u8::from(*adopts));
                        out.raw(digest);
                    }
                }
                Transaction::Policy {
                    operation,
                    statement,
                } => {
                    out.byte(2);
                    out.raw(operation);
                    out.raw(statement);
                }
                Transaction::Roster(wire) => {
                    out.byte(3);
                    out.blob(wire)?;
                }
            }
        }
    }
    out.size(views.len())?;
    for view in views {
        out.byte(match view.role {
            ViewRole::Authoritative => 1,
            ViewRole::SupersededSource => 2,
            ViewRole::UncommittedTarget => 3,
        });
        out.head(view.head);
        out.raw(&view.local_account);
        out.number(view.next_fanout_ordinal);
        out.size(view.records.len())?;
        for record in &view.records {
            out.record(record)?;
        }
        if out.0.len() > 4 * MAX_IMAGE {
            return Err(DurableError::Capacity);
        }
    }
    Ok(out.0)
}

pub(in crate::durable) fn project(
    image: &Image,
    key: &JournalKey,
    archives: &mut crate::SessionArchiveStore,
    role: ViewRole,
) -> Result<View, DurableError> {
    let mut records = Vec::with_capacity(image.records.len());
    for (id, record) in &image.records {
        let metadata = match record.kind {
            RecordKind::Initiator | RecordKind::Responder => {
                cancellation::historical_metadata(image, *id)?
            }
            RecordKind::Prekey => prekeys::historical_metadata(record)?,
            RecordKind::Messages => messages::historical_session(image, key, record, archives)?,
            RecordKind::Roster => rosters::historical_metadata(id, record)?,
            RecordKind::Fanout => messages::historical_fanout(image, key, id, record, archives)?,
        };
        records.push(RecordMetadataEntry {
            id: *id,
            context: record.context,
            phase: record.phase,
            authorities: record.authorities.clone(),
            one_time_claims: record.keys.clone(),
            inventory_references: record.prekeys.clone(),
            metadata,
        });
    }
    Ok(View {
        role,
        head: image.protection.head(image.revision, image.digest)?,
        local_account: image.local_account,
        next_fanout_ordinal: image.next_fanout,
        records,
    })
}
