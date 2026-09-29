// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Permanent local session closure with explicit host loss accounting.
use super::*;
use hmac::{Hmac, Mac};

/// Private-keyed correlation for one immutable session loss report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionClosureId([u8; 32]);
impl SessionClosureId {
    /// Restore an already retained ID; journal/context matching still applies.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public correlation bytes, not a plaintext commitment or authorization.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Read-only local lifecycle; none of these states grants network authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionClosureStatus {
    /// This session has no independent closure in progress.
    Open,
    /// Mutations and releases are permanently frozen; host accounting is pending.
    Pending(SessionClosureId),
    /// Host acknowledged the exact report; logical private state is absent.
    Closed(SessionClosureId),
}
/// Metadata-only accounting for a permanently frozen independent session.
/// Persist the complete report and deduplicate by its ID before acknowledging it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionClosure {
    /// Exact admitted session.
    pub session: [u8; 32],
    /// Original authenticated context commitment.
    pub context: [u8; 32],
    /// Retain with the host's durable accounting transaction.
    pub report: SessionClosureId,
    /// Local bootstrap role, 1 for initiator and 2 for responder.
    pub role: u8,
    /// Original peer account; closure grants no new authorization to it.
    pub peer_account: [u8; 32],
    /// Original peer device.
    pub peer_device: [u8; 16],
    /// Original peer generation.
    pub peer_generation: u64,
    /// Last committed progress, not a post-compromise recovery claim.
    pub progress: RekeyProgress,
    /// Every uncommitted input, with lengths only; no slot is refunded.
    pub reserved: Vec<ReservedAbandonment>,
    /// Complete retained delivery/loss metadata, without plaintext or keys.
    pub epochs: Vec<AbandonedEpoch>,
}

pub(super) struct Pending {
    report: SessionClosureId,
    key: ZeroizingBytes<32>,
}
pub(super) fn encode_pending(pending: &Option<Pending>, bytes: &mut Vec<u8>) {
    match pending {
        None => bytes.extend_from_slice(&[0; 64]),
        Some(pending) => {
            bytes.extend_from_slice(pending.report.as_bytes());
            bytes.extend_from_slice(pending.key.as_bytes());
        }
    }
}
pub(super) fn decode_pending(d: &mut Decoder<'_>) -> Result<Option<Pending>, Error> {
    let report = d.array()?;
    let key = key(d.take(32)?)?;
    if report == [0; 32] {
        if key.as_bytes() != &[0; 32] {
            return Err(Error::Encoding);
        }
        return Ok(None);
    }
    Ok(Some(Pending {
        report: SessionClosureId::from_trusted_state(report)?,
        key,
    }))
}
fn report_mac(
    image: &Image,
    record: &Record,
    key: &ZeroizingBytes<32>,
) -> Result<Hmac<Sha256>, DurableError> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_bytes())
        .map_err(|_| Error::Provider)?;
    mac.update(&label(b"session-closure/v1"));
    mac.update(&image.id);
    mac.update(&image.owner);
    mac.update(&record.context);
    mac.update(&(record.payload.len() as u64).to_be_bytes());
    let prefix = record
        .payload
        .len()
        .checked_sub(64)
        .ok_or(DurableError::Corrupt)?;
    mac.update(record.payload.get(..prefix).ok_or(DurableError::Corrupt)?);
    // The fixed tail is canonical zero before freezing; exclude the MAC's own
    // output and its private key without excluding any original private state.
    mac.update(&[0; 64]);
    Ok(mac)
}
fn require_independent(state: &State) -> Result<(), DurableError> {
    if state
        .epochs
        .values()
        .any(|t| t.pending.as_ref().is_some_and(|p| p.fanout.is_some()))
    {
        // A reserved aggregate must close every member through its aggregate API.
        return Err(DurableError::Suspended);
    }
    Ok(())
}
pub(super) fn validate_record(
    image: &Image,
    record: &Record,
    state: &State,
) -> Result<(), DurableError> {
    if record.phase == DurableStatus::MessagesClosing {
        let pending = state.closure.as_ref().ok_or(DurableError::Corrupt)?;
        require_independent(state).map_err(|_| DurableError::Corrupt)?;
        report_mac(image, record, &pending.key)?
            .verify_slice(pending.report.as_bytes())
            .map_err(|_| DurableError::Corrupt)
    } else if state.closure.is_some() {
        Err(DurableError::Corrupt)
    } else {
        Ok(())
    }
}
fn report(context: &BootstrapContext, state: &State) -> Result<SessionClosure, Error> {
    let devices = context.devices();
    let peer = if state.role == 1 {
        devices[1]
    } else {
        devices[0]
    };
    Ok(SessionClosure {
        session: state.session,
        context: context.digest(),
        report: state.closure.as_ref().ok_or(Error::State)?.report,
        role: state.role,
        peer_account: peer.account_id(),
        peer_device: peer.device_id(),
        peer_generation: peer.generation(),
        progress: fanout::abandoned_progress(state)?,
        reserved: state
            .epochs
            .values()
            .filter_map(|t| t.pending.as_ref())
            .map(|p| ReservedAbandonment {
                message: p.id,
                plaintext_bytes: p.plaintext.len(),
                associated_data_bytes: p.ad.len(),
            })
            .collect(),
        epochs: fanout::epoch_accounting(state),
    })
}
impl DeviceJournal {
    /// Inspect independent local closure after policy close, expiry or revocation.
    /// Sessions in reserved-fanout abandonment must use the aggregate API instead.
    pub fn session_closure_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<SessionClosureStatus, DurableError> {
        let image = self.image()?;
        let record = self.message_record_for_status(&image, context, session)?;
        let (role, status) = match record.phase {
            DurableStatus::Messages | DurableStatus::MessagesClosing => {
                let state = State::decode(&record.payload)?;
                let status = match state.closure {
                    Some(pending) => SessionClosureStatus::Pending(pending.report),
                    None => SessionClosureStatus::Open,
                };
                (state.role, status)
            }
            DurableStatus::MessagesClosed => {
                let retired = Retired::decode(&record.payload)?;
                (
                    retired.role,
                    SessionClosureStatus::Closed(SessionClosureId::from_trusted_state(
                        retired.report,
                    )?),
                )
            }
            DurableStatus::MessagesAbandoning | DurableStatus::MessagesAbandoned => {
                return Err(DurableError::Suspended)
            }
            _ => return Err(DurableError::Corrupt),
        };
        check_message_owner(&image, context, role)?;
        self.check_release(&image)?;
        Ok(status)
    }
    /// Permanently freeze an independent session and return all retained loss metadata.
    /// Existing peer authority may be expired/revoked; only original owner, context
    /// and storage protection are required. No dummy send or budget slot is consumed.
    /// A reserved fanout must use `begin_fanout_abandonment` for its complete set.
    pub fn begin_session_closure(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<SessionClosure, DurableError> {
        let mut image = self.image()?;
        let record = self.message_record_for_status(&image, context, session)?;
        match record.phase {
            DurableStatus::Messages | DurableStatus::MessagesClosing => {}
            DurableStatus::MessagesClosed => return Err(Error::Retired.into()),
            DurableStatus::MessagesAbandoning | DurableStatus::MessagesAbandoned => {
                return Err(DurableError::Suspended)
            }
            _ => return Err(DurableError::Corrupt),
        }
        let mut state = State::decode(&record.payload)?;
        check_message_owner(&image, context, state.role)?;
        require_independent(&state)?;
        if record.phase == DurableStatus::Messages {
            let mut key = ZeroizingBytes::<32>::zeroed();
            getrandom::fill(key.as_mut_bytes()).map_err(|_| Error::Entropy)?;
            let report = SessionClosureId::from_trusted_state(
                report_mac(&image, record, &key)?
                    .finalize()
                    .into_bytes()
                    .into(),
            )?;
            state.closure = Some(Pending { report, key });
            let payload = state.encode();
            if payload.len() != record.payload.len() {
                return Err(DurableError::Corrupt);
            }
            let record = image
                .records
                .get_mut(&record_id(&session))
                .ok_or(DurableError::Corrupt)?;
            record.phase = DurableStatus::MessagesClosing;
            record.payload = payload;
            self.persist(&mut image)?;
            #[cfg(all(test, unix))]
            tests::after_stage("session-closing");
        }
        let report = report(context, &state)?;
        self.check_release(&image)?;
        Ok(report)
    }
    /// After durable, deduplicated host accounting of the complete report, erase
    /// logical private session state. Unknown outcomes do not become acknowledgements.
    /// Exact repeated acknowledgement is idempotent. Historical disk/backups are
    /// outside this logical-erasure contract; source/session tombstones remain.
    pub fn acknowledge_session_closure(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        report: SessionClosureId,
    ) -> Result<(), DurableError> {
        let mut image = self.image()?;
        let record = self.message_record_for_status(&image, context, session)?;
        match record.phase {
            DurableStatus::MessagesClosed => {
                let retired = Retired::decode(&record.payload)?;
                check_message_owner(&image, context, retired.role)?;
                if retired.report != *report.as_bytes() {
                    return Err(DurableError::Conflict);
                }
            }
            DurableStatus::MessagesClosing => {
                let state = State::decode(&record.payload)?;
                check_message_owner(&image, context, state.role)?;
                if state.closure.as_ref().ok_or(DurableError::Corrupt)?.report != report {
                    return Err(DurableError::Conflict);
                }
                validate_record(&image, record, &state)?;
                let payload = Retired::closed(&state, report)?.encode();
                if payload.len() > record.payload.len() {
                    return Err(DurableError::Corrupt);
                }
                let record = image
                    .records
                    .get_mut(&record_id(&session))
                    .ok_or(DurableError::Corrupt)?;
                record.payload = payload;
                record.phase = DurableStatus::MessagesClosed;
                self.persist(&mut image)?;
                #[cfg(all(test, unix))]
                tests::after_stage("session-closed");
            }
            _ => return Err(DurableError::Conflict),
        }
        self.check_release(&image)
    }
}
