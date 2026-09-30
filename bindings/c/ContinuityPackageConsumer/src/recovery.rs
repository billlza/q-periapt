// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cleanup-only original-installation ownership; never recreates operational authority.
use super::*;

const ARCHIVE_BYTES: usize = 362;
enum State {
    Discovery(Box<p::InstallationRecovery>),
    Session(Box<Session>),
    Closed,
}
struct Session {
    owner: p::InstalledSessionRecovery,
    archive: p::SessionClosureArchive,
    report: Option<p::SessionClosure>,
}
pub(crate) struct Recovery {
    state: State,
    anchor: Option<p::AnchorClient>,
}
impl Recovery {
    fn open(
        path: &Path,
        witness: Option<witness::Configuration>,
        cancel: Cancellation,
    ) -> Result<Self> {
        let paths = p::InstallationPaths::new(
            &path.join("installation.redb"),
            &path.join("journal.redb"),
            &path.join("archives.redb"),
        )?;
        let key = p::JournalKey::open(&path.join("wrap.key"))?;
        Ok(Self {
            anchor: witness
                .map(|value| value.client(path, cancel))
                .transpose()?,
            state: State::Discovery(Box::new(p::InstallationRecovery::open(paths, key)?)),
        })
    }
    fn ids(&mut self) -> Result<Vec<[u8; 32]>> {
        match &mut self.state {
            State::Discovery(discovery) => Ok(discovery.session_ids()?),
            State::Closed => Err(p::DurableError::Closed.into()),
            State::Session(_) => Err(p::Error::State.into()),
        }
    }
    fn select(
        &mut self,
        select: impl FnOnce(
            p::InstallationRecovery,
            Option<p::AnchorClient>,
        ) -> Result<(p::InstalledSessionRecovery, p::SessionClosureArchive)>,
    ) -> Result<()> {
        if !matches!(self.state, State::Discovery(_)) {
            return Err(p::Error::State.into());
        }
        // Native selection consumes the original discovery/key owner. A failed
        // admission stays closed; it cannot be retried under different defaults.
        let state = std::mem::replace(&mut self.state, State::Closed);
        let State::Discovery(discovery) = state else {
            return Err(failure(5));
        };
        let (owner, archive) = select(*discovery, self.anchor.take())?;
        self.state = State::Session(Box::new(Session {
            owner,
            archive,
            report: None,
        }));
        Ok(())
    }
    fn owner(&mut self) -> Result<&mut p::InstalledSessionRecovery> {
        match &mut self.state {
            State::Session(session) => Ok(&mut session.owner),
            State::Discovery(_) => Err(p::Error::State.into()),
            State::Closed => Err(p::DurableError::Closed.into()),
        }
    }
    fn report(&self) -> Result<&p::SessionClosure> {
        match &self.state {
            State::Session(session) => session
                .report
                .as_ref()
                .ok_or_else(|| p::Error::State.into()),
            State::Closed => Err(p::DurableError::Closed.into()),
            _ => Err(p::Error::State.into()),
        }
    }
    fn epoch(&self, index: u32) -> Result<&p::AbandonedEpoch> {
        self.report()?
            .epochs
            .get(index as usize)
            .ok_or_else(Failure::argument)
    }
}
fn with_recovery<T>(
    handle: u64,
    action: impl FnOnce(&mut Recovery, &Cancellation) -> Result<T>,
) -> Result<T> {
    with_owned(handle, |owner, cancel| match owner {
        Owned::Recovery(owner) => action(owner, cancel),
        Owned::Operational(_) => Err(failure(6)),
    })
}
fn cancelled(cancel: &Cancellation) -> Result<()> {
    if cancel.is_cancelled() {
        Err(p::connection_transport::Error::Cancelled.into())
    } else {
        Ok(())
    }
}
unsafe fn result<T>(
    handle: u64,
    target: *mut T,
    error: *mut ErrorRecord,
    action: impl FnOnce(&mut Recovery, &Cancellation) -> Result<T>,
) -> i32 {
    let run = || {
        output(target)?;
        let value = with_recovery(handle, action)?;
        // SAFETY: exported callers forward the header's writable/aligned region.
        unsafe { put(target, value) };
        Ok(())
    };
    // SAFETY: forwarded per-call diagnostic region.
    unsafe { boundary(error, false, run) }
}
unsafe fn mutation(
    handle: u64,
    error: *mut ErrorRecord,
    action: impl FnOnce(&mut Recovery) -> Result<()>,
) -> i32 {
    let run = || {
        with_recovery(handle, |owner, cancel| {
            cancelled(cancel)?;
            action(owner)?;
            // Late cancellation never refunds or conceals a native failure. A native
            // success followed by cancellation still requires original-ID reconciliation.
            cancelled(cancel)
        })
    };
    // SAFETY: forwarded diagnostic region.
    unsafe { boundary(error, false, run) }
}
fn count(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| p::Error::Capacity.into())
}
fn length(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| p::Error::Capacity.into())
}

/// Native immutable closure summary. Optional counters have explicit presence flags.
#[repr(C)]
pub struct Header {
    pub peer_generation: u64,
    pub confirmed_epoch: u64,
    pub sending_epoch: u64,
    pub receiving_epoch: u64,
    pub pending_epoch: u64,
    pub has_pending_epoch: u32,
    pub role: u32,
    pub reserved_count: u32,
    pub epoch_count: u32,
    pub session: [u8; 32],
    pub context: [u8; 32],
    pub report: [u8; 32],
    pub peer_account: [u8; 32],
    pub peer_device: [u8; 16],
}
impl Header {
    fn from_report(report: &p::SessionClosure) -> Result<Self> {
        // Exhaustive public-field binding keeps future report additions visible.
        let p::SessionClosure {
            session,
            context,
            report,
            role,
            peer_account,
            peer_device,
            peer_generation,
            progress,
            reserved,
            epochs,
        } = report;
        let p::RekeyProgress {
            confirmed_epoch,
            sending_epoch,
            receiving_epoch,
            pending_epoch,
        } = progress;
        Ok(Self {
            peer_generation: *peer_generation,
            confirmed_epoch: *confirmed_epoch,
            sending_epoch: *sending_epoch,
            receiving_epoch: *receiving_epoch,
            pending_epoch: pending_epoch.unwrap_or(0),
            has_pending_epoch: u32::from(pending_epoch.is_some()),
            role: u32::from(*role),
            reserved_count: count(reserved.len())?,
            epoch_count: count(epochs.len())?,
            session: *session,
            context: *context,
            report: *report.as_bytes(),
            peer_account: *peer_account,
            peer_device: *peer_device,
        })
    }
}
/// All scalar accounting and nested item counts for one retained epoch.
#[repr(C)]
pub struct Epoch {
    pub epoch: u64,
    pub acknowledged_before: u64,
    pub sent: u64,
    pub consumed_before: u64,
    pub received: u64,
    pub peer_sent: u64,
    pub has_peer_sent: u32,
    pub resolution: u32,
    pub unconfirmed_count: u32,
    pub delivery_count: u32,
    pub skipped_count: u32,
    pub reserved_zero: u32,
    pub resolution_report: [u8; 32],
}
impl Epoch {
    fn from_epoch(value: &p::AbandonedEpoch) -> Result<Self> {
        let p::AbandonedEpoch {
            epoch,
            acknowledged_before,
            sent,
            consumed_before,
            received,
            peer_sent,
            resolution,
            unconfirmed,
            deliveries,
            skipped,
        } = value;
        let (resolution, resolution_report) = match resolution {
            p::EpochResolutionStatus::Unrequested => (0, [0; 32]),
            p::EpochResolutionStatus::Pending(id) => (1, *id.as_bytes()),
            p::EpochResolutionStatus::Acknowledged(id) => (2, *id.as_bytes()),
        };
        Ok(Self {
            epoch: *epoch,
            acknowledged_before: *acknowledged_before,
            sent: *sent,
            consumed_before: *consumed_before,
            received: *received,
            peer_sent: peer_sent.unwrap_or(0),
            has_peer_sent: u32::from(peer_sent.is_some()),
            resolution,
            unconfirmed_count: count(unconfirmed.len())?,
            delivery_count: count(deliveries.len())?,
            skipped_count: count(skipped.len())?,
            reserved_zero: 0,
            resolution_report,
        })
    }
}
/// Uncommitted input lengths, with no content or content digest.
#[repr(C)]
pub struct Reserved {
    pub plaintext_bytes: u64,
    pub associated_data_bytes: u64,
    pub message: [u8; 32],
}
/// Original unknown delivery and its native ciphertext commitment, not a plaintext hash.
#[repr(C)]
pub struct Unconfirmed {
    pub message: [u8; 32],
    pub ciphertext_digest: [u8; 32],
}
/// Exact locally unconsumed input position/length, without plaintext.
#[repr(C)]
pub struct Delivery {
    pub index: u64,
    pub plaintext_bytes: u64,
    pub message: [u8; 32],
}
/// 0=open, 1=pending, 2=closed. Only open has a zero report identifier.
#[repr(C)]
pub struct Status {
    pub phase: u32,
    pub report: [u8; 32],
}

/// Open original installation discovery without SDK operational policy activation.
/// # Safety
/// Header input/output validity, alignment and nonoverlap obligations apply.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_open(
    path: *const u8,
    size: usize,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe { open_recovery(path, size, None, handle, error) }
}
/// Open original cleanup discovery with its explicitly selected witness signer/pins.
/// # Safety
/// All borrowed options, input/output and diagnostic regions satisfy the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_open_witness(
    path: *const u8,
    size: usize,
    options: *const witness::Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        open_recovery(
            path,
            size,
            Some((options, witness::Carrier::SignedTcp)),
            handle,
            error,
        )
    }
}
/// Open cleanup-only original ownership with explicitly pinned witness mutual TLS.
/// # Safety
/// All borrowed input, options and output regions satisfy the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_open_witness_tls(
    path: *const u8,
    size: usize,
    options: *const witness::Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        open_recovery(
            path,
            size,
            Some((options, witness::Carrier::Tls)),
            handle,
            error,
        )
    }
}
unsafe fn open_recovery(
    path: *const u8,
    size: usize,
    witness: Option<(*const witness::Options, witness::Carrier)>,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let run = || {
        output(handle)?;
        // SAFETY: exact header regions; no caller pointer is retained.
        unsafe { put(handle, 0) };
        let path = unsafe { text(path, size, 4096) }?;
        let witness = witness
            .map(|(value, carrier)| unsafe { witness::Configuration::read(value, carrier) })
            .transpose()?;
        let reservation = Reservation::new()?;
        let owner = Recovery::open(Path::new(&path), witness, reservation.cancel.clone())?;
        let id = reservation.publish(Owned::Recovery(Box::new(owner)))?;
        unsafe { put(handle, id) };
        Ok(())
    };
    unsafe { boundary(error, false, run) }
}
/// Count validated archive-index discovery hints, not operational permissions.
/// # Safety
/// Output and diagnostic regions meet the header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_session_count(
    handle: u64,
    output: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe { result(handle, output, error, |owner, _| count(owner.ids()?.len())) }
}
/// Read an index hint; selection must separately authenticate original state.
/// # Safety
/// Output points to 32 writable bytes and is distinct from error.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_session_at(
    handle: u64,
    index: u32,
    output: *mut [u8; 32],
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            owner
                .ids()?
                .get(index as usize)
                .copied()
                .ok_or_else(Failure::argument)
        })
    }
}
/// Consume discovery into one original indexed cleanup session. Failure closes discovery.
/// # Safety
/// Session is a readable 32-byte region; error is aligned, writable and distinct.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_select(
    handle: u64,
    session: *const u8,
    error: *mut ErrorRecord,
) -> i32 {
    let run = || {
        let session = unsafe { fixed(session) }?;
        with_recovery(handle, |owner, cancel| {
            cancelled(cancel)?;
            owner.select(|discovery, anchor| {
                let mut selected = discovery.open_session(session, anchor)?;
                let archive = selected.stores()?.1.get(session)?;
                Ok((selected, archive))
            })?;
            cancelled(cancel)
        })
    };
    unsafe { boundary(error, false, run) }
}
/// Explicitly select retained original archive bytes, including after index retirement.
/// # Safety
/// Input/error satisfy the bounded readable/writable header regions.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_select_archive(
    handle: u64,
    archive: *const u8,
    size: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let run = || {
        let bytes = unsafe { bytes(archive, size, ARCHIVE_BYTES) }?;
        let archive = p::SessionClosureArchive::from_bytes(&bytes)?;
        with_recovery(handle, |owner, cancel| {
            cancelled(cancel)?;
            owner.select(|discovery, anchor| {
                let selected = discovery.open_session_from_archive(&archive, anchor)?;
                Ok((selected, archive))
            })?;
            cancelled(cancel)
        })
    };
    unsafe { boundary(error, false, run) }
}
/// Export only the original metadata authenticated during selection.
/// # Safety
/// Output is a writable 362-byte region; error is separate.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_archive(
    handle: u64,
    output: *mut [u8; ARCHIVE_BYTES],
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| match &owner.state {
            State::Session(session) => session
                .archive
                .as_bytes()
                .try_into()
                .map_err(|_| p::Error::Encoding.into()),
            State::Closed => Err(p::DurableError::Closed.into()),
            State::Discovery(_) => Err(p::Error::State.into()),
        })
    }
}
/// Permanently freeze the session and retain the complete immutable loss report.
/// # Safety
/// Header and error are valid writable, aligned, nonoverlapping regions.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_begin(
    handle: u64,
    output: *mut Header,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, cancel| {
            cancelled(cancel)?;
            let current = owner.owner()?.stores()?.0.begin()?;
            let header = Header::from_report(&current)?;
            let State::Session(session) = &mut owner.state else {
                return Err(failure(5));
            };
            session.report = Some(current);
            cancelled(cancel)?;
            Ok(header)
        })
    }
}
/// Read current native closure status, never permission to send.
/// # Safety
/// Output and error obey the header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_status(
    handle: u64,
    output: *mut Status,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            let (phase, report) = match owner.owner()?.stores()?.0.status()? {
                p::SessionClosureStatus::Open => (0, [0; 32]),
                p::SessionClosureStatus::Pending(id) => (1, *id.as_bytes()),
                p::SessionClosureStatus::Closed(id) => (2, *id.as_bytes()),
            };
            Ok(Status { phase, report })
        })
    }
}
/// Read one retained uncommitted reservation from the latest successful begin snapshot.
/// # Safety
/// Output and diagnostic regions obey the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_reserved(
    handle: u64,
    index: u32,
    output: *mut Reserved,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            let p::ReservedAbandonment {
                message,
                plaintext_bytes,
                associated_data_bytes,
            } = owner
                .report()?
                .reserved
                .get(index as usize)
                .ok_or_else(Failure::argument)?;
            Ok(Reserved {
                message: *message.as_bytes(),
                plaintext_bytes: length(*plaintext_bytes)?,
                associated_data_bytes: length(*associated_data_bytes)?,
            })
        })
    }
}
/// Read one retained epoch and every nested-list count; no item is summarized away.
/// # Safety
/// Output/error regions obey the header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_epoch(
    handle: u64,
    index: u32,
    output: *mut Epoch,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            Epoch::from_epoch(owner.epoch(index)?)
        })
    }
}
/// Read an exact unknown send ID and original ciphertext digest.
/// # Safety
/// Output/error regions obey the header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_unconfirmed(
    handle: u64,
    epoch: u32,
    index: u32,
    output: *mut Unconfirmed,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            let value = owner
                .epoch(epoch)?
                .unconfirmed
                .get(index as usize)
                .ok_or_else(Failure::argument)?;
            Ok(Unconfirmed {
                message: *value.message_id().as_bytes(),
                ciphertext_digest: *value.ciphertext_digest(),
            })
        })
    }
}
/// Read an exact unconsumed delivery ID, position and length, with no plaintext.
/// # Safety
/// Output/error regions obey the header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_delivery(
    handle: u64,
    epoch: u32,
    index: u32,
    output: *mut Delivery,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            let p::AbandonedDelivery {
                message,
                index,
                plaintext_bytes,
            } = owner
                .epoch(epoch)?
                .deliveries
                .get(index as usize)
                .ok_or_else(Failure::argument)?;
            Ok(Delivery {
                message: *message.as_bytes(),
                index: *index,
                plaintext_bytes: length(*plaintext_bytes)?,
            })
        })
    }
}
/// Read an observed skipped position; it does not prove the peer sent that message.
/// # Safety
/// Output/error regions obey the header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_skipped(
    handle: u64,
    epoch: u32,
    index: u32,
    output: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            owner
                .epoch(epoch)?
                .skipped
                .get(index as usize)
                .copied()
                .ok_or_else(Failure::argument)
        })
    }
}
/// Acknowledge only after the host durably records the complete original report.
/// # Safety
/// Report points to 32 readable bytes and error is separate and writable.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_acknowledge(
    handle: u64,
    report: *const u8,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: mutation's admission precedes the action's foreign-buffer read.
    unsafe {
        mutation(handle, error, |owner| {
            let report = p::SessionClosureId::from_trusted_state(fixed(report)?)?;
            Ok(owner.owner()?.stores()?.0.acknowledge(report)?)
        })
    }
}
/// Retire only the original closed catalogue row; zero is a validated absent row.
/// # Safety
/// Report, removed and error satisfy the exact header region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_retire(
    handle: u64,
    report: *const u8,
    removed: *mut u8,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, removed, error, |owner, cancel| {
            cancelled(cancel)?;
            let report = p::SessionClosureId::from_trusted_state(fixed(report)?)?;
            let (journal, archives) = owner.owner()?.stores()?;
            let removed = archives.retire_closed(journal, report)?;
            cancelled(cancel)?;
            Ok(u8::from(removed))
        })
    }
}
/// Restore only metadata admitted by the selected native cleanup owner.
/// # Safety
/// Error is a valid, aligned writable diagnostic region.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_restore_index(
    handle: u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        mutation(handle, error, |owner| {
            let (journal, archives) = owner.owner()?.stores()?;
            Ok(archives.restore(journal)?)
        })
    }
}
