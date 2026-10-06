// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Unpublished C consumer of the installed Continuity Rust owner, not product ABI 2.
#![deny(unsafe_op_in_unsafe_fn)]

mod account;
mod device;
mod enrollment;
mod invocation;
mod native_owner;
mod opening;
mod owner;
mod recovery;
mod server;
mod setup;
mod witness;
use p::connection_transport::{Cancellation, Consumption, Submission};
use q_periapt_continuity_identity_candidate as p;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, TryLockError,
    },
    time::Instant,
};

type Result<T> = std::result::Result<T, Failure>;
#[derive(Debug)]
struct Failure {
    code: i32,
    message: String,
}
fn failure(code: i32) -> Failure {
    let message = match code {
        1 => "invalid C argument or configured shape",
        2 => "owner handle is closed or unknown",
        3 => "owner has an active call; cancel and join before close",
        4 => "owner, invocation capacity or handle counter exhausted",
        6 => "operation requires a different owner kind",
        _ => "C boundary failed; reconcile original durable operation",
    };
    Failure {
        code,
        message: message.into(),
    }
}
fn describe(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    for _ in 0..8 {
        let Some(cause) = source else { break };
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}
/// Caller-owned diagnostic output; no thread-local or process-global last-error state.
#[repr(C)]
pub struct ErrorRecord {
    /// Same code returned by the function; zero is success.
    pub code: i32,
    /// UTF-8 diagnostic byte count; the buffer is not a C string.
    pub length: u32,
    /// One means the bounded diagnostic omitted a suffix.
    pub truncated: u32,
    /// Public error descriptions only; never keys or private journal material.
    pub message: [u8; 512],
}
impl Failure {
    fn argument() -> Self {
        failure(1)
    }
    fn configuration(error: impl std::error::Error) -> Self {
        Self {
            code: 500,
            message: describe(&error),
        }
    }
}
impl From<p::Error> for Failure {
    fn from(error: p::Error) -> Self {
        let message = describe(&error);
        let code = 100
            + match error {
                p::Error::Encoding => 1,
                p::Error::Authentication => 2,
                p::Error::Scope => 3,
                p::Error::Validity => 4,
                p::Error::Checkpoint => 5,
                p::Error::PolicyDenied => 6,
                p::Error::Conflict => 7,
                p::Error::State => 8,
                p::Error::Runtime(error) => return error.into(),
                p::Error::Capacity => 10,
                p::Error::RekeyRequired => 11,
                p::Error::Retired => 12,
                p::Error::Closed => 13,
                p::Error::Entropy => 14,
                p::Error::Provider => 15,
            };
        Self { code, message }
    }
}
impl From<q_periapt_sdk::Error> for Failure {
    fn from(error: q_periapt_sdk::Error) -> Self {
        use q_periapt_sdk::Error as E;
        let message = describe(&error);
        let code = 600
            + match error {
                E::Closed => 1,
                E::InvalidLength => 2,
                E::PolicyDenied => 3,
                E::InvalidKeyShare => 4,
                E::Entropy => 5,
                E::ResourceLimit => 6,
                E::InvalidLimits => 7,
                E::InvalidPurpose => 8,
                E::InvalidPrivateKey => 9,
                E::Backend => 10,
            };
        Self { code, message }
    }
}
impl From<q_periapt_host_store::StoreError> for Failure {
    fn from(error: q_periapt_host_store::StoreError) -> Self {
        use q_periapt_host_store::StoreError as E;
        let message = describe(&error);
        let code = 700
            + match error {
                E::Closed => 1,
                E::PrivateFile => 2,
                E::Busy => 3,
                E::Corrupt => 4,
                E::RootMismatch => 5,
                E::Stale => 6,
                E::Policy(error) => return error.into(),
                E::Io(_) => 8,
                E::Storage(_) => 9,
                E::CommitUncertain(_) => 10,
                E::ActivationAfterCommit(_) => 11,
                // Non-exhaustive upstream error: retain diagnostics and fail;
                // an unfamiliar failure is never absence or permission to retry.
                _ => 12,
            };
        Self { code, message }
    }
}
impl From<p::DurableError> for Failure {
    fn from(error: p::DurableError) -> Self {
        let message = describe(&error);
        let code = 200
            + match error {
                p::DurableError::Absent => 1,
                p::DurableError::Closed => 2,
                p::DurableError::PrivateFile => 3,
                p::DurableError::Database(_) => 4,
                p::DurableError::Io(_) => 5,
                p::DurableError::Storage(_) => 6,
                p::DurableError::CommitUncertain(_) => 7,
                p::DurableError::Authentication => 8,
                p::DurableError::Corrupt => 9,
                p::DurableError::InvalidCheckpoint(_) => 10,
                p::DurableError::Conflict => 11,
                p::DurableError::PrekeyClaimed => 12,
                p::DurableError::KeyRetired => 13,
                p::DurableError::Capacity => 14,
                p::DurableError::Suspended => 15,
                p::DurableError::AnchorRequired => 16,
                p::DurableError::ArchiveRequired => 17,
                p::DurableError::Anchor(_) => 18,
                p::DurableError::Rejected => 19,
                p::DurableError::Protocol(error) => return error.into(),
            };
        Self { code, message }
    }
}
impl From<p::connection_transport::Error> for Failure {
    fn from(error: p::connection_transport::Error) -> Self {
        use p::connection_transport::Error as E;
        let message = describe(&error);
        let code = 300
            + match error {
                E::InvalidOptions => 1,
                E::Cancelled => 2,
                E::Deadline => 3,
                E::AttemptsExhausted => 4,
                E::Binding => 5,
                E::Protocol => 6,
                E::Authority(error) => return error.into(),
                E::Clock(_) => 7,
                E::Application(_) => 8,
                E::Archive(error) => {
                    return Self {
                        code: 1000 + Failure::from(error).code,
                        message,
                    }
                }
                E::Durable(error) => return error.into(),
                E::Connection(_) => 9,
                E::Io(_) => 10,
                E::RetryExhausted { .. } => 11,
            };
        Self { code, message }
    }
}

enum Owned {
    Opening(Box<opening::Request>),
    Operational(Box<owner::Owner>),
    Recovery(Box<recovery::Recovery>),
    Device(Arc<device::Shared>),
    Peer(Box<device::Peer>),
    Setup(Box<setup::Owner>),
    Enrollment(Box<enrollment::Owner>),
}
struct Entry {
    cancel: Cancellation,
    invocation: invocation::Scope,
    owner: Mutex<Option<Owned>>,
}
struct Table {
    next: u64,
    // A pending constructor counts against the same hard cap as an active owner.
    slots: BTreeMap<u64, Option<Arc<Entry>>>,
}
static TABLE: Mutex<Table> = Mutex::new(Table {
    next: 1,
    slots: BTreeMap::new(),
});
#[cfg(test)]
static TEST_REGISTRY: Mutex<()> = Mutex::new(());
const MAX_OWNERS: usize = 64;
const MAX_CALLS: usize = 64;
static CALLS: AtomicUsize = AtomicUsize::new(0);
struct CallPermit;
impl CallPermit {
    fn reserve() -> Result<Self> {
        CALLS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_CALLS).then(|| current + 1)
            })
            .map_err(|_| failure(4))?;
        Ok(Self)
    }
}
impl Drop for CallPermit {
    fn drop(&mut self) {
        CALLS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Reservation {
    id: u64,
    published: bool,
    cancel: Cancellation,
    invocation: invocation::Scope,
}
impl Reservation {
    fn new() -> Result<Self> {
        let mut table = TABLE.lock().map_err(|_| failure(5))?;
        if table.slots.len() >= MAX_OWNERS {
            return Err(failure(4));
        }
        let id = table.next;
        table.next = id.checked_add(1).ok_or(failure(4))?;
        table.slots.insert(id, None);
        Ok(Self {
            id,
            published: false,
            cancel: Cancellation::default(),
            invocation: invocation::Scope::default(),
        })
    }
    fn publish(mut self, owner: Owned, deadline: Instant) -> Result<u64> {
        let mut table = TABLE.lock().map_err(|_| failure(5))?;
        let slot = table.slots.get_mut(&self.id).ok_or(failure(5))?;
        if slot.is_some() {
            return Err(failure(5));
        }
        opening::check(&self.cancel, deadline)?;
        *slot = Some(Arc::new(Entry {
            cancel: self.cancel.clone(),
            invocation: self.invocation.clone(),
            owner: Mutex::new(Some(owner)),
        }));
        self.published = true;
        Ok(self.id)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.published {
            // Poison never authorizes new work; cleanup can still discard a slot.
            TABLE
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .slots
                .remove(&self.id);
        }
    }
}
fn entry(id: u64) -> Result<Arc<Entry>> {
    TABLE
        .lock()
        .map_err(|_| failure(5))?
        .slots
        .get(&id)
        .and_then(Option::as_ref)
        .cloned()
        .ok_or(failure(2))
}
fn with<T>(
    id: u64,
    deadline: Instant,
    action: impl FnOnce(&mut owner::Operation<'_>, &Cancellation) -> Result<T>,
) -> Result<T> {
    with_owned(id, deadline, |owner, cancel| match owner {
        Owned::Operational(owner) => action(&mut owner.operation()?, cancel),
        Owned::Peer(peer) => peer.with_operation(deadline, cancel, action),
        _ => Err(failure(6)),
    })
}
fn with_owned<T>(
    id: u64,
    deadline: Instant,
    action: impl FnOnce(&mut Owned, &Cancellation) -> Result<T>,
) -> Result<T> {
    with_entry(id, deadline, |slot, entry| {
        let owner = slot.as_mut().ok_or(failure(2))?;
        let value = action(owner, &entry.cancel)?;
        invocation::check(deadline)?;
        Ok(value)
    })
}
fn with_entry<T>(
    id: u64,
    deadline: Instant,
    action: impl FnOnce(&mut Option<Owned>, &Entry) -> Result<T>,
) -> Result<T> {
    let entry = entry(id)?;
    let mut locked = match entry.owner.try_lock() {
        Ok(lock) => lock,
        Err(TryLockError::WouldBlock) => return Err(failure(3)),
        Err(TryLockError::Poisoned(error)) => {
            error.into_inner().take();
            entry.cancel.cancel();
            return Err(failure(5));
        }
    };
    let _active = entry.invocation.enter(deadline, &entry.cancel)?;
    match catch_unwind(AssertUnwindSafe(|| action(&mut locked, &entry))) {
        Ok(result) => result,
        Err(_) => {
            entry.cancel.cancel();
            locked.take();
            Err(failure(5))
        }
    }
}
unsafe fn boundary(
    record: *mut ErrorRecord,
    drain: bool,
    action: impl FnOnce(Instant) -> Result<()>,
) -> i32 {
    if output(record).is_err() {
        return 1;
    }
    // Admission precedes foreign-buffer copies and configuration reads. Close and
    // cancellation remain callable when every ordinary call slot is occupied.
    let mut permit = None;
    let invoke = || {
        let admitted = Instant::now();
        if !drain {
            permit = Some(CallPermit::reserve()?);
        }
        let deadline = if drain {
            admitted
        } else {
            admitted
                .checked_add(invocation::TIMEOUT)
                .ok_or_else(|| failure(5))?
        };
        action(deadline)
    };
    let result = match catch_unwind(AssertUnwindSafe(invoke)) {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(failure(5)),
    };
    let mut diagnostic = ErrorRecord {
        code: 0,
        length: 0,
        truncated: 0,
        message: [0; 512],
    };
    if let Some(error) = result {
        diagnostic.code = error.code;
        let mut count = error.message.len().min(diagnostic.message.len());
        while !error.message.is_char_boundary(count) {
            count -= 1;
        }
        for (out, input) in diagnostic
            .message
            .iter_mut()
            .zip(error.message.as_bytes())
            .take(count)
        {
            *out = *input;
        }
        diagnostic.length = count as u32;
        diagnostic.truncated = u32::from(count < error.message.len());
    }
    let code = diagnostic.code;
    // SAFETY: caller provides an aligned writable ErrorRecord, distinct from other regions.
    unsafe { record.write(diagnostic) };
    drop(permit);
    code
}

// Foreign pointers must designate the readable/writable nonoverlapping regions
// in the header contract. Null/shape/bounds are checked before dereferencing;
// arbitrary forged C addresses are outside any in-process FFI's memory guarantee.
unsafe fn bytes(pointer: *const u8, length: usize, maximum: usize) -> Result<Vec<u8>> {
    if length > maximum || (length != 0 && pointer.is_null()) {
        return Err(Failure::argument());
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: the caller supplies a readable length-byte region; bounds/null checked.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}
unsafe fn fixed(pointer: *const u8) -> Result<[u8; 32]> {
    // SAFETY: forwarded header precondition for a 32-byte input.
    unsafe { bytes(pointer, 32, 32) }?
        .try_into()
        .map_err(|_| Failure::argument())
}
unsafe fn text(pointer: *const u8, length: usize, maximum: usize) -> Result<String> {
    // SAFETY: forwarded header precondition for the specified input region.
    let value = unsafe { bytes(pointer, length, maximum) }?;
    if value.is_empty() || value.contains(&0) {
        return Err(Failure::argument());
    }
    String::from_utf8(value).map_err(|_| Failure::argument())
}
fn output<T>(pointer: *mut T) -> Result<()> {
    if pointer.is_null() || !pointer.is_aligned() {
        Err(Failure::argument())
    } else {
        Ok(())
    }
}
unsafe fn put<T>(pointer: *mut T, value: T) {
    // SAFETY: every call validates pointer shape; caller supplies the writable region.
    unsafe { pointer.write(value) };
}
fn address(value: &str) -> Result<SocketAddr> {
    let result: SocketAddr = value.parse().map_err(|_| Failure::argument())?;
    if result.port() == 0 {
        return Err(Failure::argument());
    }
    Ok(result)
}

/// Open an existing original installation. See the C header for pointer/lifetime rules.
/// # Safety
/// Inputs and output must satisfy the nonoverlapping readable/writable header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_open(
    path: *const u8,
    length: usize,
    quality: u8,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe { open_owner(path, length, quality, None, handle, error) }
}
/// Open a required-witness installation using independent original witness pins.
/// # Safety
/// The header's readable options/input and writable output regions must be valid and distinct.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_open_witness(
    path: *const u8,
    length: usize,
    quality: u8,
    options: *const witness::Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        open_owner(
            path,
            length,
            quality,
            Some((options, witness::Carrier::SignedTcp)),
            handle,
            error,
        )
    }
}
/// Open a required-witness installation using explicitly pinned mutual TLS.
/// # Safety
/// All borrowed input, options and output regions satisfy the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_open_witness_tls(
    path: *const u8,
    length: usize,
    quality: u8,
    options: *const witness::Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        open_owner(
            path,
            length,
            quality,
            Some((options, witness::Carrier::Tls)),
            handle,
            error,
        )
    }
}
unsafe fn open_owner(
    path: *const u8,
    length: usize,
    quality: u8,
    witness: Option<(*const witness::Options, witness::Carrier)>,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |deadline| {
        output(handle)?;
        // SAFETY: validated output pointer and header input preconditions.
        unsafe { put(handle, 0) };
        let path = unsafe { text(path, length, 4096) }?;
        let witness = witness
            .map(|(value, carrier)| unsafe { witness::Configuration::read(value, carrier) })
            .transpose()?;
        let quality = opening::quality(u32::from(quality))?;
        let slot = Reservation::new()?;
        let _active = slot.invocation.enter(deadline, &slot.cancel)?;
        let owner = owner::Owner::open(
            Path::new(&path),
            owner::Admission::Bootstrap(quality),
            witness,
            slot.cancel.clone(),
            slot.invocation.clone(),
            deadline,
        )?;
        let id = slot.publish(Owned::Operational(owner), deadline)?;
        unsafe { put(handle, id) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Permanently signal this owner's invocation cancellation; safe during an active call.
/// # Safety
/// Error must point to an aligned writable diagnostic record for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_cancel(handle: u64, error: *mut ErrorRecord) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |_| {
        let entry = entry(handle)?;
        entry.cancel.cancel();
        entry.invocation.cancel_active()?;
        Ok(())
    };
    unsafe { boundary(error, true, action) }
}
/// Close an idle owner. Busy preserves the handle; cancel, join the call, then close.
/// # Safety
/// Error must point to an aligned writable diagnostic record for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_close(handle: u64, error: *mut ErrorRecord) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |_| {
        let entry = entry(handle)?;
        let (mut owner, mut poisoned) = match entry.owner.try_lock() {
            Ok(lock) => (lock, false),
            Err(TryLockError::WouldBlock) => return Err(failure(3)),
            Err(TryLockError::Poisoned(error)) => (error.into_inner(), true),
        };
        if let Some(Owned::Device(device)) = owner.as_ref() {
            poisoned |= device.close()?;
        }
        entry.cancel.cancel();
        owner.take();
        if TABLE
            .lock()
            .map_err(|_| failure(5))?
            .slots
            .remove(&handle)
            .is_none()
        {
            return Err(failure(2));
        }
        if poisoned {
            Err(failure(5))
        } else {
            Ok(())
        }
    };
    unsafe { boundary(error, true, action) }
}

/// Establish using the caller's retained original initiation ID.
/// # Safety
/// All pointers satisfy the C header's exact sizes and nonoverlap requirements.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_establish(
    handle: u64,
    peer: *const u8,
    peer_length: usize,
    request: *const u8,
    session: *mut [u8; 32],
    exchanges: *mut u16,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |deadline| {
        output(session)?;
        output(exchanges)?;
        unsafe {
            put(session, [0; 32]);
            put(exchanges, 0);
        }
        let address = address(&unsafe { text(peer, peer_length, 128) }?)?;
        let request = p::InitiationId::from_trusted_state(unsafe { fixed(request) }?)?;
        let result = with(handle, deadline, |owner, cancel| {
            let endpoint = owner.endpoint()?;
            let name = owner.peer_name.to_owned();
            Ok(endpoint.establish(
                owner.actor()?,
                request,
                owner::run(address, &name, cancel, deadline),
                owner::now,
            )?)
        })?;
        unsafe {
            put(session, result.session);
            put(exchanges, result.exchanges);
        }
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Query the next slot without reserving it; a competing caller can observe the same ID.
/// # Safety
/// Inputs/outputs are valid nonoverlapping 32-byte regions as specified in the header.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_next_message(
    handle: u64,
    session: *const u8,
    message: *mut [u8; 32],
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |deadline| {
        output(message)?;
        unsafe {
            put(message, [0; 32]);
        }
        let session = unsafe { fixed(session) }?;
        let id = with(handle, deadline, |owner, _| {
            let (journal, _) = owner.service.stores()?;
            Ok(journal.next_message_id(
                owner.context,
                session,
                owner::now().map_err(Failure::configuration)?,
            )?)
        })?;
        unsafe {
            put(message, *id.as_bytes());
        }
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Send or retry exact ID/input; consumption is separate from transport success.
/// # Safety
/// Pointers are valid for their stated lengths, bounded and nonoverlapping per header.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_send(
    handle: u64,
    peer: *const u8,
    peer_length: usize,
    session: *const u8,
    message: *const u8,
    plaintext: *const u8,
    plaintext_length: usize,
    ad: *const u8,
    ad_length: usize,
    consumption: *mut u8,
    exchanges: *mut u16,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |deadline| {
        output(consumption)?;
        output(exchanges)?;
        unsafe {
            put(consumption, 0);
            put(exchanges, 0);
        }
        let address = address(&unsafe { text(peer, peer_length, 128) }?)?;
        let session = unsafe { fixed(session) }?;
        let message = p::MessageId::from_trusted_state(unsafe { fixed(message) }?)?;
        let plaintext = zeroize::Zeroizing::new(unsafe {
            bytes(
                plaintext,
                plaintext_length,
                p::contract::MAX_PLAINTEXT_BYTES,
            )
        }?);
        let ad = unsafe { bytes(ad, ad_length, p::contract::MAX_ASSOCIATED_DATA_BYTES) }?;
        let result = with(handle, deadline, |owner, cancel| {
            let endpoint = owner.endpoint()?;
            let name = owner.peer_name.to_owned();
            Ok(endpoint.send(
                owner.actor()?,
                Submission {
                    session,
                    message,
                    plaintext: &plaintext,
                    associated_data: &ad,
                },
                owner::run(address, &name, cancel, deadline),
                owner::now,
            )?)
        })?;
        let state = match result.consumption {
            Consumption::Confirmed => 1,
            Consumption::PrefixPending => 2,
        };
        unsafe {
            put(consumption, state);
            put(exchanges, result.exchanges);
        }
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Read exact outgoing status, without dispatch or inferred permission.
/// # Safety
/// Session/message each point to 32 readable bytes and status to one writable byte.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_message_status(
    handle: u64,
    session: *const u8,
    message: *const u8,
    status: *mut u8,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |deadline| {
        output(status)?;
        unsafe {
            put(status, 255);
        }
        let session = unsafe { fixed(session) }?;
        let message = p::MessageId::from_trusted_state(unsafe { fixed(message) }?)?;
        let result = with(handle, deadline, |owner, _| {
            Ok(owner
                .service
                .stores()?
                .0
                .message_status(owner.context, session, message)?)
        })?;
        let value = match result {
            p::MessageStatus::Absent => 0,
            p::MessageStatus::Reserved => 1,
            p::MessageStatus::Committed => 2,
            p::MessageStatus::Acknowledged => 3,
            p::MessageStatus::ResolutionPending => 4,
            p::MessageStatus::DeliveryUnknown => 5,
            p::MessageStatus::ReservationAbandoned => 6,
        };
        unsafe {
            put(status, value);
        }
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Complete one explicit rekey target through the same journal/control carrier.
/// # Safety
/// Input and output regions satisfy the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_rekey(
    handle: u64,
    peer: *const u8,
    peer_length: usize,
    session: *const u8,
    target: u64,
    completed_epoch: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the exported function forwards its caller-owned diagnostic contract.
    let action = |deadline| {
        output(completed_epoch)?;
        unsafe {
            put(completed_epoch, 0);
        }
        let address = address(&unsafe { text(peer, peer_length, 128) }?)?;
        let session = unsafe { fixed(session) }?;
        let result = with(handle, deadline, |owner, cancel| {
            let endpoint = owner.control(session)?;
            let run = owner::run(address, owner.peer_name, cancel, deadline);
            let (journal, _) = owner.service.stores()?;
            Ok(endpoint.run(
                p::control_transport::Session {
                    journal,
                    context: owner.context,
                    signer: owner.signer,
                },
                p::control_transport::Run {
                    target,
                    address: run.address,
                    server_name: run.server_name,
                    limits: run.limits,
                    cancel,
                },
                owner::now,
            )?)
        })?;
        unsafe {
            put(completed_epoch, result.epoch);
        }
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_call_budget_preserves_drain_and_returns_capacity_after_failure() {
        let _serial = TEST_REGISTRY.lock().expect("test registry");
        let mut diagnostic = ErrorRecord {
            code: -1,
            length: 0,
            truncated: 0,
            message: [0; 512],
        };
        let options = opening::Options {
            kind: 2,
            quality: 0,
            carrier: 0,
            witness: std::ptr::null(),
        };
        let mut pending = 0;
        // SAFETY: distinct live stack inputs and outputs; preparation performs no I/O.
        unsafe {
            assert_eq!(
                opening::qpc_owner_v1_prepare_open(
                    b"relative".as_ptr(),
                    8,
                    &options,
                    &mut pending,
                    &mut diagnostic
                ),
                0
            );
        }
        let permits = (0..MAX_CALLS)
            .map(|_| CallPermit::reserve().expect("available call slot"))
            .collect::<Vec<_>>();
        let mut handle = 99;
        // SAFETY: all arrays/scalars live for the call and no regions overlap.
        unsafe {
            assert_eq!(
                qpc_owner_v1_open(b"relative".as_ptr(), 8, 1, &mut handle, &mut diagnostic),
                4
            );
            assert_eq!(diagnostic.code, 4);
            assert_eq!(
                opening::qpc_owner_v1_finish_open(pending, &mut diagnostic),
                4
            );
            assert_eq!(qpc_owner_v1_cancel(pending, &mut diagnostic), 0);
            assert_eq!(qpc_owner_v1_close(pending, &mut diagnostic), 0);
            assert_eq!(qpc_owner_v1_cancel(0, &mut diagnostic), 2);
            assert_eq!(qpc_owner_v1_close(0, &mut diagnostic), 2);
        }
        drop(permits);
        // A fresh call reaches ordinary path validation, proving the permit was
        // returned. It still cannot create an installation from a relative path.
        unsafe {
            assert_eq!(
                qpc_owner_v1_open(b"relative".as_ptr(), 8, 1, &mut handle, &mut diagnostic),
                203
            );
        }
        assert_eq!(handle, 0);
        assert_eq!(CALLS.load(Ordering::Acquire), 0);
    }
}
