// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Caller-visible admission before synchronous original-installation activation.
use super::*;

/// Borrowed construction selection. Every pointer is copied during preparation.
#[repr(C)]
pub struct Options {
    pub kind: u32,
    pub quality: u32,
    pub carrier: u32,
    pub witness: *const witness::Options,
}
enum Kind {
    Operational(owner::Admission),
    Recovery,
    Device,
    Setup {
        create: bool,
    },
    Peer {
        parent: Arc<device::Shared>,
        admission: owner::Admission,
        role: p::BootstrapRole,
    },
}
pub(crate) struct Request {
    path: String,
    kind: Kind,
    witness: Option<witness::Configuration>,
}
pub(crate) fn quality(value: u32) -> Result<p::PrekeyQuality> {
    match value {
        1 => Ok(p::PrekeyQuality::OneTimeBoth),
        2 => Ok(p::PrekeyQuality::ReusableBoth),
        3 => Ok(p::PrekeyQuality::SignedClassicalOneTimePq),
        4 => Ok(p::PrekeyQuality::OneTimeClassicalLastResortPq),
        _ => Err(Failure::argument()),
    }
}
pub(crate) fn check(cancel: &Cancellation, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(p::connection_transport::Error::Cancelled.into());
    }
    invocation::check(deadline)
}
impl Request {
    unsafe fn read(path: *const u8, length: usize, options: *const Options) -> Result<Self> {
        if options.is_null() || !options.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: header contract requires immutable live options and pointed-to inputs.
        let options = unsafe { &*options };
        let kind = match (options.kind, options.quality) {
            (1, value) => Kind::Operational(owner::Admission::Bootstrap(quality(value)?)),
            (2, 0) => Kind::Recovery,
            (3, 0) => Kind::Device,
            _ => return Err(Failure::argument()),
        };
        let witness = match options.carrier {
            0 if options.witness.is_null() => None,
            1 | 2 => {
                let carrier = if options.carrier == 1 {
                    witness::Carrier::SignedTcp
                } else {
                    witness::Carrier::Tls
                };
                // SAFETY: forwarded options/endpoint validity and lifetime contract.
                Some(unsafe { witness::Configuration::read(options.witness, carrier) }?)
            }
            _ => return Err(Failure::argument()),
        };
        // SAFETY: caller supplies the length-byte immutable readable path.
        let path = unsafe { text(path, length, 4096) }?;
        Ok(Self {
            path,
            kind,
            witness,
        })
    }
    unsafe fn read_reopen(
        path: *const u8,
        length: usize,
        options: *const Options,
        session: *const u8,
    ) -> Result<Self> {
        // SAFETY: the explicit reopen entry forwards the same bounded input contract.
        let mut request = unsafe { Self::read(path, length, options) }?;
        let quality = match request.kind {
            Kind::Operational(owner::Admission::Bootstrap(quality)) => quality,
            _ => return Err(Failure::argument()),
        };
        // SAFETY: header requires a distinct live immutable 32-byte session ID.
        let session = unsafe { fixed(session) }?;
        if session.iter().all(|byte| *byte == 0) {
            return Err(Failure::argument());
        }
        request.kind = Kind::Operational(owner::Admission::Existing { quality, session });
        Ok(request)
    }
    fn open(self, entry: &Entry, deadline: Instant) -> Result<Owned> {
        check(&entry.cancel, deadline)?;
        let path = Path::new(&self.path);
        let cancel = entry.cancel.clone();
        let invocation = entry.invocation.clone();
        let owner = match self.kind {
            Kind::Setup { create } => Owned::Setup(Box::new(setup::Owner::open(
                path,
                create,
                self.witness,
                &cancel,
                deadline,
            )?)),
            Kind::Device => Owned::Device(device::Shared::open(
                path,
                self.witness,
                cancel,
                invocation,
                deadline,
            )?),
            Kind::Peer {
                parent,
                admission,
                role,
            } => Owned::Peer(Box::new(device::Peer::open(
                parent, path, admission, role, &cancel, deadline,
            )?)),
            Kind::Operational(admission) => Owned::Operational(Box::new(owner::Owner::open(
                path,
                admission,
                self.witness,
                cancel,
                invocation,
                deadline,
            )?)),
            Kind::Recovery => Owned::Recovery(Box::new(recovery::Recovery::open(
                path,
                self.witness,
                cancel,
                invocation,
                deadline,
            )?)),
        };
        check(&entry.cancel, deadline)?;
        Ok(owner)
    }
}

unsafe fn prepare_setup(
    path: *const u8,
    length: usize,
    options: *const Options,
    create: bool,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: the caller provides the distinct aligned writable output.
        unsafe { put(handle, 0) };
        // SAFETY: the explicit setup entry has the same bounded input contract.
        let mut request = unsafe { Request::read(path, length, options) }?;
        if !matches!(request.kind, Kind::Device) {
            return Err(Failure::argument());
        }
        request.kind = Kind::Setup { create };
        let reservation = Reservation::new()?;
        let id = reservation.publish(Owned::Opening(Box::new(request)), deadline)?;
        // SAFETY: same exclusive output region.
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Prepare an explicit new installation intent; no filesystem I/O before finish_open.
/// # Safety
/// Inputs and outputs satisfy the C header's size, lifetime and nonoverlap rules.
#[no_mangle]
pub unsafe extern "C" fn qpc_setup_v1_prepare_create(
    path: *const u8,
    length: usize,
    options: *const Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded setup construction contract.
    unsafe { prepare_setup(path, length, options, true, handle, error) }
}

/// Prepare an exact existing Creating/Active intent; never creates a missing intent.
/// # Safety
/// Inputs and outputs satisfy the C header's size, lifetime and nonoverlap rules.
#[no_mangle]
pub unsafe extern "C" fn qpc_setup_v1_prepare_resume(
    path: *const u8,
    length: usize,
    options: *const Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded original-state restoration contract.
    unsafe { prepare_setup(path, length, options, false, handle, error) }
}

unsafe fn prepare_peer(
    parent: u64,
    path: *const u8,
    length: usize,
    selection: [u32; 2],
    session: Option<*const u8>,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: forwarded C contract requires separate live input/output regions.
        unsafe { put(handle, 0) };
        let [mode, role] = selection;
        let quality = quality(mode)?;
        let role = match role {
            1 => p::BootstrapRole::Initiator,
            2 => p::BootstrapRole::Responder,
            _ => return Err(Failure::argument()),
        };
        let admission = match session {
            None => owner::Admission::Bootstrap(quality),
            Some(session) => {
                // SAFETY: the explicit restoration contract requires 32 readable bytes.
                let session = unsafe { fixed(session) }?;
                if session.iter().all(|byte| *byte == 0) {
                    return Err(Failure::argument());
                }
                owner::Admission::Existing { quality, session }
            }
        };
        let parent = device::parent(parent, deadline)?;
        // SAFETY: header requires a readable immutable length-byte configuration path.
        let path = unsafe { text(path, length, 4096) }?;
        let request = Request {
            path,
            kind: Kind::Peer {
                parent,
                admission,
                role,
            },
            witness: None,
        };
        let slot = Reservation::new()?;
        let id = slot.publish(Owned::Opening(Box::new(request)), deadline)?;
        // SAFETY: same exclusive validated output region.
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Prepare an independently verified fresh peer under one live device parent.
/// No path I/O occurs before finish_open; parent and child share the owner quota.
/// # Safety
/// All input/output regions satisfy the exact sizes and nonoverlap rules in the C header.
#[no_mangle]
pub unsafe extern "C" fn qpc_peer_v1_prepare(
    parent: u64,
    path: *const u8,
    length: usize,
    quality: u32,
    role: u32,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the exported entry forwards the same borrowed-region contract.
    unsafe { prepare_peer(parent, path, length, [quality, role], None, handle, error) }
}

/// Prepare restoration of one original peer session under the retained device parent.
/// # Safety
/// Same header contract; session is a separate immutable readable 32-byte region.
#[no_mangle]
pub unsafe extern "C" fn qpc_peer_v1_prepare_reopen(
    parent: u64,
    path: *const u8,
    length: usize,
    quality: u32,
    role: u32,
    session: *const u8,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: the caller owns all borrowed input and output regions for this call.
    unsafe {
        prepare_peer(
            parent,
            path,
            length,
            [quality, role],
            Some(session),
            handle,
            error,
        )
    }
}

/// Copy bounded options and publish a cancelable pending handle without installation I/O.
/// # Safety
/// All options, pointed-to inputs, output and diagnostic regions meet the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_prepare_open(
    path: *const u8,
    length: usize,
    options: *const Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: validated output shape and forwarded input lifetime requirements.
        unsafe { put(handle, 0) };
        let request = unsafe { Request::read(path, length, options) }?;
        let slot = Reservation::new()?;
        let id = slot.publish(Owned::Opening(Box::new(request)), deadline)?;
        // SAFETY: same exclusive writable output region.
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: caller owns this invocation's valid diagnostic output.
    unsafe { boundary(error, false, action) }
}

/// Prepare restoration of one independently selected existing session. Copies
/// every input and exposes no operational authority until finish_open succeeds.
/// # Safety
/// Same input/output contract as prepare_open; session is a live immutable 32-byte
/// input, distinct from all writable outputs. No pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_prepare_reopen(
    path: *const u8,
    length: usize,
    options: *const Options,
    session: *const u8,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: validated aligned output and the caller's distinct-region contract.
        unsafe { put(handle, 0) };
        let request = unsafe { Request::read_reopen(path, length, options, session) }?;
        let slot = Reservation::new()?;
        let id = slot.publish(Owned::Opening(Box::new(request)), deadline)?;
        // SAFETY: same exclusive writable output.
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: invocation-local writable diagnostic supplied by the caller.
    unsafe { boundary(error, false, action) }
}

/// Activate once on the calling thread; failures after admission leave only cancel/close.
/// # Safety
/// Error points to a distinct aligned writable diagnostic record for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_finish_open(handle: u64, error: *mut ErrorRecord) -> i32 {
    let action = |deadline| {
        with_entry(handle, deadline, |slot, entry| {
            let request = match slot.take() {
                Some(Owned::Opening(request)) => request,
                other => {
                    let code = if other.is_none() { 2 } else { 6 };
                    *slot = other;
                    return Err(failure(code));
                }
            };
            // The pending state has been consumed. Native failure/panic/cancellation
            // drops every partial owner; a retry must prepare a fresh original open.
            let owner = request.open(entry, deadline)?;
            // This is activation's publication boundary. No fallible work follows
            // installation of the owner; the already-known handle remains closeable.
            check(&entry.cancel, deadline)?;
            *slot = Some(owner);
            Ok(())
        })
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_open_is_cancelable_single_use_and_capacity_bounded() {
        let _serial = TEST_REGISTRY.lock().expect("test registry");
        let mut error = ErrorRecord {
            code: 0,
            length: 0,
            truncated: 0,
            message: [0; 512],
        };
        let mut options = Options {
            kind: 1,
            quality: 1,
            carrier: 0,
            witness: std::ptr::null(),
        };
        let path = b"relative-no-installation";
        let mut handle = 0;
        // SAFETY: all borrowed inputs and each output are distinct live stack regions.
        unsafe {
            assert_eq!(
                qpc_owner_v1_prepare_open(
                    path.as_ptr(),
                    path.len(),
                    &options,
                    &mut handle,
                    &mut error
                ),
                0
            );
            assert_ne!(handle, 0);
            let prior = handle;
            assert_eq!(
                with(handle, Instant::now() + invocation::TIMEOUT, |_, _| Ok(()))
                    .expect_err("pending handle has no operational owner")
                    .code,
                6
            );
            assert_eq!(qpc_owner_v1_cancel(handle, &mut error), 0);
            // Cancellation precedes invalid path I/O, and consumes construction exactly once.
            assert_eq!(qpc_owner_v1_finish_open(handle, &mut error), 302);
            assert_eq!(qpc_owner_v1_finish_open(handle, &mut error), 2);
            assert_eq!(qpc_owner_v1_close(handle, &mut error), 0);
            assert_eq!(qpc_owner_v1_cancel(handle, &mut error), 2);
            assert_eq!(
                qpc_owner_v1_prepare_open(
                    path.as_ptr(),
                    path.len(),
                    &options,
                    &mut handle,
                    &mut error
                ),
                0
            );
            assert!(handle > prior);
            assert_eq!(qpc_owner_v1_finish_open(handle, &mut error), 203);
            assert_eq!(qpc_owner_v1_finish_open(handle, &mut error), 2);
            assert_eq!(qpc_owner_v1_close(handle, &mut error), 0);
            options.kind = 2;
            options.quality = 0;
            let mut pending = Vec::new();
            for _ in 0..MAX_OWNERS {
                assert_eq!(
                    qpc_owner_v1_prepare_open(
                        path.as_ptr(),
                        path.len(),
                        &options,
                        &mut handle,
                        &mut error
                    ),
                    0
                );
                pending.push(handle);
            }
            assert_eq!(
                qpc_owner_v1_prepare_open(
                    path.as_ptr(),
                    path.len(),
                    &options,
                    &mut handle,
                    &mut error
                ),
                4
            );
            assert_eq!(handle, 0);
            for id in pending {
                assert_eq!(qpc_owner_v1_cancel(id, &mut error), 0);
                assert_eq!(qpc_owner_v1_close(id, &mut error), 0);
            }
            assert_eq!(
                qpc_owner_v1_prepare_open(
                    path.as_ptr(),
                    path.len(),
                    &options,
                    &mut handle,
                    &mut error
                ),
                0
            );
            assert_eq!(qpc_owner_v1_cancel(handle, &mut error), 0);
            assert_eq!(qpc_owner_v1_finish_open(handle, &mut error), 302);
            assert_eq!(qpc_owner_v1_close(handle, &mut error), 0);
        }
        // The restoration request copies the caller's selected session and shares
        // the same pending capacity, cancellation and one-shot activation contract.
        options.kind = 1;
        options.quality = 1;
        let mut selected = [73; 32];
        unsafe {
            assert_eq!(
                qpc_owner_v1_prepare_reopen(
                    path.as_ptr(),
                    path.len(),
                    &options,
                    selected.as_ptr(),
                    &mut handle,
                    &mut error
                ),
                0
            );
            selected.fill(0);
            with_entry(handle, Instant::now() + invocation::TIMEOUT, |slot, _| {
                match slot.as_ref() {
                    Some(Owned::Opening(request)) => match &request.kind {
                        Kind::Operational(owner::Admission::Existing { session, .. }) => {
                            assert_eq!(*session, [73; 32])
                        }
                        _ => return Err(Failure::argument()),
                    },
                    _ => return Err(Failure::argument()),
                }
                Ok(())
            })
            .expect("copied exact session");
            assert_eq!(qpc_owner_v1_cancel(handle, &mut error), 0);
            assert_eq!(qpc_owner_v1_finish_open(handle, &mut error), 302);
            assert_eq!(qpc_owner_v1_finish_open(handle, &mut error), 2);
            assert_eq!(qpc_owner_v1_close(handle, &mut error), 0);
            for pointer in [std::ptr::null(), selected.as_ptr()] {
                handle = 99;
                assert_eq!(
                    qpc_owner_v1_prepare_reopen(
                        path.as_ptr(),
                        path.len(),
                        &options,
                        pointer,
                        &mut handle,
                        &mut error
                    ),
                    1
                );
                assert_eq!(handle, 0);
            }
            selected.fill(73);
            options.kind = 2;
            options.quality = 0;
            assert_eq!(
                qpc_owner_v1_prepare_reopen(
                    path.as_ptr(),
                    path.len(),
                    &options,
                    selected.as_ptr(),
                    &mut handle,
                    &mut error
                ),
                1
            );
            assert_eq!(handle, 0);
        }
        assert!(TABLE.lock().expect("table").slots.is_empty());
        assert_eq!(CALLS.load(Ordering::Acquire), 0);
    }
}
