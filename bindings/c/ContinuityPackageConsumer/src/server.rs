// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Owned listener and synchronous application-transaction boundary.
use super::*;
use p::connection_transport::{Consumer, Served};
use std::{ffi::c_void, io};

/// Foreign application transaction; all borrowed byte regions expire on return.
pub type Commit = unsafe extern "C" fn(*mut c_void, *const u8, *const u8, *const u8, usize) -> i32;

/// One completed server exchange, meaningful only when the call returns zero.
#[repr(C)]
pub struct ServedRecord {
    /// One is bootstrap activation; two is authenticated application consumption.
    pub kind: u32,
    /// Original transcript-bound session.
    pub session: [u8; 32],
    /// Original message, or zero for bootstrap.
    pub message: [u8; 32],
    /// One means already consumed, so the application callback was not called.
    pub duplicate: u32,
}
struct Application {
    commit: Commit,
    context: *mut c_void,
}
impl Consumer for Application {
    fn commit(&mut self, session: [u8; 32], delivery: &p::CommittedPlaintext) -> io::Result<()> {
        // SAFETY: the foreign function/context satisfy the serve precondition;
        // these immutable byte owners live through the synchronous invocation.
        let status = unsafe {
            (self.commit)(
                self.context,
                session.as_ptr(),
                delivery.message_id().as_bytes().as_ptr(),
                delivery.as_bytes().as_ptr(),
                delivery.as_bytes().len(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "application callback returned {status}; reconcile the original transaction"
            )))
        }
    }
}

/// Bind one owner-held listener. Port zero requests an OS-selected ephemeral port.
/// # Safety
/// Regions satisfy the header's readable, writable, aligned and nonoverlap rules.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_listen(
    handle: u64,
    address: *const u8,
    length: usize,
    port: *mut u16,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(port)?;
        // SAFETY: forwarded exact header input/output obligations.
        unsafe { put(port, 0) };
        let address: SocketAddr = unsafe { text(address, length, 128) }?
            .parse()
            .map_err(|_| Failure::argument())?;
        let selected = with(handle, deadline, |owner, cancel| {
            if cancel.is_cancelled() {
                return Err(p::connection_transport::Error::Cancelled.into());
            }
            owner.listen(address)
        })?;
        unsafe { put(port, selected) };
        Ok(())
    };
    // SAFETY: forwarded per-call diagnostic obligation.
    unsafe { boundary(error, false, action) }
}

/// Receive one bootstrap or application exchange through the shared engine.
/// # Safety
/// The callback is valid and synchronous, never unwinds/longjmps, retains no
/// borrowed pointer, and its context remains live for the entire invocation.
/// Zero means effect and deduplication record are durable together. Header pointer
/// obligations apply; callbacks use distinct diagnostic/output buffers if reentrant.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_serve(
    handle: u64,
    commit: Option<Commit>,
    context: *mut c_void,
    result: *mut ServedRecord,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(result)?;
        // SAFETY: forwarded writable output obligation.
        unsafe {
            put(
                result,
                ServedRecord {
                    kind: 0,
                    session: [0; 32],
                    message: [0; 32],
                    duplicate: 0,
                },
            )
        };
        let commit = commit.ok_or_else(Failure::argument)?;
        let event = with(handle, deadline, |owner, cancel| {
            let endpoint = owner.server()?;
            let stream = owner.accept(cancel, deadline)?;
            Ok(endpoint.serve(
                stream,
                owner.actor()?,
                &mut Application { commit, context },
                owner::serve_limits(deadline),
                cancel,
                owner::now,
            )?)
        })?;
        let value = match event {
            Served::Established(session) => ServedRecord {
                kind: 1,
                session,
                message: [0; 32],
                duplicate: 0,
            },
            Served::Consumed {
                session,
                message,
                duplicate,
            } => ServedRecord {
                kind: 2,
                session,
                message: *message.as_bytes(),
                duplicate: u32::from(duplicate),
            },
        };
        unsafe { put(result, value) };
        Ok(())
    };
    // SAFETY: forwarded per-call diagnostic obligation.
    unsafe { boundary(error, false, action) }
}

/// Receive one rekey exchange for the original caller-selected session.
/// # Safety
/// The 32-byte session, epoch and diagnostic regions satisfy the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_owner_v1_serve_rekey(
    handle: u64,
    session: *const u8,
    epoch: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(epoch)?;
        // SAFETY: forwarded exact header input/output obligations.
        unsafe { put(epoch, 0) };
        let session = unsafe { fixed(session) }?;
        let completed = with(handle, deadline, |owner, cancel| {
            let endpoint = owner.control_server(session)?;
            let stream = owner.accept(cancel, deadline)?;
            let (journal, _) = owner.service.stores()?;
            Ok(endpoint.serve(
                stream,
                p::control_transport::Session {
                    journal,
                    context: owner.context,
                    signer: owner.signer,
                },
                owner::serve_limits(deadline),
                cancel,
                owner::now,
            )?)
        })?;
        unsafe { put(epoch, completed.epoch) };
        Ok(())
    };
    // SAFETY: forwarded per-call diagnostic obligation.
    unsafe { boundary(error, false, action) }
}
