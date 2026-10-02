// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete-account admission through one original device and all retained peers.
use super::*;
use p::connection_transport::{AccountDelivered, AccountDeliveryOutcome};

/// One live peer child and its exact established session, borrowed for one call.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Target {
    pub peer: u64,
    pub session: [u8; 32],
}

/// One member's native outcome. It never asserts atomic remote account delivery.
#[derive(Default)]
#[repr(C)]
pub struct Delivered {
    pub device: [u8; 16],
    pub session: [u8; 32],
    pub message: [u8; 32],
    pub outcome: u32,
    pub exchanges: u32,
}
impl From<AccountDelivered> for Delivered {
    fn from(result: AccountDelivered) -> Self {
        Self {
            device: result.device,
            session: result.session,
            message: *result.message.as_bytes(),
            outcome: match result.outcome {
                AccountDeliveryOutcome::Consumption(Consumption::Confirmed) => 1,
                AccountDeliveryOutcome::Consumption(Consumption::PrefixPending) => 2,
                AccountDeliveryOutcome::ResolutionPending => 3,
                AccountDeliveryOutcome::DeliveryUnknown => 4,
                AccountDeliveryOutcome::HistoryRetired => 5,
                AccountDeliveryOutcome::ReservationAbandoned => 6,
            },
            exchanges: u32::from(result.exchanges),
        }
    }
}

unsafe fn targets(pointer: *const Target, count: usize, selected: usize) -> Result<Vec<Target>> {
    if count == 0
        || count > p::MAX_DEVICES
        || selected >= count
        || pointer.is_null()
        || !pointer.is_aligned()
    {
        return Err(Failure::argument());
    }
    // SAFETY: caller supplies count readable aligned Target records; count is bounded.
    let values = unsafe { std::slice::from_raw_parts(pointer, count) }.to_vec();
    let mut peers = std::collections::BTreeSet::new();
    let mut sessions = std::collections::BTreeSet::new();
    for value in &values {
        if value.peer == 0
            || value.session == [0; 32]
            || !peers.insert(value.peer)
            || !sessions.insert(value.session)
        {
            return Err(Failure::argument());
        }
    }
    Ok(values)
}

/// Pin and nonblockingly lock the complete set in handle order. No scope or
/// parent service is borrowed after these guards are released. Any selected
/// child's cancellation signals this call, without cancelling the parent or
/// another child's permanent token. A closed/busy/cancelled member rejects the
/// whole call before native reservation or network dispatch.
fn with_peers<T>(
    parent: u64,
    targets: &[Target],
    selected: usize,
    deadline: Instant,
    action: impl FnOnce(&mut owner::Operation<'_>, &[p::FanoutTarget<'_>], &Cancellation) -> Result<T>,
) -> Result<T> {
    let parent = device::parent(parent, deadline)?;
    let selected = targets.get(selected).ok_or_else(Failure::argument)?.peer;
    let mut entries = targets
        .iter()
        .map(|target| Ok((target.peer, entry(target.peer)?)))
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by_key(|(handle, _)| *handle);
    let cancel = Cancellation::default();
    let mut locked = Vec::with_capacity(entries.len());
    let mut scopes = Vec::with_capacity(entries.len());
    for (_, entry) in &entries {
        opening::check(&entry.cancel, deadline)?;
        let guard = match entry.owner.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(failure(3)),
            Err(TryLockError::Poisoned(error)) => {
                entry.cancel.cancel();
                error.into_inner().take();
                return Err(failure(5));
            }
        };
        match guard.as_ref() {
            Some(Owned::Peer(peer)) if peer.belongs_to(&parent) => {}
            Some(Owned::Peer(_)) => return Err(p::DurableError::Conflict.into()),
            None => return Err(failure(2)),
            _ => return Err(failure(6)),
        }
        scopes.push(entry.invocation.enter(deadline, &cancel)?);
        // Closes the cancel-before-enter race without resetting any owner token.
        opening::check(&entry.cancel, deadline)?;
        locked.push(guard);
    }
    let contexts = locked
        .iter()
        .zip(&entries)
        .map(|(guard, (handle, _))| {
            let Some(Owned::Peer(peer)) = guard.as_ref() else {
                return Err(failure(5));
            };
            let session = targets
                .iter()
                .find(|target| target.peer == *handle)
                .ok_or_else(|| failure(5))?
                .session;
            Ok((Arc::clone(peer.context()), session))
        })
        .collect::<Result<Vec<_>>>()?;
    let native_targets = contexts
        .iter()
        .map(|(context, session)| p::FanoutTarget {
            context,
            session: *session,
        })
        .collect::<Vec<_>>();
    let index = entries
        .iter()
        .position(|(handle, _)| *handle == selected)
        .ok_or_else(|| failure(5))?;
    let guard = locked.get_mut(index).ok_or_else(|| failure(5))?;
    let Some(Owned::Peer(peer)) = guard.as_mut() else {
        return Err(failure(5));
    };
    let result = peer.with_operation(deadline, &cancel, |operation, cancel| {
        action(operation, &native_targets, cancel)
    })?;
    for (_, entry) in &entries {
        opening::check(&entry.cancel, deadline)?;
    }
    opening::check(&cancel, deadline)?;
    Ok(result)
}

/// Read the original journal's next account ID. This does not reserve or dispatch.
/// # Safety
/// Output and diagnostic regions obey the C header's pointer/overlap contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_device_v1_next_account(
    parent: u64,
    id: *mut u8,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(id)?;
        unsafe { put(id.cast::<[u8; 32]>(), [0; 32]) };
        let result = device::parent(parent, deadline)?
            .with_journal(deadline, |journal| Ok(journal.next_fanout_id()?))?;
        unsafe { put(id.cast::<[u8; 32]>(), *result.as_bytes()) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Read aggregate local status with its exact accounting report, never inferred delivery.
/// # Safety
/// ID is 32 readable bytes, report is 32 writable bytes, and all regions are distinct.
#[no_mangle]
pub unsafe extern "C" fn qpc_device_v1_account_status(
    parent: u64,
    id: *const u8,
    status: *mut u8,
    report: *mut u8,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        output(report)?;
        unsafe {
            put(status, 0);
            put(report.cast::<[u8; 32]>(), [0; 32]);
        }
        let id = p::FanoutId::from_trusted_state(unsafe { fixed(id) }?)?;
        let result = device::parent(parent, deadline)?
            .with_journal(deadline, |journal| Ok(journal.fanout_status(id)?))?;
        let (state, id) = match result {
            p::FanoutStatus::Absent => (0, [0; 32]),
            p::FanoutStatus::Reserved => (1, [0; 32]),
            p::FanoutStatus::Committed => (2, [0; 32]),
            p::FanoutStatus::Abandoning(id) => (3, *id.as_bytes()),
            p::FanoutStatus::Abandoned(id) => (4, *id.as_bytes()),
            p::FanoutStatus::Retired => (5, [0; 32]),
        };
        unsafe {
            put(status, state);
            put(report.cast::<[u8; 32]>(), id);
        }
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Admit/reconcile one complete-roster operation and deliver one selected member.
/// # Safety
/// All input, array and output regions satisfy the header's shape and lifetime contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_device_v1_send_account_member(
    parent: u64,
    recipients: *const Target,
    count: usize,
    selected: usize,
    id: *const u8,
    account: *const u8,
    peer: *const u8,
    peer_length: usize,
    plaintext: *const u8,
    plaintext_length: usize,
    ad: *const u8,
    ad_length: usize,
    delivered: *mut Delivered,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(delivered)?;
        unsafe { put(delivered, Delivered::default()) };
        let targets = unsafe { targets(recipients, count, selected) }?;
        let session = targets.get(selected).ok_or_else(Failure::argument)?.session;
        let id = p::FanoutId::from_trusted_state(unsafe { fixed(id) }?)?;
        let account = unsafe { fixed(account) }?;
        let address = address(&unsafe { text(peer, peer_length, 128) }?)?;
        let plaintext = zeroize::Zeroizing::new(unsafe {
            bytes(
                plaintext,
                plaintext_length,
                p::contract::MAX_PLAINTEXT_BYTES,
            )
        }?);
        let ad = unsafe { bytes(ad, ad_length, p::contract::MAX_ASSOCIATED_DATA_BYTES) }?;
        let result = with_peers(
            parent,
            &targets,
            selected,
            deadline,
            |owner, targets, cancel| {
                let endpoint = owner.endpoint()?;
                let name = owner.peer_name.to_owned();
                Ok(endpoint.send_account_member(
                    owner.actor()?,
                    p::FanoutInput {
                        id,
                        account,
                        targets,
                        plaintext: &plaintext,
                        associated_data: &ad,
                    },
                    session,
                    owner::run(address, &name, cancel, deadline),
                    owner::now,
                )?)
            },
        )?;
        unsafe { put(delivered, result.into()) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}
