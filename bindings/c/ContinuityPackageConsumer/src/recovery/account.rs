// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete original account cleanup; no operational authority or member subset.
use super::*;

pub(super) struct Account {
    owner: p::InstalledAccountRecovery,
    report: Option<p::FanoutAbandonment>,
}
impl Recovery {
    fn select_account(&mut self, id: p::FanoutId) -> Result<()> {
        let (discovery, anchor) = self.take_discovery()?;
        let owner = discovery.open_account(id, anchor)?;
        self.state = State::Account(Box::new(Account {
            owner,
            report: None,
        }));
        Ok(())
    }
    fn account_owner(&mut self) -> Result<&mut Account> {
        match &mut self.state {
            State::Account(account) => Ok(account),
            State::Closed => Err(p::DurableError::Closed.into()),
            _ => Err(p::Error::State.into()),
        }
    }
    fn account_report(&self) -> Result<&p::FanoutAbandonment> {
        match &self.state {
            State::Account(account) => account
                .report
                .as_ref()
                .ok_or_else(|| p::Error::State.into()),
            State::Closed => Err(p::DurableError::Closed.into()),
            _ => Err(p::Error::State.into()),
        }
    }
    fn account_member(&self, member: u32) -> Result<&p::AbandonedSession> {
        self.account_report()?
            .sessions
            .get(member as usize)
            .ok_or_else(Failure::argument)
    }
    fn account_epoch(&self, member: u32, epoch: u32) -> Result<&p::AbandonedEpoch> {
        self.account_member(member)?
            .epochs
            .get(epoch as usize)
            .ok_or_else(Failure::argument)
    }
}

/// Immutable complete-account report identity and canonical member count.
#[repr(C)]
pub struct AccountHeader {
    pub batch: [u8; 32],
    pub report: [u8; 32],
    pub member_count: u32,
    pub reserved_zero: u32,
}
impl AccountHeader {
    fn from_report(value: &p::FanoutAbandonment) -> Result<Self> {
        let p::FanoutAbandonment {
            batch,
            report,
            sessions,
        } = value;
        Ok(Self {
            batch: *batch.as_bytes(),
            report: *report.as_bytes(),
            member_count: count(sessions.len())?,
            reserved_zero: 0,
        })
    }
}

/// Original member identity, rekey progress and complete retained epoch count.
#[repr(C)]
pub struct Member {
    pub generation: u64,
    pub confirmed_epoch: u64,
    pub sending_epoch: u64,
    pub receiving_epoch: u64,
    pub pending_epoch: u64,
    pub has_pending_epoch: u32,
    pub role: u32,
    pub epoch_count: u32,
    pub reserved_zero: u32,
    pub device: [u8; 16],
    pub context: [u8; 32],
    pub session: [u8; 32],
}
impl Member {
    fn from_session(value: &p::AbandonedSession) -> Result<Self> {
        let p::AbandonedSession {
            device,
            generation,
            context,
            session,
            role,
            progress,
            reserved: _,
            epochs,
        } = value;
        let p::RekeyProgress {
            confirmed_epoch,
            sending_epoch,
            receiving_epoch,
            pending_epoch,
        } = progress;
        Ok(Self {
            generation: *generation,
            confirmed_epoch: *confirmed_epoch,
            sending_epoch: *sending_epoch,
            receiving_epoch: *receiving_epoch,
            pending_epoch: pending_epoch.unwrap_or(0),
            has_pending_epoch: u32::from(pending_epoch.is_some()),
            role: u32::from(*role),
            epoch_count: count(epochs.len())?,
            reserved_zero: 0,
            device: *device,
            context: *context,
            session: *session,
        })
    }
}

/// Select the complete authenticated original account operation, consuming discovery.
/// # Safety
/// ID points to 32 readable bytes; error obeys the C header contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_select_account(
    handle: u64,
    id: *const u8,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: admission precedes reading the caller's fixed-size ID.
    unsafe {
        mutation(handle, error, |owner| {
            owner.select_account(p::FanoutId::from_trusted_state(fixed(id)?)?)
        })
    }
}

/// Irreversibly freeze every original member and retain the complete loss snapshot.
/// # Safety
/// Output/error are aligned, writable and nonoverlapping as specified in the header.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_begin(
    handle: u64,
    output: *mut AccountHeader,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, cancel| {
            cancelled(cancel)?;
            let account = owner.account_owner()?;
            let current = account.owner.journal()?.begin()?;
            let header = AccountHeader::from_report(&current)?;
            account.report = Some(current);
            cancelled(cancel)?;
            Ok(header)
        })
    }
}

/// Query original aggregate state; Committed never proves remote consumption.
/// # Safety
/// Output/error obey the C header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_status(
    handle: u64,
    output: *mut Status,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            let (phase, report) = match owner.account_owner()?.owner.journal()?.status()? {
                p::FanoutStatus::Absent => (0, [0; 32]),
                p::FanoutStatus::Reserved => (1, [0; 32]),
                p::FanoutStatus::Committed => (2, [0; 32]),
                p::FanoutStatus::Abandoning(id) => (3, *id.as_bytes()),
                p::FanoutStatus::Abandoned(id) => (4, *id.as_bytes()),
                p::FanoutStatus::Retired => (5, [0; 32]),
            };
            Ok(Status { phase, report })
        })
    }
}

/// Read one canonical member from the last successful native freeze snapshot.
/// # Safety
/// Output/error obey the C header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_member(
    handle: u64,
    member: u32,
    output: *mut Member,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            Member::from_session(owner.account_member(member)?)
        })
    }
}

/// Read this member's exact uncommitted input identity and lengths, without content.
/// # Safety
/// Output/error obey the C header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_reserved(
    handle: u64,
    member: u32,
    output: *mut Reserved,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            let p::ReservedAbandonment {
                message,
                plaintext_bytes,
                associated_data_bytes,
            } = &owner.account_member(member)?.reserved;
            Ok(Reserved {
                message: *message.as_bytes(),
                plaintext_bytes: length(*plaintext_bytes)?,
                associated_data_bytes: length(*associated_data_bytes)?,
            })
        })
    }
}

/// Read complete scalar accounting and nested counts for one original member epoch.
/// # Safety
/// Output/error obey the C header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_epoch(
    handle: u64,
    member: u32,
    epoch: u32,
    output: *mut Epoch,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            Epoch::from_epoch(owner.account_epoch(member, epoch)?)
        })
    }
}

/// Read the exact unknown outgoing message and native ciphertext commitment.
/// # Safety
/// Output/error obey the C header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_unconfirmed(
    handle: u64,
    member: u32,
    epoch: u32,
    index: u32,
    output: *mut Unconfirmed,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            let value = owner
                .account_epoch(member, epoch)?
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

/// Read the exact unconsumed incoming message position and length, without plaintext.
/// # Safety
/// Output/error obey the C header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_delivery(
    handle: u64,
    member: u32,
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
                .account_epoch(member, epoch)?
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

/// Read an observed skipped position, not a claim that the peer sent a message.
/// # Safety
/// Output/error obey the C header writable-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_skipped(
    handle: u64,
    member: u32,
    epoch: u32,
    index: u32,
    output: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        result(handle, output, error, |owner, _| {
            owner
                .account_epoch(member, epoch)?
                .skipped
                .get(index as usize)
                .copied()
                .ok_or_else(Failure::argument)
        })
    }
}

/// Acknowledge all members only after durable, deduplicated host loss accounting.
/// # Safety
/// Report points to 32 readable bytes; error is separate and writable.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_acknowledge(
    handle: u64,
    report: *const u8,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        mutation(handle, error, |owner| {
            let report = p::FanoutAbandonmentId::from_trusted_state(fixed(report)?)?;
            Ok(owner
                .account_owner()?
                .owner
                .journal()?
                .acknowledge(report)?)
        })
    }
}

/// Retire only this already acknowledged batch's metadata, preserving all tombstones.
/// # Safety
/// Error obeys the C header diagnostic-region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_recovery_v1_account_retire(
    handle: u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        mutation(handle, error, |owner| {
            Ok(owner.account_owner()?.owner.journal()?.retire_metadata()?)
        })
    }
}
