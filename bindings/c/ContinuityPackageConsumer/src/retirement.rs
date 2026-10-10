// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Restricted whole-device retirement. All authority and storage transitions remain native.
use super::*;

const REPLACEMENT_BYTES: usize = 450 + 256 * 224;
const RETIREMENT_RECEIPT_BYTES: usize = 3754;
const INVENTORY_RECEIPT_BYTES: usize = 3690;
const REPORT_RECEIPT_BYTES: usize = 3730;
const REPORT_BYTES: usize = 4 * p::contract::MAX_JOURNAL_IMAGE_BYTES;

/// Independent witness pin, exact retained replacement and permanent old-subject proof.
#[repr(C)]
pub struct Options {
    pub witness: [u8; 32],
    pub public_key: *const u8,
    pub public_key_length: usize,
    pub replacement: *const u8,
    pub replacement_length: usize,
    pub subject: [u8; 96],
    pub receipt: *const u8,
    pub receipt_length: usize,
}
pub(crate) struct Admission {
    intent: p::EnrollmentIntent,
    pin: p::AnchorPin,
    retired: p::AnchorRetiredSubject,
}
impl Admission {
    pub(crate) unsafe fn read(
        intent: *const enrollment::Intent,
        options: *const Options,
    ) -> Result<Self> {
        if options.is_null() || !options.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: immutable aligned options and their bounded regions live for preparation.
        let input = unsafe { &*options };
        let approved = unsafe { enrollment::Approved::read(intent) }?;
        let key = p::PublicKey::decode(&unsafe {
            bytes(
                input.public_key,
                input.public_key_length,
                p::PUBLIC_KEY_BYTES,
            )
        }?)?;
        let pin = p::AnchorPin::new(p::AnchorIdentity::from_trusted_state(input.witness)?, key);
        let proposal = p::AnchorDeviceReplacementProposal::from_trusted_state(&unsafe {
            bytes(
                input.replacement,
                input.replacement_length,
                REPLACEMENT_BYTES,
            )
        }?)?;
        let subject = p::AnchorSubject::from_trusted_state(&input.subject)?;
        let receipt = unsafe {
            exact(
                input.receipt,
                input.receipt_length,
                RETIREMENT_RECEIPT_BYTES,
            )
        }?;
        let retired = pin.verify_retired_subject(&proposal, subject, &receipt)?;
        Ok(Self {
            intent: approved.into_native(),
            pin,
            retired,
        })
    }
}
pub(crate) struct Owner {
    native: p::RetiredDeviceEnrollment,
    pin: p::AnchorPin,
    report: Option<p::retired_device::Report>,
}
impl Owner {
    pub(crate) fn open(
        path: &Path,
        admission: Admission,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Box<Self>> {
        opening::check(cancel, deadline)?;
        let native = p::RetiredDeviceEnrollment::open(
            enrollment::paths(path)?,
            admission.intent,
            admission.pin.clone(),
            admission.retired,
        )?;
        let owner = Box::new(Self {
            native,
            pin: admission.pin,
            report: None,
        });
        opening::check(cancel, deadline)?;
        Ok(owner)
    }
}
/// Canonical public inventory expectation; bytes alone do not grant authority.
#[repr(C)]
pub struct Inventory {
    pub bytes: [u8; 313],
}
/// Presence is 0 or 1; absent bytes are all zero and assert no external outcome.
#[repr(C)]
pub struct Proposal {
    pub present: u32,
    pub bytes: [u8; 353],
    pub reserved_zero: [u8; 3],
}
impl Proposal {
    fn observed(value: Option<p::AnchorRetiredReportProposal>) -> Result<Self> {
        Ok(match value {
            Some(value) => Self {
                present: 1,
                bytes: value.to_bytes().try_into().map_err(|_| failure(5))?,
                reserved_zero: [0; 3],
            },
            None => Self {
                present: 0,
                bytes: [0; 353],
                reserved_zero: [0; 3],
            },
        })
    }
}
/// The cached complete canonical report is immutable until erasure or owner close.
#[repr(C)]
pub struct ReportInfo {
    pub length: usize,
    pub views: u32,
    pub reserved_zero: u32,
    pub report: [u8; 32],
}
unsafe fn exact(pointer: *const u8, length: usize, expected: usize) -> Result<Vec<u8>> {
    if length != expected {
        return Err(Failure::argument());
    }
    // SAFETY: forwarded readable bounded region; length checked before construction.
    unsafe { bytes(pointer, length, expected) }
}
fn with_retired<T>(
    handle: u64,
    deadline: Instant,
    close_after: bool,
    action: impl FnOnce(&mut Owner) -> Result<T>,
) -> Result<T> {
    with_entry(handle, deadline, |slot, entry| {
        match slot.as_ref() {
            None => return Err(failure(2)),
            Some(Owned::Retirement(_)) => {}
            _ => return Err(failure(6)),
        }
        // Pre-cancellation leaves the original owner available for explicit close.
        opening::check(&entry.cancel, deadline)?;
        let Some(Owned::Retirement(mut owner)) = slot.take() else {
            return Err(failure(5));
        };
        // Once admitted, any native failure/late cancellation consumes the resource.
        // Its committed original intent remains recoverable through exact reopen.
        let result = action(&mut owner)?;
        opening::check(&entry.cancel, deadline)?;
        if !close_after {
            *slot = Some(Owned::Retirement(owner));
        }
        Ok(result)
    })
}
unsafe fn scalar<T>(
    handle: u64,
    target: *mut T,
    error: *mut ErrorRecord,
    action: impl FnOnce(&mut Owner) -> Result<T>,
) -> i32 {
    let run = |deadline| {
        output(target)?;
        let value = with_retired(handle, deadline, false, action)?;
        // SAFETY: exclusive aligned output; no write occurs after an operation error.
        unsafe { put(target, value) };
        Ok(())
    };
    // SAFETY: forwarded diagnostic region.
    unsafe { boundary(error, false, run) }
}

/// Recover the original inventory captured by restricted enrollment opening.
/// # Safety
/// All regions obey the header's pointer/alignment/nonoverlap contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_inventory(
    handle: u64,
    target: *mut Inventory,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        scalar(handle, target, error, |o| {
            Ok(Inventory {
                bytes: o
                    .native
                    .installation()?
                    .proposal()?
                    .to_bytes()
                    .try_into()
                    .map_err(|_| failure(5))?,
            })
        })
    }
}
/// Retain the complete report expectation under verified independent inventory retention.
/// # Safety
/// Header regions are live, bounded and nonoverlapping for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_prepare_report(
    handle: u64,
    receipt: *const u8,
    length: usize,
    target: *mut Proposal,
    error: *mut ErrorRecord,
) -> i32 {
    let run = |deadline| {
        output(target)?;
        let wire = unsafe { exact(receipt, length, INVENTORY_RECEIPT_BYTES) }?;
        let value = with_retired(handle, deadline, false, |o| {
            let child = o.native.installation()?;
            let retained = child.verify_retained(&o.pin, &wire)?;
            Proposal::observed(Some(child.prepare_report(&retained)?))
        })?;
        unsafe { put(target, value) };
        Ok(())
    };
    unsafe { boundary(error, false, run) }
}
/// Read local original report-request presence without inferring witness non-commit.
/// # Safety
/// Header output regions are writable, aligned and distinct.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_report_proposal(
    handle: u64,
    target: *mut Proposal,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        scalar(handle, target, error, |o| {
            Proposal::observed(o.native.installation()?.report_proposal()?)
        })
    }
}
/// Authenticate and cache the complete canonical metadata report; no host ACK occurs.
/// # Safety
/// Header regions are live, bounded and nonoverlapping for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_load_report(
    handle: u64,
    inventory: *const u8,
    inventory_length: usize,
    receipt: *const u8,
    receipt_length: usize,
    target: *mut ReportInfo,
    error: *mut ErrorRecord,
) -> i32 {
    let run = |deadline| {
        output(target)?;
        let inventory = unsafe { exact(inventory, inventory_length, INVENTORY_RECEIPT_BYTES) }?;
        let wire = unsafe { exact(receipt, receipt_length, REPORT_RECEIPT_BYTES) }?;
        let info = with_retired(handle, deadline, false, |o| {
            let child = o.native.installation()?;
            let retained = child.verify_retained(&o.pin, &inventory)?;
            let report = child.report(&retained, &o.pin, &wire)?;
            let info = ReportInfo {
                length: report.as_bytes().len(),
                views: u32::try_from(report.views().len()).map_err(|_| p::Error::Capacity)?,
                reserved_zero: 0,
                report: *report.proposal().report_id(),
            };
            if info.length > REPORT_BYTES {
                return Err(p::Error::Capacity.into());
            }
            o.report = Some(report);
            Ok(info)
        })?;
        unsafe { put(target, info) };
        Ok(())
    };
    unsafe { boundary(error, false, run) }
}
/// Copy exactly the loaded canonical report, including every metadata view.
/// # Safety
/// The output denotes length writable bytes, distinct from the diagnostic.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_copy_report(
    handle: u64,
    target: *mut u8,
    length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let run = |deadline| {
        output(target)?;
        if length == 0 || length > REPORT_BYTES {
            return Err(Failure::argument());
        }
        let copy = with_retired(handle, deadline, false, |o| {
            let report = o.report.as_ref().ok_or(p::Error::State)?;
            if report.as_bytes().len() != length {
                return Err(Failure::argument());
            }
            Ok(report.as_bytes().to_vec())
        })?;
        // SAFETY: exact validated length; owned source is disjoint from caller output.
        unsafe { std::ptr::copy_nonoverlapping(copy.as_ptr(), target, length) };
        Ok(())
    };
    unsafe { boundary(error, false, run) }
}
/// Retain a host-accounted intent only after the host saved the complete report.
/// # Safety
/// Header inputs/outputs remain readable/writable and mutually nonoverlapping.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_prepare_acknowledgement(
    handle: u64,
    inventory: *const u8,
    inventory_length: usize,
    receipt: *const u8,
    receipt_length: usize,
    recorded: *const u8,
    recorded_length: usize,
    target: *mut Proposal,
    error: *mut ErrorRecord,
) -> i32 {
    let run = |deadline| {
        output(target)?;
        let inventory = unsafe { exact(inventory, inventory_length, INVENTORY_RECEIPT_BYTES) }?;
        let wire = unsafe { exact(receipt, receipt_length, REPORT_RECEIPT_BYTES) }?;
        let recorded = unsafe { bytes(recorded, recorded_length, REPORT_BYTES) }?;
        let proposal = with_retired(handle, deadline, false, |o| {
            let child = o.native.installation()?;
            let inventory = child.verify_retained(&o.pin, &inventory)?;
            let proposal = child.report_proposal()?.ok_or(p::DurableError::Suspended)?;
            let retained = o.pin.verify_retired_report(&inventory, &proposal, &wire)?;
            Proposal::observed(Some(
                child.prepare_host_acknowledgement(&recorded, &retained)?,
            ))
        })?;
        unsafe { put(target, proposal) };
        Ok(())
    };
    unsafe { boundary(error, false, run) }
}
/// Recover local host-intent presence, including after original journal loss.
/// # Safety
/// Header output regions are writable, aligned and distinct.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_acknowledgement_proposal(
    handle: u64,
    target: *mut Proposal,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        scalar(handle, target, error, |o| {
            Proposal::observed(o.native.installation()?.host_acknowledgement_proposal()?)
        })
    }
}
/// Query 0=Retained, 1=Erased after an original host-accounted intent exists.
/// # Safety
/// Header output regions are writable, aligned and distinct.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_journal_state(
    handle: u64,
    target: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        scalar(handle, target, error, |o| {
            Ok(
                match o.native.installation()?.journal_erasure_status(&o.pin)? {
                    p::retired_device::JournalErasureState::Retained => 0,
                    p::retired_device::JournalErasureState::Erased => 1,
                },
            )
        })
    }
}
/// Logically erase the original journal under an independently signed purpose-21 ACK.
/// # Safety
/// Header regions are live, bounded and nonoverlapping for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_erase_journal(
    handle: u64,
    receipt: *const u8,
    length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let run = |deadline| {
        let wire = unsafe { exact(receipt, length, REPORT_RECEIPT_BYTES) }?;
        with_retired(handle, deadline, false, |o| {
            o.native.installation()?.erase_journal(&o.pin, &wire)?;
            o.report = None;
            Ok(())
        })
    };
    unsafe { boundary(error, false, run) }
}
/// Capture the exact original signer erasure plan after authenticated journal erasure.
/// # Safety
/// Header regions are live, bounded and nonoverlapping for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_prepare_signer_erasure(
    handle: u64,
    receipt: *const u8,
    length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let run = |deadline| {
        let wire = unsafe { exact(receipt, length, REPORT_RECEIPT_BYTES) }?;
        with_retired(handle, deadline, false, |o| {
            Ok(o.native.prepare_signer_erasure(&wire)?)
        })
    };
    unsafe { boundary(error, false, run) }
}
/// Query 0=Retained, 1=Erased for the prepared original signer file.
/// # Safety
/// Header output regions are writable, aligned and distinct.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_signer_state(
    handle: u64,
    target: *mut u32,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe {
        scalar(handle, target, error, |o| {
            Ok(match o.native.signer_erasure_status()? {
                p::SigningFileErasureState::Retained => 0,
                p::SigningFileErasureState::Erased => 1,
            })
        })
    }
}
/// Logically erase the exact prepared signer; consumes the resource even on success.
/// # Safety
/// The diagnostic is a live aligned writable region.
#[no_mangle]
pub unsafe extern "C" fn qpc_retired_v1_erase_signer(handle: u64, error: *mut ErrorRecord) -> i32 {
    unsafe {
        boundary(error, false, |deadline| {
            with_retired(handle, deadline, true, |o| Ok(o.native.erase_signer()?))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retirement_output_layout_has_no_implicit_padding() {
        assert_eq!(std::mem::size_of::<Inventory>(), 313);
        assert_eq!(std::mem::size_of::<Proposal>(), 360);
        assert_eq!(std::mem::offset_of!(Proposal, reserved_zero), 357);
        assert_eq!(
            std::mem::offset_of!(ReportInfo, report),
            std::mem::size_of::<usize>() + 8
        );
        assert_eq!(
            std::mem::size_of::<ReportInfo>(),
            std::mem::size_of::<usize>() + 40
        );
        let absent = Proposal::observed(None).expect("local absent proposal");
        assert_eq!(absent.present, 0);
        assert_eq!(absent.bytes, [0; 353]);
        assert_eq!(absent.reserved_zero, [0; 3]);
    }
}
