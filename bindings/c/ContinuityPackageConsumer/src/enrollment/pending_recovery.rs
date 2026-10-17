// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact original pending-write recovery through the existing enrollment owner.
use super::*;

const PROPOSAL_BYTES: usize = p::AnchorPendingWriteRecoveryProposal::ENCODED_BYTES;
const METADATA_BYTES: usize = 4 * p::contract::MAX_JOURNAL_IMAGE_BYTES;
const SIGNED_REQUEST_BYTES: usize = 8192;

/// Lengths describe one cached immutable request; no field grants approval.
#[repr(C)]
pub struct RequestInfo {
    pub metadata_length: u32,
    pub signed_request_length: u32,
    pub proposal: [u8; 393],
    pub reserved_zero: [u8; 3],
    pub binding: [u8; 32],
}
impl RequestInfo {
    fn observed(value: &p::PendingWriteRecoveryRequest) -> Result<Self> {
        if value.metadata().is_empty()
            || value.metadata().len() > METADATA_BYTES
            || value.signed_request().is_empty()
            || value.signed_request().len() > SIGNED_REQUEST_BYTES
        {
            return Err(p::Error::Capacity.into());
        }
        Ok(Self {
            metadata_length: u32::try_from(value.metadata().len())
                .map_err(|_| p::Error::Capacity)?,
            signed_request_length: u32::try_from(value.signed_request().len())
                .map_err(|_| p::Error::Capacity)?,
            proposal: value
                .proposal()
                .to_bytes()
                .try_into()
                .map_err(|_| failure(5))?,
            reserved_zero: [0; 3],
            binding: value.proposal().binding(),
        })
    }
}

/// Cache complete original metadata without replay, network or a live runtime.
/// # Safety
/// Info/error are aligned, writable, complete, disjoint invocation-local records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_pending_write_request(
    handle: u64,
    info: *mut RequestInfo,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(info)?;
        let result = with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let pin = owner
                .witness
                .as_ref()
                .ok_or(p::DurableError::AnchorRequired)?
                .pin(&owner.path)?;
            let request = owner
                .enrollment
                .pending_write_recovery_request(&original, &pin)?;
            let info = RequestInfo::observed(&request)?;
            owner.pending_recovery = Some(request);
            Ok(info)
        })?;
        // SAFETY: publish only after successful owner, deadline and cancellation checks.
        unsafe { put(info, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}

/// Copy both complete outputs from the same request identified by its binding.
/// # Safety
/// Binding has32 readable bytes; outputs have their stated writable lengths.
/// All regions, including error, are disjoint and live for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_copy_pending_write_request(
    handle: u64,
    binding: *const u8,
    metadata: *mut u8,
    metadata_length: usize,
    signed_request: *mut u8,
    signed_request_length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        if metadata.is_null()
            || signed_request.is_null()
            || !(1..=METADATA_BYTES).contains(&metadata_length)
            || !(1..=SIGNED_REQUEST_BYTES).contains(&signed_request_length)
        {
            return Err(Failure::argument());
        }
        // SAFETY: fixed input is copied before owner admission; no output slice is formed.
        let binding = unsafe { fixed(binding)? };
        let (saved_metadata, saved_request) = with_owner(handle, deadline, |owner, _| {
            let request = owner.pending_recovery.as_ref().ok_or(p::Error::State)?;
            if request.proposal().binding() != binding {
                return Err(p::Error::Conflict.into());
            }
            if request.metadata().len() != metadata_length
                || request.signed_request().len() != signed_request_length
            {
                return Err(Failure::argument());
            }
            Ok((
                request.metadata().to_vec(),
                request.signed_request().to_vec(),
            ))
        })?;
        // SAFETY: complete disjoint outputs were validated; publish neither on error.
        unsafe {
            std::ptr::copy_nonoverlapping(saved_metadata.as_ptr(), metadata, metadata_length);
            std::ptr::copy_nonoverlapping(
                saved_request.as_ptr(),
                signed_request,
                signed_request_length,
            );
        }
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}

/// Fresh signed Query confirms only the exact approved original target.
/// # Safety
/// Inputs are readable for their lengths, disjoint from writable diagnostics.
/// No caller pointer is retained. All input bounds are checked before owner admission.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_confirm_pending_write_recovery(
    handle: u64,
    approved: *const u8,
    approved_length: usize,
    metadata: *const u8,
    metadata_length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        if approved_length != PROPOSAL_BYTES || !(1..=METADATA_BYTES).contains(&metadata_length) {
            return Err(Failure::argument());
        }
        // SAFETY: checked lengths bound immutable readable caller regions.
        let approved = p::AnchorPendingWriteRecoveryProposal::from_trusted_state(&unsafe {
            bytes(approved, approved_length, PROPOSAL_BYTES)
        }?)?;
        let metadata = unsafe { bytes(metadata, metadata_length, METADATA_BYTES) }?;
        with_owner(handle, deadline, |owner, entry| {
            let original = owner.historical_policy(entry, deadline)?;
            let parameters = owner
                .witness
                .as_ref()
                .ok_or(p::DurableError::AnchorRequired)?
                .parameters(&owner.path, entry.cancel.clone(), entry.invocation.clone())?;
            owner.enrollment.confirm_pending_write_recovery(
                &approved,
                &metadata,
                &original,
                parameters.pin,
                parameters.transport,
                parameters.timeout,
            )?;
            Ok(())
        })
    };
    // SAFETY: forwarded invocation-local diagnostics contract.
    unsafe { boundary(error, false, action) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn diagnostics() -> ErrorRecord {
        ErrorRecord {
            code: 0,
            length: 0,
            truncated: 0,
            message: [0; 512],
        }
    }
    #[test]
    fn pending_request_layout_and_failed_output_are_stable() {
        let _serial = TEST_REGISTRY.lock().expect("test registry");
        assert_eq!(std::mem::size_of::<RequestInfo>(), 436);
        assert_eq!(std::mem::align_of::<RequestInfo>(), 4);
        assert_eq!(std::mem::offset_of!(RequestInfo, proposal), 8);
        assert_eq!(std::mem::offset_of!(RequestInfo, binding), 404);
        let mut info = RequestInfo {
            metadata_length: 123,
            signed_request_length: 456,
            proposal: [7; 393],
            reserved_zero: [8; 3],
            binding: [9; 32],
        };
        let mut error = diagnostics();
        // SAFETY: all outputs are valid and separate; zero is an unknown handle.
        assert_eq!(
            unsafe { qpc_enrollment_v1_pending_write_request(0, &mut info, &mut error) },
            2
        );
        assert_eq!(
            (info.metadata_length, info.signed_request_length),
            (123, 456)
        );
        assert_eq!(info.proposal, [7; 393]);
        assert_eq!(info.reserved_zero, [8; 3]);
        assert_eq!(info.binding, [9; 32]);
    }
    #[test]
    fn pending_bounds_are_checked_before_reading_or_owner_admission() {
        let _serial = TEST_REGISTRY.lock().expect("test registry");
        let unreadable = std::ptr::dangling::<u8>();
        let mut error = diagnostics();
        for (proposal, metadata) in [(392, 1), (394, 1), (393, 0), (393, METADATA_BYTES + 1)] {
            // SAFETY: these rejected sizes must not dereference either pointer.
            assert_eq!(
                unsafe {
                    qpc_enrollment_v1_confirm_pending_write_recovery(
                        0, unreadable, proposal, unreadable, metadata, &mut error,
                    )
                },
                1
            );
        }
        // SAFETY: invalid lengths reject before binding or output memory is read/written.
        assert_eq!(
            unsafe {
                qpc_enrollment_v1_copy_pending_write_request(
                    0,
                    unreadable,
                    unreadable.cast_mut(),
                    METADATA_BYTES + 1,
                    unreadable.cast_mut(),
                    1,
                    &mut error,
                )
            },
            1
        );
    }
    #[test]
    fn pending_copy_failure_publishes_neither_output() {
        let _serial = TEST_REGISTRY.lock().expect("test registry");
        let binding = [1; 32];
        let mut metadata = [2; 8];
        let mut signature = [3; 8];
        let mut error = diagnostics();
        // SAFETY: complete separate output regions, fixed binding and diagnostics.
        assert_eq!(
            unsafe {
                qpc_enrollment_v1_copy_pending_write_request(
                    0,
                    binding.as_ptr(),
                    metadata.as_mut_ptr(),
                    metadata.len(),
                    signature.as_mut_ptr(),
                    signature.len(),
                    &mut error,
                )
            },
            2
        );
        assert_eq!(metadata, [2; 8]);
        assert_eq!(signature, [3; 8]);
    }
}
