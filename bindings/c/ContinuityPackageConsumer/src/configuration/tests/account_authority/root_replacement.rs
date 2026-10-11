// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Managed account-root ownership across the installed C boundary.
use super::*;
use crate::{retirement, root_replacement as root_api};
#[path = "root_replacement/fixture.rs"]
mod support;
use support::Case;
#[path = "root_replacement/cleanup.rs"]
mod cleanup;

fn foreign<T>(result: crate::Result<T>) -> TestResult<T> {
    result.map_err(|e| format!("foreign {}: {}", e.code, e.message).into())
}
fn state(case: &Case) -> TestResult<u32> {
    let mut error = diagnostic();
    let mut state = 0;
    checked(
        unsafe { root_api::qpc_root_v1_state(case.registry.0, &mut state, &mut error) },
        &error,
    )?;
    Ok(state)
}
fn active(handle: u64) -> TestResult<()> {
    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    let owner = foreign(crate::device::parent(handle, deadline))?;
    foreign(owner.with_journal(deadline, |journal| {
        journal.next_prekey_publication_id()?;
        Ok(())
    }))
}
#[test]
fn root_foreign_preflight_preserves_owners_then_transfer_fences_cached_device() -> TestResult<()> {
    assert_eq!(std::mem::size_of::<root_api::Scope>(), 128);
    assert_eq!(std::mem::offset_of!(root_api::Scope, checkpoint), 8);
    assert_eq!(
        std::mem::size_of::<root_api::alternative::Alternative>(),
        72
    );
    assert_eq!(
        std::mem::offset_of!(root_api::alternative::Alternative, original),
        8
    );
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let case = Case::new()?;
    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    let cached = foreign(crate::device::parent(case.old.handle.0, deadline))?;
    let wire = case.plan.to_bytes()?;
    let mut error = diagnostic();
    #[repr(align(8))]
    struct Short(u32);
    let short = Short(4);
    unsafe {
        assert_eq!(
            root_api::qpc_root_v1_begin(
                case.registry.0,
                case.old.handle.0,
                std::ptr::addr_of!(short.0).cast(),
                wire.as_ptr(),
                wire.len(),
                &mut error
            ),
            1
        );
        assert_eq!(
            root_api::qpc_root_v1_begin(
                case.registry.0,
                case.registry.0,
                &case.scope(),
                wire.as_ptr(),
                wire.len(),
                &mut error
            ),
            1
        );
        assert_eq!(
            root_api::qpc_root_v1_begin(
                case.registry.0,
                case.target.handle.0,
                &case.scope(),
                wire.as_ptr(),
                wire.len(),
                &mut error
            ),
            6
        );
        assert_eq!(
            root_api::qpc_root_v1_begin(
                case.registry.0,
                case.old.handle.0,
                &case.scope(),
                wire.as_ptr(),
                usize::MAX,
                &mut error
            ),
            1
        );
    }
    active(case.old.handle.0)?;
    let entry = foreign(crate::entry(case.old.handle.0))?;
    let guard = entry.owner.lock().map_err(|_| "entry")?;
    assert_eq!(
        unsafe {
            root_api::qpc_root_v1_begin(
                case.registry.0,
                case.old.handle.0,
                &case.scope(),
                wire.as_ptr(),
                wire.len(),
                &mut error,
            )
        },
        3
    );
    drop(guard);
    case.begin()?;
    assert_eq!(state(&case)?, 1);
    assert_eq!(
        cached
            .with_journal(deadline, |_| Ok(()))
            .err()
            .ok_or("old cache was live")?
            .code,
        2
    );
    assert!(active(case.old.handle.0).is_err());
    let mut inventory = retirement::Inventory { bytes: [0; 313] };
    assert_eq!(
        unsafe {
            retirement::qpc_retired_v1_inventory(case.registry.0, &mut inventory, &mut error)
        },
        215
    );
    assert_eq!(inventory.bytes, [0; 313]);
    assert_eq!(state(&case)?, 1);
    let mut output = vec![77; 65536];
    let mut written = 99;
    let freeze = case.freeze()?;
    assert_eq!(
        unsafe {
            root_api::qpc_root_v1_bind_freeze(
                case.registry.0,
                freeze.as_ptr(),
                freeze.len(),
                output.as_mut_ptr(),
                65535,
                &mut written,
                &mut error,
            )
        },
        1
    );
    assert_eq!(written, 99);
    assert!(output.iter().all(|b| *b == 77));
    assert_eq!(state(&case)?, 1);
    let mut corrupt = freeze.clone();
    *corrupt.last_mut().ok_or("freeze")? ^= 1;
    assert_ne!(
        unsafe {
            root_api::qpc_root_v1_bind_freeze(
                case.registry.0,
                corrupt.as_ptr(),
                corrupt.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
                &mut error,
            )
        },
        0
    );
    assert_eq!(written, 0);
    assert!(output.iter().all(|b| *b == 77));
    assert_eq!(state(&case)?, 1);
    case.bind(&freeze)?;
    assert_eq!(state(&case)?, 2);
    Ok(())
}
#[test]
fn root_foreign_resume_cleanup_keeps_successor_live_until_controller_close() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let mut case = Case::new()?;
    case.begin()?;
    case.resume()?;
    assert_eq!(state(&case)?, 1);
    let proposal = case.bind(&case.freeze()?)?;
    case.resume()?;
    assert_eq!(state(&case)?, 2);
    let receipt = case.commit(&proposal)?;
    let next = case.retain(&receipt)?;
    assert_eq!(next.revision, case.checkpoint.revision + 1);
    assert_eq!(next.account, case.target.root.account_id()?);
    let again = case.retain(&receipt)?;
    assert_eq!(next.revision, again.revision);
    case.resume()?;
    assert_eq!(state(&case)?, 3);
    case.activate()?;
    active(case.target.handle.0)?;
    cleanup::erase(&case)?;
    active(case.target.handle.0)?;
    assert_eq!(state(&case)?, 3);
    case.registry.close()?;
    assert!(active(case.target.handle.0).is_err());
    case.resume()?;
    assert_eq!(state(&case)?, 3);
    let mut status = 0;
    let mut error = diagnostic();
    checked(
        unsafe {
            retirement::qpc_retired_v1_signer_state(case.registry.0, &mut status, &mut error)
        },
        &error,
    )?;
    assert_eq!(status, 1);
    Ok(())
}
#[test]
fn root_foreign_cleanup_failure_consumes_controller_and_revokes_successor() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let case = Case::new()?;
    case.begin()?;
    let proposal = case.bind(&case.freeze()?)?;
    case.retain(&case.commit(&proposal)?)?;
    case.activate()?;
    active(case.target.handle.0)?;
    let mut output = [0; 1];
    let mut error = diagnostic();
    // Exact-length output request without a loaded report is an admitted native error.
    assert_ne!(
        unsafe {
            retirement::qpc_retired_v1_copy_report(
                case.registry.0,
                output.as_mut_ptr(),
                1,
                &mut error,
            )
        },
        0
    );
    assert!(state(&case).is_err());
    assert!(active(case.target.handle.0).is_err());
    Ok(())
}

#[path = "root_replacement/cancellation.rs"]
mod cancellation;

#[path = "root_replacement/alternatives.rs"]
mod alternatives;
