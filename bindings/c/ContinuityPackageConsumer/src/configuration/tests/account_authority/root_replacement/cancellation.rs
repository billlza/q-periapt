// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{thread, time::Duration};

#[test]
fn root_foreign_either_handle_cancels_the_actual_successor_witness_call() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    for cancel_root in [true, false] {
        let mut case = Case::new()?;
        case.begin()?;
        let proposal = case.bind(&case.freeze()?)?;
        case.retain(&case.commit(&proposal)?)?;
        let marker = case._directory.path().join("activation-held");
        *case.witness.hold_marker.lock().map_err(|_| "marker")? = Some(marker.clone());
        case.witness.arm(4)?;
        let root = case.registry.0;
        let target = case.target.handle.0;
        let worker = thread::spawn(move || {
            let mut error = diagnostic();
            let code =
                unsafe { root_api::qpc_root_v1_activate_successor(root, target, &mut error) };
            (code, error)
        });
        let end = Instant::now() + Duration::from_secs(4);
        while !marker.exists() && Instant::now() < end && !worker.is_finished() {
            thread::sleep(Duration::from_millis(2));
        }
        let observed = marker.exists();
        let mut error = diagnostic();
        let cancellation =
            unsafe { qpc_owner_v1_cancel(if cancel_root { root } else { target }, &mut error) };
        let (code, detail) = worker.join().map_err(|_| "activation worker")?;
        checked(cancellation, &error)?;
        assert!(
            observed,
            "actual signed witness reply did not reach the held-prefix barrier"
        );
        // An already processed witness request has an unknown outcome after
        // cancellation (218), unlike cancellation before dispatch (302).
        let message = String::from_utf8_lossy(
            detail
                .message
                .get(..detail.length as usize)
                .ok_or("diagnostic")?,
        );
        assert_eq!(code, 218, "{message}");
        assert!(message.contains("dispatch cancelled"));
        assert!(active(target).is_err());
        assert!(state(&case).is_err());
        case.witness.join()?;
        assert!(case
            .witness
            .captured
            .lock()
            .map_err(|_| "capture")?
            .iter()
            .any(|capture| !capture.delivered));
        // Cancellation does not recreate a target or discard the original commit.
        case.resume()?;
        assert_eq!(state(&case)?, 3);
    }
    Ok(())
}
#[test]
fn root_foreign_precancel_does_not_transfer_an_active_device() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let case = Case::new()?;
    let mut error = diagnostic();
    checked(
        unsafe { qpc_owner_v1_cancel(case.registry.0, &mut error) },
        &error,
    )?;
    let plan = case.plan.to_bytes()?;
    assert_eq!(
        unsafe {
            root_api::qpc_root_v1_begin(
                case.registry.0,
                case.old.handle.0,
                &case.scope(),
                plan.as_ptr(),
                plan.len(),
                &mut error,
            )
        },
        302
    );
    active(case.old.handle.0)?;
    Ok(())
}
