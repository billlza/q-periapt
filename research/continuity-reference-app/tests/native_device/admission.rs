// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_continuity_reference_app::native_device::NativeDevice;
use std::{sync::mpsc, thread, time::Duration};

#[test]
fn bounded_original_owner_admission_waits_only_for_exclusive_store_contention() -> Result<()> {
    let case = Case::open()?;
    let directory = case.path.join("device");
    let key = case.path.join("wrap.key");
    let mut held = NativeDevice::open(&directory, &key, case.invitation.clone())?;
    let original = serde_json::to_value(held.status()?)?;
    let cancel = sdk::Cancellation::default();
    let short = sdk::session_exchange::Run::new(&cancel, Duration::from_millis(40))?;
    let error = NativeDevice::open_in_run(&directory, &key, &case.invitation, &short)
        .err()
        .ok_or("held owner unexpectedly opened")?;
    assert!(matches!(
        error.downcast_ref::<sdk::session_exchange::Error>(),
        Some(sdk::session_exchange::Error::Deadline)
    ));
    let bounded = sdk::session_exchange::Run::new(&cancel, Duration::from_secs(30))?;
    let error = NativeDevice::open_in_run(&directory, &key, &case.invitation, &bounded)
        .err()
        .ok_or("admission cap unexpectedly opened held owner")?;
    assert!(matches!(
        error.downcast_ref::<sdk::DurableError>(),
        Some(sdk::DurableError::Database(
            q_periapt_host_store::filesystem::PrivateDatabaseError::Busy
        ))
    ));
    let mut invalid = case.invitation.clone();
    invalid.operation = [0; 32];
    let error = NativeDevice::open_in_run(&directory, &key, &invalid, &bounded)
        .err()
        .ok_or("invalid invitation admitted")?;
    assert!(error.downcast_ref::<sdk::DurableError>().is_none());

    thread::scope(|scope| -> Result<()> {
        let (started, ready) = mpsc::channel();
        let directory = &directory;
        let key = &key;
        let invitation = &case.invitation;
        let cancel = &cancel;
        let worker = scope.spawn(move || -> std::result::Result<(), String> {
            let run = sdk::session_exchange::Run::new(cancel, Duration::from_secs(5))
                .map_err(|e| e.to_string())?;
            started.send(()).map_err(|e| e.to_string())?;
            let error = NativeDevice::open_in_run(directory, key, invitation, &run)
                .err()
                .ok_or("cancelled admission returned owner")?;
            if matches!(
                error.downcast_ref::<sdk::session_exchange::Error>(),
                Some(sdk::session_exchange::Error::Cancelled)
            ) {
                Ok(())
            } else {
                Err(format!("unexpected cancellation outcome: {error:?}"))
            }
        });
        ready.recv_timeout(Duration::from_secs(1))?;
        thread::sleep(Duration::from_millis(40));
        cancel.cancel();
        worker
            .join()
            .map_err(|_| "cancelled admission worker panicked")?
            .map_err(std::io::Error::other)?;
        Ok(())
    })?;

    thread::scope(|scope| -> Result<()> {
        let (started, ready) = mpsc::channel();
        let directory = &directory;
        let key = &key;
        let invitation = &case.invitation;
        let worker = scope.spawn(move || -> std::result::Result<serde_json::Value, String> {
            let cancel = sdk::Cancellation::default();
            let run = sdk::session_exchange::Run::new(&cancel, Duration::from_secs(5))
                .map_err(|e| e.to_string())?;
            started.send(()).map_err(|e| e.to_string())?;
            let mut owner = NativeDevice::open_in_run(directory, key, invitation, &run)
                .map_err(|e| e.to_string())?;
            let status = owner.status().map_err(|e| e.to_string())?;
            owner.close();
            serde_json::to_value(status).map_err(|e| e.to_string())
        });
        ready.recv_timeout(Duration::from_secs(1))?;
        thread::sleep(Duration::from_millis(80));
        held.close();
        let reopened = worker
            .join()
            .map_err(|_| "admission worker panicked")?
            .map_err(std::io::Error::other)?;
        assert_eq!(reopened, original);
        Ok(())
    })?;
    let mut reopened = NativeDevice::open(&directory, &key, case.invitation)?;
    assert_eq!(serde_json::to_value(reopened.status()?)?, original);
    Ok(())
}
