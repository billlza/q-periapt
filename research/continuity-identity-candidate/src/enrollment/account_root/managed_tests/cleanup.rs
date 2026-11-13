// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "cleanup/process.rs"]
mod process;
use crate::{retired_device::JournalErasureState, SigningFileErasureState};

pub(super) fn erase_original(managed: &mut Managed, f: &Fixture, current: &mut EnrolledDevice) {
    let signer = fs::read(&f.original.paths.signer).expect("original encrypted signer");
    let (_, ack) = managed
        .with_retired_cleanup(|old| {
            assert!(
                DeviceEnrollment::open(f.original.paths.clone(), f.original.intent.clone())
                    .is_err(),
                "same parent stays leased"
            );
            Ok(super::super::cleanup::account_report(f, old))
        })
        .expect("original inventory, complete report and independent host accounting");
    current
        .next_prekey_publication_id()
        .expect("successor remains authorized after reporting");
    managed
        .with_retired_cleanup(|old| old.installation()?.erase_journal(&f.pin, &ack))
        .expect("separate journal erasure");
    assert_eq!(
        fs::read(&f.original.paths.signer).expect("signer still retained"),
        signer
    );
    current
        .next_prekey_publication_id()
        .expect("successor remains authorized after journal erasure");
    assert_eq!(
        managed
            .with_retired_cleanup(|old| old.installation()?.journal_erasure_status(&f.pin))
            .expect("original journal terminal"),
        JournalErasureState::Erased
    );
    managed
        .with_retired_cleanup(|old| old.prepare_signer_erasure(&ack))
        .expect("separate signer-file plan");
    managed
        .with_retired_cleanup(|old| old.erase_signer())
        .expect("logical signer erasure and parent reopen");
    assert_erased(managed);
    current
        .next_prekey_publication_id()
        .expect("closing the old signer owner does not revoke the successor");
}
pub(super) fn assert_erased(managed: &mut Managed) {
    assert_eq!(
        managed
            .with_retired_cleanup(|old| old.signer_erasure_status())
            .expect("same original authenticated signer terminal"),
        SigningFileErasureState::Erased
    );
}
fn prepared() -> (Setup, Managed, Vec<u8>, Vec<u8>, AccountAuthorityCheckpoint) {
    let (s, registry, original) = Setup::new(200);
    let mut managed = s.begin(registry, original);
    let freeze = s.freeze();
    let proposal = managed
        .bind_witness_freeze(&freeze)
        .expect("original freeze");
    let receipt = s.f.receipt(&proposal);
    let checkpoint = managed
        .retain_witness_retirement(&receipt)
        .expect("all root commits");
    (s, managed, freeze, receipt, checkpoint)
}

#[test]
fn managed_root_cleanup_preserves_successor_while_erasing_and_reopens_exact_history() {
    let (s, mut managed, freeze, receipt, checkpoint) = prepared();
    let mut current = s
        .activate(&mut managed, 150)
        .expect("actual new account owner");
    erase_original(&mut managed, &s.f, &mut current);
    assert_eq!(
        managed
            .retain_witness_retirement(&receipt)
            .expect("same historical receipt after erasure"),
        checkpoint
    );
    assert_eq!(
        managed
            .bind_witness_freeze(&freeze)
            .expect("same historical freeze after erasure")
            .operation(),
        s.plan.operation()
    );
    current
        .next_prekey_publication_id()
        .expect("same successor after historical retries");
    managed.close();
    assert!(matches!(
        current.next_prekey_publication_id(),
        Err(DurableError::Closed)
    ));
    current.close();
    s.f.assert_fenced();
    let mut managed = s.resume();
    assert_erased(&mut managed);
    assert_eq!(
        managed
            .retain_witness_retirement(&receipt)
            .expect("same permanent outcome"),
        checkpoint
    );
    let mut current = s
        .activate(&mut managed, 150)
        .expect("new account reopen without old signing seeds");
    current
        .next_prekey_publication_id()
        .expect("current authorization");
    managed.close();
    assert!(matches!(
        current.next_prekey_publication_id(),
        Err(DurableError::Closed)
    ));
}

#[test]
fn managed_root_cleanup_error_revokes_delegated_successor_and_recovers_original_inventory() {
    let (s, mut managed, _, _, _) = prepared();
    let mut current = s.activate(&mut managed, 150).expect("successor");
    let inventory = managed
        .with_retired_cleanup(|old| old.installation()?.proposal())
        .expect("exact original inventory");
    let result = managed.with_retired_cleanup::<()>(|_| Err(DurableError::Conflict));
    assert!(matches!(result, Err(DurableError::Conflict)));
    assert!(matches!(managed.state(), Err(DurableError::Closed)));
    assert!(matches!(
        current.next_prekey_publication_id(),
        Err(DurableError::Closed)
    ));
    current.close();
    let mut managed = s.resume();
    assert_eq!(
        managed
            .with_retired_cleanup(|old| old.installation()?.proposal())
            .expect("same original after failure"),
        inventory
    );
    let mut current = s
        .activate(&mut managed, 150)
        .expect("current successor recovery");
    current
        .next_prekey_publication_id()
        .expect("new owner governed by reopened registry");
}

#[test]
fn managed_root_cleanup_refuses_preparing_and_pending_without_running_the_callback() {
    let (s, registry, original) = Setup::new(200);
    let mut managed = s.begin(registry, original);
    for state in [State::Preparing, State::Pending] {
        if state == State::Pending {
            managed
                .bind_witness_freeze(&s.freeze())
                .expect("pending actual freeze");
        }
        let mut called = false;
        assert!(matches!(
            managed.with_retired_cleanup(|_| {
                called = true;
                Ok(())
            }),
            Err(DurableError::Suspended)
        ));
        assert!(!called);
        assert_eq!(
            managed.state().expect("same original controller retained"),
            state
        );
    }
}

#[test]
fn managed_root_cleanup_missing_parent_never_recreates_original_state() {
    let (s, mut managed, _, _, _) = prepared();
    managed
        .with_retired_cleanup(|old| old.installation()?.proposal())
        .expect("retained inventory");
    managed.close();
    let path = &s.f.original.paths.configuration;
    let backup = path.with_extension("owned-backup");
    let bytes = fs::read(path).expect("owned original fixture");
    fs::rename(path, &backup).expect("withhold exact parent");
    assert!(Managed::resume_original(
        s.registry(),
        s.expected,
        s.plan.clone(),
        s.f.original.paths.clone(),
        s.f.original.intent.clone(),
        s.f.pin.clone()
    )
    .is_err());
    assert!(!path.exists());
    assert_eq!(fs::read(&backup).expect("preserved original"), bytes);
    fs::rename(&backup, path).expect("restore exact owned fixture");
    s.resume()
        .with_retired_cleanup(|old| old.installation()?.proposal())
        .expect("original recovery after restoration");
}

#[test]
fn managed_root_cleanup_missing_child_closes_successor_without_replacing_the_original() {
    let (s, mut managed, _, _, _) = prepared();
    let mut current = s.activate(&mut managed, 150).expect("live successor");
    let path = s.f.original.paths.installation.files()[1];
    let backup = path.with_extension("owned-backup");
    fs::rename(path, &backup).expect("withhold original child basename in this owned fixture");
    assert!(managed
        .with_retired_cleanup(|old| old.installation()?.proposal())
        .is_err());
    assert!(matches!(
        current.next_prekey_publication_id(),
        Err(DurableError::Closed)
    ));
    assert!(matches!(managed.state(), Err(DurableError::Closed)));
    assert!(!path.exists());
    assert!(backup.exists());
    current.close();
    fs::rename(&backup, path).expect("restore same closed original inode");
    let mut managed = s.resume();
    managed
        .with_retired_cleanup(|old| old.installation()?.proposal())
        .expect("same original inventory after storage recovery");
    let mut current = s
        .activate(&mut managed, 150)
        .expect("current successor recovery");
    current
        .next_prekey_publication_id()
        .expect("fresh owner authorization");
}

#[test]
fn managed_root_cleanup_remains_historical_when_successor_credential_has_expired() {
    let (s, registry, original) = Setup::new(160);
    let mut managed = s.begin(registry, original);
    let proposal = managed
        .bind_witness_freeze(&s.freeze())
        .expect("original valid target approval");
    managed
        .retain_witness_retirement(&s.f.receipt(&proposal))
        .expect("actual commitment at fixture time 150");
    managed
        .with_retired_cleanup(|old| old.installation()?.proposal())
        .expect("historical cleanup admission");
    assert!(matches!(
        s.activate(&mut managed, 170),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let mut managed = s.resume();
    let (_, ack) = managed
        .with_retired_cleanup(|old| Ok(super::super::cleanup::account_report(&s.f, old)))
        .expect("historical report does not require expired successor operating authority");
    managed
        .with_retired_cleanup(|old| old.installation()?.erase_journal(&s.f.pin, &ack))
        .expect("acknowledged historical journal erasure");
    managed
        .with_retired_cleanup(|old| old.prepare_signer_erasure(&ack))
        .expect("old signer plan");
    managed
        .with_retired_cleanup(|old| old.erase_signer())
        .expect("old signer erasure");
    assert_erased(&mut managed);
    assert!(matches!(
        s.activate(&mut managed, 170),
        Err(DurableError::Protocol(Error::Validity))
    ));
}

#[test]
fn managed_root_cleanup_callback_unwind_revokes_controller_and_cached_successor() {
    let (s, mut managed, _, _, _) = prepared();
    let mut current = s
        .activate(&mut managed, 150)
        .expect("actual cached successor");
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        managed.with_retired_cleanup::<()>(|_| {
            std::panic::resume_unwind(Box::new("owned cleanup callback unwind"))
        })
    }));
    assert!(
        caught.is_err(),
        "the callback failure must remain an unwind"
    );
    let state = managed.state();
    let released = current.next_prekey_publication_id();
    assert!(matches!(state, Err(DurableError::Closed)) && matches!(released, Err(DurableError::Closed)),
        "unwind must close the controller and revoke cached release: state={state:?}, successor_released={}", released.is_ok());
    current.close();
    let mut managed = s.resume();
    managed
        .with_retired_cleanup(|old| old.installation()?.proposal())
        .expect("exact original recovery after unwind");
}
