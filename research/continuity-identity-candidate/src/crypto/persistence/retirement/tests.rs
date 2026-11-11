// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::DeviceSigningKey;
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
};
#[path = "fixture.rs"]
mod fixture;
use fixture::Case;

#[test]
fn signer_retirement_roundtrip_is_terminal_and_platform_separated() {
    let c = Case::new();
    let plan = c.capture(&c.path);
    assert!(!c.erased(&plan, &c.path).expect("original remains"));
    let mut wire = Vec::new();
    plan.encode(&mut wire);
    assert_eq!(wire.get(..8), Some(PLAN_TAG.as_slice()));
    let mut d = Decoder::new(&wire);
    assert_eq!(
        SigningFilePlan::decode(&mut d).expect("same native format"),
        plan
    );
    d.finish().expect("canonical plan length");
    for tag in [b"QPSRPL01", b"QPSRPL02", b"QPSRPL03"] {
        if tag != PLAN_TAG {
            let mut other = wire.clone();
            other.get_mut(..8).expect("header").copy_from_slice(tag);
            assert!(SigningFilePlan::decode(&mut Decoder::new(&other)).is_err());
        }
    }
    #[cfg(windows)]
    {
        let mut invalid = wire.clone();
        invalid
            .get_mut(40..48)
            .expect("volume width")
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(SigningFilePlan::decode(&mut Decoder::new(&invalid)).is_err());
    }
    c.erase(&plan, &c.path).expect("authorized erasure");
    assert_eq!(fs::read(&c.path).expect("terminal"), TAG);
    assert!(DeviceSigningKey::open(&c.path, &c.key, c.identity).is_err());
    let restored = SigningFilePlan::decode(&mut Decoder::new(&wire)).expect("retained plan");
    assert!(c.erased(&restored, &c.path).expect("recovered terminal"));
    c.erase(&restored, &c.path).expect("exact retry");
}

#[test]
fn signer_retirement_refuses_substituted_file_even_with_identical_ciphertext() {
    let c = Case::new();
    let plan = c.capture(&c.path);
    let bytes = fs::read(&c.path).expect("original sealed file");
    let retained = c.path.with_file_name("retained");
    fs::rename(&c.path, &retained).expect("retain original file");
    publish_private_bytes(&c.path, &bytes).expect("different file, identical bytes");
    assert!(matches!(
        c.erase(&plan, &c.path),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.erased(&plan, &c.path),
        Err(DurableError::Conflict)
    ));
    assert_eq!(fs::read(&c.path).expect("substitute unchanged"), bytes);
    assert_eq!(fs::read(&retained).expect("original unchanged"), bytes);
    // Restoring the actual original file is an explicit fixture action, not recovery fallback.
    fs::remove_file(&c.path).expect("remove test substitute");
    fs::rename(&retained, &c.path).expect("restore exact original");
    c.erase(&plan, &c.path).expect("same identity can finish");
}

#[test]
fn signer_retirement_refuses_modified_ciphertext_and_unrelated_report() {
    let c = Case::new();
    let plan = c.capture(&c.path);
    let mut changed_report = plan.clone();
    changed_report.report =
        AnchorRetiredReportProposal::from_report(plan.report.inventory().clone(), [172; 32])
            .expect("different report expectation");
    assert!(matches!(
        c.erase(&changed_report, &c.path),
        Err(DurableError::Conflict)
    ));
    let mut bytes = fs::read(&c.path).expect("original");
    let byte = bytes.get_mut(100).expect("sealed payload");
    *byte ^= 1;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&c.path)
        .expect("original file");
    file.seek(SeekFrom::Start(0)).expect("start");
    file.write_all(&bytes).expect("same-file mutation");
    file.sync_all().expect("mutation durable");
    drop(file);
    assert!(matches!(
        c.erase(&plan, &c.path),
        Err(DurableError::Conflict)
    ));
    assert_eq!(fs::read(&c.path).expect("failure preserves state"), bytes);
}

#[test]
fn signer_retirement_metadata_checks_keep_exclusive_lock() {
    let c = Case::new();
    let plan = c.capture(&c.path);
    let file = Admitted::open(&c.path).expect("first owner");
    file.check_name(&plan)
        .expect("metadata through separate handle");
    assert!(
        Admitted::open(&c.path).is_err(),
        "metadata handle must not release the lifetime lock"
    );
    assert!(
        c.erase(&plan, &c.path).is_err(),
        "second erasure owner refused"
    );
    file.finish(Ok(()))
        .expect("explicit operation lock release");
    c.erase(&plan, &c.path)
        .expect("released lock permits exact retry");
}

#[test]
fn signer_retirement_releases_lock_with_a_surviving_descriptor() {
    for fail in [false, true] {
        let c = Case::new();
        let plan = c.capture(&c.path);
        // A duplicate shares the open-file description, as an inherited descriptor
        // can during a concurrent fork/exec. It must not extend this operation's lock.
        let injection = inject(IoFault::RetainedDescriptor { fail });
        assert_eq!(c.erase(&plan, &c.path).is_err(), fail);
        assert!(injection.fired());
        assert!(injection.descriptor_is_held());
        c.erase(&plan, &c.path)
            .expect("operation released its lock despite a surviving descriptor");
        assert!(c.erased(&plan, &c.path).expect("same terminal readback"));
        assert!(injection.descriptor_is_held());
    }
}

#[test]
fn signer_retirement_partial_headers_and_io_boundaries_never_return_success() {
    let c = Case::new();
    let bytes = fs::read(&c.path).expect("original sealed bytes");
    let mut faults: Vec<_> = (0..=8).map(IoFault::Prefix).collect();
    for stage in [
        IoStage::HeaderWrite,
        IoStage::HeaderSync,
        IoStage::Truncate,
        IoStage::TerminalSync,
        IoStage::DirectorySync,
    ] {
        faults.extend([
            IoFault::Boundary(stage, false),
            IoFault::Boundary(stage, true),
        ]);
    }
    for (index, fault) in faults.into_iter().enumerate() {
        let path = c.path.with_file_name(format!("fault-{index}"));
        publish_private_bytes(&path, &bytes).expect("independent fixture file");
        let plan = c.capture(&path);
        let injection = inject(fault);
        assert!(c.erase(&plan, &path).is_err(), "injected failure {index}");
        assert!(injection.fired(), "reached fault {index}");
        drop(injection);
        let observed = fs::read(&path).expect("retained recoverable state");
        if observed.len() == FILE_BYTES {
            assert_eq!(
                observed.get(8..),
                bytes.get(8..),
                "only public header may change"
            );
            assert!(!c.erased(&plan, &path).expect("unfinished original"));
        } else {
            assert_eq!(observed, TAG, "only exact terminal permitted");
            assert!(c.erased(&plan, &path).expect("terminal resynced"));
        }
        c.erase(&plan, &path)
            .expect("exact recovery of original plan");
        assert!(c.erased(&plan, &path).expect("terminal readback"));
        assert!(DeviceSigningKey::open(&path, &c.key, c.identity).is_err());
    }
    eprintln!("NATIVE_SIGNER_RETIREMENT partial_headers=9 io_boundaries=10 exact_retry=true authenticated_ack=true");
}
