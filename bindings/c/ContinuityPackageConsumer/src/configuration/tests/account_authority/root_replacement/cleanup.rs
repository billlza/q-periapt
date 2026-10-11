// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::io::Write;

pub(super) fn erase(case: &Case) -> TestResult<()> {
    let handle = case.registry.0;
    let mut error = diagnostic();
    let mut inventory = retirement::Inventory { bytes: [0; 313] };
    checked(
        unsafe { retirement::qpc_retired_v1_inventory(handle, &mut inventory, &mut error) },
        &error,
    )?;
    let expected = p::AnchorRetiredCleanupProposal::from_trusted_state(&inventory.bytes)?;
    let inventory_receipt = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.retain_retired_cleanup(&expected)?;
        witness.retired_cleanup_receipt(&expected)?
    };
    let mut proposal = retirement::Proposal {
        present: 0,
        bytes: [0; 353],
        reserved_zero: [0; 3],
    };
    checked(
        unsafe {
            retirement::qpc_retired_v1_prepare_report(
                handle,
                inventory_receipt.as_ptr(),
                inventory_receipt.len(),
                &mut proposal,
                &mut error,
            )
        },
        &error,
    )?;
    assert_eq!(proposal.present, 1);
    let expected = p::AnchorRetiredReportProposal::from_trusted_state(&proposal.bytes)?;
    let report_receipt = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.retain_retired_report(&expected)?;
        witness.retired_report_receipt(&expected)?
    };
    let mut info = retirement::ReportInfo {
        length: 0,
        views: 0,
        reserved_zero: 0,
        report: [0; 32],
    };
    checked(
        unsafe {
            retirement::qpc_retired_v1_load_report(
                handle,
                inventory_receipt.as_ptr(),
                inventory_receipt.len(),
                report_receipt.as_ptr(),
                report_receipt.len(),
                &mut info,
                &mut error,
            )
        },
        &error,
    )?;
    let mut report = vec![0; info.length];
    checked(
        unsafe {
            retirement::qpc_retired_v1_copy_report(
                handle,
                report.as_mut_ptr(),
                report.len(),
                &mut error,
            )
        },
        &error,
    )?;
    let mut host = fs::File::create_new(case.old.path.join("host-retirement-report"))?;
    host.write_all(&report)?;
    host.sync_all()?;
    fs::File::open(&case.old.path)?.sync_all()?;
    checked(
        unsafe {
            retirement::qpc_retired_v1_prepare_acknowledgement(
                handle,
                inventory_receipt.as_ptr(),
                inventory_receipt.len(),
                report_receipt.as_ptr(),
                report_receipt.len(),
                report.as_ptr(),
                report.len(),
                &mut proposal,
                &mut error,
            )
        },
        &error,
    )?;
    assert_eq!(
        p::AnchorRetiredReportProposal::from_trusted_state(&proposal.bytes)?,
        expected
    );
    let ack = {
        let mut witness = case
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        witness.acknowledge_retired_report(&expected)?;
        witness.retired_report_acknowledgement_receipt(&expected)?
    };
    let signer = fs::read(case.old.path.join("signer.key"))?;
    checked(
        unsafe {
            retirement::qpc_retired_v1_erase_journal(handle, ack.as_ptr(), ack.len(), &mut error)
        },
        &error,
    )?;
    assert_eq!(fs::read(case.old.path.join("signer.key"))?, signer);
    active(case.target.handle.0)?;
    checked(
        unsafe {
            retirement::qpc_retired_v1_prepare_signer_erasure(
                handle,
                ack.as_ptr(),
                ack.len(),
                &mut error,
            )
        },
        &error,
    )?;
    checked(
        unsafe { retirement::qpc_retired_v1_erase_signer(handle, &mut error) },
        &error,
    )?;
    let mut erased = 77;
    checked(
        unsafe { retirement::qpc_retired_v1_signer_state(handle, &mut erased, &mut error) },
        &error,
    )?;
    assert_eq!(erased, 1);
    active(case.target.handle.0)?;
    Ok(())
}
