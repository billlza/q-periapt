// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual foreign process exits before a Query reply and after local confirmation.
use super::*;
use std::{path::Path, sync::mpsc, thread};

fn receipt(value: &[u8], phase: u8, original: &Request) -> Result<()> {
    if value
        != [
            b"QPPCUT01".as_slice(),
            &[phase],
            &original.proposal.binding(),
        ]
        .concat()
    {
        return Err("process cut receipt does not identify the original proposal and phase".into());
    }
    Ok(())
}

pub(super) fn exercise(
    base: &Path,
    inputs: &Path,
    transport: &transport::Carrier,
    witness: &witness::Witness,
    original: &Request,
    run: &impl Fn(&str, &str) -> Result<Vec<u8>>,
    cut: &impl Fn(&str, &str) -> Result<Vec<u8>>,
) -> Result<()> {
    let before = transport.captures(witness)?.len();
    let image =
        crate::witness_tls_faults::snapshot(&witness._directory.path().join("witness.redb"))?;
    let (exited, exit) = mpsc::sync_channel(1);
    let (worker, prefix) =
        cancellation::start_control(base, inputs, transport, witness, original, Some(exit))?;
    let outcome = cut("pending-confirm-process-cut", "query-process-cut")
        .and_then(|bytes| receipt(&bytes, 1, original));
    let signal = if outcome.is_ok() {
        exited.send(()).map_err(|error| error.to_string())
    } else {
        Ok(())
    };
    drop(exited);
    let gate = worker.join().map_err(|_| "process cut control panicked")?;
    let control = match (outcome, signal, gate) {
        (Ok(()), Ok(()), Ok(control)) => control,
        (client, signal, gate) => {
            return Err(
                format!("process cut: client={client:?}; exit={signal:?}; gate={gate:?}").into(),
            )
        }
    };
    retain(&base.join("query-process-cut.exit"), &77_u32.to_be_bytes())?;
    let until = Instant::now() + Duration::from_secs(1);
    let records = loop {
        let records = transport.captures(witness)?;
        if records.len() == before + 1 {
            break records;
        }
        if records.len() > before + 1 || Instant::now() >= until {
            return Err("process cut Query count".into());
        }
        thread::sleep(Duration::from_millis(2));
    };
    let record = records.get(before).ok_or("cut Query")?;
    assert!(!record.delivered);
    assert_eq!(record.request.get(204), Some(&1));
    assert_eq!(record.reply.get(204), Some(&1));
    let mut transcript = vec![0];
    transcript.extend_from_slice(&record.request);
    transcript.extend_from_slice(&record.reply);
    retain(&base.join("process-cut-transcript"), &transcript)?;
    retain(&base.join("process-cut-control"), &control)?;
    retain(&base.join("process-cut-prefix"), &fs::read(prefix)?)?;
    let restored = Request::parse(&run("pending-request", "pending-after-process-cut")?)?;
    assert_eq!(restored.proposal, original.proposal);
    assert_eq!(restored.metadata, original.metadata);

    // This process returns from the public API, then exits before a successful
    // application result is published. No database-internal cut is claimed.
    receipt(
        &cut("pending-confirm-result-cut", "confirmation-result-cut")?,
        2,
        original,
    )?;
    retain(
        &base.join("confirmation-result-cut.exit"),
        &77_u32.to_be_bytes(),
    )?;
    assert_eq!(
        run("pending-request-absent", "pending-after-result-cut")?,
        201_u32.to_be_bytes()
    );
    assert!(
        image
            == crate::witness_tls_faults::snapshot(
                &witness._directory.path().join("witness.redb")
            )?
    );
    retain(&base.join("process-cut-store-unchanged"), &[1])?;
    Ok(())
}
