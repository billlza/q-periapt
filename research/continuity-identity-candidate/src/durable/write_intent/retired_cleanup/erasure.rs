// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Atomic logical retirement of the exact independently acknowledged journal inventory.
use super::*;
use crate::{retired_device::JournalErasureState, AnchorPin, AnchorRetiredReportProposal};

const TAG: &[u8; 8] = b"QPRJER01";
const RECEIPT_BYTES: usize = 3730;
const BODY_BYTES: usize = 8 + RECEIPT_BYTES;
const TERMINAL_BYTES: usize = BODY_BYTES + 32;

struct Scope<'a> {
    key: &'a JournalKey,
    identity: JournalIdentity,
    retired: AnchorRetiredSubject,
    pin: &'a AnchorPin,
    report: &'a AnchorRetiredReportProposal,
}
impl<'a> Scope<'a> {
    fn new(
        key: &'a JournalKey,
        identity: JournalIdentity,
        retired: AnchorRetiredSubject,
        pin: &'a AnchorPin,
        report: &'a AnchorRetiredReportProposal,
    ) -> Result<Self, DurableError> {
        report.inventory().check_retirement(retired)?;
        if *identity.as_bytes() != report.inventory().subject().journal_parts().0
            || pin.binding() != retired.witness_binding()
        {
            return Err(DurableError::Conflict);
        }
        Ok(Self {
            key,
            identity,
            retired,
            pin,
            report,
        })
    }
    fn authenticator(&self) -> Result<Hmac<Sha256>, DurableError> {
        let mut derived = ZeroizingBytes::<32>::zeroed();
        hkdf::Hkdf::<Sha256>::new(None, self.key.0.as_bytes())
            .expand(
                b"Q-PERIAPT-CONTINUITY-RETIRED-JOURNAL-TERMINAL-KEY/v1",
                derived.as_mut_bytes(),
            )
            .map_err(|_| Error::Provider)?;
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
            .map_err(|_| Error::Provider.into())
    }
    fn verify_receipt(&self, wire: &[u8]) -> Result<(), DurableError> {
        self.pin
            .verify_retired_report_acknowledgement(self.retired, self.report, wire)?;
        Ok(())
    }
    fn read_terminal(&self, db: &Database) -> Result<bool, DurableError> {
        let read = db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        let Some(row) = table.get("retired").map_err(storage)? else {
            return Ok(false);
        };
        let bytes = row.value();
        if table.len().map_err(storage)? != 1
            || bytes.len() != TERMINAL_BYTES
            || bytes.get(..8) != Some(TAG.as_slice())
        {
            return Err(DurableError::Corrupt);
        }
        let body = bytes.get(..BODY_BYTES).ok_or(DurableError::Corrupt)?;
        let mut mac = self.authenticator()?;
        mac.update(body);
        mac.verify_slice(bytes.get(BODY_BYTES..).ok_or(DurableError::Corrupt)?)
            .map_err(|_| DurableError::Corrupt)?;
        self.verify_receipt(body.get(8..).ok_or(DurableError::Corrupt)?)?;
        Ok(true)
    }
    fn check_inventory(&self, db: &Database) -> Result<(), DurableError> {
        let (_, _, actual) = snapshot(db, self.key, self.identity, self.retired)?;
        if &actual != self.report.inventory() {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn erase(&self, db: &Database, receipt: &[u8]) -> Result<(), DurableError> {
        // The caller verifies this receipt before database admission. A saved terminal
        // authenticates its own receipt; equivalent fresh signatures need not be equal.
        if self.read_terminal(db)? {
            return Ok(());
        }
        self.check_inventory(db)?;
        let mut terminal = TAG.to_vec();
        terminal.extend_from_slice(receipt);
        let mut mac = self.authenticator()?;
        mac.update(&terminal);
        terminal.extend_from_slice(&mac.finalize().into_bytes());
        let tx = transaction(db)?;
        {
            let mut table = tx.open_table(TABLE).map_err(storage)?;
            let inventory = self.report.inventory();
            // Bind the destructive transaction to the exact bytes just authenticated,
            // including genuine absence of a pending intent. No basename replacement.
            let image = table
                .get("image")
                .map_err(storage)?
                .ok_or(DurableError::Corrupt)?;
            let pending = table.get("pending").map_err(storage)?;
            let pending_hash = pending
                .as_ref()
                .map(|p| digest(b"Q-PERIAPT-CONTINUITY-RETIRED-LOCAL-INTENT/v1", p.value()));
            if image_hash(image.value()) != inventory.stored_image_digest()
                || pending_hash != inventory.pending_intent_digest()
                || table.len().map_err(storage)? != if pending.is_some() { 2 } else { 1 }
            {
                return Err(DurableError::Conflict);
            }
            drop(image);
            drop(pending);
            table.remove("image").map_err(storage)?;
            table.remove("pending").map_err(storage)?;
            table
                .insert("retired", terminal.as_slice())
                .map_err(storage)?;
        }
        #[cfg(all(test, unix))]
        at_boundary("before-commit");
        tx.commit().map_err(DurableError::CommitUncertain)?;
        #[cfg(all(test, unix))]
        at_boundary("after-commit");
        Ok(())
    }
}

impl DeviceJournal {
    pub(crate) fn retired_journal_has_terminal(
        path: &Path,
        key: &JournalKey,
        identity: JournalIdentity,
        retired: AnchorRetiredSubject,
        pin: &AnchorPin,
        report: &AnchorRetiredReportProposal,
    ) -> Result<bool, DurableError> {
        let scope = Scope::new(key, identity, retired, pin, report)?;
        scope.read_terminal(&open_private_database(path)?)
    }
    pub(crate) fn retired_journal_state(
        path: &Path,
        key: &JournalKey,
        identity: JournalIdentity,
        retired: AnchorRetiredSubject,
        pin: &AnchorPin,
        report: &AnchorRetiredReportProposal,
    ) -> Result<JournalErasureState, DurableError> {
        let scope = Scope::new(key, identity, retired, pin, report)?;
        let db = open_private_database(path)?;
        if scope.read_terminal(&db)? {
            return Ok(JournalErasureState::Erased);
        }
        scope.check_inventory(&db)?;
        Ok(JournalErasureState::Retained)
    }
    pub(crate) fn erase_retired_journal(
        path: &Path,
        key: &JournalKey,
        identity: JournalIdentity,
        retired: AnchorRetiredSubject,
        pin: &AnchorPin,
        report: &AnchorRetiredReportProposal,
        receipt: &[u8],
    ) -> Result<(), DurableError> {
        let scope = Scope::new(key, identity, retired, pin, report)?;
        scope.verify_receipt(receipt)?;
        scope.erase(&open_private_database(path)?, receipt)
    }
    #[cfg(all(test, unix))]
    pub(crate) fn erase_retired_journal_in_database(
        db: &Database,
        key: &JournalKey,
        identity: JournalIdentity,
        retired: AnchorRetiredSubject,
        pin: &AnchorPin,
        report: &AnchorRetiredReportProposal,
        receipt: &[u8],
    ) -> Result<(), DurableError> {
        let scope = Scope::new(key, identity, retired, pin, report)?;
        scope.verify_receipt(receipt)?;
        scope.erase(db, receipt)
    }
}

#[cfg(all(test, unix))]
fn at_boundary(stage: &str) {
    if std::env::var("QPERIAPT_RETIRED_ERASURE_STAGE")
        .ok()
        .as_deref()
        != Some(stage)
    {
        return;
    }
    let root = std::env::var_os("QPERIAPT_RETIRED_ERASURE_CHILD").expect("owned child root");
    let root = Path::new(&root);
    use std::io::Write;
    let mut ready = std::fs::File::create_new(root.join("erasure-ready.pending")).expect("ready");
    ready.write_all(stage.as_bytes()).expect("stage");
    ready.sync_all().expect("ready durable");
    std::fs::rename(
        root.join("erasure-ready.pending"),
        root.join("erasure-ready"),
    )
    .expect("ready name");
    loop {
        std::thread::park();
    }
}
