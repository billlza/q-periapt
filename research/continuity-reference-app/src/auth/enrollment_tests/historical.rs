// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A signed expired credential plus a disjoint, newer roster retaining it.
//! Isolated test state only; production APIs always use the actual OS clock.
use super::*;
use redb::{ReadableDatabase, TableDefinition};
use serde_json::json;

pub(super) struct Snapshot {
    pub first: Vec<u8>,
    pub roster: sdk::IssuedRoster,
    pub current: sdk::IssuedRoster,
    pub certificate: Vec<u8>,
}
pub(super) fn expired_snapshot(
    path: &Path,
    original: &mut Invitation,
    account: &crate::store::Account,
    at: u64,
) -> Result<Snapshot> {
    original.valid_from = at - 120;
    original.valid_until = at - 60;
    original.deadline = at - 90;
    // Construct one old issuance entirely inside this isolated fixture. Its
    // real root/device signatures use their explicit historical validity. The
    // API under test below always reads the real OS clock.
    let (_, proof) = request_at(path, original, original.valid_from)?;
    let db = q_periapt_host_store::filesystem::open_private_database(&path.join("accounts.redb"))?;
    let roots: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_roots");
    let operations: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_operations");
    let signers: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_signers");
    let mut root: serde_json::Value = {
        let tx = db.begin_read()?;
        let table = tx.open_table(roots)?;
        serde_json::from_slice(
            table
                .get(account.application_id.as_slice())?
                .ok_or("root")?
                .value(),
        )?
    };
    let identity: [u8; 32] = serde_json::from_value(root["signing_id"].clone())?;
    let stem = URL_SAFE_NO_PAD.encode(identity);
    let wrapping = sdk::JournalKey::open(&path.join(format!("enrollment-{stem}.wrap")))?;
    let signer = sdk::RootSigningKey::open(
        &path.join(format!("enrollment-{stem}.signer")),
        &wrapping,
        sdk::SigningKeyId::from_trusted_state(identity)?,
    )?;
    let verified =
        sdk::VerifiedEnrollmentRequest::verify(&proof, &original.intent()?, original.valid_from)?;
    let certificate = signer.issue_enrollment(&verified, original.valid_from)?;
    let roster = signer.issue_roster(
        1,
        sdk::Validity::new(original.valid_from, original.valid_until)?,
        &[signer.roster_entry(&certificate)?],
    )?;
    let first = serde_json::to_vec(&IssuedEnrollment {
        operation: original.operation,
        root_revision: original.root_revision,
        certificate: certificate.clone(),
        roster: roster.as_bytes().to_vec(),
        checkpoint: roster.checkpoint().into(),
    })?;
    root["members"] =
        json!([{"device":original.device,"certificate":URL_SAFE_NO_PAD.encode(&certificate)}]);
    // A later authoritative roster can retain an expired member while its
    // validity no longer overlaps that credential. This is not old permission.
    let current = signer.issue_roster(
        2,
        sdk::Validity::new(at, at + 3600)?,
        &[signer.roster_entry(&certificate)?],
    )?;
    root["roster"] = json!({"checkpoint":crate::enrollment::Checkpoint::from(current.checkpoint()),"bytes":URL_SAFE_NO_PAD.encode(current.as_bytes())});
    let operation = json!({"invitation":original,"phase":{"phase":"Issued","request":URL_SAFE_NO_PAD.encode(&proof),"response":URL_SAFE_NO_PAD.encode(&first)}});
    let scope = [
        account.application_id.as_slice(),
        identity.as_slice(),
        verified.identity().as_bytes().as_slice(),
    ]
    .concat();
    let mut tx = db.begin_write()?;
    tx.set_durability(redb::Durability::Immediate)?;
    tx.set_two_phase_commit(true);
    tx.open_table(roots)?.insert(
        account.application_id.as_slice(),
        serde_json::to_vec(&root)?.as_slice(),
    )?;
    tx.open_table(operations)?.insert(
        original.operation.as_slice(),
        serde_json::to_vec(&operation)?.as_slice(),
    )?;
    tx.open_table(signers)?
        .insert(scope.as_slice(), original.operation.as_slice())?;
    tx.commit()?;
    drop(db);
    drop(signer);
    drop(wrapping);

    Ok(Snapshot {
        first,
        roster,
        current,
        certificate,
    })
}
