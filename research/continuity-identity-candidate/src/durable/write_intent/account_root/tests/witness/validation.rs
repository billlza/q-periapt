// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn row(c: &WitnessCase, name: &str) -> Vec<u8> {
    let db = open_private_database(&c.path()).expect("original database");
    let tx = db.begin_read().expect("read");
    let table = image_table(&tx).expect("table");
    table
        .get(name)
        .expect("row")
        .expect("present original row")
        .value()
        .to_vec()
}
fn change(c: &WitnessCase, name: &str, wire: Option<&[u8]>) {
    let db = open_private_database(&c.path()).expect("owned test database");
    let tx = transaction(&db).expect("test transaction");
    {
        let mut table = tx.open_table(TABLE).expect("table");
        if let Some(wire) = wire {
            table.insert(name, wire).expect("exact replacement");
        } else {
            table.remove(name).expect("remove owned test row");
        }
    }
    tx.commit().expect("commit owned corruption");
}

#[test]
fn transferred_root_journal_refuses_missing_or_mismatched_selection_and_restores_exact_context() {
    let f = Ready::new();
    let old = f.c.original_rows();
    let selection = control(&f.c).expect("original selection");
    let wrong = plan(&f.c, &f.approval, false);
    assert!(matches!(
        AccountRootJournalRecovery::resume_transferred_original(
            &f.c.path(),
            f.c.key(),
            &f.c.device,
            f.c.identity,
            wrong
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(f.c.original_rows(), old);
    let mut owner = f.open().expect("correct independent context");
    owner.close();
    change(&f.c, witness_handoff::ROW, None);
    assert!(matches!(f.open(), Err(DurableError::Suspended)));
    change(&f.c, witness_handoff::ROW, Some(&selection));
    let mut recovered = f.open().expect("same restored original row");
    assert_eq!(
        recovered.status().expect("fenced"),
        AccountRootJournalState::LocalFenced
    );
    recovered.close();
    assert_eq!(f.c.original_rows(), old);
    assert_eq!(control(&f.c), Some(selection));
}

#[test]
fn transferred_root_journal_rejects_authenticated_context_and_proof_corruption() {
    let mut f = Ready::new();
    let old = f.c.original_rows();
    let selected = control(&f.c);
    let decision = f.decide(false);
    let mut owner = f.open().expect("original owner");
    owner
        .retain_account_decision(decision.as_bytes())
        .expect("retained proof");
    owner.close();
    let original = row(&f.c, ROW);
    // Valid storage MAC cannot substitute the independent history checkpoint.
    let mut bad = original.clone();
    let body = bad.len() - 32;
    *bad.get_mut(body - 129 + 64).expect("current-history field") ^= 1;
    let mut auth = mac(&f.c.key()).expect("owned test MAC");
    auth.update(bad.get(..body).expect("body"));
    bad.truncate(body);
    bad.extend_from_slice(&auth.finalize().into_bytes());
    change(&f.c, ROW, Some(&bad));
    assert!(matches!(f.open(), Err(DurableError::Suspended)));
    change(&f.c, ROW, Some(&original));
    let mut fence = Fence::decode(&f.c.key(), &original).expect("original fence");
    *fence
        .receipt
        .as_mut()
        .expect("proof")
        .last_mut()
        .expect("signature byte") ^= 1;
    change(
        &f.c,
        ROW,
        Some(
            &fence
                .encode(&f.c.key())
                .expect("valid MAC over damaged proof"),
        ),
    );
    assert!(f.open().is_err());
    change(&f.c, ROW, Some(&original));
    let mut recovered = f.open().expect("exact restored proof");
    assert_eq!(
        recovered
            .account_decision()
            .expect("original signed outcome")
            .as_bytes(),
        decision.as_bytes()
    );
    recovered.close();
    assert_eq!(f.c.original_rows(), old);
    assert_eq!(control(&f.c), selected);
}
