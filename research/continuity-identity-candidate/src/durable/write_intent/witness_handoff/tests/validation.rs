// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn replace(c: &Case, bytes: Option<&[u8]>) {
    let db = open_private_database(&c.path()).expect("owned lease");
    let tx = transaction(&db).expect("transaction");
    {
        let mut table = tx.open_table(TABLE).expect("table");
        table.remove(ROW).expect("remove only control row");
        if let Some(bytes) = bytes {
            table.insert(ROW, bytes).expect("replace control");
        }
    }
    tx.commit().expect("commit test mutation");
}
#[test]
fn witness_journal_adoption_cold_open_requires_original_control_and_exact_public_proof() {
    let c = Case::new(Some(2));
    let before = c.original_rows();
    let mut owner =
        WitnessJournalAdoption::prepare_original(&c.path(), c.key(), c.plan.clone(), || Ok(180))
            .expect("prepare");
    owner.adopt_authorization(&c.receipt).expect("adopt");
    let saved = owner
        .active
        .as_ref()
        .expect("owner")
        .read()
        .expect("control");
    let original = saved.encode(&c.key()).expect("bytes");
    owner.close();
    replace(&c, None);
    assert!(matches!(
        WitnessJournalAdoption::resume_original(&c.path(), c.key(), c.plan.clone()),
        Err(DurableError::Absent)
    ));
    replace(&c, Some(&original));
    for changed in 0..3 {
        let mut next = saved.clone();
        match changed {
            0 => next.image[0] ^= 1,
            1 => {
                let mut digest = next.pending.expect("actual P intent");
                digest[0] ^= 1;
                next.pending = Some(digest);
            }
            2 => {
                *next
                    .receipt
                    .as_mut()
                    .expect("receipt")
                    .last_mut()
                    .expect("signature") ^= 1
            }
            _ => unreachable!(),
        }
        let wire = next
            .encode(&c.key())
            .expect("valid storage MAC cannot authorize altered state");
        replace(&c, Some(&wire));
        assert!(
            WitnessJournalAdoption::resume_original(&c.path(), c.key(), c.plan.clone()).is_err()
        );
        replace(&c, Some(&original));
        let mut owner = c.resume();
        assert_eq!(
            owner
                .authorization_receipt()
                .expect("restored exact receipt")
                .as_bytes(),
            c.receipt
        );
        owner.close();
    }
    assert_eq!(c.original_rows(), before);
}
