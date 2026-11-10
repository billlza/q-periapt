// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn row(
    path: &Path,
    table_name: &'static str,
    replacement: Option<&[u8]>,
    remove: bool,
) -> Option<Vec<u8>> {
    let db = open_private_database(path).expect("owned closed fixture");
    let tx = transaction(&db).expect("test mutation transaction");
    let mut table = tx
        .open_table(redb::TableDefinition::<&str, &[u8]>::new(table_name))
        .expect("table");
    let old = table
        .get("witness-handoff")
        .expect("row lookup")
        .map(|v| v.value().to_vec());
    if remove {
        table
            .remove("witness-handoff")
            .expect("remove only fixture row");
    }
    if let Some(value) = replacement {
        table
            .insert("witness-handoff", value)
            .expect("restore fixture row");
    }
    drop(table);
    tx.commit().expect("test mutation committed");
    old
}
fn parent_mac(f: &Fixture, bytes: &mut [u8]) {
    let end = bytes.len().checked_sub(32).expect("MAC width");
    let key = JournalKey::open(&f.c.paths.wrapping).expect("owned fixture key");
    let mut mac = auth(&key).expect("parent authenticator");
    mac.update(b"Q-PERIAPT-ENROLLMENT-WITNESS-SELECTION/v1");
    mac.update(bytes.get(..end).expect("body"));
    bytes
        .get_mut(end..)
        .expect("MAC")
        .copy_from_slice(&mac.finalize().into_bytes());
}

#[test]
fn transferred_cancellation_rejects_missing_and_conflicting_parent_child_metadata() {
    for case in [
        "missing-parent",
        "missing-child",
        "parent-time",
        "parent-receipt",
    ] {
        let (f, _, transfer) = staged_transfer();
        let before = disk(&f);
        let parent = case != "missing-child";
        let path = if parent {
            f.c.paths.configuration.as_path()
        } else {
            f.c.paths.installation.files()[1]
        };
        let table = if parent {
            "continuity_enrollment_v1"
        } else {
            "continuity_device_candidate_v21"
        };
        let old = row(path, table, None, false).expect("original selection row");
        assert!(!old.is_empty());
        if case.starts_with("missing") {
            let _ = row(path, table, None, true);
        } else {
            let mut changed = old.clone();
            if case == "parent-time" {
                changed
                    .get_mut(72..80)
                    .expect("prepared time")
                    .copy_from_slice(&181u64.to_be_bytes());
            } else {
                let end = changed.len();
                *changed.get_mut(end - 33).expect("receipt signature") ^= 1;
            }
            parent_mac(&f, &mut changed);
            let _ = row(path, table, Some(&changed), false);
        }
        let mut owner = open(&f.c);
        assert!(
            owner
                .prepare_witnessed_credential_cancellation_with_witness_plan(
                    f.c.policy.historical(),
                    transfer.plan.clone(),
                    290
                )
                .is_err(),
            "{case}"
        );
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        assert!(
            disk(&f) == before,
            "no intent or ciphertext change on {case}"
        );
        assert_eq!(transfer.requests.load(Ordering::SeqCst), 0);
        let _ = row(path, table, Some(&old), false);
        open(&f.c)
            .prepare_witnessed_credential_cancellation_with_witness_plan(
                f.c.policy.historical(),
                transfer.plan.clone(),
                290,
            )
            .expect("exact restored original selection");
    }
}

#[test]
fn transferred_cancellation_refuses_foreign_plan_and_foreign_control_subject() {
    let (f, g, transfer) = staged_transfer();
    let (other, other_g, foreign) = staged_transfer();
    let before = disk(&f);
    let mut owner = open(&f.c);
    assert!(owner
        .prepare_witnessed_credential_cancellation_with_witness_plan(
            f.c.policy.historical(),
            foreign.plan.clone(),
            290
        )
        .is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert!(disk(&f) == before);
    let original = open(&f.c)
        .prepare_witnessed_credential_cancellation_with_witness_plan(
            f.c.policy.historical(),
            transfer.plan.clone(),
            290,
        )
        .expect("original cancellation");
    let wrong = open(&other.c)
        .prepare_witnessed_credential_cancellation_with_witness_plan(
            other.c.policy.historical(),
            foreign.plan.clone(),
            290,
        )
        .expect("independent foreign cancellation");
    let mut target = transfer.target.lock().expect("target");
    assert!(target.transferred_control(&foreign.control).is_err());
    let mut controlled = target
        .transferred_control(&transfer.control)
        .expect("own committed approval");
    assert!(controlled
        .close_unprepared_credential_renewal(
            wrong,
            other_g.historical(),
            other.c.policy.historical()
        )
        .is_err());
    assert_eq!(
        controlled
            .close_unprepared_credential_renewal(original, g.historical(), f.c.policy.historical())
            .expect("unmodified original target"),
        crate::AnchorCredentialCancellationState::Closed
    );
}
