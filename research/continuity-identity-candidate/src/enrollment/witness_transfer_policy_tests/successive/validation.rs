// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::WitnessJournalAdoption;
use std::sync::atomic::Ordering;

fn next(f: &Fixture, first: &Transfer) -> Transfer {
    let mut second = next_transfer(f, first, 154, 78);
    second.plan = second
        .plan
        .clone()
        .continue_from(&first.plan, &first.control)
        .expect("independent exact predecessor and receipt");
    second.set_time(156);
    second
}
fn table(parent: bool) -> redb::TableDefinition<'static, &'static str, &'static [u8]> {
    if parent {
        TABLE
    } else {
        redb::TableDefinition::new("continuity_device_candidate_v21")
    }
}
fn database(f: &Fixture, parent: bool) -> redb::Database {
    open_private_database(if parent {
        &f.c.paths.configuration
    } else {
        f.c.paths.installation.files()[1]
    })
    .expect("closed owned fixture database")
}
fn row(f: &Fixture, parent: bool) -> Option<Vec<u8>> {
    let db = database(f, parent);
    let tx = db.begin_read().expect("read");
    let table = tx.open_table(table(parent)).expect("table");
    let row = table.get("witness-handoff").expect("selection row");
    row.map(|v| v.value().to_vec())
}
fn replace(f: &Fixture, parent: bool, bytes: Option<&[u8]>) {
    let db = database(f, parent);
    let tx = transaction(&db).expect("owned mutation");
    {
        let mut table = tx.open_table(table(parent)).expect("table");
        if let Some(bytes) = bytes {
            table.insert("witness-handoff", bytes).expect("replace");
        } else {
            table.remove("witness-handoff").expect("remove");
        }
    }
    tx.commit().expect("test mutation committed");
}
fn refused_client(f: &Fixture, transfer: &Transfer) {
    let mut owner = open(&f.c);
    assert!(owner
        .current_witness_anchor_client(
            f.c.policy.historical(),
            transfer.plan.clone(),
            transfer.carrier(),
            Duration::from_secs(3),
        )
        .is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert_eq!(transfer.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn enrollment_witness_successor_cannot_replace_prepared_or_parent_unknown_predecessor() {
    for child_adopted in [false, true] {
        let (f, a, p) = pending_case();
        let before = journal(&f);
        let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
        let first = Transfer::new(
            &mut f.carrier.store.lock().expect("A"),
            &f.c,
            &f.original,
            &f.original,
            f.c.policy.historical(),
            subject,
            151,
        );
        open(&f.c)
            .prepare_witness_handoff(f.c.policy.historical(), first.plan.clone(), || Ok(152))
            .expect("first prepared parent and child");
        if child_adopted {
            let mut child = WitnessJournalAdoption::resume_original(
                f.c.paths.installation.files()[1],
                JournalKey::open(&f.c.paths.wrapping).expect("same key"),
                first.plan.clone(),
            )
            .expect("original first child");
            child
                .adopt_authorization(&first.receipt)
                .expect("child-only commit");
            child.close();
        }
        let second = next(&f, &first);
        let saved = [row(&f, false), row(&f, true)];
        let mut owner = open(&f.c);
        assert!(matches!(
            owner.prepare_witness_handoff(f.c.policy.historical(), second.plan.clone(), || Ok(155)),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        assert_eq!([row(&f, false), row(&f, true)], saved);
        assert_eq!(journal(&f), before);
        assert_eq!(second.requests.load(Ordering::SeqCst), 0);
        // The retired first target need not re-sign or be online: reconcile its
        // exact committed decision locally before advancing to the new target.
        first.adopt_parent(&f.c, 155).close();
        second.adopt_parent(&f.c, 155).close();
        complete_original(&f, &a, p, &before, &second, 156);
    }
}

#[test]
fn enrollment_witness_successor_refuses_missing_rows_and_repairs_only_exact_parent_lag() {
    let (f, a, p) = pending_case();
    let before = journal(&f);
    let first = first_transfer(&f);
    let previous = [row(&f, false), row(&f, true)];
    let second = next(&f, &first);
    second.adopt_parent(&f.c, 155).close();
    let current = [row(&f, false), row(&f, true)];
    refused_client(&f, &first);
    for parent in [false, true] {
        replace(&f, parent, None);
        let mut owner = open(&f.c);
        assert!(owner
            .prepare_witness_handoff(f.c.policy.historical(), second.plan.clone(), || Ok(155))
            .is_err());
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        assert!(
            row(&f, parent).is_none(),
            "missing state cannot be recreated"
        );
        refused_client(&f, &second);
        replace(
            &f,
            parent,
            current
                .get(usize::from(parent))
                .expect("parent/child slot")
                .as_deref(),
        );
    }
    replace(&f, false, previous[0].as_deref());
    refused_client(&f, &second);
    let mut owner = open(&f.c);
    let clock_calls = std::cell::Cell::new(0);
    assert!(
        owner
            .prepare_witness_handoff(f.c.policy.historical(), second.plan.clone(), || Ok(155))
            .is_err(),
        "parent already selected C: an old B child is not a retry"
    );
    replace(&f, false, current[0].as_deref());
    replace(&f, true, previous[1].as_deref());
    refused_client(&f, &second);
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .prepare_witness_handoff(f.c.policy.historical(), second.plan.clone(), || {
                clock_calls.set(clock_calls.get() + 1);
                Err(DurableError::Conflict)
            })
            .expect("publish exact new child's existing receipt to lagging parent"),
        WitnessJournalAdoptionState::Adopted
    );
    assert_eq!(
        clock_calls.get(),
        0,
        "historical retry cannot request another time decision"
    );
    owner.close();
    assert_eq!([row(&f, false), row(&f, true)], current);
    assert_eq!(journal(&f), before);
    assert_eq!(second.requests.load(Ordering::SeqCst), 0);
    complete_original(&f, &a, p, &before, &second, 156);
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mutation {
    Omit,
    Receipt,
    PreparedTime,
}
fn altered(f: &Fixture, wire: &[u8], parent: bool, mutation: Mutation) -> Vec<u8> {
    let header = if parent { 80 } else { 81 };
    assert_eq!(
        wire.get(..8).expect("header"),
        if parent { b"QPEWAH02" } else { b"QPWJAH02" }
    );
    let mut d = Decoder::new(wire);
    d.take(header).expect("header");
    let request = u32::from_be_bytes(d.array().expect("request length")) as usize;
    d.take(request).expect("request");
    let receipt = usize::from(d.u16().expect("receipt length"));
    d.take(receipt).expect("receipt");
    let start = header + 4 + request + 2 + receipt;
    assert_eq!(wire.get(start), Some(&1), "one actual prior decision");
    let end = wire.len().checked_sub(32).expect("MAC width");
    let mut body = wire.get(..end).expect("authenticated body").to_vec();
    match mutation {
        Mutation::Omit => {
            body.truncate(start);
            body.get_mut(..8)
                .expect("header")
                .copy_from_slice(if parent { b"QPEWAH01" } else { b"QPWJAH01" });
        }
        Mutation::Receipt => *body.last_mut().expect("last prior receipt signature byte") ^= 1,
        Mutation::PreparedTime => body
            .get_mut(start + 1..start + 9)
            .expect("prior preparation time")
            .copy_from_slice(&153u64.to_be_bytes()),
    }
    let key = JournalKey::open(&f.c.paths.wrapping).expect("owned fixture key");
    if parent {
        let mut mac = auth(&key).expect("parent authenticator");
        mac.update(b"Q-PERIAPT-ENROLLMENT-WITNESS-SELECTION/v1");
        mac.update(&body);
        body.extend_from_slice(&mac.finalize().into_bytes());
        body
    } else {
        crate::durable::tests::authenticate_witness_control(&key, &body)
    }
}

#[test]
fn enrollment_witness_successor_rejects_mac_valid_history_loss_and_pins_attached_lineage() {
    let (f, a, p) = pending_case();
    let before = journal(&f);
    let first = first_transfer(&f);
    let second = next(&f, &first);
    second.adopt_parent(&f.c, 155).close();
    let current = [
        row(&f, false).expect("child"),
        row(&f, true).expect("parent"),
    ];
    for mutation in [Mutation::Omit, Mutation::Receipt, Mutation::PreparedTime] {
        let mut owner = open(&f.c);
        let mut attached = second.client(&mut owner, &f.c);
        owner.close();
        for parent in [false, true] {
            replace(
                &f,
                parent,
                Some(&altered(
                    &f,
                    current.get(usize::from(parent)).expect("parent/child slot"),
                    parent,
                    mutation,
                )),
            );
        }
        if mutation != Mutation::PreparedTime {
            // Both MACs and the current receipt remain valid. The independently
            // retained full plan still rejects omitted or substituted history.
            let mut owner = open(&f.c);
            assert!(owner
                .witness_handoff_status(f.c.policy.historical(), second.plan.clone())
                .is_err());
            assert!(matches!(owner.status(), Err(DurableError::Closed)));
        }
        // A valid but different past preparation time is not signed by the
        // target. An already attached client must still pin its exact lineage.
        let mut owner = open(&f.c);
        assert!(owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                156,
                &mut attached
            )
            .is_err());
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        assert_eq!(
            second.requests.load(Ordering::SeqCst),
            0,
            "refuse before dispatch"
        );
        for parent in [false, true] {
            replace(
                &f,
                parent,
                Some(current.get(usize::from(parent)).expect("parent/child slot")),
            );
        }
        assert_eq!(journal(&f), before);
    }
    complete_original(&f, &a, p, &before, &second, 156);
}

#[test]
fn enrollment_witness_successor_requires_strict_extension_and_exact_predecessor_receipt() {
    let (f, a, p) = pending_case();
    let before = journal(&f);
    let first = first_transfer(&f);
    let mut second = next_transfer(&f, &first, 154, 78);
    let saved = [row(&f, false), row(&f, true)];
    assert!(
        first
            .plan
            .clone()
            .continue_from(&first.plan, &first.control)
            .is_err(),
        "the same history is not a successor"
    );
    assert!(
        second
            .plan
            .clone()
            .continue_from(&first.plan, &second.control)
            .is_err(),
        "a valid new target receipt cannot stand in for the old target's receipt"
    );
    let mut owner = open(&f.c);
    assert!(
        owner
            .prepare_witness_handoff(f.c.policy.historical(), second.plan.clone(), || Ok(155))
            .is_err(),
        "a fresh independently approved plan cannot discard the retained predecessor"
    );
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert_eq!([row(&f, false), row(&f, true)], saved);
    second.plan = second
        .plan
        .clone()
        .continue_from(&first.plan, &first.control)
        .expect("exact full predecessor history");
    assert!(
        matches!(
            second
                .plan
                .clone()
                .continue_from(&first.plan, &first.control),
            Err(Error::State)
        ),
        "an already bound predecessor cannot be silently rebased"
    );
    assert_eq!(second.requests.load(Ordering::SeqCst), 0);
    second.set_time(156);
    second.adopt_parent(&f.c, 155).close();
    assert_eq!(journal(&f), before);
    complete_original(&f, &a, p, &before, &second, 156);
}
