// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real current-authority requests cross a durable second-source freeze.
use super::*;
use crate::anchor::transferred::Authority;
#[path = "handoff_successive_freeze_tests/faults.rs"]
mod faults;
#[path = "handoff_successive_freeze_tests/process.rs"]
mod process;

#[test]
fn successive_source_control_cannot_be_dropped_or_used_to_rewrite_data() {
    for case in 0..3 {
        let mut f = Prepared::new(Some(("P", false)));
        f.active
            .authorize_handoff_client(&f.request, || Ok(180))
            .expect("current authorization");
        let (_, plan) = next_plan(&mut f.active, 244);
        let freeze = f.active.freeze_handoff(&plan, 180).expect("freeze");
        let receipt = if case == 0 {
            freeze
        } else {
            f.active.cancel_handoff(&plan).expect("cancel")
        };
        let mut image = f.active.handoff_image().expect("complete control and data");
        let digest = image.digest;
        let revision = image.revision;
        let result = if case == 2 {
            image.revision = increment(image.revision).expect("changed data revision");
            f.active.persist_image(&mut image, false)
        } else {
            image.handoff = None;
            f.active.persist_image(&mut image, true)
        };
        if case == 0 {
            assert!(matches!(result, Err(DurableError::Suspended)));
        } else {
            assert!(matches!(result, Err(DurableError::Conflict)));
        }
        assert!(f.active.active.is_none(), "failed write closes the owner");
        f.reopen();
        let unchanged = f.active.handoff_image().expect("original state survives");
        assert_eq!(unchanged.digest, digest);
        assert_eq!(unchanged.revision, revision);
        assert_eq!(
            f.active
                .observe_handoff(&plan)
                .expect("exact decision")
                .as_bytes(),
            receipt.as_bytes()
        );
    }
}

fn next_plan(
    active: &mut AnchorStore,
    operation: u8,
) -> (AnchorHandoffSourceState, AnchorHandoffPlan) {
    let snapshot = active
        .handoff_source_state()
        .expect("complete activated source");
    let key = AnchorSigningKey::generate().expect("independent next authority");
    let pin = AnchorPin::new(
        AnchorIdentity::generate().expect("next identity"),
        key.public_key().expect("next public key"),
    );
    let plan = AnchorHandoffPlan::from_trusted_state(
        [operation; 32],
        &snapshot,
        pin,
        Validity::new(180, 200).expect("independent source window"),
        [operation.wrapping_add(1); 32],
    )
    .expect("exact independently approved next intent");
    (snapshot, plan)
}

#[test]
fn successive_source_freeze_blocks_current_requests_and_recovers_exact_cancellation() {
    let mut f = Prepared::new(Some(("P", false)));
    let authorization = f
        .active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("existing current authorization");
    let authority = Authority::verified(
        &f.approved,
        &f.history,
        authorization.as_bytes(),
        &f.request,
    )
    .expect("original current request authority");
    let query = authority
        .request(f.c.subject, AnchorOperation::query(), &f.c.signer)
        .expect("fresh current query");
    let wire = f
        .active
        .handle(query.as_bytes(), 180)
        .expect("actual service before freeze");
    authority
        .verify(&query, &wire)
        .expect("current signer and original command ID");
    let original = f.original_entry();
    let (snapshot, plan) = next_plan(&mut f.active, 244);
    let freeze = f
        .active
        .freeze_handoff(&plan, 180)
        .expect("durable second-source freeze of actual pending state");
    assert_eq!(freeze.state(), AnchorHandoffState::Frozen);
    assert_eq!(
        f.active
            .freeze_handoff(&plan, 181)
            .expect("exact retry")
            .as_bytes(),
        freeze.as_bytes()
    );
    f.reopen();
    assert_eq!(
        f.active
            .observe_handoff(&plan)
            .expect("retained decision")
            .as_bytes(),
        freeze.as_bytes()
    );
    assert_eq!(
        f.active
            .frozen_handoff_state(&plan)
            .expect("exact complete prior state")
            .as_bytes(),
        snapshot.as_bytes()
    );
    assert!(matches!(
        f.active.handle(query.as_bytes(), 181),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    assert!(matches!(
        f.active.authorize_handoff_client(&f.request, || Ok(181)),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        f.active.transferred_control(&authorization),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        f.active.handoff_source_state(),
        Err(DurableError::Suspended)
    ));
    let cancelled = f
        .active
        .cancel_handoff(&plan)
        .expect("exact historical cancellation");
    assert_eq!(cancelled.state(), AnchorHandoffState::Cancelled);
    f.reopen();
    assert_eq!(
        f.active
            .cancel_handoff(&plan)
            .expect("exact terminal retry")
            .as_bytes(),
        cancelled.as_bytes()
    );
    assert!(matches!(
        f.active.freeze_handoff(&plan, 180),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert_eq!(f.original_entry(), original);
    let query = authority
        .request(f.c.subject, AnchorOperation::query(), &f.c.signer)
        .expect("fresh request after cancellation");
    let reply = f
        .active
        .handle(query.as_bytes(), 181)
        .expect("current authority resumes");
    authority
        .verify(&query, &reply)
        .expect("same exact client grant/current signer");
    let after = f
        .active
        .handoff_source_state()
        .expect("cancellation history in next capture");
    assert_ne!(after.commitment(), snapshot.commitment());
    let (second_snapshot, second) = next_plan(&mut f.active, 246);
    f.active
        .freeze_handoff(&second, 182)
        .expect("next distinct source decision");
    assert_eq!(
        f.active
            .frozen_handoff_state(&second)
            .expect("retained cancelled history")
            .as_bytes(),
        second_snapshot.as_bytes()
    );
    assert_eq!(
        f.active
            .observe_handoff(&plan)
            .expect("first cancellation not forgotten")
            .as_bytes(),
        cancelled.as_bytes()
    );
    f.active
        .cancel_handoff(&second)
        .expect("same original pending work after second cancel");
    assert_eq!(f.original_entry(), original);
}

#[test]
fn successive_source_decisions_are_observable_without_either_signing_key() {
    let mut f = Prepared::new(Some(("G", true)));
    let authorization = f
        .active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("retained original client authorization");
    let (snapshot, plan) = next_plan(&mut f.active, 244);
    let receipt = f
        .active
        .freeze_handoff(&plan, 180)
        .expect("durable source freeze");
    assert_eq!(
        f.active
            .freeze_handoff(&plan, 201)
            .expect("expired exact retry does not resign")
            .as_bytes(),
        receipt.as_bytes()
    );
    f.active.close();
    f.c.store.close();
    let source = f.c.server.join("signer");
    let source_held = f.c.server.join("held-source-signer");
    let target = f.f.directory.join("signer");
    let target_held = f.f.directory.join("held-target-signer");
    fs::rename(&source, &source_held).expect("withhold owned A signer");
    fs::rename(&target, &target_held).expect("withhold owned B signer");
    let mut observer = f.f.open();
    assert_eq!(
        observer
            .observe_source_handoff(&plan)
            .expect("keyless source decision")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert_eq!(
        observer
            .frozen_source_handoff_state(&plan)
            .expect("keyless complete prior bytes")
            .as_bytes(),
        snapshot.as_bytes()
    );
    assert_eq!(
        observer
            .client_authorization_receipt(f.c.subject)
            .expect("retained history")
            .as_bytes(),
        authorization.as_bytes()
    );
    observer.close();
    fs::rename(&source_held, &source).expect("restore original owned A file");
    fs::rename(&target_held, &target).expect("restore original owned B file");
    f.reopen();
    let cancelled = f
        .active
        .cancel_handoff(&plan)
        .expect("historical cancellation after expiry");
    f.active.close();
    let mut observer = f.f.open();
    assert_eq!(
        observer
            .observe_source_handoff(&plan)
            .expect("retained terminal decision")
            .as_bytes(),
        cancelled.as_bytes()
    );
    assert!(matches!(
        observer.frozen_source_handoff_state(&plan),
        Err(DurableError::Protocol(Error::Retired))
    ));
}

#[test]
fn successive_source_freeze_rejects_a_capture_before_client_authorization() {
    let mut f = Prepared::new(Some(("R", false)));
    let (_, stale) = next_plan(&mut f.active, 244);
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("separate later commit");
    assert!(matches!(
        f.active.freeze_handoff(&stale, 180),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        f.active.observe_handoff(&stale),
        Err(DurableError::Absent)
    ));
    let (snapshot, current) = next_plan(&mut f.active, 246);
    f.active
        .freeze_handoff(&current, 181)
        .expect("new independent current decision");
    f.reopen();
    assert_eq!(
        f.active
            .frozen_handoff_state(&current)
            .expect("full index and all proof rows")
            .as_bytes(),
        snapshot.as_bytes()
    );
    // A prior target approval is not the independently approved current plan.
    assert!(matches!(
        f.active.retire_handoff(&f.f.approval, &[], || Ok(182)),
        Err(DurableError::Absent)
    ));
    f.active
        .cancel_handoff(&current)
        .expect("exact current decision remains cancellable");
}

#[test]
fn successive_source_marker_refuses_missing_extra_and_mac_valid_forged_control(
) -> Result<(), Box<dyn std::error::Error>> {
    const CONTROL: TableDefinition<&str, &[u8]> =
        TableDefinition::new("continuity_anchor_handoff_source_v1");
    const PRIMARY: TableDefinition<&str, &[u8]> =
        TableDefinition::new("continuity_anchor_handoff_import_v1");
    for case in [
        "missing-table",
        "missing-row",
        "extra-row",
        "bad-mac",
        "forged-signature",
        "extra-table",
    ] {
        let mut f = Prepared::new(Some(("P", true)));
        f.active
            .authorize_handoff_client(&f.request, || Ok(180))
            .expect("client authorization");
        let (snapshot, plan) = next_plan(&mut f.active, 244);
        let freeze = f
            .active
            .freeze_handoff(&plan, 180)
            .expect("current source frozen");
        f.active.close();
        let before = fs::read(f.f.db_path()).expect("owned exact database backup");
        let db = open_private_database(&f.f.db_path()).expect("closed owned fixture");
        let tx = transaction(&db).expect("test corruption transaction");
        match case {
            "missing-table" => {
                assert!(tx
                    .delete_table(CONTROL)
                    .expect("remove fixture control table"));
            }
            "missing-row" => {
                tx.open_table(CONTROL)
                    .expect("table")
                    .remove("state")
                    .expect("remove fixture row");
            }
            "extra-row" => {
                tx.open_table(CONTROL)
                    .expect("table")
                    .insert("extra", b"invalid".as_slice())
                    .expect("extra fixture row");
            }
            "extra-table" => {
                tx.open_table(TableDefinition::<&str, &[u8]>::new(
                    "unexpected_source_table",
                ))
                .expect("extra fixture table")
                .insert("x", b"unexpected".as_slice())
                .expect("extra value");
            }
            "bad-mac" | "forged-signature" => {
                let mut table = tx.open_table(CONTROL).expect("table");
                let mut row = table
                    .get("state")
                    .expect("read")
                    .expect("state")
                    .value()
                    .to_vec();
                let body_end = row.len().checked_sub(32).expect("row MAC");
                *row.get_mut(body_end.checked_sub(1).expect("retained signature byte"))
                    .expect("signature") ^= 1;
                if case == "forged-signature" {
                    let key = f.f.key();
                    let body = row.get(..body_end).expect("control public body");
                    let commitment = digest(b"Q-PERIAPT-ANCHOR-SOURCE-CONTROL-ROW/v1", body);
                    let mut mac = authenticator(&key).expect("owned fixture MAC");
                    mac.update(b"Q-PERIAPT-ANCHOR-SOURCE-CONTROL-MAC/v1");
                    mac.update(body);
                    row.get_mut(body_end..)
                        .expect("MAC field")
                        .copy_from_slice(&mac.finalize().into_bytes());
                    let mut primary = tx.open_table(PRIMARY).expect("primary table");
                    let mut bytes = primary
                        .get("image")
                        .expect("read")
                        .expect("image")
                        .value()
                        .to_vec();
                    assert_eq!(bytes.get(..8).expect("tag"), b"QPAHI004");
                    let end = bytes.len().checked_sub(32).expect("primary MAC");
                    bytes
                        .get_mut(end.checked_sub(32).expect("control digest")..end)
                        .expect("marker")
                        .copy_from_slice(&commitment);
                    let mut mac = authenticator(&key).expect("owned primary MAC");
                    mac.update(bytes.get(..end).expect("primary body"));
                    bytes
                        .get_mut(end..)
                        .expect("primary tag")
                        .copy_from_slice(&mac.finalize().into_bytes());
                    primary
                        .insert("image", bytes.as_slice())
                        .expect("test primary replacement");
                }
                table
                    .insert("state", row.as_slice())
                    .expect("test control replacement");
            }
            _ => return Err(format!("unknown corruption case {case}").into()),
        }
        tx.commit().expect("fixture corruption committed");
        drop(db);
        let error = match AnchorHandoffTarget::open(&f.f.db_path(), f.f.key(), f.f.approval.clone())
        {
            Err(error) => error,
            Ok(mut owner) => {
                owner.close();
                return Err(format!("accepted {case}").into());
            }
        };
        match case {
            "bad-mac" => assert!(matches!(error, DurableError::Authentication)),
            "forged-signature" => assert!(matches!(
                error,
                DurableError::Protocol(Error::Authentication)
            )),
            _ => assert!(matches!(error, DurableError::Corrupt)),
        }
        fs::write(f.f.db_path(), before).expect("restore only owned original fixture");
        let mut observer = f.f.open();
        assert_eq!(
            observer
                .observe_source_handoff(&plan)
                .expect("original freeze survives restored state")
                .as_bytes(),
            freeze.as_bytes()
        );
        assert_eq!(
            observer
                .frozen_source_handoff_state(&plan)
                .expect("all original pending metadata")
                .as_bytes(),
            snapshot.as_bytes()
        );
    }
    Ok(())
}
