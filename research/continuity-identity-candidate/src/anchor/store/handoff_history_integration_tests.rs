// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn original_v1_and_bound_v2_imports_verify_history_without_activating_or_resigning() {
    for legacy in [false, true] {
        let mut c = case();
        let f = TargetFixture::with_legacy_plan(&mut c, 150, legacy);
        let plan = f.plan.to_bytes();
        assert_eq!(
            plan.get(..8).expect("tag"),
            if legacy { b"QPAHPL01" } else { b"QPAHPL02" }
        );
        c.store.close();
        c.store = reopen(&c.server);
        let mut target = f.provision();
        let acknowledgement = target.import_receipt().expect("committed import");
        assert!(target.verify_source_retirement(&f.freeze).is_err());
        assert!(target
            .verify_source_retirement(acknowledgement.as_bytes())
            .is_err());
        let retirement = c
            .store
            .retire_handoff(&f.approval, acknowledgement.as_bytes(), || Ok(150))
            .expect("actual committed source retirement");
        c.store.close();
        fs::remove_file(c.server.join("signer")).expect("remove only owned test key");
        let before = fs::read(f.db_path()).expect("inactive durable bytes");
        let history = target
            .verify_source_retirement(retirement.as_bytes())
            .expect("historical proof without old signer or new time");
        assert_eq!(history.namespace_binding(), c.pin.binding());
        assert_eq!(history.current_pin().binding(), f.pin.binding());
        assert_eq!(history.sequence(), 1);
        assert_eq!(
            history
                .historical_pin(c.pin.binding())
                .expect("historical source")
                .public_key(),
            c.pin.public_key()
        );
        assert!(matches!(
            history.require_current(c.pin.binding()),
            Err(Error::Retired)
        ));
        history
            .require_current(f.pin.binding())
            .expect("current metadata pin");
        let wire = history.to_bytes().expect("retained public proof");
        let restored = AnchorHandoffHistory::restore_trusted_state(
            &wire,
            &c.pin,
            &f.pin,
            history.checkpoint(),
        )
        .expect("independent pins and exact checkpoint");
        assert_eq!(restored.to_bytes().expect("canonical proof"), wire);
        assert_eq!(
            target.status().expect("proof is not activation"),
            AnchorHandoffTargetState::ImportedInactive
        );
        assert_eq!(
            target.retained_source_state().expect("full original state"),
            f.source
        );
        assert_eq!(
            fs::read(f.db_path()).expect("no write during verification"),
            before
        );
        target.close();
        assert!(AnchorStore::open(&f.db_path(), f.key(), f.signer(), f.pin.identity()).is_err());
    }
}

#[test]
fn original_store_and_import_reject_fictitious_history_even_with_valid_source_signature() {
    let mut c = case();
    let f = TargetFixture::new(&mut c);
    c.store
        .cancel_handoff(&f.plan)
        .expect("known source cancellation");
    let source = c
        .store
        .handoff_source_state()
        .expect("current original image");
    let plan = AnchorHandoffPlan::from_trusted_state(
        [196; 32],
        &source,
        f.pin.clone(),
        Validity::new(140, 160).expect("interval"),
        [197; 32],
    )
    .expect("new approved intent");
    let mut bytes = plan.to_bytes();
    let offset = bytes
        .len()
        .checked_sub(40)
        .expect("sequence and predecessor");
    bytes
        .get_mut(offset..offset + 8)
        .expect("sequence")
        .copy_from_slice(&1_u64.to_be_bytes());
    bytes
        .get_mut(offset + 8..)
        .expect("false predecessor")
        .fill(198);
    let fictitious = AnchorHandoffPlan::restore_trusted_state(&bytes)
        .expect("shape is not authenticated history");
    assert!(matches!(
        c.store.freeze_handoff(&fictitious, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        c.store
            .handoff_source_state()
            .expect("unchanged source")
            .as_bytes(),
        source.as_bytes()
    );
    let approval = AnchorHandoffTargetApproval::from_trusted_state(
        &fictitious,
        &c.pin,
        &f.pin,
        Validity::new(145, 155).expect("interval"),
        [199; 32],
    )
    .expect("test approval shape");
    let (_, signer, _) = owners(&c.server);
    let mut body = b"QPAHFR01".to_vec();
    body.extend_from_slice(&fictitious.to_bytes());
    let wire = envelope(
        &body,
        &signer
            .sign(Purpose::AnchorHandoffFreeze, &body)
            .expect("valid source signature"),
    )
    .expect("freeze envelope");
    let path = f.directory.join("false-history.redb");
    assert!(matches!(
        AnchorHandoffTarget::provision_import(
            &path,
            f.key(),
            &f.signer(),
            approval,
            source.as_bytes(),
            &wire,
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(!path.exists());
}
