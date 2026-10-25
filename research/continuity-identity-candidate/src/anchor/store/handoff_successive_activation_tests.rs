// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::anchor::transferred::Authority;
#[path = "handoff_successive_activation_tests/recovery.rs"]
mod recovery;

fn fresh_grant(
    c: &PolicyCase,
    current: &mut AnchorStore,
    device: &VerifiedDevice,
    policy: &HistoricalSessionPolicy,
    history: &AnchorHandoffHistory,
    activation: &AnchorHandoffActivationReceipt,
    now: u64,
) -> (Approved, Vec<u8>, AnchorHandoffClientAuthorizationReceipt) {
    let m = materials(c, device, policy, history, activation);
    let scope = current
        .handoff_adoption_scope(
            Id::generate().expect("new operation"),
            c.subject,
            &m,
            Validity::new(now, now + 10).expect("fresh permission interval"),
        )
        .expect("exact original entry and current history");
    let statement = Statement::new(&scope, &m, now).expect("fresh decision");
    let account = c
        .account
        .approve_anchor_handoff_adoption(&statement)
        .expect("account approval");
    let policy = c
        .issuer
        .approve_anchor_handoff_adoption(&statement)
        .expect("independent policy approval");
    let approved =
        Approved::from_approvals(&account, &policy, &scope, &m).expect("both exact approvals");
    let request = approved
        .prepare_witness_authorization(&m)
        .expect("current grant request");
    let grant = current
        .authorize_handoff_client(&request, || Ok(now))
        .expect("durable current grant");
    (approved, request, grant)
}
fn archived_bytes(current: &AnchorStore) -> Vec<u8> {
    let owner = current.active.as_ref().expect("live target");
    let tx = owner.db.begin_read().expect("inspect immutable archive");
    let table = tx
        .open_table(TableDefinition::<&str, &[u8]>::new(
            "continuity_anchor_handoff_source_archive_v1",
        ))
        .expect("source archive");
    table
        .get("source")
        .expect("read")
        .expect("original source")
        .value()
        .to_vec()
}

#[test]
fn successive_activation_retires_exact_source_and_requires_fresh_client_approval() {
    eprintln!(
        "SUCCESSIVE_LAYOUT owner={} active={} fixture={} prepared={} target={}",
        std::mem::size_of::<AnchorStore>(),
        std::mem::size_of::<Active>(),
        std::mem::size_of::<PolicyCase>(),
        std::mem::size_of::<Prepared>(),
        std::mem::size_of::<TargetFixture>()
    );
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE fixture");
    let mut c = PolicyCase::new();
    let proof = c.approval(&c.original, None, &c.target);
    let proposal = c.proposal(&proof, c.initial, 241);
    c.prepare(proposal, &proof).expect("original actual P");
    let device = c.device.clone();
    let policy = c.original.clone();
    let (mut f, next) = next_from(Prepared::from_case(c, device, policy), true);
    let before = image_codec::encode_content(
        &f.history,
        &f.active.handoff_image().expect("full frozen B data"),
    )
    .expect("retained original P");
    let mut target = next.provision();
    let ack = target.import_receipt().expect("complete C import");
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE retire-b");
    let retirement = f
        .active
        .retire_handoff(&next.approval, ack.as_bytes(), || Ok(185))
        .expect("B retirement preflight and durable commit");
    assert_eq!(retirement.state(), AnchorHandoffState::Retired);
    let history = target
        .verify_source_retirement(retirement.as_bytes())
        .expect("complete A-B-C history");
    assert_eq!(history.sequence(), 2);
    assert_eq!(history.namespace_binding(), f.c.pin.binding());
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE activate-c");
    let (mut current, activation) = target
        .activate(retirement.as_bytes(), next.signer())
        .expect("exact C activation");
    assert_eq!(activation.history_checkpoint(), history.checkpoint());
    assert_eq!(
        image_codec::encode_content(&history, &current.image().expect("complete C data"))
            .expect("same original operations"),
        before
    );
    assert!(matches!(
        current.handoff_client_authorization(f.c.subject),
        Err(DurableError::Absent)
    ));
    assert!(
        current
            .authorize_handoff_client(&f.request, || Ok(186))
            .is_err(),
        "old B permission cannot authorize C"
    );
    let (approved, request, grant) = fresh_grant(
        &f.c,
        &mut current,
        &f.c.device,
        &f.c.original,
        &history,
        &activation,
        186,
    );
    let c_grant_request = request.clone();
    let authority = Authority::verified(&approved, &history, grant.as_bytes(), &request)
        .expect("current signer with original logical binding");
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE rpc-c");
    let archive_before = archived_bytes(&current);
    crate::anchor::store::handoff::take_archive_reads();
    for (op, expected) in [
        (
            AnchorOperation::policy_renewal_status(&proposal),
            crate::AnchorPolicyRenewalState::Prepared,
        ),
        (
            AnchorOperation::commit_policy_renewal(&proposal),
            crate::AnchorPolicyRenewalState::Applied,
        ),
    ] {
        let request = authority
            .request(f.c.subject, op, &f.c.signer)
            .expect("original operation under new current permission");
        let reply = current
            .handle(request.as_bytes(), 186)
            .expect("real C request");
        let reply = authority
            .verify(&request, &reply)
            .expect("current C signature and exact logical command");
        assert_eq!(
            reply
                .policy_renewal_state(&proposal)
                .expect("original exact P result"),
            expected
        );
        assert_eq!(reply.logical_witness_binding(), f.c.pin.binding());
        assert_eq!(reply.signing_witness_binding(), next.pin.binding());
    }
    assert_eq!(
        crate::anchor::store::handoff::take_archive_reads(),
        0,
        "ordinary request must not resolve the historical archive"
    );
    assert_eq!(archived_bytes(&current), archive_before);
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE cold-c");
    current.close();
    let mut target = next.open();
    assert_eq!(
        target
            .activation_receipt()
            .expect("cold exact activation")
            .as_bytes(),
        activation.as_bytes()
    );
    assert_eq!(
        target
            .retained_source_state()
            .expect("full immutable source"),
        next.source
    );
    let (mut current, reopened) = target
        .activate(retirement.as_bytes(), next.signer())
        .expect("same active C");
    assert_eq!(reopened.as_bytes(), activation.as_bytes());
    assert_eq!(
        current
            .handoff_client_authorization(f.c.subject)
            .expect("same C permission")
            .as_bytes(),
        grant.as_bytes()
    );
    let request = authority
        .request(
            f.c.subject,
            AnchorOperation::commit_policy_renewal(&proposal),
            &f.c.signer,
        )
        .expect("same original P retry");
    let reply = current
        .handle(request.as_bytes(), 187)
        .expect("exact committed P retry");
    let reply = authority
        .verify(&request, &reply)
        .expect("verified original result");
    assert_eq!(
        reply
            .policy_renewal_state(&proposal)
            .expect("exact applied retry"),
        crate::AnchorPolicyRenewalState::Applied
    );
    assert_eq!(reply.observed_head(), proposal.target_head());
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE capture-d");
    let root = f.c.server.join("third-transition");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("owned next target root");
    let third =
        TargetFixture::from_store_operation(&mut current, &root, &next.pin, 189, false, 242);
    assert!(third.source.starts_with(b"QPAHSS03"));
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE import-d");
    let mut target = third.provision();
    let ack = target
        .import_receipt()
        .expect("D complete recursive source");
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE retire-c");
    let retired = current
        .retire_handoff(&third.approval, ack.as_bytes(), || Ok(189))
        .expect("C exact retirement");
    let history_d = target
        .verify_source_retirement(retired.as_bytes())
        .expect("full A-B-C-D history");
    assert_eq!(history_d.sequence(), 3);
    assert_eq!(history_d.namespace_binding(), f.c.pin.binding());
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE activate-d");
    let (mut last, activation_d) = target
        .activate(retired.as_bytes(), third.signer())
        .expect("D activation");
    assert!(
        last.authorize_handoff_client(&c_grant_request, || Ok(190))
            .is_err(),
        "previous C grant cannot authorize D"
    );
    eprintln!("SUCCESSIVE_ACTIVATION_STAGE grant-d");
    let (approved_d, request_d, grant_d) = fresh_grant(
        &f.c,
        &mut last,
        &f.c.device,
        f.c.target.historical(),
        &history_d,
        &activation_d,
        190,
    );
    let authority_d = Authority::verified(&approved_d, &history_d, grant_d.as_bytes(), &request_d)
        .expect("D permission over original A operation");
    crate::anchor::store::handoff::take_archive_reads();
    let request_d = authority_d
        .request(
            f.c.subject,
            AnchorOperation::commit_policy_renewal(&proposal),
            &f.c.signer,
        )
        .expect("same P at D");
    let response = last
        .handle(request_d.as_bytes(), 190)
        .expect("D actual original P retry");
    let reply = authority_d.verify(&request_d, &response).expect("D signer");
    assert_eq!(
        reply
            .policy_renewal_state(&proposal)
            .expect("same applied P"),
        crate::AnchorPolicyRenewalState::Applied
    );
    assert_eq!(reply.logical_witness_binding(), f.c.pin.binding());
    assert_eq!(reply.signing_witness_binding(), third.pin.binding());
    assert_eq!(crate::anchor::store::handoff::take_archive_reads(), 0);
    assert_eq!(archived_bytes(&last), third.source);
    last.close();
    assert_eq!(
        third
            .open()
            .activation_receipt()
            .expect("cold D receipt")
            .as_bytes(),
        activation_d.as_bytes()
    );
    current.close();
    assert_eq!(
        next.open()
            .observe_source_handoff(&third.plan)
            .expect("keyless retired C observer")
            .as_bytes(),
        retired.as_bytes()
    );
    assert!(matches!(
        f.active.cancel_handoff(&next.plan),
        Err(DurableError::Protocol(Error::Retired))
    ));
}

#[test]
fn successive_activation_reaches_history_bound_without_resetting_namespace_or_pending_work() {
    eprintln!(
        "SUCCESSIVE_BOUND_LAYOUT image={} journal={}",
        std::mem::size_of::<Image>(),
        std::mem::size_of::<crate::anchor::store::handoff::Journal>()
    );
    let mut c = PolicyCase::new();
    let proof = c.approval(&c.original, None, &c.target);
    let proposal = c.proposal(&proof, c.initial, 241);
    c.prepare(proposal, &proof).expect("original retained P");
    let device = c.device.clone();
    let policy = c.original.clone();
    let mut f = Prepared::from_case(c, device, policy);
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("B permission");
    let mut current = std::mem::replace(&mut f.active, AnchorStore { active: None });
    let mut last_history = f.history.clone();
    let mut previous_request = f.request.clone();
    for sequence in 2u8..=8 {
        eprintln!("SUCCESSIVE_BOUND_STAGE sequence={sequence}");
        let root = f.c.server.join(format!("bounded-hop-{sequence}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("owned next target");
        let pin = current.pin().expect("current authority");
        let now = 180 + u64::from(sequence);
        let next = TargetFixture::from_store_operation(
            &mut current,
            &root,
            &pin,
            now,
            false,
            220 + sequence,
        );
        let mut target = next.provision();
        let ack = target.import_receipt().expect("complete next import");
        let retirement = current
            .retire_handoff(&next.approval, ack.as_bytes(), || Ok(now))
            .expect("exact next retirement");
        let history = target
            .verify_source_retirement(retirement.as_bytes())
            .expect("full retained chain");
        assert_eq!(history.sequence(), u64::from(sequence));
        assert_eq!(history.namespace_binding(), f.c.pin.binding());
        let (mut adopted, activation) = target
            .activate(retirement.as_bytes(), next.signer())
            .expect("exact next activation");
        assert!(adopted
            .authorize_handoff_client(&previous_request, || Ok(now + 1))
            .is_err());
        let (approved, request, grant) = fresh_grant(
            &f.c,
            &mut adopted,
            &f.c.device,
            &f.c.original,
            &history,
            &activation,
            now + 1,
        );
        let authority = Authority::verified(&approved, &history, grant.as_bytes(), &request)
            .expect("new current grant");
        adopted.close();
        let (mut reopened, saved) = next
            .open()
            .activate(retirement.as_bytes(), next.signer())
            .expect("cold full-chain validation");
        assert_eq!(saved.as_bytes(), activation.as_bytes());
        crate::anchor::store::handoff::take_archive_reads();
        let query = authority
            .request(
                f.c.subject,
                AnchorOperation::policy_renewal_status(&proposal),
                &f.c.signer,
            )
            .expect("new challenge");
        let wire = reopened
            .handle(query.as_bytes(), now + 1)
            .expect("actual latest-owner query");
        let reply = authority
            .verify(&query, &wire)
            .expect("same logical operation, current signer");
        assert_eq!(reply.observed_head(), f.c.initial);
        assert_eq!(
            reply
                .policy_renewal_state(&proposal)
                .expect("same pending P"),
            crate::AnchorPolicyRenewalState::Prepared
        );
        assert_eq!(reply.logical_witness_binding(), f.c.pin.binding());
        assert_eq!(reply.signing_witness_binding(), next.pin.binding());
        assert_eq!(crate::anchor::store::handoff::take_archive_reads(), 0);
        current.close();
        current = reopened;
        last_history = history;
        previous_request = request;
    }
    assert_eq!(last_history.sequence(), 8);
    let root = f.c.server.join("refused-ninth-hop");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("owned prospective target");
    let pin = current.pin().expect("last authority");
    let ninth = TargetFixture::from_store_operation(&mut current, &root, &pin, 195, false, 239);
    assert!(matches!(
        AnchorHandoffTarget::provision_import(
            &ninth.db_path(),
            ninth.key(),
            &ninth.signer(),
            ninth.approval.clone(),
            &ninth.source,
            &ninth.freeze,
            195
        ),
        Err(DurableError::Capacity)
    ));
    assert!(!ninth.db_path().exists());
    current
        .cancel_handoff(&ninth.plan)
        .expect("capacity failure remains exactly cancellable");
    assert_eq!(
        current
            .handoff_source_state()
            .expect("complete last live source")
            .pin()
            .binding(),
        pin.binding()
    );
}

#[test]
fn successive_activation_preserves_all_prepared_and_applied_g_p_r() {
    for kind in ["G", "P", "R"] {
        for applied in [false, true] {
            let (mut f, next) = setup(kind, applied, applied);
            let before = image_codec::encode_content(
                &f.history,
                &f.active.handoff_image().expect("frozen complete GPR"),
            )
            .expect("original current image");
            let mut target = next.provision();
            let ack = target.import_receipt().expect("exact target import");
            let retired = f
                .active
                .retire_handoff(&next.approval, ack.as_bytes(), || Ok(185))
                .expect("source retirement with unresolved work");
            let history = target
                .verify_source_retirement(retired.as_bytes())
                .expect("full verified history");
            let (mut current, activation) = target
                .activate(retired.as_bytes(), next.signer())
                .expect("complete successor activation");
            assert_eq!(history.sequence(), 2);
            assert_eq!(history.namespace_binding(), f.c.pin.binding());
            assert_eq!(
                image_codec::encode_content(
                    &history,
                    &current.handoff_image().expect("complete current GPR"),
                )
                .expect("current encoding"),
                before,
                "{kind} applied={applied}: activation cannot rewrite original work"
            );
            current.close();
            let mut observer = next.open();
            assert_eq!(
                observer.retained_source_state().expect("archive"),
                next.source
            );
            assert_eq!(
                observer
                    .activation_receipt()
                    .expect("exact activation")
                    .as_bytes(),
                activation.as_bytes()
            );
            let (mut current, _) = observer
                .activate(retired.as_bytes(), next.signer())
                .expect("cold original successor");
            assert_eq!(
                image_codec::encode_content(
                    &history,
                    &current.handoff_image().expect("cold complete GPR"),
                )
                .expect("cold encoding"),
                before
            );
            assert!(matches!(
                current.handoff_client_authorization(f.c.subject),
                Err(DurableError::Absent)
            ));
            assert!(current
                .authorize_handoff_client(&f.request, || Ok(186))
                .is_err());
            assert!(matches!(
                f.active.cancel_handoff(&next.plan),
                Err(DurableError::Protocol(Error::Retired))
            ));
        }
    }
}
