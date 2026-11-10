// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual HTTP account authentication, original response loss and signed root cutover.
use super::*;
use q_periapt_continuity_reference_app::{
    account_authority::{
        Association, AssociationRequest, Cutover, CutoverRequest, CutoverStatus, Retirement,
    },
    enrollment::RosterSnapshot,
    policy_publisher::{Anchor, BootstrapMode, PolicyInput, Publisher, Request},
    root_preparation::{Predecessor, Preparation, Status},
    store::Store,
    witness::{AccountRootOutcome, AccountRootTrust, EnrollmentRequest, EnrollmentTrust, Witness},
};

#[tokio::test]
async fn http_root_cutover_recovers_lost_decisions_under_original_account_authentication() -> Result
{
    let path = directory()?.keep().canonicalize()?;
    eprintln!("Root cutover HTTP private fixture: {}", path.display());
    let mut witness = Witness::provision(&path.join("witness.redb"), [80; 32])?;
    let pin = witness.prepare()?;
    let mut publisher = Publisher::provision(
        &path.join("publisher.redb"),
        [81; 32],
        crate::test_support::sdk_input()?,
    )?;
    let family = publisher.prepare()?.family;
    let at = now()?;
    publisher.issue(
        [82; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: at,
            valid_until: at + 3600,
            send_budget: 8,
            anchor: Anchor::Required {
                identity: pin.identity,
                key: pin.key,
            },
        },
        at,
    )?;
    let (pins, materials) = publisher.export([82; 32])?;
    let input = PolicyInput { pins, materials };
    let (policy, _) = input.pins.verify(&input.materials, family, at)?;
    let server = Server::with_family(&path, "127.0.0.1:0".parse()?, true, family).await?;
    let mut alice = Client::default();
    let mut auth = alice.register(&server, "alice").await?;
    alice
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?;
    let old = invitation(&mut alice, &server, 80).await?;
    let (_, proof) = device_request(&path, &old)?;
    approve(&mut alice, &server, &old, &proof).await?;
    let old_result = issue(&mut alice, &server, &old).await?;
    let root: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    let address = server.address;
    let origin = server.origin.clone();
    server.close().await?;
    let mut store = Store::open(&path.join("accounts.redb"), &origin)?;
    store.enable_enrollment_extensions()?;
    store.enable_credential_grants()?;
    store.enable_policy_approvals()?;
    store.enable_device_replacements()?;
    store.enable_root_preparations()?;
    store.enable_root_successors()?;
    store.enable_account_authorities()?;
    drop(store);
    let server = Server::with_family(&path, address, false, family).await?;
    let association = AssociationRequest {
        request_id: [83; 32],
        enrollment: old.operation,
        root: Predecessor {
            revision: root.revision,
            account: root.account,
        },
        roster: root.roster.as_ref().ok_or("original roster")?.checkpoint,
        policy: input.clone(),
    };
    let route = "/api/enrollment/authority/associate";
    alice
        .post(&server, route, &association)
        .await?
        .checked(401)?;
    alice.login(&server, "alice", &mut auth).await?;
    for origin in [None, Some("http://untrusted.example")] {
        alice
            .request(
                &server,
                route,
                Some(serde_json::to_string(&association)?),
                origin,
            )
            .await?
            .checked(400)?;
    }
    assert!(alice
        .disconnect_before_body(&server, route, &association)
        .await?
        .checked(200)?
        .body
        .is_empty());
    server.close().await?;
    let server = Server::with_family(&path, address, false, family).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let stored: Association = alice
        .get(&server, "/api/enrollment/authority")
        .await?
        .checked(200)?
        .json()?;
    assert!(stored.request == association);
    assert!(
        alice
            .post(&server, route, &association)
            .await?
            .checked(200)?
            .json::<Association>()?
            == stored
    );
    let prepared: Preparation = alice
        .post(
            &server,
            "/api/enrollment/root-candidate/prepare",
            json!({"request_id":vec![84u8;32],
        "predecessor":{"revision":root.revision,"account":root.account}}),
        )
        .await?
        .checked(200)?
        .json()?;
    let Status::Prepared { candidate } = prepared.status else {
        return Err("candidate".into());
    };
    let next: Invitation = alice
        .post(
            &server,
            "/api/enrollment/root-candidate/invite",
            json!({"preparation":prepared.operation,"request_id":vec![85u8;32]}),
        )
        .await?
        .checked(200)?
        .json()?;
    let (paths, request) = device_request(&path, &next)?;
    approve(&mut alice, &server, &next, &request).await?;
    let response = issue(&mut alice, &server, &next).await?;
    let issued: IssuedEnrollment = serde_json::from_slice(&response)?;
    let target_root = RootInfo {
        revision: candidate.revision,
        account: candidate.account,
        public_key: candidate.public_key,
        family,
        suspended: false,
        roster: Some(RosterSnapshot {
            checkpoint: issued.checkpoint,
            bytes: issued.roster.clone(),
        }),
    };
    let mut native = sdk::DeviceEnrollment::open(paths, next.intent()?)?;
    let account_pin = sdk::AccountPin::new(
        target_root.account,
        sdk::PublicKey::decode(&target_root.public_key)?,
        issued.checkpoint.as_sdk()?,
        family,
    )?;
    let installation = native.accept(
        &issued.certificate,
        &issued.roster,
        &account_pin,
        &policy,
        now()?,
    )?;
    let sdk::InstallationPreparation::RequiresEnrollment(genesis) =
        native.prepare(&policy, now()?)?
    else {
        return Err("witness preparation".into());
    };
    let journal = *native.public_admission()?.journal().as_bytes();
    let target = EnrollmentRequest {
        preparation: "RequiresWitnessEnrollment".into(),
        subject: genesis.subject().to_bytes(),
        head: genesis.image_digest(),
    };
    let trust = AccountRootTrust {
        schema: "qperiapt-witness-account-root-trust/1".into(),
        operation: [86; 32],
        freeze_operation: [87; 32],
        previous_root: root.public_key.clone(),
        successor: EnrollmentTrust {
            schema: "qperiapt-witness-enrollment-trust/1".into(),
            account: target_root.clone(),
            device: next.device,
            generation: next.generation,
            journal,
            genesis_head: target.head,
            certificate: issued.certificate.clone(),
            policy: input.clone(),
        },
    };
    let plan = witness.plan_account_root_replacement(&trust, &target, now()?)?;
    let approval = CutoverRequest {
        preparation: prepared.operation,
        enrollment: next.operation,
        roster: issued.checkpoint,
        journal,
        genesis_head: target.head,
        policy: input,
        plan,
        target,
    };
    let route = "/api/enrollment/root-cutover/approve";
    let mut bob = Client::default();
    let _bob_auth = bob.register(&server, "bob").await?;
    for origin in [None, Some("http://untrusted.example")] {
        alice
            .request(
                &server,
                route,
                Some(serde_json::to_string(&approval)?),
                origin,
            )
            .await?
            .checked(400)?;
    }
    Client::default()
        .post(&server, route, &approval)
        .await?
        .checked(401)?;
    // Bob has no original root association; he cannot retain Alice's operation.
    bob.post(&server, route, &approval).await?.checked(409)?;
    assert!(alice
        .disconnect_before_body(&server, route, &approval)
        .await?
        .checked(200)?
        .body
        .is_empty());
    server.close().await?;
    let server = Server::with_family(&path, address, false, family).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let operation = json!({"operation":trust.operation});
    let retained: Cutover = alice
        .post(&server, "/api/enrollment/root-cutover/resume", &operation)
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(retained.status, CutoverStatus::AwaitingOutcome);
    assert_eq!(
        alice
            .post(&server, route, &approval)
            .await?
            .checked(200)?
            .json::<Cutover>()?,
        retained
    );
    assert!(
        alice
            .get(&server, "/api/enrollment/root")
            .await?
            .checked(200)?
            .json::<RootInfo>()?
            .suspended
    );
    alice
        .post(
            &server,
            "/api/enrollment/invite",
            json!({"request_id":vec![88u8;32]}),
        )
        .await?
        .checked(409)?;
    let frozen = witness.freeze_account_root(&approval.plan)?;
    let decision = witness.bind_account_root_replacement(
        &trust,
        &approval.target,
        &approval.plan,
        &frozen,
        now()?,
    )?;
    let AccountRootOutcome::Committed { receipt, .. } = witness.commit_account_root_replacement(
        &trust,
        &approval.target,
        &approval.plan,
        &frozen,
        &decision,
        now()?,
    )?
    else {
        return Err("witness committed".into());
    };
    let retirement = Retirement { decision, receipt };
    let commit = json!({"operation":trust.operation,"proof":retirement});
    let close = json!({"operation":trust.operation,"receipt":URL_SAFE_NO_PAD.encode([0u8;16])});
    for (route, body) in [
        ("/api/enrollment/root-cutover/commit", commit.clone()),
        ("/api/enrollment/root-cutover/close", close.clone()),
        ("/api/enrollment/root-cutover/resume", operation.clone()),
        ("/api/enrollment/root-cutover/status", operation.clone()),
        (
            "/api/enrollment/root/retired",
            json!({"revision":root.revision}),
        ),
    ] {
        Client::default()
            .post(&server, route, &body)
            .await?
            .checked(401)?;
        alice
            .request(
                &server,
                route,
                Some(serde_json::to_string(&body)?),
                Some("http://untrusted.example"),
            )
            .await?
            .checked(400)?;
    }
    alice
        .post(&server, "/api/enrollment/root-cutover/close", close)
        .await?
        .checked(400)?;
    assert!(alice
        .disconnect_before_body(&server, "/api/enrollment/root-cutover/commit", &commit)
        .await?
        .checked(200)?
        .body
        .is_empty());
    server.close().await?;
    let server = Server::with_family(&path, address, false, family).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let current: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(current, target_root);
    let result: Cutover = alice
        .post(&server, "/api/enrollment/root-cutover/status", &operation)
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(
        result.status,
        CutoverStatus::Committed {
            successor: current.clone()
        }
    );
    assert_eq!(
        alice
            .post(&server, "/api/enrollment/root-cutover/commit", commit)
            .await?
            .checked(200)?
            .json::<Cutover>()?,
        result
    );
    assert_eq!(
        alice
            .post(
                &server,
                "/api/enrollment/root/retired",
                json!({"revision":root.revision})
            )
            .await?
            .checked(200)?
            .json::<RootInfo>()?,
        RootInfo {
            suspended: true,
            ..root
        }
    );
    assert_eq!(
        native.accept(
            &issued.certificate,
            &issued.roster,
            &account_pin,
            &policy,
            now()?
        )?,
        installation
    );
    let sdk::InstallationPreparation::RequiresEnrollment(reopened) =
        native.prepare(&policy, now()?)?
    else {
        return Err("original witness preparation".into());
    };
    assert_eq!(reopened.subject().to_bytes(), genesis.subject().to_bytes());
    assert_eq!(reopened.image_digest(), genesis.image_digest());
    native.close();
    assert_eq!(issue(&mut alice, &server, &old).await?, old_result);
    assert_eq!(issue(&mut alice, &server, &next).await?, response);
    assert_eq!(
        invitation(&mut alice, &server, 89).await?.root,
        current.public_key
    );
    server.close().await?;
    Ok(())
}
