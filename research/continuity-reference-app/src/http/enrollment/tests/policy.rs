// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated HTTP issuance, original response loss and SDK policy adoption.
use super::*;
use q_periapt_continuity_reference_app::{
    native_device::{NativeDevice, PolicyRecoveryInputs},
    policy_approval::{
        IssuedPolicyApproval, PolicyApprovalRequest, PolicyInput, MAX_POLICY_APPROVAL_REQUEST,
    },
    policy_publisher::{Anchor, BootstrapMode, Publisher, RenewalRequest, Request},
    store::Store,
};
use std::{fs, os::unix::fs::DirBuilderExt};

#[tokio::test]
async fn http_account_and_policy_issuers_recover_original_approval_and_adopt_without_reenrollment(
) -> Result {
    let path = directory()?.keep().canonicalize()?;
    eprintln!("Account policy HTTP private fixture: {}", path.display());
    let mut publisher = Publisher::provision(
        &path.join("publisher.redb"),
        [70; 32],
        crate::test_support::sdk_input()?,
    )?;
    let family = publisher.prepare()?.family;
    let at = now()?;
    publisher.issue(
        [71; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: at,
            valid_until: at + 3600,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        at,
    )?;
    publisher.issue(
        [72; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: at,
            valid_until: at + 7200,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        at,
    )?;
    let (pins, materials) = publisher.export([71; 32])?;
    let (policy, _) = pins.verify(&materials, family, now()?)?;
    let original_policy = pins.verify_historical(&materials, family)?.0;
    let server = Server::with_family(&path, "127.0.0.1:0".parse()?, true, family).await?;
    let mut alice = Client::default();
    let mut auth = alice.register(&server, "alice").await?;
    alice
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?;
    let invitation = invitation(&mut alice, &server, 1).await?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path.join("device"))?;
    drop(sdk::JournalKey::provision(&path.join("wrap.key"))?);
    let mut native = NativeDevice::begin(
        &path.join("device"),
        &path.join("wrap.key"),
        invitation.clone(),
        now()?,
    )?;
    approve(&mut alice, &server, &invitation, &native.request(now()?)?).await?;
    let first = issue(&mut alice, &server, &invitation).await?;
    let current: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    native.accept(&serde_json::from_slice(&first)?, &current, &policy, now()?)?;
    native.prepare(&current, &policy, now()?)?;
    native
        .activate(&current, &policy, None, None, now()?)?
        .close();
    let mut native = NativeDevice::open(
        &path.join("device"),
        &path.join("wrap.key"),
        invitation.clone(),
    )?;
    let retained = native.policy_renewal_request(
        sdk::PolicyRenewalId::from_trusted_state([73; 32])?,
        &original_policy,
    )?;
    native.close();
    let keys = (
        fs::read(path.join("device/device.key"))?,
        fs::read(path.join("wrap.key"))?,
    );
    let original = PolicyInput { pins, materials };
    let (pins, materials) = publisher.export([72; 32])?;
    let request = PolicyApprovalRequest {
        retained,
        original_extension: None,
        current_extension: None,
        original: original.clone(),
        previous: original,
        target: PolicyInput { pins, materials },
    };
    let route = "/api/enrollment/policy-approval";
    let status_route = "/api/enrollment/policy-approval/status";
    let cancel_route = "/api/enrollment/policy-approval/cancel";
    alice.post(&server, route, &request).await?.checked(409)?;
    let address = server.address;
    let origin = server.origin.clone();
    server.close().await?;
    let mut store = Store::open(&path.join("accounts.redb"), &origin)?;
    store.enable_enrollment_extensions()?;
    store.enable_credential_grants()?;
    store.enable_policy_approvals()?;
    drop(store);
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let json = serde_json::to_string(&request)?;
    let padded = format!("{}{}", " ".repeat(70 * 1024), json);
    assert!(padded.len() < MAX_POLICY_APPROVAL_REQUEST);
    assert_eq!(
        alice
            .request(
                &server,
                status_route,
                Some(padded.clone()),
                Some(&server.origin)
            )
            .await?
            .checked(200)?
            .json::<serde_json::Value>()?,
        json!({"state":"Absent"})
    );
    alice
        .request(
            &server,
            "/api/enrollment/credential-grant/status",
            Some(padded),
            Some(&server.origin),
        )
        .await
        .map_err(|e| format!("Ordinary-route oversized request: {e}"))?
        .checked(413)?;
    alice
        .request(
            &server,
            route,
            Some(format!(
                "{}{}",
                " ".repeat(MAX_POLICY_APPROVAL_REQUEST),
                json
            )),
            Some(&server.origin),
        )
        .await
        .map_err(|e| format!("Policy-route oversized request: {e}"))?
        .checked(413)?;
    let mut anonymous = Client::default();
    let mut bob = Client::default();
    let _bob_auth = bob.register(&server, "bob").await?;
    for endpoint in [route, status_route, cancel_route] {
        anonymous
            .post(&server, endpoint, &request)
            .await?
            .checked(401)?;
        bob.post(&server, endpoint, &request).await?.checked(401)?;
        alice
            .request(
                &server,
                endpoint,
                Some(json.clone()),
                Some("http://untrusted.invalid"),
            )
            .await?
            .checked(400)?;
    }
    let mut malformed = serde_json::to_value(&request)?;
    malformed
        .as_object_mut()
        .ok_or("request")?
        .remove("original_extension");
    alice.post(&server, route, &malformed).await?.checked(422)?;
    let lost = alice
        .disconnect_before_body(&server, route, &request)
        .await?
        .checked(200)?;
    assert!(lost.body.is_empty());
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.post(&server, route, &request).await?.checked(401)?;
    alice.login(&server, "alice", &mut auth).await?;
    let recovered = alice
        .post(&server, route, &request)
        .await?
        .checked(200)?
        .body;
    let result: IssuedPolicyApproval = serde_json::from_slice(&recovered)?;
    let observed: serde_json::Value = alice
        .post(&server, status_route, &request)
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(observed["state"], "Issued");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(observed["response"].as_str().ok_or("response")?)?,
        recovered
    );
    assert_eq!(
        alice
            .post(&server, route, &request)
            .await?
            .checked(200)?
            .body,
        recovered
    );
    publisher.enable_renewals()?;
    let policy_approval = publisher.approve_renewal(
        &RenewalRequest {
            retained: request.retained.clone(),
            original_publication: [71; 32],
            previous_publication: [71; 32],
            target_publication: [72; 32],
        },
        &current,
    )?;
    assert_eq!(policy_approval.statement, result.statement);
    let target = request
        .target
        .pins
        .verify(&request.target.materials, family, now()?)?
        .0;
    let mut native = NativeDevice::open(
        &path.join("device"),
        &path.join("wrap.key"),
        invitation.clone(),
    )?;
    assert!(matches!(native.adopt_policy(&PolicyRecoveryInputs {
        request: &request.retained, account_approval: &result.approval,
        policy_approval: &policy_approval.approval, current: &current,
        original: &original_policy, previous: &original_policy, target: &target,
    }, now()?)?, sdk::PolicyRenewalStatus::Committed { statement, .. } if statement == result.statement));
    native.close();
    assert_eq!(
        (
            fs::read(path.join("device/device.key"))?,
            fs::read(path.join("wrap.key"))?
        ),
        keys
    );
    assert_eq!(
        alice
            .get(&server, "/api/enrollment/root")
            .await?
            .checked(200)?
            .json::<RootInfo>()?,
        current
    );
    assert_eq!(issue(&mut alice, &server, &invitation).await?, first);
    alice
        .post(&server, cancel_route, &request)
        .await?
        .checked(409)?;
    let mut next = request.clone();
    next.retained.scope.operation = [74; 32];
    alice
        .post(&server, cancel_route, &next)
        .await?
        .checked(204)?;
    alice.post(&server, route, &next).await?.checked(409)?;
    assert_eq!(
        alice
            .post(&server, status_route, &next)
            .await?
            .checked(200)?
            .json::<serde_json::Value>()?,
        json!({"state":"Closed"})
    );
    server.close().await
}
