// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_continuity_reference_app::{
    credential_grant::{CredentialGrantRequest, IssuedCredentialGrant},
    enrollment::{CredentialExtensionRequest, IssuedCredentialExtension},
    native_device::NativeDevice,
    policy_publisher::{Anchor, BootstrapMode, Publisher, Request},
    store::Store,
};
use std::{fs, os::unix::fs::DirBuilderExt};

#[tokio::test]
async fn http_retained_grant_lost_response_reopens_exact_original_decision() -> Result {
    let path = directory()?.keep().canonicalize()?;
    eprintln!("Retained grant HTTP private fixture: {}", path.display());
    let mut publisher = Publisher::provision(
        &path.join("publisher.redb"),
        [50; 32],
        crate::test_support::sdk_input()?,
    )?;
    let family = publisher.prepare()?.family;
    publisher.issue(
        [51; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: now()?,
            valid_until: now()? + 7200,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        now()?,
    )?;
    let (pins, materials) = publisher.export([51; 32])?;
    let (policy, _) = pins.verify(&materials, family, now()?)?;
    let (historical, _) = pins.verify_historical(&materials, family)?;
    let server = Server::with_family(&path, "127.0.0.1:0".parse()?, true, family).await?;
    let mut alice = Client::default();
    let mut authenticator = alice.register(&server, "alice").await?;
    alice
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?;
    let original = invitation(&mut alice, &server, 1).await?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path.join("device"))?;
    drop(sdk::JournalKey::provision(&path.join("wrap.key"))?);
    let mut device = NativeDevice::begin(
        &path.join("device"),
        &path.join("wrap.key"),
        original.clone(),
        now()?,
    )?;
    approve(&mut alice, &server, &original, &device.request(now()?)?).await?;
    let first = issue(&mut alice, &server, &original).await?;
    let current: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    device.accept(&serde_json::from_slice(&first)?, &current, &policy, now()?)?;
    device.prepare(&current, &policy, now()?)?;
    device
        .activate(&current, &policy, None, None, now()?)?
        .close();
    let mut device = NativeDevice::open(
        &path.join("device"),
        &path.join("wrap.key"),
        original.clone(),
    )?;
    let retained = device.credential_renewal_request([52; 32], &historical, None, None)?;
    device.close();
    let address = server.address;
    let origin = server.origin.clone();
    server.close().await?;
    let mut store = Store::open(&path.join("accounts.redb"), &origin)?;
    store.enable_enrollment_extensions()?;
    store.enable_credential_grants()?;
    drop(store);
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut authenticator).await?;
    let extension = CredentialExtensionRequest {
        request_id: [53; 32],
        enrollment: original.operation,
        previous_extension: None,
        predecessor: current.roster.ok_or("roster")?.checkpoint,
        valid_until: original.valid_until + 3600,
    };
    let next: IssuedCredentialExtension = alice
        .post(&server, "/api/enrollment/extend-credential", &extension)
        .await?
        .checked(200)?
        .json()?;
    let request = CredentialGrantRequest {
        retained,
        original_extension: None,
        previous_extension: None,
        successor_extension: extension.request_id,
        target_checkpoint: next.checkpoint,
    };
    let route = "/api/enrollment/credential-grant";
    let status_route = "/api/enrollment/credential-grant/status";
    assert_eq!(
        alice
            .post(&server, status_route, &request)
            .await?
            .checked(200)?
            .json::<serde_json::Value>()?,
        json!({"state":"Absent"})
    );
    let mut anonymous = Client::default();
    anonymous
        .post(&server, route, &request)
        .await?
        .checked(401)?;
    let mut bob = Client::default();
    let _auth = bob.register(&server, "bob").await?;
    bob.post(&server, route, &request).await?.checked(401)?;
    alice
        .request(
            &server,
            route,
            Some(serde_json::to_string(&request)?),
            Some("http://untrusted.invalid"),
        )
        .await?
        .checked(400)?;
    let mut malformed = serde_json::to_value(&request)?;
    malformed
        .as_object_mut()
        .ok_or("object")?
        .remove("previous_extension");
    alice.post(&server, route, malformed).await?.checked(422)?;
    let lost = alice
        .disconnect_before_body(&server, route, &request)
        .await?
        .checked(200)?;
    assert!(lost.body.is_empty());
    let current: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(
        current.roster.as_ref().ok_or("roster")?.checkpoint,
        next.checkpoint
    );
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.post(&server, route, &request).await?.checked(401)?;
    alice.login(&server, "alice", &mut authenticator).await?;
    let recovered = alice
        .post(&server, route, &request)
        .await?
        .checked(200)?
        .body;
    let issued: IssuedCredentialGrant = serde_json::from_slice(&recovered)?;
    let status: serde_json::Value = alice
        .post(&server, status_route, &request)
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(status["state"], "Issued");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(status["response"].as_str().ok_or("status response")?)?,
        recovered
    );
    let pin = sdk::AccountPin::new(
        current.account,
        sdk::PublicKey::decode(&current.public_key)?,
        next.checkpoint.as_sdk()?,
        current.family,
    )?;
    let grant = sdk::VerifiedCredentialRenewal::verify(
        &issued.grant,
        &pin,
        request.retained.original_policy.digest,
        now()?,
    )?;
    assert_eq!(
        grant.original_storage_owner(),
        request.retained.original_owner
    );
    assert_eq!(grant.statement_digest(), issued.statement);
    assert_eq!(
        alice
            .post(&server, route, &request)
            .await?
            .checked(200)?
            .body,
        recovered
    );
    let mut changed = request.clone();
    changed.retained.journal[0] ^= 1;
    alice.post(&server, route, &changed).await?.checked(409)?;
    alice
        .post(&server, "/api/enrollment/credential-grant/cancel", &request)
        .await?
        .checked(409)?;
    assert_eq!(issue(&mut alice, &server, &original).await?, first);
    let mut cancelled = request.clone();
    cancelled.retained.operation = [54; 32];
    alice
        .post(
            &server,
            "/api/enrollment/credential-grant/cancel",
            &cancelled,
        )
        .await?
        .checked(204)?;
    assert_eq!(
        alice
            .post(&server, status_route, &cancelled)
            .await?
            .checked(200)?
            .json::<serde_json::Value>()?,
        json!({"state":"Closed"})
    );
    alice.post(&server, route, &cancelled).await?.checked(409)?;
    assert_eq!(
        alice
            .get(&server, "/api/enrollment/root")
            .await?
            .checked(200)?
            .json::<RootInfo>()?,
        current
    );
    server.close().await?;
    Ok(())
}
