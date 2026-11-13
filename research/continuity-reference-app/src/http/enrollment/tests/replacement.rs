// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_continuity_reference_app::store::Store;

#[tokio::test]
async fn http_replacement_requires_account_origin_and_recovers_lost_invitation_and_issuance(
) -> Result {
    let dir = directory()?;
    let path = dir.path().canonicalize()?;
    let server = Server::start(&path, "127.0.0.1:0".parse()?, true).await?;
    let mut alice = Client::default();
    let mut auth = alice.register(&server, "alice").await?;
    alice
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?;
    let old = invitation(&mut alice, &server, 1).await?;
    let (_, proof) = device_request(&path, &old)?;
    approve(&mut alice, &server, &old, &proof).await?;
    let first = issue(&mut alice, &server, &old).await?;
    let issued: IssuedEnrollment = serde_json::from_slice(&first)?;
    let request =
        json!({"request_id":([9u8;32]),"enrollment":old.operation,"predecessor":issued.checkpoint});
    let route = "/api/enrollment/replace-device";
    alice
        .post(&server, route, request.clone())
        .await?
        .checked(409)?;
    let address = server.address;
    let origin = server.origin.clone();
    server.close().await?;
    let mut store = Store::open(&path.join("accounts.redb"), &origin)?;
    store.enable_enrollment_extensions()?;
    store.enable_credential_grants()?;
    store.enable_policy_approvals()?;
    store.enable_device_replacements()?;
    drop(store);
    let server = Server::start(&path, address, false).await?;
    alice
        .post(&server, route, request.clone())
        .await?
        .checked(401)?;
    alice.login(&server, "alice", &mut auth).await?;
    Client::default()
        .post(&server, route, request.clone())
        .await?
        .checked(401)?;
    let mut bob = Client::default();
    let _auth = bob.register(&server, "bob").await?;
    bob.post(&server, route, request.clone())
        .await?
        .checked(401)?;
    for origin in [None, Some("http://untrusted.example")] {
        let rejected = alice
            .request(
                &server,
                route,
                Some(serde_json::to_string(&request)?),
                origin,
            )
            .await?
            .checked(400)?;
        assert!(std::str::from_utf8(&rejected.body)?.contains("Expected same-origin request"));
    }
    for field in ["enrollment", "predecessor", "request_id"] {
        let mut missing = request.clone();
        missing.as_object_mut().ok_or("object")?.remove(field);
        alice.post(&server, route, missing).await?.checked(422)?;
    }
    let lost = alice
        .disconnect_before_body(&server, route, request.clone())
        .await?
        .checked(200)?;
    assert!(lost.body.is_empty());
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let recovered = alice
        .post(&server, route, request.clone())
        .await?
        .checked(200)?
        .body;
    assert_eq!(
        alice
            .post(&server, route, request.clone())
            .await?
            .checked(200)?
            .body,
        recovered
    );
    let next: Invitation = serde_json::from_slice(&recovered)?;
    assert_eq!(next.device, old.device);
    assert_eq!(next.generation, 2);
    let (_, new_proof) = device_request(&path, &next)?;
    approve(&mut alice, &server, &next, &new_proof).await?;
    alice
        .disconnect_before_body(
            &server,
            "/api/enrollment/issue",
            json!({"operation":next.operation}),
        )
        .await?
        .checked(200)?;
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let response = issue(&mut alice, &server, &next).await?;
    let next_receipt: IssuedEnrollment = serde_json::from_slice(&response)?;
    let root: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    let pin = sdk::AccountPin::new(
        root.account,
        sdk::PublicKey::decode(&root.public_key)?,
        next_receipt.checkpoint.as_sdk()?,
        root.family,
    )?;
    pin.verify_device(&next_receipt.certificate, &next_receipt.roster, now()?)?;
    assert!(pin
        .verify_device(&issued.certificate, &next_receipt.roster, now()?)
        .is_err());
    assert_eq!(issue(&mut alice, &server, &next).await?, response);
    assert_eq!(issue(&mut alice, &server, &old).await?, first);
    server.close().await?;
    Ok(())
}
