// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_continuity_reference_app::{enrollment::IssuedCredentialExtension, store::Store};

#[tokio::test]
async fn http_credential_extension_requires_explicit_approval_and_recovers_after_disconnect(
) -> Result {
    let dir = directory()?;
    let path = dir.path().canonicalize()?;
    let server = Server::start(&path, "127.0.0.1:0".parse()?, true).await?;
    let mut alice = Client::default();
    let mut authenticator = alice.register(&server, "alice").await?;
    alice
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?;
    let original = invitation(&mut alice, &server, 1).await?;
    let (_, proof) = device_request(&path, &original)?;
    approve(&mut alice, &server, &original, &proof).await?;
    let first = issue(&mut alice, &server, &original).await?;
    let issued: IssuedEnrollment = serde_json::from_slice(&first)?;
    let request = json!({"request_id":([9u8;32]), "enrollment":original.operation, "previous_extension":null,
                         "predecessor":issued.checkpoint, "valid_until":original.valid_until+3600});
    let route = "/api/enrollment/extend-credential";
    alice
        .post(&server, route, request.clone())
        .await?
        .checked(409)?;
    let address = server.address;
    let origin = server.origin.clone();
    server.close().await?;
    let mut store = Store::open(&path.join("accounts.redb"), &origin)?;
    store.enable_enrollment_extensions()?;
    drop(store);
    let server = Server::start(&path, address, false).await?;
    alice
        .post(&server, route, request.clone())
        .await?
        .checked(401)?;
    alice.login(&server, "alice", &mut authenticator).await?;
    let mut anonymous = Client::default();
    anonymous
        .post(&server, route, request.clone())
        .await?
        .checked(401)?;
    let mut bob = Client::default();
    let _auth = bob.register(&server, "bob").await?;
    bob.post(&server, route, request.clone())
        .await?
        .checked(401)?;
    let mut missing = request.clone();
    missing
        .as_object_mut()
        .ok_or("object")?
        .remove("previous_extension");
    alice.post(&server, route, missing).await?.checked(422)?;
    let lost = alice
        .disconnect_before_body(&server, route, request.clone())
        .await?
        .checked(200)?;
    assert!(lost.body.is_empty());
    let current: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(
        current.roster.as_ref().ok_or("roster")?.checkpoint.version,
        2
    );
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut authenticator).await?;
    let recovered = alice
        .post(&server, route, request.clone())
        .await?
        .checked(200)?
        .body;
    let next: IssuedCredentialExtension = serde_json::from_slice(&recovered)?;
    let roster = current.roster.as_ref().ok_or("roster")?;
    sdk::AccountPin::new(
        current.account,
        sdk::PublicKey::decode(&current.public_key)?,
        roster.checkpoint.as_sdk()?,
        current.family,
    )?
    .verify_device(&next.certificate, &next.roster, now()?)?;
    assert_eq!(next.checkpoint, roster.checkpoint);
    assert_eq!(
        alice
            .post(&server, route, request.clone())
            .await?
            .checked(200)?
            .body,
        recovered
    );
    assert_eq!(issue(&mut alice, &server, &original).await?, first);
    let mut changed = request.clone();
    changed["valid_until"] = (original.valid_until + 7200).into();
    alice.post(&server, route, changed).await?.checked(409)?;
    let unchanged: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(unchanged, current);
    server.close().await?;
    Ok(())
}
