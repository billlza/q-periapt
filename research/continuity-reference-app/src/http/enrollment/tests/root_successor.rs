// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real HTTP/software Passkey flow; lost bodies retain the original candidate and device.
use super::*;
use q_periapt_continuity_reference_app::{
    root_preparation::{Preparation, Status, SuccessorObservation},
    store::Store,
};

#[tokio::test]
async fn http_candidate_root_enrollment_preserves_account_and_recovers_original_lost_results(
) -> Result {
    let dir = directory()?;
    let path = dir.path().canonicalize()?;
    let server = Server::start(&path, "127.0.0.1:0".parse()?, true).await?;
    let mut alice = Client::default();
    let mut auth = alice.register(&server, "alice").await?;
    let root: RootInfo = alice
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?
        .json()?;
    let prepare = json!({"request_id":vec![71u8;32],"predecessor":{"revision":root.revision,"account":root.account}});
    let prepare_route = "/api/enrollment/root-candidate/prepare";
    alice
        .post(&server, prepare_route, prepare.clone())
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
    store.enable_root_preparations()?;
    store.enable_root_successors()?;
    drop(store);
    let server = Server::start(&path, address, false).await?;
    alice
        .post(&server, prepare_route, prepare.clone())
        .await?
        .checked(401)?;
    alice.login(&server, "alice", &mut auth).await?;
    for origin in [None, Some("http://untrusted.example")] {
        alice
            .request(
                &server,
                prepare_route,
                Some(serde_json::to_string(&prepare)?),
                origin,
            )
            .await?
            .checked(400)?;
    }
    let lost = alice
        .disconnect_before_body(&server, prepare_route, prepare.clone())
        .await?
        .checked(200)?;
    assert!(lost.body.is_empty());
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let preparation: Preparation = alice
        .post(&server, prepare_route, prepare.clone())
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(
        alice
            .post(&server, prepare_route, prepare.clone())
            .await?
            .checked(200)?
            .json::<Preparation>()?,
        preparation
    );
    let Status::Prepared { candidate } = &preparation.status else {
        return Err("candidate not prepared".into());
    };
    assert_ne!(candidate.account, root.account);
    assert_ne!(candidate.public_key, root.public_key);
    let op = json!({"operation":preparation.operation});
    assert!(alice
        .post(
            &server,
            "/api/enrollment/root-candidate/successor",
            op.clone()
        )
        .await?
        .checked(200)?
        .json::<SuccessorObservation>()?
        .enrollment
        .is_none());
    let invite = json!({"preparation":preparation.operation,"request_id":vec![72u8;32]});
    let invite_route = "/api/enrollment/root-candidate/invite";
    let mut bob = Client::default();
    let _bob_auth = bob.register(&server, "bob").await?;
    for (route, body) in [
        ("/api/enrollment/root-candidate/status", op.clone()),
        ("/api/enrollment/root-candidate/close", op.clone()),
        ("/api/enrollment/root-candidate/successor", op.clone()),
        (invite_route, invite.clone()),
    ] {
        Client::default()
            .post(&server, route, body.clone())
            .await?
            .checked(401)?;
        bob.post(&server, route, body).await?.checked(401)?;
    }
    for origin in [None, Some("http://untrusted.example")] {
        alice
            .request(
                &server,
                invite_route,
                Some(serde_json::to_string(&invite)?),
                origin,
            )
            .await?
            .checked(400)?;
    }
    for field in ["preparation", "request_id"] {
        let mut missing = invite.clone();
        missing.as_object_mut().ok_or("object")?.remove(field);
        alice
            .post(&server, invite_route, missing)
            .await?
            .checked(422)?;
    }
    assert!(alice
        .disconnect_before_body(&server, invite_route, invite.clone())
        .await?
        .checked(200)?
        .body
        .is_empty());
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let next: Invitation = alice
        .post(&server, invite_route, invite.clone())
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(
        alice
            .post(
                &server,
                "/api/enrollment/root-candidate/successor",
                op.clone()
            )
            .await?
            .checked(200)?
            .json::<SuccessorObservation>()?
            .enrollment,
        Some(next.clone())
    );
    assert_eq!(next.root, candidate.public_key);
    assert_eq!(next.root_revision, candidate.revision);
    assert_eq!(
        alice
            .post(&server, invite_route, invite.clone())
            .await?
            .checked(200)?
            .json::<Invitation>()?,
        next
    );
    let (_, proof) = device_request(&path, &next)?;
    approve(&mut alice, &server, &next, &proof).await?;
    assert!(alice
        .disconnect_before_body(
            &server,
            "/api/enrollment/issue",
            json!({"operation":next.operation})
        )
        .await?
        .checked(200)?
        .body
        .is_empty());
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    alice.login(&server, "alice", &mut auth).await?;
    let response = issue(&mut alice, &server, &next).await?;
    let issued: IssuedEnrollment = serde_json::from_slice(&response)?;
    sdk::AccountPin::new(
        candidate.account,
        sdk::PublicKey::decode(&candidate.public_key)?,
        issued.checkpoint.as_sdk()?,
        candidate.family,
    )?
    .verify_device(&issued.certificate, &issued.roster, now()?)?;
    assert_eq!(
        alice
            .get(&server, "/api/enrollment/root")
            .await?
            .checked(200)?
            .json::<RootInfo>()?,
        root
    );
    assert_eq!(issue(&mut alice, &server, &next).await?, response);
    let closed: Preparation = alice
        .post(&server, "/api/enrollment/root-candidate/close", op.clone())
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(closed.status, Status::Closed);
    assert_eq!(
        alice
            .post(&server, "/api/enrollment/root-candidate/status", op)
            .await?
            .checked(200)?
            .json::<Preparation>()?,
        closed
    );
    alice
        .post(&server, prepare_route, prepare)
        .await?
        .checked(409)?;
    assert_eq!(issue(&mut alice, &server, &next).await?, response);
    server.close().await?;
    Ok(())
}
