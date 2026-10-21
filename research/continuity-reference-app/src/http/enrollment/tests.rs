// SPDX-License-Identifier: Apache-2.0 OR MIT
mod extension;
mod grant;
mod policy;
mod replacement;
mod root_successor;
mod support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::enrollment::{
    EnrollmentStatus, Invitation, IssuedEnrollment, RootInfo,
};
use serde_json::json;
use support::*;

async fn invitation(client: &mut Client, server: &Server, id: u8) -> Result<Invitation> {
    client
        .post(
            server,
            "/api/enrollment/invite",
            json!({"request_id": ([id; 32])}),
        )
        .await?
        .checked(200)?
        .json()
}
async fn approve(
    client: &mut Client,
    server: &Server,
    invitation: &Invitation,
    proof: &[u8],
) -> Result {
    client
        .post(
            server,
            "/api/enrollment/approve",
            json!({"operation": invitation.operation, "request": URL_SAFE_NO_PAD.encode(proof)}),
        )
        .await?
        .checked(204)?;
    Ok(())
}
async fn issue(client: &mut Client, server: &Server, invitation: &Invitation) -> Result<Vec<u8>> {
    Ok(client
        .post(
            server,
            "/api/enrollment/issue",
            json!({"operation": invitation.operation}),
        )
        .await?
        .checked(200)?
        .body)
}
async fn status(
    client: &mut Client,
    server: &Server,
    invitation: &Invitation,
) -> Result<EnrollmentStatus> {
    client
        .post(
            server,
            "/api/enrollment/status",
            json!({"operation": invitation.operation}),
        )
        .await?
        .checked(200)?
        .json()
}

#[tokio::test]
async fn http_enrollment_requires_host_auth_and_recovers_exact_response_after_restart() -> Result {
    let dir = directory()?;
    let path = dir.path().canonicalize()?;
    let server = Server::start(&path, "127.0.0.1:0".parse()?, true).await?;
    let mut alice = Client::default();
    // The real router must deliver every module referenced by the browser entry.
    for (url, source) in [
        (
            "/transport.mjs",
            include_bytes!("../../../web/transport.mjs").as_slice(),
        ),
        (
            "/enrollment-records.mjs",
            include_bytes!("../../../web/enrollment-records.mjs").as_slice(),
        ),
        (
            "/enrollment-model.mjs",
            include_bytes!("../../../web/enrollment-model.mjs").as_slice(),
        ),
        (
            "/enrollment.mjs",
            include_bytes!("../../../web/enrollment.mjs").as_slice(),
        ),
        (
            "/extension-model.mjs",
            include_bytes!("../../../web/extension-model.mjs").as_slice(),
        ),
        (
            "/record-validation.mjs",
            include_bytes!("../../../web/record-validation.mjs").as_slice(),
        ),
        (
            "/grant-records.mjs",
            include_bytes!("../../../web/grant-records.mjs").as_slice(),
        ),
        (
            "/grant-model.mjs",
            include_bytes!("../../../web/grant-model.mjs").as_slice(),
        ),
        (
            "/grant.mjs",
            include_bytes!("../../../web/grant.mjs").as_slice(),
        ),
        (
            "/extension.mjs",
            include_bytes!("../../../web/extension.mjs").as_slice(),
        ),
    ] {
        let reply = alice.get(&server, url).await?.checked(200)?;
        assert_eq!(
            reply.content_type.as_deref(),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(reply.body, source);
    }
    let mut authenticator = alice.register(&server, "alice").await?;
    let root: RootInfo = alice
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?
        .json()?;
    let original = invitation(&mut alice, &server, 1).await?;
    assert_eq!(invitation(&mut alice, &server, 1).await?, original);
    let (paths, proof) = device_request(&path, &original)?;
    let body = json!({"operation": original.operation, "request": URL_SAFE_NO_PAD.encode(&proof)});
    let operation = json!({"operation": original.operation});
    let mut anonymous = Client::default();
    // A genuine dual-signed device proof is insufficient for account authorization.
    for (endpoint, value) in [
        ("root/prepare", json!({})),
        ("root/suspend", json!({})),
        ("invite", json!({"request_id": ([2u8; 32])})),
        ("approve", body.clone()),
        ("issue", operation.clone()),
        ("status", operation.clone()),
        ("cancel", operation.clone()),
        (
            "reapprove",
            json!({"previous": original.operation, "request_id": ([3u8; 32]), "predecessor": null, "request": URL_SAFE_NO_PAD.encode(&proof)}),
        ),
    ] {
        anonymous
            .post(&server, &format!("/api/enrollment/{endpoint}"), value)
            .await?
            .checked(401)?;
    }
    anonymous
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(401)?;
    let mut bob = Client::default();
    let _bob_auth = bob.register(&server, "bob").await?;
    for (endpoint, value) in [
        ("approve", body.clone()),
        ("issue", operation.clone()),
        ("status", operation.clone()),
        ("cancel", operation.clone()),
    ] {
        bob.post(&server, &format!("/api/enrollment/{endpoint}"), value)
            .await?
            .checked(401)?;
    }
    // Failed cross-account and anonymous requests leave the original invitation intact.
    assert!(matches!(
        status(&mut alice, &server, &original).await?,
        EnrollmentStatus::Invited { .. }
    ));
    approve(&mut alice, &server, &original, &proof).await?;
    approve(&mut alice, &server, &original, &proof).await?;
    let lost = alice
        .disconnect_before_body(&server, "/api/enrollment/issue", operation.clone())
        .await?
        .checked(200)?;
    assert!(lost.body.is_empty());
    let first = match status(&mut alice, &server, &original).await? {
        EnrollmentStatus::Issued { response, .. } => response,
        _ => return Err("committed response was not recovered after TCP disconnect".into()),
    };
    let receipt: IssuedEnrollment = serde_json::from_slice(&first)?;
    let current: RootInfo = alice
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    let roster = current.roster.as_ref().ok_or("current roster missing")?;
    sdk::AccountPin::new(
        current.account,
        sdk::PublicKey::decode(&root.public_key)?,
        roster.checkpoint.as_sdk()?,
        root.family,
    )?
    .verify_device(&receipt.certificate, &roster.bytes, now()?)?;
    assert_eq!(roster.checkpoint.version, 1);
    let address = server.address;
    server.close().await?;
    let server = Server::start(&path, address, false).await?;
    // Same database and original browser cookie; a restart demands a fresh login.
    alice
        .post(&server, "/api/enrollment/issue", operation.clone())
        .await?
        .checked(401)?;
    alice.login(&server, "alice", &mut authenticator).await?;
    assert_eq!(issue(&mut alice, &server, &original).await?, first);
    match status(&mut alice, &server, &original).await? {
        EnrollmentStatus::Issued { response, current } => {
            assert_eq!(response, first);
            assert_eq!(current.public_key, root.public_key);
            assert_eq!(
                current.roster.ok_or("reopened roster")?.checkpoint.version,
                1
            );
        }
        _ => return Err("original issuance not recovered".into()),
    }
    let mut device = sdk::DeviceEnrollment::open(paths, original.intent()?)?;
    assert_eq!(device.request(now()?)?, proof);
    device.close();
    alice
        .post(&server, "/api/logout", json!({}))
        .await?
        .checked(200)?;
    alice
        .post(&server, "/api/enrollment/issue", operation)
        .await?
        .checked(401)?;
    server.close().await
}

#[tokio::test]
async fn http_reapproval_preserves_original_request_and_separates_history_from_current_roster(
) -> Result {
    let dir = directory()?;
    let path = dir.path().canonicalize()?;
    let server = Server::start(&path, "127.0.0.1:0".parse()?, true).await?;
    let mut client = Client::default();
    let _authenticator = client.register(&server, "alice").await?;
    client
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?;
    let first = invitation(&mut client, &server, 10).await?;
    let second = invitation(&mut client, &server, 11).await?;
    let (_, first_proof) = device_request(&path, &first)?;
    let (second_paths, second_proof) = device_request(&path, &second)?;
    approve(&mut client, &server, &first, &first_proof).await?;
    approve(&mut client, &server, &second, &second_proof).await?;
    let first_response = issue(&mut client, &server, &first).await?;
    client
        .post(
            &server,
            "/api/enrollment/issue",
            json!({"operation":second.operation}),
        )
        .await?
        .checked(409)?;
    let current: RootInfo = client
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json()?;
    let predecessor = current.roster.ok_or("roster")?.checkpoint;
    let reapproval = json!({"previous": second.operation, "request_id": ([12u8; 32]), "predecessor": predecessor, "request": URL_SAFE_NO_PAD.encode(&second_proof)});
    let mut changed = reapproval.clone();
    changed["predecessor"] = serde_json::Value::Null;
    client
        .post(&server, "/api/enrollment/reapprove", changed)
        .await?
        .checked(409)?;
    let mut changed = reapproval.clone();
    changed["request"] = URL_SAFE_NO_PAD.encode(&first_proof).into();
    client
        .post(&server, "/api/enrollment/reapprove", changed)
        .await?
        .checked(409)?;
    let successor: Invitation = client
        .post(&server, "/api/enrollment/reapprove", reapproval.clone())
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(successor.root, second.root);
    assert_eq!(successor.family, second.family);
    assert_eq!(successor.device, second.device);
    assert_eq!(successor.generation, second.generation);
    assert_eq!(successor.valid_from, second.valid_from);
    assert_eq!(successor.valid_until, second.valid_until);
    assert_eq!(
        client
            .post(&server, "/api/enrollment/reapprove", reapproval.clone())
            .await?
            .checked(200)?
            .json::<Invitation>()?,
        successor
    );
    assert!(
        matches!(status(&mut client, &server, &second).await?, EnrollmentStatus::Reapproved { successor: next } if next == successor)
    );
    for action in ["issue", "cancel"] {
        client
            .post(
                &server,
                &format!("/api/enrollment/{action}"),
                json!({"operation": second.operation}),
            )
            .await?
            .checked(409)?;
    }
    let second_response = issue(&mut client, &server, &successor).await?;
    let mut device = sdk::DeviceEnrollment::open(second_paths, successor.intent()?)?;
    assert_eq!(device.request(now()?)?, second_proof);
    device.close();
    match status(&mut client, &server, &first).await? {
        EnrollmentStatus::Issued { response, current } => {
            assert_eq!(response, first_response);
            assert_eq!(current.roster.ok_or("new roster")?.checkpoint.version, 2);
            assert_eq!(
                serde_json::from_slice::<IssuedEnrollment>(&response)?
                    .checkpoint
                    .version,
                1
            );
        }
        _ => return Err("issued status absent".into()),
    }
    let cancelled = invitation(&mut client, &server, 13).await?;
    client
        .post(
            &server,
            "/api/enrollment/cancel",
            json!({"operation": cancelled.operation}),
        )
        .await?
        .checked(204)?;
    assert!(matches!(
        status(&mut client, &server, &cancelled).await?,
        EnrollmentStatus::Closed
    ));
    client
        .post(
            &server,
            "/api/enrollment/issue",
            json!({"operation": cancelled.operation}),
        )
        .await?
        .checked(409)?;
    let pending = invitation(&mut client, &server, 14).await?;
    let (_, pending_proof) = device_request(&path, &pending)?;
    approve(&mut client, &server, &pending, &pending_proof).await?;
    client
        .post(&server, "/api/enrollment/root/suspend", json!({}))
        .await?
        .checked(200)?;
    client
        .post(
            &server,
            "/api/enrollment/issue",
            json!({"operation": pending.operation}),
        )
        .await?
        .checked(409)?;
    assert_eq!(
        issue(&mut client, &server, &successor).await?,
        second_response
    );
    assert_eq!(
        client
            .post(&server, "/api/enrollment/reapprove", reapproval)
            .await?
            .checked(200)?
            .json::<Invitation>()?,
        successor
    );
    assert!(
        matches!(status(&mut client, &server, &successor).await?, EnrollmentStatus::Issued { current, .. } if current.suspended)
    );
    server.close().await
}

#[tokio::test]
async fn http_enrollment_rejects_cross_origin_substitution_and_malformed_or_oversized_bodies(
) -> Result {
    let dir = directory()?;
    let path = dir.path().canonicalize()?;
    let server = Server::start(&path, "127.0.0.1:0".parse()?, true).await?;
    let mut client = Client::default();
    let _authenticator = client.register(&server, "alice").await?;
    client
        .post(&server, "/api/enrollment/root/prepare", json!({}))
        .await?
        .checked(200)?;
    let first = invitation(&mut client, &server, 20).await?;
    let other = invitation(&mut client, &server, 21).await?;
    let (_, proof) = device_request(&path, &first)?;
    let (_, other_proof) = device_request(&path, &other)?;
    let approval = json!({"operation": first.operation, "request": URL_SAFE_NO_PAD.encode(&proof)});
    // Absent is not an explicit decision that the predecessor roster is empty.
    client
        .post(
            &server,
            "/api/enrollment/reapprove",
            json!({
                "previous": first.operation, "request_id": ([22u8; 32]),
                "request": URL_SAFE_NO_PAD.encode(&proof)
            }),
        )
        .await?
        .checked(422)?;
    for origin in [None, Some("null"), Some("https://attacker.example")] {
        client
            .request(
                &server,
                "/api/enrollment/approve",
                Some(serde_json::to_string(&approval)?),
                origin,
            )
            .await?
            .checked(400)?;
    }
    for request in [
        URL_SAFE_NO_PAD.encode(&other_proof),
        "???".into(),
        format!("{}=", URL_SAFE_NO_PAD.encode(&proof)),
        URL_SAFE_NO_PAD.encode([0u8; 8193]),
        String::new(),
    ] {
        client
            .post(
                &server,
                "/api/enrollment/approve",
                json!({"operation":first.operation,"request":request}),
            )
            .await?
            .checked(400)?;
    }
    let mut substituted = approval.clone();
    substituted["account"] = "alice".into();
    client
        .post(&server, "/api/enrollment/approve", substituted)
        .await?
        .checked(422)?;
    client
        .post(
            &server,
            "/api/enrollment/invite",
            json!({"request_id":([0u8;32])}),
        )
        .await?
        .checked(400)?;
    client
        .post(
            &server,
            "/api/enrollment/status",
            json!({"operation":[1,2]}),
        )
        .await?
        .checked(422)?;
    client
        .post(
            &server,
            "/api/enrollment/approve",
            json!({"operation":first.operation,"request":"A".repeat(65536)}),
        )
        .await?
        .checked(413)?;
    assert!(matches!(
        status(&mut client, &server, &first).await?,
        EnrollmentStatus::Invited { .. }
    ));
    assert!(client
        .get(&server, "/api/enrollment/root")
        .await?
        .checked(200)?
        .json::<RootInfo>()?
        .roster
        .is_none());
    let empty_predecessor: Invitation = client
        .post(
            &server,
            "/api/enrollment/reapprove",
            json!({
                "previous": other.operation, "request_id": ([23u8; 32]),
                "predecessor": null, "request": URL_SAFE_NO_PAD.encode(&other_proof)
            }),
        )
        .await?
        .checked(200)?
        .json()?;
    assert_eq!(empty_predecessor.predecessor, None);
    assert_eq!(empty_predecessor.device, other.device);
    approve(&mut client, &server, &first, &proof).await?;
    let result = issue(&mut client, &server, &first).await?;
    assert_eq!(
        serde_json::from_slice::<IssuedEnrollment>(&result)?
            .checkpoint
            .version,
        1
    );
    server.close().await
}
