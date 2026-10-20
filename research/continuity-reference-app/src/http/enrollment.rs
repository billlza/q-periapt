// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated host decisions. Device proofs never replace the login session.
use super::{cookie, Shared, SESSION};
use crate::error::Error;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_reference_app::enrollment::{Checkpoint, CredentialExtensionRequest};
use serde::Deserialize;

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/enrollment/root", get(root))
        .route("/api/enrollment/root/prepare", post(prepare))
        .route("/api/enrollment/root/suspend", post(suspend))
        .route("/api/enrollment/invite", post(invite))
        .route("/api/enrollment/approve", post(approve))
        .route("/api/enrollment/issue", post(issue))
        .route("/api/enrollment/status", post(status))
        .route("/api/enrollment/cancel", post(cancel))
        .route("/api/enrollment/reapprove", post(reapprove))
        .route("/api/enrollment/extend-credential", post(extend_credential))
        .route("/api/enrollment/credential-grant", post(credential_grant))
        .route(
            "/api/enrollment/credential-grant/cancel",
            post(cancel_grant),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Correlation {
    request_id: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    operation: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    operation: [u8; 32],
    request: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reapproval {
    previous: [u8; 32],
    request_id: [u8; 32],
    #[serde(deserialize_with = "selected_predecessor")]
    predecessor: Option<Checkpoint>,
    request: String,
}

fn selected_predecessor<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> Result<Option<Checkpoint>, D::Error> {
    // Unlike serde's implicit missing Option default, this requires the field
    // to be present. Explicit null is the host's selected empty roster.
    Option::<Checkpoint>::deserialize(value)
}

fn session(headers: &HeaderMap) -> Result<String, Error> {
    cookie(headers, SESSION)?.ok_or(Error::Unauthorized)
}
fn proof(encoded: &str) -> Result<Vec<u8>, Error> {
    // The existing SDK enrollment request is bounded at 8192 bytes. Reject before
    // allocating a decoded request; the outer router also bounds the entire body.
    if encoded.len() > 8192_usize.div_ceil(3) * 4 {
        return Err(Error::Invalid("Enrollment request exceeds bound"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Invalid("Expected canonical unpadded base64url request"))?;
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err(Error::Invalid("Enrollment request size"));
    }
    Ok(bytes)
}

async fn root(State(state): State<Shared>, headers: HeaderMap) -> Result<Response, Error> {
    let token = session(&headers)?;
    Ok(Json(state.call(move |s| s.enrollment_root(&token)).await?).into_response())
}
async fn prepare(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(_): Json<Empty>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.prepare_enrollment_root(&token))
            .await?,
    )
    .into_response())
}
async fn suspend(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(_): Json<Empty>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.suspend_enrollment_root(&token))
            .await?,
    )
    .into_response())
}
async fn invite(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Correlation>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.invite_enrollment(&token, body.request_id))
            .await?,
    )
    .into_response())
}
async fn approve(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Approval>,
) -> Result<StatusCode, Error> {
    let token = session(&headers)?;
    let request = proof(&body.request)?;
    state
        .call(move |s| s.approve_enrollment(&token, body.operation, &request))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn issue(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Operation>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    let original = state
        .call(move |s| s.issue_enrollment(&token, body.operation))
        .await?;
    // Return the exact durably committed response, including after an unknown
    // outcome. Parsing and serializing it here would weaken byte-exact recovery.
    Ok(([(header::CONTENT_TYPE, "application/json")], original).into_response())
}

async fn extend_credential(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<CredentialExtensionRequest>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    let original = state
        .call(move |s| s.extend_enrollment_credential(&token, &request))
        .await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], original).into_response())
}
async fn credential_grant(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<
        q_periapt_continuity_reference_app::credential_grant::CredentialGrantRequest,
    >,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    let result = state
        .call(move |s| s.issue_credential_grant(&token, &request))
        .await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], result).into_response())
}
async fn cancel_grant(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<
        q_periapt_continuity_reference_app::credential_grant::CredentialGrantRequest,
    >,
) -> Result<StatusCode, Error> {
    let token = session(&headers)?;
    state
        .call(move |s| s.cancel_credential_grant(&token, &request))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn status(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Operation>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.enrollment_status(&token, body.operation))
            .await?,
    )
    .into_response())
}
async fn cancel(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Operation>,
) -> Result<StatusCode, Error> {
    let token = session(&headers)?;
    state
        .call(move |s| s.cancel_enrollment(&token, body.operation))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn reapprove(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Reapproval>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    let request = proof(&body.request)?;
    Ok(Json(
        state
            .call(move |s| {
                s.reapprove_enrollment(
                    &token,
                    body.previous,
                    body.request_id,
                    body.predecessor,
                    &request,
                )
            })
            .await?,
    )
    .into_response())
}

#[cfg(test)]
mod tests;
