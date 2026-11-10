// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit authenticated account decision; policy signatures remain independent.
use super::{cookie, Shared, SESSION};
use crate::error::Error;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use q_periapt_continuity_reference_app::policy_approval::{
    PolicyApprovalPreview, PolicyApprovalRequest, PolicyApprovalStatus, MAX_POLICY_APPROVAL_REQUEST,
};
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/enrollment/policy-approval", post(issue))
        .route("/api/enrollment/policy-approval/preview", post(preview))
        .route("/api/enrollment/policy-approval/status", post(status))
        .route("/api/enrollment/policy-approval/cancel", post(cancel))
        .layer(DefaultBodyLimit::max(MAX_POLICY_APPROVAL_REQUEST))
}
async fn preview(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<PolicyApprovalRequest>,
) -> Result<Json<PolicyApprovalPreview>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.preview_policy_approval(&token, &request))
            .await?,
    ))
}
fn session(headers: &HeaderMap) -> Result<String, Error> {
    cookie(headers, SESSION)?.ok_or(Error::Unauthorized)
}
async fn issue(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<PolicyApprovalRequest>,
) -> Result<Response, Error> {
    let token = session(&headers)?;
    let bytes = state
        .call(move |s| s.issue_policy_approval(&token, &request))
        .await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}
async fn status(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<PolicyApprovalRequest>,
) -> Result<Json<PolicyApprovalStatus>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.policy_approval_status(&token, &request))
            .await?,
    ))
}
async fn cancel(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<PolicyApprovalRequest>,
) -> Result<StatusCode, Error> {
    let token = session(&headers)?;
    state
        .call(move |s| s.cancel_policy_approval(&token, &request))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
