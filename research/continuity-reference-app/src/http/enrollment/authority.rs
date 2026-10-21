// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host authentication authorizes exact root operations, never a device's self-selection.
use super::*;
use q_periapt_continuity_reference_app::{
    account_authority::{
        Association, AssociationRequest, Closure, Cutover, CutoverRequest, Retirement,
    },
    enrollment::RootInfo,
};
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/enrollment/authority/associate", post(associate))
        .route("/api/enrollment/authority", get(association))
        .route("/api/enrollment/root-cutover/approve", post(approve))
        .route("/api/enrollment/root-cutover/commit", post(commit))
        .route("/api/enrollment/root-cutover/close", post(close))
        .route("/api/enrollment/root-cutover/resume", post(resume))
        .route("/api/enrollment/root-cutover/status", post(status))
        .route("/api/enrollment/root/retired", post(retired))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    operation: [u8; 32],
    proof: Retirement,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    revision: u64,
}
async fn associate(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<AssociationRequest>,
) -> Result<Json<Association>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.associate_account_authority(&token, &request))
            .await?,
    ))
}
async fn association(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<Association>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state.call(move |s| s.account_authority(&token)).await?,
    ))
}
async fn approve(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<CutoverRequest>,
) -> Result<Json<Cutover>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.approve_account_root(&token, &request))
            .await?,
    ))
}
async fn commit(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Commit>,
) -> Result<Json<Cutover>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.commit_account_root(&token, request.operation, &request.proof))
            .await?,
    ))
}
async fn close(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Closure>,
) -> Result<Json<Cutover>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.close_account_root(&token, request.operation, &request.receipt))
            .await?,
    ))
}
async fn resume(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Operation>,
) -> Result<Json<Cutover>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.resume_account_root(&token, request.operation))
            .await?,
    ))
}
async fn status(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Operation>,
) -> Result<Json<Cutover>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.account_root_cutover(&token, request.operation))
            .await?,
    ))
}
async fn retired(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Retired>,
) -> Result<Json<RootInfo>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.retired_account_root(&token, request.revision))
            .await?,
    ))
}
