// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Candidate creation and original enrollment, distinct from current-root selection.
use super::*;
use q_periapt_continuity_reference_app::{
    enrollment::Invitation,
    root_preparation::{Preparation, Request, SuccessorObservation, SuccessorRequest},
};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/enrollment/root-candidate/prepare", post(prepare))
        .route("/api/enrollment/root-candidate/status", post(status))
        .route("/api/enrollment/root-candidate/close", post(close))
        .route("/api/enrollment/root-candidate/invite", post(invite))
        .route("/api/enrollment/root-candidate/successor", post(successor))
}
async fn successor(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Operation>,
) -> Result<Json<SuccessorObservation>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.root_successor(&token, request.operation))
            .await?,
    ))
}
async fn prepare(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> Result<Json<Preparation>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.prepare_account_root(&token, &request))
            .await?,
    ))
}
async fn status(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Operation>,
) -> Result<Json<Preparation>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.account_root_preparation(&token, request.operation))
            .await?,
    ))
}
async fn close(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<Operation>,
) -> Result<Json<Preparation>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.close_account_root_preparation(&token, request.operation))
            .await?,
    ))
}
async fn invite(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<SuccessorRequest>,
) -> Result<Json<Invitation>, Error> {
    let token = session(&headers)?;
    Ok(Json(
        state
            .call(move |s| s.invite_root_successor(&token, &request))
            .await?,
    ))
}
