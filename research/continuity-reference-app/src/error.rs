// SPDX-License-Identifier: Apache-2.0 OR MIT
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Unauthorized,
    AccountNotRegistered,
    Conflict(&'static str),
    Capacity,
    IssuerUnavailable,
    AuthorityUnavailable,
    Internal,
}
impl Error {
    pub fn internal(context: &'static str, error: impl std::fmt::Display) -> Self {
        eprintln!("{context}: {error}");
        Self::Internal
    }
    pub(crate) fn issuer_key(context: &'static str, error: impl std::fmt::Display) -> Self {
        eprintln!("{context}: {error}");
        Self::IssuerUnavailable
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<q_periapt_host_store::filesystem::PrivateDatabaseError> for Error {
    fn from(value: q_periapt_host_store::filesystem::PrivateDatabaseError) -> Self {
        Self::internal("private host database", value)
    }
}
#[derive(Serialize)]
struct Failure {
    error: &'static str,
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, message),
            Self::AccountNotRegistered => (StatusCode::UNAUTHORIZED, "No registered account for this name. Create an account first, or check the account name."),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Authentication required or ceremony invalid",
            ),
            Self::Conflict(message) => (StatusCode::CONFLICT, message),
            Self::Capacity => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Capacity reached; retry later",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Operation failed; retained state must be reconciled",
            ),
            Self::IssuerUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Original issuer key unavailable; reconcile its retained state",
            ),
            Self::AuthorityUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Original account authority unavailable; reconcile its retained store and key",
            ),
        };
        (status, Json(Failure { error })).into_response()
    }
}
