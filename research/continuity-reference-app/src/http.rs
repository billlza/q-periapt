// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{auth::Service, error::Error};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, HeaderValue, Method},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

mod enrollment;
mod policy_approval;

const CEREMONY: &str = "qpc_reference_ceremony";
const SESSION: &str = "qpc_reference_session";
#[derive(Clone)]
pub struct Shared {
    service: Arc<Mutex<Service>>,
    slots: Arc<Semaphore>,
    origin: String,
    host: String,
}
impl Shared {
    pub fn new(service: Service, origin: String, host: String) -> Self {
        Self {
            service: Arc::new(Mutex::new(service)),
            slots: Arc::new(Semaphore::new(16)),
            origin,
            host,
        }
    }
    async fn call<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Service) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)?;
        let service = self.service.clone();
        let job = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let mut service = service.lock().map_err(|_| Error::Internal)?;
            work(&mut service)
        });
        tokio::time::timeout(Duration::from_secs(30), job)
            .await
            .map_err(|_| Error::Internal)?
            .map_err(|e| Error::internal("account worker", e))?
    }
}
pub fn router(state: Shared) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/app.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/app.css"),
                )
            }),
        )
        .route("/api/register/start", post(register_start))
        .route("/api/register/finish", post(register_finish))
        .route("/api/login/start", post(login_start))
        .route("/api/login/finish", post(login_finish))
        .route("/api/me", get(identity))
        .route("/api/logout", post(logout))
        .merge(browser_modules())
        .merge(enrollment::routes())
        .layer(DefaultBodyLimit::max(64 * 1024))
        .merge(policy_approval::routes())
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
fn browser_modules() -> Router<Shared> {
    let mut routes = Router::new();
    for (path, source) in [
        ("/transport.mjs", include_str!("../web/transport.mjs")),
        (
            "/enrollment-records.mjs",
            include_str!("../web/enrollment-records.mjs"),
        ),
        (
            "/enrollment-model.mjs",
            include_str!("../web/enrollment-model.mjs"),
        ),
        ("/enrollment.mjs", include_str!("../web/enrollment.mjs")),
        (
            "/extension-model.mjs",
            include_str!("../web/extension-model.mjs"),
        ),
        ("/extension.mjs", include_str!("../web/extension.mjs")),
        (
            "/record-validation.mjs",
            include_str!("../web/record-validation.mjs"),
        ),
        (
            "/grant-records.mjs",
            include_str!("../web/grant-records.mjs"),
        ),
        ("/grant-model.mjs", include_str!("../web/grant-model.mjs")),
        ("/grant.mjs", include_str!("../web/grant.mjs")),
        (
            "/credential-history.mjs",
            include_str!("../web/credential-history.mjs"),
        ),
        (
            "/policy-records.mjs",
            include_str!("../web/policy-records.mjs"),
        ),
        ("/policy-model.mjs", include_str!("../web/policy-model.mjs")),
        ("/policy.mjs", include_str!("../web/policy.mjs")),
    ] {
        routes = routes.route(
            path,
            get(move || async move {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    source,
                )
            }),
        );
    }
    routes
}
async fn boundary(State(state): State<Shared>, request: Request, next: Next) -> Response {
    if request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        != Some(state.host.as_str())
    {
        return Error::Invalid("Unexpected host").into_response();
    }
    if request.method() != Method::GET
        && request
            .headers()
            .get(header::ORIGIN)
            .and_then(|h| h.to_str().ok())
            != Some(state.origin.as_str())
    {
        return Error::Invalid("Expected same-origin request").into_response();
    }
    let mut response = match tokio::time::timeout(Duration::from_secs(35), next.run(request)).await
    {
        Ok(value) => value,
        Err(_) => Error::Internal.into_response(),
    };
    for (name, value) in [
        ("cache-control", "no-store"), ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    ] { response.headers_mut().insert(name, HeaderValue::from_static(value)); }
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    name: String,
}
async fn register_start(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Name>,
) -> Result<Response, Error> {
    let session = cookie(&headers, SESSION)?;
    let previous = cookie(&headers, CEREMONY)?;
    let (id, options) = state
        .call(move |s| s.start_registration(&body.name, session.as_deref(), previous.as_deref()))
        .await?;
    with_cookie(Json(options).into_response(), CEREMONY, &id, 180)
}
async fn register_finish(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<RegisterPublicKeyCredential>,
) -> Result<Response, Error> {
    let token = cookie(&headers, CEREMONY)?.ok_or(Error::Unauthorized)?;
    let session = cookie(&headers, SESSION)?;
    let identity = state
        .call(move |s| s.finish_registration(&token, body, session.as_deref()))
        .await?;
    with_cookie(Json(identity).into_response(), CEREMONY, "", 0)
}
async fn login_start(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Name>,
) -> Result<Response, Error> {
    let previous = cookie(&headers, CEREMONY)?;
    let (id, options) = state
        .call(move |s| s.start_login(&body.name, previous.as_deref()))
        .await?;
    with_cookie(Json(options).into_response(), CEREMONY, &id, 180)
}
async fn login_finish(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<PublicKeyCredential>,
) -> Result<Response, Error> {
    let token = cookie(&headers, CEREMONY)?.ok_or(Error::Unauthorized)?;
    let previous = cookie(&headers, SESSION)?;
    let (id, identity) = state
        .call(move |s| s.finish_login(&token, body, previous.as_deref()))
        .await?;
    let response = with_cookie(Json(identity).into_response(), CEREMONY, "", 0)?;
    with_cookie(response, SESSION, &id, 900)
}
async fn identity(State(state): State<Shared>, headers: HeaderMap) -> Result<Response, Error> {
    let token = cookie(&headers, SESSION)?.ok_or(Error::Unauthorized)?;
    Ok(Json(state.call(move |s| s.identity(&token)).await?).into_response())
}
async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Result<Response, Error> {
    let token = cookie(&headers, SESSION)?.ok_or(Error::Unauthorized)?;
    state.call(move |s| s.logout(&token)).await?;
    with_cookie(
        Json(serde_json::json!({"signed_out": true})).into_response(),
        SESSION,
        "",
        0,
    )
}
fn with_cookie(
    mut response: Response,
    name: &str,
    value: &str,
    age: u16,
) -> Result<Response, Error> {
    // This listener admits only HTTP localhost. A deployed HTTPS profile must
    // use Secure cookies and its own explicit origin; it is not enabled here.
    let header = HeaderValue::from_str(&format!(
        "{name}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={age}"
    ))
    .map_err(|e| Error::internal("cookie encoding", e))?;
    response.headers_mut().append(header::SET_COOKIE, header);
    Ok(response)
}
fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, Error> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for part in header
            .to_str()
            .map_err(|_| Error::Invalid("Invalid cookie"))?
            .split(';')
        {
            if let Some((key, value)) = part.trim().split_once('=') {
                if key != name {
                    continue;
                }
                if found.is_some()
                    || value.len() != 43
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(Error::Invalid("Invalid authentication cookie"));
                }
                found = Some(value.to_owned());
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use axum::{body::Body, http::StatusCode};
    use std::os::unix::fs::PermissionsExt;
    use tower::ServiceExt;
    use webauthn_rs::prelude::{Url, WebauthnBuilder};

    #[tokio::test]
    async fn rejects_cross_origin_and_host_before_authentication(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let origin = "http://localhost:8087";
        let store = Store::provision(&temp.path().canonicalize()?.join("accounts.redb"), origin)?;
        let webauthn = WebauthnBuilder::new("localhost", &Url::parse(origin)?)?.build()?;
        let app = router(Shared::new(
            Service::new(webauthn, store),
            origin.into(),
            "localhost:8087".into(),
        ));
        for (host, origin_header) in [
            ("attacker.example", origin),
            ("localhost:8087", "https://attacker.example"),
            ("localhost:8087", "null"),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/api/register/start")
                .header("host", host)
                .header("origin", origin_header)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"alice"}"#))?;
            assert_eq!(
                app.clone().oneshot(request).await?.status(),
                StatusCode::BAD_REQUEST
            );
        }
        let request = Request::builder()
            .uri("/api/me")
            .header("host", "localhost:8087")
            .body(Body::empty())?;
        let response = app.oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers().contains_key("content-security-policy"));
        Ok(())
    }
    #[test]
    fn duplicate_and_malformed_authentication_cookies_are_rejected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        let token = "A".repeat(43);
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{SESSION}={token}; {SESSION}={token}"))?,
        );
        assert!(cookie(&headers, SESSION).is_err());
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("qpc_reference_session=short"),
        );
        assert!(cookie(&headers, SESSION).is_err());
        headers.clear();
        assert!(cookie(&headers, SESSION)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn actual_loopback_tcp_preserves_authentication_boundary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::{Read, Write};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let host = format!("localhost:{}", address.port());
        let origin = format!("http://{host}");
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let store = Store::provision(&temp.path().canonicalize()?.join("accounts.redb"), &origin)?;
        let webauthn = WebauthnBuilder::new("localhost", &Url::parse(&origin)?)?.build()?;
        let state = Shared::new(Service::new(webauthn, store), origin, host.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state))
                .with_graceful_shutdown(async move {
                    if let Err(error) = stopped.await {
                        eprintln!("TCP test shutdown sender: {error}");
                    }
                })
                .await
        });
        let client = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut socket =
                std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            write!(
                socket,
                "GET /api/me HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            )?;
            let mut bytes = Vec::new();
            socket.take(65537).read_to_end(&mut bytes)?;
            Ok(bytes)
        })
        .await;
        let shutdown = stop.send(());
        tokio::time::timeout(Duration::from_secs(5), server).await???;
        shutdown.map_err(|_| "TCP server ended before shutdown")?;
        let bytes = client??;
        assert!(bytes.len() <= 65536);
        let response = String::from_utf8(bytes)?;
        assert!(response.starts_with("HTTP/1.1 401 "));
        assert!(response
            .to_ascii_lowercase()
            .contains("cache-control: no-store\r\n"));
        assert!(response.contains("Authentication required or ceremony invalid"));
        Ok(())
    }
}
