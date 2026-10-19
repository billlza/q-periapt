// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual loopback HTTP and real signatures from a software test authenticator.
use super::super::super::{router, Shared};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{auth::Service, enrollment::Invitation, store::Store};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::{Url, WebauthnBuilder};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type Authenticator = WebauthnAuthenticator<SoftPasskey>;
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub struct Server {
    pub address: SocketAddr,
    pub origin: String,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Server {
    pub async fn start(path: &Path, address: SocketAddr, create: bool) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let host = format!("localhost:{}", address.port());
        let origin = format!("http://{host}");
        let db = path.join("accounts.redb");
        let store = if create {
            let mut store = Store::provision(&db, &origin)?;
            store.enable_enrollment([42; 32])?;
            store.enable_enrollment_reapproval()?;
            store
        } else {
            Store::open(&db, &origin)?
        };
        let webauthn = WebauthnBuilder::new("localhost", &Url::parse(&origin)?)?.build()?;
        let app = router(Shared::new(
            Service::new(webauthn, store),
            origin.clone(),
            host,
        ));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    if let Err(error) = stopped.await {
                        eprintln!("enrollment test shutdown: {error}");
                    }
                })
                .await
        });
        Ok(Self {
            address,
            origin,
            stop,
            task,
        })
    }
    pub async fn close(self) -> Result {
        self.stop
            .send(())
            .map_err(|_| "HTTP service ended before shutdown")?;
        tokio::time::timeout(Duration::from_secs(10), self.task).await???;
        Ok(())
    }
}
pub fn directory() -> Result<tempfile::TempDir> {
    Ok(tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?)
}
pub struct Reply {
    pub code: u16,
    pub body: Vec<u8>,
}
impl Reply {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }
    pub fn checked(self, expected: u16) -> Result<Self> {
        if self.code != expected {
            return Err(format!(
                "HTTP status {} instead of {expected}: {}",
                self.code,
                String::from_utf8_lossy(&self.body)
            )
            .into());
        }
        Ok(self)
    }
}
#[derive(Default)]
pub struct Client {
    cookies: BTreeMap<String, String>,
}
impl Client {
    pub async fn request(
        &mut self,
        server: &Server,
        path: &str,
        body: Option<String>,
        origin: Option<&str>,
    ) -> Result<Reply> {
        self.exchange(server, path, body, origin, false).await
    }
    async fn exchange(
        &mut self,
        server: &Server,
        path: &str,
        body: Option<String>,
        origin: Option<&str>,
        disconnect_before_body: bool,
    ) -> Result<Reply> {
        let address = server.address;
        let cookie = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let method = if body.is_some() { "POST" } else { "GET" };
        let body = body.unwrap_or_default();
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", address.port(), body.len());
        if !cookie.is_empty() {
            request.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        if let Some(origin) = origin {
            request.push_str(&format!("Origin: {origin}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(&body);
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut stream =
                std::net::TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            stream.write_all(request.as_bytes())?;
            let mut bytes = Vec::new();
            if disconnect_before_body {
                // Read exactly the response headers, then close the TCP socket
                // without reading any credential/roster bytes. The client has
                // no issuance body and must recover the original operation.
                while !bytes.ends_with(b"\r\n\r\n") {
                    if bytes.len() >= 8192 {
                        return Err(std::io::Error::other("HTTP test header exceeds bound"));
                    }
                    let mut byte = [0];
                    stream.read_exact(&mut byte)?;
                    bytes.push(byte[0]);
                }
            } else {
                stream.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            }
            Ok(bytes)
        })
        .await??;
        if bytes.len() > 1024 * 1024 {
            return Err("HTTP test response exceeds bound".into());
        }
        let end = bytes
            .windows(4)
            .position(|b| b == b"\r\n\r\n")
            .ok_or("HTTP header absent")?;
        let header = std::str::from_utf8(&bytes[..end])?;
        let code = header
            .lines()
            .next()
            .ok_or("HTTP status absent")?
            .split_whitespace()
            .nth(1)
            .ok_or("HTTP status code absent")?
            .parse()?;
        for line in header.lines().skip(1) {
            let (name, value) = line.split_once(':').ok_or("HTTP header syntax")?;
            if name.eq_ignore_ascii_case("set-cookie") {
                let pair = value.trim().split(';').next().ok_or("cookie pair absent")?;
                let (key, value) = pair.split_once('=').ok_or("cookie syntax")?;
                if value.is_empty() {
                    self.cookies.remove(key);
                } else {
                    self.cookies.insert(key.into(), value.into());
                }
            }
        }
        if !header
            .to_ascii_lowercase()
            .contains("cache-control: no-store")
            && code != 400
        {
            return Err("HTTP no-store boundary absent".into());
        }
        Ok(Reply {
            code,
            body: bytes[end + 4..].to_vec(),
        })
    }
    pub async fn post(
        &mut self,
        server: &Server,
        path: &str,
        body: impl Serialize,
    ) -> Result<Reply> {
        self.request(
            server,
            path,
            Some(serde_json::to_string(&body)?),
            Some(&server.origin),
        )
        .await
    }
    pub async fn disconnect_before_body(
        &mut self,
        server: &Server,
        path: &str,
        body: impl Serialize,
    ) -> Result<Reply> {
        self.exchange(
            server,
            path,
            Some(serde_json::to_string(&body)?),
            Some(&server.origin),
            true,
        )
        .await
    }
    pub async fn get(&mut self, server: &Server, path: &str) -> Result<Reply> {
        self.request(server, path, None, None).await
    }
    pub async fn register(&mut self, server: &Server, name: &str) -> Result<Authenticator> {
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let options = self
            .post(
                server,
                "/api/register/start",
                serde_json::json!({"name":name}),
            )
            .await?
            .checked(200)?
            .json()?;
        let credential = authenticator.do_registration(Url::parse(&server.origin)?, options)?;
        self.post(server, "/api/register/finish", credential)
            .await?
            .checked(200)?;
        self.login(server, name, &mut authenticator).await?;
        Ok(authenticator)
    }
    pub async fn login(
        &mut self,
        server: &Server,
        name: &str,
        authenticator: &mut Authenticator,
    ) -> Result {
        let options = self
            .post(server, "/api/login/start", serde_json::json!({"name":name}))
            .await?
            .checked(200)?
            .json()?;
        let credential = authenticator.do_authentication(Url::parse(&server.origin)?, options)?;
        self.post(server, "/api/login/finish", credential)
            .await?
            .checked(200)?;
        Ok(())
    }
}
pub fn device_request(
    path: &Path,
    invitation: &Invitation,
) -> Result<(sdk::EnrollmentPaths, Vec<u8>)> {
    let directory = path.join(URL_SAFE_NO_PAD.encode(invitation.operation));
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    drop(sdk::JournalKey::provision(&directory.join("wrap.key"))?);
    let paths = sdk::EnrollmentPaths::new(
        &directory.join("wrap.key"),
        &directory.join("signer.key"),
        &directory.join("enrollment.redb"),
        sdk::InstallationPaths::new(
            &directory.join("installation.redb"),
            &directory.join("journal.redb"),
            &directory.join("archive.redb"),
        )?,
    )?;
    let mut device = sdk::DeviceEnrollment::provision(paths.clone(), invitation.intent()?)?;
    let request = device.request(now()?)?;
    device.close();
    Ok((paths, request))
}
