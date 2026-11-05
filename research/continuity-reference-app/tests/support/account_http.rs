// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared qualification-only HTTP client and software WebAuthn authenticator.
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::SocketAddr,
    time::Duration,
};
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::Url;
pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type Authenticator = WebauthnAuthenticator<SoftPasskey>;
pub struct Endpoint {
    pub address: SocketAddr,
    pub origin: String,
}
pub struct Reply {
    pub code: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
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
        server: &Endpoint,
        path: &str,
        body: Option<String>,
        origin: Option<&str>,
    ) -> Result<Reply> {
        self.exchange(server, path, body, origin, false).await
    }
    async fn exchange(
        &mut self,
        server: &Endpoint,
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
        if !body.is_empty() {
            request.push_str("Expect: 100-continue\r\n");
        }
        request.push_str("\r\n");
        let path = path.to_owned();
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut stream =
                std::net::TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            let write_error = |e: std::io::Error| {
                std::io::Error::new(e.kind(), format!("HTTP test write {path}: {e}"))
            };
            let read_error = |e: std::io::Error| {
                std::io::Error::new(e.kind(), format!("HTTP test read {path}: {e}"))
            };
            stream.write_all(request.as_bytes()).map_err(write_error)?;
            // A final response can reject a declared body before reading it.
            // Wait for Continue instead of racing that refusal with a large upload.
            let mut response =
                read_response(&mut stream, disconnect_before_body).map_err(read_error)?;
            if !body.is_empty() && response_code(&response)? == 100 {
                stream.write_all(body.as_bytes()).map_err(write_error)?;
                response =
                    read_response(&mut stream, disconnect_before_body).map_err(read_error)?;
            }
            if response_code(&response)? < 200 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP test final response absent",
                ));
            }
            Ok(response)
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
        let code = response_code(&bytes)?;
        let mut content_type = None;
        for line in header.lines().skip(1) {
            let (name, value) = line.split_once(':').ok_or("HTTP header syntax")?;
            if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.trim().to_owned());
            }
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
            content_type,
        })
    }
    pub async fn post(
        &mut self,
        server: &Endpoint,
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
        server: &Endpoint,
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
    pub async fn get(&mut self, server: &Endpoint, path: &str) -> Result<Reply> {
        self.request(server, path, None, None).await
    }
    pub async fn register(&mut self, server: &Endpoint, name: &str) -> Result<Authenticator> {
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
        server: &Endpoint,
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

fn response_code(bytes: &[u8]) -> std::io::Result<u16> {
    use std::io::{Error, ErrorKind};
    let invalid = |message| Error::new(ErrorKind::InvalidData, message);
    let end = bytes
        .windows(2)
        .position(|part| part == b"\r\n")
        .ok_or_else(|| invalid("HTTP test status absent"))?;
    let line =
        std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("HTTP test status encoding"))?;
    let mut parts = line.split_whitespace();
    if parts.next() != Some("HTTP/1.1") {
        return Err(invalid("HTTP test version"));
    }
    parts
        .next()
        .ok_or_else(|| invalid("HTTP test status absent"))?
        .parse::<u16>()
        .map_err(|_| invalid("HTTP test status"))
}

// These JSON/file routes send fixed-length responses. Read their complete HTTP
// frame, not transport EOF: early Origin/body rejection can close unread request
// data with a reset after a complete error response. Incomplete frames still fail.
fn read_response(stream: &mut impl Read, headers_only: bool) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    let invalid = |message| Error::new(ErrorKind::InvalidData, message);
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 8192 {
            return Err(invalid("HTTP test header exceeds bound"));
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    let header = std::str::from_utf8(&bytes).map_err(|_| invalid("HTTP test header encoding"))?;
    let code = response_code(&bytes)?;
    let mut length = None;
    for line in header.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("HTTP test header syntax"))?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("HTTP test fixed-length response required"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("HTTP test content length"));
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| invalid("HTTP test content length"))?,
            );
        }
    }
    let length = match (code, length) {
        (100, None) => 0,
        (100, Some(_)) => return Err(invalid("HTTP Continue cannot carry content length")),
        (101..=199, _) => return Err(invalid("HTTP test informational response unsupported")),
        (204 | 304, None | Some(0)) => 0,
        (204 | 304, Some(_)) => return Err(invalid("HTTP test body forbidden")),
        (_, Some(length)) => length,
        (_, None) => return Err(invalid("HTTP test content length absent")),
    };
    let total = bytes
        .len()
        .checked_add(length)
        .filter(|n| *n <= 1024 * 1024)
        .ok_or_else(|| invalid("HTTP test response exceeds bound"))?;
    if !headers_only {
        let offset = bytes.len();
        bytes.resize(total, 0);
        stream.read_exact(&mut bytes[offset..])?;
    }
    Ok(bytes)
}

#[test]
fn http_test_reader_requires_complete_bounded_frames_without_requiring_transport_eof(
) -> std::io::Result<()> {
    struct ResetAfter(std::io::Cursor<Vec<u8>>);
    impl Read for ResetAfter {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.0.position() == self.0.get_ref().len() as u64 {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            self.0.read(output)
        }
    }
    let complete = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad";
    assert_eq!(
        read_response(
            &mut ResetAfter(std::io::Cursor::new(complete.to_vec())),
            false
        )?,
        complete
    );
    let truncated = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 4\r\n\r\nbad";
    assert!(read_response(
        &mut ResetAfter(std::io::Cursor::new(truncated.to_vec())),
        false
    )
    .is_err());
    for invalid in [
        "HTTP/1.1 200 OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
        "HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 100 Continue\r\nContent-Length: 1\r\n\r\nx",
        "HTTP/1.1 103 Early Hints\r\n\r\n",
    ] {
        assert!(read_response(&mut std::io::Cursor::new(invalid.as_bytes()), false).is_err());
    }
    let empty = b"HTTP/1.1 204 No Content\r\n\r\n";
    assert_eq!(
        read_response(&mut std::io::Cursor::new(empty), false)?,
        empty
    );
    Ok(())
}

#[tokio::test]
async fn http_test_client_observes_complete_early_refusal_without_uploading_body() -> Result {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = Endpoint {
        address: listener.local_addr()?,
        origin: "http://localhost".into(),
    };
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            let (mut socket, _) = listener.accept().await?;
            test_request_header(&mut socket).await?;
            socket.write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 9\r\nCache-Control: no-store\r\nConnection: close\r\n\r\ntoo large").await?;
            socket.shutdown().await?;
            let mut byte = [0];
            socket.read(&mut byte).await
        })
        .await
        .map_err(std::io::Error::other)?
    });
    let reply = Client::default()
        .request(
            &endpoint,
            "/oversized",
            Some("x".repeat(2 * 1024 * 1024)),
            None,
        )
        .await;
    let uploaded_after_refusal = server.await??;
    let reply = reply?.checked(413)?;
    assert_eq!(reply.body, b"too large");
    assert_eq!(
        uploaded_after_refusal, 0,
        "final refusal did not stop upload"
    );
    Ok(())
}

#[cfg(test)]
async fn test_request_header(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 8192 {
            return Err(std::io::Error::other("request header bound"));
        }
        header.push(socket.read_u8().await?);
    }
    Ok(header)
}

#[tokio::test]
async fn http_test_client_sends_exact_body_after_continue_and_reads_final_response() -> Result {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = Endpoint {
        address: listener.local_addr()?,
        origin: "http://localhost".into(),
    };
    let body = b"{\"original\":true}";
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            let (mut socket, _) = listener.accept().await?;
            let header = test_request_header(&mut socket).await?;
            assert!(header
                .windows(b"Expect: 100-continue\r\n".len())
                .any(|part| part == b"Expect: 100-continue\r\n"));
            socket.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            let mut received = vec![0; body.len()];
            socket.read_exact(&mut received).await?;
            assert_eq!(received, body);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nCache-Control: no-store\r\n\r\nok",
                )
                .await?;
            std::io::Result::Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    });
    let reply = Client::default()
        .request(
            &endpoint,
            "/accepted",
            Some(std::str::from_utf8(body)?.into()),
            None,
        )
        .await;
    server.await??;
    assert_eq!(reply?.checked(200)?.body, b"ok");
    Ok(())
}

#[tokio::test]
async fn http_test_client_rejects_truncated_or_missing_final_response() -> Result {
    use tokio::io::AsyncWriteExt;
    for response in [
        &b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 4\r\nCache-Control: no-store\r\n\r\nbad"[..],
        &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n"[..],
        &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\nCache-Control: no-store\r\n\r\nok"[..],
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = Endpoint { address: listener.local_addr()?, origin: "http://localhost".into() };
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), async move {
                let (mut socket, _) = listener.accept().await?;
                test_request_header(&mut socket).await?;
                socket.write_all(response).await?;
                socket.shutdown().await
            }).await.map_err(std::io::Error::other)?
        });
        let reply = Client::default().request(&endpoint, "/incomplete", Some("{}".into()), None).await;
        server.await??;
        assert!(reply.is_err(), "incomplete response became a completed result");
    }
    Ok(())
}
