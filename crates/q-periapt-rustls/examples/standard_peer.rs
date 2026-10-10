// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local independent-peer diagnostic, not a reference application or a TLS server.
//! The Python driver bounds process lifetime and keeps generated test keys private.
use q_periapt_rustls::standard::{MutualTlsClient, MutualTlsServer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{CommonState, NamedGroup, RootCertStore, StreamOwned};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(unix)]
fn fixtures(directory: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    for (label, name) in [("server", "localhost"), ("client", "client.test")] {
        let certificate = rcgen::generate_simple_self_signed(vec![name.to_owned()])?;
        for (suffix, bytes) in [
            ("der", certificate.cert.der().to_vec()),
            ("pem", certificate.cert.pem().into_bytes()),
            ("key.der", certificate.signing_key.serialize_der()),
            (
                "key.pem",
                certificate.signing_key.serialize_pem().into_bytes(),
            ),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(format!("{label}.{suffix}")))?;
            file.write_all(&bytes)?;
        }
    }
    println!("TEST_FIXTURES_READY");
    Ok(())
}

struct DiagnosticResponse(Vec<u8>);
impl Drop for DiagnosticResponse {
    fn drop(&mut self) {
        q_periapt_core::secure_wipe(&mut self.0);
    }
}
#[cfg(not(unix))]
fn fixtures(_directory: &Path) -> Result<()> {
    Err("the local interop fixture driver requires Unix permission semantics".into())
}

fn read(directory: &Path, name: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(directory.join(name))?
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err("diagnostic fixture exceeds size limit".into());
    }
    Ok(bytes)
}
fn roots(directory: &Path, peer: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(read(
        directory,
        &format!("{peer}.der"),
    )?))?;
    Ok(roots)
}
fn identity(
    directory: &Path,
    side: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    Ok((
        vec![read(directory, &format!("{side}.der"))?.into()],
        PrivateKeyDer::try_from(read(directory, &format!("{side}.key.der"))?)?,
    ))
}
fn observed(connection: &CommonState) -> Result<()> {
    if connection.is_handshaking()
        || connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || connection
            .negotiated_key_exchange_group()
            .map(|group| group.name())
            != Some(NamedGroup::X25519MLKEM768)
        || connection.handshake_kind() != Some(rustls::HandshakeKind::Full)
        || connection
            .peer_certificates()
            .is_none_or(|certs| certs.is_empty())
    {
        return Err(
            "standard TLS diagnostic did not establish the required authenticated handshake".into(),
        );
    }
    println!(
        "TLS_STANDARD_PEER_OK version=TLS1.3 group=X25519MLKEM768 fresh=true peer_certificate=true"
    );
    Ok(())
}
fn timeouts(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(())
}
fn serve(directory: &Path) -> Result<()> {
    let (certificates, key) = identity(directory, "server")?;
    let server = MutualTlsServer::new(roots(directory, "client")?, certificates, key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    println!("LISTEN {}", listener.local_addr()?);
    std::io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    };
    // BSD/macOS accept can inherit the listener's nonblocking status. The
    // diagnostic uses blocking rustls I/O with explicit socket/process deadlines.
    socket.set_nonblocking(false)?;
    timeouts(&socket)?;
    let mut stream = StreamOwned::new(server.accept()?, socket);
    let mut request = [0; 5];
    stream.read_exact(&mut request)?;
    if &request != b"PING\n" {
        return Err("unexpected diagnostic request".into());
    }
    observed(&stream.conn)?;
    stream.write_all(b"QPERIAPT_STANDARD_TLS_OK\n")?;
    stream.conn.send_close_notify();
    stream.flush()?;
    Ok(())
}
fn connect(directory: &Path, address: &str, server_name: &str) -> Result<()> {
    let address: SocketAddr = address.parse()?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("diagnostic accepts only a loopback endpoint".into());
    }
    let (certificates, key) = identity(directory, "client")?;
    let client = MutualTlsClient::new(roots(directory, "server")?, certificates, key)?;
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    timeouts(&socket)?;
    let mut stream = StreamOwned::new(
        client.connect(ServerName::try_from(server_name.to_owned())?)?,
        socket,
    );
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    stream.flush()?;
    let mut response = DiagnosticResponse(Vec::new());
    (&mut stream).take(65_537).read_to_end(&mut response.0)?;
    if response.0.len() > 65_536 || !response.0.starts_with(b"HTTP/1.0 200 ok\r\n") {
        return Err("invalid independent-peer HTTP diagnostic response".into());
    }
    observed(&stream.conn)?;
    // OpenSSL's diagnostic page may contain session material. Do not print it.
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, directory] if mode == "fixtures" => fixtures(Path::new(directory)),
        [mode, directory] if mode == "server" => serve(Path::new(directory)),
        [mode, directory, address, server_name] if mode == "client" => {
            connect(Path::new(directory), address, server_name)
        }
        _ => Err(
            "usage: standard_peer fixtures DIR | server DIR | client DIR LOOPBACK:PORT SERVER_NAME"
                .into(),
        ),
    }
}
