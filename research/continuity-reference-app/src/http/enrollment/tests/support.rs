// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual loopback HTTP and real signatures from a software test authenticator.
use super::super::super::{router, Shared};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{auth::Service, enrollment::Invitation, store::Store};
use std::{
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use webauthn_rs::prelude::{Url, WebauthnBuilder};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[path = "../../../../tests/support/account_http.rs"]
mod account_http;
pub use account_http::{Client, Endpoint};
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub struct Server {
    endpoint: Endpoint,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl std::ops::Deref for Server {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint {
        &self.endpoint
    }
}
impl Server {
    pub async fn start(path: &Path, address: SocketAddr, create: bool) -> Result<Self> {
        Self::with_family(path, address, create, [42; 32]).await
    }
    pub async fn with_family(
        path: &Path,
        address: SocketAddr,
        create: bool,
        family: [u8; 32],
    ) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let host = format!("localhost:{}", address.port());
        let origin = format!("http://{host}");
        let db = path.join("accounts.redb");
        let store = if create {
            let mut store = Store::provision(&db, &origin)?;
            store.enable_enrollment(family)?;
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
            endpoint: Endpoint { address, origin },
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
