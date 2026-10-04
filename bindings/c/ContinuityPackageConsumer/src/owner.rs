// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original protected installation opened with independently retained public pins.
//! This consumer configuration does not provision or infer trust from a bundle.
use crate::{Failure, Result};
use p::connection_transport::{Actor, Cancellation, ConnectionEndpoint, Run, RunLimits};
use q_periapt_continuity_identity_candidate as p;
use q_periapt_host_store::{filesystem::OwnedPrivateDirectory, PolicyStore};
use q_periapt_rustls::connection::{Credentials, Limits};
use std::{
    io::{self, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub(crate) fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}
pub(crate) fn read(
    directory: &OwnedPrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>> {
    let file = directory
        .open_config_file(name, maximum)
        .map_err(Failure::configuration)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum).map_err(Failure::configuration)? + 1)
        .read_to_end(&mut bytes)
        .map_err(Failure::configuration)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Failure::argument());
    }
    Ok(bytes)
}
pub(crate) fn array<const N: usize>(
    directory: &OwnedPrivateDirectory,
    name: &str,
) -> Result<[u8; N]> {
    read(directory, name, N)?
        .try_into()
        .map_err(|_| Failure::argument())
}
pub(crate) fn private_bytes(
    directory: &OwnedPrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = directory
        .open_config_file(name, maximum)
        .map_err(Failure::configuration)?;
    // Partial reads are erased on failure too, before a secret owner is returned.
    let capacity = maximum.checked_add(1).ok_or_else(Failure::argument)?;
    let mut bytes = Zeroizing::new(vec![0; capacity]);
    let mut length = 0;
    while length < capacity {
        let count = file
            .read(bytes.get_mut(length..).ok_or_else(Failure::argument)?)
            .map_err(Failure::configuration)?;
        if count == 0 {
            break;
        }
        length += count;
    }
    if length == 0 || length > maximum {
        return Err(Failure::argument());
    }
    bytes.truncate(length);
    Ok(bytes)
}
pub(crate) fn account(
    directory: &OwnedPrivateDirectory,
    label: &str,
    family: [u8; 32],
) -> Result<p::AccountPin> {
    Ok(p::AccountPin::new(
        array(directory, &format!("{label}-account"))?,
        p::PublicKey::decode(&read(directory, &format!("{label}-root"), 8192)?)?,
        p::RosterCheckpoint::from_trusted_state(
            u64::from_be_bytes(array(directory, &format!("{label}-roster-version"))?),
            array(directory, &format!("{label}-roster-digest"))?,
        )?,
        family,
    )?)
}

pub(crate) fn configured_policy(
    path: &Path,
    directory: &OwnedPrivateDirectory,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(PolicyStore, Arc<p::VerifiedSessionPolicy>, [u8; 32])> {
    let store = PolicyStore::open_configured(
        &path.join("sdk.redb"),
        &read(directory, "sdk-policy", 4096)?,
        &read(directory, "sdk-signature", 8192)?,
        &read(directory, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    crate::opening::check(cancel, deadline)?;
    let (pin, family) = configured_policy_pin(directory)?;
    let policy = Arc::new(pin.verify(
        &read(directory, "protocol-policy", 8192)?,
        store.runtime()?,
        now().map_err(Failure::configuration)?,
    )?);
    crate::opening::check(cancel, deadline)?;
    Ok((store, policy, family))
}

fn configured_policy_pin(directory: &OwnedPrivateDirectory) -> Result<(p::PolicyPin, [u8; 32])> {
    let family = array(directory, "family")?;
    let pin = p::PolicyPin::new(
        family,
        p::PublicKey::decode(&read(directory, "policy-root", 8192)?)?,
        p::PolicyCheckpoint::from_trusted_state(
            u64::from_be_bytes(array(directory, "policy-version")?),
            array(directory, "policy-digest")?,
        )?,
    )?;
    Ok((pin, family))
}
// Signature-verified original metadata only: no SDK runtime or current-time
// substitution. The native original enrollment checks its durable policy digest.
pub(crate) fn configured_historical_policy(
    path: &Path,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<p::HistoricalSessionPolicy> {
    crate::opening::check(cancel, deadline)?;
    let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
    let (pin, _) = configured_policy_pin(&directory)?;
    let policy = pin.verify_historical(&read(&directory, "protocol-policy", 8192)?)?;
    crate::opening::check(cancel, deadline)?;
    Ok(policy)
}

pub(crate) enum Admission {
    Bootstrap(p::PrekeyQuality),
    Existing {
        quality: p::PrekeyQuality,
        session: [u8; 32],
    },
}
impl Admission {
    pub(crate) fn quality(&self) -> p::PrekeyQuality {
        match self {
            Self::Bootstrap(quality) | Self::Existing { quality, .. } => *quality,
        }
    }
}

/// One original local installation, never a reconstructed policy permission.
pub(crate) struct Owner {
    listener: Option<TcpListener>,
    native: crate::native_owner::NativeOwner,
    pub(crate) context: Arc<p::BootstrapContext>,
    policy_store: PolicyStore,
    certificate: Vec<u8>,
    tls_key: Zeroizing<Vec<u8>>,
    peer_certificate: Vec<u8>,
    pub(crate) peer_name: String,
}

/// Borrow one service and one peer for the original native operations. Neither
/// this view nor a peer child owns or closes another service's private owners.
pub(crate) struct Operation<'a> {
    pub(crate) listener: &'a mut Option<TcpListener>,
    pub(crate) service: &'a mut p::DeviceService,
    pub(crate) signer: &'a p::DeviceSigningKey,
    pub(crate) context: &'a Arc<p::BootstrapContext>,
    pub(crate) certificate: &'a [u8],
    pub(crate) tls_key: &'a [u8],
    pub(crate) peer_certificate: &'a [u8],
    pub(crate) peer_name: &'a str,
}
impl Owner {
    pub(crate) fn open(
        path: &Path,
        admission: Admission,
        witness: Option<crate::witness::Configuration>,
        cancel: Cancellation,
        invocation: crate::invocation::Scope,
        deadline: Instant,
    ) -> Result<Self> {
        crate::opening::check(&cancel, deadline)?;
        let paths = p::InstallationPaths::new(
            &path.join("installation.redb"),
            &path.join("journal.redb"),
            &path.join("archives.redb"),
        )?;
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let (policy_store, policy, family) =
            configured_policy(path, &directory, &cancel, deadline)?;
        let initiator = account(&directory, "initiator", family)?;
        let responder = account(&directory, "responder", family)?;
        let bundle = p::BootstrapBundle::from_bytes(&read(
            &directory,
            "bootstrap.bundle",
            p::MAX_BOOTSTRAP_BUNDLE_BYTES,
        )?)?;
        let required = p::BootstrapRequirements {
            initiator: p::ExpectedDevice::new(
                &initiator,
                array(&directory, "initiator-device")?,
                u64::from_be_bytes(array(&directory, "initiator-generation")?),
            )?,
            responder: p::ExpectedDevice::new(
                &responder,
                array(&directory, "responder-device")?,
                u64::from_be_bytes(array(&directory, "responder-generation")?),
            )?,
            quality: admission.quality(),
            directory: p::DirectoryExpectation::from_trusted_state(array(
                &directory,
                "directory",
            )?)?,
        };
        let role = match array(&directory, "role")? {
            [1] => p::BootstrapRole::Initiator,
            [2] => p::BootstrapRole::Responder,
            _ => return Err(Failure::argument()),
        };
        enum Verified {
            Bootstrap(Arc<p::BootstrapContext>),
            Existing(p::SessionReopenRequest),
        }
        let verified = match admission {
            Admission::Bootstrap(_) => Verified::Bootstrap(Arc::new(bundle.verify(
                policy,
                required,
                now().map_err(Failure::configuration)?,
            )?)),
            Admission::Existing { session, .. } => Verified::Existing(bundle.request_reopen(
                policy,
                required,
                role,
                session,
                now().map_err(Failure::configuration)?,
            )?),
        };
        crate::opening::check(&cancel, deadline)?;
        let key = p::JournalKey::open(&path.join("wrap.key"))?;
        let signer = p::DeviceSigningKey::open(
            &path.join("signer.key"),
            &key,
            p::SigningKeyId::from_trusted_state(array(&directory, "signer-id")?)?,
        )?;
        crate::opening::check(&cancel, deadline)?;
        // Witness choice is explicit for both admission paths; failure never
        // retries under a different profile or constructs replacement state.
        let make_anchor = || {
            witness
                .map(|configured| configured.client(path, cancel.clone(), invocation))
                .transpose()
        };
        let (service, context) = match verified {
            Verified::Bootstrap(context) => {
                let device = context.device(role);
                let installation = p::DeviceInstallation::open(
                    paths,
                    &key,
                    device,
                    context.policy(),
                    now().map_err(Failure::configuration)?,
                )?;
                let anchor = make_anchor()?;
                crate::opening::check(&cancel, deadline)?;
                let service = installation.activate(
                    key,
                    device,
                    context.policy(),
                    now().map_err(Failure::configuration)?,
                    anchor,
                )?;
                (service, context)
            }
            Verified::Existing(request) => {
                let anchor = make_anchor()?;
                crate::opening::check(&cancel, deadline)?;
                p::DeviceInstallation::reopen_session(
                    paths,
                    key,
                    request,
                    now().map_err(Failure::configuration)?,
                    anchor,
                )?
                .into_parts()
            }
        };
        crate::opening::check(&cancel, deadline)?;
        let mut owner = Self {
            listener: None,
            native: crate::native_owner::NativeOwner::installed(service, signer),
            context,
            policy_store,
            certificate: read(&directory, "tls-cert", 8192)?,
            tls_key: private_bytes(&directory, "tls-key", 8192)?,
            peer_certificate: read(&directory, "tls-peer", 8192)?,
            peer_name: String::from_utf8(read(&directory, "tls-peer-name", 128)?)
                .map_err(Failure::configuration)?,
        };
        // Validate certificate/key/pin configuration before returning a handle.
        owner.operation()?.endpoint()?;
        crate::opening::check(&cancel, deadline)?;
        Ok(owner)
    }
    pub(crate) fn operation(&mut self) -> Result<Operation<'_>> {
        let (service, signer) = self.native.parts()?;
        Ok(Operation {
            listener: &mut self.listener,
            service,
            signer,
            context: &self.context,
            certificate: &self.certificate,
            tls_key: &self.tls_key,
            peer_certificate: &self.peer_certificate,
            peer_name: &self.peer_name,
        })
    }
    pub(crate) fn close(&mut self) {
        self.listener.take();
        self.native.close();
        self.context.policy().close();
        self.policy_store.close();
    }
}
impl Operation<'_> {
    fn credentials(&self) -> Credentials<'_> {
        Credentials {
            certificate: self.certificate,
            private_key: self.tls_key,
            peer_certificate: self.peer_certificate,
        }
    }
    fn tls_limits() -> Limits {
        Limits {
            max_connections: 1,
            handshake_ms: 10_000,
            request_ms: 10_000,
            idle_ms: 10_000,
        }
    }
    pub(crate) fn endpoint(&self) -> Result<ConnectionEndpoint> {
        Ok(ConnectionEndpoint::client(
            self.context,
            self.credentials(),
            Self::tls_limits(),
        )?)
    }
    pub(crate) fn control(
        &self,
        session: [u8; 32],
    ) -> Result<p::control_transport::ControlEndpoint> {
        Ok(p::control_transport::ControlEndpoint::client(
            self.context,
            session,
            self.credentials(),
            Self::tls_limits(),
        )?)
    }
    pub(crate) fn server(&self) -> Result<ConnectionEndpoint> {
        Ok(ConnectionEndpoint::server(
            self.context,
            self.credentials(),
            Self::tls_limits(),
        )?)
    }
    pub(crate) fn control_server(
        &self,
        session: [u8; 32],
    ) -> Result<p::control_transport::ControlEndpoint> {
        Ok(p::control_transport::ControlEndpoint::server(
            self.context,
            session,
            self.credentials(),
            Self::tls_limits(),
        )?)
    }
    pub(crate) fn listen(&mut self, address: SocketAddr) -> Result<u16> {
        if self.listener.is_some() {
            return Err(p::Error::State.into());
        }
        self.server()?;
        let listener = TcpListener::bind(address).map_err(p::connection_transport::Error::Io)?;
        listener
            .set_nonblocking(true)
            .map_err(p::connection_transport::Error::Io)?;
        let port = listener
            .local_addr()
            .map_err(p::connection_transport::Error::Io)?
            .port();
        *self.listener = Some(listener);
        Ok(port)
    }
    pub(crate) fn accept(&self, cancel: &Cancellation, deadline: Instant) -> Result<TcpStream> {
        let listener = self.listener.as_ref().ok_or(p::Error::State)?;
        loop {
            if cancel.is_cancelled() {
                return Err(p::connection_transport::Error::Cancelled.into());
            }
            if Instant::now() >= deadline {
                return Err(p::connection_transport::Error::Deadline.into());
            }
            match listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(
                        Duration::from_millis(25)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(p::connection_transport::Error::Io(error).into()),
            }
        }
    }
    pub(crate) fn actor(&mut self) -> Result<Actor<'_>> {
        let (journal, archives) = self.service.stores()?;
        Ok(Actor {
            journal,
            archives,
            context: self.context,
            signer: self.signer,
        })
    }
}

pub(crate) fn serve_limits(deadline: Instant) -> RunLimits {
    RunLimits {
        exchanges: 8,
        timeout: Duration::from_secs(20),
        connect_timeout: Duration::from_secs(1),
        outer_deadline: Some(deadline),
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) fn run<'a>(
    address: SocketAddr,
    name: &'a str,
    cancel: &'a Cancellation,
    deadline: Instant,
) -> Run<'a> {
    Run {
        address,
        server_name: name,
        cancel,
        limits: RunLimits {
            exchanges: 8,
            timeout: Duration::from_secs(20),
            connect_timeout: Duration::from_secs(1),
            outer_deadline: Some(deadline),
        },
    }
}
