// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One original device service and independently admitted public peer children.
use super::*;
use owner::{array, now, read};
use q_periapt_host_store::{filesystem::OwnedPrivateDirectory, PolicyStore};
use std::{net::TcpListener, sync::atomic::AtomicBool};
use zeroize::Zeroizing;

pub(crate) struct Authority {
    pub(crate) identity: p::VerifiedDevice,
    signer: p::DeviceSigningKey,
    pub(crate) environment: Environment,
}
pub(crate) struct Environment {
    pub(crate) authority: PolicyAuthority,
    pub(crate) original_policy: Option<p::HistoricalSessionPolicy>,
    certificate: Vec<u8>,
    tls_key: Zeroizing<Vec<u8>>,
}
pub(crate) struct PolicyAuthority {
    pub(crate) policy: Arc<p::VerifiedSessionPolicy>,
    policy_store: PolicyStore,
    pub(crate) family: [u8; 32],
}
impl Drop for PolicyAuthority {
    fn drop(&mut self) {
        self.policy.close();
        self.policy_store.close();
    }
}
struct Device {
    native: native_owner::NativeOwner,
    environment: Environment,
    identity: p::VerifiedDevice,
}
impl Drop for Device {
    fn drop(&mut self) {
        self.native.close();
    }
}

pub(crate) fn paths(path: &Path) -> Result<p::InstallationPaths> {
    Ok(p::InstallationPaths::new(
        &path.join("installation.redb"),
        &path.join("journal.redb"),
        &path.join("archives.redb"),
    )?)
}

impl Authority {
    pub(crate) fn load(
        path: &Path,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(Self, p::JournalKey)> {
        opening::check(cancel, deadline)?;
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let environment = Environment::load(path, cancel, deadline)?;
        let account = owner::account(&directory, "local", environment.authority.family)?;
        let identity = account.verify_device(
            &read(&directory, "local-certificate", 8192)?,
            &read(&directory, "local-roster", 65_536)?,
            now().map_err(Failure::configuration)?,
        )?;
        if identity.device_id() != array(&directory, "local-device")?
            || identity.generation() != u64::from_be_bytes(array(&directory, "local-generation")?)
        {
            return Err(p::Error::Scope.into());
        }
        opening::check(cancel, deadline)?;
        let key = p::JournalKey::open(&path.join("wrap.key"))?;
        let signer = p::DeviceSigningKey::open(
            &path.join("signer.key"),
            &key,
            p::SigningKeyId::from_trusted_state(array(&directory, "signer-id")?)?,
        )?;
        signer.check_device(&identity)?;
        let authority = Self {
            identity,
            signer,
            environment,
        };
        opening::check(cancel, deadline)?;
        Ok((authority, key))
    }
}

impl Environment {
    pub(crate) fn load(path: &Path, cancel: &Cancellation, deadline: Instant) -> Result<Self> {
        let authority = PolicyAuthority::load(path, cancel, deadline)?;
        Self::from_policy(path, authority, cancel, deadline)
    }
    pub(crate) fn from_policy(
        path: &Path,
        authority: PolicyAuthority,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        opening::check(cancel, deadline)?;
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let value = Self {
            authority,
            original_policy: None,
            certificate: read(&directory, "tls-cert", 8192)?,
            tls_key: owner::private_bytes(&directory, "tls-key", 8192)?,
        };
        opening::check(cancel, deadline)?;
        Ok(value)
    }
}
impl PolicyAuthority {
    pub(crate) fn from_supplied(
        source: &mut crate::first_install::SuppliedPolicy,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        let (policy_store, policy) = source.take_current(cancel, deadline)?;
        Ok(Self {
            family: policy.family(),
            policy_store,
            policy,
        })
    }
    pub(crate) fn from_pinned_input(
        path: &Path,
        pin: &p::PolicyPin,
        wire: &[u8],
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        opening::check(cancel, deadline)?;
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let policy_store = owner::configured_sdk_store(path, &directory)?;
        opening::check(cancel, deadline)?;
        let policy = Arc::new(pin.verify(
            wire,
            policy_store.runtime()?,
            now().map_err(Failure::configuration)?,
        )?);
        let result = Self {
            family: policy.family(),
            policy,
            policy_store,
        };
        opening::check(cancel, deadline)?;
        Ok(result)
    }
    pub(crate) fn load(path: &Path, cancel: &Cancellation, deadline: Instant) -> Result<Self> {
        opening::check(cancel, deadline)?;
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let (policy_store, policy, family) =
            owner::configured_policy(path, &directory, cancel, deadline)?;
        Ok(Self {
            policy_store,
            policy,
            family,
        })
    }
}

/// Child references pin this control object, not independent storage leases.
/// Explicit parent close removes the actual device even if idle children remain.
pub(crate) struct Shared {
    device: Mutex<Option<Device>>,
    cancel: Cancellation,
    invocation: invocation::Scope,
    closed: AtomicBool,
}
impl Shared {
    pub(crate) fn open(
        path: &Path,
        witness: Option<witness::Configuration>,
        cancel: Cancellation,
        invocation: invocation::Scope,
        deadline: Instant,
    ) -> Result<Arc<Self>> {
        let (authority, key) = Authority::load(path, &cancel, deadline)?;
        let mut installation = p::DeviceInstallation::open(
            paths(path)?,
            &key,
            &authority.identity,
            &authority.environment.authority.policy,
            now().map_err(Failure::configuration)?,
        )?;
        // Operational restart never creates children or activates a creation intent.
        if installation.status()? != p::InstallationStatus::Active {
            return Err(p::DurableError::Conflict.into());
        }
        let anchor = witness
            .map(|configured| configured.client(path, cancel.clone(), invocation.clone()))
            .transpose()?;
        opening::check(&cancel, deadline)?;
        let service = installation.activate(
            key,
            &authority.identity,
            &authority.environment.authority.policy,
            now().map_err(Failure::configuration)?,
            anchor,
        )?;
        opening::check(&cancel, deadline)?;
        Ok(Self::from_parts(service, authority, cancel, invocation))
    }

    pub(crate) fn from_parts(
        service: p::DeviceService,
        authority: Authority,
        cancel: Cancellation,
        invocation: invocation::Scope,
    ) -> Arc<Self> {
        Self::from_native(
            native_owner::NativeOwner::installed(service, authority.signer),
            authority.environment,
            authority.identity,
            cancel,
            invocation,
        )
    }

    pub(crate) fn from_enrolled(
        mut owner: p::EnrolledDevice,
        environment: Environment,
        cancel: Cancellation,
        invocation: invocation::Scope,
    ) -> Result<Arc<Self>> {
        let identity = owner.parts()?.2.clone();
        Ok(Self::from_native(
            native_owner::NativeOwner::enrolled(owner),
            environment,
            identity,
            cancel,
            invocation,
        ))
    }

    fn from_native(
        native: native_owner::NativeOwner,
        environment: Environment,
        identity: p::VerifiedDevice,
        cancel: Cancellation,
        invocation: invocation::Scope,
    ) -> Arc<Self> {
        Arc::new(Self {
            device: Mutex::new(Some(Device {
                native,
                environment,
                identity,
            })),
            cancel,
            invocation,
            closed: AtomicBool::new(false),
        })
    }

    fn with_device<T>(
        &self,
        deadline: Instant,
        cancel: &Cancellation,
        action: impl FnOnce(&mut Device) -> Result<T>,
    ) -> Result<T> {
        if self.closed.load(Ordering::Acquire) {
            return Err(failure(2));
        }
        opening::check(&self.cancel, deadline)?;
        opening::check(cancel, deadline)?;
        let mut locked = match self.device.try_lock() {
            Ok(locked) => locked,
            Err(TryLockError::WouldBlock) => return Err(failure(3)),
            Err(TryLockError::Poisoned(error)) => {
                self.closed.store(true, Ordering::Release);
                self.cancel.cancel();
                error.into_inner().take();
                return Err(failure(5));
            }
        };
        let device = locked.as_mut().ok_or_else(|| failure(2))?;
        let _active = self.invocation.enter(deadline, cancel)?;
        // Closes the race with parent cancellation before this scope was entered.
        opening::check(&self.cancel, deadline)?;
        opening::check(cancel, deadline)?;
        let result = action(device)?;
        opening::check(&self.cancel, deadline)?;
        opening::check(cancel, deadline)?;
        Ok(result)
    }

    pub(crate) fn close(&self) -> Result<bool> {
        let (mut locked, poisoned) = match self.device.try_lock() {
            Ok(locked) => (locked, false),
            Err(TryLockError::WouldBlock) => return Err(failure(3)),
            Err(TryLockError::Poisoned(error)) => (error.into_inner(), true),
        };
        self.cancel.cancel();
        self.closed.store(true, Ordering::Release);
        locked.take();
        Ok(poisoned)
    }

    pub(crate) fn admit_peer_roster(
        &self,
        deadline: Instant,
        wire: &[u8],
        pin: &p::AccountPin,
    ) -> Result<p::RosterCheckpoint> {
        self.with_device(deadline, &self.cancel, |device| {
            let policy = Arc::clone(&device.environment.authority.policy);
            let roster = pin.verify_roster(wire, now().map_err(Failure::configuration)?)?;
            opening::check(&self.cancel, deadline)?;
            Ok(device.native.parts()?.0.admit_peer_roster(
                &roster,
                &policy,
                now().map_err(Failure::configuration)?,
            )?)
        })
    }

    pub(crate) fn admit_peer_credential_renewal(
        &self,
        deadline: Instant,
        wire: &[u8],
        pin: &p::AccountPin,
        operation: p::CredentialRenewalId,
    ) -> Result<p::RosterCheckpoint> {
        self.with_device(deadline, &self.cancel, |device| {
            let policy = Arc::clone(&device.environment.authority.policy);
            let grant = p::VerifiedCredentialRenewal::verify(
                wire,
                pin,
                device.environment.original_policy.as_ref().map_or_else(
                    || policy.checkpoint().digest(),
                    |original| original.checkpoint().digest(),
                ),
                now().map_err(Failure::configuration)?,
            )?;
            opening::check(&self.cancel, deadline)?;
            Ok(device.native.parts()?.0.admit_peer_credential_renewal(
                &grant,
                operation,
                &policy,
                now().map_err(Failure::configuration)?,
            )?)
        })
    }

    pub(crate) fn prepare_publication(
        &self,
        deadline: Instant,
        id: p::PrekeyPublicationId,
        plan: &p::PrekeyPublicationPlan,
    ) -> Result<p::PreparedPrekeyPublication> {
        self.with_device(deadline, &self.cancel, |device| {
            device.native.prepare_publication(
                id,
                plan,
                &device.environment.authority.policy,
                &device.identity,
                p::PrekeyPublicationRun {
                    cancel: &self.cancel,
                    deadline,
                },
            )
        })
    }

    pub(crate) fn abandon_publication(
        &self,
        deadline: Instant,
        id: p::PrekeyPublicationId,
        intent: [u8; 32],
    ) -> Result<p::PrekeyPublicationStatus> {
        self.with_device(deadline, &self.cancel, |device| {
            Ok(device
                .native
                .parts()?
                .0
                .stores()?
                .0
                .abandon_prekey_publication(id, intent, &device.environment.authority.policy)?)
        })
    }

    pub(crate) fn with_journal<T>(
        &self,
        deadline: Instant,
        action: impl FnOnce(&mut p::DeviceJournal) -> Result<T>,
    ) -> Result<T> {
        self.with_device(deadline, &self.cancel, |device| {
            action(device.native.parts()?.0.stores()?.0)
        })
    }
}

pub(crate) fn parent(handle: u64, deadline: Instant) -> Result<Arc<Shared>> {
    let entry = entry(handle)?;
    opening::check(&entry.cancel, deadline)?;
    let locked = match entry.owner.try_lock() {
        Ok(locked) => locked,
        Err(TryLockError::WouldBlock) => return Err(failure(3)),
        Err(TryLockError::Poisoned(_)) => return Err(failure(5)),
    };
    match locked.as_ref() {
        Some(Owned::Device(device)) => Ok(Arc::clone(device)),
        None => Err(failure(2)),
        _ => Err(failure(6)),
    }
}

pub(crate) struct Peer {
    parent: Arc<Shared>,
    context: Arc<p::BootstrapContext>,
    listener: Option<TcpListener>,
    certificate: Vec<u8>,
    name: String,
}
impl Peer {
    pub(crate) fn belongs_to(&self, parent: &Arc<Shared>) -> bool {
        Arc::ptr_eq(&self.parent, parent)
    }

    pub(crate) fn context(&self) -> &Arc<p::BootstrapContext> {
        &self.context
    }

    pub(crate) fn open(
        parent: Arc<Shared>,
        path: &Path,
        admission: owner::Admission,
        role: p::BootstrapRole,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        parent.with_device(deadline, cancel, |device| {
            let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
            let material = crate::peer_configuration::Material::from_directory(
                &directory,
                device.environment.authority.family,
            )?;
            Self::admit(&parent, device, material, admission, role, cancel, deadline)
        })
    }

    pub(crate) fn open_supplied(
        parent: Arc<Shared>,
        material: crate::peer_configuration::Material,
        admission: owner::Admission,
        role: p::BootstrapRole,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        parent.with_device(deadline, cancel, |device| {
            Self::admit(&parent, device, material, admission, role, cancel, deadline)
        })
    }

    fn admit(
        parent: &Arc<Shared>,
        device: &mut Device,
        material: crate::peer_configuration::Material,
        admission: owner::Admission,
        role: p::BootstrapRole,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        if material.family != device.environment.authority.family {
            return Err(p::Error::Scope.into());
        }
        let required = material.requirements(admission.quality())?;
        let bundle = &material.bundle;
        opening::check(cancel, deadline)?;
        let time = now().map_err(Failure::configuration)?;
        let context = match admission {
            owner::Admission::Bootstrap(_) => {
                if device.environment.original_policy.is_some() {
                    return Err(p::Error::PolicyDenied.into());
                }
                let context = Arc::new(bundle.verify(
                    Arc::clone(&device.environment.authority.policy),
                    required,
                    time,
                )?);
                Arc::clone(
                    device
                        .native
                        .parts()?
                        .0
                        .admit_peer(context, role, time)?
                        .context(),
                )
            }
            owner::Admission::Existing { session, .. } => {
                let peer = if let Some(original) = &device.environment.original_policy {
                    let request = bundle.request_historical_reopen(
                        Arc::new(original.clone()),
                        required,
                        role,
                        session,
                        time,
                    )?;
                    device.native.parts()?.0.reopen_continued_peer(
                        request,
                        Arc::clone(&device.environment.authority.policy),
                        time,
                    )?
                } else {
                    device.native.parts()?.0.reopen_peer_bundle(
                        bundle,
                        Arc::clone(&device.environment.authority.policy),
                        required,
                        role,
                        session,
                        time,
                    )?
                };
                Arc::clone(peer.context())
            }
        };
        let mut peer = Self {
            parent: Arc::clone(parent),
            context,
            listener: None,
            certificate: material.certificate,
            name: material.name,
        };
        // No child is published before exact TLS credentials and peer pin pass.
        peer.operation(device)?.endpoint()?;
        Ok(peer)
    }

    fn operation<'a>(&'a mut self, device: &'a mut Device) -> Result<owner::Operation<'a>> {
        let (service, signer) = device.native.parts()?;
        Ok(owner::Operation {
            listener: &mut self.listener,
            service,
            signer,
            context: &self.context,
            certificate: &device.environment.certificate,
            tls_key: &device.environment.tls_key,
            peer_certificate: &self.certificate,
            peer_name: &self.name,
        })
    }

    pub(crate) fn with_operation<T>(
        &mut self,
        deadline: Instant,
        cancel: &Cancellation,
        action: impl FnOnce(&mut owner::Operation<'_>, &Cancellation) -> Result<T>,
    ) -> Result<T> {
        let parent = Arc::clone(&self.parent);
        parent.with_device(deadline, cancel, |device| {
            action(&mut self.operation(device)?, cancel)
        })
    }
}
