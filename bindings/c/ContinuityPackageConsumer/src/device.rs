// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One original device service and independently admitted public peer children.
use super::*;
use owner::{array, now, read};
use q_periapt_host_store::{filesystem::OwnedPrivateDirectory, PolicyStore};
use std::{net::TcpListener, sync::atomic::AtomicBool};
use zeroize::Zeroizing;

struct Device {
    service: p::DeviceService,
    signer: p::DeviceSigningKey,
    policy: Arc<p::VerifiedSessionPolicy>,
    policy_store: PolicyStore,
    family: [u8; 32],
    certificate: Vec<u8>,
    tls_key: Zeroizing<Vec<u8>>,
}
impl Drop for Device {
    fn drop(&mut self) {
        self.service.close();
        self.signer.close();
        self.policy.close();
        self.policy_store.close();
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
        opening::check(&cancel, deadline)?;
        let directory = OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let (policy_store, policy, family) =
            owner::configured_policy(path, &directory, &cancel, deadline)?;
        let account = owner::account(&directory, "local", family)?;
        let device = account.verify_device(
            &read(&directory, "local-certificate", 8192)?,
            &read(&directory, "local-roster", 65_536)?,
            now().map_err(Failure::configuration)?,
        )?;
        if device.device_id() != array(&directory, "local-device")?
            || device.generation() != u64::from_be_bytes(array(&directory, "local-generation")?)
        {
            return Err(p::Error::Scope.into());
        }
        opening::check(&cancel, deadline)?;
        let key = p::JournalKey::open(&path.join("wrap.key"))?;
        let signer = p::DeviceSigningKey::open(
            &path.join("signer.key"),
            &key,
            p::SigningKeyId::from_trusted_state(array(&directory, "signer-id")?)?,
        )?;
        signer.check_device(&device)?;
        let paths = p::InstallationPaths::new(
            &path.join("installation.redb"),
            &path.join("journal.redb"),
            &path.join("archives.redb"),
        )?;
        let mut installation = p::DeviceInstallation::open(
            paths,
            &key,
            &device,
            &policy,
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
            &device,
            &policy,
            now().map_err(Failure::configuration)?,
            anchor,
        )?;
        let device = Device {
            service,
            signer,
            policy,
            policy_store,
            family,
            certificate: read(&directory, "tls-cert", 8192)?,
            tls_key: owner::private_bytes(&directory, "tls-key", 8192)?,
        };
        opening::check(&cancel, deadline)?;
        Ok(Arc::new(Self {
            device: Mutex::new(Some(device)),
            cancel,
            invocation,
            closed: AtomicBool::new(false),
        }))
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

    pub(crate) fn with_journal<T>(
        &self,
        deadline: Instant,
        action: impl FnOnce(&mut p::DeviceJournal) -> Result<T>,
    ) -> Result<T> {
        self.with_device(deadline, &self.cancel, |device| {
            action(device.service.stores()?.0)
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
            let initiator = owner::account(&directory, "initiator", device.family)?;
            let responder = owner::account(&directory, "responder", device.family)?;
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
            let bundle = p::BootstrapBundle::from_bytes(&read(
                &directory,
                "bootstrap.bundle",
                p::MAX_BOOTSTRAP_BUNDLE_BYTES,
            )?)?;
            opening::check(cancel, deadline)?;
            let time = now().map_err(Failure::configuration)?;
            let context = match admission {
                owner::Admission::Bootstrap(_) => {
                    let context =
                        Arc::new(bundle.verify(Arc::clone(&device.policy), required, time)?);
                    Arc::clone(device.service.admit_peer(context, role, time)?.context())
                }
                owner::Admission::Existing { session, .. } => {
                    let request = bundle.request_reopen(
                        Arc::clone(&device.policy),
                        required,
                        role,
                        session,
                        time,
                    )?;
                    Arc::clone(device.service.reopen_peer(request, time)?.context())
                }
            };
            let mut peer = Self {
                parent: Arc::clone(&parent),
                context,
                listener: None,
                certificate: read(&directory, "tls-peer", 8192)?,
                name: String::from_utf8(read(&directory, "tls-peer-name", 128)?)
                    .map_err(Failure::configuration)?,
            };
            // No child is published before exact TLS credentials and peer pin pass.
            peer.operation(device).endpoint()?;
            Ok(peer)
        })
    }

    fn operation<'a>(&'a mut self, device: &'a mut Device) -> owner::Operation<'a> {
        owner::Operation {
            listener: &mut self.listener,
            service: &mut device.service,
            signer: &device.signer,
            context: &self.context,
            certificate: &device.certificate,
            tls_key: &device.tls_key,
            peer_certificate: &self.certificate,
            peer_name: &self.name,
        }
    }

    pub(crate) fn with_operation<T>(
        &mut self,
        deadline: Instant,
        cancel: &Cancellation,
        action: impl FnOnce(&mut owner::Operation<'_>, &Cancellation) -> Result<T>,
    ) -> Result<T> {
        let parent = Arc::clone(&self.parent);
        parent.with_device(deadline, cancel, |device| {
            action(&mut self.operation(device), cancel)
        })
    }
}
