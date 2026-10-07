// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit original installation setup; enrollment and operational owners stay separate.
use super::*;
use std::path::PathBuf;

#[repr(C)]
pub struct Status {
    pub phase: u32,
    pub journal: [u8; 32],
}

#[repr(C)]
pub struct Preparation {
    pub protection: u32,
    pub journal: [u8; 32],
    pub subject: [u8; 96],
    pub image_digest: [u8; 32],
}
impl Preparation {
    pub(crate) fn from_native(
        journal: [u8; 32],
        prepared: p::InstallationPreparation,
    ) -> Result<Self> {
        Ok(match prepared {
            p::InstallationPreparation::Local => Self {
                protection: 1,
                journal,
                subject: [0; 96],
                image_digest: [0; 32],
            },
            p::InstallationPreparation::RequiresEnrollment(genesis) => Self {
                protection: 2,
                journal,
                subject: genesis
                    .subject()
                    .to_bytes()
                    .try_into()
                    .map_err(|_| failure(5))?,
                image_digest: genesis.image_digest(),
            },
        })
    }
}

pub(crate) struct Owner {
    path: PathBuf,
    installation: p::DeviceInstallation,
    authority: device::Authority,
    witness: Option<witness::Configuration>,
}
impl Owner {
    pub(crate) fn open(
        path: &Path,
        create: bool,
        witness: Option<witness::Configuration>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Box<Self>> {
        let (authority, key) = device::Authority::load(path, cancel, deadline)?;
        opening::check(cancel, deadline)?;
        let time = owner::now().map_err(Failure::configuration)?;
        // No open failure is interpreted as permission to create a new lineage.
        let installation = if create {
            p::DeviceInstallation::provision(
                device::paths(path)?,
                &key,
                &authority.identity,
                &authority.environment.authority.policy,
                time,
            )?
        } else {
            p::DeviceInstallation::open(
                device::paths(path)?,
                &key,
                &authority.identity,
                &authority.environment.authority.policy,
                time,
            )?
        };
        let result = Box::new(Self {
            path: path.into(),
            installation,
            authority,
            witness,
        });
        opening::check(cancel, deadline)?;
        Ok(result)
    }

    fn status(&mut self) -> Result<Status> {
        let phase = match self.installation.status()? {
            p::InstallationStatus::Creating => 1,
            p::InstallationStatus::Active => 2,
        };
        Ok(Status {
            phase,
            journal: *self.installation.identity()?.as_bytes(),
        })
    }

    fn prepare(&mut self, cancel: &Cancellation, deadline: Instant) -> Result<Preparation> {
        opening::check(cancel, deadline)?;
        let key = p::JournalKey::open(&self.path.join("wrap.key"))?;
        let journal = *self.installation.identity()?.as_bytes();
        opening::check(cancel, deadline)?;
        let prepared = self.installation.prepare(
            key,
            &self.authority.identity,
            &self.authority.environment.authority.policy,
            owner::now().map_err(Failure::configuration)?,
        )?;
        let result = Preparation::from_native(journal, prepared)?;
        opening::check(cancel, deadline)?;
        Ok(result)
    }

    fn activate(self, entry: &Entry, deadline: Instant) -> Result<Arc<device::Shared>> {
        opening::check(&entry.cancel, deadline)?;
        let key = p::JournalKey::open(&self.path.join("wrap.key"))?;
        let anchor = self
            .witness
            .map(|configured| {
                configured.client(&self.path, entry.cancel.clone(), entry.invocation.clone())
            })
            .transpose()?;
        opening::check(&entry.cancel, deadline)?;
        let service = self.installation.activate(
            key,
            &self.authority.identity,
            &self.authority.environment.authority.policy,
            owner::now().map_err(Failure::configuration)?,
            anchor,
        )?;
        opening::check(&entry.cancel, deadline)?;
        Ok(device::Shared::from_parts(
            service,
            self.authority,
            entry.cancel.clone(),
            entry.invocation.clone(),
        ))
    }
}

/// Read the original durable installation identity and Creating/Active phase.
/// # Safety
/// Status and error are distinct aligned writable C records, with no concurrent writer.
#[no_mangle]
pub unsafe extern "C" fn qpc_setup_v1_status(
    handle: u64,
    status: *mut Status,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        let result = with_owned(handle, deadline, |owner, cancel| {
            opening::check(cancel, deadline)?;
            match owner {
                Owned::Setup(setup) => setup.status(),
                _ => Err(failure(6)),
            }
        })?;
        // SAFETY: exclusive validated output; meaningful only on success.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Prepare only original Creating children; release no operating service or witness grant.
/// # Safety
/// Preparation and error satisfy the header's aligned writable nonoverlapping contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_setup_v1_prepare_storage(
    handle: u64,
    preparation: *mut Preparation,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(preparation)?;
        let result = with_owned(handle, deadline, |owner, cancel| match owner {
            Owned::Setup(setup) => setup.prepare(cancel, deadline),
            _ => Err(failure(6)),
        })?;
        // SAFETY: exclusive validated output; failure never publishes preparation.
        unsafe { put(preparation, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Consume setup and convert the same known handle to a device parent after native activation.
/// # Safety
/// Error is a distinct aligned invocation-local writable diagnostic record.
#[no_mangle]
pub unsafe extern "C" fn qpc_setup_v1_activate(handle: u64, error: *mut ErrorRecord) -> i32 {
    let action = |deadline| {
        with_entry(handle, deadline, |slot, entry| {
            let setup = match slot.take() {
                Some(Owned::Setup(setup)) => setup,
                other => {
                    let code = if other.is_none() { 2 } else { 6 };
                    *slot = other;
                    return Err(failure(code));
                }
            };
            // Any admitted failure releases all partial leases/owners. Durable Active
            // may already exist; resume the same configuration to reconcile it.
            let device = setup.activate(entry, deadline)?;
            opening::check(&entry.cancel, deadline)?;
            *slot = Some(Owned::Device(device));
            Ok(())
        })
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
