// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit original registration, borrowing the existing native transaction.
use super::*;
use q_periapt_host_store::filesystem::OwnedPrivateDirectory;
use std::{io, path::PathBuf};

#[repr(C)]
pub struct Intent {
    pub root: *const u8,
    pub root_length: usize,
    pub device: [u8; 16],
    pub generation: u64,
    pub family: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
}
pub(crate) struct Approved {
    native: p::EnrollmentIntent,
    family: [u8; 32],
}
impl Approved {
    pub(crate) unsafe fn read(pointer: *const Intent) -> Result<Self> {
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: immutable aligned intent and its root are live for preparation.
        let input = unsafe { &*pointer };
        let root = p::PublicKey::decode(&unsafe {
            bytes(input.root, input.root_length, p::PUBLIC_KEY_BYTES)
        }?)?;
        let description = p::DeviceDescription::new(
            input.device,
            input.generation,
            input.family,
            p::Validity::new(input.valid_from, input.valid_until)?,
        )?;
        Ok(Self {
            native: p::EnrollmentIntent::new(root, description),
            family: input.family,
        })
    }
}

#[repr(C)]
pub struct Checkpoint {
    pub version: u64,
    pub digest: [u8; 32],
}
impl Checkpoint {
    fn native(&self) -> Result<p::RosterCheckpoint> {
        Ok(p::RosterCheckpoint::from_trusted_state(
            self.version,
            self.digest,
        )?)
    }
    fn empty() -> Self {
        Self {
            version: 0,
            digest: [0; 32],
        }
    }
    fn observed(value: p::RosterCheckpoint) -> Self {
        Self {
            version: value.version(),
            digest: value.digest(),
        }
    }
}
#[repr(C)]
pub struct Pin {
    pub account: [u8; 32],
    pub root: *const u8,
    pub root_length: usize,
    pub family: [u8; 32],
    pub checkpoint: Checkpoint,
}
impl Pin {
    unsafe fn read(pointer: *const Self) -> Result<p::AccountPin> {
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Failure::argument());
        }
        // SAFETY: independently trusted immutable aligned pin and readable root.
        let input = unsafe { &*pointer };
        let root = p::PublicKey::decode(&unsafe {
            bytes(input.root, input.root_length, p::PUBLIC_KEY_BYTES)
        }?)?;
        Ok(p::AccountPin::new(
            input.account,
            root,
            input.checkpoint.native()?,
            input.family,
        )?)
    }
}
#[repr(C)]
pub struct Status {
    pub phase: u32,
    pub signing_id: [u8; 32],
    pub journal: [u8; 32],
    pub previous: Checkpoint,
    pub next: Checkpoint,
}
#[repr(C)]
pub struct RequestBytes {
    pub length: u32,
    pub bytes: [u8; 8192],
}

pub(crate) struct Owner {
    path: PathBuf,
    enrollment: p::DeviceEnrollment,
    family: [u8; 32],
    // Not loaded until an operation requires a live SDK/protocol policy.
    // Phase inspection and original request creation do not require TLS files.
    authority: Option<device::PolicyAuthority>,
    witness: Option<witness::Configuration>,
}
impl Owner {
    pub(crate) fn open(
        path: &Path,
        create: bool,
        approved: Approved,
        witness: Option<witness::Configuration>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        opening::check(cancel, deadline)?;
        let paths = p::EnrollmentPaths::new(
            &path.join("wrap.key"),
            &path.join("signer.key"),
            &path.join("enrollment.redb"),
            device::paths(path)?,
        )?;
        let enrollment = if create {
            p::DeviceEnrollment::provision(paths, approved.native)?
        } else {
            p::DeviceEnrollment::open(paths, approved.native)?
        };
        let result = Self {
            path: path.into(),
            enrollment,
            family: approved.family,
            authority: None,
            witness,
        };
        opening::check(cancel, deadline)?;
        Ok(result)
    }
    fn ensure_policy(&mut self, cancel: &Cancellation, deadline: Instant) -> Result<()> {
        if self.authority.is_none() {
            let authority = device::PolicyAuthority::load(&self.path, cancel, deadline)?;
            if authority.family != self.family {
                return Err(p::Error::Scope.into());
            }
            self.authority = Some(authority);
        }
        Ok(())
    }
    fn status(&mut self) -> Result<Status> {
        let status = self.enrollment.status()?;
        let signing_id = *self.enrollment.identity()?.as_bytes();
        let mut result = Status {
            phase: 0,
            signing_id,
            journal: [0; 32],
            previous: Checkpoint::empty(),
            next: Checkpoint::empty(),
        };
        let (phase, journal) = match status {
            p::EnrollmentStatus::Preparing => (1, None),
            p::EnrollmentStatus::Requested => (2, None),
            p::EnrollmentStatus::Accepted(id) => (3, Some(id)),
            p::EnrollmentStatus::Activating(id) => (4, Some(id)),
            p::EnrollmentStatus::Active(id) => (5, Some(id)),
            p::EnrollmentStatus::Refreshing {
                journal,
                previous,
                next,
            } => {
                result.previous = Checkpoint::observed(previous);
                result.next = Checkpoint::observed(next);
                (6, Some(journal))
            }
        };
        result.phase = phase;
        if let Some(journal) = journal {
            result.journal = *journal.as_bytes();
        }
        Ok(result)
    }
    fn activate(mut self, entry: &Entry, deadline: Instant) -> Result<Arc<device::Shared>> {
        self.ensure_policy(&entry.cancel, deadline)?;
        let authority = self.authority.take().ok_or_else(|| failure(5))?;
        let environment =
            device::Environment::from_policy(&self.path, authority, &entry.cancel, deadline)?;
        let now = owner::now().map_err(Failure::configuration)?;
        let anchor = if let Some(configured) = self.witness {
            let parameters = configured.parameters(
                &self.path,
                entry.cancel.clone(),
                entry.invocation.clone(),
            )?;
            Some(self.enrollment.anchor_client(
                &environment.authority.policy,
                now,
                parameters.pin,
                parameters.transport,
                parameters.timeout,
            )?)
        } else {
            None
        };
        opening::check(&entry.cancel, deadline)?;
        let enrolled = self.enrollment.activate(
            &environment.authority.policy,
            owner::now().map_err(Failure::configuration)?,
            anchor,
        )?;
        opening::check(&entry.cancel, deadline)?;
        Ok(device::Shared::from_enrolled(
            enrolled,
            environment,
            entry.cancel.clone(),
            entry.invocation.clone(),
        ))
    }
}

fn take_owner(slot: &mut Option<Owned>, entry: &Entry, deadline: Instant) -> Result<Box<Owner>> {
    // Closed/kind describe the actual retained resource, even after cancellation.
    // A live pre-cancelled owner stays in its slot until the caller closes it.
    match slot.as_ref() {
        None => return Err(failure(2)),
        Some(Owned::Enrollment(_)) => {}
        Some(_) => return Err(failure(6)),
    }
    opening::check(&entry.cancel, deadline)?;
    match slot.take() {
        Some(Owned::Enrollment(owner)) => Ok(owner),
        other => {
            *slot = other;
            Err(failure(5))
        }
    }
}

fn with_owner<T>(
    handle: u64,
    deadline: Instant,
    action: impl FnOnce(&mut Owner, &Cancellation) -> Result<T>,
) -> Result<T> {
    with_entry(handle, deadline, |slot, entry| {
        let mut owner = take_owner(slot, entry, deadline)?;
        // On any admitted failure the original transaction may have committed.
        // Drop every lease; only cancel/close remain until explicit resume.
        let result = action(&mut owner, &entry.cancel)?;
        opening::check(&entry.cancel, deadline)?;
        *slot = Some(Owned::Enrollment(owner));
        Ok(result)
    })
}

/// Explicit first-use wrapping key creation, never missing-active-key repair.
/// # Safety
/// Path and invocation-local error satisfy the header's pointer contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_provision_wrapping_key(
    path: *const u8,
    length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        // SAFETY: immutable caller path is copied before filesystem access.
        let text = unsafe { text(path, length, 4096) }?;
        let path = Path::new(&text);
        OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        for name in [
            "enrollment.redb",
            "signer.key",
            "installation.redb",
            "journal.redb",
            "archives.redb",
        ] {
            match std::fs::symlink_metadata(path.join(name)) {
                Ok(_) => return Err(p::DurableError::Conflict.into()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(Failure::configuration(error)),
            }
        }
        invocation::check(deadline)?;
        let _key = p::JournalKey::provision(&path.join("wrap.key"))?;
        invocation::check(deadline)
    };
    // SAFETY: forwarded writable diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Read authenticated registration progress; this grants no operational authority.
/// # Safety
/// Outputs are distinct aligned writable records for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_status(
    handle: u64,
    status: *mut Status,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        let result = with_owner(handle, deadline, |owner, _| owner.status())?;
        // SAFETY: validated exclusive caller output.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Commit/recover the exact original signed request before releasing public bytes.
/// # Safety
/// Request and error are distinct aligned writable records, with no concurrent writer.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_request(
    handle: u64,
    request: *mut RequestBytes,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(request)?;
        let result = with_owner(handle, deadline, |owner, _| {
            let wire = owner
                .enrollment
                .request(owner::now().map_err(Failure::configuration)?)?;
            let mut out = RequestBytes {
                length: u32::try_from(wire.len()).map_err(|_| failure(5))?,
                bytes: [0; 8192],
            };
            out.bytes
                .get_mut(..wire.len())
                .ok_or_else(|| failure(5))?
                .copy_from_slice(&wire);
            Ok(out)
        })?;
        // SAFETY: validated exclusive caller output; unused tail is zero.
        unsafe { put(request, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Admit credential/roster under an independent current pin, retaining the original signer.
/// # Safety
/// All declared input lengths are readable; pin/root and output regions are distinct and live.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_accept(
    handle: u64,
    certificate: *const u8,
    certificate_length: usize,
    roster: *const u8,
    roster_length: usize,
    pin: *const Pin,
    journal: *mut [u8; 32],
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(journal)?;
        if certificate_length == 0 || roster_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: exact input lifetimes and lengths are supplied by the caller.
        let (certificate, roster, pin) = unsafe {
            (
                bytes(certificate, certificate_length, 8192)?,
                bytes(roster, roster_length, 8192)?,
                Pin::read(pin)?,
            )
        };
        let id = with_owner(handle, deadline, |owner, cancel| {
            owner.ensure_policy(cancel, deadline)?;
            let policy = Arc::clone(&owner.authority.as_ref().ok_or_else(|| failure(5))?.policy);
            Ok(*owner
                .enrollment
                .accept(
                    &certificate,
                    &roster,
                    &pin,
                    &policy,
                    owner::now().map_err(Failure::configuration)?,
                )?
                .as_bytes())
        })?;
        // SAFETY: validated exclusive caller output.
        unsafe { put(journal, id) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Prepare only the original accepted installation; witness enrollment remains independent.
/// # Safety
/// Preparation and error are distinct aligned writable invocation-local records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_prepare_storage(
    handle: u64,
    preparation: *mut setup::Preparation,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(preparation)?;
        let result = with_owner(handle, deadline, |owner, cancel| {
            owner.ensure_policy(cancel, deadline)?;
            let status = owner.status()?;
            let policy = Arc::clone(&owner.authority.as_ref().ok_or_else(|| failure(5))?.policy);
            let prepared = owner
                .enrollment
                .prepare(&policy, owner::now().map_err(Failure::configuration)?)?;
            setup::Preparation::from_native(status.journal, prepared)
        })?;
        // SAFETY: validated exclusive caller output.
        unsafe { put(preparation, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Persist one independently authorized same-credential target before activation.
/// # Safety
/// Previous checkpoint, pin/root and roster are distinct readable immutable inputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_refresh_roster(
    handle: u64,
    previous: *const Checkpoint,
    roster: *const u8,
    roster_length: usize,
    pin: *const Pin,
    status: *mut Status,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        if previous.is_null() || !previous.is_aligned() || roster_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: aligned original expectation and immutable supplied current authority bytes.
        let (previous, roster, pin) = unsafe {
            (
                (&*previous).native()?,
                bytes(roster, roster_length, 8192)?,
                Pin::read(pin)?,
            )
        };
        let result = with_owner(handle, deadline, |owner, cancel| {
            owner.ensure_policy(cancel, deadline)?;
            let policy = Arc::clone(&owner.authority.as_ref().ok_or_else(|| failure(5))?.policy);
            owner.enrollment.refresh_roster(
                previous,
                &roster,
                &pin,
                &policy,
                owner::now().map_err(Failure::configuration)?,
            )?;
            owner.status()
        })?;
        // SAFETY: validated exclusive caller output.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Convert the same handle into a device parent retaining the complete EnrolledDevice.
/// # Safety
/// Error is a distinct aligned writable invocation-local record.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_activate(handle: u64, error: *mut ErrorRecord) -> i32 {
    let action = |deadline| {
        with_entry(handle, deadline, |slot, entry| {
            let owner = take_owner(slot, entry, deadline)?;
            let device = owner.activate(entry, deadline)?;
            opening::check(&entry.cancel, deadline)?;
            *slot = Some(Owned::Device(device));
            Ok(())
        })
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}
