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
/// Historical renewal progress. Conditional zero fields are defined by the C header.
#[repr(C)]
pub struct RenewalStatus {
    pub phase: u32,
    pub operation: [u8; 32],
    pub statement: [u8; 32],
    pub checkpoint: Checkpoint,
    pub observed_at: u64,
}
impl RenewalStatus {
    fn observed(status: p::CredentialRenewalStatus) -> Self {
        match status {
            p::CredentialRenewalStatus::Absent => Self {
                phase: 0,
                operation: [0; 32],
                statement: [0; 32],
                checkpoint: Checkpoint::empty(),
                observed_at: 0,
            },
            p::CredentialRenewalStatus::Pending {
                operation,
                statement,
            } => Self {
                phase: 1,
                operation: *operation.as_bytes(),
                statement,
                checkpoint: Checkpoint::empty(),
                observed_at: 0,
            },
            p::CredentialRenewalStatus::Committed {
                operation,
                statement,
                target,
            } => Self {
                phase: 2,
                operation: *operation.as_bytes(),
                statement,
                checkpoint: Checkpoint::observed(target),
                observed_at: 0,
            },
            p::CredentialRenewalStatus::Closed {
                operation,
                statement,
                target,
            } => Self {
                phase: 4,
                operation: *operation.as_bytes(),
                statement,
                checkpoint: Checkpoint::observed(target),
                observed_at: 0,
            },
            p::CredentialRenewalStatus::ExpiredUncommitted {
                operation,
                statement,
                observed_head,
                observed_at,
            } => Self {
                phase: 3,
                operation: *operation.as_bytes(),
                statement,
                checkpoint: Checkpoint::observed(observed_head),
                observed_at,
            },
        }
    }
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

/// Read the original renewal fact without loading TLS, a grant or a live policy.
/// # Safety
/// Status/error are distinct aligned writable invocation-local records.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_credential_renewal_status(
    handle: u64,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        let result = with_owner(handle, deadline, |owner, _| {
            Ok(RenewalStatus::observed(
                owner.enrollment.credential_renewal_status()?,
            ))
        })?;
        // SAFETY: validated exclusive caller output, written only after success.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Verify independent current authority and durably stage the original local renewal.
/// # Safety
/// Grant/pin/root are immutable readable input, operation is 32 readable bytes,
/// and status/error are distinct aligned writable records. All regions are disjoint.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_stage_credential_renewal(
    handle: u64,
    wire: *const u8,
    wire_length: usize,
    pin: *const Pin,
    operation: *const u8,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        if wire_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: bounded immutable public inputs obey the header pointer contract.
        let (wire, pin, operation) = unsafe {
            (
                bytes(wire, wire_length, p::MAX_CREDENTIAL_RENEWAL_BYTES)?,
                Pin::read(pin)?,
                p::CredentialRenewalId::from_trusted_state(fixed(operation)?)?,
            )
        };
        let result = with_owner(handle, deadline, |owner, cancel| {
            owner.ensure_policy(cancel, deadline)?;
            let policy = Arc::clone(&owner.authority.as_ref().ok_or_else(|| failure(5))?.policy);
            // The foreign facade has not exposed independent proposal approval
            // and the native terminal coordinator yet. Refuse before staging an
            // intent that this facade cannot finish; never select local fallback.
            if policy.anchor_requirement().binding().is_some() {
                return Err(p::DurableError::AnchorRequired.into());
            }
            let grant = p::VerifiedCredentialRenewal::verify(
                &wire,
                &pin,
                policy.checkpoint().digest(),
                owner::now().map_err(Failure::configuration)?,
            )?;
            opening::check(cancel, deadline)?;
            Ok(RenewalStatus::observed(
                owner.enrollment.stage_credential_renewal(
                    &grant,
                    operation,
                    &policy,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: validated exclusive caller output, never inferred from an error.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Reconcile an exact expired original operation, publishing a fact but no device.
/// # Safety
/// Operation/statement are 32 readable bytes each; status/error are distinct
/// aligned writable invocation-local records, disjoint from the inputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_enrollment_v1_reconcile_expired_credential_renewal(
    handle: u64,
    operation: *const u8,
    statement: *const u8,
    status: *mut RenewalStatus,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(status)?;
        // SAFETY: exact original public identities, checked before taking an owner.
        let (operation, statement) = unsafe {
            (
                p::CredentialRenewalId::from_trusted_state(fixed(operation)?)?,
                fixed(statement)?,
            )
        };
        if statement == [0; 32] {
            return Err(Failure::argument());
        }
        let result = with_owner(handle, deadline, |owner, cancel| {
            owner.ensure_policy(cancel, deadline)?;
            let policy = Arc::clone(&owner.authority.as_ref().ok_or_else(|| failure(5))?.policy);
            // Native recovery authenticates the retained wire historically. Requiring
            // a newly verified live target here would strand the expired intent.
            Ok(RenewalStatus::observed(
                owner.enrollment.reconcile_expired_credential_renewal(
                    operation,
                    statement,
                    &policy,
                    owner::now().map_err(Failure::configuration)?,
                )?,
            ))
        })?;
        // SAFETY: validated exclusive caller output.
        unsafe { put(status, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}

/// Admit a peer's independent root grant through the original device parent.
/// # Safety
/// Grant/pin/root are immutable readable inputs; operation is 32 readable bytes.
/// Checkpoint/error are distinct aligned writable records, disjoint from all inputs.
#[no_mangle]
pub unsafe extern "C" fn qpc_device_v1_admit_peer_credential_renewal(
    handle: u64,
    wire: *const u8,
    wire_length: usize,
    pin: *const Pin,
    operation: *const u8,
    checkpoint: *mut Checkpoint,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(checkpoint)?;
        if wire_length == 0 {
            return Err(Failure::argument());
        }
        // SAFETY: bounded immutable inputs are copied before parent admission.
        let (wire, pin, operation) = unsafe {
            (
                bytes(wire, wire_length, p::MAX_CREDENTIAL_RENEWAL_BYTES)?,
                Pin::read(pin)?,
                p::CredentialRenewalId::from_trusted_state(fixed(operation)?)?,
            )
        };
        let result = device::parent(handle, deadline)?
            .admit_peer_credential_renewal(deadline, &wire, &pin, operation)?;
        // SAFETY: validated exclusive output; a failed/unknown commit writes no success.
        unsafe { put(checkpoint, Checkpoint::observed(result)) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic.
    unsafe { boundary(error, false, action) }
}
