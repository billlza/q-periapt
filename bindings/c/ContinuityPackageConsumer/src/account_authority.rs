// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One foreign registry owner; pending children retain native read access only.
use super::*;
use q_periapt_host_store::filesystem::OwnedPrivateDirectory;

const KEY: &str = "authority.key";
const STORE: &str = "authority.redb";
#[cfg(all(test, unix))]
mod tests;

#[repr(C)]
pub struct Options {
    pub struct_size: u32,
    pub identity: [u8; 32],
    pub family: [u8; 32],
    pub witness: [u8; 32],
    pub public_key: *const u8,
    pub public_key_length: usize,
}

// Call only for repr(C) options, whose first field is u32.
// No reference to the full object is formed until its declared size is checked.
pub(crate) unsafe fn check_options<T>(pointer: *const T) -> Result<()> {
    if pointer.is_null() || !pointer.is_aligned() {
        return Err(Failure::argument());
    }
    // SAFETY: the caller provides at least the aligned readable size header.
    let size = unsafe { pointer.cast::<u32>().read() };
    if usize::try_from(size).ok() != Some(std::mem::size_of::<T>()) {
        return Err(Failure::argument());
    }
    Ok(())
}

pub(crate) struct Admission {
    create: bool,
    identity: p::AccountAuthorityIdentity,
    family: [u8; 32],
    pin: p::AnchorPin,
}
impl Admission {
    unsafe fn read(pointer: *const Options, create: bool) -> Result<Self> {
        // SAFETY: forwarded readable size header and declared complete input.
        unsafe { check_options(pointer) }?;
        // SAFETY: validated exact size/alignment; inputs remain immutable now.
        let input = unsafe { &*pointer };
        if input.family == [0; 32] {
            return Err(Failure::argument());
        }
        let public_key = p::PublicKey::decode(&unsafe {
            bytes(
                input.public_key,
                input.public_key_length,
                p::PUBLIC_KEY_BYTES,
            )
        }?)?;
        Ok(Self {
            create,
            identity: p::AccountAuthorityIdentity::from_trusted_state(input.identity)?,
            family: input.family,
            pin: p::AnchorPin::new(
                p::AnchorIdentity::from_trusted_state(input.witness)?,
                public_key,
            ),
        })
    }
}

pub(crate) struct Owner {
    store: p::AccountAuthorityStore,
}
impl Owner {
    pub(crate) fn into_store(self: Box<Self>) -> p::AccountAuthorityStore {
        self.store
    }
    pub(crate) fn open(
        path: &Path,
        admission: Admission,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Box<Self>> {
        opening::check(cancel, deadline)?;
        OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        let key = p::JournalKey::open(&path.join(KEY))?;
        let store = if admission.create {
            p::AccountAuthorityStore::provision(
                &path.join(STORE),
                key,
                admission.identity,
                admission.family,
                admission.pin,
            )?
        } else {
            p::AccountAuthorityStore::open(
                &path.join(STORE),
                key,
                admission.identity,
                admission.family,
                admission.pin,
            )?
        };
        opening::check(cancel, deadline)?;
        Ok(Box::new(Self { store }))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub application: [u8; 32],
    pub revision: u64,
    pub account: [u8; 32],
}
impl Checkpoint {
    pub(crate) fn native(&self) -> Result<p::AccountAuthorityCheckpoint> {
        Ok(p::AccountAuthorityCheckpoint::from_trusted_state(
            p::ApplicationAccountId::from_trusted_state(self.application)?,
            self.revision,
            self.account,
        )?)
    }
    pub(crate) fn observed(value: p::AccountAuthorityCheckpoint) -> Self {
        Self {
            application: *value.application().as_bytes(),
            revision: value.revision(),
            account: value.account(),
        }
    }
}

pub(crate) struct Selection {
    access: p::AccountAuthorityAccess,
    expected: p::AccountAuthorityCheckpoint,
}
impl Selection {
    pub(crate) fn admit(&self) -> Result<p::JournalAccountAuthority> {
        Ok(p::JournalAccountAuthority::new(
            self.access.clone(),
            self.expected,
        )?)
    }
    fn read(handle: u64, checkpoint: &Checkpoint, deadline: Instant) -> Result<Self> {
        let expected = checkpoint.native()?;
        with_access(handle, deadline, |access| {
            let selection = Self {
                access: access.clone(),
                expected,
            };
            selection.admit()?;
            Ok(selection)
        })
    }
}

fn with_access<T>(
    handle: u64,
    deadline: Instant,
    action: impl FnOnce(&p::AccountAuthorityAccess) -> Result<T>,
) -> Result<T> {
    with_owned(handle, deadline, |owner, cancel| {
        opening::check(cancel, deadline)?;
        let access = match owner {
            Owned::AccountAuthority(owner) => owner.store.access()?,
            Owned::RootReplacement(owner) => owner.access(),
            _ => return Err(failure(6)),
        };
        let value = action(&access)?;
        opening::check(cancel, deadline)?;
        Ok(value)
    })
}
fn with_registry<T>(
    handle: u64,
    deadline: Instant,
    action: impl FnOnce(&mut Owner) -> Result<T>,
) -> Result<T> {
    with_owned(handle, deadline, |owner, cancel| {
        opening::check(cancel, deadline)?;
        let value = match owner {
            Owned::AccountAuthority(owner) => action(owner)?,
            _ => return Err(failure(6)),
        };
        opening::check(cancel, deadline)?;
        Ok(value)
    })
}

unsafe fn prepare(
    path: *const u8,
    length: usize,
    options: *const Options,
    create: bool,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: distinct validated output and caller-owned immutable inputs.
        unsafe { put(handle, 0) };
        let path = unsafe { text(path, length, 4096) }?;
        let admission = unsafe { Admission::read(options, create) }?;
        let request = opening::PathRequest {
            path,
            kind: opening::Kind::AccountAuthority(Box::new(admission)),
            witness: None,
            account: None,
        };
        let id = Reservation::new()?.publish(
            Owned::Opening(opening::Request::Path(Box::new(request))),
            deadline,
        )?;
        // SAFETY: same validated exclusive output.
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Prepare explicit first creation; finish_open performs the original I/O.
/// # Safety
/// Inputs and outputs obey the header's bounded readable/nonoverlapping contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_prepare_create(
    path: *const u8,
    length: usize,
    options: *const Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded original options, path and output contract.
    unsafe { prepare(path, length, options, true, handle, error) }
}

/// Prepare only the original existing registry; absence never provisions one.
/// # Safety
/// Inputs and outputs obey the header's bounded readable/nonoverlapping contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_prepare_open(
    path: *const u8,
    length: usize,
    options: *const Options,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    // SAFETY: forwarded original options, path and output contract.
    unsafe { prepare(path, length, options, false, handle, error) }
}

/// Provision a new independent key only while the registry file is absent.
/// # Safety
/// Path and error obey the header's exact region contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_provision_wrapping_key(
    path: *const u8,
    length: usize,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        // SAFETY: caller supplies this immutable length-byte path.
        let path = unsafe { text(path, length, 4096) }?;
        let path = Path::new(&path);
        OwnedPrivateDirectory::open(path).map_err(Failure::configuration)?;
        match std::fs::symlink_metadata(path.join(STORE)) {
            Ok(_) => return Err(p::DurableError::Conflict.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Failure::configuration(error)),
        }
        invocation::check(deadline)?;
        let _key = p::JournalKey::provision(&path.join(KEY))?;
        invocation::check(deadline)
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

/// Read public original mapping metadata; it is not an operational permission.
/// # Safety
/// Application is 32 readable bytes and outputs are exclusive aligned regions.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_checkpoint(
    handle: u64,
    application: *const u8,
    checkpoint: *mut Checkpoint,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(checkpoint)?;
        // SAFETY: caller supplies the exact immutable application identity.
        let application =
            p::ApplicationAccountId::from_trusted_state(unsafe { fixed(application) }?)?;
        let result = with_access(handle, deadline, |access| {
            Ok(Checkpoint::observed(access.current(application)?))
        })?;
        // SAFETY: validated exclusive output.
        unsafe { put(checkpoint, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

#[repr(C)]
pub struct Association {
    pub struct_size: u32,
    pub application: [u8; 32],
    pub pin: *const enrollment::Pin,
    pub certificate: *const u8,
    pub certificate_length: usize,
    pub roster: *const u8,
    pub roster_length: usize,
}

/// Associate only an independently pinned, signature-verified account root.
/// # Safety
/// Association declares its complete size; nested inputs and outputs obey the header.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_associate(
    handle: u64,
    association: *const Association,
    checkpoint: *mut Checkpoint,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(checkpoint)?;
        // SAFETY: forwarded readable header and immutable complete input contract.
        unsafe { check_options(association) }?;
        let input = unsafe { &*association };
        let application = p::ApplicationAccountId::from_trusted_state(input.application)?;
        let (pin, certificate, roster) = unsafe {
            (
                enrollment::Pin::read(input.pin)?,
                bytes(input.certificate, input.certificate_length, 8192)?,
                bytes(input.roster, input.roster_length, 8192)?,
            )
        };
        let device = pin.verify_device(
            &certificate,
            &roster,
            owner::now().map_err(Failure::configuration)?,
        )?;
        let result = with_registry(handle, deadline, |owner| {
            Ok(Checkpoint::observed(
                owner.store.associate(application, &device)?,
            ))
        })?;
        // SAFETY: validated exclusive output, meaningful only on success.
        unsafe { put(checkpoint, result) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

#[repr(C)]
pub struct EnrollmentOptions {
    pub struct_size: u32,
    pub create: u32,
    pub registry: u64,
    pub checkpoint: Checkpoint,
    pub intent: *const enrollment::Intent,
    pub options: *const opening::Options,
}

/// Prepare enrollment with an explicitly selected original registry owner.
/// # Safety
/// Options and nested immutable regions remain readable for preparation; outputs are exclusive.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_prepare_enrollment(
    path: *const u8,
    length: usize,
    options: *const EnrollmentOptions,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: validated exclusive output and immutable size-versioned input.
        unsafe { put(handle, 0) };
        unsafe { check_options(options) }?;
        let input = unsafe { &*options };
        let create = match input.create {
            0 => false,
            1 => true,
            _ => return Err(Failure::argument()),
        };
        let selection = Selection::read(input.registry, &input.checkpoint, deadline)?;
        // SAFETY: nested inputs satisfy the original opening/enrollment contracts.
        let mut request = unsafe { opening::PathRequest::read(path, length, input.options) }?;
        if !matches!(request.kind, opening::Kind::Device) || request.witness.is_none() {
            return Err(Failure::argument());
        }
        let approved = unsafe { enrollment::Approved::read(input.intent) }?;
        request.account = Some(selection);
        request.kind = opening::Kind::Enrollment {
            create,
            approved: Box::new(approved),
        };
        let id = Reservation::new()?.publish(
            Owned::Opening(opening::Request::Path(Box::new(request))),
            deadline,
        )?;
        // SAFETY: same validated exclusive output.
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

pub(crate) fn installation(
    anchor: Option<p::AnchorClient>,
    account: Option<p::JournalAccountAuthority>,
) -> Result<p::InstallationAdmission> {
    Ok(match account {
        Some(account) => p::InstallationAdmission::managed(
            anchor.ok_or(p::DurableError::AnchorRequired)?,
            account,
        ),
        None => anchor.into(),
    })
}

#[repr(C)]
pub struct OpenOptions {
    pub struct_size: u32,
    pub reopen: u32,
    pub registry: u64,
    pub checkpoint: Checkpoint,
    pub options: *const opening::Options,
    pub session: *const u8,
}

/// Prepare an existing device or peer session with original registry admission.
/// # Safety
/// Size-versioned options and nested inputs remain readable; outputs are exclusive.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_prepare_owner(
    path: *const u8,
    length: usize,
    options: *const OpenOptions,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: validated output and caller-provided immutable size header.
        unsafe { put(handle, 0) };
        unsafe { check_options(options) }?;
        let input = unsafe { &*options };
        let selection = Selection::read(input.registry, &input.checkpoint, deadline)?;
        // SAFETY: forwarded bounded original opening/session input contracts.
        let mut request = match input.reopen {
            0 if input.session.is_null() => {
                unsafe { opening::PathRequest::read(path, length, input.options) }?
            }
            1 => unsafe {
                opening::PathRequest::read_reopen(path, length, input.options, input.session)
            }?,
            _ => return Err(Failure::argument()),
        };
        if !matches!(
            request.kind,
            opening::Kind::Device | opening::Kind::Operational(_)
        ) || request.witness.is_none()
        {
            return Err(Failure::argument());
        }
        request.account = Some(selection);
        let id = Reservation::new()?.publish(
            Owned::Opening(opening::Request::Path(Box::new(request))),
            deadline,
        )?;
        // SAFETY: same exclusive validated output.
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}

#[repr(C)]
pub struct EnrollmentSelection {
    pub struct_size: u32,
    pub registry: u64,
    pub checkpoint: Checkpoint,
}

/// Select original registry admission on a registration before operational activation.
/// This permits the first device's signed request to precede account association.
/// # Safety
/// The aligned size header and complete options remain immutable and readable;
/// error is a distinct exclusive diagnostic record for this synchronous invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_authority_v1_select_enrollment(
    enrollment: u64,
    options: *const EnrollmentSelection,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        // SAFETY: read only the size header before borrowing the declared structure.
        unsafe { check_options(options) }?;
        let input = unsafe { &*options };
        let selection = Selection::read(input.registry, &input.checkpoint, deadline)?;
        with_owned(enrollment, deadline, |owned, cancel| {
            opening::check(cancel, deadline)?;
            match owned {
                Owned::Enrollment(owner) => owner.select_account_authority(selection.admit()?)?,
                _ => return Err(failure(6)),
            }
            opening::check(cancel, deadline)
        })
    };
    // SAFETY: forwarded invocation-local diagnostic contract.
    unsafe { boundary(error, false, action) }
}
