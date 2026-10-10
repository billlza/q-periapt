// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Initial publication and explicit host-trusted policy ownership for registration.
use super::*;
use crate::first_install::{
    self as init, FirstInstallConfiguration, OpenConfiguration, ProtocolConfiguration,
    SdkConfiguration, SdkTrust, TlsConfiguration,
};
use q_periapt_host_store::PolicyRecoveryTrust;
use std::path::PathBuf;
use zeroize::Zeroizing;

impl From<init::Error> for Failure {
    fn from(error: init::Error) -> Self {
        match error {
            init::Error::Input(_) => Self::argument(),
            init::Error::Changed(_) => Self {
                code: 107,
                message: describe(&error),
            },
            init::Error::Sdk(error) => error.into(),
            init::Error::Protocol(error) => error.into(),
            init::Error::Durable(error) => error.into(),
            init::Error::Store(error) => error.into(),
            init::Error::File(error) => Self {
                code: 203,
                message: describe(&error),
            },
            init::Error::Io(error) => Self {
                code: 205,
                message: describe(&error),
            },
            init::Error::Tls(error) => Self {
                code: 309,
                message: describe(&error),
            },
            init::Error::Publication(error) => Self::configuration(error),
        }
    }
}

#[repr(C)]
pub struct Header {
    pub struct_size: u32,
    pub version: u32,
}
#[repr(C)]
pub struct Blob {
    pub data: *const u8,
    pub length: usize,
}
impl Blob {
    pub(crate) unsafe fn snapshot(&self, bound: usize) -> Result<Vec<u8>> {
        // SAFETY: the caller provides this exact immutable readable region.
        unsafe { bytes(self.data, self.length, bound) }
    }
}
#[repr(C)]
pub struct SdkTrustInput {
    pub mode: u32,
    pub scope: [u8; 32],
    pub initial_root: Blob,
    pub recovery_root: Blob,
}
impl SdkTrustInput {
    unsafe fn snapshot(&self) -> Result<SdkTrust> {
        // SAFETY: borrowed roots are bounded and copied before returning.
        let initial = unsafe { self.initial_root.snapshot(1952) }?;
        match self.mode {
            1 if self.scope == [0; 32]
                && self.recovery_root.length == 0
                && self.recovery_root.data.is_null() =>
            {
                Ok(SdkTrust::fixed(&initial)?)
            }
            2 => {
                let recovery = unsafe { self.recovery_root.snapshot(1952) }?;
                Ok(SdkTrust::recoverable(&PolicyRecoveryTrust::new(
                    self.scope, &initial, &recovery,
                )?))
            }
            _ => Err(Failure::argument()),
        }
    }
}
#[repr(C)]
pub struct ProtocolInput {
    pub family: [u8; 32],
    pub root: Blob,
    pub version: u64,
    pub digest: [u8; 32],
    pub policy: Blob,
}
impl ProtocolInput {
    unsafe fn snapshot(&self) -> Result<ProtocolConfiguration> {
        // SAFETY: public signature/pin inputs are copied within their native bounds.
        Ok(ProtocolConfiguration::new(
            self.family,
            &unsafe { self.root.snapshot(p::PUBLIC_KEY_BYTES) }?,
            p::PolicyCheckpoint::from_trusted_state(self.version, self.digest)?,
            &unsafe { self.policy.snapshot(8192) }?,
        )?)
    }
}
#[repr(C)]
pub struct CreateInput {
    pub header: Header,
    pub sdk: SdkTrustInput,
    pub sdk_policy: Blob,
    pub sdk_signature: Blob,
    pub recovery_enrollment: Blob,
    pub protocol: ProtocolInput,
    pub tls_certificate: Blob,
    pub tls_key: Blob,
}
#[repr(C)]
pub struct OpenInput {
    pub header: Header,
    pub sdk: SdkTrustInput,
    pub protocol: ProtocolInput,
}

/// Original witness trust is supplied independently on every registration open.
/// Signed TCP carries authenticated witness messages without transport secrecy.
#[repr(C)]
pub struct WitnessInput {
    pub header: Header,
    pub carrier: u32,
    pub options: witness::Options,
    pub identity: [u8; 32],
    pub public_key: Blob,
    pub tls_peer: Blob,
    pub tls_certificate: Blob,
    pub tls_key: Blob,
    pub tls_name: Blob,
}
impl WitnessInput {
    unsafe fn read(pointer: *const Self) -> Result<Option<witness::Configuration>> {
        if pointer.is_null() {
            return Ok(None);
        }
        unsafe { header(pointer) }?;
        // SAFETY: exact version/size/alignment admitted before this borrow.
        let input = unsafe { &*pointer };
        let carrier = match input.carrier {
            1 => witness::Carrier::SignedTcp,
            2 => witness::Carrier::Tls,
            _ => return Err(Failure::argument()),
        };
        let endpoint = unsafe { witness::Configuration::read(&input.options, carrier) }?;
        let pin = p::AnchorPin::new(
            p::AnchorIdentity::from_trusted_state(input.identity)?,
            p::PublicKey::decode(&unsafe { input.public_key.snapshot(p::PUBLIC_KEY_BYTES) }?)?,
        );
        let (peer, certificate, key, name) = match carrier {
            witness::Carrier::SignedTcp => {
                if [
                    &input.tls_peer,
                    &input.tls_certificate,
                    &input.tls_key,
                    &input.tls_name,
                ]
                .iter()
                .any(|blob| blob.length != 0 || !blob.data.is_null())
                {
                    return Err(Failure::argument());
                }
                (
                    Vec::new(),
                    Vec::new(),
                    Zeroizing::new(Vec::new()),
                    String::new(),
                )
            }
            witness::Carrier::Tls => (
                unsafe { input.tls_peer.snapshot(8192) }?,
                unsafe { input.tls_certificate.snapshot(8192) }?,
                Zeroizing::new(unsafe { input.tls_key.snapshot(8192) }?),
                unsafe { text(input.tls_name.data, input.tls_name.length, 128) }?,
            ),
        };
        Ok(Some(endpoint.trusted(
            pin,
            peer,
            certificate,
            &key,
            name,
        )?))
    }
}

pub(crate) unsafe fn header<T>(pointer: *const T) -> Result<()> {
    if pointer.is_null() {
        return Err(Failure::argument());
    }
    // Read only the first four bytes before accepting the versioned size. A
    // short caller structure therefore never authorizes a full-structure read.
    let size = unsafe { pointer.cast::<u32>().read_unaligned() };
    if usize::try_from(size).map_err(|_| Failure::argument())? != std::mem::size_of::<T>() {
        return Err(Failure::argument());
    }
    // SAFETY: the declared full-sized region includes this two-u32 header.
    let value = unsafe { pointer.cast::<Header>().read_unaligned() };
    if value.version != 1 || !pointer.is_aligned() {
        return Err(Failure::argument());
    }
    Ok(())
}
impl CreateInput {
    unsafe fn read(pointer: *const Self) -> Result<FirstInstallConfiguration> {
        // SAFETY: header admission precedes borrowing the complete known version.
        unsafe { header(pointer) }?;
        let input = unsafe { &*pointer };
        if input.sdk.mode == 1
            && (input.recovery_enrollment.length != 0 || !input.recovery_enrollment.data.is_null())
        {
            return Err(Failure::argument());
        }
        let sdk = SdkConfiguration::with_trust(
            &unsafe {
                input
                    .sdk_policy
                    .snapshot(q_periapt_policy::MAX_SIGNED_POLICY_BYTES)
            }?,
            &unsafe { input.sdk_signature.snapshot(3309) }?,
            unsafe { input.sdk.snapshot() }?,
            &unsafe { input.recovery_enrollment.snapshot(3309) }?,
        )?;
        let protocol = unsafe { input.protocol.snapshot() }?;
        let certificate = unsafe { input.tls_certificate.snapshot(8192) }?;
        let key = Zeroizing::new(unsafe { input.tls_key.snapshot(8192) }?);
        Ok(FirstInstallConfiguration::new(
            sdk,
            protocol,
            TlsConfiguration::new(&certificate, &key)?,
        ))
    }
}
impl OpenInput {
    unsafe fn read(pointer: *const Self) -> Result<OpenConfiguration> {
        unsafe { header(pointer) }?;
        // SAFETY: exact known version, aligned and caller-owned for this call.
        let input = unsafe { &*pointer };
        Ok(OpenConfiguration::new(
            unsafe { input.sdk.snapshot() }?,
            unsafe { input.protocol.snapshot() }?,
        ))
    }
}

pub(crate) enum Preparation {
    Initial {
        input: Box<FirstInstallConfiguration>,
        create: bool,
    },
    Current(Box<OpenConfiguration>),
}
pub(crate) struct Owner {
    path: PathBuf,
    policy: init::SuppliedPolicy,
}
impl Owner {
    pub(crate) fn open(
        path: &Path,
        preparation: Preparation,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Box<Self>> {
        opening::check(cancel, deadline)?;
        let policy = match preparation {
            Preparation::Initial { input, create } => input.prepare(path, create)?,
            Preparation::Current(input) => input.open(path)?,
        };
        opening::check(cancel, deadline)?;
        Ok(Box::new(Self {
            path: path.into(),
            policy,
        }))
    }
}

unsafe fn prepare_initial(
    path: *const u8,
    length: usize,
    input: *const CreateInput,
    create: bool,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: exclusive output, separate from all borrowed inputs.
        unsafe { put(handle, 0) };
        let path = unsafe { text(path, length, 4096) }?;
        let input = unsafe { CreateInput::read(input) }?;
        let request = opening::PathRequest {
            path,
            witness: None,
            kind: opening::Kind::Configuration(Preparation::Initial {
                input: Box::new(input),
                create,
            }),
        };
        let id = Reservation::new()?.publish(
            Owned::Opening(opening::Request::Path(Box::new(request))),
            deadline,
        )?;
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: mandatory caller-owned invocation-local diagnostic region.
    unsafe { boundary(error, false, action) }
}

/// Snapshot explicit first-use inputs; finish_open publishes the complete private tree.
/// # Safety
/// Inputs follow the versioned header and bounded, immutable buffer contract; outputs are disjoint.
#[no_mangle]
pub unsafe extern "C" fn qpc_configuration_v1_prepare_create(
    path: *const u8,
    length: usize,
    input: *const CreateInput,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe { prepare_initial(path, length, input, true, handle, error) }
}

/// Snapshot exact original inputs; finish_open never overwrites or recreates missing state.
/// # Safety
/// Inputs follow the versioned header and bounded, immutable buffer contract; outputs are disjoint.
#[no_mangle]
pub unsafe extern "C" fn qpc_configuration_v1_prepare_reconcile(
    path: *const u8,
    length: usize,
    input: *const CreateInput,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe { prepare_initial(path, length, input, false, handle, error) }
}

/// Open current stored SDK state under original host trust, with pinned protocol metadata.
/// # Safety
/// Inputs follow the versioned header and bounded, immutable buffer contract; outputs are disjoint.
#[no_mangle]
pub unsafe extern "C" fn qpc_configuration_v1_prepare_open(
    path: *const u8,
    length: usize,
    input: *const OpenInput,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        unsafe { put(handle, 0) };
        let path = unsafe { text(path, length, 4096) }?;
        let input = unsafe { OpenInput::read(input) }?;
        let request = opening::PathRequest {
            path,
            witness: None,
            kind: opening::Kind::Configuration(Preparation::Current(Box::new(input))),
        };
        let id = Reservation::new()?.publish(
            Owned::Opening(opening::Request::Path(Box::new(request))),
            deadline,
        )?;
        unsafe { put(handle, id) };
        Ok(())
    };
    unsafe { boundary(error, false, action) }
}

/// Consume configuration into the existing original registration on the same handle.
/// # Safety
/// Intent/witness inputs are immutable readable records; error is a distinct writable output.
#[no_mangle]
pub unsafe extern "C" fn qpc_configuration_v1_begin_enrollment(
    handle: u64,
    intent: *const enrollment::Intent,
    mode: u32,
    witness: *const WitnessInput,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        let create = match mode {
            1 => true,
            2 => false,
            _ => return Err(Failure::argument()),
        };
        let witness = unsafe { WitnessInput::read(witness) }?;
        let approved = unsafe { enrollment::Approved::read(intent) }?;
        with_entry(handle, deadline, |slot, entry| {
            let configured = match slot.as_ref() {
                Some(Owned::Configuration(owner)) => owner,
                Some(_) => return Err(failure(6)),
                None => return Err(failure(2)),
            };
            if configured.policy.family() != approved.family {
                return Err(p::Error::Scope.into());
            }
            if let Some(witness) = &witness {
                if configured
                    .policy
                    .historical()?
                    .anchor_requirement()
                    .binding()
                    != witness.trusted_binding()
                {
                    return Err(p::Error::Scope.into());
                }
            }
            opening::check(&entry.cancel, deadline)?;
            let Some(Owned::Configuration(configured)) = slot.take() else {
                return Err(failure(5));
            };
            // From this point a failure consumes the volatile owner. Reopen the
            // same durable configuration/intent; no error authorizes first use.
            let owner = enrollment::Owner::open(
                &configured.path,
                create,
                approved,
                witness,
                &entry.cancel,
                deadline,
                Some(configured.policy),
            )?;
            opening::check(&entry.cancel, deadline)?;
            *slot = Some(Owned::Enrollment(owner));
            Ok(())
        })
    };
    unsafe { boundary(error, false, action) }
}

#[cfg(test)]
mod tests;

/// Transfer a configured target's existing SDK lease into an original enrollment.
/// No policy file is loaded and no durable policy transaction is performed here.
/// # Safety
/// Error is a distinct writable diagnostic record for this invocation.
#[no_mangle]
pub unsafe extern "C" fn qpc_configuration_v1_select_continued_policy(
    configuration: u64,
    enrollment: u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        if configuration == enrollment {
            return Err(Failure::argument());
        }
        with_entry(configuration, deadline, |slot, configured_entry| {
            match slot.as_ref() {
                Some(Owned::Configuration(_)) => {}
                Some(_) => return Err(failure(6)),
                None => return Err(failure(2)),
            }
            // Both owner locks are nonblocking. Busy/wrong-kind admission of
            // the enrollment leaves the configuration available to retry.
            enrollment::with_owner(enrollment, deadline, |owner, entry| {
                let Some(Owned::Configuration(configured)) = slot.take() else {
                    return Err(failure(5));
                };
                // An admitted failure drops both leases. Only explicit reopen
                // of the original inputs/intent may recover; no first-use retry.
                owner.select_supplied_policy(
                    configured.policy,
                    &configured_entry.cancel,
                    entry,
                    deadline,
                )
            })
        })
    };
    unsafe { boundary(error, false, action) }
}
