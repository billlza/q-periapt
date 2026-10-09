// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit independent peer expectations, separate from untrusted public bundle bytes.
use super::*;
use crate::configuration::{Blob, Header};
use q_periapt_host_store::filesystem::OwnedPrivateDirectory;

#[repr(C)]
pub struct ExpectedDeviceInput {
    pub account: enrollment::Pin,
    pub device: [u8; 16],
    pub generation: u64,
}
#[repr(C)]
pub struct Input {
    pub header: Header,
    pub quality: u32,
    pub role: u32,
    pub initiator: ExpectedDeviceInput,
    pub responder: ExpectedDeviceInput,
    pub directory: [u8; 32],
    pub bundle: Blob,
    pub tls_peer: Blob,
    pub tls_name: Blob,
}
struct Expected {
    account: p::AccountPin,
    device: [u8; 16],
    generation: u64,
}
impl Expected {
    fn required(&self) -> Result<p::ExpectedDevice<'_>> {
        Ok(p::ExpectedDevice::new(
            &self.account,
            self.device,
            self.generation,
        )?)
    }
    unsafe fn snapshot(input: &ExpectedDeviceInput) -> Result<Self> {
        // SAFETY: the enclosing versioned record and its independent root are readable.
        let account = unsafe { enrollment::Pin::read(&input.account) }?;
        let result = Self {
            account,
            device: input.device,
            generation: input.generation,
        };
        result.required()?;
        Ok(result)
    }
    fn from_directory(
        directory: &OwnedPrivateDirectory,
        label: &str,
        family: [u8; 32],
    ) -> Result<Self> {
        let result = Self {
            account: owner::account(directory, label, family)?,
            device: owner::array(directory, &format!("{label}-device"))?,
            generation: u64::from_be_bytes(owner::array(
                directory,
                &format!("{label}-generation"),
            )?),
        };
        result.required()?;
        Ok(result)
    }
}
pub(crate) struct Material {
    initiator: Expected,
    responder: Expected,
    pub(crate) family: [u8; 32],
    directory: p::DirectoryExpectation,
    pub(crate) bundle: p::BootstrapBundle,
    pub(crate) certificate: Vec<u8>,
    pub(crate) name: String,
}
impl Material {
    pub(crate) fn requirements(
        &self,
        quality: p::PrekeyQuality,
    ) -> Result<p::BootstrapRequirements<'_>> {
        Ok(p::BootstrapRequirements {
            initiator: self.initiator.required()?,
            responder: self.responder.required()?,
            directory: self.directory,
            quality,
        })
    }
    pub(crate) fn from_directory(
        directory: &OwnedPrivateDirectory,
        family: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            initiator: Expected::from_directory(directory, "initiator", family)?,
            responder: Expected::from_directory(directory, "responder", family)?,
            family,
            directory: p::DirectoryExpectation::from_trusted_state(owner::array(
                directory,
                "directory",
            )?)?,
            bundle: p::BootstrapBundle::from_bytes(&owner::read(
                directory,
                "bootstrap.bundle",
                p::MAX_BOOTSTRAP_BUNDLE_BYTES,
            )?)?,
            certificate: owner::read(directory, "tls-peer", 8192)?,
            name: String::from_utf8(owner::read(directory, "tls-peer-name", 128)?)
                .map_err(Failure::configuration)?,
        })
    }
}
impl Input {
    unsafe fn snapshot(
        pointer: *const Self,
    ) -> Result<(Material, p::PrekeyQuality, p::BootstrapRole)> {
        // SAFETY: admit only a readable size prefix before the complete aligned record.
        unsafe { configuration::header(pointer) }?;
        let input = unsafe { &*pointer };
        let quality = opening::quality(input.quality)?;
        let role = match input.role {
            1 => p::BootstrapRole::Initiator,
            2 => p::BootstrapRole::Responder,
            _ => return Err(Failure::argument()),
        };
        if input.initiator.account.family != input.responder.account.family {
            return Err(p::Error::Scope.into());
        }
        // SAFETY: copy every independently supplied public input before returning.
        let material = unsafe {
            Material {
                initiator: Expected::snapshot(&input.initiator)?,
                responder: Expected::snapshot(&input.responder)?,
                family: input.initiator.account.family,
                directory: p::DirectoryExpectation::from_trusted_state(input.directory)?,
                bundle: p::BootstrapBundle::from_bytes(
                    &input.bundle.snapshot(p::MAX_BOOTSTRAP_BUNDLE_BYTES)?,
                )?,
                certificate: input.tls_peer.snapshot(8192)?,
                name: text(input.tls_name.data, input.tls_name.length, 128)?,
            }
        };
        if material.certificate.is_empty() {
            return Err(Failure::argument());
        }
        Ok((material, quality, role))
    }
}
unsafe fn prepare(
    parent: u64,
    input: *const Input,
    session: Option<*const u8>,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    let action = |deadline| {
        output(handle)?;
        // SAFETY: separate aligned writable output; snapshot all borrowed public inputs now.
        unsafe { put(handle, 0) };
        let (material, quality, role) = unsafe { Input::snapshot(input) }?;
        let admission = match session {
            None => owner::Admission::Bootstrap(quality),
            Some(pointer) => {
                let session = unsafe { fixed(pointer) }?;
                if session == [0; 32] {
                    return Err(Failure::argument());
                }
                owner::Admission::Existing { quality, session }
            }
        };
        let parent = device::parent(parent, deadline)?;
        let request = opening::Request::Peer(Box::new(opening::PeerRequest {
            parent,
            material: Box::new(material),
            admission,
            role,
        }));
        let reservation = Reservation::new()?;
        let id = reservation.publish(Owned::Opening(request), deadline)?;
        unsafe { put(handle, id) };
        Ok(())
    };
    // SAFETY: forwarded invocation-local diagnostic and separate output contract.
    unsafe { boundary(error, false, action) }
}

/// Copy original peer trust and untrusted bundle under a retained live device.
/// # Safety
/// Header, pointed-to input bytes, output and error follow the C readable/immutable/nonoverlap contract.
#[no_mangle]
pub unsafe extern "C" fn qpc_peer_v1_prepare_configured(
    parent: u64,
    input: *const Input,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe { prepare(parent, input, None, handle, error) }
}
/// Copy peer material for exact original-session restoration. Never fresh admission.
/// # Safety
/// Same versioned input contract; session is a separate immutable readable 32-byte region.
#[no_mangle]
pub unsafe extern "C" fn qpc_peer_v1_prepare_configured_reopen(
    parent: u64,
    input: *const Input,
    session: *const u8,
    handle: *mut u64,
    error: *mut ErrorRecord,
) -> i32 {
    unsafe { prepare(parent, input, Some(session), handle, error) }
}

#[cfg(test)]
mod tests;
