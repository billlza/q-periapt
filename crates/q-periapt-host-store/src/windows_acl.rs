//! Handle-based Windows owner/DACL admission and private creation descriptors.
//!
//! All pointers originate in owned OS allocations or bounded, aligned buffers.
//! The effective thread identity is queried per operation; no identity is cached.
#![allow(unsafe_code)]

use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::{size_of, size_of_val},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_NO_TOKEN},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        *,
    },
    Storage::FileSystem::FILE_ALL_ACCESS,
    System::{
        SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
        },
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private Windows owner or DACL admission failed",
    )
}

fn checked(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct EffectiveUser {
    // TokenUser consists of TOKEN_USER and at most SECURITY_MAX_SID_SIZE bytes.
    // Heap allocation keeps the embedded SID address stable when this owner moves.
    _storage: Box<[u64; 16]>,
    sid: PSID,
}

impl EffectiveUser {
    fn current() -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: pseudo handles are valid for this call; raw is an output slot.
        let thread = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
        if thread == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                return Err(error);
            }
            // SAFETY: only absence of an impersonation token selects the process.
            checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) })?;
        }
        if raw.is_null() {
            return Err(denied());
        }
        // SAFETY: successful token open returned one newly owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut storage = Box::new([0u64; 16]);
        let bytes = u32::try_from(size_of::<[u64; 16]>()).map_err(|_| denied())?;
        let mut returned = 0;
        // SAFETY: storage is aligned for TOKEN_USER and valid for bytes bytes.
        checked(unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                bytes,
                &mut returned,
            )
        })?;
        if returned < size_of::<TOKEN_USER>() as u32 || returned > bytes {
            return Err(denied());
        }
        // SAFETY: the successful query filled at least the complete aligned header.
        let user = unsafe { storage.as_ptr().cast::<TOKEN_USER>().read() };
        let start = storage.as_ptr() as usize;
        let end = start.checked_add(returned as usize).ok_or_else(denied)?;
        let sid = user.User.Sid;
        bounded_sid(sid, start, end)?;
        Ok(Self {
            _storage: storage,
            sid,
        })
    }
}

fn bounded_sid(sid: PSID, start: usize, end: usize) -> io::Result<()> {
    let address = sid as usize;
    if address < start || address.checked_add(8).is_none_or(|v| v > end) {
        return Err(denied());
    }
    // SAFETY: the first eight SID bytes are inside the supplied live allocation.
    let count = unsafe { sid.cast::<u8>().add(1).read() } as usize;
    let size = 8usize
        .checked_add(count.checked_mul(4).ok_or_else(denied)?)
        .ok_or_else(denied)?;
    if size > SECURITY_MAX_SID_SIZE as usize || address.checked_add(size).is_none_or(|v| v > end) {
        return Err(denied());
    }
    // SAFETY: the complete declared SID lies inside the live allocation.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(denied());
    }
    Ok(())
}

struct SecurityAllocation(PSECURITY_DESCRIPTOR);
impl Drop for SecurityAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc;
            // this unique owner releases it exactly once after all borrowed ACEs.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub(crate) fn validate(file: &File) -> io::Result<()> {
    let user = EffectiveUser::current()?;
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: file remains open; all non-null output pointers are valid slots.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let allocation = SecurityAllocation(descriptor);
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if allocation.0.is_null() || owner.is_null() || dacl.is_null() {
        return Err(denied());
    }
    // SAFETY: the complete security descriptor was allocated by GetSecurityInfo.
    if unsafe { IsValidSecurityDescriptor(allocation.0) } == 0 {
        return Err(denied());
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: the validated descriptor remains owned by allocation.
    checked(unsafe { GetSecurityDescriptorControl(allocation.0, &mut control, &mut revision) })?;
    if control & SE_DACL_PRESENT == 0 || revision != SECURITY_DESCRIPTOR_REVISION {
        return Err(denied());
    }
    // SAFETY: validated descriptor owns owner; user owns its bounded valid SID.
    if unsafe { EqualSid(owner, user.sid) } == 0 {
        return Err(denied());
    }
    // SAFETY: dacl points into the validated descriptor returned by the OS.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(denied());
    }
    // SAFETY: IsValidAcl checked the fixed ACL header.
    let header = unsafe { dacl.read() };
    let start = dacl as usize;
    let end = start
        .checked_add(header.AclSize as usize)
        .ok_or_else(denied)?;
    for index in 0..u32::from(header.AceCount) {
        let mut entry: *mut c_void = ptr::null_mut();
        // SAFETY: dacl remains valid, and entry is an output slot.
        checked(unsafe { GetAce(dacl, index, &mut entry) })?;
        let address = entry as usize;
        if address < start
            || address
                .checked_add(size_of::<ACE_HEADER>())
                .is_none_or(|v| v > end)
        {
            return Err(denied());
        }
        // SAFETY: fixed header is inside the ACL allocation; unaligned access is allowed.
        let ace = unsafe { entry.cast::<ACE_HEADER>().read_unaligned() };
        let ace_end = address
            .checked_add(ace.AceSize as usize)
            .ok_or_else(denied)?;
        if ace.AceSize < 16 || ace_end > end {
            return Err(denied());
        }
        let known_flags = OBJECT_INHERIT_ACE
            | CONTAINER_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE
            | INHERIT_ONLY_ACE
            | INHERITED_ACE;
        if u32::from(ace.AceFlags) & !known_flags != 0 {
            return Err(denied());
        }
        if u32::from(ace.AceType) != ACCESS_ALLOWED_ACE_TYPE
            && u32::from(ace.AceType) != ACCESS_DENIED_ACE_TYPE
        {
            return Err(denied());
        }
        // Basic allow/deny ACEs have a four-byte header and mask before the SID.
        // SAFETY: minimum ACE width was checked above; bounded_sid checks all SID bytes.
        let sid = unsafe { entry.cast::<u8>().add(8).cast::<c_void>() };
        bounded_sid(sid, address, ace_end)?;
        if u32::from(ace.AceType) == ACCESS_ALLOWED_ACE_TYPE {
            // SAFETY: both compared SIDs have been validated and remain owned.
            let trusted = unsafe {
                EqualSid(sid, user.sid) != 0 || IsWellKnownSid(sid, WinLocalSystemSid) != 0
            };
            if !trusted {
                return Err(denied());
            }
        }
    }
    Ok(())
}

/// Supply a protected descriptor for exclusive creation, never for an existing inode.
pub(crate) fn create_with_private_descriptor(
    directory: bool,
    create: impl FnOnce(&SECURITY_DESCRIPTOR) -> io::Result<File>,
) -> io::Result<File> {
    let user = EffectiveUser::current()?;
    let mut acl_storage = [0usize; 32];
    let acl = acl_storage.as_mut_ptr().cast::<ACL>();
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let sd = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    let inheritance = if directory {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };
    // SAFETY: the aligned ACL buffer exceeds the fixed header, one basic ACE and
    // a maximum-size SID. The descriptor/SID/ACL all outlive the synchronous create.
    unsafe {
        checked(InitializeAcl(
            acl,
            size_of_val(&acl_storage) as u32,
            ACL_REVISION,
        ))?;
        checked(AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            inheritance,
            FILE_ALL_ACCESS,
            user.sid,
        ))?;
        checked(InitializeSecurityDescriptor(
            sd,
            SECURITY_DESCRIPTOR_REVISION,
        ))?;
        checked(SetSecurityDescriptorOwner(sd, user.sid, 0))?;
        checked(SetSecurityDescriptorDacl(sd, 1, acl, 0))?;
        checked(SetSecurityDescriptorControl(
            sd,
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        ))?;
    }
    create(&descriptor)
}

#[cfg(test)]
pub(crate) fn grant_everyone_read_for_test(file: &File) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
    let user = EffectiveUser::current()?;
    let mut sid = [0u64; 16];
    let mut sid_bytes = size_of_val(&sid) as u32;
    let mut acl_storage = [0usize; 64];
    let acl = acl_storage.as_mut_ptr().cast::<ACL>();
    // SAFETY: bounded aligned fixture buffers and the caller's owned fixture
    // handle. This helper is not included in production builds.
    unsafe {
        checked(CreateWellKnownSid(
            WinWorldSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_bytes,
        ))?;
        checked(InitializeAcl(
            acl,
            size_of_val(&acl_storage) as u32,
            ACL_REVISION,
        ))?;
        checked(AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            0,
            FILE_ALL_ACCESS,
            user.sid,
        ))?;
        checked(AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            0,
            FILE_GENERIC_READ,
            sid.as_mut_ptr().cast(),
        ))?;
        let result = SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        );
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
    }
    Ok(())
}
