//! Checked native file primitives. No namespace cleanup or commit decisions.
#![allow(unsafe_code)]

use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io,
    mem::{size_of, size_of_val},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileFsDeviceInformation, FileRenameInformation, NtCreateFile,
            NtQueryVolumeInformationFile, NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE,
            FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
            FILE_RENAME_INFORMATION_0, FILE_SYNCHRONOUS_IO_NONALERT,
        },
        System::SystemServices::{FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE},
    },
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, GENERIC_READ, GENERIC_WRITE, OBJ_CASE_INSENSITIVE,
            UNICODE_STRING,
        },
        Security::SECURITY_DESCRIPTOR,
        Storage::FileSystem::*,
        System::{SystemServices::FILE_PERSISTENT_ACLS, IO::IO_STATUS_BLOCK},
    },
};

pub(super) fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private Windows file admission failed",
    )
}

fn status(result: i32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        // SAFETY: this routine translates a scalar NT status and borrows no memory.
        Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ))
    }
}

pub(super) fn leaf(name: &OsStr) -> io::Result<Vec<u16>> {
    let value: Vec<u16> = name.encode_wide().take(256).collect();
    if value.is_empty()
        || value.len() > 255
        || value
            .iter()
            .any(|c| matches!(*c, 0..=31 | 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
        || value == [46]
        || value == [46, 46]
        || matches!(value.last(), Some(32 | 46))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid private Windows leaf",
        ));
    }
    // Reject Win32 device aliases even though relative NT opens avoid DOS parsing.
    let stem = name
        .to_string_lossy()
        .split('.')
        .next()
        .ok_or_else(denied)?
        .to_ascii_uppercase();
    let port = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"));
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || port.is_some_and(|suffix| {
        matches!(
            suffix,
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private leaf is a device alias",
        ));
    }
    Ok(value)
}

#[derive(Clone, Copy)]
pub(super) enum OpenKind {
    TraverseDirectory,
    PrivateDirectory,
    Metadata,
    Configuration,
    State,
}

/// Only this module can construct the source capability used by native rename.
/// It always owns a FILE_SYNCHRONOUS_IO_NONALERT file object, so borrowed rename
/// buffers cannot outlive an asynchronous operation.
pub(super) struct StagingFile(File);

impl StagingFile {
    pub(super) fn file(&self) -> &File {
        &self.0
    }
}

pub(super) fn create_staging(parent: &File, name: &OsStr) -> io::Result<StagingFile> {
    create(parent, name, false).map(StagingFile)
}

pub(super) fn drive_root(letter: u8) -> io::Result<File> {
    if !letter.is_ascii_alphabetic() {
        return Err(denied());
    }
    let path = format!("{}:\\", char::from(letter));
    let file = OpenOptions::new()
        .read(true)
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    check_local_ntfs(&file)?;
    check_directory(&file)?;
    Ok(file)
}

pub(super) fn check_local_ntfs(file: &File) -> io::Result<()> {
    let mut information = FILE_FS_DEVICE_INFORMATION::default();
    let mut completion = IO_STATUS_BLOCK::default();
    // SAFETY: live handle, correctly sized initialized output structures.
    status(unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &mut completion,
            (&mut information as *mut FILE_FS_DEVICE_INFORMATION).cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    })?;
    // SAFETY: the synchronous query filled this status union member.
    status(unsafe { completion.Anonymous.Status })?;
    if information.Characteristics & FILE_REMOTE_DEVICE != 0 {
        return Err(denied());
    }
    let mut filesystem = [0u16; 64];
    let mut flags = 0;
    // SAFETY: optional outputs are null; filesystem and flags have their declared capacities.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = filesystem.iter().position(|c| *c == 0).ok_or_else(denied)?;
    if filesystem.get(..end) != Some(&[78u16, 84, 70, 83][..]) || flags & FILE_PERSISTENT_ACLS == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private Windows storage requires local NTFS with persistent ACLs",
        ));
    }
    Ok(())
}

pub(super) fn open(parent: &File, name: &OsStr, kind: OpenKind) -> io::Result<File> {
    let (access, kind_flags) = match kind {
        OpenKind::TraverseDirectory => (
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_DIRECTORY_FILE,
        ),
        OpenKind::PrivateDirectory => (
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            FILE_DIRECTORY_FILE,
        ),
        OpenKind::Metadata => (FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, 0),
        OpenKind::Configuration => (GENERIC_READ | SYNCHRONIZE, FILE_NON_DIRECTORY_FILE),
        OpenKind::State => (
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            FILE_NON_DIRECTORY_FILE,
        ),
    };
    create_or_open(parent, name, access, kind_flags, FILE_OPEN, None)
}

pub(super) fn create(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    crate::windows_acl::create_with_private_descriptor(directory, |descriptor| {
        create_or_open(
            parent,
            name,
            GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
            if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            },
            FILE_CREATE,
            Some(descriptor),
        )
    })
}

fn create_or_open(
    parent: &File,
    name: &OsStr,
    access: u32,
    kind: u32,
    disposition: u32,
    security: Option<&SECURITY_DESCRIPTOR>,
) -> io::Result<File> {
    let mut name = leaf(name)?;
    let bytes =
        u16::try_from(name.len().checked_mul(2).ok_or_else(denied)?).map_err(|_| denied())?;
    let mut unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.map_or(ptr::null(), ptr::from_ref),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let mut completion = IO_STATUS_BLOCK::default();
    // SAFETY: all name/descriptor buffers remain live for this synchronous call.
    // FILE_CREATE refuses existing names; OPEN_REPARSE_POINT prevents leaf following.
    status(unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut completion,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    })?;
    if handle.is_null() {
        return Err(denied());
    }
    // SAFETY: success returned a newly owned handle, released exactly once by File.
    let file = unsafe { File::from_raw_handle(handle) };
    // SAFETY: this synchronous create/open filled the status union member.
    status(unsafe { completion.Anonymous.Status })?;
    Ok(file)
}

pub(super) fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: querying the live file handle does not access file contents.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(denied());
    }
    let mut result = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: result is a correctly sized output structure for this live handle.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut result) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if result.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied());
    }
    Ok(result)
}

pub(super) fn check_directory(file: &File) -> io::Result<()> {
    if information(file)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(denied());
    }
    Ok(())
}

fn regular_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let info = information(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || info.nNumberOfLinks != 1 {
        return Err(denied());
    }
    Ok(info)
}

pub(super) fn file_length(file: &File) -> io::Result<u64> {
    let info = regular_information(file)?;
    Ok((u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow))
}

pub(super) fn file_identity(file: &File) -> io::Result<(u32, u64)> {
    let info = regular_information(file)?;
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

pub(super) fn same_file(first: &File, second: &File) -> io::Result<()> {
    if file_identity(first)? != file_identity(second)? {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn same_directory(first: &File, second: &File) -> io::Result<()> {
    let a = information(first)?;
    let b = information(second)?;
    if a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || b.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || (a.dwVolumeSerialNumber, a.nFileIndexHigh, a.nFileIndexLow)
            != (b.dwVolumeSerialNumber, b.nFileIndexHigh, b.nFileIndexLow)
    {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn rename_file(
    file: &StagingFile,
    parent: &File,
    destination: &OsStr,
) -> io::Result<()> {
    rename_synchronous_handle(file.file(), parent, destination)
}

pub(super) fn rename_directory(
    directory: &super::windows::OwnedPrivateDirectory,
    parent: &File,
    destination: &OsStr,
) -> io::Result<()> {
    // OwnedPrivateDirectory can only contain a synchronously opened directory.
    // Newly created staging directories also carry DELETE access. Never close
    // child handles to make rename succeed; native refusal preserves the tree.
    check_directory(&directory.descriptor)?;
    rename_synchronous_handle(&directory.descriptor, parent, destination)
}

fn rename_synchronous_handle(file: &File, parent: &File, destination: &OsStr) -> io::Result<()> {
    let name = leaf(destination)?;
    let name_bytes = name.len().checked_mul(2).ok_or_else(denied)?;
    let bytes = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes + 2)
        .ok_or_else(denied)?;
    let mut storage = vec![0u64; bytes.div_ceil(size_of::<u64>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: u64 allocation supplies the native structure's alignment and enough
    // trailing storage for the complete UTF-16 name and NUL, with checked lengths.
    unsafe {
        info.write(FILE_RENAME_INFORMATION {
            Anonymous: FILE_RENAME_INFORMATION_0 {
                ReplaceIfExists: false,
            },
            RootDirectory: parent.as_raw_handle(),
            FileNameLength: name_bytes as u32,
            FileName: [0],
        });
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    let mut completion = IO_STATUS_BLOCK::default();
    // SAFETY: all buffers and both source/parent handles remain live for the call.
    // Do not replace a failed NTSTATUS with an unfilled zero completion status.
    let result = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut completion,
            info.cast(),
            u32::try_from(size_of_val(storage.as_slice())).map_err(|_| denied())?,
            FileRenameInformation,
        )
    };
    status(result)?;
    // SAFETY: a synchronous successful call filled the status member of the union.
    status(unsafe { completion.Anonymous.Status })
}
