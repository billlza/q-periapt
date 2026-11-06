//! Checked native file primitives. No namespace cleanup or commit decisions.
#![allow(unsafe_code)]

use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of, size_of_val},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileDispositionInformationEx, FileFsDeviceInformation, FileNamesInformation,
            FileRenameInformation, NtCreateFile, NtQueryDirectoryFile,
            NtQueryVolumeInformationFile, NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE,
            FILE_DISPOSITION_DELETE, FILE_DISPOSITION_INFORMATION_EX,
            FILE_DISPOSITION_POSIX_SEMANTICS, FILE_NAMES_INFORMATION, FILE_NON_DIRECTORY_FILE,
            FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0,
            FILE_SYNCHRONOUS_IO_NONALERT,
        },
        System::SystemServices::{FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE},
    },
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, GENERIC_READ, GENERIC_WRITE, OBJ_CASE_INSENSITIVE,
            STATUS_NO_MORE_FILES, UNICODE_STRING,
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

#[cfg_attr(test, track_caller)]
fn status(result: i32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        // SAFETY: this routine translates a scalar NT status and borrows no memory.
        let error = io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        );
        #[cfg(test)]
        eprintln!(
            "private Windows native failure at {}: ntstatus={result:#010x}, error={error:?}",
            std::panic::Location::caller(),
        );
        Err(error)
    }
}

#[cfg_attr(test, track_caller)]
fn last_error() -> io::Error {
    let error = io::Error::last_os_error();
    #[cfg(test)]
    eprintln!(
        "private Windows native failure at {}: error={error:?}",
        std::panic::Location::caller(),
    );
    error
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
    DirectoryRename,
    FileRemoval,
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
        return Err(last_error());
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
        OpenKind::DirectoryRename => (
            DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_DIRECTORY_FILE,
        ),
        OpenKind::FileRemoval => (
            DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_NON_DIRECTORY_FILE,
        ),
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
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | if directory { 0 } else { DELETE },
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
        return Err(last_error());
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
    if directory_identity(first)? != directory_identity(second)? {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn directory_identity(file: &File) -> io::Result<(u32, u64)> {
    let info = information(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(denied());
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

pub(super) fn rename_file(
    file: &StagingFile,
    parent: &File,
    destination: &OsStr,
) -> io::Result<()> {
    rename_synchronous_handle(file.file(), parent, destination)
}

pub(super) fn rename_plain_file_to(
    source_parent: &File,
    name: &OsStr,
    destination_parent: &File,
    destination: &OsStr,
    original: &File,
) -> io::Result<()> {
    // FileRemoval requests DELETE access without setting a delete disposition.
    // Bind this late, synchronous handle to the original retained control field.
    let named = open(source_parent, name, OpenKind::FileRemoval)?;
    check_local_ntfs(&named)?;
    crate::windows_acl::validate(&named)?;
    same_file(original, &named)?;
    rename_synchronous_handle(&named, destination_parent, destination)
}

pub(super) fn rename_directory(
    directory: &super::windows::OwnedPrivateDirectory,
    source_parent: &File,
    name: &OsStr,
    destination_parent: &File,
    destination: &OsStr,
) -> io::Result<()> {
    // Keep the original read/write directory pin throughout preparation. An
    // early DELETE handle can conflict with the kernel's child-rename target
    // open. Acquire deletion access only now, and bind it to that original pin.
    // All these handles are synchronous; no borrowed rename buffer can escape.
    let named = open(source_parent, name, OpenKind::DirectoryRename)?;
    crate::windows_acl::validate(&named)?;
    same_directory(&directory.descriptor, &named)?;
    rename_synchronous_handle(&named, destination_parent, destination)
}

pub(super) fn remove_file(parent: &File, name: &OsStr, original: &File) -> io::Result<()> {
    let named = open(parent, name, OpenKind::FileRemoval)?;
    check_local_ntfs(&named)?;
    crate::windows_acl::validate(&named)?;
    same_file(original, &named)?;
    remove_synchronous_handle(named)
}

pub(super) fn remove_directory(parent: &File, name: &OsStr, original: &File) -> io::Result<()> {
    let named = open(parent, name, OpenKind::DirectoryRename)?;
    check_local_ntfs(&named)?;
    crate::windows_acl::validate(&named)?;
    same_directory(original, &named)?;
    remove_synchronous_handle(named)
}

fn remove_synchronous_handle(file: File) -> io::Result<()> {
    let mut disposition = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
    };
    let mut completion = IO_STATUS_BLOCK::default();
    // SAFETY: this owned handle was opened synchronously with DELETE access. The
    // fixed-size input and completion buffers remain live through the native call.
    status(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut completion,
            (&mut disposition as *mut FILE_DISPOSITION_INFORMATION_EX).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    })?;
    // SAFETY: successful synchronous completion initialized this union member.
    status(unsafe { completion.Anonymous.Status })?;
    // POSIX disposition removes the name when this deletion handle closes, even
    // while the caller's original pin remains live. There is no legacy fallback,
    // readonly-attribute override, or closure of the caller's independent lease.
    drop(file);
    Ok(())
}

/// Return at most `limit` non-dot names. This is not a namespace snapshot; the
/// caller must retain its own lease and revalidate each opened entry's identity.
pub(super) fn directory_entries(parent: &File, limit: usize) -> io::Result<Vec<OsString>> {
    if limit == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory enumeration requires a positive limit",
        ));
    }
    // A duplicate handle would share the enumeration cursor. ReOpenFile rejects
    // directories, including with BACKUP_SEMANTICS. Reopen this pinned object by
    // its empty relative NT name, with explicit directory and synchronous options.
    // This internal empty name is not a caller-supplied leaf or a pathname fallback.
    let mut name = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: ptr::null_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let mut completion = IO_STATUS_BLOCK::default();
    // SAFETY: the pinned directory and all input/output structures remain live
    // through this synchronous open of the same object. No child name is resolved.
    status(unsafe {
        NtCreateFile(
            &mut handle,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            &attributes,
            &mut completion,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    })?;
    if handle.is_null() {
        return Err(denied());
    }
    // SAFETY: successful NtCreateFile returned one new owned synchronous handle.
    let directory = unsafe { File::from_raw_handle(handle) };
    // SAFETY: successful synchronous completion initialized this union member.
    status(unsafe { completion.Anonymous.Status })?;
    check_local_ntfs(&directory)?;
    crate::windows_acl::validate(&directory)?;
    same_directory(parent, &directory)?;
    let mut entries = Vec::new();
    let mut restart = true;
    while entries.len() < limit {
        // LONG alignment and room for a complete maximum-length NTFS leaf.
        let mut buffer = [0u32; 256];
        let mut completion = IO_STATUS_BLOCK::default();
        // SAFETY: synchronous handle, no event/APC, aligned bounded output buffer,
        // and live completion storage. Request exactly one complete directory entry.
        let result = unsafe {
            NtQueryDirectoryFile(
                directory.as_raw_handle(),
                ptr::null_mut(),
                None,
                ptr::null(),
                &mut completion,
                buffer.as_mut_ptr().cast(),
                size_of_val(&buffer) as u32,
                FileNamesInformation,
                true,
                ptr::null(),
                restart,
            )
        };
        if result == STATUS_NO_MORE_FILES {
            break;
        }
        status(result)?;
        // SAFETY: successful synchronous completion initialized this union member.
        status(unsafe { completion.Anonymous.Status })?;
        restart = false;
        let start = offset_of!(FILE_NAMES_INFORMATION, FileName);
        let used = completion.Information;
        let name_bytes = buffer[2] as usize;
        if used < start
            || used > size_of_val(&buffer)
            || buffer[0] != 0
            || name_bytes == 0
            || name_bytes > 255 * size_of::<u16>()
            || !name_bytes.is_multiple_of(size_of::<u16>())
            || start + name_bytes > used
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private directory enumeration returned an incomplete entry",
            ));
        }
        // SAFETY: the validated native byte length lies inside initialized buffer;
        // its LONG-aligned base plus FileName offset is aligned for u16.
        let name = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<u8>().add(start).cast::<u16>(),
                name_bytes / size_of::<u16>(),
            )
        };
        if name != [46] && name != [46, 46] {
            entries.push(OsString::from_wide(name));
        }
    }
    Ok(entries)
}

#[cfg(test)]
pub(super) fn directory_entries_preserve_cursor_for_test(
    parent: &File,
    limit: usize,
) -> io::Result<Vec<OsString>> {
    let mut filter = leaf(OsStr::new("lease"))?;
    let bytes = u16::try_from(filter.len() * size_of::<u16>()).map_err(|_| denied())?;
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: filter.as_mut_ptr(),
    };
    let query = |completion: &mut IO_STATUS_BLOCK,
                 buffer: &mut [u32; 256],
                 name: *const UNICODE_STRING,
                 restart: bool| {
        // SAFETY: this test retains the synchronous directory pin and all borrowed
        // query buffers. A supplied filter remains live through the native call.
        unsafe {
            NtQueryDirectoryFile(
                parent.as_raw_handle(),
                ptr::null_mut(),
                None,
                ptr::null(),
                completion,
                buffer.as_mut_ptr().cast(),
                size_of_val(buffer) as u32,
                FileNamesInformation,
                true,
                name,
                restart,
            )
        }
    };
    let mut buffer = [0u32; 256];
    let mut completion = IO_STATUS_BLOCK::default();
    status(query(&mut completion, &mut buffer, &name, true))?;
    // SAFETY: successful synchronous completion initialized this union member.
    status(unsafe { completion.Anonymous.Status })?;
    let start = offset_of!(FILE_NAMES_INFORMATION, FileName);
    if buffer[0] != 0
        || buffer[2] != u32::from(bytes)
        || completion.Information < start + usize::from(bytes)
        || completion.Information > size_of_val(&buffer)
    {
        return Err(io::Error::other("original directory filter was not honored"));
    }
    // SAFETY: the complete bounded name lies within the initialized aligned buffer.
    let actual = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(start).cast::<u16>(),
            filter.len(),
        )
    };
    if actual != filter.as_slice() {
        return Err(io::Error::other("original directory filter was not honored"));
    }

    // Windows captures FileName on the first query for a file object. Duplicating
    // this pin would retain the lease-only filter even with RestartScan=true.
    let entries = directory_entries(parent, limit)?;
    completion = IO_STATUS_BLOCK::default();
    let result = query(&mut completion, &mut buffer, ptr::null(), false);
    if result != STATUS_NO_MORE_FILES {
        status(result)?;
        return Err(io::Error::other(
            "independent scan changed original directory cursor",
        ));
    }
    Ok(entries)
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
