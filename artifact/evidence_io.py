#!/usr/bin/env python3
"""Fail-closed byte snapshots and strict JSON parsing for evidence files."""

from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from typing import Any, NoReturn

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes


DEFAULT_JSON_MAX_BYTES = 16 * 1024 * 1024


class EvidenceIOError(ValueError):
    """An evidence file cannot be read as one stable, strict snapshot."""


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    """The exact bytes and digest read from one open regular-file description."""

    path: pathlib.Path
    data: bytes
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class JsonObjectSnapshot:
    """A strict JSON object parsed from the same bytes used for its digest."""

    file: FileSnapshot
    value: dict[str, Any]


if os.name == "nt":
    # Windows has no public openat(2) equivalent in Python.  NtOpenFile's
    # RootDirectory contract lets us retain the same security property as the
    # POSIX descriptor walk: every untrusted component is resolved relative to
    # an already-open directory handle, never by reparsing a full path.
    _OBJ_CASE_INSENSITIVE = 0x00000040
    _OBJ_DONT_REPARSE = 0x00001000

    _SYNCHRONIZE = 0x00100000
    _FILE_READ_DATA = 0x00000001
    _FILE_TRAVERSE = 0x00000020
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_SHARE_READ = 0x00000001

    _FILE_DIRECTORY_FILE = 0x00000001
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_OPEN_REPARSE_POINT = 0x00200000

    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _OPEN_EXISTING = 3
    _DRIVE_FIXED = 3
    _FILE_TYPE_DISK = 1
    _FILE_NAME_NORMALIZED = 0x00000000
    _VOLUME_NAME_GUID = 0x00000001

    _FILE_BASIC_INFO_CLASS = 0
    _FILE_STANDARD_INFO_CLASS = 1
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _FILE_ID_INFO_CLASS = 18

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _WINDOWS_INVALID_COMPONENT = frozenset('<>:"/\\|?*')
    _WINDOWS_RESERVED_COMPONENT = re.compile(
        r"^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|"
        r"COM[1-9\u00b9\u00b2\u00b3]|"
        r"LPT[1-9\u00b9\u00b2\u00b3])$",
        re.IGNORECASE,
    )
    _WINDOWS_VOLUME_GUID_ROOT = re.compile(
        r"^\\\\\?\\Volume\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-"
        r"[0-9A-F]{4}-[0-9A-F]{12}\}\\$",
        re.IGNORECASE,
    )

    class _UnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class _IoStatusValue(ctypes.Union):
        _fields_ = [
            ("Status", wintypes.LONG),
            ("Pointer", wintypes.LPVOID),
        ]

    class _IoStatusBlock(ctypes.Structure):
        _anonymous_ = ("Value",)
        _fields_ = [
            ("Value", _IoStatusValue),
            ("Information", ctypes.c_size_t),
        ]

    class _ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        ]

    class _FileStandardInfo(ctypes.Structure):
        _fields_ = [
            ("AllocationSize", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("NumberOfLinks", wintypes.DWORD),
            ("DeletePending", ctypes.c_ubyte),
            ("Directory", ctypes.c_ubyte),
        ]

    class _FileId128(ctypes.Structure):
        _fields_ = [("Identifier", ctypes.c_ubyte * 16)]

    class _FileIdInfo(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", _FileId128),
        ]

    @dataclass(frozen=True, slots=True)
    class _WindowsFileIdentity:
        volume_serial: int
        file_id: bytes
        creation_time: int
        last_write_time: int
        change_time: int
        attributes: int
        end_of_file: int
        number_of_links: int
        delete_pending: bool
        directory: bool

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _GetDriveTypeW = _kernel32.GetDriveTypeW
    _GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _GetDriveTypeW.restype = wintypes.UINT

    _GetFileType = _kernel32.GetFileType
    _GetFileType.argtypes = [wintypes.HANDLE]
    _GetFileType.restype = wintypes.DWORD

    _GetFinalPathNameByHandleW = _kernel32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _GetFinalPathNameByHandleW.restype = wintypes.DWORD

    _GetFileInformationByHandleEx = _kernel32.GetFileInformationByHandleEx
    _GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _GetFileInformationByHandleEx.restype = wintypes.BOOL

    _NtOpenFile = _ntdll.NtOpenFile
    _NtOpenFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _NtOpenFile.restype = wintypes.LONG

    _RtlNtStatusToDosError = _ntdll.RtlNtStatusToDosError
    _RtlNtStatusToDosError.argtypes = [wintypes.LONG]
    _RtlNtStatusToDosError.restype = wintypes.ULONG

    _windows_abi_sizes = (
        ctypes.sizeof(_UnicodeString),
        ctypes.sizeof(_ObjectAttributes),
        ctypes.sizeof(_IoStatusBlock),
        ctypes.sizeof(_FileAttributeTagInfo),
        ctypes.sizeof(_FileBasicInfo),
        ctypes.sizeof(_FileStandardInfo),
        ctypes.sizeof(_FileIdInfo),
    )
    _expected_windows_abi_sizes = (
        (16, 48, 16, 8, 40, 24, 24)
        if ctypes.sizeof(ctypes.c_void_p) == 8
        else (8, 24, 8, 8, 40, 24, 24)
    )
    if _windows_abi_sizes != _expected_windows_abi_sizes:
        raise RuntimeError(
            "unsupported Windows ctypes ABI for evidence I/O: "
            f"got {_windows_abi_sizes}, expected {_expected_windows_abi_sizes}"
        )
    _windows_abi_offsets = (
        _FileBasicInfo.FileAttributes.offset,
        _FileStandardInfo.AllocationSize.offset,
        _FileStandardInfo.EndOfFile.offset,
        _FileStandardInfo.NumberOfLinks.offset,
        _FileStandardInfo.DeletePending.offset,
        _FileStandardInfo.Directory.offset,
        _FileIdInfo.FileId.offset,
    )
    _expected_windows_abi_offsets = (32, 0, 8, 16, 20, 21, 8)
    if _windows_abi_offsets != _expected_windows_abi_offsets:
        raise RuntimeError(
            "unsupported Windows ctypes field layout for evidence I/O: "
            f"got {_windows_abi_offsets}, expected {_expected_windows_abi_offsets}"
        )


    @dataclass(slots=True)
    class _OwnedWindowsHandle:
        value: int | None
        label: str

        def release(self) -> int:
            if self.value is None:
                raise EvidenceIOError(f"Windows handle already released: {self.label}")
            value = self.value
            self.value = None
            return value

        def close(self) -> None:
            if self.value is None:
                return
            value = self.value
            if not _CloseHandle(wintypes.HANDLE(value)):
                error = ctypes.get_last_error()
                raise EvidenceIOError(
                    f"cannot close Windows evidence handle {self.label}: "
                    f"{ctypes.FormatError(error).strip()} (WinError {error})"
                )
            self.value = None


    def _windows_handle_value(handle: object) -> int | None:
        value = getattr(handle, "value", handle)
        return None if value is None else int(value)


    def _windows_path_components(
        path: pathlib.Path,
    ) -> tuple[pathlib.Path, str, tuple[str, ...]]:
        raw = os.fspath(path)
        folded = raw.casefold()
        if "\x00" in raw or any(
            unicodedata.category(char) in {"Cc", "Cs"} for char in raw
        ):
            raise EvidenceIOError(f"evidence path contains a control character: {path!r}")
        if folded.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
            raise EvidenceIOError(f"Windows device paths are not accepted as evidence: {path}")

        lexical = pathlib.Path(path)
        if ".." in lexical.parts:
            raise EvidenceIOError(f"evidence path must not contain '..': {path}")
        if lexical.drive and not lexical.root:
            raise EvidenceIOError(f"drive-relative evidence paths are not accepted: {path}")
        if lexical.root and not lexical.drive:
            raise EvidenceIOError(f"root-relative evidence paths are not accepted: {path}")

        absolute = pathlib.Path(os.path.abspath(lexical))
        drive = absolute.drive
        if not re.fullmatch(r"[A-Za-z]:", drive) or not absolute.root:
            raise EvidenceIOError(
                f"evidence path must resolve to a local Windows drive: {path}"
            )
        root = absolute.anchor
        components = tuple(absolute.parts[1:])
        if not components:
            raise EvidenceIOError(f"evidence path must name a file: {path}")

        for component in components:
            if (
                not component
                or component[-1] in {" ", "."}
                or any(char in _WINDOWS_INVALID_COMPONENT for char in component)
                or any(
                    unicodedata.category(char) in {"Cc", "Cs"} for char in component
                )
            ):
                raise EvidenceIOError(
                    f"unsafe Windows evidence path component {component!r}: {path}"
                )
            stem = component.split(".", 1)[0]
            if _WINDOWS_RESERVED_COMPONENT.fullmatch(stem):
                raise EvidenceIOError(
                    f"reserved Windows evidence path component {component!r}: {path}"
                )
            try:
                encoded_length = len(component.encode("utf-16-le"))
            except UnicodeError as exc:
                raise EvidenceIOError(
                    f"Windows evidence path component is not valid UTF-16: {component!r}"
                ) from exc
            if encoded_length > 65_532:
                raise EvidenceIOError(
                    f"Windows evidence path component is too long: {component!r}"
                )
        return absolute, root, components


    def _windows_info(
        handle: int,
        info_class: int,
        structure: ctypes.Structure,
        *,
        operation: str,
    ) -> None:
        if not _GetFileInformationByHandleEx(
            wintypes.HANDLE(handle),
            info_class,
            ctypes.byref(structure),
            ctypes.sizeof(structure),
        ):
            error = ctypes.get_last_error()
            raise EvidenceIOError(
                f"cannot query {operation}: {ctypes.FormatError(error).strip()} "
                f"(WinError {error})"
            )


    def _windows_identity(
        handle: int,
        *,
        label: str,
        expect_directory: bool,
    ) -> _WindowsFileIdentity:
        file_type = _GetFileType(wintypes.HANDLE(handle))
        if file_type != _FILE_TYPE_DISK:
            raise EvidenceIOError(
                f"Windows evidence handle is not a disk file for {label}: type={file_type}"
            )

        tag = _FileAttributeTagInfo()
        basic = _FileBasicInfo()
        standard = _FileStandardInfo()
        file_id = _FileIdInfo()
        _windows_info(
            handle,
            _FILE_ATTRIBUTE_TAG_INFO_CLASS,
            tag,
            operation=f"attributes for {label}",
        )
        _windows_info(
            handle,
            _FILE_BASIC_INFO_CLASS,
            basic,
            operation=f"basic metadata for {label}",
        )
        _windows_info(
            handle,
            _FILE_STANDARD_INFO_CLASS,
            standard,
            operation=f"standard metadata for {label}",
        )
        _windows_info(
            handle,
            _FILE_ID_INFO_CLASS,
            file_id,
            operation=f"file identity for {label}",
        )

        if int(tag.FileAttributes) != int(basic.FileAttributes):
            raise EvidenceIOError(
                f"Windows evidence attributes changed while validating {label}"
            )
        attributes_directory = bool(tag.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY)
        standard_directory = bool(standard.Directory)
        if tag.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise EvidenceIOError(f"Windows evidence path traverses a reparse point: {label}")
        if attributes_directory != standard_directory:
            raise EvidenceIOError(
                f"Windows evidence directory metadata disagrees for {label}"
            )
        if attributes_directory is not expect_directory:
            expected = "directory" if expect_directory else "regular file"
            raise EvidenceIOError(f"Windows evidence component is not a {expected}: {label}")
        if bool(standard.DeletePending):
            raise EvidenceIOError(f"Windows evidence object is pending deletion: {label}")
        if standard.EndOfFile < 0:
            raise EvidenceIOError(f"Windows evidence file has a negative size: {label}")

        return _WindowsFileIdentity(
            volume_serial=int(file_id.VolumeSerialNumber),
            file_id=bytes(file_id.FileId.Identifier),
            creation_time=int(basic.CreationTime),
            last_write_time=int(basic.LastWriteTime),
            change_time=int(basic.ChangeTime),
            attributes=int(basic.FileAttributes),
            end_of_file=int(standard.EndOfFile),
            number_of_links=int(standard.NumberOfLinks),
            delete_pending=bool(standard.DeletePending),
            directory=standard_directory,
        )


    def _windows_final_guid_path(handle: int, *, label: str) -> str:
        flags = _FILE_NAME_NORMALIZED | _VOLUME_NAME_GUID
        required = int(
            _GetFinalPathNameByHandleW(
                wintypes.HANDLE(handle),
                None,
                0,
                flags,
            )
        )
        if required == 0:
            error = ctypes.get_last_error()
            raise EvidenceIOError(
                f"cannot resolve the Windows volume path for {label}: "
                f"{ctypes.FormatError(error).strip()} (WinError {error})"
            )
        if required > 32_768:
            raise EvidenceIOError(
                f"Windows volume path for {label} exceeds the supported length"
            )

        buffer = ctypes.create_unicode_buffer(required)
        written = int(
            _GetFinalPathNameByHandleW(
                wintypes.HANDLE(handle),
                buffer,
                required,
                flags,
            )
        )
        if written == 0:
            error = ctypes.get_last_error()
            raise EvidenceIOError(
                f"cannot read the Windows volume path for {label}: "
                f"{ctypes.FormatError(error).strip()} (WinError {error})"
            )
        if written >= required:
            raise EvidenceIOError(
                f"Windows volume path changed while validating {label}"
            )
        return buffer.value


    def _raise_windows_failure(
        primary: BaseException | None,
        cleanup_errors: list[BaseException],
        *,
        context: str,
    ) -> NoReturn:
        if primary is not None:
            for cleanup_error in cleanup_errors:
                primary.add_note(f"cleanup also failed: {cleanup_error}")
            if isinstance(primary, EvidenceIOError) or not isinstance(primary, Exception):
                raise primary.with_traceback(primary.__traceback__)
            wrapped = EvidenceIOError(f"{context}: {primary}")
            raise wrapped from primary

        if not cleanup_errors:
            raise EvidenceIOError(f"{context}: failure had no recorded cause")
        first = cleanup_errors[0]
        for cleanup_error in cleanup_errors[1:]:
            first.add_note(f"additional cleanup failure: {cleanup_error}")
        if not isinstance(first, Exception):
            raise first.with_traceback(first.__traceback__)
        wrapped = EvidenceIOError(f"{context}: cleanup failed: {first}")
        raise wrapped from first


    def _close_windows_owner_after_failure(
        owner: _OwnedWindowsHandle,
        primary: BaseException,
        *,
        context: str,
    ) -> NoReturn:
        cleanup_errors: list[BaseException] = []
        try:
            owner.close()
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
        _raise_windows_failure(primary, cleanup_errors, context=context)


    def _windows_open_root(root: str) -> _OwnedWindowsHandle:
        if _GetDriveTypeW(root) != _DRIVE_FIXED:
            raise EvidenceIOError(
                f"Windows evidence root must be a fixed local drive: {root}"
            )
        raw_handle = _CreateFileW(
            root,
            _FILE_TRAVERSE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        value = _windows_handle_value(raw_handle)
        if value in {None, _INVALID_HANDLE_VALUE}:
            error = ctypes.get_last_error()
            raise EvidenceIOError(
                f"cannot open Windows evidence root {root}: "
                f"{ctypes.FormatError(error).strip()} (WinError {error})"
            )
        owner = _OwnedWindowsHandle(value, root)
        try:
            _windows_identity(value, label=root, expect_directory=True)
            final_path = _windows_final_guid_path(value, label=root)
            if not _WINDOWS_VOLUME_GUID_ROOT.fullmatch(final_path):
                raise EvidenceIOError(
                    "Windows evidence root is not a direct local volume root: "
                    f"{root} resolved to {final_path}"
                )
        except BaseException as exc:
            _close_windows_owner_after_failure(
                owner,
                exc,
                context=f"cannot validate Windows evidence root {root}",
            )
        return owner


    def _windows_open_relative(
        parent: _OwnedWindowsHandle,
        component: str,
        *,
        directory: bool,
        shown_path: pathlib.Path,
    ) -> _OwnedWindowsHandle:
        if parent.value is None:
            raise EvidenceIOError("internal Windows evidence parent handle is closed")
        encoded_length = len(component.encode("utf-16-le"))
        name_buffer = ctypes.create_unicode_buffer(component)
        name = _UnicodeString(
            Length=encoded_length,
            MaximumLength=encoded_length + 2,
            Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
        )
        attributes = _ObjectAttributes(
            Length=ctypes.sizeof(_ObjectAttributes),
            RootDirectory=wintypes.HANDLE(parent.value),
            ObjectName=ctypes.pointer(name),
            Attributes=_OBJ_CASE_INSENSITIVE | _OBJ_DONT_REPARSE,
            SecurityDescriptor=None,
            SecurityQualityOfService=None,
        )
        io_status = _IoStatusBlock()
        raw_handle = wintypes.HANDLE()
        desired_access = _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
        options = _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT
        if directory:
            desired_access |= _FILE_TRAVERSE
            options |= _FILE_DIRECTORY_FILE
        else:
            desired_access |= _FILE_READ_DATA
            options |= _FILE_NON_DIRECTORY_FILE

        status = int(
            _NtOpenFile(
                ctypes.byref(raw_handle),
                desired_access,
                ctypes.byref(attributes),
                ctypes.byref(io_status),
                _FILE_SHARE_READ,
                options,
            )
        )
        value = _windows_handle_value(raw_handle)
        if status != 0:
            unsigned_status = status & 0xFFFFFFFF
            winerror = int(_RtlNtStatusToDosError(status))
            message = ctypes.FormatError(winerror).strip()
            primary = EvidenceIOError(
                f"cannot safely open Windows evidence component {component!r} "
                f"for {shown_path}: {message} (WinError {winerror}, "
                f"NTSTATUS 0x{unsigned_status:08X})"
            )
            if value not in {None, _INVALID_HANDLE_VALUE}:
                unexpected = _OwnedWindowsHandle(value, str(shown_path))
                _close_windows_owner_after_failure(
                    unexpected,
                    primary,
                    context=f"cannot safely open Windows evidence component {component!r}",
                )
            raise primary
        if value in {None, _INVALID_HANDLE_VALUE}:
            raise EvidenceIOError(
                f"NtOpenFile returned success without a handle for {shown_path}"
            )

        owner = _OwnedWindowsHandle(value, str(shown_path))
        try:
            _windows_identity(
                value,
                label=str(shown_path),
                expect_directory=directory,
            )
        except BaseException as exc:
            _close_windows_owner_after_failure(
                owner,
                exc,
                context=f"cannot validate Windows evidence component {shown_path}",
            )
        return owner


    def _open_regular_no_reparse_windows(path: pathlib.Path) -> int:
        absolute, root, components = _windows_path_components(path)
        owners: list[_OwnedWindowsHandle] = []
        descriptor: int | None = None
        primary: BaseException | None = None
        try:
            parent = _windows_open_root(root)
            owners.append(parent)
            current = pathlib.Path(root)
            for index, component in enumerate(components):
                current /= component
                child = _windows_open_relative(
                    parent,
                    component,
                    directory=index < len(components) - 1,
                    shown_path=current,
                )
                owners.append(child)
                parent = child

            if parent.value is None:
                raise EvidenceIOError("internal Windows evidence file handle is closed")
            try:
                descriptor = msvcrt.open_osfhandle(
                    parent.value,
                    os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT,
                )
            except OSError as exc:
                raise EvidenceIOError(
                    f"cannot convert Windows evidence handle for {absolute}: {exc}"
                ) from exc
            parent.release()
            try:
                msvcrt.setmode(descriptor, os.O_BINARY)
                if os.get_inheritable(descriptor):
                    raise EvidenceIOError(
                        "Windows evidence descriptor is unexpectedly inheritable: "
                        f"{absolute}"
                    )
            except OSError as exc:
                raise EvidenceIOError(
                    f"cannot configure Windows evidence descriptor for {absolute}: {exc}"
                ) from exc
        except BaseException as exc:
            primary = exc

        cleanup_errors: list[BaseException] = []
        for owner in reversed(owners):
            try:
                owner.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
        if primary is not None or cleanup_errors:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    cleanup_errors.append(exc)
            _raise_windows_failure(
                primary,
                cleanup_errors,
                context=f"cannot safely open Windows evidence file {absolute}",
            )
        if descriptor is None:
            raise EvidenceIOError("Windows evidence opening produced no descriptor")
        return descriptor


    def _windows_descriptor_identity(descriptor: int) -> _WindowsFileIdentity:
        try:
            handle = int(msvcrt.get_osfhandle(descriptor))
        except OSError as exc:
            raise EvidenceIOError(
                f"cannot obtain Windows handle for evidence descriptor: {exc}"
            ) from exc
        if handle in {-1, -2}:
            raise EvidenceIOError(
                f"invalid Windows evidence descriptor handle: {handle}"
            )
        return _windows_identity(
            handle,
            label=f"descriptor {descriptor}",
            expect_directory=False,
        )


def _open_regular_no_symlinks_posix(path: pathlib.Path) -> int:
    """Open every path component with O_NOFOLLOW and return the final descriptor."""

    if os.open not in os.supports_dir_fd:
        raise EvidenceIOError("this platform lacks dir_fd-safe evidence opening")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise EvidenceIOError("this platform lacks no-follow evidence opening")

    lexical = pathlib.Path(path)
    if ".." in lexical.parts:
        raise EvidenceIOError(f"evidence path must not contain '..': {path}")
    absolute = pathlib.Path(os.path.abspath(lexical))
    # macOS exposes three fixed root aliases.  Permit only these operating-system
    # aliases; every caller-controlled component is still walked with O_NOFOLLOW.
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        alias = absolute.parts[1]
        expected = {"etc": "private/etc", "tmp": "private/tmp", "var": "private/var"}.get(alias)
        if expected is not None:
            alias_path = pathlib.Path(absolute.anchor) / alias
            try:
                target = os.readlink(alias_path)
            except OSError:
                target = ""
            if target.lstrip("/") == expected:
                absolute = pathlib.Path("/private") / alias / pathlib.Path(*absolute.parts[2:])
    parts = absolute.parts
    if not parts or parts[0] != absolute.anchor or len(parts) < 2:
        raise EvidenceIOError(f"evidence path must name a file: {path}")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(absolute.anchor, directory_flags)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(parts[-1], file_flags, dir_fd=directory_fd)
    except OSError as exc:
        raise EvidenceIOError(f"cannot safely open evidence file {path}: {exc}") from exc
    finally:
        os.close(directory_fd)


def _open_regular_no_symlinks(path: pathlib.Path) -> int:
    """Return one stable file descriptor without following untrusted links."""

    if os.name == "nt":
        return _open_regular_no_reparse_windows(path)
    return _open_regular_no_symlinks_posix(path)


def _descriptor_identity(descriptor: int, observed: os.stat_result) -> object:
    """Return mutation-sensitive metadata for one already-open descriptor."""

    if os.name == "nt":
        native = _windows_descriptor_identity(descriptor)
        if native.end_of_file != observed.st_size:
            raise EvidenceIOError(
                "Windows evidence size disagrees between CRT and native metadata: "
                f"{observed.st_size} != {native.end_of_file}"
            )
        return native
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def read_regular_snapshot(
    path: pathlib.Path,
    *,
    maximum: int,
    label: str,
) -> FileSnapshot:
    """Read one bounded regular file and hash exactly the bytes returned."""

    if type(maximum) is not int or maximum <= 0:
        raise EvidenceIOError(f"{label} maximum must be a positive integer")
    descriptor = _open_regular_no_symlinks(path)
    primary_error: BaseException | None = None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceIOError(f"{label} is not a regular file: {path}")
        if before.st_size > maximum:
            raise EvidenceIOError(f"{label} exceeds {maximum} bytes: {path}")

        identity_before = _descriptor_identity(descriptor, before)

        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise EvidenceIOError(f"{label} exceeds {maximum} bytes: {path}")

        after = os.fstat(descriptor)
        identity_after = _descriptor_identity(descriptor, after)
        if (
            identity_before != identity_after
            or len(data) != before.st_size
            or len(data) != after.st_size
        ):
            raise EvidenceIOError(f"{label} changed while it was read: {path}")

        return FileSnapshot(
            path=pathlib.Path(os.path.abspath(path)),
            data=data,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
    except OSError as exc:
        primary_error = EvidenceIOError(f"cannot read {label} {path}: {exc}")
        raise primary_error from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            if primary_error is not None:
                primary_error.add_note(
                    f"closing the evidence descriptor also failed: {cleanup_error}"
                )
            elif isinstance(cleanup_error, Exception):
                raise EvidenceIOError(
                    f"cannot close {label} evidence descriptor for {path}: {cleanup_error}"
                ) from cleanup_error
            else:
                raise


def parse_strict_json_bytes(data: bytes, *, label: str) -> Any:
    """Parse RFC JSON while rejecting duplicate keys and non-finite constants."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceIOError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        raise EvidenceIOError(f"{label} contains non-finite JSON number: {value}")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise EvidenceIOError(f"{label} contains non-finite JSON number: {value}")
        return parsed

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
            parse_float=parse_finite_float,
        )
    except EvidenceIOError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceIOError(f"{label} is not strict UTF-8 JSON: {exc}") from exc


def load_json_object_snapshot(
    path: pathlib.Path,
    *,
    maximum: int = DEFAULT_JSON_MAX_BYTES,
    label: str,
) -> JsonObjectSnapshot:
    """Read, hash, and parse one JSON object without reopening its path."""

    file_snapshot = read_regular_snapshot(path, maximum=maximum, label=label)
    value = parse_strict_json_bytes(file_snapshot.data, label=label)
    if not isinstance(value, dict):
        raise EvidenceIOError(f"{label} root must be a JSON object")
    return JsonObjectSnapshot(file=file_snapshot, value=value)
