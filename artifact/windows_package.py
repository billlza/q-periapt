#!/usr/bin/env python3
"""Create and verify the strict manifest inside the Windows x64 ABI2 SDK ZIP."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import ntpath
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import Any, BinaryIO, Iterable

from c_abi_contract import ABI_MAJOR, PACKAGE_SEMVER, load_contract
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    load_json_object_snapshot,
    read_regular_snapshot,
)
from package_bom import (
    EXPECTED_CRYPTO_ASSETS,
    PackageBomError,
    verify as verify_package_boms,
)
from release_binary_scan import ReleaseBinaryScanError, scan_release_file
from third_party_licenses import (
    INVENTORY_RELATIVE as THIRD_PARTY_INVENTORY_RELATIVE,
    ThirdPartyLicenseError,
    verify as verify_third_party_licenses,
)

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JobObjectBasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    _CREATE_SUSPENDED = 0x00000004
    _TH32CS_SNAPTHREAD = 0x00000004
    _THREAD_SUSPEND_RESUME = 0x0002
    _ERROR_NO_MORE_FILES = 18
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_SET_QUOTA = 0x0100
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _CreateJobObjectW = _kernel32.CreateJobObjectW
    _CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _CreateJobObjectW.restype = wintypes.HANDLE

    _SetInformationJobObject = _kernel32.SetInformationJobObject
    _SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _SetInformationJobObject.restype = wintypes.BOOL

    _OpenProcess = _kernel32.OpenProcess
    _OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _OpenProcess.restype = wintypes.HANDLE

    _AssignProcessToJobObject = _kernel32.AssignProcessToJobObject
    _AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _AssignProcessToJobObject.restype = wintypes.BOOL

    _TerminateJobObject = _kernel32.TerminateJobObject
    _TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _TerminateJobObject.restype = wintypes.BOOL

    _CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
    _CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    _Thread32First = _kernel32.Thread32First
    _Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    _Thread32First.restype = wintypes.BOOL

    _Thread32Next = _kernel32.Thread32Next
    _Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    _Thread32Next.restype = wintypes.BOOL

    _OpenThread = _kernel32.OpenThread
    _OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _OpenThread.restype = wintypes.HANDLE

    _ResumeThread = _kernel32.ResumeThread
    _ResumeThread.argtypes = [wintypes.HANDLE]
    _ResumeThread.restype = wintypes.DWORD

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL


SCHEMA_VERSION = 3
KIND = "qperiapt.windows_c_package_manifest"
TARGET = "x86_64-pc-windows-msvc"
ABI_PLATFORM = "windows"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_DEPENDENCY_RE = re.compile(
    r"^[A-Za-z0-9._-]+\.dll$",
    re.IGNORECASE | re.ASCII,
)
TREE_RE = re.compile(r"^[0-9a-f]{40,64}$")
MSVC_VERSION_RE = re.compile(
    r"^MSVC (?P<major>[1-9][0-9])\.(?P<minor>[0-9]{2})\."
    r"(?P<build>0|[1-9][0-9]{0,4})\."
    r"(?P<revision>0|[1-9][0-9]{0,9})$",
    re.ASCII,
)
MSVC_VERSION_PROBE_RE = re.compile(
    rb"[ \t\r\n]*QPERIAPT_MSVC_VERSION[ \t]+"
    rb"(?P<short>[1-9][0-9]{3})[ \t]+"
    rb"(?P<full>[0-9]{9})[ \t]+"
    rb"(?P<revision>0|[1-9][0-9]{0,9})[ \t]+100[ \t\r\n]*"
)
MSVC_VERSION_PROBE_SOURCE = (
    b"#if !defined(_MSC_VER) || !defined(_MSC_FULL_VER) || "
    b"!defined(_MSC_BUILD)\n"
    b"#error QPERIAPT_MSVC_VERSION_MACROS_UNAVAILABLE\n"
    b"#endif\n"
    b"#if !defined(_M_X64) || defined(_M_ARM64EC) || "
    b"defined(_M_ARM64) || \\\n"
    b"    defined(_M_ARM) || defined(_M_IX86)\n"
    b"#error QPERIAPT_MSVC_X64_REQUIRED\n"
    b"#endif\n"
    b"QPERIAPT_MSVC_VERSION _MSC_VER _MSC_FULL_VER _MSC_BUILD _M_X64\n"
)
MSVC_VERSION_PROBE_FILENAME = "msvc-version-probe.c"
# With /EP, supported MSVC toolchains reserve stdout for preprocessed bytes and
# emit this one fixed source-progress record on stderr. This is an exact
# protocol record, not a license to ignore compiler diagnostics.
MSVC_VERSION_PROBE_STDERR = MSVC_VERSION_PROBE_FILENAME.encode("ascii") + b"\r\n"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_FILE_BYTES = 512 * 1024 * 1024
MAX_DUMPBIN_OUTPUT_BYTES = 1024 * 1024
MAX_MSVC_VERSION_PROBE_OUTPUT_BYTES = 512
MAX_MSVC_VERSION_CHARS = 64
MAX_RUSTC_NATIVE_STATIC_LIBS_BYTES = 1024 * 1024
MAX_RUSTC_LINK_ARGUMENTS_BYTES = 4 * 1024 * 1024
DUMPBIN_DEPENDENCY_HEADER = b"Image has the following dependencies:"
DUMPBIN_SUMMARY_HEADER = b"Summary"
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
PE_MACHINE_AMD64 = 0x8664
PE32_PLUS_MAGIC = 0x020B
PE_FILE_RELOCS_STRIPPED = 0x0001
PE_FILE_EXECUTABLE_IMAGE = 0x0002
PE_FILE_DLL = 0x2000
PE_HIGH_ENTROPY_VA = 0x0020
PE_DYNAMIC_BASE = 0x0040
PE_NX_COMPAT = 0x0100
PE_DEBUG_TYPE_REPRO = 16
PE_DEBUG_DIRECTORY_SIZE = 28
MAX_PE_DEBUG_DIAGNOSTIC_ENTRIES = 4
PE_RELOCATION_TYPE_ABSOLUTE = 0
PE_RELOCATION_TYPE_DIR64 = 10
PE_MAX_SECTIONS = 96
PE_UINT32_LIMIT = 1 << 32
MAX_PE_RELOCATION_DIRECTORY_BYTES = 1024 * 1024
MAX_PE_RELOCATION_ENTRIES = 65_536

MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "package",
        "version",
        "generated_at",
        "source_date_epoch",
        "git_commit",
        "git_tree",
        "git_dirty",
        "target",
        "release_class",
        "authenticode",
        "abi",
        "hardening",
        "native_dependencies",
        "third_party_rust",
        "toolchain",
        "source_inputs_sha256",
        "files",
    }
)
SOURCE_INPUT_PATHS = {
    "cargo_lock": "Cargo.lock",
    "c_abi_contract": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    "c_abi_verifier": "artifact/c_abi_contract.py",
    "ffi_header": "crates/q-periapt-ffi/include/q_periapt.h",
    "signed_policy_fixture": "bindings/c/signed_policy_fixture.h",
    "smoke_consumer": "bindings/c/smoke.c",
    "windows_package_script": "artifact/windows-package.ps1",
    "windows_msvc_version_probe": "artifact/msvc-version-probe.c",
    "windows_toolchain_tests": "artifact/windows-toolchain-tests.ps1",
    "windows_manifest_script": "artifact/windows_package.py",
    "deterministic_archive_script": "artifact/deterministic_archive.py",
    "evidence_io_script": "artifact/evidence_io.py",
    "package_bom_script": "artifact/package_bom.py",
    "python_bootstrap_script": "artifact/python_bootstrap.py",
    "release_binary_scan_script": "artifact/release_binary_scan.py",
    "third_party_licenses_script": "artifact/third_party_licenses.py",
    "vendor_inventory": "crates/q-periapt-mlkem-native-sys/vendor/INVENTORY.sha256",
    "vendor_license": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE.mlkem-native",
    "vendor_license_inventory": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE-INVENTORY.md",
    "vendor_provenance": "crates/q-periapt-mlkem-native-sys/vendor/PROVENANCE.md",
}
RUST_WORKSPACE_INPUTS = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates")
ALLOWED_DEPENDENCY_NAMES = frozenset(
    name.casefold()
    for name in (
        "ADVAPI32.dll",
        "bcrypt.dll",
        "bcryptprimitives.dll",
        "KERNEL32.dll",
        "ntdll.dll",
        "USERENV.dll",
        "WS2_32.dll",
        "VCRUNTIME140.dll",
        "VCRUNTIME140_1.dll",
        "ucrtbase.dll",
        "api-ms-win-core-synch-l1-2-0.dll",
        "api-ms-win-crt-conio-l1-1-0.dll",
        "api-ms-win-crt-convert-l1-1-0.dll",
        "api-ms-win-crt-environment-l1-1-0.dll",
        "api-ms-win-crt-filesystem-l1-1-0.dll",
        "api-ms-win-crt-heap-l1-1-0.dll",
        "api-ms-win-crt-locale-l1-1-0.dll",
        "api-ms-win-crt-math-l1-1-0.dll",
        "api-ms-win-crt-multibyte-l1-1-0.dll",
        "api-ms-win-crt-process-l1-1-0.dll",
        "api-ms-win-crt-private-l1-1-0.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
        "api-ms-win-crt-stdio-l1-1-0.dll",
        "api-ms-win-crt-string-l1-1-0.dll",
        "api-ms-win-crt-time-l1-1-0.dll",
        "api-ms-win-crt-utility-l1-1-0.dll",
    )
)
EXPECTED_WINDOWS_NATIVE_STATIC_LIBRARY_TOKENS = (
    "kernel32.lib",
    "ntdll.lib",
    "userenv.lib",
    "ws2_32.lib",
    "dbghelp.lib",
    "/defaultlib:msvcrt",
)
CANONICAL_WINDOWS_NATIVE_STATIC_LIBRARIES = (
    "kernel32.lib",
    "ntdll.lib",
    "userenv.lib",
    "ws2_32.lib",
    "dbghelp.lib",
    "msvcrt.lib",
)

WINDOWS_DRIVE_ABSOLUTE_RE = re.compile(r"[A-Za-z]:[\\/]", re.ASCII)
REQUIRED_MSVC_LINK_ARGUMENTS = ("/nologo", "/wx")
EXPECTED_RUSTC_VERSION = "rustc 1.97.0 (2d8144b78 2026-07-07)"
EXPECTED_CARGO_VERSION = "cargo 1.97.0 (c980f4866 2026-06-30)"

EXPECTED_PAYLOAD_FILES = frozenset(
    {
        "LICENSE",
        "LICENSES/Apache-2.0.txt",
        "LICENSES/MIT.txt",
        "README.md",
        "THIRD_PARTY/mlkem-native/INVENTORY.sha256",
        "THIRD_PARTY/mlkem-native/LICENSE-INVENTORY.md",
        "THIRD_PARTY/mlkem-native/LICENSE.mlkem-native",
        "THIRD_PARTY/mlkem-native/PROVENANCE.md",
        "bin/q_periapt_ffi_abi2.dll",
        "include/qperiapt/abi2/q_periapt.h",
        "include/qperiapt/abi2/signed_policy_fixture.h",
        "lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake",
        "lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake",
        "lib/q_periapt_ffi_abi2.lib",
        "lib/q_periapt_ffi_abi2_static.lib",
        "share/q-periapt/abi/q-periapt-c-abi-v2.json",
        "share/q-periapt/bom/cbom.cdx.json",
        "share/q-periapt/bom/sbom.cdx.json",
        "share/q-periapt/smoke.c",
    }
)
EXPECTED_ALL_FILES = EXPECTED_PAYLOAD_FILES | {"MANIFEST.json", "SHA256SUMS"}


class WindowsPackageError(ValueError):
    """The Windows package is malformed, untrusted, or internally inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WindowsPackageError(message)


def _validate_msvc_version(value: object, label: str) -> None:
    if (
        type(value) is not str
        or not 0 < len(value) <= MAX_MSVC_VERSION_CHARS
    ):
        raise WindowsPackageError(f"{label} is malformed")
    match = MSVC_VERSION_RE.fullmatch(value)
    _require(
        match is not None
        and int(match.group("revision"), 10) < PE_UINT32_LIMIT,
        f"{label} is malformed",
    )


if os.name == "nt":

    def _windows_api_error(operation: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{operation}: {ctypes.FormatError(code).strip()}")


    def _close_windows_handle(handle: int, label: str) -> None:
        if not _CloseHandle(handle):
            raise _windows_api_error(f"CloseHandle for {label} failed")


    def _create_windows_kill_job() -> int:
        _require(
            ctypes.sizeof(_JobObjectBasicLimitInformation) == 64
            and ctypes.sizeof(_IoCounters) == 48
            and ctypes.sizeof(_JobObjectExtendedLimitInformation) == 144
            and ctypes.sizeof(_ThreadEntry32) == 28,
            "Windows job-object ctypes layout differs from the x64 ABI",
        )
        job = _CreateJobObjectW(None, None)
        if not job:
            raise _windows_api_error("CreateJobObjectW failed")
        information = _JobObjectExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not _SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error = _windows_api_error("SetInformationJobObject failed")
            try:
                _close_windows_handle(job, "unconfigured job")
            except OSError as close_error:
                raise close_error from error
            raise error
        return int(job)


    def _assign_process_to_windows_job(job: int, process_id: int) -> None:
        process_handle = _OpenProcess(
            _PROCESS_TERMINATE | _PROCESS_SET_QUOTA,
            False,
            process_id,
        )
        if not process_handle:
            raise _windows_api_error("OpenProcess failed")
        try:
            if not _AssignProcessToJobObject(job, process_handle):
                raise _windows_api_error("AssignProcessToJobObject failed")
        finally:
            _close_windows_handle(process_handle, "process")


    def _resume_suspended_windows_process(process_id: int) -> None:
        snapshot = _CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot == _INVALID_HANDLE_VALUE:
            raise _windows_api_error("CreateToolhelp32Snapshot failed")
        try:
            entry = _ThreadEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            if not _Thread32First(snapshot, ctypes.byref(entry)):
                raise _windows_api_error("Thread32First failed")
            thread_ids: list[int] = []
            while True:
                if entry.th32OwnerProcessID == process_id:
                    thread_ids.append(int(entry.th32ThreadID))
                entry.dwSize = ctypes.sizeof(entry)
                ctypes.set_last_error(0)
                if _Thread32Next(snapshot, ctypes.byref(entry)):
                    continue
                error_code = ctypes.get_last_error()
                if error_code != _ERROR_NO_MORE_FILES:
                    raise OSError(
                        error_code,
                        "Thread32Next failed: "
                        f"{ctypes.FormatError(error_code).strip()}",
                    )
                break
            _require(
                len(thread_ids) == 1,
                "suspended native-tool process must have exactly one initial thread",
            )
            thread = _OpenThread(_THREAD_SUSPEND_RESUME, False, thread_ids[0])
            if not thread:
                raise _windows_api_error("OpenThread failed")
            try:
                previous_suspend_count = int(_ResumeThread(thread))
                if previous_suspend_count == 0xFFFFFFFF:
                    raise _windows_api_error("ResumeThread failed")
                _require(
                    previous_suspend_count == 1,
                    "native-tool initial thread suspend count differs",
                )
            finally:
                _close_windows_handle(thread, "initial thread")
        finally:
            _close_windows_handle(snapshot, "thread snapshot")


    def _terminate_and_close_windows_job(job: int) -> None:
        termination_error = None
        if not _TerminateJobObject(job, 1):
            termination_error = _windows_api_error("TerminateJobObject failed")
        try:
            _close_windows_handle(job, "job")
        except OSError as close_error:
            if termination_error is not None:
                raise close_error from termination_error
            raise
        if termination_error is not None:
            raise termination_error


def _sha256(path: pathlib.Path) -> str:
    try:
        return read_regular_snapshot(
            path, maximum=MAX_PACKAGE_FILE_BYTES, label="Windows package file"
        ).sha256
    except EvidenceIOError as exc:
        raise WindowsPackageError(str(exc)) from exc


def _load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        return load_json_object_snapshot(path, maximum=MAX_JSON_BYTES, label=label).value
    except EvidenceIOError as exc:
        raise WindowsPackageError(str(exc)) from exc


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _tree_hash(repository_root: pathlib.Path, relative_inputs: Iterable[str]) -> str:
    """Hash the complete Rust workspace build-input closure deterministically."""

    repository = pathlib.Path(repository_root).resolve(strict=True)
    candidates: dict[str, pathlib.Path] = {}
    for relative in relative_inputs:
        pure = pathlib.PurePosixPath(relative)
        _require(
            not pure.is_absolute()
            and ".." not in pure.parts
            and pure.as_posix() == relative,
            f"unsafe Windows source-tree input: {relative!r}",
        )
        source = repository.joinpath(*pure.parts)
        try:
            metadata = source.lstat()
        except OSError as exc:
            raise WindowsPackageError(f"cannot inspect source-tree input {relative}: {exc}") from exc
        _require(not source.is_symlink(), f"source-tree input must not be a symlink: {relative}")
        if stat.S_ISREG(metadata.st_mode):
            candidates[relative] = source
            continue
        _require(stat.S_ISDIR(metadata.st_mode), f"source-tree input has unsupported type: {relative}")
        try:
            descendants = sorted(source.rglob("*"), key=lambda path: path.as_posix())
        except OSError as exc:
            raise WindowsPackageError(f"cannot enumerate source-tree input {relative}: {exc}") from exc
        for descendant in descendants:
            try:
                descendant_metadata = descendant.lstat()
            except OSError as exc:
                raise WindowsPackageError(f"cannot inspect source-tree input {descendant}: {exc}") from exc
            _require(not descendant.is_symlink(), f"source-tree input contains symlink: {descendant}")
            _require(
                stat.S_ISDIR(descendant_metadata.st_mode)
                or stat.S_ISREG(descendant_metadata.st_mode),
                f"source-tree input has unsupported entry: {descendant}",
            )
            if stat.S_ISREG(descendant_metadata.st_mode):
                relative_descendant = descendant.relative_to(repository).as_posix()
                _require(relative_descendant not in candidates, f"duplicate source-tree path: {relative_descendant}")
                candidates[relative_descendant] = descendant
    _require(bool(candidates), "Windows source-tree input closure is empty")
    digest = hashlib.sha256()
    for relative, path in sorted(candidates.items()):
        snapshot = read_regular_snapshot(
            path,
            maximum=MAX_PACKAGE_FILE_BYTES,
            label=f"Windows source-tree input {relative}",
        )
        relative_bytes = relative.encode("utf-8")
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(snapshot.size.to_bytes(8, "big"))
        digest.update(snapshot.data)
    return digest.hexdigest()


def _validate_package_root(root: pathlib.Path) -> pathlib.Path:
    original = pathlib.Path(root)
    try:
        metadata = original.lstat()
        resolved = original.resolve(strict=True)
    except OSError as exc:
        raise WindowsPackageError(f"cannot resolve Windows package root {root}: {exc}") from exc
    _require(stat.S_ISDIR(metadata.st_mode) and not original.is_symlink(), "Windows package root must be a non-symlink directory")
    return resolved


def _inventory(root: pathlib.Path) -> dict[str, pathlib.Path]:
    files: dict[str, pathlib.Path] = {}
    for path in sorted(root.rglob("*")):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WindowsPackageError(f"cannot inspect package entry {path}: {exc}") from exc
        _require(not path.is_symlink(), f"Windows package entry must not be a symlink: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        _require(stat.S_ISREG(metadata.st_mode), f"Windows package entry must be a regular file: {path}")
        relative = path.relative_to(root).as_posix()
        _require(relative not in files, f"duplicate Windows package path: {relative}")
        files[relative] = path
    return files


def _third_party_rust_files(root: pathlib.Path) -> tuple[dict[str, Any], frozenset[str]]:
    try:
        inventory = verify_third_party_licenses(root, expected_target=TARGET)
    except ThirdPartyLicenseError as exc:
        raise WindowsPackageError(f"third-party Rust licenses are invalid: {exc}") from exc
    paths = {THIRD_PARTY_INVENTORY_RELATIVE.as_posix()}
    for package in inventory["packages"]:
        for license_file in package["license_files"]:
            paths.add(license_file["path"])
    return inventory, frozenset(paths)


def _validate_boms(package_root: pathlib.Path, repository_root: pathlib.Path | None) -> None:
    try:
        verify_package_boms(
            package_root,
            cargo_lock=(repository_root / "Cargo.lock") if repository_root else None,
        )
    except PackageBomError as exc:
        raise WindowsPackageError(str(exc)) from exc


def _validate_contracts(package_root: pathlib.Path, repository_root: pathlib.Path | None) -> tuple[str, str]:
    embedded_path = package_root / "share/q-periapt/abi/q-periapt-c-abi-v2.json"
    try:
        embedded = load_contract(embedded_path)
    except ValueError as exc:
        raise WindowsPackageError(f"embedded ABI contract is invalid: {exc}") from exc
    _require(embedded.document["package"]["semver"] == PACKAGE_SEMVER, "embedded contract package version differs")
    identity = embedded.document["package"]["platforms"][ABI_PLATFORM]
    _require(identity["shared_filename"] == "q_periapt_ffi_abi2.dll", "embedded Windows DLL identity differs")
    _require(identity["import_library_filename"] == "q_periapt_ffi_abi2.lib", "embedded Windows import-library identity differs")
    _require(identity["static_filename"] == "q_periapt_ffi_abi2_static.lib", "embedded Windows static-library identity differs")
    if repository_root is not None:
        source = load_contract(
            repository_root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
        )
        _require(source.sha256 == embedded.sha256, "embedded ABI contract differs from repository trust root")
    exports = sorted(item["name"] for item in embedded.document["abi"]["exports"])
    _require(len(exports) == 9 and len(exports) == len(set(exports)), "ABI export set is not exactly nine unique names")
    exports_sha256 = hashlib.sha256(("\n".join(exports) + "\n").encode()).hexdigest()
    return embedded.sha256, exports_sha256


def _normalize_dependencies(dependencies: Iterable[str]) -> list[str]:
    normalized: dict[str, str] = {}
    for raw in dependencies:
        _require(isinstance(raw, str) and SAFE_DEPENDENCY_RE.fullmatch(raw) is not None, f"invalid Windows DLL dependency: {raw!r}")
        _require(
            re.fullmatch(r"q_periapt_ffi(?:_abi[12])?\.dll", raw, re.IGNORECASE)
            is None,
            f"legacy or recursive Q-Periapt DLL dependency: {raw}",
        )
        _require(
            raw.casefold() in ALLOWED_DEPENDENCY_NAMES,
            f"unexpected Windows DLL dependency: {raw}",
        )
        key = raw.casefold()
        _require(key not in normalized, f"duplicate Windows DLL dependency: {raw}")
        normalized[key] = raw
    _require(normalized, "Windows DLL dependency set must not be empty")
    return [normalized[key] for key in sorted(normalized)]


def parse_dumpbin_dependents(output: bytes) -> list[str]:
    """Parse the one canonical dependency block without ignoring malformed imports."""

    _require(isinstance(output, bytes), "dumpbin dependency output must be bytes")
    _require(
        len(output) <= MAX_DUMPBIN_OUTPUT_BYTES,
        "dumpbin dependency output exceeds the size limit",
    )
    _require(b"\0" not in output, "dumpbin dependency output contains a NUL byte")
    lines = output.splitlines()
    dependency_headers = [
        index
        for index, line in enumerate(lines)
        if line.strip().startswith(b"Image has the following ")
        and line.strip().endswith(b"dependencies:")
    ]
    _require(
        len(dependency_headers) == 1
        and lines[dependency_headers[0]].strip() == DUMPBIN_DEPENDENCY_HEADER,
        "dumpbin must emit exactly one canonical dependency header",
    )
    summaries = [
        index
        for index, line in enumerate(lines)
        if line.strip() == DUMPBIN_SUMMARY_HEADER
    ]
    _require(
        len(summaries) == 1 and dependency_headers[0] < summaries[0],
        "dumpbin must emit exactly one Summary after the dependency block",
    )
    dependencies: list[str] = []
    for raw_line in lines[dependency_headers[0] + 1 : summaries[0]]:
        candidate = raw_line.strip(b" \t")
        if not candidate:
            continue
        try:
            dependency = candidate.decode("ascii")
        except UnicodeDecodeError as exc:
            raise WindowsPackageError(
                "dumpbin dependency name is not portable ASCII"
            ) from exc
        _require(
            SAFE_DEPENDENCY_RE.fullmatch(dependency) is not None,
            f"invalid Windows DLL dependency: {dependency!r}",
        )
        dependencies.append(dependency)
    return _normalize_dependencies(dependencies)


def parse_rustc_native_static_libraries(output: bytes) -> list[str]:
    """Parse and freeze rustc's ordered Windows static-link contract."""

    _require(isinstance(output, bytes), "rustc native-static-libs output must be bytes")
    _require(
        len(output) <= MAX_RUSTC_NATIVE_STATIC_LIBS_BYTES,
        "rustc native-static-libs output exceeds the size limit",
    )
    _require(b"\0" not in output, "rustc native-static-libs output contains a NUL byte")
    _require(
        b"\x1b" not in output,
        "rustc native-static-libs output contains an unsupported terminal escape",
    )
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WindowsPackageError(
            "rustc native-static-libs output is not portable ASCII"
        ) from exc
    marker = "native-static-libs:"
    _require(
        text.count(marker) == 1,
        "rustc must emit exactly one native-static-libs marker",
    )
    matches = re.findall(
        r"(?m)^\s*(?:note:\s*)?native-static-libs:\s*(\S(?:[^\r\n]*\S)?)\s*$",
        text,
        flags=re.ASCII,
    )
    _require(
        len(matches) == 1,
        "rustc must emit exactly one canonical native-static-libs line",
    )
    libraries = matches[0].split()
    _require(
        tuple(libraries) == EXPECTED_WINDOWS_NATIVE_STATIC_LIBRARY_TOKENS,
        "rustc Windows native-static-libs contract differs",
    )
    return list(CANONICAL_WINDOWS_NATIVE_STATIC_LIBRARIES)


def _decode_rust_debug_string(
    command: str,
    offset: int,
    *,
    label: str,
) -> tuple[str, int]:
    _require(
        offset < len(command) and command[offset] == '"',
        f"rustc linker command {label} is not a quoted string",
    )
    try:
        value, end = json.JSONDecoder().raw_decode(command, offset)
    except json.JSONDecodeError as exc:
        raise WindowsPackageError(
            f"rustc linker command {label} has unsupported escaping"
        ) from exc
    _require(
        isinstance(value, str) and "\0" not in value,
        f"rustc linker command {label} is malformed",
    )
    _require(
        command[offset:end] == json.dumps(value, ensure_ascii=False),
        f"rustc linker command {label} is not encoded canonically",
    )
    return value, end


def _parse_windows_rust_debug_command(output: bytes) -> tuple[str, list[str]]:
    """Parse Windows rustc's bounded ``--print link-args`` representation."""

    _require(isinstance(output, bytes), "rustc link-args output must be bytes")
    _require(
        len(output) <= MAX_RUSTC_LINK_ARGUMENTS_BYTES,
        "rustc link-args output exceeds the size limit",
    )
    _require(b"\0" not in output, "rustc link-args output contains a NUL byte")
    _require(
        output.endswith(b"\n")
        and output.count(b"\n") == 1
        and b"\r" not in output,
        "rustc link-args output must contain exactly one LF-terminated command",
    )
    try:
        command = output[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WindowsPackageError("rustc link-args output is not UTF-8") from exc

    program, offset = _decode_rust_debug_string(
        command,
        0,
        label="program",
    )
    arguments: list[str] = []
    while offset < len(command):
        _require(
            command[offset] == " ",
            "rustc linker command tokens are not separated canonically",
        )
        argument, offset = _decode_rust_debug_string(
            command,
            offset + 1,
            label="argument",
        )
        arguments.append(argument)
    _require(arguments, "rustc linker command has no arguments")
    return program, arguments


def _canonical_windows_linker_path(value: str, *, label: str) -> str:
    _require(
        isinstance(value, str)
        and "\0" not in value
        and WINDOWS_DRIVE_ABSOLUTE_RE.match(value) is not None,
        f"{label} must be an absolute Windows drive path",
    )
    normalized = ntpath.normpath(value)
    _require(
        value == normalized,
        f"{label} must be a canonical backslash-separated path",
    )
    _require(
        ntpath.basename(normalized).casefold() == "link.exe",
        f"{label} must name link.exe",
    )
    return ntpath.normcase(normalized)


def verify_rustc_linker_invocation(
    output: bytes,
    expected_linker: str,
) -> list[str]:
    """Validate the link-args half of the PowerShell-enforced linker proof."""

    program, arguments = _parse_windows_rust_debug_command(output)
    _require(
        program == "link.exe",
        "rustc linker program must be the exact bare link.exe name",
    )
    _canonical_windows_linker_path(
        expected_linker,
        label="expected MSVC linker",
    )
    folded_arguments = [argument.casefold() for argument in arguments]
    for required in REQUIRED_MSVC_LINK_ARGUMENTS:
        _require(
            folded_arguments.count(required) == 1,
            f"rustc linker command must contain exactly one {required} argument",
        )
    _require(
        "/wx:no" not in folded_arguments,
        "rustc linker command disables warnings-as-errors",
    )
    repro_options = [
        (index, argument)
        for index, argument in enumerate(folded_arguments)
        if argument.startswith(("/brepro", "-brepro"))
    ]
    _require(
        [argument for _index, argument in repro_options] == ["/brepro"],
        "rustc linker reproducible-build option contract differs",
    )
    coff_group_options = [
        (index, argument)
        for index, argument in enumerate(folded_arguments)
        if argument.startswith(
            (
                "/nocoffgrpinfo",
                "-nocoffgrpinfo",
                "/coffgrpinfo",
                "-coffgrpinfo",
            )
        )
    ]
    _require(
        [argument for _index, argument in coff_group_options]
        == ["/nocoffgrpinfo"],
        "rustc linker COFF-group metadata option contract differs",
    )

    debug_options = [
        (index, argument)
        for index, argument in enumerate(folded_arguments)
        if argument.startswith(("/debug", "-debug"))
    ]
    _require(
        [argument for _index, argument in debug_options]
        == ["/debug", "/debug:none"],
        "rustc linker command must contain one automatic /DEBUG followed by one /DEBUG:NONE",
    )
    pdb_options = [
        (index, argument)
        for index, argument in enumerate(folded_arguments)
        if argument.startswith(("/pdb", "-pdb"))
    ]
    _require(
        [argument for _index, argument in pdb_options]
        == ["/pdbaltpath:%_pdb%"],
        "rustc linker PDB option contract differs",
    )
    opt_options = [
        (index, argument)
        for index, argument in enumerate(folded_arguments)
        if argument.startswith(("/opt", "-opt"))
    ]
    # Optimized Rust MSVC links emit ICF automatically. The release script
    # deliberately appends NOICF after disabling debug output, so accepting
    # this exact order proves the final linker state without hiding a changed
    # compiler default or permitting an earlier NOICF to be overridden.
    _require(
        [argument for _index, argument in opt_options]
        == ["/opt:ref,icf", "/opt:ref,noicf"],
        "rustc linker optimization option contract differs",
    )
    automatic_debug_index = debug_options[0][0]
    disabled_debug_index = debug_options[1][0]
    pdb_altpath_index = pdb_options[0][0]
    warnings_as_errors_index = folded_arguments.index("/wx")
    reproducible_link_index = repro_options[0][0]
    no_coff_group_info_index = coff_group_options[0][0]
    _require(
        opt_options[0][0]
        < automatic_debug_index
        < pdb_altpath_index
        < warnings_as_errors_index
        < disabled_debug_index
        < reproducible_link_index
        < no_coff_group_info_index
        < opt_options[1][0],
        "rustc linker debug/PDB/repro/COFF-group/optimization options are not ordered fail-closed",
    )
    return arguments


def _pe_uint(data: bytes, offset: int, size: int, label: str) -> int:
    _require(
        type(offset) is int
        and type(size) is int
        and offset >= 0
        and size > 0
        and offset + size <= len(data),
        f"Windows PE {label} is truncated",
    )
    return int.from_bytes(data[offset : offset + size], "little")


def _map_pe_rva(
    data: bytes,
    rva: int,
    size: int,
    *,
    size_of_headers: int,
    sections: list[tuple[int, int, int, int]],
    label: str,
) -> int:
    """Map one complete RVA range to exactly one file-backed PE range."""

    _require(
        type(rva) is int
        and type(size) is int
        and rva > 0
        and size > 0
        and rva + size <= PE_UINT32_LIMIT,
        f"Windows PE {label} RVA range is invalid",
    )
    end_rva = rva + size
    candidates: list[int] = []
    if rva < size_of_headers and end_rva <= size_of_headers:
        _require(
            end_rva <= len(data),
            f"Windows PE {label} header range exceeds the file",
        )
        candidates.append(rva)

    for virtual_address, virtual_size, raw_pointer, raw_size in sections:
        virtual_extent = max(virtual_size, raw_size)
        _require(
            virtual_address + virtual_extent <= PE_UINT32_LIMIT,
            "Windows PE section virtual range overflows 32 bits",
        )
        if not (
            virtual_extent > 0
            and virtual_address <= rva
            and end_rva <= virtual_address + virtual_extent
        ):
            continue
        relative = rva - virtual_address
        _require(
            relative + size <= raw_size,
            f"Windows PE {label} is not completely file-backed",
        )
        file_offset = raw_pointer + relative
        _require(
            file_offset + size <= len(data),
            f"Windows PE {label} file range is truncated",
        )
        candidates.append(file_offset)

    _require(
        len(candidates) == 1,
        f"Windows PE {label} RVA must map to exactly one file range",
    )
    return candidates[0]


def _parse_pe_base_relocations(
    data: bytes,
    directory_offset: int,
    directory_size: int,
    *,
    size_of_headers: int,
    sections: list[tuple[int, int, int, int]],
) -> int:
    """Validate every x64 base-relocation block and count real DIR64 entries."""

    _require(
        8 <= directory_size <= MAX_PE_RELOCATION_DIRECTORY_BYTES,
        "Windows PE base-relocation directory size is invalid",
    )
    _require(
        directory_offset + directory_size <= len(data),
        "Windows PE base-relocation directory is truncated",
    )
    cursor = 0
    total_entries = 0
    dir64_count = 0
    previous_page_rva = -1
    while cursor < directory_size:
        _require(
            cursor % 4 == 0 and directory_size - cursor >= 8,
            "Windows PE base-relocation block is truncated or misaligned",
        )
        block = directory_offset + cursor
        page_rva = _pe_uint(data, block, 4, "base-relocation page RVA")
        block_size = _pe_uint(data, block + 4, 4, "base-relocation block size")
        _require(
            page_rva > previous_page_rva
            and page_rva % 0x1000 == 0
            and page_rva < PE_UINT32_LIMIT,
            "Windows PE base-relocation pages are not canonical",
        )
        _require(
            block_size >= 8
            and block_size % 4 == 0
            and cursor + block_size <= directory_size,
            "Windows PE base-relocation block size is invalid",
        )
        block_entries = (block_size - 8) // 2
        _require(
            total_entries + block_entries <= MAX_PE_RELOCATION_ENTRIES,
            "Windows PE base-relocation entry count exceeds the policy limit",
        )
        total_entries += block_entries
        previous_page_rva = page_rva
        seen_offsets: set[int] = set()
        absolute_padding_seen = False
        for entry_offset in range(8, block_size, 2):
            entry = _pe_uint(
                data,
                block + entry_offset,
                2,
                "base-relocation entry",
            )
            relocation_type = entry >> 12
            offset_within_page = entry & 0x0FFF
            if relocation_type == PE_RELOCATION_TYPE_ABSOLUTE:
                _require(
                    entry == 0
                    and not absolute_padding_seen
                    and entry_offset == block_size - 2,
                    "Windows PE ABSOLUTE base-relocation padding differs",
                )
                absolute_padding_seen = True
                continue
            _require(
                relocation_type == PE_RELOCATION_TYPE_DIR64,
                "Windows PE contains a non-DIR64 base relocation",
            )
            target_rva = page_rva + offset_within_page
            _require(
                target_rva + 8 <= PE_UINT32_LIMIT
                and offset_within_page not in seen_offsets,
                "Windows PE DIR64 relocation target is invalid or duplicated",
            )
            target_offset = _map_pe_rva(
                data,
                target_rva,
                8,
                size_of_headers=size_of_headers,
                sections=sections,
                label="DIR64 relocation target",
            )
            _require(
                target_offset + 8 <= directory_offset
                or directory_offset + directory_size <= target_offset,
                "Windows PE DIR64 relocation targets its relocation directory",
            )
            seen_offsets.add(offset_within_page)
            dir64_count += 1
        cursor += block_size
    _require(
        cursor == directory_size and dir64_count > 0,
        "Windows PE contains no effective DIR64 base relocation",
    )
    return dir64_count


def parse_windows_pe_evidence(data: bytes) -> dict[str, Any]:
    """Parse the exact native x64 PE policy without trusting localized tools."""

    _require(type(data) is bytes, "Windows PE evidence must be exact bytes")
    _require(len(data) >= 64, "Windows PE DOS header is truncated")
    _require(data[:2] == b"MZ", "Windows PE DOS signature differs")
    pe_offset = _pe_uint(data, 0x3C, 4, "PE header offset")
    _require(
        pe_offset >= 64 and pe_offset % 4 == 0,
        "Windows PE header offset is invalid",
    )
    _require(
        pe_offset + 24 <= len(data),
        "Windows PE signature or COFF header is truncated",
    )
    _require(data[pe_offset : pe_offset + 4] == b"PE\0\0", "Windows PE signature differs")

    coff = pe_offset + 4
    machine = _pe_uint(data, coff, 2, "machine")
    number_of_sections = _pe_uint(data, coff + 2, 2, "section count")
    pointer_to_symbols = _pe_uint(data, coff + 8, 4, "COFF symbol-table pointer")
    number_of_symbols = _pe_uint(data, coff + 12, 4, "COFF symbol count")
    optional_size = _pe_uint(data, coff + 16, 2, "optional-header size")
    characteristics = _pe_uint(data, coff + 18, 2, "COFF characteristics")
    _require(machine == PE_MACHINE_AMD64, "Windows PE machine is not x86_64")
    _require(
        1 <= number_of_sections <= PE_MAX_SECTIONS,
        "Windows PE section count is invalid",
    )
    _require(
        pointer_to_symbols == 0 and number_of_symbols == 0,
        "Windows PE contains a deprecated COFF symbol table",
    )
    _require(
        characteristics & PE_FILE_RELOCS_STRIPPED == 0,
        "Windows PE strips the relocations required for ASLR",
    )
    _require(
        characteristics & (PE_FILE_EXECUTABLE_IMAGE | PE_FILE_DLL)
        == (PE_FILE_EXECUTABLE_IMAGE | PE_FILE_DLL),
        "Windows PE is not an executable DLL image",
    )

    optional = coff + 20
    optional_end = optional + optional_size
    _require(optional_end <= len(data), "Windows PE optional header is truncated")
    _require(
        optional_size >= 168,
        "Windows PE optional header cannot contain the debug directory",
    )
    _require(
        _pe_uint(data, optional, 2, "optional-header magic") == PE32_PLUS_MAGIC,
        "Windows PE is not PE32+",
    )
    size_of_headers = _pe_uint(data, optional + 60, 4, "SizeOfHeaders")
    dll_characteristics = _pe_uint(
        data, optional + 70, 2, "DLL characteristics"
    )
    required_dll_characteristics = PE_HIGH_ENTROPY_VA | PE_DYNAMIC_BASE | PE_NX_COMPAT
    _require(
        dll_characteristics & required_dll_characteristics
        == required_dll_characteristics,
        "Windows PE ASLR/NX/high-entropy hardening differs",
    )
    number_of_directories = _pe_uint(
        data, optional + 108, 4, "data-directory count"
    )
    directory_capacity = (optional_size - 112) // 8
    _require(
        7 <= number_of_directories <= directory_capacity,
        "Windows PE data-directory count is inconsistent with the optional header",
    )

    section_table = optional_end
    section_table_end = section_table + number_of_sections * 40
    _require(
        section_table_end <= size_of_headers <= len(data),
        "Windows PE section table or SizeOfHeaders is invalid",
    )
    sections: list[tuple[int, int, int, int]] = []
    raw_ranges: list[tuple[int, int]] = []
    for index in range(number_of_sections):
        section = section_table + index * 40
        virtual_size = _pe_uint(data, section + 8, 4, "section VirtualSize")
        virtual_address = _pe_uint(data, section + 12, 4, "section VirtualAddress")
        raw_size = _pe_uint(data, section + 16, 4, "section SizeOfRawData")
        raw_pointer = _pe_uint(data, section + 20, 4, "section PointerToRawData")
        if raw_size:
            _require(
                raw_pointer >= size_of_headers
                and raw_pointer + raw_size <= len(data),
                "Windows PE section raw range is invalid",
            )
            raw_ranges.append((raw_pointer, raw_pointer + raw_size))
        sections.append((virtual_address, virtual_size, raw_pointer, raw_size))
    for previous, current in zip(sorted(raw_ranges), sorted(raw_ranges)[1:]):
        _require(
            previous[1] <= current[0],
            "Windows PE section raw ranges overlap",
        )

    relocation_directory = optional + 112 + 5 * 8
    relocation_rva = _pe_uint(
        data, relocation_directory, 4, "base-relocation directory RVA"
    )
    relocation_size = _pe_uint(
        data, relocation_directory + 4, 4, "base-relocation directory size"
    )
    _require(
        relocation_rva > 0 and relocation_size > 0,
        "Windows PE base-relocation directory is missing",
    )
    relocation_offset = _map_pe_rva(
        data,
        relocation_rva,
        relocation_size,
        size_of_headers=size_of_headers,
        sections=sections,
        label="base-relocation directory",
    )
    dir64_count = _parse_pe_base_relocations(
        data,
        relocation_offset,
        relocation_size,
        size_of_headers=size_of_headers,
        sections=sections,
    )

    certificate_directory = optional + 112 + 4 * 8
    certificate_pointer = _pe_uint(
        data, certificate_directory, 4, "certificate-table file pointer"
    )
    certificate_size = _pe_uint(
        data, certificate_directory + 4, 4, "certificate-table size"
    )
    _require(
        certificate_pointer == 0 and certificate_size == 0,
        "unsigned Windows PE unexpectedly contains an Authenticode certificate table",
    )

    debug_directory = optional + 112 + 6 * 8
    debug_rva = _pe_uint(data, debug_directory, 4, "debug-directory RVA")
    debug_size = _pe_uint(data, debug_directory + 4, 4, "debug-directory size")
    diagnostic = ""
    diagnostic_count = debug_size // PE_DEBUG_DIRECTORY_SIZE
    if (
        debug_size != PE_DEBUG_DIRECTORY_SIZE
        and debug_size % PE_DEBUG_DIRECTORY_SIZE == 0
        and 2 <= diagnostic_count <= MAX_PE_DEBUG_DIAGNOSTIC_ENTRIES
    ):
        diagnostic_offset = _map_pe_rva(
            data,
            debug_rva,
            debug_size,
            size_of_headers=size_of_headers,
            sections=sections,
            label="debug directory diagnostic",
        )
        _require(
            relocation_offset + relocation_size <= diagnostic_offset
            or diagnostic_offset + debug_size <= relocation_offset,
            "Windows PE debug and base-relocation directories overlap",
        )
        entries: list[str] = []
        for index in range(diagnostic_count):
            entry = diagnostic_offset + index * PE_DEBUG_DIRECTORY_SIZE
            entry_type = _pe_uint(data, entry + 12, 4, "debug entry Type")
            data_size = _pe_uint(data, entry + 16, 4, "debug entry SizeOfData")
            entries.append(
                f"{index}:type={entry_type},size_of_data={data_size}"
            )
        diagnostic = "; entries=[" + ";".join(entries) + "]"
    _require(
        debug_size == PE_DEBUG_DIRECTORY_SIZE,
        "Windows PE must contain exactly one debug-directory entry "
        f"(observed size {debug_size} bytes{diagnostic})",
    )
    debug_offset = _map_pe_rva(
        data,
        debug_rva,
        debug_size,
        size_of_headers=size_of_headers,
        sections=sections,
        label="debug directory",
    )
    _require(
        relocation_offset + relocation_size <= debug_offset
        or debug_offset + debug_size <= relocation_offset,
        "Windows PE debug and base-relocation directories overlap",
    )
    reserved = _pe_uint(data, debug_offset, 4, "debug entry Characteristics")
    major_version = _pe_uint(data, debug_offset + 8, 2, "debug entry MajorVersion")
    minor_version = _pe_uint(data, debug_offset + 10, 2, "debug entry MinorVersion")
    debug_type = _pe_uint(data, debug_offset + 12, 4, "debug entry Type")
    data_size = _pe_uint(data, debug_offset + 16, 4, "debug entry SizeOfData")
    data_rva = _pe_uint(data, debug_offset + 20, 4, "debug entry AddressOfRawData")
    data_pointer = _pe_uint(data, debug_offset + 24, 4, "debug entry PointerToRawData")
    _require(
        reserved == 0 and major_version == 0 and minor_version == 0,
        "Windows PE REPRO entry reserved/version fields differ",
    )
    _require(
        debug_type == PE_DEBUG_TYPE_REPRO,
        "Windows PE debug directory is not REPRO-only",
    )

    if data_size == 0:
        _require(
            data_rva == 0 and data_pointer == 0,
            "Windows PE empty REPRO entry has raw-data references",
        )
        payload_kind = "empty"
        hash_bytes = 0
    else:
        _require(
            data_size == 36 and data_rva > 0 and data_pointer > 0,
            "Windows PE REPRO hash payload shape differs",
        )
        mapped_pointer = _map_pe_rva(
            data,
            data_rva,
            data_size,
            size_of_headers=size_of_headers,
            sections=sections,
            label="REPRO hash payload",
        )
        _require(
            mapped_pointer == data_pointer,
            "Windows PE REPRO hash RVA and file pointer differ",
        )
        _require(
            data_pointer + data_size <= len(data),
            "Windows PE REPRO hash payload is truncated",
        )
        _require(
            data_pointer + data_size <= debug_offset
            or debug_offset + debug_size <= data_pointer,
            "Windows PE REPRO hash payload overlaps its directory entry",
        )
        _require(
            data_pointer + data_size <= relocation_offset
            or relocation_offset + relocation_size <= data_pointer,
            "Windows PE REPRO hash payload overlaps base relocations",
        )
        hash_bytes = _pe_uint(data, data_pointer, 4, "REPRO hash length")
        _require(
            hash_bytes == 32 and hash_bytes + 4 == data_size,
            "Windows PE REPRO hash length differs",
        )
        payload_kind = "length_prefixed_hash"

    return {
        "authenticode_certificate_directory_present": False,
        "hardening": {
            "machine": "x86_64",
            "dynamic_base": True,
            "nx_compatible": True,
            "high_entropy_va": True,
            "base_relocations": {
                "directory_present": True,
                "dir64_count": dir64_count,
            },
            "debug_directory": {
                "entry_count": 1,
                "entry_type": "IMAGE_DEBUG_TYPE_REPRO",
                "payload_kind": payload_kind,
                "hash_bytes": hash_bytes,
            },
        },
    }


def inspect_windows_pe_evidence(
    library: pathlib.Path,
) -> tuple[dict[str, Any], str, int]:
    """Read one stable DLL snapshot and return its PE evidence, digest, and size."""

    dll = pathlib.Path(library)
    _require(
        dll.name == "q_periapt_ffi_abi2.dll",
        "Windows DLL filename differs from the ABI contract",
    )
    try:
        snapshot = read_regular_snapshot(
            dll,
            maximum=MAX_PACKAGE_FILE_BYTES,
            label="Windows ABI2 DLL",
        )
    except EvidenceIOError as exc:
        raise WindowsPackageError(str(exc)) from exc
    return parse_windows_pe_evidence(snapshot.data), snapshot.sha256, snapshot.size


def _regular_windows_tool(
    path: pathlib.Path,
    *,
    expected_name: str,
    label: str,
) -> pathlib.Path:
    tool = pathlib.Path(path)
    _require(tool.is_absolute(), f"{label} path must be absolute")
    try:
        metadata = tool.lstat()
    except OSError as exc:
        raise WindowsPackageError(f"cannot inspect the {label} executable") from exc
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not tool.is_symlink()
        and not (
            getattr(metadata, "st_file_attributes", 0)
            & FILE_ATTRIBUTE_REPARSE_POINT
        ),
        f"{label} must be a non-reparse regular file",
    )
    _require(
        tool.name.casefold() == expected_name.casefold(),
        f"{label} executable name differs",
    )
    return tool


def _read_bounded_process_stream(stream: BinaryIO, maximum: int) -> bytes:
    """Drain a process pipe while retaining only enough bytes to prove overflow."""

    retained = bytearray()
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        remaining = maximum + 1 - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return bytes(retained)


def _run_bounded_process(
    arguments: list[str],
    *,
    cwd: str,
    stdin: int,
    stdout: int,
    stderr: int,
    check: bool,
    timeout: int,
    output_limit: int = MAX_DUMPBIN_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    """Run a native tool with concurrent, bounded capture and tree cleanup."""

    _require(stdin == subprocess.DEVNULL, "bounded process stdin contract differs")
    _require(
        stdout == subprocess.PIPE and stderr == subprocess.PIPE,
        "bounded process output contract differs",
    )
    _require(check is False, "bounded process must return native failure evidence")
    _require(
        type(output_limit) is int and 0 < output_limit <= MAX_DUMPBIN_OUTPUT_BYTES,
        "bounded process output limit is invalid",
    )
    process: subprocess.Popen[bytes] | None = None
    windows_job: int | None = None
    windows_assigned = False
    reader_streams: list[tuple[threading.Thread, BinaryIO]] = []
    started_readers: list[threading.Thread] = []
    timeout_error: subprocess.TimeoutExpired | None = None
    returncode: int | None = None

    try:
        if os.name == "nt":
            windows_job = _create_windows_kill_job()
            process = subprocess.Popen(
                arguments,
                cwd=cwd,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                bufsize=0,
                creationflags=_CREATE_SUSPENDED,
            )
        else:
            process = subprocess.Popen(
                arguments,
                cwd=cwd,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                bufsize=0,
                start_new_session=True,
            )
        run_deadline = time.monotonic() + timeout
        _require(
            process.stdout is not None and process.stderr is not None,
            "bounded process pipes are unavailable",
        )
        if os.name == "nt":
            _assign_process_to_windows_job(windows_job, process.pid)
            windows_assigned = True

        results: list[bytes | None] = [None, None]
        failures: list[Exception | None] = [None, None]

        def drain(index: int, stream: BinaryIO) -> None:
            try:
                results[index] = _read_bounded_process_stream(stream, output_limit)
            except Exception as exc:
                failures[index] = exc

        reader_streams = [
            (
                threading.Thread(
                    target=drain,
                    args=(0, process.stdout),
                    daemon=True,
                ),
                process.stdout,
            ),
            (
                threading.Thread(
                    target=drain,
                    args=(1, process.stderr),
                    daemon=True,
                ),
                process.stderr,
            ),
        ]
        for reader, _stream in reader_streams:
            try:
                reader.start()
            except RuntimeError as exc:
                raise WindowsPackageError(
                    "cannot start bounded native-tool output readers"
                ) from exc
            started_readers.append(reader)

        if os.name == "nt":
            _resume_suspended_windows_process(process.pid)

        remaining = max(0.0, run_deadline - time.monotonic())
        if remaining == 0:
            timeout_error = subprocess.TimeoutExpired(arguments, timeout)
        else:
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                timeout_error = exc
        if timeout_error is None:
            _require(
                process.returncode is not None,
                "native-tool process status is unavailable",
            )
            returncode = process.returncode
    finally:
        cleanup_failures: list[Exception] = []
        cleanup_deadline = time.monotonic() + 5.0
        direct_cleanup_required = False

        if os.name == "nt":
            if windows_job is not None:
                job = windows_job
                windows_job = None
                try:
                    if windows_assigned:
                        _terminate_and_close_windows_job(job)
                    else:
                        _close_windows_handle(job, "unassigned job")
                except Exception as exc:
                    cleanup_failures.append(exc)
                    direct_cleanup_required = True
            if process is not None and not windows_assigned:
                direct_cleanup_required = True
        elif process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                cleanup_failures.append(exc)
                direct_cleanup_required = True

        if (
            process is not None
            and direct_cleanup_required
            and process.poll() is None
        ):
            try:
                process.kill()
            except OSError as exc:
                cleanup_failures.append(exc)

        if process is not None and process.returncode is None:
            remaining = max(0.0, cleanup_deadline - time.monotonic())
            if remaining == 0:
                cleanup_failures.append(
                    WindowsPackageError(
                        "native-tool root process cleanup deadline expired"
                    )
                )
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired as exc:
                    cleanup_failures.append(exc)

        for reader in started_readers:
            remaining = max(0.0, cleanup_deadline - time.monotonic())
            if remaining > 0:
                reader.join(timeout=remaining)

        started_reader_ids = {id(reader) for reader in started_readers}
        for reader, stream in reader_streams:
            if id(reader) in started_reader_ids and reader.is_alive():
                cleanup_failures.append(
                    WindowsPackageError(
                        "native-tool output pipe did not close after process-tree cleanup"
                    )
                )
                continue
            try:
                stream.close()
            except (OSError, ValueError) as exc:
                cleanup_failures.append(exc)

        if process is not None and not reader_streams:
            for stream in (process.stdout, process.stderr):
                if stream is None:
                    continue
                try:
                    stream.close()
                except (OSError, ValueError) as exc:
                    cleanup_failures.append(exc)

        if cleanup_failures:
            first_cleanup_failure = cleanup_failures[0]
            cleanup_error = WindowsPackageError(
                "cannot clean up native-tool process tree: "
                f"{type(first_cleanup_failure).__name__}: {first_cleanup_failure}"
            )
            active_error = sys.exception()
            if active_error is not None:
                cleanup_error.add_note(
                    "native-tool operation also failed before cleanup: "
                    f"{type(active_error).__name__}: {active_error}"
                )
            for additional_failure in cleanup_failures[1:]:
                cleanup_error.add_note(
                    "additional cleanup failure: "
                    f"{type(additional_failure).__name__}: {additional_failure}"
                )
            raise cleanup_error from first_cleanup_failure

    failure = next((failure for failure in failures if failure is not None), None)
    if failure is not None:
        raise WindowsPackageError("cannot read native-tool process output") from failure
    if timeout_error is not None:
        raise timeout_error
    captured_stdout, captured_stderr = results
    _require(
        captured_stdout is not None and captured_stderr is not None,
        "native-tool process output capture is incomplete",
    )
    _require(returncode is not None, "native-tool process status is unavailable")
    return subprocess.CompletedProcess(
        arguments,
        returncode,
        captured_stdout,
        captured_stderr,
    )


def parse_msvc_version_probe(output: bytes) -> str:
    """Parse one exact, ASCII-only MSVC version and x64 identity record."""

    if (
        type(output) is not bytes
        or len(output) > MAX_MSVC_VERSION_PROBE_OUTPUT_BYTES
    ):
        raise WindowsPackageError("MSVC compiler version probe output is malformed")
    match = MSVC_VERSION_PROBE_RE.fullmatch(output)
    if match is None:
        raise WindowsPackageError("MSVC compiler version probe output is malformed")
    short_version = match.group("short")
    full_version = match.group("full")
    revision = int(match.group("revision"), 10)
    _require(
        full_version[:4] == short_version,
        "MSVC compiler version macros are inconsistent",
    )
    _require(
        revision < PE_UINT32_LIMIT,
        "MSVC compiler revision is out of range",
    )
    major = int(short_version[:2], 10)
    minor = int(short_version[2:], 10)
    build = int(full_version[4:], 10)
    return f"MSVC {major:02d}.{minor:02d}.{build}.{revision}"


def _read_frozen_msvc_version_probe(probe: pathlib.Path) -> FileSnapshot:
    probe_path = pathlib.Path(probe)
    _require(probe_path.is_absolute(), "MSVC version probe path must be absolute")
    _require(
        probe_path.name == MSVC_VERSION_PROBE_FILENAME,
        "MSVC version probe filename differs",
    )
    try:
        snapshot = read_regular_snapshot(
            probe_path,
            maximum=len(MSVC_VERSION_PROBE_SOURCE),
            label="MSVC version probe",
        )
    except EvidenceIOError as exc:
        raise WindowsPackageError(str(exc)) from exc
    _require(
        snapshot.data == MSVC_VERSION_PROBE_SOURCE,
        "MSVC version probe source differs from the frozen contract",
    )
    return snapshot


def inspect_msvc_version(
    compiler: pathlib.Path,
    probe: pathlib.Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = _run_bounded_process,
) -> str:
    """Run the resolved MSVC compiler against the frozen macro probe."""

    tool = _regular_windows_tool(
        compiler,
        expected_name="cl.exe",
        label="MSVC compiler",
    )
    probe_path = pathlib.Path(probe)
    probe_snapshot = _read_frozen_msvc_version_probe(probe_path)
    try:
        completed = runner(
            [
                str(tool),
                "/nologo",
                "/EP",
                "/TC",
                "/X",
                "/WX",
                str(probe_path),
            ],
            cwd=str(tool.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            output_limit=MAX_MSVC_VERSION_PROBE_OUTPUT_BYTES,
        )
    except subprocess.TimeoutExpired as exc:
        raise WindowsPackageError("MSVC compiler version probe timed out") from exc
    except OSError as exc:
        raise WindowsPackageError("cannot execute MSVC compiler version probe") from exc
    _require(
        type(completed.returncode) is int
        and type(completed.stdout) is bytes
        and type(completed.stderr) is bytes,
        "MSVC compiler version runner returned malformed process evidence",
    )
    _require(
        len(completed.stdout) <= MAX_MSVC_VERSION_PROBE_OUTPUT_BYTES
        and len(completed.stderr) <= MAX_MSVC_VERSION_PROBE_OUTPUT_BYTES,
        "MSVC compiler version probe output exceeds the size limit",
    )
    _require(completed.returncode == 0, "MSVC compiler version probe failed")
    _require(
        completed.stderr == MSVC_VERSION_PROBE_STDERR,
        "MSVC compiler version probe stderr differs from the frozen contract",
    )
    version = parse_msvc_version_probe(completed.stdout)
    final_probe_snapshot = _read_frozen_msvc_version_probe(probe_path)
    _require(
        final_probe_snapshot.sha256 == probe_snapshot.sha256
        and final_probe_snapshot.size == probe_snapshot.size,
        "MSVC version probe changed during compiler inspection",
    )
    return version


def inspect_dumpbin_dependencies(
    dumpbin: pathlib.Path,
    library: pathlib.Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = _run_bounded_process,
) -> list[str]:
    """Run an absolute dumpbin against the exact packaged DLL and parse fail-closed."""

    tool = _regular_windows_tool(
        dumpbin,
        expected_name="dumpbin.exe",
        label="dumpbin",
    )
    dll = pathlib.Path(library)
    _require(dll.is_absolute(), "Windows DLL path must be absolute")
    try:
        metadata = dll.lstat()
    except OSError as exc:
        raise WindowsPackageError("cannot inspect the Windows DLL") from exc
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not dll.is_symlink()
        and not (
            getattr(metadata, "st_file_attributes", 0)
            & FILE_ATTRIBUTE_REPARSE_POINT
        ),
        "Windows DLL must be a non-reparse regular file",
    )
    _require(
        dll.name == "q_periapt_ffi_abi2.dll",
        "Windows DLL filename differs from the ABI contract",
    )
    try:
        completed = runner(
            [str(tool), "/nologo", "/dependents", str(dll)],
            cwd=str(tool.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise WindowsPackageError("dumpbin dependency inspection timed out") from exc
    except OSError as exc:
        raise WindowsPackageError("cannot execute dumpbin dependency inspection") from exc
    _require(
        type(completed.returncode) is int
        and isinstance(completed.stdout, bytes)
        and isinstance(completed.stderr, bytes),
        "dumpbin runner returned malformed process evidence",
    )
    _require(
        len(completed.stdout) <= MAX_DUMPBIN_OUTPUT_BYTES
        and len(completed.stderr) <= MAX_DUMPBIN_OUTPUT_BYTES,
        "dumpbin process output exceeds the size limit",
    )
    _require(completed.returncode == 0, "dumpbin dependency inspection failed")
    _require(not completed.stderr, "dumpbin dependency inspection emitted diagnostics")
    return parse_dumpbin_dependents(completed.stdout)


def _source_hashes(repository_root: pathlib.Path) -> dict[str, str]:
    result = {
        name: _sha256(repository_root / relative)
        for name, relative in SOURCE_INPUT_PATHS.items()
    }
    result["rust_workspace_build_inputs"] = _tree_hash(
        repository_root, RUST_WORKSPACE_INPUTS
    )
    return result


def _iso8601(epoch: int) -> str:
    _require(type(epoch) is int and 0 <= epoch <= 4_102_444_800, "source date epoch is out of range")
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def create_manifest(
    package_root: pathlib.Path,
    repository_root: pathlib.Path,
    *,
    package_name: str,
    version: str,
    git_commit: str,
    git_tree: str,
    source_date_epoch: int,
    rustc: str,
    cargo: str,
    cl: str,
    dependencies: Iterable[str],
    forbidden_windows_paths: Iterable[str] = (),
) -> dict[str, Any]:
    """Create deterministic MANIFEST.json and SHA256SUMS after every native gate passed."""

    root = _validate_package_root(package_root)
    repository = pathlib.Path(repository_root).resolve(strict=True)
    dependency_list = list(dependencies)
    windows_path_list = list(forbidden_windows_paths)
    _require(COMMIT_RE.fullmatch(git_commit) is not None, "git commit must be 40 lowercase hexadecimal digits")
    _require(TREE_RE.fullmatch(git_tree) is not None, "git tree must be 40 to 64 lowercase hexadecimal digits")
    _require(type(source_date_epoch) is int, "source date epoch must be an integer")
    _require(version == PACKAGE_SEMVER, f"Windows package version must be {PACKAGE_SEMVER}")
    _require(package_name == f"q-periapt-c-abi2-{version}-{TARGET}", "Windows package name differs from release contract")
    _require(
        rustc == EXPECTED_RUSTC_VERSION,
        "Windows rustc version differs from the canonical release toolchain",
    )
    _require(
        cargo == EXPECTED_CARGO_VERSION,
        "Windows cargo version differs from the canonical release toolchain",
    )
    _validate_msvc_version(cl, "cl version")

    third_party, third_party_files = _third_party_rust_files(root)
    expected_payload_files = EXPECTED_PAYLOAD_FILES | third_party_files
    inventory = _inventory(root)
    _require(set(inventory) == expected_payload_files, f"Windows payload file set differs: missing={sorted(expected_payload_files - set(inventory))} extra={sorted(set(inventory) - expected_payload_files)}")
    _validate_boms(root, repository)
    contract_sha256, exports_sha256 = _validate_contracts(root, repository)
    pe_evidence, pe_sha256, pe_size = inspect_windows_pe_evidence(
        inventory["bin/q_periapt_ffi_abi2.dll"]
    )

    forbidden = [str(repository), repository.as_posix()]
    entries: list[dict[str, Any]] = []
    for relative, path in sorted(inventory.items()):
        try:
            scan = scan_release_file(
                path,
                forbidden_text=forbidden,
                forbidden_windows_paths=windows_path_list,
            )
        except ReleaseBinaryScanError as exc:
            raise WindowsPackageError(str(exc)) from exc
        if relative == "bin/q_periapt_ffi_abi2.dll":
            _require(
                scan.sha256 == pe_sha256 and scan.bytes == pe_size,
                "Windows DLL changed between PE inspection and payload hashing",
            )
        entries.append(
            {
                "bytes": scan.bytes,
                "mode": "0o644",
                "path": relative,
                "sha256": scan.sha256,
                "type": "file",
            }
        )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "package": package_name,
        "version": version,
        "generated_at": _iso8601(source_date_epoch),
        "source_date_epoch": source_date_epoch,
        "git_commit": git_commit,
        "git_tree": git_tree,
        "git_dirty": False,
        "target": TARGET,
        "release_class": "unsigned_experimental_prerelease",
        "authenticode": {
            "signed": False,
            "certificate_directory_present": pe_evidence[
                "authenticode_certificate_directory_present"
            ],
            "reason": "No trusted Windows Authenticode credential was available; integrity relies on GitHub immutable-release and artifact attestations.",
        },
        "abi": {
            "major": ABI_MAJOR,
            "platform": ABI_PLATFORM,
            "contract_sha256": contract_sha256,
            "exports_sha256": exports_sha256,
            "export_count": 9,
            "shared_filename": "q_periapt_ffi_abi2.dll",
            "import_library_filename": "q_periapt_ffi_abi2.lib",
            "static_filename": "q_periapt_ffi_abi2_static.lib",
        },
        "hardening": {
            **pe_evidence["hardening"],
            "linker_warnings_as_errors": True,
        },
        "native_dependencies": _normalize_dependencies(dependency_list),
        "third_party_rust": {
            "inventory_sha256": _sha256(
                root.joinpath(*THIRD_PARTY_INVENTORY_RELATIVE.parts)
            ),
            "package_count": len(third_party["packages"]),
        },
        "toolchain": {"cargo": cargo, "cl": cl, "rustc": rustc},
        "source_inputs_sha256": _source_hashes(repository),
        "files": entries,
    }
    manifest_path = root / "MANIFEST.json"
    manifest_path.write_bytes(_canonical_json(payload))
    sums_entries = [*entries, {"path": "MANIFEST.json", "sha256": _sha256(manifest_path)}]
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{entry['sha256']}  {entry['path']}\n"
            for entry in sorted(sums_entries, key=lambda entry: entry["path"])
        ),
        encoding="utf-8",
    )
    verify_package(
        root,
        repository_root=repository,
        expected_dependencies=dependency_list,
        expected_git_commit=git_commit,
        expected_git_tree=git_tree,
        forbidden_windows_paths=windows_path_list,
    )
    return payload


def _parse_sums(path: pathlib.Path, expected_payload_files: frozenset[str]) -> dict[str, str]:
    try:
        text = read_regular_snapshot(path, maximum=MAX_JSON_BYTES, label="Windows SHA256SUMS").data.decode("ascii")
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise WindowsPackageError(f"cannot read strict SHA256SUMS: {exc}") from exc
    _require(text.endswith("\n"), "Windows SHA256SUMS must end with one newline")
    entries: dict[str, str] = {}
    for line in text.splitlines():
        _require(bool(line), "Windows SHA256SUMS contains a blank line")
        parts = line.split("  ", 1)
        _require(len(parts) == 2, f"malformed SHA256SUMS line: {line!r}")
        digest, relative = parts
        _require(SHA256_RE.fullmatch(digest) is not None, f"invalid SHA256SUMS digest: {relative}")
        _require(relative in expected_payload_files | {"MANIFEST.json"}, f"unexpected SHA256SUMS path: {relative}")
        _require(relative not in entries, f"duplicate SHA256SUMS path: {relative}")
        entries[relative] = digest
    _require(list(entries) == sorted(entries), "Windows SHA256SUMS is not canonically sorted")
    return entries


def verify_package(
    package_root: pathlib.Path,
    *,
    repository_root: pathlib.Path | None = None,
    expected_dependencies: Iterable[str] | None = None,
    expected_git_commit: str | None = None,
    expected_git_tree: str | None = None,
    forbidden_windows_paths: Iterable[str] = (),
) -> dict[str, Any]:
    """Verify the complete extracted package without trusting archive metadata."""

    root = _validate_package_root(package_root)
    windows_path_list = list(forbidden_windows_paths)
    third_party, third_party_files = _third_party_rust_files(root)
    expected_payload_files = EXPECTED_PAYLOAD_FILES | third_party_files
    expected_all_files = expected_payload_files | {"MANIFEST.json", "SHA256SUMS"}
    inventory = _inventory(root)
    _require(set(inventory) == expected_all_files, f"Windows package file set differs: missing={sorted(expected_all_files - set(inventory))} extra={sorted(set(inventory) - expected_all_files)}")
    pe_evidence, pe_sha256, pe_size = inspect_windows_pe_evidence(
        inventory["bin/q_periapt_ffi_abi2.dll"]
    )
    manifest = _load_json(inventory["MANIFEST.json"], "Windows MANIFEST.json")
    _require(
        read_regular_snapshot(
            inventory["MANIFEST.json"],
            maximum=MAX_JSON_BYTES,
            label="Windows MANIFEST.json",
        ).data
        == _canonical_json(manifest),
        "Windows manifest is not canonical JSON",
    )
    _require(set(manifest) == MANIFEST_KEYS, "Windows manifest fields differ")
    _require(manifest.get("schema_version") == SCHEMA_VERSION, "Windows manifest schema differs")
    _require(manifest.get("kind") == KIND, "Windows manifest kind differs")
    _require(
        manifest.get("package") == f"q-periapt-c-abi2-{PACKAGE_SEMVER}-{TARGET}",
        "Windows manifest package differs",
    )
    _require(manifest.get("version") == PACKAGE_SEMVER, "Windows manifest version differs")
    _require(manifest.get("target") == TARGET, "Windows manifest target differs")
    source_date_epoch = manifest.get("source_date_epoch")
    _require(type(source_date_epoch) is int, "Windows source date epoch is invalid")
    _require(
        manifest.get("generated_at") == _iso8601(source_date_epoch),
        "Windows generated_at differs from source date epoch",
    )
    _require(manifest.get("git_dirty") is False, "Windows manifest is not clean-source bound")
    _require(COMMIT_RE.fullmatch(manifest.get("git_commit", "")) is not None, "Windows manifest git commit is malformed")
    _require(TREE_RE.fullmatch(manifest.get("git_tree", "")) is not None, "Windows manifest git tree is malformed")
    if expected_git_commit is not None:
        _require(
            manifest["git_commit"] == expected_git_commit,
            "Windows manifest git commit differs from trusted source",
        )
    if expected_git_tree is not None:
        _require(
            manifest["git_tree"] == expected_git_tree,
            "Windows manifest git tree differs from trusted source",
        )
    _require(manifest.get("release_class") == "unsigned_experimental_prerelease", "Windows release class is not explicit")
    _require(manifest.get("authenticode") == {
        "signed": False,
        "certificate_directory_present": pe_evidence[
            "authenticode_certificate_directory_present"
        ],
        "reason": "No trusted Windows Authenticode credential was available; integrity relies on GitHub immutable-release and artifact attestations.",
    }, "Windows Authenticode boundary differs")
    _require(manifest.get("hardening") == {
        **pe_evidence["hardening"],
        "linker_warnings_as_errors": True,
    }, "Windows hardening evidence differs")
    manifest_dependencies = manifest.get("native_dependencies")
    _require(isinstance(manifest_dependencies, list), "Windows native dependency list is missing")
    normalized_dependencies = _normalize_dependencies(manifest_dependencies)
    _require(
        manifest_dependencies == normalized_dependencies,
        "Windows native dependency list is not canonical",
    )
    if expected_dependencies is not None:
        _require(
            normalized_dependencies == _normalize_dependencies(expected_dependencies),
            "Windows manifest dependencies differ from native dumpbin evidence",
        )
    _require(
        manifest.get("third_party_rust")
        == {
            "inventory_sha256": _sha256(
                root.joinpath(*THIRD_PARTY_INVENTORY_RELATIVE.parts)
            ),
            "package_count": len(third_party["packages"]),
        },
        "Windows third-party Rust license evidence differs",
    )
    repository = pathlib.Path(repository_root).resolve(strict=True) if repository_root is not None else None
    toolchain = manifest.get("toolchain")
    _require(
        isinstance(toolchain, dict) and set(toolchain) == {"cargo", "cl", "rustc"},
        "Windows toolchain fields differ",
    )
    _require(
        toolchain["rustc"] == EXPECTED_RUSTC_VERSION,
        "Windows manifest rustc version differs from the canonical release toolchain",
    )
    _require(
        toolchain["cargo"] == EXPECTED_CARGO_VERSION,
        "Windows manifest cargo version differs from the canonical release toolchain",
    )
    _validate_msvc_version(toolchain["cl"], "Windows cl version")
    source_inputs = manifest.get("source_inputs_sha256")
    _require(
        isinstance(source_inputs, dict)
        and set(source_inputs) == set(SOURCE_INPUT_PATHS) | {"rust_workspace_build_inputs"},
        "Windows source input fields differ",
    )
    for label, digest in source_inputs.items():
        _require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            f"Windows source input digest is malformed: {label}",
        )
    if repository is not None:
        _require(
            source_inputs == _source_hashes(repository),
            "Windows source input digests differ from repository",
        )
    contract_sha256, exports_sha256 = _validate_contracts(root, repository)
    abi = manifest.get("abi")
    _require(isinstance(abi, dict), "Windows manifest ABI object is missing")
    _require(abi == {
        "major": ABI_MAJOR,
        "platform": ABI_PLATFORM,
        "contract_sha256": contract_sha256,
        "exports_sha256": exports_sha256,
        "export_count": 9,
        "shared_filename": "q_periapt_ffi_abi2.dll",
        "import_library_filename": "q_periapt_ffi_abi2.lib",
        "static_filename": "q_periapt_ffi_abi2_static.lib",
    }, "Windows manifest ABI identity differs")

    forbidden = [str(repository), repository.as_posix()] if repository is not None else []
    file_entries = manifest.get("files")
    _require(isinstance(file_entries, list), "Windows manifest files list is missing")
    manifest_hashes: dict[str, str] = {}
    manifest_sizes: dict[str, int] = {}
    manifest_paths: list[str] = []
    for entry in file_entries:
        _require(isinstance(entry, dict) and set(entry) == {"bytes", "mode", "path", "sha256", "type"}, "Windows manifest file entry shape differs")
        relative = entry["path"]
        _require(relative in expected_payload_files and relative not in manifest_hashes, f"invalid or duplicate Windows manifest path: {relative}")
        _require(entry["mode"] == "0o644" and entry["type"] == "file", f"Windows manifest file metadata differs: {relative}")
        _require(type(entry["bytes"]) is int and entry["bytes"] >= 0, f"Windows manifest file size differs: {relative}")
        _require(SHA256_RE.fullmatch(entry["sha256"]) is not None, f"Windows manifest file digest is malformed: {relative}")
        try:
            scan = scan_release_file(
                inventory[relative],
                forbidden_text=forbidden,
                forbidden_windows_paths=windows_path_list,
            )
        except ReleaseBinaryScanError as exc:
            raise WindowsPackageError(str(exc)) from exc
        _require(scan.bytes == entry["bytes"], f"Windows package file size mismatch: {relative}")
        _require(scan.sha256 == entry["sha256"], f"Windows package file hash mismatch: {relative}")
        manifest_hashes[relative] = scan.sha256
        manifest_sizes[relative] = scan.bytes
        manifest_paths.append(relative)
    _require(set(manifest_hashes) == expected_payload_files, "Windows manifest file set differs")
    _require(
        manifest_hashes["bin/q_periapt_ffi_abi2.dll"] == pe_sha256
        and manifest_sizes["bin/q_periapt_ffi_abi2.dll"] == pe_size,
        "Windows PE inspection snapshot differs from manifest DLL bytes",
    )
    _require(manifest_paths == sorted(manifest_paths), "Windows manifest files are not canonically sorted")
    sums = _parse_sums(inventory["SHA256SUMS"], expected_payload_files)
    expected_sums = {**manifest_hashes, "MANIFEST.json": _sha256(inventory["MANIFEST.json"])}
    _require(sums == expected_sums, "Windows SHA256SUMS differs from package bytes")
    _validate_boms(root, repository)
    for relative in ("MANIFEST.json", "SHA256SUMS"):
        try:
            scan_release_file(
                inventory[relative],
                forbidden_text=forbidden,
                forbidden_windows_paths=windows_path_list,
            )
        except ReleaseBinaryScanError as exc:
            raise WindowsPackageError(str(exc)) from exc
    return manifest


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    native_libraries = subparsers.add_parser("parse-native-static-libraries")
    native_libraries.add_argument(
        "--compiler-output", required=True, type=pathlib.Path
    )
    linker_invocation = subparsers.add_parser("verify-linker-invocation")
    linker_invocation.add_argument(
        "--link-arguments", required=True, type=pathlib.Path
    )
    linker_invocation.add_argument("--expected-linker", required=True)
    msvc_version = subparsers.add_parser("inspect-msvc-version")
    msvc_version.add_argument("--cl", required=True, type=pathlib.Path)
    msvc_version.add_argument("--probe", required=True, type=pathlib.Path)
    create = subparsers.add_parser("create")
    create.add_argument("--package-root", required=True, type=pathlib.Path)
    create.add_argument("--repository-root", required=True, type=pathlib.Path)
    create.add_argument("--package-name", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--git-commit", required=True)
    create.add_argument("--git-tree", required=True)
    create.add_argument("--source-date-epoch", required=True, type=int)
    create.add_argument("--rustc", required=True)
    create.add_argument("--cargo", required=True)
    create.add_argument("--cl", required=True)
    create.add_argument("--dumpbin", required=True, type=pathlib.Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--package-root", required=True, type=pathlib.Path)
    verify.add_argument("--repository-root", type=pathlib.Path)
    verify.add_argument("--dumpbin", required=True, type=pathlib.Path)
    verify.add_argument("--expected-git-commit")
    verify.add_argument("--expected-git-tree")
    for command in (create, verify):
        command.add_argument(
            "--forbid-windows-path",
            action="append",
            default=[],
        )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        if args.command == "parse-native-static-libraries":
            output = read_regular_snapshot(
                args.compiler_output,
                maximum=MAX_RUSTC_NATIVE_STATIC_LIBS_BYTES,
                label="rustc native-static-libs output",
            ).data
            libraries = parse_rustc_native_static_libraries(output)
            payload = (
                json.dumps(libraries, separators=(",", ":")) + "\n"
            ).encode("ascii")
            written = sys.stdout.buffer.write(payload)
            _require(
                written == len(payload),
                "cannot write the complete native static library contract",
            )
            sys.stdout.buffer.flush()
            return 0
        if args.command == "verify-linker-invocation":
            output = read_regular_snapshot(
                args.link_arguments,
                maximum=MAX_RUSTC_LINK_ARGUMENTS_BYTES,
                label="rustc link-args output",
            ).data
            verify_rustc_linker_invocation(output, args.expected_linker)
            print("WINDOWS_RUST_LINKER_INVOCATION_PASS")
            return 0
        if args.command == "inspect-msvc-version":
            version = inspect_msvc_version(args.cl, args.probe)
            payload = (version + "\n").encode("ascii")
            written = sys.stdout.buffer.write(payload)
            _require(
                written == len(payload),
                "cannot write the complete MSVC compiler version",
            )
            sys.stdout.buffer.flush()
            return 0
        dependencies = inspect_dumpbin_dependencies(
            args.dumpbin,
            args.package_root / "bin/q_periapt_ffi_abi2.dll",
        )
        if args.command == "create":
            result = create_manifest(
                args.package_root,
                args.repository_root,
                package_name=args.package_name,
                version=args.version,
                git_commit=args.git_commit,
                git_tree=args.git_tree,
                source_date_epoch=args.source_date_epoch,
                rustc=args.rustc,
                cargo=args.cargo,
                cl=args.cl,
                dependencies=dependencies,
                forbidden_windows_paths=args.forbid_windows_path,
            )
        else:
            result = verify_package(
                args.package_root,
                repository_root=args.repository_root,
                expected_dependencies=dependencies,
                expected_git_commit=args.expected_git_commit,
                expected_git_tree=args.expected_git_tree,
                forbidden_windows_paths=args.forbid_windows_path,
            )
    except (OSError, ValueError, WindowsPackageError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(
        json.dumps(
            {
                "git_commit": result["git_commit"],
                "package": result["package"],
                "status": "pass",
                "target": result["target"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
