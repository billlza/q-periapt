#!/usr/bin/env python3
"""Create and verify the strict manifest inside the Windows x64 ABI2 SDK ZIP."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
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
from evidence_io import EvidenceIOError, load_json_object_snapshot, read_regular_snapshot
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


SCHEMA_VERSION = 2
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
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_FILE_BYTES = 512 * 1024 * 1024
MAX_DUMPBIN_OUTPUT_BYTES = 1024 * 1024
DUMPBIN_DEPENDENCY_HEADER = b"Image has the following dependencies:"
DUMPBIN_SUMMARY_HEADER = b"Summary"
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

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
                "suspended dumpbin process must have exactly one initial thread",
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
                    "dumpbin initial thread suspend count differs",
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


def _regular_windows_tool(path: pathlib.Path) -> pathlib.Path:
    tool = pathlib.Path(path)
    _require(tool.is_absolute(), "dumpbin path must be absolute")
    try:
        metadata = tool.lstat()
    except OSError as exc:
        raise WindowsPackageError("cannot inspect the dumpbin executable") from exc
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not tool.is_symlink()
        and not (
            getattr(metadata, "st_file_attributes", 0)
            & FILE_ATTRIBUTE_REPARSE_POINT
        ),
        "dumpbin must be a non-reparse regular file",
    )
    _require(tool.name.casefold() == "dumpbin.exe", "dumpbin executable name differs")
    return tool


def _read_bounded_process_stream(stream: BinaryIO) -> bytes:
    """Drain a process pipe while retaining only enough bytes to prove overflow."""

    retained = bytearray()
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        remaining = MAX_DUMPBIN_OUTPUT_BYTES + 1 - len(retained)
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
) -> subprocess.CompletedProcess[bytes]:
    """Run dumpbin with concurrent, memory-bounded stdout and stderr capture."""

    _require(stdin == subprocess.DEVNULL, "bounded process stdin contract differs")
    _require(
        stdout == subprocess.PIPE and stderr == subprocess.PIPE,
        "bounded process output contract differs",
    )
    _require(check is False, "bounded process must return native failure evidence")
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
                results[index] = _read_bounded_process_stream(stream)
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
                    "cannot start bounded dumpbin output readers"
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
                "dumpbin process status is unavailable",
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
                        "dumpbin root process cleanup deadline expired"
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
                        "dumpbin output pipe did not close after process-tree cleanup"
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
                "cannot clean up dumpbin process tree: "
                f"{type(first_cleanup_failure).__name__}: {first_cleanup_failure}"
            )
            active_error = sys.exception()
            if active_error is not None:
                cleanup_error.add_note(
                    "dumpbin operation also failed before cleanup: "
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
        raise WindowsPackageError("cannot read dumpbin process output") from failure
    if timeout_error is not None:
        raise timeout_error
    captured_stdout, captured_stderr = results
    _require(
        captured_stdout is not None and captured_stderr is not None,
        "dumpbin process output capture is incomplete",
    )
    _require(returncode is not None, "dumpbin process status is unavailable")
    return subprocess.CompletedProcess(
        arguments,
        returncode,
        captured_stdout,
        captured_stderr,
    )


def inspect_dumpbin_dependencies(
    dumpbin: pathlib.Path,
    library: pathlib.Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = _run_bounded_process,
) -> list[str]:
    """Run an absolute dumpbin against the exact packaged DLL and parse fail-closed."""

    tool = _regular_windows_tool(dumpbin)
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
) -> dict[str, Any]:
    """Create deterministic MANIFEST.json and SHA256SUMS after every native gate passed."""

    root = _validate_package_root(package_root)
    repository = pathlib.Path(repository_root).resolve(strict=True)
    dependency_list = list(dependencies)
    _require(COMMIT_RE.fullmatch(git_commit) is not None, "git commit must be 40 lowercase hexadecimal digits")
    _require(TREE_RE.fullmatch(git_tree) is not None, "git tree must be 40 to 64 lowercase hexadecimal digits")
    _require(type(source_date_epoch) is int, "source date epoch must be an integer")
    _require(version == PACKAGE_SEMVER, f"Windows package version must be {PACKAGE_SEMVER}")
    _require(package_name == f"q-periapt-c-abi2-{version}-{TARGET}", "Windows package name differs from release contract")
    for label, value in (("rustc", rustc), ("cargo", cargo), ("cl", cl)):
        _require(isinstance(value, str) and value and "\n" not in value and "\r" not in value, f"{label} version is malformed")

    third_party, third_party_files = _third_party_rust_files(root)
    expected_payload_files = EXPECTED_PAYLOAD_FILES | third_party_files
    inventory = _inventory(root)
    _require(set(inventory) == expected_payload_files, f"Windows payload file set differs: missing={sorted(expected_payload_files - set(inventory))} extra={sorted(set(inventory) - expected_payload_files)}")
    _validate_boms(root, repository)
    contract_sha256, exports_sha256 = _validate_contracts(root, repository)

    forbidden = [str(repository), repository.as_posix()]
    entries: list[dict[str, Any]] = []
    for relative, path in sorted(inventory.items()):
        try:
            scan = scan_release_file(path, forbidden_text=forbidden)
        except ReleaseBinaryScanError as exc:
            raise WindowsPackageError(str(exc)) from exc
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
            "machine": "x86_64",
            "dynamic_base": True,
            "nx_compatible": True,
            "high_entropy_va": True,
            "linker_warnings_as_errors": True,
            "debug_directory_absent": True,
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
) -> dict[str, Any]:
    """Verify the complete extracted package without trusting archive metadata."""

    root = _validate_package_root(package_root)
    third_party, third_party_files = _third_party_rust_files(root)
    expected_payload_files = EXPECTED_PAYLOAD_FILES | third_party_files
    expected_all_files = expected_payload_files | {"MANIFEST.json", "SHA256SUMS"}
    inventory = _inventory(root)
    _require(set(inventory) == expected_all_files, f"Windows package file set differs: missing={sorted(expected_all_files - set(inventory))} extra={sorted(set(inventory) - expected_all_files)}")
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
        "reason": "No trusted Windows Authenticode credential was available; integrity relies on GitHub immutable-release and artifact attestations.",
    }, "Windows Authenticode boundary differs")
    _require(manifest.get("hardening") == {
        "machine": "x86_64",
        "dynamic_base": True,
        "nx_compatible": True,
        "high_entropy_va": True,
        "linker_warnings_as_errors": True,
        "debug_directory_absent": True,
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
    for label, value in toolchain.items():
        _require(
            isinstance(value, str)
            and value
            and "\n" not in value
            and "\r" not in value,
            f"Windows {label} version is malformed",
        )
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

    file_entries = manifest.get("files")
    _require(isinstance(file_entries, list), "Windows manifest files list is missing")
    manifest_hashes: dict[str, str] = {}
    manifest_paths: list[str] = []
    for entry in file_entries:
        _require(isinstance(entry, dict) and set(entry) == {"bytes", "mode", "path", "sha256", "type"}, "Windows manifest file entry shape differs")
        relative = entry["path"]
        _require(relative in expected_payload_files and relative not in manifest_hashes, f"invalid or duplicate Windows manifest path: {relative}")
        _require(entry["mode"] == "0o644" and entry["type"] == "file", f"Windows manifest file metadata differs: {relative}")
        _require(type(entry["bytes"]) is int and entry["bytes"] >= 0, f"Windows manifest file size differs: {relative}")
        _require(SHA256_RE.fullmatch(entry["sha256"]) is not None, f"Windows manifest file digest is malformed: {relative}")
        _require(inventory[relative].stat().st_size == entry["bytes"], f"Windows package file size mismatch: {relative}")
        _require(_sha256(inventory[relative]) == entry["sha256"], f"Windows package file hash mismatch: {relative}")
        manifest_hashes[relative] = entry["sha256"]
        manifest_paths.append(relative)
    _require(set(manifest_hashes) == expected_payload_files, "Windows manifest file set differs")
    _require(manifest_paths == sorted(manifest_paths), "Windows manifest files are not canonically sorted")
    sums = _parse_sums(inventory["SHA256SUMS"], expected_payload_files)
    expected_sums = {**manifest_hashes, "MANIFEST.json": _sha256(inventory["MANIFEST.json"])}
    _require(sums == expected_sums, "Windows SHA256SUMS differs from package bytes")
    _validate_boms(root, repository)
    forbidden = [str(repository), repository.as_posix()] if repository is not None else []
    for path in inventory.values():
        try:
            scan_release_file(path, forbidden_text=forbidden)
        except ReleaseBinaryScanError as exc:
            raise WindowsPackageError(str(exc)) from exc
    return manifest


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
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
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
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
            )
        else:
            result = verify_package(
                args.package_root,
                repository_root=args.repository_root,
                expected_dependencies=dependencies,
                expected_git_commit=args.expected_git_commit,
                expected_git_tree=args.expected_git_tree,
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
