#!/usr/bin/env python3

"""Fail-closed checks for the packaged Rust/C build surface."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from collections.abc import Callable, Iterable

from bounded_process import BoundedProcessError, BoundedResult, capture_stdout
from evidence_io import (
    EvidenceIOError,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import GIT, GitProvenanceError, inspect_worktree


class RustPublishContractError(RuntimeError):
    """The packaged Rust/C build surface violates the package contract."""


RUSTSEC_ADVISORY_DB_URL = "https://github.com/RustSec/advisory-db.git"
RUST_PACKAGE_TOOLCHAIN_MARKER = (
    "RUST_PACKAGE_TOOLCHAIN_PASS "
    "rustc=1.96.1 cargo=1.96.1 cargo-audit=0.22.2"
)
RUST_PACKAGE_CARGO_HOME_MARKER = (
    "RUST_CARGO_HOME_ISOLATION_PASS mode=0700 ambient_cargo_home_data=unused"
)
RUST_PACKAGE_NORMALIZED_AUDIT_MARKER = "RUST_BACKENDS_NORMALIZED_AUDIT_PASS"
RUST_PACKAGE_CARGO_HOME_CLEANUP_MARKER = (
    "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS cargo-home"
)
RUST_CRATES_IO_SPARSE_INDEX = "https://index.crates.io"
RUST_CRATES_IO_REGISTRY_SOURCE = (
    "registry+https://github.com/rust-lang/crates.io-index"
)
RUST_SPARSE_INDEX_USER_AGENT = "q-periapt-rust-package-contract/1"
RUST_SPARSE_REQUEST_TIMEOUT_SECONDS = 15
RUST_SPARSE_INDEX_MAX_BYTES = 8 * 1024 * 1024
RUST_SPARSE_AGGREGATE_MAX_BYTES = 128 * 1024 * 1024
RUST_SPARSE_INDEX_MAX_WORKERS = 8
RUST_SPARSE_LOCK_MAX_BYTES = 4 * 1024 * 1024
RUST_SPARSE_MAX_REGISTRY_PACKAGES = 256
RUST_SPARSE_ACCEPTANCE_TIMEOUT_SECONDS = 275
RUST_SPARSE_HELPER_TIMEOUT_SECONDS = 295
RUST_SPARSE_TOTAL_TIMEOUT_SECONDS = 300
RUST_SPARSE_HELPER_MAX_OUTPUT_BYTES = 64 * 1024
RUST_SPARSE_HELPER_MAX_MESSAGE_CHARS = 1024
RUST_SPARSE_HELPER_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
_EXACT_TRANSCRIPT_MARKERS = (
    ("RUST_PACKAGE_TOOLCHAIN_PASS", RUST_PACKAGE_TOOLCHAIN_MARKER),
    ("RUST_CARGO_HOME_ISOLATION_PASS", RUST_PACKAGE_CARGO_HOME_MARKER),
    (
        "RUST_BACKENDS_NORMALIZED_AUDIT_PASS",
        RUST_PACKAGE_NORMALIZED_AUDIT_MARKER,
    ),
    (
        "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS cargo-home",
        RUST_PACKAGE_CARGO_HOME_CLEANUP_MARKER,
    ),
)
RUST_PUBLISHABLE_CRATES = (
    "q-periapt-mlkem-native-sys",
    "q-periapt-core",
    "q-periapt-kem",
    "q-periapt-sig",
    "q-periapt-backends",
    "q-periapt-policy",
    "q-periapt-ffi",
    "q-periapt-wasm",
    "q-periapt-rustls",
    "q-periapt-cli",
)
RUST_NORMALIZED_LOCAL_CRATES = frozenset(
    {
        "q-periapt-backends",
        "q-periapt-core",
        "q-periapt-kem",
        "q-periapt-mlkem-native-sys",
        "q-periapt-sig",
    }
)


@dataclasses.dataclass(frozen=True, slots=True)
class RustPackageContractReceipt:
    """Parsed fields from one complete clean-tree Rust package transcript."""

    advisory_db_commit: str
    completed_at: str
    package_list_crates: tuple[str, ...]
    package_verification_crates: tuple[str, ...]
    normalized_cargo_lock_sha256: str
    registry_package_count: int
    source_commit: str


def _git_environment() -> dict[str, str]:
    """Return the same caller-independent Git boundary used for provenance."""

    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


_OWNED_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_OWNED_TEMP_PREFIX = re.compile(
    r"qperiapt-package-(?:verification|inspection|cargo-home|sparse-lock)\.$"
)
_OWNED_TEMP_NAME = re.compile(
    r"qperiapt-package-(?:verification|inspection|cargo-home|sparse-lock)"
    r"\.[0-9a-f]{24}$"
)


def _require_owned_directory_apis() -> None:
    if (
        os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.rmdir not in os.supports_dir_fd
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise RustPublishContractError(
            "owned package directories require POSIX openat no-follow APIs"
        )


def _temporary_parent() -> pathlib.Path:
    try:
        parent = pathlib.Path("/tmp").resolve(strict=True)
        metadata = parent.lstat()
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot resolve the package temporary parent: {exc}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise RustPublishContractError(
            f"package temporary parent must resolve to a real directory: {parent}"
        )
    return parent


def _directory_identity(metadata: os.stat_result, label: pathlib.Path) -> tuple[int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise RustPublishContractError(f"owned package path is not a directory: {label}")
    return metadata.st_dev, metadata.st_ino


def _validate_owned_root_metadata(
    metadata: os.stat_result,
    path: pathlib.Path,
) -> tuple[int, int]:
    identity = _directory_identity(metadata, path)
    if metadata.st_uid != os.getuid():
        raise RustPublishContractError(
            f"owned package directory has the wrong owner: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RustPublishContractError(
            f"owned package directory must have mode 0700: {path}"
        )
    return identity


def create_owned_package_directory(prefix: str) -> tuple[pathlib.Path, int, int]:
    """Create a private package target relative to an anchored temporary parent."""

    _require_owned_directory_apis()
    if _OWNED_TEMP_PREFIX.fullmatch(prefix) is None:
        raise RustPublishContractError("owned package directory prefix is malformed")
    parent = _temporary_parent()
    try:
        parent_fd = os.open(parent, _OWNED_DIRECTORY_FLAGS)
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot open the package temporary parent: {parent}: {exc}"
        ) from exc
    try:
        for _ in range(128):
            name = prefix + secrets.token_hex(12)
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            path = parent / name
            try:
                directory_fd = os.open(name, _OWNED_DIRECTORY_FLAGS, dir_fd=parent_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot anchor the new package directory: {path}: {exc}"
                ) from exc
            try:
                descriptor_identity = _validate_owned_root_metadata(
                    os.fstat(directory_fd), path
                )
                named_identity = _validate_owned_root_metadata(
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False), path
                )
                if named_identity != descriptor_identity:
                    raise RustPublishContractError(
                        f"new package directory was replaced during creation: {path}"
                    )
                return path, descriptor_identity[0], descriptor_identity[1]
            finally:
                os.close(directory_fd)
        raise RustPublishContractError(
            "cannot allocate a unique owned package directory after 128 attempts"
        )
    finally:
        os.close(parent_fd)


def inspect_package_source(
    root: pathlib.Path,
    *,
    allow_dirty: bool,
) -> tuple[str, bool]:
    """Return hardened source provenance, rejecting dirt unless diagnostic-only."""

    if not isinstance(allow_dirty, bool):
        raise RustPublishContractError(
            "Rust package source dirty policy must be a boolean"
        )
    try:
        inspection = inspect_worktree(pathlib.Path(root))
    except GitProvenanceError as exc:
        raise RustPublishContractError(
            f"cannot inspect Rust package source provenance: {exc}"
        ) from exc
    if re.fullmatch(r"[0-9a-f]{40,64}", inspection.commit) is None:
        raise RustPublishContractError(
            f"Rust package source commit is malformed: {inspection.commit}"
        )
    if inspection.dirty and not allow_dirty:
        reasons = "; ".join(inspection.reasons[:8]) or "unspecified dirty state"
        raise RustPublishContractError(
            f"Rust package source worktree is dirty: {reasons}"
        )
    return inspection.commit, inspection.dirty


@dataclasses.dataclass(frozen=True, slots=True)
class _LockedRegistryPackage:
    name: str
    version: str
    checksum: str


_CRATE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_CHECKSUM = re.compile(r"[0-9a-f]{64}")
_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def _is_semver(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = _SEMVER.fullmatch(value)
    if match is None:
        return False
    prerelease = match.group(4)
    if prerelease is None:
        return True
    return all(
        not (identifier.isdigit() and len(identifier) > 1 and identifier[0] == "0")
        for identifier in prerelease.split(".")
    )


def _parse_normalized_cargo_lock(
    lock_data: bytes,
) -> tuple[_LockedRegistryPackage, ...]:
    if not isinstance(lock_data, bytes):
        raise RustPublishContractError(
            "normalized Cargo.lock must be supplied as exact bytes"
        )
    if len(lock_data) > RUST_SPARSE_LOCK_MAX_BYTES:
        raise RustPublishContractError(
            "normalized Cargo.lock exceeds the byte limit"
        )
    try:
        document = tomllib.loads(lock_data.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise RustPublishContractError(
            f"normalized Cargo.lock is invalid UTF-8 TOML: {exc}"
        ) from exc
    if type(document.get("version")) is not int or document.get("version") != 4:
        raise RustPublishContractError(
            "normalized Cargo.lock must use schema version 4"
        )
    raw_packages = document.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise RustPublishContractError(
            "normalized Cargo.lock must contain a non-empty package array"
        )

    local_names: set[str] = set()
    registry_identities: set[tuple[str, str]] = set()
    registry_packages: list[_LockedRegistryPackage] = []
    for record in raw_packages:
        if not isinstance(record, dict):
            raise RustPublishContractError(
                "normalized Cargo.lock contains a non-table package record"
            )
        name = record.get("name")
        version = record.get("version")
        if not isinstance(name, str) or _CRATE_NAME.fullmatch(name) is None:
            raise RustPublishContractError(
                "normalized Cargo.lock contains an invalid package name"
            )
        if not _is_semver(version):
            raise RustPublishContractError(
                f"normalized Cargo.lock contains an invalid version for {name}"
            )

        if "source" not in record:
            if name not in RUST_NORMALIZED_LOCAL_CRATES:
                raise RustPublishContractError(
                    f"normalized Cargo.lock contains an unexpected local package: {name}"
                )
            if name in local_names:
                raise RustPublishContractError(
                    f"normalized Cargo.lock contains a duplicate local package: {name}"
                )
            if "checksum" in record:
                raise RustPublishContractError(
                    f"normalized Cargo.lock local package has a checksum: {name}"
                )
            local_names.add(name)
            continue

        source = record.get("source")
        if source != RUST_CRATES_IO_REGISTRY_SOURCE:
            raise RustPublishContractError(
                f"normalized Cargo.lock contains a non-crates.io source: {source!r}"
            )
        if name in RUST_NORMALIZED_LOCAL_CRATES:
            raise RustPublishContractError(
                "normalized Cargo.lock resolves a required local package from crates.io: "
                f"{name}"
            )
        checksum = record.get("checksum")
        if not isinstance(checksum, str) or _CHECKSUM.fullmatch(checksum) is None:
            raise RustPublishContractError(
                f"normalized Cargo.lock contains an invalid checksum for {name} {version}"
            )
        identity = name, version
        if identity in registry_identities:
            raise RustPublishContractError(
                "normalized Cargo.lock contains a duplicate crates.io package: "
                f"{name} {version}"
            )
        registry_identities.add(identity)
        registry_packages.append(
            _LockedRegistryPackage(
                name=name,
                version=version,
                checksum=checksum,
            )
        )
        if len(registry_packages) > RUST_SPARSE_MAX_REGISTRY_PACKAGES:
            raise RustPublishContractError(
                "normalized Cargo.lock exceeds the registry package limit"
            )

    if local_names != RUST_NORMALIZED_LOCAL_CRATES:
        raise RustPublishContractError(
            "normalized Cargo.lock local package set differs: "
            f"missing={sorted(RUST_NORMALIZED_LOCAL_CRATES - local_names)} "
            f"extra={sorted(local_names - RUST_NORMALIZED_LOCAL_CRATES)}"
        )
    if not registry_packages:
        raise RustPublishContractError(
            "normalized Cargo.lock contains no crates.io registry packages"
        )
    return tuple(registry_packages)


def _crates_io_sparse_path(name: str) -> str:
    if _CRATE_NAME.fullmatch(name) is None:
        raise RustPublishContractError("crates.io sparse index name is malformed")
    lowered = name.lower()
    if len(lowered) == 1:
        return f"1/{lowered}"
    if len(lowered) == 2:
        return f"2/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"


def _fetch_crates_io_sparse_entry(url: str) -> bytes:
    if not url.startswith(RUST_CRATES_IO_SPARSE_INDEX + "/"):
        raise RustPublishContractError(
            "crates.io sparse index URL is outside the official HTTPS origin"
        )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": RUST_SPARSE_INDEX_USER_AGENT,
        },
        method="GET",
    )
    try:
        response = urllib.request.urlopen(
            request,
            timeout=RUST_SPARSE_REQUEST_TIMEOUT_SECONDS,
        )
        with response:
            status = getattr(response, "status", None)
            if type(status) is not int or status != 200:
                raise RustPublishContractError(
                    f"crates.io sparse index returned HTTP status {status!r}"
                )
            if response.geturl() != url:
                raise RustPublishContractError(
                    "crates.io sparse index redirected away from the canonical URL"
                )
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                if not content_length.isascii() or not content_length.isdigit():
                    raise RustPublishContractError(
                        "crates.io sparse index Content-Length is malformed"
                    )
                if int(content_length) > RUST_SPARSE_INDEX_MAX_BYTES:
                    raise RustPublishContractError(
                        "crates.io sparse index response exceeds the byte limit"
                    )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(
                    min(
                        64 * 1024,
                        RUST_SPARSE_INDEX_MAX_BYTES + 1 - total,
                    )
                )
                if not isinstance(chunk, bytes):
                    raise RustPublishContractError(
                        "crates.io sparse index returned a non-byte response"
                    )
                if not chunk:
                    break
                total += len(chunk)
                if total > RUST_SPARSE_INDEX_MAX_BYTES:
                    raise RustPublishContractError(
                        "crates.io sparse index response exceeds the byte limit"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except RustPublishContractError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise RustPublishContractError(
            f"crates.io sparse index request failed: {exc}"
        ) from exc


def _validate_sparse_index_entry(
    name: str,
    payload: bytes,
    expected: tuple[_LockedRegistryPackage, ...],
) -> None:
    if not isinstance(payload, bytes):
        raise RustPublishContractError(
            f"crates.io sparse index response for {name} is not bytes"
        )
    if len(payload) > RUST_SPARSE_INDEX_MAX_BYTES:
        raise RustPublishContractError(
            f"crates.io sparse index response for {name} exceeds the byte limit"
        )
    if not payload or not payload.endswith(b"\n") or b"\r" in payload:
        raise RustPublishContractError(
            f"crates.io sparse index response for {name} is not canonical JSON-lines"
        )

    records: dict[str, tuple[str, bool]] = {}
    for line_number, line in enumerate(payload[:-1].split(b"\n"), start=1):
        if not line:
            raise RustPublishContractError(
                f"crates.io sparse index response for {name} contains a blank line"
            )
        try:
            record = parse_strict_json_bytes(
                line,
                label=f"crates.io sparse index {name} line {line_number}",
            )
        except EvidenceIOError as exc:
            raise RustPublishContractError(str(exc)) from exc
        if not isinstance(record, dict):
            raise RustPublishContractError(
                f"crates.io sparse index record for {name} is not an object"
            )
        record_name = record.get("name")
        version = record.get("vers")
        checksum = record.get("cksum")
        yanked = record.get("yanked")
        if record_name != name:
            raise RustPublishContractError(
                f"crates.io sparse index record name differs for {name}"
            )
        if not _is_semver(version):
            raise RustPublishContractError(
                f"crates.io sparse index version is malformed for {name}"
            )
        if not isinstance(checksum, str) or _CHECKSUM.fullmatch(checksum) is None:
            raise RustPublishContractError(
                f"crates.io sparse index checksum is malformed for {name} {version}"
            )
        if type(yanked) is not bool:
            raise RustPublishContractError(
                f"crates.io sparse index yanked flag is malformed for {name} {version}"
            )
        if version in records:
            raise RustPublishContractError(
                f"crates.io sparse index contains a duplicate version for {name}: {version}"
            )
        records[version] = checksum, yanked

    for package in expected:
        indexed = records.get(package.version)
        if indexed is None:
            raise RustPublishContractError(
                f"crates.io sparse index lacks {name} {package.version}"
            )
        indexed_checksum, yanked = indexed
        if indexed_checksum != package.checksum:
            raise RustPublishContractError(
                f"crates.io sparse index checksum differs for {name} {package.version}"
            )
        if yanked is not False:
            raise RustPublishContractError(
                f"crates.io sparse index marks {name} {package.version} as yanked"
            )


def _validate_crates_io_sparse_yanked_with_fetcher(
    lock_data: bytes,
    *,
    fetcher: Callable[[str], bytes],
) -> int:
    """Testable worker implementation; production wraps it in a hard-wall process."""

    registry_packages = _parse_normalized_cargo_lock(lock_data)
    by_name: dict[str, list[_LockedRegistryPackage]] = {}
    canonical_names: dict[str, str] = {}
    for package in registry_packages:
        canonical = package.name.lower()
        prior = canonical_names.setdefault(canonical, package.name)
        if prior != package.name:
            raise RustPublishContractError(
                "normalized Cargo.lock contains case-ambiguous crates.io names: "
                f"{prior}, {package.name}"
            )
        by_name.setdefault(package.name, []).append(package)

    if not callable(fetcher):
        raise RustPublishContractError("crates.io sparse index fetcher is not callable")
    names = sorted(by_name)
    if len(names) > RUST_SPARSE_MAX_REGISTRY_PACKAGES:
        raise RustPublishContractError(
            "normalized Cargo.lock exceeds the unique registry name limit"
        )
    worker_count = min(RUST_SPARSE_INDEX_MAX_WORKERS, len(names))
    executor = ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="qperiapt-crates-index",
    )
    futures: dict[str, Future[bytes]] = {}
    current_future: Future[bytes] | None = None
    next_name_index = 0
    total_payload_bytes = 0
    started_at = time.monotonic()
    deadline = started_at + RUST_SPARSE_ACCEPTANCE_TIMEOUT_SECONDS
    def fill_window() -> None:
        nonlocal next_name_index
        while (
            next_name_index < len(names)
            and len(futures) < worker_count
            and total_payload_bytes
            + (len(futures) + 1) * RUST_SPARSE_INDEX_MAX_BYTES
            <= RUST_SPARSE_AGGREGATE_MAX_BYTES
        ):
            name = names[next_name_index]
            futures[name] = executor.submit(
                fetcher,
                f"{RUST_CRATES_IO_SPARSE_INDEX}/{_crates_io_sparse_path(name)}",
            )
            next_name_index += 1

    try:
        fill_window()
        for name in names:
            if name not in futures:
                fill_window()
            if name not in futures:
                raise RustPublishContractError(
                    "crates.io sparse index aggregate budget cannot admit "
                    "the remaining response"
                )
            current_future = futures.pop(name)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RustPublishContractError(
                    "crates.io sparse index verification exceeded the total deadline"
                )
            try:
                payload = current_future.result(timeout=remaining)
            except FutureTimeoutError as exc:
                raise RustPublishContractError(
                    "crates.io sparse index verification exceeded the total deadline"
                ) from exc
            except RustPublishContractError:
                raise
            except Exception as exc:
                raise RustPublishContractError(
                    f"crates.io sparse index fetch failed for {name}: {exc}"
                ) from exc
            try:
                if not isinstance(payload, bytes):
                    raise RustPublishContractError(
                        f"crates.io sparse index response for {name} is not bytes"
                    )
                total_payload_bytes += len(payload)
                if total_payload_bytes > RUST_SPARSE_AGGREGATE_MAX_BYTES:
                    raise RustPublishContractError(
                        "crates.io sparse index aggregate response exceeds the byte limit"
                    )
                _validate_sparse_index_entry(
                    name,
                    payload,
                    tuple(by_name[name]),
                )
            finally:
                del payload
                del current_future
                current_future = None
            fill_window()
    except BaseException:
        if current_future is not None:
            current_future.cancel()
        for pending in futures.values():
            pending.cancel()
        # Drain normal worker failures synchronously so no thread escapes the
        # helper. A slow-drip or otherwise stuck worker is ultimately stopped by
        # the parent's 295-second bounded helper process; bounded-process then has
        # its fixed five-second reap window, keeping the outer boundary at 300s.
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    executor.shutdown(wait=True)
    if time.monotonic() - started_at > RUST_SPARSE_TOTAL_TIMEOUT_SECONDS:
        raise RustPublishContractError(
            "crates.io sparse index verification exceeded the total boundary"
        )
    return len(registry_packages)


def _write_owned_sparse_lock(directory: pathlib.Path, lock_data: bytes) -> pathlib.Path:
    lock_path = directory / "Cargo.lock"
    try:
        directory_fd = os.open(directory, _OWNED_DIRECTORY_FLAGS)
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot anchor sparse-lock helper directory: {exc}"
        ) from exc
    descriptor = -1
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open("Cargo.lock", flags, 0o600, dir_fd=directory_fd)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot create sparse-lock helper input: {exc}"
            ) from exc
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(lock_data):
            written = os.write(descriptor, lock_data[offset:])
            if written <= 0:
                raise RustPublishContractError(
                    "cannot completely write sparse-lock helper input"
                )
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(lock_data)
        ):
            raise RustPublishContractError(
                "sparse-lock helper input lacks its private regular-file identity"
            )
        return lock_path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _validate_crates_io_sparse_via_helper(
    lock_data: bytes,
    *,
    runner: Callable[..., BoundedResult],
) -> int:
    if not isinstance(lock_data, bytes):
        raise RustPublishContractError(
            "normalized Cargo.lock must be supplied as exact bytes"
        )
    if len(lock_data) > RUST_SPARSE_LOCK_MAX_BYTES:
        raise RustPublishContractError("normalized Cargo.lock exceeds the byte limit")
    lock_sha256 = hashlib.sha256(lock_data).hexdigest()
    directory, device, inode = create_owned_package_directory(
        "qperiapt-package-sparse-lock."
    )
    primary: BaseException | None = None
    try:
        lock_path = _write_owned_sparse_lock(directory, lock_data)
        module_path = pathlib.Path(__file__).resolve(strict=True)
        root = module_path.parents[1]
        command = (
            "/bin/sh",
            str(root / "artifact" / "python-run.sh"),
            str(module_path),
            "verify-crates-io-sparse-worker",
            str(lock_path),
            lock_sha256,
        )
        try:
            result = runner(
                command,
                timeout_seconds=RUST_SPARSE_HELPER_TIMEOUT_SECONDS,
                maximum_bytes=RUST_SPARSE_HELPER_MAX_OUTPUT_BYTES,
                stderr=subprocess.STDOUT,
                environment=RUST_SPARSE_HELPER_ENVIRONMENT,
            )
        except BoundedProcessError as exc:
            raise RustPublishContractError(
                "crates.io sparse verification helper failed at "
                f"{exc.kind} boundary: {exc}"
            ) from exc
        if not isinstance(result, BoundedResult) or type(result.returncode) is not int:
            raise RustPublishContractError(
                "crates.io sparse verification helper returned a malformed result"
            )
        try:
            value = parse_strict_json_bytes(
                result.stdout,
                label="crates.io sparse verification helper result",
            )
        except EvidenceIOError as exc:
            raise RustPublishContractError(str(exc)) from exc
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise RustPublishContractError(
                "crates.io sparse verification helper result schema differs"
            )
        ok = value.get("ok")
        if type(ok) is not bool:
            raise RustPublishContractError(
                "crates.io sparse verification helper result is malformed"
            )
        if not ok:
            expected_fields = {"error_kind", "message", "ok", "schema"}
            error_kind = value.get("error_kind")
            message = value.get("message")
            if (
                set(value) != expected_fields
                or result.returncode != 1
                or error_kind != "verification"
                or not isinstance(message, str)
                or not message
                or len(message) > RUST_SPARSE_HELPER_MAX_MESSAGE_CHARS
                or any(ord(character) < 0x20 for character in message)
            ):
                raise RustPublishContractError(
                    "crates.io sparse verification helper failure result is malformed"
                )
            raise RustPublishContractError(
                f"crates.io sparse verification failed: {message}"
            )
        expected_fields = {
            "normalized_lock_sha256",
            "ok",
            "registry_packages",
            "schema",
        }
        count = value.get("registry_packages")
        if (
            set(value) != expected_fields
            or result.returncode != 0
            or type(count) is not int
            or not 1 <= count <= RUST_SPARSE_MAX_REGISTRY_PACKAGES
            or value.get("normalized_lock_sha256") != lock_sha256
        ):
            raise RustPublishContractError(
                "crates.io sparse verification helper success result is malformed"
            )
        return count
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            remove_owned_package_directory(directory, device, inode)
        except BaseException as cleanup_exc:
            if primary is not None:
                primary.add_note(
                    "sparse-lock helper input cleanup also failed: "
                    f"{cleanup_exc}"
                )
            else:
                raise


def validate_crates_io_sparse_yanked(lock_data: bytes) -> int:
    """Verify normalized registry packages under one hard-wall helper process."""

    return _validate_crates_io_sparse_via_helper(
        lock_data,
        runner=capture_stdout,
    )


def _owned_real_directory_identity(
    path: pathlib.Path,
    label: str,
) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot inspect {label}: {path}: {exc}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RustPublishContractError(
            f"{label} must be a current-user-owned real directory"
        )
    return metadata.st_dev, metadata.st_ino


def validate_rustsec_advisory_database(database: pathlib.Path) -> str:
    """Validate the exact clean RustSec database fetched for this contract run."""

    requested_database = pathlib.Path(database)
    requested_identity = _owned_real_directory_identity(
        requested_database,
        "RustSec advisory database",
    )
    try:
        database = requested_database.resolve(strict=True)
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot resolve the RustSec advisory database: {requested_database}: {exc}"
        ) from exc
    database_identity = _owned_real_directory_identity(
        database,
        "RustSec advisory database",
    )
    if database_identity != requested_identity:
        raise RustPublishContractError(
            "RustSec advisory database identity changed during resolution"
        )

    git_directory = database / ".git"
    git_directory_identity = _owned_real_directory_identity(
        git_directory,
        "RustSec advisory database .git directory",
    )

    git_prefix = [
        GIT,
        "--no-pager",
        f"--git-dir={git_directory}",
        f"--work-tree={database}",
        "-c",
        f"safe.directory={database}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.quotePath=true",
    ]

    def revalidate_identities() -> None:
        if (
            _owned_real_directory_identity(
                database,
                "RustSec advisory database",
            )
            != database_identity
            or _owned_real_directory_identity(
                git_directory,
                "RustSec advisory database .git directory",
            )
            != git_directory_identity
        ):
            raise RustPublishContractError(
                "RustSec advisory database identity changed during inspection"
            )

    def git_value(operation: str, *arguments: str) -> str:
        revalidate_identities()
        try:
            result = capture_stdout(
                [*git_prefix, *arguments],
                timeout_seconds=30,
                maximum_bytes=64 * 1024,
                stderr=subprocess.STDOUT,
                environment=_git_environment(),
            )
        except BoundedProcessError as exc:
            raise RustPublishContractError(
                f"RustSec advisory database {operation} inspection failed at "
                f"{exc.kind} boundary: {exc}"
            ) from exc
        try:
            output = result.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RustPublishContractError(
                f"RustSec advisory database {operation} inspection emitted "
                "non-UTF-8 output"
            ) from exc
        if result.returncode != 0:
            raise RustPublishContractError(
                f"RustSec advisory database {operation} inspection failed "
                f"(exit={result.returncode})"
            )
        revalidate_identities()
        return output.strip()

    origin = git_value(
        "origin",
        "config",
        "--local",
        "--no-includes",
        "--get-all",
        "remote.origin.url",
    )
    if origin != RUSTSEC_ADVISORY_DB_URL:
        raise RustPublishContractError(
            "RustSec advisory database origin differs from the pinned RustSec URL"
        )
    commit = git_value(
        "commit",
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
    )
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RustPublishContractError(
            f"RustSec advisory database commit is malformed: {commit}"
        )
    status_output = git_value(
        "worktree",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
        "--no-renames",
    )
    if status_output:
        raise RustPublishContractError(
            "RustSec advisory database worktree is not clean"
        )

    revalidate_identities()
    return commit


_PACKAGE_LIST_MARKER = re.compile(
    r"RUST_PACKAGE_LIST_PASS ([a-z0-9][a-z0-9-]*) files=([1-9][0-9]*)"
)
_PACKAGE_VERIFICATION_MARKER = re.compile(
    r"RUST_PACKAGE_VERIFICATION_PASS ([a-z0-9][a-z0-9-]*) "
    r"registry=crates-io upload=not-attempted"
)
_ADVISORY_DATABASE_MARKER = re.compile(
    r"RUST_ADVISORY_DB_PASS origin="
    + re.escape(RUSTSEC_ADVISORY_DB_URL)
    + r" commit=([0-9a-f]{40}) clean=1 isolated_cargo_home=1"
)
_SOURCE_MARKER = re.compile(
    r"RUST_PACKAGE_SOURCE_PASS commit=([0-9a-f]{40,64}) clean=1"
)
_CRATES_IO_LOCK_VERIFY_MARKER = re.compile(
    r"RUST_CRATES_IO_LOCK_VERIFY_PASS registry_packages=([1-9][0-9]*) "
    r"index=sparse-https checksums=exact yanked=0 "
    r"normalized_lock_sha256=([0-9a-f]{64})"
)
_NORMALIZED_LOCK_STABILITY_MARKER = re.compile(
    r"RUST_NORMALIZED_LOCK_STABILITY_PASS sha256=([0-9a-f]{64})"
)
_CLEAN_CONTRACT_MARKER = re.compile(
    r"RUST_PACKAGE_CONTRACT_PASS dirty=0 registry=crates-io "
    r"upload=not-attempted completed_at="
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)"
)


def _single_exact_marker_index(
    lines: list[str],
    marker: str,
    label: str,
) -> int:
    indices = [index for index, line in enumerate(lines) if line == marker]
    if len(indices) != 1:
        raise RustPublishContractError(
            f"Rust package transcript must contain exactly one {label} marker"
        )
    return indices[0]


def _validate_exact_crate_sequence(
    crates: list[str],
    label: str,
) -> tuple[str, ...]:
    if len(set(crates)) != len(crates):
        raise RustPublishContractError(
            f"Rust package transcript contains duplicate {label} crate markers"
        )
    expected = set(RUST_PUBLISHABLE_CRATES)
    actual = set(crates)
    if actual != expected:
        raise RustPublishContractError(
            f"Rust package transcript {label} crate set differs: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )
    if tuple(crates) != RUST_PUBLISHABLE_CRATES:
        raise RustPublishContractError(
            f"Rust package transcript {label} crate order differs"
        )
    return tuple(crates)


def validate_rust_package_contract_transcript(
    transcript: bytes | str,
) -> RustPackageContractReceipt:
    """Parse one complete, warning-free, clean-tree package-contract transcript."""

    if isinstance(transcript, bytes):
        try:
            text = transcript.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RustPublishContractError(
                "Rust package transcript is not valid UTF-8"
            ) from exc
    elif isinstance(transcript, str):
        text = transcript
    else:
        raise RustPublishContractError(
            "Rust package transcript must be bytes or text"
        )
    if "\x00" in text or "\r" in text:
        raise RustPublishContractError(
            "Rust package transcript contains a non-canonical control character"
        )

    lines = text.split("\n")
    for line in lines:
        diagnostic = line.lstrip().casefold()
        if diagnostic.startswith("warning:") or diagnostic.startswith("error:"):
            raise RustPublishContractError(
                "Rust package transcript contains a warning or error diagnostic"
            )
        canonical_line = line.lstrip()
        if canonical_line.startswith(
            "DIRTY_RUST_PACKAGE_CONTRACT_DIAGNOSTIC_ONLY"
        ) or canonical_line.startswith(
            "RUST_PACKAGE_CONTRACT_DIAGNOSTIC_PASS"
        ):
            raise RustPublishContractError(
                "Rust package transcript is a dirty diagnostic receipt"
            )
        for prefix, expected in _EXACT_TRANSCRIPT_MARKERS:
            if canonical_line.startswith(prefix) and line != expected:
                raise RustPublishContractError(
                    f"Rust package transcript contains a malformed {prefix} marker"
                )
        if canonical_line.startswith("RUST_PACKAGE_SOURCE_PASS") and (
            _SOURCE_MARKER.fullmatch(line) is None
        ):
            raise RustPublishContractError(
                "Rust package transcript contains a malformed source marker"
            )
        if canonical_line.startswith("RUST_CRATES_IO_LOCK_VERIFY_PASS") and (
            _CRATES_IO_LOCK_VERIFY_MARKER.fullmatch(line) is None
        ):
            raise RustPublishContractError(
                "Rust package transcript contains a malformed crates.io lock marker"
            )
        if canonical_line.startswith("RUST_NORMALIZED_LOCK_STABILITY_PASS") and (
            _NORMALIZED_LOCK_STABILITY_MARKER.fullmatch(line) is None
        ):
            raise RustPublishContractError(
                "Rust package transcript contains a malformed lock stability marker"
            )

    toolchain_index = _single_exact_marker_index(
        lines,
        RUST_PACKAGE_TOOLCHAIN_MARKER,
        "toolchain",
    )
    cargo_home_index = _single_exact_marker_index(
        lines,
        RUST_PACKAGE_CARGO_HOME_MARKER,
        "isolated Cargo home",
    )

    list_crates: list[str] = []
    list_indices: list[int] = []
    verification_crates: list[str] = []
    verification_indices: list[int] = []
    advisory_commits: list[str] = []
    advisory_indices: list[int] = []
    source_commits: list[str] = []
    source_indices: list[int] = []
    registry_package_counts: list[int] = []
    normalized_lock_sha256s: list[str] = []
    yanked_indices: list[int] = []
    stable_lock_sha256s: list[str] = []
    stability_indices: list[int] = []
    clean_final_times: list[str] = []
    clean_final_indices: list[int] = []
    for index, line in enumerate(lines):
        canonical_line = line.lstrip()
        if canonical_line.startswith("RUST_PACKAGE_LIST_PASS"):
            match = _PACKAGE_LIST_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed package-list marker"
                )
            list_crates.append(match.group(1))
            list_indices.append(index)
        if canonical_line.startswith("RUST_PACKAGE_VERIFICATION_PASS"):
            match = _PACKAGE_VERIFICATION_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed verification marker"
                )
            verification_crates.append(match.group(1))
            verification_indices.append(index)
        if canonical_line.startswith("RUST_ADVISORY_DB_PASS"):
            match = _ADVISORY_DATABASE_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed advisory database marker"
                )
            advisory_commits.append(match.group(1))
            advisory_indices.append(index)
        if canonical_line.startswith("RUST_PACKAGE_SOURCE_PASS"):
            match = _SOURCE_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed source marker"
                )
            source_commits.append(match.group(1))
            source_indices.append(index)
        if canonical_line.startswith("RUST_CRATES_IO_LOCK_VERIFY_PASS"):
            match = _CRATES_IO_LOCK_VERIFY_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed crates.io lock marker"
                )
            registry_package_counts.append(int(match.group(1)))
            normalized_lock_sha256s.append(match.group(2))
            yanked_indices.append(index)
        if canonical_line.startswith("RUST_NORMALIZED_LOCK_STABILITY_PASS"):
            match = _NORMALIZED_LOCK_STABILITY_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed lock stability marker"
                )
            stable_lock_sha256s.append(match.group(1))
            stability_indices.append(index)
        if canonical_line.startswith("RUST_PACKAGE_CONTRACT_PASS"):
            match = _CLEAN_CONTRACT_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed clean final marker"
                )
            clean_final_times.append(match.group(1))
            clean_final_indices.append(index)

    package_list_crates = _validate_exact_crate_sequence(
        list_crates,
        "package-list",
    )
    package_verification_crates = _validate_exact_crate_sequence(
        verification_crates,
        "verification",
    )
    if len(advisory_commits) != 1:
        raise RustPublishContractError(
            "Rust package transcript must contain exactly one advisory database marker"
        )
    if len(source_commits) != 1:
        raise RustPublishContractError(
            "Rust package transcript must contain exactly one source marker"
        )
    if len(registry_package_counts) != 1:
        raise RustPublishContractError(
            "Rust package transcript must contain exactly one crates.io lock marker"
        )
    if registry_package_counts[0] > RUST_SPARSE_MAX_REGISTRY_PACKAGES:
        raise RustPublishContractError(
            "Rust package transcript crates.io package count exceeds the contract limit"
        )
    if len(stable_lock_sha256s) != 1:
        raise RustPublishContractError(
            "Rust package transcript must contain exactly one lock stability marker"
        )
    if stable_lock_sha256s[0] != normalized_lock_sha256s[0]:
        raise RustPublishContractError(
            "Rust package transcript normalized lock hashes differ"
        )
    if len(clean_final_times) != 1:
        raise RustPublishContractError(
            "Rust package transcript must contain exactly one clean final marker"
        )

    normalized_audit_index = _single_exact_marker_index(
        lines,
        RUST_PACKAGE_NORMALIZED_AUDIT_MARKER,
        "normalized dependency audit",
    )
    cleanup_index = _single_exact_marker_index(
        lines,
        RUST_PACKAGE_CARGO_HOME_CLEANUP_MARKER,
        "Cargo home cleanup",
    )
    final_index = clean_final_indices[0]
    final_nonempty_index = max(
        (index for index, line in enumerate(lines) if line),
        default=-1,
    )
    if final_index != final_nonempty_index:
        raise RustPublishContractError(
            "Rust package transcript clean final marker is not the last non-empty line"
        )

    completed_at = clean_final_times[0]
    try:
        parsed_completed_at = dt.datetime.strptime(
            completed_at,
            "%Y-%m-%dT%H:%M:%SZ",
        )
    except ValueError as exc:
        raise RustPublishContractError(
            "Rust package transcript completion time is not canonical RFC3339 UTC"
        ) from exc
    if parsed_completed_at.strftime("%Y-%m-%dT%H:%M:%SZ") != completed_at:
        raise RustPublishContractError(
            "Rust package transcript completion time is not canonical RFC3339 UTC"
        )

    ordered_indices = [
        cargo_home_index,
        toolchain_index,
        source_indices[0],
        *list_indices,
        *verification_indices,
        yanked_indices[0],
        normalized_audit_index,
        advisory_indices[0],
        stability_indices[0],
        cleanup_index,
        final_index,
    ]
    if any(
        current >= following
        for current, following in zip(ordered_indices, ordered_indices[1:])
    ):
        raise RustPublishContractError(
            "Rust package transcript phase marker order differs"
        )

    return RustPackageContractReceipt(
        advisory_db_commit=advisory_commits[0],
        completed_at=completed_at,
        package_list_crates=package_list_crates,
        package_verification_crates=package_verification_crates,
        normalized_cargo_lock_sha256=normalized_lock_sha256s[0],
        registry_package_count=registry_package_counts[0],
        source_commit=source_commits[0],
    )


def _clear_owned_package_directory(directory_fd: int, path: pathlib.Path) -> None:
    try:
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot list owned package directory: {path}: {exc}"
        ) from exc

    for name in names:
        child_path = path / name
        try:
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot inspect owned package entry: {child_path}: {exc}"
            ) from exc
        if not stat.S_ISDIR(observed.st_mode):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot unlink owned package entry: {child_path}: {exc}"
                ) from exc
            continue

        observed_identity = _directory_identity(observed, child_path)
        try:
            child_fd = os.open(name, _OWNED_DIRECTORY_FLAGS, dir_fd=directory_fd)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot anchor owned package subdirectory: {child_path}: {exc}"
            ) from exc
        try:
            descriptor_identity = _directory_identity(os.fstat(child_fd), child_path)
            if descriptor_identity != observed_identity:
                raise RustPublishContractError(
                    f"owned package subdirectory was replaced before cleanup: {child_path}"
                )
            _clear_owned_package_directory(child_fd, child_path)
            try:
                final_identity = _directory_identity(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                    child_path,
                )
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot revalidate owned package subdirectory: {child_path}: {exc}"
                ) from exc
            if final_identity != descriptor_identity:
                raise RustPublishContractError(
                    f"owned package subdirectory was replaced during cleanup: {child_path}"
                )
            try:
                os.rmdir(name, dir_fd=directory_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot remove owned package subdirectory: {child_path}: {exc}"
                ) from exc
        finally:
            os.close(child_fd)


def remove_owned_package_directory(
    path: pathlib.Path,
    expected_device: int,
    expected_inode: int,
) -> None:
    """Remove only the identity captured for a package target, using anchored paths."""

    _require_owned_directory_apis()
    path = pathlib.Path(path)
    parent = _temporary_parent()
    if (
        not path.is_absolute()
        or path.parent != parent
        or _OWNED_TEMP_NAME.fullmatch(path.name) is None
        or expected_device < 0
        or expected_inode <= 0
    ):
        raise RustPublishContractError(
            f"owned package directory cleanup request is malformed: {path}"
        )
    expected_identity = expected_device, expected_inode
    try:
        parent_fd = os.open(parent, _OWNED_DIRECTORY_FLAGS)
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot open the package temporary parent: {parent}: {exc}"
        ) from exc
    try:
        try:
            observed = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot inspect owned package directory before cleanup: {path}: {exc}"
            ) from exc
        observed_identity = _validate_owned_root_metadata(observed, path)
        if observed_identity != expected_identity:
            raise RustPublishContractError(
                f"owned package directory identity changed before cleanup: {path}"
            )
        try:
            directory_fd = os.open(path.name, _OWNED_DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot anchor owned package directory for cleanup: {path}: {exc}"
            ) from exc
        try:
            descriptor_identity = _validate_owned_root_metadata(
                os.fstat(directory_fd), path
            )
            if descriptor_identity != expected_identity:
                raise RustPublishContractError(
                    f"owned package directory was replaced before cleanup: {path}"
                )
            _clear_owned_package_directory(directory_fd, path)
            final_identity = _validate_owned_root_metadata(
                os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False), path
            )
            if final_identity != descriptor_identity:
                raise RustPublishContractError(
                    f"owned package directory was replaced during cleanup: {path}"
                )
            try:
                os.rmdir(path.name, dir_fd=parent_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot remove owned package directory: {path}: {exc}"
                ) from exc
        finally:
            os.close(directory_fd)
    finally:
        os.close(parent_fd)


def validate_cargo_output(label: str, streams: Iterable[str]) -> None:
    """Reject every Cargo warning without hiding any other diagnostic."""

    if not label or any(character in label for character in "\r\n"):
        raise RustPublishContractError("Cargo command label is malformed")
    for stream in streams:
        for line in stream.splitlines():
            if "warning:" in line.casefold():
                raise RustPublishContractError(
                    f"{label} emitted a warning: {line}"
                )


def validate_cargo_package_completion(
    crate: str,
    streams: Iterable[str],
) -> None:
    """Require Cargo's complete package and rebuilt-archive verification phases."""

    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", crate) is None:
        raise RustPublishContractError("Cargo package name is malformed")
    output = "\n".join(streams)
    required = (
        f"Packaging {crate} ",
        "Packaged ",
        f"Verifying {crate} ",
        "Finished `dev` profile",
    )
    missing = [marker for marker in required if marker not in output]
    if missing:
        raise RustPublishContractError(
            f"Cargo package verification log for {crate} is incomplete: {missing}"
        )


_ALLOWED_BUILD_MODULE = '#[path = "src/build_support.rs"]\nmod build_support;'
_EXPECTED_BUILD_SURFACE_SHA256 = {
    "build.rs": "762ca28ec0f738e5165c2f2b8c9efa20bc1870ca997bcbedeffee19847e3928a",
    "src/build_support.rs": "aede04be9ca74fc58b4c0e2cf26503fde702598075c55b95f0d8c50369c70d63",
    "src/mlkem_bridge.c": "a05b807108685a33ac03b42cad4eb5c9b9c26c850030aa3d2de503e7f97fb93e",
    "src/mlkem_bridge.h": "b8c286379f0f6444c91b3ae66b9aa3dcc412b62a727cd480c610b7e8d19722a2",
    "src/mlkem_config.h": "a6a1eb47cd506dc8db14e08c7dbe1a245386db252cab3ca3821565b83eef27e4",
}
_EXPECTED_LOCAL_SOURCE_FILES = frozenset(
    {
        "src/build_support.rs",
        "src/build_support_tests.rs",
        "src/lib.rs",
        "src/mlkem_bridge.c",
        "src/mlkem_bridge.h",
        "src/mlkem_config.h",
        "src/raw.rs",
        "src/tests.rs",
    }
)
_CONFIG_SELECTION = re.compile(
    r'\.define\(\s*"MLK_CONFIG_FILE"\s*,\s*'
    r'Some\(\s*"\\"mlkem_config\.h\\""\s*\)\s*\)'
)
_INCLUDE_SOURCE_TOKEN = re.compile(r"(?<!\.)\binclude(?:_bytes|_str)?\b")
_C_INCLUDE_DIRECTIVE = re.compile(
    r"(?m)^[ \t]*(?:#|%:|\?\?=)[ \t]*(?:include|include_next|import)\b[^\r\n]*$"
)
_C_LITERAL_INCLUDE = re.compile(
    r'(?m)^[ \t]*#[ \t]*include[ \t]*(?P<target>"[^"\r\n]+"|<[^>\r\n]+>)[ \t]*$'
)
_EXPECTED_C_INCLUDES = {
    "src/mlkem_bridge.c": (
        '"mlkem_bridge.h"',
        '"mlkem_native.c"',
        '"mlkem_native.c"',
        '"mlkem_native.c"',
    ),
    "src/mlkem_bridge.h": ("<stdint.h>", '"mlkem_native.h"'),
    "src/mlkem_config.h": (
        "<stddef.h>",
        "<stdint.h>",
        '"src/sys.h"',
        "<stddef.h>",
        "<stdint.h>",
        '"src/sys.h"',
    ),
}
_PORTABLE_CONFIG_PREFIX = (
    "/* SPDX-License-Identifier: Apache-2.0 OR MIT */\n"
    "#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH) || \\\n"
    "    defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202) || \\\n"
    "    defined(MLK_CONFIG_ARITH_BACKEND_FILE) || \\\n"
    "    defined(MLK_CONFIG_FIPS202_BACKEND_FILE) || \\\n"
    "    defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER) || \\\n"
    "    defined(MLK_CONFIG_FIPS202X4_CUSTOM_HEADER)\n"
    "#error External or native mlkem-native backends are not supported by this portable-only crate\n"
    "#endif\n\n"
    "#ifndef QPN_MLKEM_CONFIG_H\n"
    "#define QPN_MLKEM_CONFIG_H\n"
)
_REQUIRED_GUARD_TOKENS = {
    "MLK_CONFIG_USE_NATIVE_BACKEND_ARITH",
    "MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202",
    "MLK_CONFIG_ARITH_BACKEND_FILE",
    "MLK_CONFIG_FIPS202_BACKEND_FILE",
    "MLK_CONFIG_FIPS202_CUSTOM_HEADER",
    "MLK_CONFIG_FIPS202X4_CUSTOM_HEADER",
}
_NATIVE_ENABLE_PATTERNS = {
    "C #define MLK_CONFIG_USE_NATIVE_BACKEND_*": re.compile(
        r"(?m)^\s*#\s*define\s+MLK_CONFIG_USE_NATIVE_BACKEND_(?:ARITH|FIPS202)(?:\s|$)"
    ),
    "cc::Build::define MLK_CONFIG_USE_NATIVE_BACKEND_*": re.compile(
        r'\.define\(\s*"MLK_CONFIG_USE_NATIVE_BACKEND_(?:ARITH|FIPS202)"'
    ),
    "C #define MLK_CONFIG_*_BACKEND_FILE": re.compile(
        r"(?m)^\s*#\s*define\s+MLK_CONFIG_(?:ARITH|FIPS202)_BACKEND_FILE(?:\s|$)"
    ),
    "cc::Build::define MLK_CONFIG_*_BACKEND_FILE": re.compile(
        r'\.define\(\s*"MLK_CONFIG_(?:ARITH|FIPS202)_BACKEND_FILE"'
    ),
    "assembly translation unit": re.compile(
        r'(?i)#\s*include\s*[<"][^>"]+\.S[>"]|'
        r"\.files?\([^\n)]*\.S|mlkem_native_asm\.S"
    ),
    "prebuilt object": re.compile(r"\.objects?\b"),
    "native assembly symbol": re.compile(r"(?i)\b[a-z_][a-z0-9_]*_asm\s*\("),
}


def validate_packaged_mlkem_native_local_sources(source_files: set[str]) -> None:
    """Reject local package files outside the reviewed sys-crate source set."""

    missing = sorted(_EXPECTED_LOCAL_SOURCE_FILES - source_files)
    extra = sorted(source_files - _EXPECTED_LOCAL_SOURCE_FILES)
    if missing or extra:
        raise RustPublishContractError(
            "sys crate packaged local source set differs from the audited allowlist: "
            f"missing={missing} extra={extra}"
        )


def _validate_c_include_graph(name: str, source: str) -> None:
    directives = _C_INCLUDE_DIRECTIVE.findall(source)
    literal_targets = tuple(
        match.group("target") for match in _C_LITERAL_INCLUDE.finditer(source)
    )
    expected_targets = _EXPECTED_C_INCLUDES[name]
    if len(directives) != len(literal_targets) or literal_targets != expected_targets:
        raise RustPublishContractError(
            "portable C include graph differs from the audited allowlist: "
            f"file={name} directives={len(directives)} "
            f"literal_targets={list(literal_targets)} "
            f"expected={list(expected_targets)}"
        )


def validate_mlkem_native_build_surface(
    *,
    build_rs: str,
    build_support: str,
    bridge_c: str,
    bridge_h: str,
    local_config: str,
) -> None:
    """Validate the complete packaged build-script and portable C surface.

    The semantic checks are intentionally lexical and conservative. The final
    whole-file digest allowlist closes equivalent Rust and C spellings without
    pretending that these checks are complete language parsers.
    """

    build_rust_surface = "\n".join((build_rs, build_support))
    build_surface = "\n".join(
        (build_rust_surface, bridge_c, bridge_h, local_config)
    )

    allowed_build_module_count = build_rs.count(_ALLOWED_BUILD_MODULE)
    remaining_build_rs = build_rs.replace(_ALLOWED_BUILD_MODULE, "", 1)
    unapproved_mod_sources = sorted(
        name
        for name, rust_source in (
            ("build.rs", remaining_build_rs),
            ("src/build_support.rs", build_support),
        )
        if re.search(r"\bmod\b", rust_source)
    )
    included_sources = sorted(
        name
        for name, rust_source in (
            ("build.rs", build_rs),
            ("src/build_support.rs", build_support),
        )
        if _INCLUDE_SOURCE_TOKEN.search(rust_source)
    )
    if (
        allowed_build_module_count != 1
        or unapproved_mod_sources
        or included_sources
    ):
        raise RustPublishContractError(
            "sys crate build-script module graph differs from the audited surface: "
            f"allowed_count={allowed_build_module_count} "
            f"unapproved_mod_sources={unapproved_mod_sources} "
            f"include_macros={included_sources}"
        )

    config_selections = _CONFIG_SELECTION.findall(build_rust_surface)
    if len(config_selections) != 1:
        raise RustPublishContractError(
            "portable build must select packaged mlkem_config.h exactly once: "
            f"matches={len(config_selections)}"
        )

    source_files = re.findall(r'\.file\(\s*"([^"]+)"', build_rust_surface)
    file_call_count = len(re.findall(r"\.file\b", build_rust_surface))
    files_call_count = len(re.findall(r"\.files\b", build_rust_surface))
    if (
        source_files != ["src/mlkem_bridge.c"]
        or file_call_count != 1
        or files_call_count != 0
    ):
        raise RustPublishContractError(
            "sys crate must compile exactly the single portable bridge translation unit: "
            f"literal_files={source_files} file_calls={file_call_count} "
            f"files_calls={files_call_count}"
        )

    define_names = re.findall(r'\.define\(\s*"([^"]+)"', build_rust_surface)
    define_call_count = len(re.findall(r"\.define\b", build_rust_surface))
    expected_define_names = ["MLK_CONFIG_FILE", "QPN_MLKEM_FREESTANDING"]
    try_compile_count = len(re.findall(r"\.try_compile\b", build_rust_surface))
    forbidden_build_tokens = sorted(
        token for token in _REQUIRED_GUARD_TOKENS if token in build_rust_surface
    )
    if (
        define_names != expected_define_names
        or define_call_count != len(expected_define_names)
        or try_compile_count != 1
        or forbidden_build_tokens
    ):
        raise RustPublishContractError(
            "sys crate build-script API surface differs from the portable allowlist: "
            f"defines={define_names} define_calls={define_call_count} "
            f"try_compile_calls={try_compile_count} "
            f"forbidden_tokens={forbidden_build_tokens}"
        )

    for name, source in (
        ("src/mlkem_bridge.c", bridge_c),
        ("src/mlkem_bridge.h", bridge_h),
        ("src/mlkem_config.h", local_config),
    ):
        _validate_c_include_graph(name, source)

    guard_token_counts = {
        token: local_config.count(token) for token in sorted(_REQUIRED_GUARD_TOKENS)
    }
    error_directive_count = len(
        re.findall(r"(?m)^[ \t]*#[ \t]*error\b", local_config)
    )
    if (
        not local_config.startswith(_PORTABLE_CONFIG_PREFIX)
        or any(count != 1 for count in guard_token_counts.values())
        or error_directive_count != 1
    ):
        raise RustPublishContractError(
            "portable config lacks the active fail-fast native-backend guard prefix: "
            f"token_counts={guard_token_counts} "
            f"error_directives={error_directive_count}"
        )

    enabled_native_shapes = sorted(
        label
        for label, pattern in _NATIVE_ENABLE_PATTERNS.items()
        if pattern.search(build_surface)
    )
    if enabled_native_shapes:
        raise RustPublishContractError(
            "sys crate release build is not portable-only: "
            f"{enabled_native_shapes}"
        )

    packaged_sources = {
        "build.rs": build_rs,
        "src/build_support.rs": build_support,
        "src/mlkem_bridge.c": bridge_c,
        "src/mlkem_bridge.h": bridge_h,
        "src/mlkem_config.h": local_config,
    }
    actual_digests = {
        name: hashlib.sha256(source.encode("utf-8")).hexdigest()
        for name, source in packaged_sources.items()
    }
    mismatches = {
        name: {
            "expected": _EXPECTED_BUILD_SURFACE_SHA256[name],
            "actual": actual_digests[name],
        }
        for name in packaged_sources
        if actual_digests[name] != _EXPECTED_BUILD_SURFACE_SHA256[name]
    }
    if mismatches:
        raise RustPublishContractError(
            "packaged build-surface bytes differ from the audited allowlist: "
            f"{mismatches}"
        )


def _verify_crates_io_sparse_worker(arguments: list[str]) -> int:
    if len(arguments) != 2:
        _print_sparse_worker_failure("sparse verification worker arguments are malformed")
        return 2
    lock_path = pathlib.Path(arguments[0])
    expected_sha256 = arguments[1]
    if _CHECKSUM.fullmatch(expected_sha256) is None:
        _print_sparse_worker_failure("sparse verification worker hash is malformed")
        return 2
    try:
        snapshot = read_regular_snapshot(
            lock_path,
            maximum=RUST_SPARSE_LOCK_MAX_BYTES,
            label="normalized q-periapt-backends Cargo.lock worker input",
        )
        if snapshot.sha256 != expected_sha256:
            raise RustPublishContractError(
                "sparse verification worker input hash differs"
            )
        registry_packages = _validate_crates_io_sparse_yanked_with_fetcher(
            snapshot.data,
            fetcher=_fetch_crates_io_sparse_entry,
        )
    except (EvidenceIOError, RustPublishContractError) as exc:
        _print_sparse_worker_failure(str(exc))
        return 1
    print(
        json.dumps(
            {
                "normalized_lock_sha256": snapshot.sha256,
                "ok": True,
                "registry_packages": registry_packages,
                "schema": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


def _print_sparse_worker_failure(message: str) -> None:
    sanitized = " ".join(message.split())
    if not sanitized:
        sanitized = "unspecified sparse verification failure"
    sanitized = sanitized[:RUST_SPARSE_HELPER_MAX_MESSAGE_CHARS]
    print(
        json.dumps(
            {
                "error_kind": "verification",
                "message": sanitized,
                "ok": False,
                "schema": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _main(arguments: list[str]) -> int:
    if arguments and arguments[0] == "verify-crates-io-sparse-worker":
        return _verify_crates_io_sparse_worker(arguments[1:])
    print("error: unsupported Rust package contract command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
