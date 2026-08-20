#!/usr/bin/env python3

"""Fail-closed checks for the packaged Rust/C build surface."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import math
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
from collections.abc import Callable, Iterable, Mapping

from bounded_process import (
    REAP_TIMEOUT_SECONDS,
    BoundedProcessError,
    BoundedResult,
    capture_stdout,
)
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
RUST_PACKAGE_VERIFICATION_CLEANUP_MARKER = (
    "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS package-verification"
)
RUST_PACKAGE_INSPECTION_CLEANUP_MARKER = (
    "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS package-inspection"
)
RUST_MLKEM_PROVIDER_FENCE_MARKER = (
    "RUST_MLKEM_PROVIDER_FENCE_PASS "
    "reference=ml-kem@0.2.3:dev-only normal=q-periapt-mlkem-native-sys"
)
RUST_PUBLISH_METADATA_MARKER = (
    "RUST_PUBLISH_METADATA_PASS publishable=10 nonpublishable=5 "
    "mlkem_provider=q-periapt-mlkem-native-sys "
    "sys_build_dependency=cc@1.2.67"
)
RUST_BACKENDS_INSPECTION_MARKER = (
    "RUST_BACKENDS_INSPECTION_PACKAGE_PASS "
    "package=q-periapt-backends normalized_archive=present"
)
RUST_BACKENDS_NORMALIZED_MANIFEST_MARKER = (
    "RUST_BACKENDS_NORMALIZED_MANIFEST_PASS package=q-periapt-backends "
    "mlkem_provider=q-periapt-mlkem-native-sys retired=none vendored_mlkem=none "
    "performance_reference_api=absent"
)
RUST_MLKEM_UPSTREAM_VERSION = "v1.2.0"
RUST_MLKEM_UPSTREAM_COMMIT = "0ba906cb14b1c241476134d7403a811b382ca498"
RUST_MLKEM_VENDOR_FILE_COUNT = 118
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
    (
        "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS package-verification",
        RUST_PACKAGE_VERIFICATION_CLEANUP_MARKER,
    ),
    (
        "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS package-inspection",
        RUST_PACKAGE_INSPECTION_CLEANUP_MARKER,
    ),
    ("RUST_MLKEM_PROVIDER_FENCE_PASS", RUST_MLKEM_PROVIDER_FENCE_MARKER),
    ("RUST_PUBLISH_METADATA_PASS", RUST_PUBLISH_METADATA_MARKER),
    (
        "RUST_BACKENDS_INSPECTION_PACKAGE_PASS",
        RUST_BACKENDS_INSPECTION_MARKER,
    ),
    (
        "RUST_BACKENDS_NORMALIZED_MANIFEST_PASS",
        RUST_BACKENDS_NORMALIZED_MANIFEST_MARKER,
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
RUST_PACKAGE_WARNING_FREE_LABELS = (
    "cargo-metadata",
    *(f"cargo-package-list-{crate}" for crate in RUST_PUBLISHABLE_CRATES),
    *(f"cargo-package-verification-{crate}" for crate in RUST_PUBLISHABLE_CRATES),
    "cargo-package-inspection-q-periapt-mlkem-native-sys",
    "cargo-package-inspection-q-periapt-backends",
    "cargo-generate-normalized-backends-lockfile",
    "cargo-audit-normalized-backends",
)
RUST_PACKAGE_COMPLETION_CRATES = RUST_PUBLISHABLE_CRATES + (
    "q-periapt-mlkem-native-sys",
    "q-periapt-backends",
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
RUST_WORKSPACE_LOCAL_CRATES = frozenset(
    {
        "q-periapt-backends",
        "q-periapt-cli",
        "q-periapt-continuity-model",
        "q-periapt-core",
        "q-periapt-ctstats",
        "q-periapt-ffi",
        "q-periapt-kem",
        "q-periapt-migration",
        "q-periapt-mlkem-native-sys",
        "q-periapt-policy",
        "q-periapt-policy-agent",
        "q-periapt-rustls",
        "q-periapt-sig",
        "q-periapt-tls-demo",
        "q-periapt-wasm",
    }
)
RUST_FUZZ_LOCAL_CRATES = frozenset(
    {
        "q-periapt-backends",
        "q-periapt-core",
        "q-periapt-fuzz",
        "q-periapt-mlkem-native-sys",
        "q-periapt-sig",
    }
)
RUST_WORKSPACE_AUDIT_MARKER_PREFIX = "RUST_WORKSPACE_DEPENDENCY_AUDIT_PASS"
RUST_WORKSPACE_DEPENDENCY_AUDIT_TIMEOUT_SECONDS = 900
RUST_DEPENDENCY_AUDIT_TIMEOUT_SECONDS = 300
RUST_DEPENDENCY_AUDIT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
RUST_DEPENDENCY_AUDIT_TOOL_COMPONENTS = (
    "target",
    "qperiapt-audit-tool",
    "bin",
    "cargo-audit",
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
    cargo_warning_free_labels: tuple[str, ...]
    package_completion_crates: tuple[str, ...]
    mlkem_host_target: str
    mlkem_implementation: str
    mlkem_implementation_id: str
    mlkem_archive_object_count: int
    mlkem_archive_symbol_count: int
    mlkem_vendor_file_count: int
    mlkem_upstream_version: str
    mlkem_upstream_commit: str
    mlkem_reference_provider: str
    mlkem_normal_provider: str
    publishable_crate_count: int
    nonpublishable_crate_count: int
    backends_package: str


@dataclasses.dataclass(frozen=True, slots=True)
class RustPackageDiagnosticContractReceipt:
    """Identity fields from one complete diagnostic-only package transcript."""

    completed_at: str
    source_commit: str
    source_dirty: bool


@dataclasses.dataclass(frozen=True, slots=True)
class WorkspaceDependencyAuditReceipt:
    """Bound fields from one isolated workspace-plus-fuzz dependency audit."""

    workspace_registry_packages: int
    fuzz_registry_packages: int
    advisory_db_commit: str
    workspace_lock_sha256: str
    fuzz_lock_sha256: str


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
    r"qperiapt-(?:package-(?:verification|inspection|cargo-home|sparse-lock)"
    r"|rust-package-handoff-stage)\.$"
)
_OWNED_TEMP_NAME = re.compile(
    r"qperiapt-(?:package-(?:verification|inspection|cargo-home|sparse-lock)"
    r"|rust-package-handoff-stage)\.[0-9a-f]{24}$"
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


def exact_internal_dependency_requirement(version: object) -> str:
    """Return the coordinated workspace's exact Cargo requirement."""

    if not _is_semver(version):
        raise RustPublishContractError(
            f"workspace package version is not strict SemVer: {version!r}"
        )
    return f"={version}"


def _local_crates_for_lock_scope(scope: str) -> frozenset[str]:
    policies = (
        ("normalized-backends", RUST_NORMALIZED_LOCAL_CRATES),
        ("workspace", RUST_WORKSPACE_LOCAL_CRATES),
        ("fuzz", RUST_FUZZ_LOCAL_CRATES),
    )
    for name, local_crates in policies:
        if scope == name:
            return local_crates
    raise RustPublishContractError(f"Cargo.lock scope is unsupported: {scope!r}")


def _dependency_audit_stage_timeout(
    deadline: float | None,
    *,
    maximum_seconds: int,
    label: str,
) -> int:
    """Return a subprocess timeout that preserves one shared audit deadline."""

    if type(maximum_seconds) is not int or maximum_seconds <= 0:
        raise RustPublishContractError(
            "dependency-audit stage timeout policy is malformed"
        )
    if deadline is None:
        return maximum_seconds
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise RustPublishContractError(
            "workspace dependency-audit deadline is malformed"
        )
    remaining = deadline - time.monotonic()
    # Bounded subprocess cleanup may need its fixed reap window after the
    # command timeout. Reserve that window so a timed-out child cannot turn a
    # stage-local limit into an unbounded run-wide audit.
    timeout_seconds = min(
        maximum_seconds,
        int(remaining - REAP_TIMEOUT_SECONDS),
    )
    if timeout_seconds < 1:
        raise RustPublishContractError(
            "workspace dependency audit exhausted its total deadline before "
            f"{label}"
        )
    return timeout_seconds


def _require_dependency_audit_deadline(
    deadline: float | None,
    *,
    label: str,
) -> None:
    if deadline is None:
        return
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise RustPublishContractError(
            "workspace dependency-audit deadline is malformed"
        )
    if time.monotonic() >= deadline:
        raise RustPublishContractError(
            "workspace dependency audit exhausted its total deadline "
            f"during {label}"
        )


def _parse_cargo_lock_scope(
    lock_data: bytes,
    *,
    scope: str = "normalized-backends",
) -> tuple[_LockedRegistryPackage, ...]:
    local_crates = _local_crates_for_lock_scope(scope)
    lock_label = f"{scope} Cargo.lock"
    if not isinstance(lock_data, bytes):
        raise RustPublishContractError(
            f"{lock_label} must be supplied as exact bytes"
        )
    if len(lock_data) > RUST_SPARSE_LOCK_MAX_BYTES:
        raise RustPublishContractError(
            f"{lock_label} exceeds the byte limit"
        )
    try:
        document = tomllib.loads(lock_data.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise RustPublishContractError(
            f"{lock_label} is invalid UTF-8 TOML: {exc}"
        ) from exc
    if type(document.get("version")) is not int or document.get("version") != 4:
        raise RustPublishContractError(
            f"{lock_label} must use schema version 4"
        )
    raw_packages = document.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise RustPublishContractError(
            f"{lock_label} must contain a non-empty package array"
        )

    local_names: set[str] = set()
    registry_identities: set[tuple[str, str]] = set()
    registry_packages: list[_LockedRegistryPackage] = []
    for record in raw_packages:
        if not isinstance(record, dict):
            raise RustPublishContractError(
                f"{lock_label} contains a non-table package record"
            )
        name = record.get("name")
        version = record.get("version")
        if not isinstance(name, str) or _CRATE_NAME.fullmatch(name) is None:
            raise RustPublishContractError(
                f"{lock_label} contains an invalid package name"
            )
        if not _is_semver(version):
            raise RustPublishContractError(
                f"{lock_label} contains an invalid version for {name}"
            )

        if "source" not in record:
            if name not in local_crates:
                raise RustPublishContractError(
                    f"{lock_label} contains an unexpected local package: {name}"
                )
            if name in local_names:
                raise RustPublishContractError(
                    f"{lock_label} contains a duplicate local package: {name}"
                )
            if "checksum" in record:
                raise RustPublishContractError(
                    f"{lock_label} local package has a checksum: {name}"
                )
            local_names.add(name)
            continue

        source = record.get("source")
        if source != RUST_CRATES_IO_REGISTRY_SOURCE:
            raise RustPublishContractError(
                f"{lock_label} contains a non-crates.io source: {source!r}"
            )
        if name in local_crates:
            raise RustPublishContractError(
                f"{lock_label} resolves a required local package from crates.io: "
                f"{name}"
            )
        checksum = record.get("checksum")
        if not isinstance(checksum, str) or _CHECKSUM.fullmatch(checksum) is None:
            raise RustPublishContractError(
                f"{lock_label} contains an invalid checksum for {name} {version}"
            )
        identity = name, version
        if identity in registry_identities:
            raise RustPublishContractError(
                f"{lock_label} contains a duplicate crates.io package: "
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
                f"{lock_label} exceeds the registry package limit"
            )

    if local_names != local_crates:
        raise RustPublishContractError(
            f"{lock_label} local package set differs: "
            f"missing={sorted(local_crates - local_names)} "
            f"extra={sorted(local_names - local_crates)}"
        )
    if not registry_packages:
        raise RustPublishContractError(
            f"{lock_label} contains no crates.io registry packages"
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
    scope: str = "normalized-backends",
) -> int:
    """Testable worker implementation; production wraps it in a hard-wall process."""

    lock_label = f"{scope} Cargo.lock"
    registry_packages = _parse_cargo_lock_scope(lock_data, scope=scope)
    by_name: dict[str, list[_LockedRegistryPackage]] = {}
    canonical_names: dict[str, str] = {}
    for package in registry_packages:
        canonical = package.name.lower()
        prior = canonical_names.setdefault(canonical, package.name)
        if prior != package.name:
            raise RustPublishContractError(
                f"{lock_label} contains case-ambiguous crates.io names: "
                f"{prior}, {package.name}"
            )
        by_name.setdefault(package.name, []).append(package)

    if not callable(fetcher):
        raise RustPublishContractError("crates.io sparse index fetcher is not callable")
    names = sorted(by_name)
    if len(names) > RUST_SPARSE_MAX_REGISTRY_PACKAGES:
        raise RustPublishContractError(
            f"{lock_label} exceeds the unique registry name limit"
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


def _write_owned_regular_file(
    directory: pathlib.Path,
    name: str,
    data: bytes,
) -> pathlib.Path:
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9.-]{0,63}", name) is None:
        raise RustPublishContractError("owned file name is malformed")
    if not isinstance(data, bytes):
        raise RustPublishContractError("owned file data must be exact bytes")
    output_path = directory / name
    try:
        directory_fd = os.open(directory, _OWNED_DIRECTORY_FLAGS)
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot anchor owned dependency-audit file directory: {exc}"
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
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot create owned dependency-audit file: {exc}"
            ) from exc
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise RustPublishContractError(
                    "cannot completely write owned dependency-audit file"
                )
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(data)
        ):
            raise RustPublishContractError(
                "owned dependency-audit file lacks its private regular-file identity"
            )
        return output_path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _write_owned_sparse_lock(directory: pathlib.Path, lock_data: bytes) -> pathlib.Path:
    return _write_owned_regular_file(directory, "Cargo.lock", lock_data)


def _validate_crates_io_sparse_via_helper(
    lock_data: bytes,
    *,
    runner: Callable[..., BoundedResult],
    scope: str = "normalized-backends",
    deadline: float | None = None,
) -> int:
    _local_crates_for_lock_scope(scope)
    lock_label = f"{scope} Cargo.lock"
    _require_dependency_audit_deadline(
        deadline,
        label=f"{scope} crates.io sparse verification preflight",
    )
    if not isinstance(lock_data, bytes):
        raise RustPublishContractError(
            f"{lock_label} must be supplied as exact bytes"
        )
    if len(lock_data) > RUST_SPARSE_LOCK_MAX_BYTES:
        raise RustPublishContractError(f"{lock_label} exceeds the byte limit")
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
            scope,
            str(lock_path),
            lock_sha256,
        )
        helper_timeout_seconds = _dependency_audit_stage_timeout(
            deadline,
            maximum_seconds=RUST_SPARSE_HELPER_TIMEOUT_SECONDS,
            label=f"{scope} crates.io sparse verification helper",
        )
        try:
            result = runner(
                command,
                timeout_seconds=helper_timeout_seconds,
                maximum_bytes=RUST_SPARSE_HELPER_MAX_OUTPUT_BYTES,
                stderr=subprocess.STDOUT,
                environment=RUST_SPARSE_HELPER_ENVIRONMENT,
            )
        except BoundedProcessError as exc:
            raise RustPublishContractError(
                "crates.io sparse verification helper failed at "
                f"{exc.kind} boundary: {exc}"
            ) from exc
        _require_dependency_audit_deadline(
            deadline,
            label=f"{scope} crates.io sparse verification helper",
        )
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
            "lock_sha256",
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
            or value.get("lock_sha256") != lock_sha256
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


def validate_crates_io_sparse_yanked(
    lock_data: bytes,
    *,
    scope: str = "normalized-backends",
    deadline: float | None = None,
) -> int:
    """Verify one fixed-scope lock under a hard-wall sparse helper process."""

    return _validate_crates_io_sparse_via_helper(
        lock_data,
        runner=capture_stdout,
        scope=scope,
        deadline=deadline,
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


def validate_rustsec_advisory_database(
    database: pathlib.Path,
    *,
    deadline: float | None = None,
) -> str:
    """Validate the exact clean RustSec database fetched for this contract run."""

    _require_dependency_audit_deadline(
        deadline,
        label="RustSec advisory database inspection preflight",
    )

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
        timeout_seconds = _dependency_audit_stage_timeout(
            deadline,
            maximum_seconds=30,
            label=f"RustSec advisory database {operation} inspection",
        )
        try:
            result = capture_stdout(
                [*git_prefix, *arguments],
                timeout_seconds=timeout_seconds,
                maximum_bytes=64 * 1024,
                stderr=subprocess.STDOUT,
                environment=_git_environment(),
            )
        except BoundedProcessError as exc:
            raise RustPublishContractError(
                f"RustSec advisory database {operation} inspection failed at "
                f"{exc.kind} boundary: {exc}"
            ) from exc
        _require_dependency_audit_deadline(
            deadline,
            label=f"RustSec advisory database {operation} inspection",
        )
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
    _require_dependency_audit_deadline(
        deadline,
        label="RustSec advisory database inspection",
    )
    return commit


def _dependency_audit_executable_identity(
    executable: pathlib.Path,
) -> tuple[pathlib.Path, tuple[int, int]]:
    requested = pathlib.Path(executable)
    if not requested.is_absolute():
        raise RustPublishContractError(
            "cargo-audit executable path must be absolute"
        )
    try:
        metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
        resolved_metadata = resolved.lstat()
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot inspect cargo-audit executable: {requested}: {exc}"
        ) from exc
    identity = metadata.st_dev, metadata.st_ino
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        or resolved != requested
        or not stat.S_ISREG(resolved_metadata.st_mode)
        or (resolved_metadata.st_dev, resolved_metadata.st_ino) != identity
    ):
        raise RustPublishContractError(
            "cargo-audit must be an absolute current-user-owned real executable"
        )
    return resolved, identity


def _fixed_workspace_dependency_audit_paths() -> tuple[pathlib.Path, pathlib.Path]:
    """Return code-derived source and tool paths for the release audit."""

    try:
        module_path = pathlib.Path(__file__).resolve(strict=True)
        root = module_path.parent.parent
        root_metadata = root.lstat()
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot resolve the fixed dependency-audit layout: {exc}"
        ) from exc
    if (
        module_path.name != "rust_publish_contract.py"
        or module_path.parent.name != "artifact"
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root / "artifact" / "rust_publish_contract.py" != module_path
    ):
        raise RustPublishContractError(
            "dependency-audit module is outside the fixed repository layout"
        )
    return root, root.joinpath(*RUST_DEPENDENCY_AUDIT_TOOL_COMPONENTS)


def _dependency_audit_environment(cargo_home: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(cargo_home),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TERM_COLOR": "never",
        "TERM": "dumb",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _run_dependency_audit_command(
    argv: tuple[str, ...],
    *,
    environment: dict[str, str],
    label: str,
    deadline: float,
) -> BoundedResult:
    timeout_seconds = _dependency_audit_stage_timeout(
        deadline,
        maximum_seconds=RUST_DEPENDENCY_AUDIT_TIMEOUT_SECONDS,
        label=label,
    )
    try:
        result = capture_stdout(
            argv,
            timeout_seconds=timeout_seconds,
            maximum_bytes=RUST_DEPENDENCY_AUDIT_MAX_OUTPUT_BYTES,
            stderr=subprocess.STDOUT,
            environment=environment,
        )
    except BoundedProcessError as exc:
        raise RustPublishContractError(
            f"{label} failed at {exc.kind} boundary: {exc}"
        ) from exc
    _require_dependency_audit_deadline(deadline, label=label)
    if not isinstance(result, BoundedResult) or type(result.returncode) is not int:
        raise RustPublishContractError(f"{label} returned a malformed result")
    try:
        output = result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RustPublishContractError(f"{label} emitted non-UTF-8 output") from exc
    if result.returncode != 0:
        diagnostic_lines = [line.strip() for line in output.splitlines() if line.strip()]
        detail = " | ".join(diagnostic_lines[-4:])
        detail = " ".join(detail.split())[:1024]
        suffix = f": {detail}" if detail else ""
        raise RustPublishContractError(
            f"{label} failed (exit={result.returncode}){suffix}"
        )
    validate_cargo_output(label, (output,))
    if any(
        line.lstrip().casefold().startswith("error:")
        for line in output.splitlines()
    ):
        raise RustPublishContractError(f"{label} emitted an error diagnostic")
    return result


def _revalidate_dependency_audit_executable(
    executable: pathlib.Path,
    identity: tuple[int, int],
) -> None:
    current, current_identity = _dependency_audit_executable_identity(executable)
    if current != executable or current_identity != identity:
        raise RustPublishContractError(
            "cargo-audit executable identity changed during dependency audit"
        )


def _fetch_rustsec_advisory_database(
    database: pathlib.Path,
    *,
    environment: dict[str, str],
    deadline: float,
) -> str:
    if database.exists() or database.is_symlink():
        raise RustPublishContractError(
            "fresh dependency-audit Cargo home contains an advisory database"
        )
    clone_argv = (
        GIT,
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "clone",
        "--depth=1",
        "--single-branch",
        "--no-tags",
        "--",
        RUSTSEC_ADVISORY_DB_URL,
        str(database),
    )
    _run_dependency_audit_command(
        clone_argv,
        environment=environment,
        label="git-fetch-rustsec-advisory-database",
        deadline=deadline,
    )
    return validate_rustsec_advisory_database(database, deadline=deadline)


def _verify_workspace_dependency_audit(
    root: pathlib.Path,
    cargo_audit_bin: pathlib.Path,
) -> WorkspaceDependencyAuditReceipt:
    """Audit the exact workspace and fuzz locks without ambient Cargo state."""

    deadline = (
        time.monotonic() + RUST_WORKSPACE_DEPENDENCY_AUDIT_TIMEOUT_SECONDS
    )

    requested_root = pathlib.Path(root)
    try:
        resolved_root = requested_root.resolve(strict=True)
        root_metadata = resolved_root.lstat()
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot resolve dependency-audit source root: {requested_root}: {exc}"
        ) from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise RustPublishContractError("dependency-audit source root is not a directory")

    cargo_audit, cargo_audit_identity = _dependency_audit_executable_identity(
        cargo_audit_bin
    )
    lock_inputs = (
        (
            "workspace",
            resolved_root / "Cargo.lock",
            "Workspace.lock",
        ),
        (
            "fuzz",
            resolved_root / "fuzz" / "Cargo.lock",
            "Fuzz.lock",
        ),
    )
    snapshots = {}
    try:
        for scope, path, _owned_name in lock_inputs:
            snapshots[scope] = read_regular_snapshot(
                path,
                maximum=RUST_SPARSE_LOCK_MAX_BYTES,
                label=f"{scope} dependency-audit Cargo.lock",
            )
    except EvidenceIOError as exc:
        raise RustPublishContractError(str(exc)) from exc

    _require_dependency_audit_deadline(
        deadline,
        label="Cargo.lock snapshot collection",
    )

    registry_counts: dict[str, int] = {}
    for scope, _path, _owned_name in lock_inputs:
        registry_counts[scope] = validate_crates_io_sparse_yanked(
            snapshots[scope].data,
            scope=scope,
            deadline=deadline,
        )
        _require_dependency_audit_deadline(
            deadline,
            label=f"{scope} crates.io sparse verification",
        )

    cargo_home, cargo_home_device, cargo_home_inode = (
        create_owned_package_directory("qperiapt-package-cargo-home.")
    )
    primary: BaseException | None = None
    try:
        owned_locks = {
            scope: _write_owned_regular_file(
                cargo_home,
                owned_name,
                snapshots[scope].data,
            )
            for scope, _path, owned_name in lock_inputs
        }
        advisory_database = cargo_home / "advisory-db"
        environment = _dependency_audit_environment(cargo_home)
        version_result = _run_dependency_audit_command(
            (str(cargo_audit), "--version"),
            environment=environment,
            label="cargo-audit-version",
            deadline=deadline,
        )
        if (
            version_result.stdout.rstrip(b"\n") != b"cargo-audit 0.22.2"
        ):
            raise RustPublishContractError(
                "workspace dependency audit requires cargo-audit 0.22.2"
            )
        _revalidate_dependency_audit_executable(
            cargo_audit,
            cargo_audit_identity,
        )
        advisory_commit = _fetch_rustsec_advisory_database(
            advisory_database,
            environment=environment,
            deadline=deadline,
        )

        common = (
            "audit",
            "--deny",
            "warnings",
            "--no-yanked",
            "--db",
            str(advisory_database),
            "--no-fetch",
        )
        _run_dependency_audit_command(
            (str(cargo_audit), *common, "--file", str(owned_locks["workspace"])),
            environment=environment,
            label="cargo-audit-workspace",
            deadline=deadline,
        )
        if (
            validate_rustsec_advisory_database(
                advisory_database,
                deadline=deadline,
            )
            != advisory_commit
        ):
            raise RustPublishContractError(
                "RustSec advisory database commit changed during workspace audit"
            )
        _revalidate_dependency_audit_executable(
            cargo_audit,
            cargo_audit_identity,
        )
        _run_dependency_audit_command(
            (
                str(cargo_audit),
                *common,
                "--file",
                str(owned_locks["fuzz"]),
            ),
            environment=environment,
            label="cargo-audit-fuzz",
            deadline=deadline,
        )
        if (
            validate_rustsec_advisory_database(
                advisory_database,
                deadline=deadline,
            )
            != advisory_commit
        ):
            raise RustPublishContractError(
                "RustSec advisory database commit changed between lock audits"
            )
        _revalidate_dependency_audit_executable(
            cargo_audit,
            cargo_audit_identity,
        )

        for scope, path, owned_name in lock_inputs:
            try:
                source_after = read_regular_snapshot(
                    path,
                    maximum=RUST_SPARSE_LOCK_MAX_BYTES,
                    label=f"post-audit {scope} Cargo.lock",
                )
                copy_after = read_regular_snapshot(
                    cargo_home / owned_name,
                    maximum=RUST_SPARSE_LOCK_MAX_BYTES,
                    label=f"post-audit owned {scope} Cargo.lock",
                )
            except EvidenceIOError as exc:
                raise RustPublishContractError(str(exc)) from exc
            expected = snapshots[scope]
            if (
                source_after.sha256 != expected.sha256
                or source_after.size != expected.size
                or copy_after.sha256 != expected.sha256
                or copy_after.size != expected.size
            ):
                raise RustPublishContractError(
                    f"{scope} Cargo.lock changed during dependency audit"
                )

        _require_dependency_audit_deadline(
            deadline,
            label="dependency-audit lock stability verification",
        )

        return WorkspaceDependencyAuditReceipt(
            workspace_registry_packages=registry_counts["workspace"],
            fuzz_registry_packages=registry_counts["fuzz"],
            advisory_db_commit=advisory_commit,
            workspace_lock_sha256=snapshots["workspace"].sha256,
            fuzz_lock_sha256=snapshots["fuzz"].sha256,
        )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            remove_owned_package_directory(
                cargo_home,
                cargo_home_device,
                cargo_home_inode,
            )
        except BaseException as cleanup_exc:
            if primary is not None:
                primary.add_note(
                    "dependency-audit Cargo home cleanup also failed: "
                    f"{cleanup_exc}"
                )
            else:
                raise


def verify_workspace_dependency_audit() -> WorkspaceDependencyAuditReceipt:
    """Audit fixed repository locks with the fixed repository-local tool."""

    root, cargo_audit = _fixed_workspace_dependency_audit_paths()
    return _verify_workspace_dependency_audit(root, cargo_audit)


_PACKAGE_LIST_MARKER = re.compile(
    r"RUST_PACKAGE_LIST_PASS ([a-z0-9][a-z0-9-]*) files=([1-9][0-9]*)"
)
_PACKAGE_VERIFICATION_MARKER = re.compile(
    r"RUST_PACKAGE_VERIFICATION_PASS ([a-z0-9][a-z0-9-]*) "
    r"registry=crates-io upload=not-attempted"
)
_CARGO_WARNING_FREE_MARKER = re.compile(
    r"RUST_CARGO_WARNING_FREE_PASS ([a-z0-9][a-z0-9-]*)"
)
_PACKAGE_COMPLETION_MARKER = re.compile(
    r"RUST_PACKAGE_COMPLETION_PASS ([a-z0-9][a-z0-9-]*)"
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
_MLKEM_ARCHIVE_BINARY_MARKER = re.compile(
    r"RUST_MLKEM_NATIVE_SYS_ARCHIVE_BINARY_PASS "
    r"target=([a-z0-9][a-z0-9_.-]*) "
    r"implementation=(portable|aarch64-native) "
    r"implementation_id=(mlkem-native-1\.2\.0/"
    r"(?:portable-c|aarch64-native-arith\+fips202-v8a-scalar"
    r"|aarch64-native-arith\+fips202-v84a)) "
    r"objects=([1-9][0-9]*) symbols=([1-9][0-9]*) "
    r"reserved_dynamic_abi=none"
)
_MLKEM_ARCHIVE_SOURCE_MARKER = re.compile(
    r"RUST_MLKEM_NATIVE_SYS_ARCHIVE_PASS "
    r"vendor_files=([1-9][0-9]*) upstream=(v[0-9]+\.[0-9]+\.[0-9]+) "
    r"commit=([0-9a-f]{40})"
)
_CLEAN_CONTRACT_MARKER = re.compile(
    r"RUST_PACKAGE_CONTRACT_PASS dirty=0 registry=crates-io "
    r"upload=not-attempted completed_at="
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)"
)
RUST_PACKAGE_DIAGNOSTIC_OPENING_MARKER = (
    "DIRTY_RUST_PACKAGE_CONTRACT_DIAGNOSTIC_ONLY"
)
_DIAGNOSTIC_SOURCE_MARKER = re.compile(
    r"RUST_PACKAGE_SOURCE_DIAGNOSTIC commit=([0-9a-f]{40,64}) dirty=([01])"
)
_DIAGNOSTIC_CONTRACT_MARKER = re.compile(
    r"RUST_PACKAGE_CONTRACT_DIAGNOSTIC_PASS dirty=([01]) registry=crates-io "
    r"upload=not-attempted completed_at="
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)"
)

_KNOWN_TRANSCRIPT_MARKER_PREFIXES = (
    "RUST_CARGO_HOME_ISOLATION_PASS",
    "RUST_PACKAGE_TOOLCHAIN_PASS",
    "RUST_PACKAGE_SOURCE_PASS",
    "RUST_CARGO_WARNING_FREE_PASS",
    "RUST_MLKEM_PROVIDER_FENCE_PASS",
    "RUST_PUBLISH_METADATA_PASS",
    "RUST_PACKAGE_LIST_PASS",
    "RUST_PACKAGE_COMPLETION_PASS",
    "RUST_PACKAGE_VERIFICATION_PASS",
    "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS",
    "RUST_MLKEM_NATIVE_SYS_ARCHIVE_BINARY_PASS",
    "RUST_MLKEM_NATIVE_SYS_ARCHIVE_PASS",
    "RUST_BACKENDS_INSPECTION_PACKAGE_PASS",
    "RUST_BACKENDS_NORMALIZED_MANIFEST_PASS",
    "RUST_CRATES_IO_LOCK_VERIFY_PASS",
    "RUST_BACKENDS_NORMALIZED_AUDIT_PASS",
    "RUST_ADVISORY_DB_PASS",
    "RUST_NORMALIZED_LOCK_STABILITY_PASS",
    "RUST_PACKAGE_CONTRACT_PASS",
)
_DYNAMIC_TRANSCRIPT_MARKERS = (
    (
        "RUST_CARGO_WARNING_FREE_PASS",
        _CARGO_WARNING_FREE_MARKER,
        "Cargo warning-free",
    ),
    (
        "RUST_PACKAGE_COMPLETION_PASS",
        _PACKAGE_COMPLETION_MARKER,
        "package completion",
    ),
    (
        "RUST_MLKEM_NATIVE_SYS_ARCHIVE_BINARY_PASS",
        _MLKEM_ARCHIVE_BINARY_MARKER,
        "ML-KEM binary archive",
    ),
    (
        "RUST_MLKEM_NATIVE_SYS_ARCHIVE_PASS",
        _MLKEM_ARCHIVE_SOURCE_MARKER,
        "ML-KEM source archive",
    ),
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
        if canonical_line.startswith(
            "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS"
        ) and line not in {
            RUST_PACKAGE_VERIFICATION_CLEANUP_MARKER,
            RUST_PACKAGE_INSPECTION_CLEANUP_MARKER,
            RUST_PACKAGE_CARGO_HOME_CLEANUP_MARKER,
        }:
            raise RustPublishContractError(
                "Rust package transcript contains a malformed owned-directory cleanup marker"
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
        for prefix, pattern, label in _DYNAMIC_TRANSCRIPT_MARKERS:
            if canonical_line.startswith(prefix) and pattern.fullmatch(line) is None:
                raise RustPublishContractError(
                    f"Rust package transcript contains a malformed {label} marker"
                )
        if canonical_line.startswith("RUST_") and not any(
            canonical_line.startswith(prefix)
            for prefix in _KNOWN_TRANSCRIPT_MARKER_PREFIXES
        ):
            raise RustPublishContractError(
                "Rust package transcript contains an unrecognized Rust gate marker: "
                f"{canonical_line!r}"
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
    provider_fence_index = _single_exact_marker_index(
        lines,
        RUST_MLKEM_PROVIDER_FENCE_MARKER,
        "ML-KEM provider fence",
    )
    publish_metadata_index = _single_exact_marker_index(
        lines,
        RUST_PUBLISH_METADATA_MARKER,
        "publish metadata",
    )
    verification_cleanup_index = _single_exact_marker_index(
        lines,
        RUST_PACKAGE_VERIFICATION_CLEANUP_MARKER,
        "package-verification cleanup",
    )
    backends_inspection_index = _single_exact_marker_index(
        lines,
        RUST_BACKENDS_INSPECTION_MARKER,
        "backend inspection package",
    )
    backends_manifest_index = _single_exact_marker_index(
        lines,
        RUST_BACKENDS_NORMALIZED_MANIFEST_MARKER,
        "backend normalized manifest",
    )

    warning_free_labels: list[str] = []
    warning_free_indices: list[int] = []
    completion_crates: list[str] = []
    completion_indices: list[int] = []
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
    archive_binary_receipts: list[tuple[str, str, str, int, int]] = []
    archive_binary_indices: list[int] = []
    archive_source_receipts: list[tuple[int, str, str]] = []
    archive_source_indices: list[int] = []
    for index, line in enumerate(lines):
        canonical_line = line.lstrip()
        if canonical_line.startswith("RUST_CARGO_WARNING_FREE_PASS"):
            match = _CARGO_WARNING_FREE_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed Cargo warning-free marker"
                )
            warning_free_labels.append(match.group(1))
            warning_free_indices.append(index)
        if canonical_line.startswith("RUST_PACKAGE_COMPLETION_PASS"):
            match = _PACKAGE_COMPLETION_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed package completion marker"
                )
            completion_crates.append(match.group(1))
            completion_indices.append(index)
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
        if canonical_line.startswith("RUST_MLKEM_NATIVE_SYS_ARCHIVE_BINARY_PASS"):
            match = _MLKEM_ARCHIVE_BINARY_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed ML-KEM binary archive marker"
                )
            archive_binary_receipts.append(
                (
                    match.group(1),
                    match.group(2),
                    match.group(3),
                    int(match.group(4)),
                    int(match.group(5)),
                )
            )
            archive_binary_indices.append(index)
        if canonical_line.startswith("RUST_MLKEM_NATIVE_SYS_ARCHIVE_PASS"):
            match = _MLKEM_ARCHIVE_SOURCE_MARKER.fullmatch(line)
            if match is None:
                raise RustPublishContractError(
                    "Rust package transcript contains a malformed ML-KEM source archive marker"
                )
            archive_source_receipts.append(
                (int(match.group(1)), match.group(2), match.group(3))
            )
            archive_source_indices.append(index)

    package_list_crates = _validate_exact_crate_sequence(
        list_crates,
        "package-list",
    )
    package_verification_crates = _validate_exact_crate_sequence(
        verification_crates,
        "verification",
    )
    if tuple(warning_free_labels) != RUST_PACKAGE_WARNING_FREE_LABELS:
        raise RustPublishContractError(
            "Rust package transcript Cargo warning-free label sequence differs: "
            f"actual={warning_free_labels} "
            f"expected={list(RUST_PACKAGE_WARNING_FREE_LABELS)}"
        )
    if tuple(completion_crates) != RUST_PACKAGE_COMPLETION_CRATES:
        raise RustPublishContractError(
            "Rust package transcript package completion crate sequence differs: "
            f"actual={completion_crates} "
            f"expected={list(RUST_PACKAGE_COMPLETION_CRATES)}"
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
    if len(archive_binary_receipts) != 1:
        raise RustPublishContractError(
            "Rust package transcript must contain exactly one ML-KEM binary archive marker"
        )
    if len(archive_source_receipts) != 1:
        raise RustPublishContractError(
            "Rust package transcript must contain exactly one ML-KEM source archive marker"
        )
    (
        mlkem_host_target,
        mlkem_implementation,
        mlkem_implementation_id,
        mlkem_archive_object_count,
        mlkem_archive_symbol_count,
    ) = archive_binary_receipts[0]
    expected_native = mlkem_host_target in _NATIVE_TARGETS
    expected_binary_contract = (
        "aarch64-native" if expected_native else "portable",
        (
            _native_implementation_id_for_target(mlkem_host_target)
            if expected_native
            else _PORTABLE_IMPLEMENTATION_ID
        ),
        2 if expected_native else 1,
        42 if expected_native else 30,
    )
    actual_binary_contract = (
        mlkem_implementation,
        mlkem_implementation_id,
        mlkem_archive_object_count,
        mlkem_archive_symbol_count,
    )
    if actual_binary_contract != expected_binary_contract:
        raise RustPublishContractError(
            "Rust package transcript ML-KEM binary archive fields differ from the "
            "host target contract: "
            f"target={mlkem_host_target!r} actual={actual_binary_contract} "
            f"expected={expected_binary_contract}"
        )
    (
        mlkem_vendor_file_count,
        mlkem_upstream_version,
        mlkem_upstream_commit,
    ) = archive_source_receipts[0]
    expected_source_contract = (
        RUST_MLKEM_VENDOR_FILE_COUNT,
        RUST_MLKEM_UPSTREAM_VERSION,
        RUST_MLKEM_UPSTREAM_COMMIT,
    )
    if archive_source_receipts[0] != expected_source_contract:
        raise RustPublishContractError(
            "Rust package transcript ML-KEM source archive fields differ from the "
            "audited source contract: "
            f"actual={archive_source_receipts[0]} expected={expected_source_contract}"
        )
    normalized_audit_index = _single_exact_marker_index(
        lines,
        RUST_PACKAGE_NORMALIZED_AUDIT_MARKER,
        "normalized dependency audit",
    )
    inspection_cleanup_index = _single_exact_marker_index(
        lines,
        RUST_PACKAGE_INSPECTION_CLEANUP_MARKER,
        "package-inspection cleanup",
    )
    cargo_home_cleanup_index = _single_exact_marker_index(
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
        warning_free_indices[0],
        provider_fence_index,
        publish_metadata_index,
    ]
    warning_index = 1
    for list_index in list_indices:
        ordered_indices.extend((warning_free_indices[warning_index], list_index))
        warning_index += 1
    for completion_index, verification_index in zip(
        completion_indices[: len(RUST_PUBLISHABLE_CRATES)],
        verification_indices,
    ):
        ordered_indices.extend(
            (
                warning_free_indices[warning_index],
                completion_index,
                verification_index,
            )
        )
        warning_index += 1
    ordered_indices.extend(
        (
            verification_cleanup_index,
            warning_free_indices[warning_index],
            completion_indices[len(RUST_PUBLISHABLE_CRATES)],
            archive_binary_indices[0],
            archive_source_indices[0],
        )
    )
    warning_index += 1
    ordered_indices.extend(
        (
            warning_free_indices[warning_index],
            completion_indices[len(RUST_PUBLISHABLE_CRATES) + 1],
            backends_inspection_index,
            backends_manifest_index,
        )
    )
    warning_index += 1
    ordered_indices.extend(
        (
            warning_free_indices[warning_index],
            yanked_indices[0],
        )
    )
    warning_index += 1
    ordered_indices.extend(
        (
            warning_free_indices[warning_index],
            normalized_audit_index,
            advisory_indices[0],
            stability_indices[0],
            inspection_cleanup_index,
            cargo_home_cleanup_index,
            final_index,
        )
    )
    if warning_index != len(warning_free_indices) - 1:
        raise RustPublishContractError(
            "internal Rust package marker ordering contract drifted"
        )
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
        cargo_warning_free_labels=tuple(warning_free_labels),
        package_completion_crates=tuple(completion_crates),
        mlkem_host_target=mlkem_host_target,
        mlkem_implementation=mlkem_implementation,
        mlkem_implementation_id=mlkem_implementation_id,
        mlkem_archive_object_count=mlkem_archive_object_count,
        mlkem_archive_symbol_count=mlkem_archive_symbol_count,
        mlkem_vendor_file_count=mlkem_vendor_file_count,
        mlkem_upstream_version=mlkem_upstream_version,
        mlkem_upstream_commit=mlkem_upstream_commit,
        mlkem_reference_provider="ml-kem@0.2.3:dev-only",
        mlkem_normal_provider="q-periapt-mlkem-native-sys",
        publishable_crate_count=len(RUST_PUBLISHABLE_CRATES),
        nonpublishable_crate_count=5,
        backends_package="q-periapt-backends",
    )


def validate_rust_package_diagnostic_transcript(
    transcript: bytes | str,
) -> RustPackageDiagnosticContractReceipt:
    """Parse one complete diagnostic transcript without granting clean status."""

    if isinstance(transcript, bytes):
        try:
            text = transcript.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RustPublishContractError(
                "Rust package diagnostic transcript is not valid UTF-8"
            ) from exc
    elif isinstance(transcript, str):
        text = transcript
    else:
        raise RustPublishContractError(
            "Rust package diagnostic transcript must be bytes or text"
        )
    if "\x00" in text or "\r" in text:
        raise RustPublishContractError(
            "Rust package diagnostic transcript contains a non-canonical "
            "control character"
        )

    lines = text.split("\n")
    opening_indices = [
        index
        for index, line in enumerate(lines)
        if line.lstrip().startswith(
            RUST_PACKAGE_DIAGNOSTIC_OPENING_MARKER
        )
    ]
    if (
        len(opening_indices) != 1
        or lines[opening_indices[0]]
        != RUST_PACKAGE_DIAGNOSTIC_OPENING_MARKER
    ):
        raise RustPublishContractError(
            "Rust package diagnostic transcript must contain exactly one "
            "canonical diagnostic-only opening marker"
        )
    first_nonempty_index = next(
        (index for index, line in enumerate(lines) if line),
        -1,
    )
    if opening_indices[0] != first_nonempty_index:
        raise RustPublishContractError(
            "Rust package diagnostic opening marker must be first"
        )

    source_indices = [
        index
        for index, line in enumerate(lines)
        if line.lstrip().startswith("RUST_PACKAGE_SOURCE_DIAGNOSTIC")
    ]
    if len(source_indices) != 1:
        raise RustPublishContractError(
            "Rust package diagnostic transcript must contain exactly one "
            "diagnostic source marker"
        )
    source_match = _DIAGNOSTIC_SOURCE_MARKER.fullmatch(
        lines[source_indices[0]]
    )
    if source_match is None:
        raise RustPublishContractError(
            "Rust package diagnostic transcript contains a malformed source marker"
        )

    final_indices = [
        index
        for index, line in enumerate(lines)
        if line.lstrip().startswith("RUST_PACKAGE_CONTRACT_DIAGNOSTIC_PASS")
    ]
    if len(final_indices) != 1:
        raise RustPublishContractError(
            "Rust package diagnostic transcript must contain exactly one "
            "diagnostic final marker"
        )
    final_match = _DIAGNOSTIC_CONTRACT_MARKER.fullmatch(
        lines[final_indices[0]]
    )
    if final_match is None:
        raise RustPublishContractError(
            "Rust package diagnostic transcript contains a malformed final marker"
        )
    if any(
        line.lstrip().startswith("RUST_PACKAGE_CONTRACT_PASS")
        for line in lines
    ):
        raise RustPublishContractError(
            "Rust package diagnostic transcript contains a clean final marker"
        )
    if any("RUST_PACKAGE_HANDOFF_" in line for line in lines):
        raise RustPublishContractError(
            "Rust package diagnostic transcript contains a reserved handoff marker"
        )
    source_dirty = source_match.group(2) == "1"
    if final_match.group(1) != source_match.group(2):
        raise RustPublishContractError(
            "Rust package diagnostic source and final dirty states differ"
        )

    normalized_lines = lines.copy()
    normalized_lines[opening_indices[0]] = ""
    normalized_lines[source_indices[0]] = (
        f"RUST_PACKAGE_SOURCE_PASS commit={source_match.group(1)} clean=1"
    )
    normalized_lines[final_indices[0]] = (
        "RUST_PACKAGE_CONTRACT_PASS dirty=0 registry=crates-io "
        "upload=not-attempted completed_at=" + final_match.group(2)
    )
    normalized = validate_rust_package_contract_transcript(
        "\n".join(normalized_lines)
    )
    if (
        normalized.source_commit != source_match.group(1)
        or normalized.completed_at != final_match.group(2)
    ):
        raise RustPublishContractError(
            "Rust package diagnostic normalization identity differs"
        )
    return RustPackageDiagnosticContractReceipt(
        completed_at=normalized.completed_at,
        source_commit=normalized.source_commit,
        source_dirty=source_dirty,
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


def validate_no_registry_credentials(environment: Mapping[str, str]) -> None:
    """Reject every ambient Cargo registry secret/provider override by name."""

    if not isinstance(environment, Mapping) or any(
        not isinstance(name, str) for name in environment
    ):
        raise RustPublishContractError("Cargo environment mapping is malformed")
    for name in environment:
        forbidden = (
            name
            in {
                "CARGO_REGISTRY_TOKEN",
                "CARGO_REGISTRY_CREDENTIAL_PROVIDER",
                "CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS",
            }
            or name.startswith("CARGO_CREDENTIAL_ALIAS_")
            or (
                name.startswith("CARGO_REGISTRIES_")
                and name.endswith(("_TOKEN", "_CREDENTIAL_PROVIDER"))
            )
        )
        if forbidden:
            raise RustPublishContractError(
                "registry credentials and credential-provider overrides must be "
                "unset for the no-upload package contract"
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
_EXPECTED_LOCAL_SOURCE_SHA256 = {
    "build.rs": "f63b712d01166e2fbb28c2a06911fd066467eb816c1a9d27f88a9dc55f8a58bb",
    "src/build_support.rs": "38c419a0e91f36ae0ad1297701b79d5ee8c56e07ffab933bb2d0f610e64c543d",
    "src/build_support_tests.rs": "69d9e0857ce5eaab46ba12b1f27803f1966be73b18b1839792f8a9d0c0631e14",
    "src/lib.rs": "ba789ccae6ef1cafdf99de52f8a4d5bd4012feaf698f7de215ecb0207b3c0975",
    "src/mlkem_bridge.c": "c12dbf268527fff0241a79f84f8dbcade065b37f3c76060f4f95c03a83bf149d",
    "src/mlkem_bridge_native.c": "88c9210692994677e8ab077c1a56c9bd8354897085eeec56e25743f46d8781b5",
    "src/mlkem_bridge_portable.c": "6d51c2083fc58fededd279edab804ef9300da0ffe3a4be14178c68aa85e7e623",
    "src/mlkem_bridge_asm.S": "c658b40e52fa3aebeef74c1c5dd4f56fa3d71d6f52721df9d47d6c1e13d50b7a",
    "src/mlkem_bridge.h": "b8c286379f0f6444c91b3ae66b9aa3dcc412b62a727cd480c610b7e8d19722a2",
    "src/mlkem_config.h": "3f0c08923e0f3d127335b987c9d0f9b70a7bacf69d3601d2a51eeed3fbb8a5e0",
    "src/mlkem_fips202_aarch64.h": "6057160bbae3ba7ce63794ac3708e6b6ce16cd018e9d3852f1e7b4f5f50dfad8",
    "src/raw.rs": "3da32c86e71ee0769c51ec6b0b925d6457259714f143c184a84001e958f3978b",
    "src/tests.rs": "89b082a5b5dfb78b75c8f8854f8243b708106a2dc48b1f5ffab160ae6320af26",
}
_EXPECTED_BUILD_SURFACE_FILES = (
    "build.rs",
    "src/build_support.rs",
    "src/mlkem_bridge.c",
    "src/mlkem_bridge_native.c",
    "src/mlkem_bridge_portable.c",
    "src/mlkem_bridge_asm.S",
    "src/mlkem_bridge.h",
    "src/mlkem_config.h",
    "src/mlkem_fips202_aarch64.h",
)
_EXPECTED_BUILD_SURFACE_SHA256 = {
    name: _EXPECTED_LOCAL_SOURCE_SHA256[name]
    for name in _EXPECTED_BUILD_SURFACE_FILES
}
_EXPECTED_LOCAL_SOURCE_FILES = frozenset(
    name for name in _EXPECTED_LOCAL_SOURCE_SHA256 if name.startswith("src/")
)
_INCLUDE_SOURCE_TOKEN = re.compile(r"(?<!\.)\binclude(?:_bytes|_str)?\b")
_EXPECTED_INCLUDE_SOURCE_TOKEN_COUNTS = {
    "build.rs": 0,
    "src/build_support.rs": 1,
}
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
    "src/mlkem_bridge_native.c": ('"mlkem_bridge.c"',),
    "src/mlkem_bridge_portable.c": ('"mlkem_bridge.c"',),
    "src/mlkem_bridge_asm.S": ('"mlkem_native_asm.S"',),
    "src/mlkem_bridge.h": ("<stdint.h>", '"mlkem_native.h"'),
    "src/mlkem_config.h": (
        "<TargetConditionals.h>",
        "<stddef.h>",
        "<stdint.h>",
        '"src/sys.h"',
        "<stddef.h>",
        "<stdint.h>",
        '"src/sys.h"',
    ),
    "src/mlkem_fips202_aarch64.h": (
        '"src/fips202/native/aarch64/x1_v84a.h"',
        '"src/fips202/native/aarch64/x2_v84a.h"',
        '"src/fips202/native/aarch64/x1_scalar.h"',
        '"src/fips202/native/aarch64/x4_v8a_scalar.h"',
    ),
}
_TARGET_SELECTED_CONFIG_PREFIX = (
    "/* SPDX-License-Identifier: Apache-2.0 OR MIT */\n"
    "#ifndef QPN_MLKEM_CONFIG_H\n"
    "#define QPN_MLKEM_CONFIG_H\n\n"
    "/* Exactly one source wrapper owns the implementation selection. */\n"
    "#if defined(QPN_MLKEM_BUILD_NATIVE_AARCH64) == \\\n"
    "    defined(QPN_MLKEM_BUILD_PORTABLE)\n"
    "#error Exactly one owned mlkem-native implementation selector is required\n"
    "#endif\n\n"
    "/* Reject caller-supplied upstream backend selection before defining ours. */\n"
    "#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH) || \\\n"
    "    defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202) || \\\n"
    "    defined(MLK_CONFIG_ARITH_BACKEND_FILE) || \\\n"
    "    defined(MLK_CONFIG_FIPS202_BACKEND_FILE) || \\\n"
    "    defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER) || \\\n"
    "    defined(MLK_CONFIG_FIPS202X4_CUSTOM_HEADER)\n"
    "#error External mlkem-native backend configuration is not supported\n"
    "#endif\n"
)
_EXPECTED_CONFIG_TOKEN_COUNTS = {
    "QPN_MLKEM_BUILD_NATIVE_AARCH64": 3,
    "QPN_MLKEM_BUILD_PORTABLE": 1,
    "MLK_CONFIG_USE_NATIVE_BACKEND_ARITH": 2,
    "MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202": 2,
    "MLK_CONFIG_ARITH_BACKEND_FILE": 2,
    "MLK_CONFIG_FIPS202_BACKEND_FILE": 2,
    "MLK_CONFIG_FIPS202_CUSTOM_HEADER": 1,
    "MLK_CONFIG_FIPS202X4_CUSTOM_HEADER": 1,
}
_C_DEFINE_DIRECTIVE = re.compile(
    r"(?m)^[ \t]*#[ \t]*define[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:[ \t]+(?P<value>[^\r\n]+?))?[ \t]*$"
)
_EXPECTED_WRAPPER_DEFINES = {
    "src/mlkem_bridge_native.c": (
        ("QPN_MLKEM_BUILD_NATIVE_AARCH64", ""),
        ("MLK_CONFIG_FILE", '"mlkem_config.h"'),
    ),
    "src/mlkem_bridge_portable.c": (
        ("QPN_MLKEM_BUILD_PORTABLE", ""),
        ("MLK_CONFIG_FILE", '"mlkem_config.h"'),
    ),
    "src/mlkem_bridge_asm.S": (
        ("QPN_MLKEM_BUILD_NATIVE_AARCH64", ""),
        ("MLK_CONFIG_FILE", '"mlkem_config.h"'),
        ("MLK_CONFIG_PARAMETER_SET", "512"),
        ("MLK_CONFIG_MULTILEVEL_WITH_SHARED", ""),
    ),
}
_PORTABLE_IMPLEMENTATION_ID = "mlkem-native-1.2.0/portable-c"
_AARCH64_NATIVE_IMPLEMENTATION_ID = (
    "mlkem-native-1.2.0/aarch64-native-arith+fips202-v8a-scalar"
)
_AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID = (
    "mlkem-native-1.2.0/aarch64-native-arith+fips202-v84a"
)
_EXPECTED_NATIVE_TARGETS = (
    ("aarch64-apple-darwin", "", "Aarch64NativeSha3", "macos", "apple"),
    ("aarch64-apple-ios", "", "Aarch64Native", "ios", "apple"),
    ("aarch64-apple-ios-sim", "sim", "Aarch64NativeSha3", "ios", "apple"),
    ("aarch64-unknown-linux-gnu", "gnu", "Aarch64Native", "linux", "unknown"),
    ("aarch64-linux-android", "", "Aarch64Native", "android", "unknown"),
)
_NATIVE_TARGETS = frozenset(target for target, _, _, _, _ in _EXPECTED_NATIVE_TARGETS)
_NATIVE_SHA3_TARGETS = frozenset(
    target
    for target, _, implementation, _, _ in _EXPECTED_NATIVE_TARGETS
    if implementation == "Aarch64NativeSha3"
)
_NATIVE_TARGET_ROW = re.compile(
    r'"(?P<target>[a-z0-9_-]+)"\s*=>\s*Some\(ExpectedNativeTarget\s*\{\s*'
    r'environment:\s*"(?P<environment>[a-z]*)",\s*'
    r"implementation:\s*MlKemImplementation::"
    r"(?P<implementation>Aarch64Native|Aarch64NativeSha3),\s*"
    r'operating_system:\s*"(?P<operating_system>[a-z]+)",\s*'
    r'vendor:\s*"(?P<vendor>[a-z]+)",\s*\}\),',
    re.DOTALL,
)


def _native_implementation_id_for_target(target: str) -> str:
    """Return the audited per-target AArch64 implementation identity."""

    if target in _NATIVE_SHA3_TARGETS:
        return _AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID
    return _AARCH64_NATIVE_IMPLEMENTATION_ID
_BRIDGE_SYMBOLS = frozenset(
    f"qpn_mlkem_bridge_v1_2_0_{parameter_set}_{operation}"
    for parameter_set in ("512", "768", "1024")
    for operation in (
        "keypair_derand",
        "encapsulate_derand",
        "decapsulate",
        "check_public_key",
    )
)
_SHARED_FIPS202_SYMBOLS = frozenset(
    f"qpn_mlkem_internal_v1_2_0__{suffix}"
    for suffix in (
        "keccakf1600_extract_bytes",
        "keccakf1600_permute",
        "keccakf1600_xor_bytes",
        "keccakf1600x4_extract_bytes",
        "keccakf1600x4_permute",
        "keccakf1600x4_xor_bytes",
        "sha3_256",
        "sha3_512",
        "shake128_absorb_once",
        "shake128_init",
        "shake128_release",
        "shake128_squeezeblocks",
        "shake128x4_absorb_once",
        "shake128x4_init",
        "shake128x4_release",
        "shake128x4_squeezeblocks",
        "shake256",
        "shake256x4",
    )
)
_AARCH64_ARITH_ASSEMBLY_SYMBOLS = frozenset(
    f"qpn_mlkem_internal_v1_2_0__{suffix}"
    for suffix in (
        "intt_aarch64_asm",
        "ntt_aarch64_asm",
        "poly_mulcache_compute_aarch64_asm",
        "poly_reduce_aarch64_asm",
        "poly_tobytes_aarch64_asm",
        "poly_tomont_aarch64_asm",
        "polyvec_basemul_acc_montgomery_cached_k2_aarch64_asm",
        "polyvec_basemul_acc_montgomery_cached_k3_aarch64_asm",
        "polyvec_basemul_acc_montgomery_cached_k4_aarch64_asm",
        "rej_uniform_aarch64_asm",
    )
)
_AARCH64_ASSEMBLY_SYMBOLS = _AARCH64_ARITH_ASSEMBLY_SYMBOLS | frozenset(
    f"qpn_mlkem_internal_v1_2_0__{suffix}"
    for suffix in (
        "keccak_f1600_x1_scalar_aarch64_asm",
        "keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm",
    )
)
_AARCH64_SHA3_ASSEMBLY_SYMBOLS = _AARCH64_ARITH_ASSEMBLY_SYMBOLS | frozenset(
    f"qpn_mlkem_internal_v1_2_0__{suffix}"
    for suffix in (
        "keccak_f1600_x1_v84a_aarch64_asm",
        "keccak_f1600_x2_v84a_aarch64_asm",
    )
)


@dataclasses.dataclass(frozen=True, slots=True)
class MlKemArchiveContract:
    """Observed target-selected C archive shape from a packaged sys crate."""

    implementation: str
    implementation_id: str
    object_count: int
    symbol_count: int


def validate_packaged_mlkem_native_local_sources(source_files: set[str]) -> None:
    """Reject local package files outside the reviewed sys-crate source set."""

    missing = sorted(_EXPECTED_LOCAL_SOURCE_FILES - source_files)
    extra = sorted(source_files - _EXPECTED_LOCAL_SOURCE_FILES)
    if missing or extra:
        raise RustPublishContractError(
            "sys crate packaged local source set differs from the audited allowlist: "
            f"missing={missing} extra={extra}"
        )


def validate_packaged_mlkem_native_local_source_digests(
    source_files: Mapping[str, bytes],
) -> None:
    """Require every packaged build/local-source byte to match its audited digest."""

    actual_names = set(source_files)
    expected_names = set(_EXPECTED_LOCAL_SOURCE_SHA256)
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    malformed = sorted(
        name for name, data in source_files.items() if not isinstance(data, bytes)
    )
    if missing or extra or malformed:
        raise RustPublishContractError(
            "sys crate packaged local source digest set differs from the audited allowlist: "
            f"missing={missing} extra={extra} non_bytes={malformed}"
        )
    actual_digests = {
        name: hashlib.sha256(data).hexdigest() for name, data in source_files.items()
    }
    mismatches = {
        name: {
            "expected": _EXPECTED_LOCAL_SOURCE_SHA256[name],
            "actual": actual_digests[name],
        }
        for name in sorted(expected_names)
        if actual_digests[name] != _EXPECTED_LOCAL_SOURCE_SHA256[name]
    }
    if mismatches:
        raise RustPublishContractError(
            "packaged local source bytes differ from the audited allowlist: "
            f"{mismatches}"
        )


def _validate_c_include_graph(name: str, source: str) -> None:
    directives = _C_INCLUDE_DIRECTIVE.findall(source)
    literal_targets = tuple(
        match.group("target") for match in _C_LITERAL_INCLUDE.finditer(source)
    )
    expected_targets = _EXPECTED_C_INCLUDES[name]
    if len(directives) != len(literal_targets) or literal_targets != expected_targets:
        raise RustPublishContractError(
            "target-selected C/assembly include graph differs from the audited allowlist: "
            f"file={name} directives={len(directives)} "
            f"literal_targets={list(literal_targets)} "
            f"expected={list(expected_targets)}"
        )


def _validate_source_wrapper(name: str, source: str) -> None:
    actual_defines = tuple(
        (match.group("name"), (match.group("value") or "").strip())
        for match in _C_DEFINE_DIRECTIVE.finditer(source)
    )
    expected_defines = _EXPECTED_WRAPPER_DEFINES[name]
    if actual_defines != expected_defines:
        raise RustPublishContractError(
            "source-owned implementation wrapper differs from the audited selector: "
            f"file={name} actual={actual_defines} expected={expected_defines}"
        )
    _validate_c_include_graph(name, source)


def _extract_rust_function(source: str, function_name: str) -> str:
    signature = re.search(rf"\bfn\s+{re.escape(function_name)}\s*\(", source)
    if signature is None:
        raise RustPublishContractError(
            f"required Rust build helper is missing: {function_name}"
        )
    opening = source.find("{", signature.end())
    if opening < 0:
        raise RustPublishContractError(
            f"required Rust build helper has no body: {function_name}"
        )
    depth = 0
    for index in range(opening, len(source)):
        character = source[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise RustPublishContractError(
        f"required Rust build helper has an unterminated body: {function_name}"
    )


def _validate_target_selection(build_support: str) -> None:
    expected_target_body = _extract_rust_function(
        build_support, "expected_native_target"
    )
    actual_targets = tuple(
        (
            match.group("target"),
            match.group("environment"),
            match.group("implementation"),
            match.group("operating_system"),
            match.group("vendor"),
        )
        for match in _NATIVE_TARGET_ROW.finditer(expected_target_body)
    )
    fallback_count = len(re.findall(r"_\s*=>\s*None\s*,", expected_target_body))
    if actual_targets != _EXPECTED_NATIVE_TARGETS or fallback_count != 1:
        raise RustPublishContractError(
            "AArch64 native target allowlist must contain exactly the five audited targets "
            "with one portable fallback: "
            f"actual={actual_targets} fallback_count={fallback_count}"
        )

    selection_body = _extract_rust_function(
        build_support, "select_mlkem_implementation"
    )
    compact = re.sub(r"\s+", " ", selection_body).strip()
    fallback = (
        "let Some(expected) = expected_native_target(target) else { "
        "return Ok(MlKemImplementation::Portable); };"
    )
    expected_mismatches = (
        ('target_arch != "aarch64"', "Architecture"),
        ('target_endian != "little"', "Endianness"),
        ("target_env != expected.environment", "Environment"),
        ("target_os != expected.operating_system", "OperatingSystem"),
        ("target_vendor != expected.vendor", "Vendor"),
    )
    missing_mismatches = [
        error
        for condition, error in expected_mismatches
        if (
            f"if {condition} {{ return Err(NativeTargetMetadataError::{error}); }}"
            not in compact
        )
    ]
    if (
        fallback not in compact
        or selection_body.count("MlKemImplementation::Portable") != 1
        or selection_body.count("return Err(") != len(expected_mismatches)
        or missing_mismatches
        or compact.count("Ok(expected.implementation)") != 1
    ):
        raise RustPublishContractError(
            "native target metadata mismatches must fail closed and only non-allowlisted "
            "targets may use the portable fallback: "
            f"missing_mismatches={missing_mismatches}"
        )


def _validate_implementation_ids(build_rs: str, build_support: str) -> None:
    expected_constants = (
        (
            "PORTABLE_IMPLEMENTATION_ID",
            _PORTABLE_IMPLEMENTATION_ID,
        ),
        (
            "AARCH64_NATIVE_IMPLEMENTATION_ID",
            _AARCH64_NATIVE_IMPLEMENTATION_ID,
        ),
        (
            "AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID",
            _AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID,
        ),
    )
    missing = [
        name
        for name, value in expected_constants
        if re.search(
            rf'pub\(crate\)\s+const\s+{name}:\s*&str\s*=\s*"{re.escape(value)}"\s*;',
            build_support,
        )
        is None
    ]
    id_body = re.sub(
        r"\s+", " ", _extract_rust_function(build_support, "id")
    ).strip()
    expected_id_arms = (
        "Self::Portable => PORTABLE_IMPLEMENTATION_ID",
        "Self::Aarch64Native => AARCH64_NATIVE_IMPLEMENTATION_ID",
        "Self::Aarch64NativeSha3 => AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID",
    )
    marker = "cargo:rustc-env=QPN_MLKEM_IMPLEMENTATION_ID={}"
    if (
        missing
        or any(arm not in id_body for arm in expected_id_arms)
        or build_rs.count(marker) != 1
        or build_rs.count("implementation.id()") != 2
    ):
        raise RustPublishContractError(
            "target-selected implementation IDs differ from the audited contract: "
            f"missing_constants={missing}"
        )


def _validate_build_topology(build_rs: str, build_support: str) -> None:
    build_rust_surface = "\n".join((build_rs, build_support))
    expected_constants = {
        "NATIVE_ASSEMBLY_WRAPPER": "src/mlkem_bridge_asm.S",
        "NATIVE_C_WRAPPER": "src/mlkem_bridge_native.c",
        "PORTABLE_C_WRAPPER": "src/mlkem_bridge_portable.c",
    }
    missing_constants = [
        name
        for name, value in expected_constants.items()
        if re.search(
            rf'const\s+{name}:\s*&str\s*=\s*"{re.escape(value)}"\s*;',
            build_rs,
        )
        is None
    ]
    file_calls = len(re.findall(r"\.file\s*\(", build_rust_surface))
    files_calls = len(re.findall(r"\.files\s*\(", build_rust_surface))
    file_method_tokens = len(
        re.findall(r"\.(?:r#)?files?\b", build_rust_surface)
    )
    object_calls = len(re.findall(r"\.object\s*\(", build_rust_surface))
    objects_calls = len(re.findall(r"\.objects\s*\(", build_rust_surface))
    object_method_tokens = len(
        re.findall(r"\.(?:r#)?objects?\b", build_rust_surface)
    )
    intermediate_calls = len(
        re.findall(r"\.try_compile_intermediates\s*\(", build_rust_surface)
    )
    archive_calls = len(re.findall(r"\.try_compile\s*\(", build_rust_surface))
    archive_method_tokens = len(
        re.findall(r"\.(?:r#)?try_compile\b", build_rust_surface)
    )
    compact = re.sub(r"\s+", " ", build_rs)
    c_selection = (
        ".file(if implementation.uses_aarch64_native() { NATIVE_C_WRAPPER "
        "} else { PORTABLE_C_WRAPPER })"
    )
    required_native_shapes = (
        ".file(NATIVE_ASSEMBLY_WRAPPER)",
        "let [object] = objects.as_slice() else",
        "build.object(assembly_object);",
        '.try_compile("q_periapt_mlkem_native")',
        "same_compiler_metadata(c_compiler, &assembly_compiler)",
    )
    if (
        missing_constants
        or file_calls != 2
        or files_calls != 0
        or file_method_tokens != 2
        or object_calls != 1
        or objects_calls != 0
        or object_method_tokens != 1
        or intermediate_calls != 1
        or archive_calls != 1
        or archive_method_tokens != 1
        or c_selection not in compact
        or any(shape not in compact for shape in required_native_shapes)
    ):
        raise RustPublishContractError(
            "sys crate compilation topology must produce one selected C wrapper plus exactly "
            "one native assembly intermediate object in one archive: "
            f"missing_constants={missing_constants} file_calls={file_calls} "
            f"files_calls={files_calls} file_tokens={file_method_tokens} "
            f"object_calls={object_calls} objects_calls={objects_calls} "
            f"object_tokens={object_method_tokens} "
            f"intermediate_calls={intermediate_calls} archive_calls={archive_calls} "
            f"archive_tokens={archive_method_tokens}"
        )

    define_names = re.findall(r'\.define\(\s*"([^"]+)"', build_rust_surface)
    define_calls = len(re.findall(r"\.define\s*\(", build_rust_surface))
    define_method_tokens = len(
        re.findall(r"\.(?:r#)?define\b", build_rust_surface)
    )
    if (
        define_names != ["QPN_MLKEM_FREESTANDING"]
        or define_calls != 1
        or define_method_tokens != 1
    ):
        raise RustPublishContractError(
            "build script may define only the portable freestanding boundary; "
            "implementation selectors must remain source-owned: "
            f"defines={define_names} define_calls={define_calls} "
            f"define_tokens={define_method_tokens}"
        )


def _validate_native_compiler_contract(build_rs: str, build_support: str) -> None:
    build_march_values = re.findall(r'"(-march=[^"]*)"', build_rs)
    support_march_values = re.findall(r'"(-march=[^"]*)"', build_support)
    march_flag_body = re.sub(
        r"\s+", " ", _extract_rust_function(build_support, "aarch64_march_flag")
    ).strip()
    expected_march_arms = (
        "Self::Portable => None",
        'Self::Aarch64Native => Some("-march=armv8-a+nosha3")',
        'Self::Aarch64NativeSha3 => Some("-march=armv8.4-a+sha3")',
    )
    required_build_shapes = (
        "if let Some(march) = implementation.aarch64_march_flag() {",
        "build.inherit_rustflags(false).flag(march);",
        "if let Some(expected_march) = implementation.aarch64_march_flag() {",
        "validate_native_build_environment()?;",
        'let required_platform_define = (target_os == "android").then_some("-DANDROID");',
        "build_support::validate_native_compiler_arguments( arguments.iter().copied(), expected_march, required_platform_define, )",
    )
    compact_build = re.sub(r"\s+", " ", build_rs)
    required_guard_shapes = (
        'argument.contains("QPN_MLKEM")',
        'argument.contains("MLK_CONFIG")',
        'argument.starts_with("-D")',
        'argument.starts_with("-U")',
        'argument.starts_with("-march")',
        'argument.starts_with("-mcpu")',
        'argument.starts_with("-mtune")',
        'argument.starts_with("-mattr")',
        'argument.starts_with("-mbranch-protection")',
        'argument == "-fno-integrated-as"',
        'argument == "-no-integrated-as"',
        'argument.starts_with("-Xclang")',
        'argument.starts_with("-Xpreprocessor")',
        'argument.starts_with("-Xassembler")',
        'argument.starts_with("-mllvm")',
        "if argument == expected_march",
        "required_platform_define == Some(argument)",
        "MissingPlatformDefine",
        "DuplicatePlatformDefine",
        '"branch-protection"',
    )
    if (
        build_march_values != []
        or support_march_values
        != ["-march=armv8-a+nosha3", "-march=armv8.4-a+sha3"]
        or any(arm not in march_flag_body for arm in expected_march_arms)
        or build_rs.count("inherit_rustflags(false)") != 1
        or any(shape not in compact_build for shape in required_build_shapes)
        or any(shape not in build_support for shape in required_guard_shapes)
        or build_support.count("MissingArmv8Baseline") != 3
        or build_support.count("DuplicateArmv8Baseline") != 3
        or 'println!("cargo:rerun-if-env-changed=CRATE_CC_NO_DEFAULTS")'
        not in build_rs
        or 'env::var_os("CRATE_CC_NO_DEFAULTS")' not in build_rs
        or 'println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS")'
        not in build_rs
        or 'env::var_os("CARGO_ENCODED_RUSTFLAGS")' not in build_rs
    ):
        raise RustPublishContractError(
            "fixed AArch64 compiler flag/ambient override guard differs from the audited "
            "per-target Armv8-A/Armv8.4-A+SHA3 no-BTI contract: "
            f"build_march_values={build_march_values} "
            f"support_march_values={support_march_values}"
        )


def validate_mlkem_native_build_surface(
    *,
    build_rs: str,
    build_support: str,
    bridge_c: str,
    bridge_native_c: str,
    bridge_portable_c: str,
    bridge_asm: str,
    bridge_h: str,
    local_config: str,
    aarch64_fips202: str,
) -> None:
    """Validate the complete packaged target-selected native/portable surface.

    The semantic checks are intentionally lexical and conservative. The final
    whole-file digest allowlist closes equivalent Rust and C spellings without
    pretending that these checks are complete language parsers.
    """

    build_rust_surface = "\n".join((build_rs, build_support))
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
        f"{name}:{len(_INCLUDE_SOURCE_TOKEN.findall(rust_source))}"
        for name, rust_source in (
            ("build.rs", build_rs),
            ("src/build_support.rs", build_support),
        )
        if len(_INCLUDE_SOURCE_TOKEN.findall(rust_source))
        != _EXPECTED_INCLUDE_SOURCE_TOKEN_COUNTS[name]
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

    _validate_target_selection(build_support)
    _validate_implementation_ids(build_rs, build_support)
    _validate_build_topology(build_rs, build_support)
    _validate_native_compiler_contract(build_rs, build_support)

    for name, source in (
        ("src/mlkem_bridge.c", bridge_c),
        ("src/mlkem_bridge_native.c", bridge_native_c),
        ("src/mlkem_bridge_portable.c", bridge_portable_c),
        ("src/mlkem_bridge_asm.S", bridge_asm),
        ("src/mlkem_bridge.h", bridge_h),
        ("src/mlkem_config.h", local_config),
        ("src/mlkem_fips202_aarch64.h", aarch64_fips202),
    ):
        _validate_c_include_graph(name, source)
    for name, source in (
        ("src/mlkem_bridge_native.c", bridge_native_c),
        ("src/mlkem_bridge_portable.c", bridge_portable_c),
        ("src/mlkem_bridge_asm.S", bridge_asm),
    ):
        _validate_source_wrapper(name, source)

    config_token_counts = {
        token: local_config.count(token)
        for token in sorted(_EXPECTED_CONFIG_TOKEN_COUNTS)
    }
    error_directive_count = len(
        re.findall(r"(?m)^[ \t]*#[ \t]*error\b", local_config)
    )
    if (
        not local_config.startswith(_TARGET_SELECTED_CONFIG_PREFIX)
        or config_token_counts != _EXPECTED_CONFIG_TOKEN_COUNTS
        or error_directive_count != 8
        or '#define MLK_CONFIG_ARITH_BACKEND_FILE "native/meta.h"' not in local_config
        or (
            '#define MLK_CONFIG_FIPS202_BACKEND_FILE "mlkem_fips202_aarch64.h"'
            not in local_config
        )
        or local_config.count("#if !defined(__ARM_FEATURE_SHA3)") != 1
        or local_config.count("#if defined(__ARM_FEATURE_SHA3)") != 2
        or "fixed Armv8.4-A SHA3 FIPS 202 profile" not in local_config
        or local_config.count("fixed Armv8-A FIPS 202 profile") != 2
        or "#include <TargetConditionals.h>" not in local_config
        or "#if TARGET_OS_OSX || TARGET_OS_SIMULATOR" not in local_config
    ):
        raise RustPublishContractError(
            "target-selected config lacks its active source-selector, ambient native-macro, "
            "or per-target SHA3/BTI baseline guards: "
            f"token_counts={config_token_counts} "
            f"error_directives={error_directive_count}"
        )

    if (
        "auto.h" in aarch64_fips202
        or aarch64_fips202.count("#if defined(__ARM_FEATURE_SHA3)") != 1
        or aarch64_fips202.count("x1_v84a.h") != 1
        or aarch64_fips202.count("x2_v84a.h") != 1
        or aarch64_fips202.count("x1_scalar.h") != 1
        or aarch64_fips202.count("x4_v8a_scalar.h") != 1
        or "x4_v8a_v84a" in aarch64_fips202
    ):
        raise RustPublishContractError(
            "AArch64 FIPS 202 selector must pin exactly the fixed per-target header "
            "pairs (x1_v84a+x2_v84a under __ARM_FEATURE_SHA3, otherwise "
            "x1_scalar+x4_v8a_scalar) and must not select auto or hybrid backends"
        )

    packaged_sources = {
        "build.rs": build_rs,
        "src/build_support.rs": build_support,
        "src/mlkem_bridge.c": bridge_c,
        "src/mlkem_bridge_native.c": bridge_native_c,
        "src/mlkem_bridge_portable.c": bridge_portable_c,
        "src/mlkem_bridge_asm.S": bridge_asm,
        "src/mlkem_bridge.h": bridge_h,
        "src/mlkem_config.h": local_config,
        "src/mlkem_fips202_aarch64.h": aarch64_fips202,
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


def parse_mlkem_archive_defined_symbols(
    output: str,
    *,
    leading_underscore: bool,
) -> tuple[str, ...]:
    """Parse names-only nm output while rejecting unrecognized rows."""

    symbols: list[str] = []
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if line.endswith(":") and not any(character.isspace() for character in line):
            continue
        if re.fullmatch(r"_?[A-Za-z][A-Za-z0-9_.$@]*", line) is None:
            raise RustPublishContractError(
                "cannot parse names-only nm output for the sys archive: "
                f"line={line_number} value={raw_line!r}"
            )
        if leading_underscore:
            if not line.startswith("_"):
                raise RustPublishContractError(
                    "Mach-O external symbol lacks its required leading underscore: "
                    f"{line!r}"
                )
            line = line[1:]
        symbols.append(line)
    if not symbols:
        raise RustPublishContractError("sys archive nm output contains no defined symbols")
    return tuple(symbols)


def validate_mlkem_native_archive_contract(
    *,
    target: str,
    archive_members: Iterable[str],
    defined_symbols: Iterable[str],
    build_output: str,
) -> MlKemArchiveContract:
    """Validate the actual packaged build archive selected for one host target."""

    if re.fullmatch(r"[A-Za-z0-9_.-]+", target) is None:
        raise RustPublishContractError(f"Rust host target is malformed: {target!r}")
    native = target in _NATIVE_TARGETS
    implementation = "aarch64-native" if native else "portable"
    implementation_id = (
        _native_implementation_id_for_target(target)
        if native
        else _PORTABLE_IMPLEMENTATION_ID
    )
    expected_marker = (
        "cargo:rustc-env=QPN_MLKEM_IMPLEMENTATION_ID=" + implementation_id
    )
    actual_markers = [
        line
        for line in build_output.splitlines()
        if line.startswith("cargo:rustc-env=QPN_MLKEM_IMPLEMENTATION_ID=")
    ]
    if actual_markers != [expected_marker]:
        raise RustPublishContractError(
            "packaged sys archive implementation ID differs from its target contract: "
            f"target={target} markers={actual_markers} expected={expected_marker!r}"
        )

    raw_members = tuple(member.strip() for member in archive_members if member.strip())
    if len(raw_members) != len(set(raw_members)):
        raise RustPublishContractError("sys C archive contains duplicate members")
    metadata_members = {"/", "//", "__.SYMDEF", "__.SYMDEF SORTED"}
    object_members = tuple(
        member for member in raw_members if member not in metadata_members
    )
    expected_suffixes = (
        ("mlkem_bridge_native.o", "mlkem_bridge_asm.o")
        if native
        else ("mlkem_bridge_portable.o",)
    )
    actual_suffixes: list[str] = []
    malformed_members: list[str] = []
    for member in object_members:
        match = re.fullmatch(
            r"[0-9a-f]{16}-(mlkem_bridge_(?:native|portable|asm)\.o)", member
        )
        if match is None:
            malformed_members.append(member)
        else:
            actual_suffixes.append(match.group(1))
    if malformed_members or tuple(actual_suffixes) != expected_suffixes:
        raise RustPublishContractError(
            "sys C archive object contract differs from the selected implementation: "
            f"target={target} malformed={malformed_members} "
            f"actual={actual_suffixes} expected={list(expected_suffixes)}"
        )

    symbols = tuple(defined_symbols)
    if len(symbols) != len(set(symbols)):
        raise RustPublishContractError("sys C archive reports duplicate defined symbols")
    public_symbols = sorted(symbol for symbol in symbols if symbol.startswith("q_periapt_"))
    if public_symbols:
        raise RustPublishContractError(
            "sys C archive would expand the reserved q_periapt_ dynamic ABI namespace: "
            f"{public_symbols}"
        )
    expected_symbols = _BRIDGE_SYMBOLS | _SHARED_FIPS202_SYMBOLS
    if native:
        expected_symbols |= (
            _AARCH64_SHA3_ASSEMBLY_SYMBOLS
            if target in _NATIVE_SHA3_TARGETS
            else _AARCH64_ASSEMBLY_SYMBOLS
        )
    actual_symbols = set(symbols)
    if actual_symbols != expected_symbols:
        raise RustPublishContractError(
            "sys C archive external-symbol contract differs from the selected implementation: "
            f"target={target} missing={sorted(expected_symbols - actual_symbols)} "
            f"extra={sorted(actual_symbols - expected_symbols)}"
        )

    return MlKemArchiveContract(
        implementation=implementation,
        implementation_id=implementation_id,
        object_count=len(object_members),
        symbol_count=len(symbols),
    )


def _verify_crates_io_sparse_worker(arguments: list[str]) -> int:
    if len(arguments) != 3:
        _print_sparse_worker_failure("sparse verification worker arguments are malformed")
        return 2
    scope = arguments[0]
    lock_path = pathlib.Path(arguments[1])
    expected_sha256 = arguments[2]
    if _CHECKSUM.fullmatch(expected_sha256) is None:
        _print_sparse_worker_failure("sparse verification worker hash is malformed")
        return 2
    try:
        _local_crates_for_lock_scope(scope)
        snapshot = read_regular_snapshot(
            lock_path,
            maximum=RUST_SPARSE_LOCK_MAX_BYTES,
            label=f"{scope} Cargo.lock sparse worker input",
        )
        if snapshot.sha256 != expected_sha256:
            raise RustPublishContractError(
                "sparse verification worker input hash differs"
            )
        registry_packages = _validate_crates_io_sparse_yanked_with_fetcher(
            snapshot.data,
            fetcher=_fetch_crates_io_sparse_entry,
            scope=scope,
        )
    except (EvidenceIOError, RustPublishContractError) as exc:
        _print_sparse_worker_failure(str(exc))
        return 1
    print(
        json.dumps(
            {
                "lock_sha256": snapshot.sha256,
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
    if arguments and arguments[0] == "verify-workspace-dependency-audit":
        if arguments != ["verify-workspace-dependency-audit"]:
            print(
                "error: verify-workspace-dependency-audit accepts no arguments",
                file=sys.stderr,
            )
            return 2
        try:
            receipt = verify_workspace_dependency_audit()
        except RustPublishContractError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"{RUST_WORKSPACE_AUDIT_MARKER_PREFIX} "
            f"workspace_registry_packages={receipt.workspace_registry_packages} "
            f"fuzz_registry_packages={receipt.fuzz_registry_packages} "
            f"advisory_db_commit={receipt.advisory_db_commit} "
            f"workspace_lock_sha256={receipt.workspace_lock_sha256} "
            f"fuzz_lock_sha256={receipt.fuzz_lock_sha256} "
            "locks_stable=1 sparse_checksums=exact yanked=0 "
            "warnings=denied ambient_cargo_home_data=unused"
        )
        return 0
    print("error: unsupported Rust package contract command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
