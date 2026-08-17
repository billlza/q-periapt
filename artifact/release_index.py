#!/usr/bin/env python3
"""Build and verify a local, ABI-contract-bound Q-Periapt release index.

The index is a packaging manifest, not a public release claim or a leaf-package
attestation. Package hashes are necessary but insufficient: verification binds
the current package envelopes, aggregate boundaries, and ABI 2 semantics to the
frozen repository contract. Deep binary, consumer, BOM, and license validation
remains a required precondition owned by the named leaf gates.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import errno
import hashlib
import importlib
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterator, NoReturn

from apple_proof_contract import APPLE_MATRIX_PROOF_SCHEMA_VERSION
from android_emulator_control import (
    EMULATOR_ROUTING_MODE,
    EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
    NATIVE_ADB_NOTIFIER_MODE,
    NATIVE_ADB_NOTIFIER_PORT,
    OWNED_ADB_PROFILE_DIALECTS,
    AdbIsolationCheckpoint,
    emulator_routing_transport_binding_sha256,
)
from evidence_io import (
    EvidenceIOError,
    FileDigestSnapshot,
    JsonObjectSnapshot,
    consume_regular_snapshot,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    require_commit_ancestor,
    require_commit_or_evidence_successor,
)
from git_provenance import (
    git_commit as provenance_git_commit,
)
from git_provenance import (
    source_tree_dirty as provenance_source_tree_dirty,
)
from platform_release_contract import ANDROID_DEVICE_PROOF_SCHEMA_VERSION


@dataclass(frozen=True)
class PackageManifestContract:
    schema_version: int
    kind: str | None
    manifest_fields: frozenset[str]
    abi_fields: frozenset[str]


@dataclass(frozen=True, slots=True)
class ReleaseIndexSelection:
    """A fixed local index path and the digest authorized by its pointer."""

    path: pathlib.Path
    expected_sha256: str
    expected_generated_at: str


@dataclass(frozen=True, slots=True)
class VerifiedReleaseIndex:
    """An index value and digest read from the same regular-file snapshot."""

    path: pathlib.Path
    sha256: str
    value: dict[str, Any]


@dataclass(frozen=True, slots=True)
class BuiltReleaseTree:
    """A fully verified but not-yet-selected immutable release tree."""

    index_path: pathlib.Path
    index_sha256: str
    generated_at: str


SCHEMA_VERSION = 5
KIND = "qperiapt.local_release_index"
POINTER_KIND = "qperiapt.local_release_index.pointer"
REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
ABI_MAJOR = 2
EXPORT_COUNT = 9
EXPECTED_RUSTC_VERSION = "rustc 1.96.1 (31fca3adb 2026-06-26)"
EXPECTED_CARGO_VERSION = "cargo 1.96.1 (356927216 2026-06-26)"
EXPECTED_SWIFT_RUST_HOST = "aarch64-apple-darwin"
EXPECTED_SWIFT_VERSION = (
    "swift-driver version: 1.148.6 Apple Swift version 6.3.3 "
    "(swiftlang-6.3.3.1.3 clang-2100.1.1.101) "
    "Target: arm64-apple-macosx28.0"
)
EXPECTED_XCODE_VERSION = ("Xcode 26.6", "Build version 17F113")
SWIFT_MANIFEST_KIND = "qperiapt.swift_xcframework_manifest"
ANDROID_MANIFEST_KIND = "qperiapt.android_aar_manifest"
SWIFT_PACKAGE_TYPE = "swiftpm-binaryTarget-xcframework"
SWIFT_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
)
ANDROID_ABIS = ("arm64-v8a", "x86_64", "armeabi-v7a", "x86")
ANDROID_RELEASE_DEVICE_KIND = "emulator"
ANDROID_RELEASE_DEVICE_ABI = "arm64-v8a"
ANDROID_RELEASE_DEVICE_SDK = 35
ANDROID_RELEASE_PAGE_SIZE = 16_384
ANDROID_EMULATOR_ROUTING_MODE = EMULATOR_ROUTING_MODE
ANDROID_NATIVE_NOTIFIER_MODE = NATIVE_ADB_NOTIFIER_MODE
C_HOST_PLATFORMS = {
    "aarch64-apple-darwin": "macos",
    "x86_64-apple-darwin": "macos",
    "aarch64-unknown-linux-gnu": "linux",
    "x86_64-unknown-linux-gnu": "linux",
}
ANDROID_PACKAGE_BOUNDARY = (
    "AAR/JNI packaging proof only; Android emulator or physical-device "
    "instrumentation is required before claiming Android runtime readiness."
)
PACKAGE_MANIFEST_FIELDS = {
    "c-abi": frozenset(
        {
            "schema_version",
            "package",
            "version",
            "host",
            "generated_at",
            "source_date_epoch",
            "git_commit",
            "git_dirty",
            "diagnostic_only",
            "rustc",
            "cargo",
            "platform_compatibility",
            "abi",
            "source_inputs_sha256",
            "files",
        }
    ),
    "swift": frozenset(
        {
            "schema_version",
            "kind",
            "package",
            "version",
            "release_identity",
            "type",
            "git_commit",
            "git_dirty",
            "toolchain",
            "targets",
            "abi",
            "artifacts",
            "consumer_verification",
            "source_inputs",
            "build_path_hygiene",
            "public_release_boundary",
        }
    ),
    "android": frozenset(
        {
            "schema_version",
            "kind",
            "package",
            "version",
            "generated_at",
            "source_date_epoch",
            "git_commit",
            "git_dirty",
            "diagnostic_only",
            "source_tree_sha256",
            "package_only",
            "device_runtime_proof",
            "boundary",
            "toolchain",
            "third_party",
            "abi",
            "android",
            "artifacts",
        }
    ),
}
PACKAGE_ABI_FIELDS = {
    "c-abi": frozenset(
        {
            "major",
            "contract_path",
            "embedded_contract_path",
            "contract_sha256",
            "exports_sha256",
            "export_count",
            "platform",
            "runtime_identity",
            "shared_filename",
            "static_filename",
        }
    ),
    "swift": frozenset(
        {
            "major",
            "contract_path",
            "contract_sha256",
            "exports_sha256",
            "export_count",
            "platform",
            "runtime_identity",
            "shared_filename",
            "static_filename",
        }
    ),
    "android": frozenset(
        {
            "major",
            "contract_path",
            "contract_sha256",
            "exports_sha256",
            "export_count",
            "platform",
            "runtime_identity",
            "shared_filename",
            "static_filename",
        }
    ),
}
PACKAGE_MANIFEST_CONTRACTS = {
    "c-abi": PackageManifestContract(
        schema_version=2,
        kind=None,
        manifest_fields=PACKAGE_MANIFEST_FIELDS["c-abi"],
        abi_fields=PACKAGE_ABI_FIELDS["c-abi"],
    ),
    "swift": PackageManifestContract(
        schema_version=5,
        kind=SWIFT_MANIFEST_KIND,
        manifest_fields=PACKAGE_MANIFEST_FIELDS["swift"],
        abi_fields=PACKAGE_ABI_FIELDS["swift"],
    ),
    "android": PackageManifestContract(
        schema_version=4,
        kind=ANDROID_MANIFEST_KIND,
        manifest_fields=PACKAGE_MANIFEST_FIELDS["android"],
        abi_fields=PACKAGE_ABI_FIELDS["android"],
    ),
}
CONTRACT_RELATIVE_PATH = pathlib.PurePosixPath(
    "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
)
EXPECTED_EXPORT_NAMES = frozenset(
    {
        "q_periapt_abi_version",
        "q_periapt_version",
        "q_periapt_fixed_suite_id",
        "q_periapt_fixed_suite_id_len",
        "q_periapt_status_name",
        "q_periapt_decision_from_signed_policy",
        "q_periapt_generate_keypair",
        "q_periapt_encapsulate",
        "q_periapt_decapsulate",
    }
)
EXPECTED_FACES = frozenset(PACKAGE_MANIFEST_CONTRACTS)
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40,64}")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_CANONICAL_PATH_ASCII = MappingProxyType(
    {
        character: character
        for character in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._+/-"
    }
)
_PATH_CHARACTERS = frozenset(_CANONICAL_PATH_ASCII)
SAFE_PLATFORM = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}")
MAX_TAR_MEMBERS = 8192
MAX_TAR_METADATA_BYTES = 16 * 1024 * 1024
MAX_TAR_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TAR_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TAR_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_INDEXED_FILE_BYTES = 512 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_SHA256SUMS_ENTRIES = 8192
MAX_RELEASE_TREE_ENTRIES = 16_384
MAX_RELEASE_STAGING_PARENT_ENTRIES = 16_384
MAX_STALE_RELEASE_STAGING_TREES = 32
MAX_STALE_RELEASE_POINTER_FILES = 32
RENAME_EXCL = 0x00000004
RENAME_NOREPLACE = 0x00000001
FORBIDDEN_INDEX_TEXT = (
    "artifact/device-runs",
    ".mobileprovision",
    ".xcresult",
    "ProvisionedDevices",
    "TeamIdentifier",
    "000081",
    "emulator-",
)


@dataclass(frozen=True)
class AbiTrustRoot:
    contract_sha256: str
    exports_sha256: str
    version: str
    archive_prefix: str
    platforms: dict[str, dict[str, Any]]


@dataclass(frozen=True, slots=True)
class _SemanticVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] | None
    build: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class _ReleasePointerIdentity:
    version_text: str
    version: _SemanticVersion
    commit: str
    index_path: str
    index_sha256: str
    generated_at: str


def fail(message: str) -> NoReturn:
    raise SystemExit(f"error: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_exact_int(value: Any, expected: int, label: str) -> None:
    require(type(value) is int, f"{label} must be an integer")
    require(value == expected, f"{label} must be {expected}, got {value}")


def require_exact_object(
    value: Any, expected_fields: frozenset[str], label: str
) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(
        set(value) == expected_fields,
        f"{label} fields differ: got {sorted(value)}, expected {sorted(expected_fields)}",
    )
    return value


def require_exact_json(value: Any, expected: Any, label: str) -> None:
    require(type(value) is type(expected), f"{label} has the wrong JSON type")
    if isinstance(expected, dict):
        require(set(value) == set(expected), f"{label} fields differ")
        for key, expected_value in expected.items():
            require_exact_json(value[key], expected_value, f"{label}.{key}")
    elif isinstance(expected, (list, tuple)):
        require(len(value) == len(expected), f"{label} length differs")
        for index, expected_value in enumerate(expected):
            require_exact_json(value[index], expected_value, f"{label}[{index}]")
    else:
        require(value == expected, f"{label} differs")


def require_safe_string_list(
    value: Any, expected: tuple[str, ...], label: str
) -> list[str]:
    require(isinstance(value, list), f"{label} must be a list")
    require(
        all(
            isinstance(item, str) and SAFE_PLATFORM.fullmatch(item) is not None
            for item in value
        ),
        f"{label} contains an unsafe value",
    )
    require(len(value) == len(set(value)), f"{label} contains duplicates")
    require_exact_json(value, list(expected), label)
    return value


def require_bounded_text(value: Any, label: str, *, maximum: int = 4096) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        fail(f"{label} is not valid Unicode scalar text: {exc}")
    require(len(encoded) <= maximum, f"{label} is too large")
    require(
        all(ord(character) >= 32 and ord(character) != 127 for character in value),
        f"{label} contains a control character",
    )
    return value


def require_utc_timestamp(value: Any, label: str) -> str:
    text = require_bounded_text(value, label, maximum=64)
    require(text.endswith("Z"), f"{label} must use the UTC Z suffix")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        fail(f"{label} is not an ISO-8601 timestamp: {exc}")
    require(parsed.tzinfo == dt.timezone.utc, f"{label} is not UTC")
    return text


def require_source_timestamp(manifest: dict[str, Any], label: str) -> None:
    epoch = manifest.get("source_date_epoch")
    require(
        type(epoch) is int and 0 <= epoch <= 0xFFFFFFFF,
        f"{label} source_date_epoch must be an unsigned 32-bit integer",
    )
    expected = (
        dt.datetime.fromtimestamp(epoch, dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    require_exact_json(manifest.get("generated_at"), expected, f"{label} generated_at")


def normalized_absolute(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def read_bytes(path: pathlib.Path, *, maximum: int = MAX_TEXT_BYTES) -> bytes:
    try:
        return read_regular_snapshot(
            path, maximum=maximum, label=f"release input {path}"
        ).data
    except EvidenceIOError as exc:
        fail(str(exc))


def read_text(path: pathlib.Path, *, maximum: int = MAX_TEXT_BYTES) -> str:
    try:
        return read_bytes(path, maximum=maximum).decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"cannot decode UTF-8 text {path}: {exc}")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    require(not path.is_symlink(), f"JSON file must not be a symlink: {path}")
    try:
        return load_json_object_snapshot(path, label=f"release JSON {path}").value
    except EvidenceIOError as exc:
        fail(str(exc))


def _open_private_directory(path: pathlib.Path, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label} directory {path}: {exc}")
    try:
        metadata = os.fstat(descriptor)
        require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            f"{label} directory must be current-user-owned with mode 0700: {path}",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def protect_private_directory(path: pathlib.Path, label: str) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    primary: BaseException | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        require(
            stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid(),
            f"{label} directory is not current-user-owned: {path}",
        )
        os.fchmod(descriptor, 0o700)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        primary = SystemExit(f"error: cannot protect {label} directory {path}: {exc}")
        raise primary from exc
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                if primary is not None:
                    primary.add_note(
                        f"closing the protected directory also failed: {cleanup_error}"
                    )
                elif isinstance(cleanup_error, Exception):
                    fail(f"cannot close {label} directory {path}: {cleanup_error}")
                else:
                    raise
    require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        f"{label} directory is not private: {path}",
    )


def ensure_private_directory(path: pathlib.Path, base: pathlib.Path) -> None:
    require_under(path, base, "private release directory")
    current = normalized_absolute(base)
    for component in normalized_absolute(path).relative_to(current).parts:
        current /= component
        try:
            current.mkdir(mode=0o700, exist_ok=True)
            os.chmod(current, 0o700)
            metadata = current.lstat()
        except OSError as exc:
            fail(f"cannot create private release directory {current}: {exc}")
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            f"release directory is not private: {current}",
        )


@contextlib.contextmanager
def release_emit_lock(target: pathlib.Path) -> Iterator[None]:
    """Serialize local-index emitters without leaving a stale process lock."""

    require(
        os.name == "posix",
        "local release-index emission requires POSIX advisory locks",
    )
    try:
        flock_module = importlib.import_module("fcntl")
    except ImportError as exc:
        fail(f"local release-index emission cannot load POSIX advisory locks: {exc}")

    release_base = target / "qperiapt-local-release"
    ensure_private_directory(release_base, target)
    directory_fd = _open_private_directory(release_base, "release store")
    lock_fd = -1
    primary: BaseException | None = None
    try:
        lock_fd = os.open(
            ".emit.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(lock_fd, 0o600)
        metadata = os.fstat(lock_fd)
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            "release emitter lock must be one current-user private regular file",
        )
        try:
            flock_module.flock(
                lock_fd,
                flock_module.LOCK_EX | flock_module.LOCK_NB,
            )
        except BlockingIOError:
            fail("another local release-index emitter is already running")
        yield
    except BaseException as exc:
        primary = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if lock_fd >= 0:
            try:
                flock_module.flock(lock_fd, flock_module.LOCK_UN)
            except BaseException as exc:
                cleanup_errors.append(exc)
            try:
                os.close(lock_fd)
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            os.close(directory_fd)
        except BaseException as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            if primary is not None:
                for cleanup_error in cleanup_errors:
                    primary.add_note(
                        f"release emitter lock cleanup failed: {cleanup_error}"
                    )
            else:
                fail(
                    f"cannot release the local-index emitter lock: {cleanup_errors[0]}"
                )


def remove_unpublished_release_tree(
    release_root: pathlib.Path,
    target: pathlib.Path,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    """Remove only this emitter's unselected private tree after a failed build."""

    require_strictly_under(
        release_root,
        target / "qperiapt-local-release",
        "unpublished release tree",
    )
    try:
        metadata = release_root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        fail(f"cannot inspect unpublished release tree {release_root}: {exc}")
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        f"unpublished release tree is not one owned private directory: {release_root}",
    )
    if expected_identity is not None:
        require(
            (metadata.st_dev, metadata.st_ino) == expected_identity,
            "refusing to remove an unpublished release tree whose identity changed: "
            f"{release_root}",
        )
    try:
        shutil.rmtree(release_root)
    except OSError as exc:
        fail(f"cannot remove unpublished release tree {release_root}: {exc}")
    require(
        not release_root.exists() and not release_root.is_symlink(),
        f"unpublished release tree survived cleanup: {release_root}",
    )


def create_release_staging_tree(
    release_root: pathlib.Path,
    target: pathlib.Path,
) -> tuple[pathlib.Path, tuple[int, int]]:
    """Create a private run-owned sibling that cannot poison the final identity."""

    ensure_private_directory(release_root.parent, target)
    staging_root = release_root.parent / (
        f".{release_root.name}.staging-{secrets.token_hex(16)}"
    )
    require_strictly_under(
        staging_root,
        target / "qperiapt-local-release",
        "release staging tree",
    )
    try:
        staging_root.mkdir(mode=0o700, exist_ok=False)
        metadata = staging_root.lstat()
    except OSError as exc:
        fail(f"cannot create private release staging tree {staging_root}: {exc}")
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        f"release staging tree is not one owned private directory: {staging_root}",
    )
    return staging_root, (metadata.st_dev, metadata.st_ino)


def cleanup_stale_release_staging_trees(
    release_root: pathlib.Path,
    target: pathlib.Path,
) -> None:
    """Recover private staging trees left by a terminated previous emitter."""

    ensure_private_directory(release_root.parent, target)
    prefix = f".{release_root.name}.staging-"
    directory_fd = _open_private_directory(
        release_root.parent,
        "release staging parent",
    )
    primary: BaseException | None = None
    try:
        try:
            entries = os.scandir(directory_fd)
        except OSError as exc:
            fail(
                f"cannot enumerate release staging parent {release_root.parent}: {exc}"
            )
        with entries:
            parent_entry_count = 0
            stale_entries: list[tuple[str, tuple[int, int]]] = []
            for entry in entries:
                parent_entry_count += 1
                require(
                    parent_entry_count <= MAX_RELEASE_STAGING_PARENT_ENTRIES,
                    "release staging parent exceeds its entry limit",
                )
                name = entry.name
                if not name.startswith(prefix):
                    continue
                require(
                    len(stale_entries) < MAX_STALE_RELEASE_STAGING_TREES,
                    "release staging parent has too many stale staging trees",
                )
                suffix = name[len(prefix) :]
                require(
                    len(suffix) == 32
                    and all(character in "0123456789abcdef" for character in suffix),
                    f"release staging entry has an invalid owned name: {name}",
                )
                try:
                    metadata = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    fail(f"cannot inspect stale release staging tree {name}: {exc}")
                require(
                    stat.S_ISDIR(metadata.st_mode)
                    and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o700,
                    f"stale release staging entry is not one owned private directory: {name}",
                )
                stale_entries.append((name, (metadata.st_dev, metadata.st_ino)))
        validated_stale_roots: list[tuple[pathlib.Path, tuple[int, int]]] = []
        for name, identity in stale_entries:
            stale_root = release_root.parent / name
            bounded_release_files(stale_root)
            validated_stale_roots.append((stale_root, identity))
        for stale_root, identity in validated_stale_roots:
            remove_unpublished_release_tree(
                stale_root,
                target,
                expected_identity=identity,
            )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(directory_fd)
        except BaseException as cleanup_error:
            if primary is not None:
                primary.add_note(
                    f"closing the release staging parent also failed: {cleanup_error}"
                )
            elif isinstance(cleanup_error, Exception):
                fail(
                    "cannot close release staging parent "
                    f"{release_root.parent}: {cleanup_error}"
                )
            else:
                raise


def _rename_release_tree_noreplace(
    directory_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Publish one sibling directory with the host's atomic no-replace API."""

    for name, label in (
        (source_name, "release staging basename"),
        (destination_name, "release destination basename"),
    ):
        require(
            isinstance(name, str)
            and 0 < len(os.fsencode(name)) <= 255
            and name not in {".", ".."}
            and "/" not in name
            and "\\" not in name
            and "\x00" not in name,
            f"{label} is invalid",
        )
    try:
        library = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        fail(f"cannot load the native no-replace rename API: {exc}")

    if sys.platform == "darwin":
        symbol_name = "renameatx_np"
        flags = RENAME_EXCL
    elif sys.platform.startswith("linux"):
        symbol_name = "renameat2"
        flags = RENAME_NOREPLACE
    else:
        fail(
            "immutable release publication is unsupported on this platform; "
            "a native atomic no-replace rename is required"
        )

    try:
        rename = getattr(library, symbol_name)
    except AttributeError:
        fail(
            f"immutable release publication cannot load {symbol_name}; "
            "native atomic no-replace rename is required"
        )
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename(
        directory_fd,
        os.fsencode(source_name),
        directory_fd,
        os.fsencode(destination_name),
        flags,
    )
    if result == 0:
        return
    observed_errno = ctypes.get_errno()
    if observed_errno == errno.EEXIST:
        fail(
            f"release index output is immutable and already exists: {destination_name}"
        )
    unsupported_errors = {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    if observed_errno in unsupported_errors:
        fail(
            f"{symbol_name} does not provide atomic no-replace publication on "
            f"this host/filesystem: {os.strerror(observed_errno)} "
            f"(errno {observed_errno})"
        )
    if observed_errno == 0:
        fail(f"{symbol_name} failed without reporting errno")
    fail(
        f"cannot publish immutable release tree with {symbol_name}: "
        f"{os.strerror(observed_errno)} (errno {observed_errno})"
    )


def publish_release_staging_tree(
    staging_root: pathlib.Path,
    release_root: pathlib.Path,
    expected_identity: tuple[int, int],
) -> None:
    """Atomically move one verified private staging tree to its immutable identity."""

    require(
        staging_root.parent == release_root.parent,
        "release staging and final trees must share one parent",
    )
    parent = release_root.parent
    protect_private_directory(parent, "release publication parent")
    directory_fd = _open_private_directory(parent, "release publication parent")
    primary: BaseException | None = None
    try:
        try:
            staging_metadata = os.stat(
                staging_root.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            fail(f"cannot inspect release staging tree {staging_root}: {exc}")
        require(
            stat.S_ISDIR(staging_metadata.st_mode)
            and staging_metadata.st_uid == os.geteuid()
            and stat.S_IMODE(staging_metadata.st_mode) == 0o700
            and (staging_metadata.st_dev, staging_metadata.st_ino) == expected_identity,
            f"release staging tree identity changed before publication: {staging_root}",
        )
        try:
            os.stat(
                release_root.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            fail(f"cannot inspect immutable release destination {release_root}: {exc}")
        else:
            fail(
                f"release index output is immutable and already exists: {release_root}"
            )
        try:
            _rename_release_tree_noreplace(
                directory_fd,
                staging_root.name,
                release_root.name,
            )
            os.fsync(directory_fd)
        except OSError as exc:
            fail(f"cannot publish immutable release tree {release_root}: {exc}")
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(directory_fd)
        except BaseException as cleanup_error:
            if primary is not None:
                primary.add_note(
                    "closing the release publication parent also failed: "
                    f"{cleanup_error}"
                )
            elif isinstance(cleanup_error, Exception):
                fail(
                    "cannot close the release publication parent "
                    f"{parent}: {cleanup_error}"
                )
            else:
                raise


@contextlib.contextmanager
def defer_termination_signals() -> Iterator[None]:
    """Defer termination only across a short publication linearization window."""

    managed_signals = tuple(
        getattr(signal, name)
        for name in ("SIGHUP", "SIGINT", "SIGTERM")
        if hasattr(signal, name)
    )
    if not managed_signals or not hasattr(signal, "pthread_sigmask"):
        yield
        return
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


@contextlib.contextmanager
def _release_pointer_lock(pointer_path: pathlib.Path) -> Iterator[None]:
    """Serialize pointer comparison and replacement without stale lock state."""

    protect_private_directory(pointer_path.parent, "release pointer")
    lock_path = pointer_path.with_name(f".{pointer_path.name}.lock")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        fail(f"cannot open release pointer lock {lock_path}: {exc}")
    locked = False
    primary: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            f"release pointer lock is not one owned mode-0600 file: {lock_path}",
        )
        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                fail(f"another release pointer transaction is active: {exc}")
        elif os.name == "nt":
            import msvcrt

            if metadata.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                fail(f"another release pointer transaction is active: {exc}")
        else:
            fail(f"release pointer locking is unsupported on {os.name!r}")
        locked = True
        yield
    except BaseException as exc:
        primary = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if locked:
            try:
                if os.name == "posix":
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                elif os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            os.close(descriptor)
        except BaseException as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            if primary is not None:
                for cleanup_error in cleanup_errors:
                    primary.add_note(
                        f"release pointer lock cleanup failed: {cleanup_error}"
                    )
            else:
                fail(f"cannot release pointer lock: {cleanup_errors[0]}")


def _existing_release_pointer(pointer_path: pathlib.Path) -> dict[str, Any] | None:
    try:
        pointer_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        fail(f"cannot inspect existing release pointer {pointer_path}: {exc}")
    return load_json(pointer_path)


def _validate_pointer_replacement(
    *,
    root: pathlib.Path,
    pointer_path: pathlib.Path,
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> None:
    if pointer_path.name == "latest-release.json":
        validate_release_pointer_transition(previous, current, root=root)
    elif pointer_path.name != "latest-diagnostic.json":
        fail("release pointer has an unknown fixed leaf")


def _verify_published_pointer(
    pointer_path: pathlib.Path, expected: dict[str, Any]
) -> None:
    actual = load_json(pointer_path)
    require_exact_json(actual, expected, "published release pointer")


def publish_release_transaction(
    *,
    staging_root: pathlib.Path,
    release_root: pathlib.Path,
    staging_identity: tuple[int, int],
    target: pathlib.Path,
    pointer_path: pathlib.Path,
    pointer: dict[str, Any],
) -> None:
    """Publish the verified tree and pointer or roll back before signals resume."""

    pointer_published = False

    def mark_pointer_published() -> None:
        nonlocal pointer_published
        pointer_published = True

    with _release_pointer_lock(pointer_path), defer_termination_signals():
        previous = _existing_release_pointer(pointer_path)
        _validate_pointer_replacement(
            root=target.parent,
            pointer_path=pointer_path,
            previous=previous,
            current=pointer,
        )
        try:
            publish_release_staging_tree(
                staging_root,
                release_root,
                staging_identity,
            )
            write_json(
                pointer_path,
                pointer,
                on_commit=mark_pointer_published,
            )
            _verify_published_pointer(pointer_path, pointer)
        except BaseException as primary:
            if not pointer_published:
                for unpublished_tree in (release_root, staging_root):
                    try:
                        remove_unpublished_release_tree(
                            unpublished_tree,
                            target,
                            expected_identity=staging_identity,
                        )
                    except BaseException as cleanup_error:
                        primary.add_note(
                            "unpublished release tree cleanup also failed for "
                            f"{unpublished_tree}: {cleanup_error}"
                        )
            raise


def write_private_bytes(
    path: pathlib.Path,
    data: bytes,
    *,
    on_commit: Callable[[], None] | None = None,
) -> None:
    require(type(data) is bytes, "private release output must be bytes")
    protect_private_directory(path.parent, "release output")
    directory_fd = _open_private_directory(path.parent, "release output")
    temporary_name = f".{path.name}.private-{secrets.token_hex(16)}"
    temporary_fd = -1
    replaced = False
    primary: BaseException | None = None
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            fail(f"cannot inspect private release output {path}: {exc}")
        if existing is not None:
            require(
                stat.S_ISREG(existing.st_mode)
                and existing.st_uid == os.geteuid()
                and existing.st_nlink == 1,
                f"existing release output is not one current-user regular file: {path}",
            )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        temporary_fd = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(temporary_fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(temporary_fd, view)
            require(written > 0, f"short write for private release output: {path}")
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        with defer_termination_signals():
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            replaced = True
            if on_commit is not None:
                on_commit()
        os.fsync(directory_fd)
    except BaseException as exc:
        primary = exc
        if isinstance(exc, SystemExit):
            raise
        if isinstance(exc, OSError):
            fail(f"cannot write private release output {path}: {exc}")
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if not replaced:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            os.close(directory_fd)
        except BaseException as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            if primary is not None:
                for cleanup_error in cleanup_errors:
                    primary.add_note(
                        f"private release output cleanup failed: {cleanup_error}"
                    )
            else:
                fail(f"cannot clean private release output {path}: {cleanup_errors[0]}")


def write_json(
    path: pathlib.Path,
    value: dict[str, Any],
    *,
    on_commit: Callable[[], None] | None = None,
) -> None:
    write_private_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        on_commit=on_commit,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_regular_file(
    path: pathlib.Path,
    *,
    maximum: int = MAX_INDEXED_FILE_BYTES,
    label: str = "hash input",
) -> FileDigestSnapshot:
    try:
        return consume_regular_snapshot(
            path,
            maximum=maximum,
            label=label,
        )
    except EvidenceIOError as exc:
        fail(str(exc))


def sha256_file(path: pathlib.Path, *, maximum: int = MAX_INDEXED_FILE_BYTES) -> str:
    return digest_regular_file(path, maximum=maximum).sha256


def exports_sha256(names: set[str] | frozenset[str]) -> str:
    canonical = "\n".join(sorted(names)) + "\n"
    return sha256_bytes(canonical.encode("utf-8"))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def run_line(args: list[str], *, cwd: pathlib.Path | None = None) -> str:
    try:
        return subprocess.check_output(
            args, cwd=cwd, text=True, stderr=subprocess.STDOUT
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot run {' '.join(args)}: {exc}")


def git_commit(root: pathlib.Path) -> str:
    try:
        return provenance_git_commit(root)
    except GitProvenanceError as exc:
        fail(f"cannot inspect git commit: {exc}")


def git_dirty(root: pathlib.Path) -> bool:
    try:
        return provenance_source_tree_dirty(root)
    except GitProvenanceError as exc:
        fail(f"cannot inspect git worktree: {exc}")


def cargo_version(root: pathlib.Path) -> str:
    raw = run_line(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
        cwd=root,
    )
    try:
        data = parse_strict_json_bytes(raw.encode("utf-8"), label="cargo metadata")
    except EvidenceIOError as exc:
        fail(f"cannot parse cargo metadata: {exc}")
    require(isinstance(data, dict), "cargo metadata root is not an object")
    packages = data.get("packages")
    require(isinstance(packages, list), "cargo metadata packages are malformed")
    for package in packages:
        if isinstance(package, dict) and package.get("name") == "q-periapt-ffi":
            version = package.get("version")
            require(
                isinstance(version, str) and version,
                "q-periapt-ffi version is malformed",
            )
            return version
    fail("q-periapt-ffi package not found in cargo metadata")


def rust_host() -> str:
    for line in run_line(["rustc", "-vV"]).splitlines():
        if line.startswith("host: "):
            return line.split(": ", 1)[1]
    fail("cannot determine rustc host triple")


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    candidate = normalized_absolute(path)
    parent = normalized_absolute(base)
    try:
        candidate.relative_to(parent)
    except ValueError:
        fail(f"{label} must be under {parent}: {candidate}")


def require_strictly_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    candidate = normalized_absolute(path)
    parent = normalized_absolute(base)
    require_under(candidate, parent, label)
    require(
        candidate != parent, f"{label} must be a dedicated subdirectory of {parent}"
    )


def require_no_symlink_components(
    path: pathlib.Path, base: pathlib.Path, label: str
) -> None:
    candidate = normalized_absolute(path)
    parent = normalized_absolute(base)
    require_under(candidate, parent, label)
    current = parent
    require(not current.is_symlink(), f"{label} base must not be a symlink: {current}")
    for component in candidate.relative_to(parent).parts:
        current /= component
        require(
            not current.is_symlink(), f"{label} must not traverse a symlink: {current}"
        )


def canonical_path_text(value: Any, label: str, *, maximum: int = 4096) -> str:
    require(
        isinstance(value, str) and 0 < len(value) <= maximum,
        f"{label} must be a bounded non-empty string",
    )
    rebuilt: list[str] = []
    for character in value:
        canonical = _CANONICAL_PATH_ASCII.get(character)
        require(
            canonical is not None and canonical in _PATH_CHARACTERS,
            f"{label} contains an unsupported character",
        )
        rebuilt.append(canonical)
    return "".join(rebuilt)


def require_relative_safe(path: Any, label: str) -> str:
    canonical = canonical_path_text(path, label)
    require(
        not canonical.startswith(("/", "\\")),
        f"{label} must be relative: {canonical}",
    )
    require("\\" not in canonical, f"{label} must use POSIX separators: {canonical}")
    pure = pathlib.PurePosixPath(canonical)
    require(
        all(part not in {"", ".", ".."} for part in pure.parts),
        f"{label} contains an unsafe component: {canonical}",
    )
    require(
        pure.as_posix() == canonical,
        f"{label} is not canonically spelled: {canonical}",
    )
    return canonical


def require_safe_basename(value: Any, label: str) -> str:
    canonical = canonical_path_text(value, label, maximum=128)
    require(
        "/" not in canonical and "\\" not in canonical, f"{label} must be a basename"
    )
    require(canonical not in {".", ".."}, f"{label} must be a safe basename")
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", canonical) is not None,
        f"{label} contains unsupported characters",
    )
    return canonical


def require_release_channel(value: str) -> str:
    if value == "release":
        return "release"
    if value == "diagnostic":
        return "diagnostic"
    fail("release channel is invalid")


def _parse_semantic_version(value: object, label: str) -> _SemanticVersion:
    text = require_bounded_text(value, label, maximum=128)
    match = SEMVER.fullmatch(text)
    require(match is not None, f"{label} is not canonical SemVer")
    prerelease_text = match.group(4)
    build_text = match.group(5)
    prerelease = (
        tuple(prerelease_text.split("."))
        if prerelease_text is not None
        else None
    )
    build = tuple(build_text.split(".")) if build_text is not None else None
    if prerelease is not None:
        require(
            all(
                not (identifier.isdigit() and len(identifier) > 1 and identifier[0] == "0")
                for identifier in prerelease
            ),
            f"{label} has a zero-padded numeric prerelease identifier",
        )
    return _SemanticVersion(
        major=int(match.group(1)),
        minor=int(match.group(2)),
        patch=int(match.group(3)),
        prerelease=prerelease,
        build=build,
    )


def _compare_semantic_precedence(
    left: _SemanticVersion, right: _SemanticVersion
) -> int:
    left_core = (left.major, left.minor, left.patch)
    right_core = (right.major, right.minor, right.patch)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    if left.prerelease is None:
        return 0 if right.prerelease is None else 1
    if right.prerelease is None:
        return -1
    for left_identifier, right_identifier in zip(
        left.prerelease, right.prerelease, strict=False
    ):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdigit()
        right_numeric = right_identifier.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_identifier) < int(right_identifier) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_identifier < right_identifier else 1
    if len(left.prerelease) == len(right.prerelease):
        return 0
    return -1 if len(left.prerelease) < len(right.prerelease) else 1


def _release_pointer_identity(
    pointer: dict[str, Any], *, label: str
) -> _ReleasePointerIdentity:
    value = require_exact_object(
        pointer,
        frozenset(
            {
                "schema_version",
                "kind",
                "version",
                "channel",
                "diagnostic_only",
                "index_path",
                "index_sha256",
                "generated_at",
            }
        ),
        label,
    )
    require_exact_int(value.get("schema_version"), SCHEMA_VERSION, f"{label} schema")
    require(value.get("kind") == POINTER_KIND, f"{label} kind mismatch")
    require(value.get("channel") == "release", f"{label} channel mismatch")
    require_exact_json(value.get("diagnostic_only"), False, f"{label} diagnostic_only")
    version_text = require_safe_basename(value.get("version"), f"{label} version")
    version = _parse_semantic_version(version_text, f"{label} version")
    index_sha256 = value.get("index_sha256")
    require(
        isinstance(index_sha256, str)
        and HEX_SHA256.fullmatch(index_sha256) is not None,
        f"{label} index digest is malformed",
    )
    generated_at = require_utc_timestamp(value.get("generated_at"), f"{label} generated_at")
    relative = require_relative_safe(value.get("index_path"), f"{label} index_path")
    parts = pathlib.PurePosixPath(relative).parts
    require(len(parts) == 5, f"{label} index_path component count differs")
    commit = require_safe_basename(parts[3], f"{label} commit")
    require(GIT_COMMIT.fullmatch(commit) is not None, f"{label} commit is malformed")
    expected_path = pathlib.PurePosixPath(
        "qperiapt-local-release",
        "release",
        version_text,
        commit,
        "index.json",
    ).as_posix()
    require(relative == expected_path, f"{label} index_path identity mismatch")
    return _ReleasePointerIdentity(
        version_text=version_text,
        version=version,
        commit=commit,
        index_path=relative,
        index_sha256=index_sha256,
        generated_at=generated_at,
    )


def validate_release_pointer_transition(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
    *,
    root: pathlib.Path,
) -> None:
    """Require a monotonic stable release-pointer transition."""

    current_identity = _release_pointer_identity(
        current, label="current release pointer"
    )
    require(
        current_identity.version.prerelease is None
        and current_identity.version.build is None,
        "current release pointer must select a stable SemVer without build metadata",
    )
    if previous is None:
        return
    previous_identity = _release_pointer_identity(
        previous, label="previous release pointer"
    )
    precedence = _compare_semantic_precedence(
        previous_identity.version, current_identity.version
    )
    if precedence == 0:
        require(
            previous == current,
            "same-version release pointer update is not byte-equivalent idempotence",
        )
        return
    require(precedence < 0, "release pointer version would move backwards")
    previous_time = dt.datetime.fromisoformat(
        previous_identity.generated_at[:-1] + "+00:00"
    )
    current_time = dt.datetime.fromisoformat(
        current_identity.generated_at[:-1] + "+00:00"
    )
    require(
        current_time > previous_time,
        "release pointer generated_at did not move forwards",
    )
    try:
        require_commit_ancestor(
            root,
            previous_identity.commit,
            current_identity.commit,
        )
    except GitProvenanceError as exc:
        fail(f"release pointer commit lineage differs: {exc}")


def release_pointer_selection(
    root: pathlib.Path, channel: str
) -> ReleaseIndexSelection:
    channel = require_release_channel(channel)
    target = normalized_absolute(root / "target")
    release_base = target / "qperiapt-local-release"
    pointer_name = (
        "latest-release.json" if channel == "release" else "latest-diagnostic.json"
    )
    pointer_path = release_base / pointer_name
    require_no_symlink_components(pointer_path, target, "release pointer")
    pointer = require_exact_object(
        load_json(pointer_path),
        frozenset(
            {
                "schema_version",
                "kind",
                "version",
                "channel",
                "diagnostic_only",
                "index_path",
                "index_sha256",
                "generated_at",
            }
        ),
        "release pointer",
    )
    require_exact_int(
        pointer.get("schema_version"), SCHEMA_VERSION, "release pointer schema"
    )
    require(pointer.get("kind") == POINTER_KIND, "release pointer kind mismatch")
    require(pointer.get("channel") == channel, "release pointer channel mismatch")
    require_exact_json(
        pointer.get("diagnostic_only"),
        channel == "diagnostic",
        "release pointer diagnostic_only",
    )
    pointer_generated_at = require_utc_timestamp(
        pointer.get("generated_at"),
        "release pointer generated_at",
    )
    pointer_version = require_safe_basename(
        pointer.get("version"), "release pointer version"
    )
    rel = pointer.get("index_path")
    expected = pointer.get("index_sha256")
    require(
        isinstance(expected, str) and HEX_SHA256.fullmatch(expected) is not None,
        "release pointer lacks a valid index_sha256",
    )
    rel = require_relative_safe(rel, "release pointer index_path")
    rel_parts = pathlib.PurePosixPath(rel).parts
    require(
        len(rel_parts) == 5,
        "release pointer index_path has the wrong component count",
    )
    pointer_commit = require_safe_basename(rel_parts[3], "release pointer commit")
    require(
        GIT_COMMIT.fullmatch(pointer_commit) is not None,
        "release pointer commit is malformed",
    )
    expected_rel = pathlib.PurePosixPath(
        "qperiapt-local-release",
        channel,
        pointer_version,
        pointer_commit,
        "index.json",
    ).as_posix()
    require(rel == expected_rel, "release pointer index_path identity mismatch")
    index_path = normalized_absolute(target / pathlib.PurePosixPath(rel))
    require_strictly_under(
        index_path,
        release_base / channel,
        "release pointer index",
    )
    require_no_symlink_components(index_path, target, "release pointer index")
    return ReleaseIndexSelection(
        path=index_path,
        expected_sha256=expected,
        expected_generated_at=pointer_generated_at,
    )


def release_output_identity(
    root: pathlib.Path,
    *,
    channel: str,
    version: str,
    commit: str,
) -> pathlib.Path:
    channel = require_release_channel(channel)
    version = require_safe_basename(version, "release version")
    commit = require_safe_basename(commit, "release commit")
    require(GIT_COMMIT.fullmatch(commit) is not None, "release commit is malformed")
    target = normalized_absolute(root / "target")
    release_base = target / "qperiapt-local-release"
    channel_base = release_base / channel
    output = normalized_absolute(channel_base / version / commit)
    require_strictly_under(output, channel_base, "release index output")
    require_no_symlink_components(output, target, "release index output")
    return output


def resolve_release_output(
    root: pathlib.Path,
    *,
    channel: str,
    version: str,
    commit: str,
) -> pathlib.Path:
    output = release_output_identity(
        root,
        channel=channel,
        version=version,
        commit=commit,
    )
    require(
        not output.exists() and not output.is_symlink(),
        f"release index output is immutable and already exists: {output}",
    )
    return output


def require_disjoint_output(output: pathlib.Path, inputs: list[pathlib.Path]) -> None:
    output_abs = normalized_absolute(output)
    for source in inputs:
        source_abs = normalized_absolute(source)
        overlap = False
        try:
            output_abs.relative_to(source_abs)
            overlap = True
        except ValueError:
            pass
        try:
            source_abs.relative_to(output_abs)
            overlap = True
        except ValueError:
            pass
        require(
            not overlap,
            f"release index output overlaps input package path: {source_abs}",
        )


def load_abi_trust_root(root: pathlib.Path) -> AbiTrustRoot:
    contract_path = root / pathlib.Path(CONTRACT_RELATIVE_PATH)
    require_no_symlink_components(contract_path, root, "ABI contract")
    contract = load_json(contract_path)
    require_exact_int(contract.get("schema"), 1, "ABI contract schema")
    require(
        contract.get("kind") == "qperiapt.c_abi_contract", "ABI contract kind mismatch"
    )
    abi = contract.get("abi")
    require(isinstance(abi, dict), "ABI contract abi object is missing")
    require_exact_int(abi.get("major"), ABI_MAJOR, "ABI contract major")
    exports = abi.get("exports")
    require(isinstance(exports, list), "ABI contract exports are malformed")
    names: set[str] = set()
    for entry in exports:
        require(isinstance(entry, dict), "ABI contract export entry is malformed")
        name = entry.get("name")
        require(isinstance(name, str) and name, "ABI contract export name is malformed")
        require(name not in names, f"ABI contract contains duplicate export: {name}")
        names.add(name)
    require(
        names == EXPECTED_EXPORT_NAMES, "ABI contract exact 9-export allowlist mismatch"
    )
    package = contract.get("package")
    require(isinstance(package, dict), "ABI contract package object is missing")
    version = require_safe_basename(package.get("semver"), "ABI package semver")
    archive_prefix = require_safe_basename(
        package.get("archive_prefix"), "ABI archive prefix"
    )
    platforms = package.get("platforms")
    require(
        isinstance(platforms, dict) and platforms,
        "ABI contract platforms are malformed",
    )
    normalized_platforms: dict[str, dict[str, Any]] = {}
    for platform, identity in platforms.items():
        require(
            isinstance(platform, str) and SAFE_PLATFORM.fullmatch(platform) is not None,
            f"ABI contract platform is malformed: {platform}",
        )
        require(
            isinstance(identity, dict) and identity,
            f"ABI contract identity is malformed for {platform}",
        )
        normalized_platforms[platform] = identity
    return AbiTrustRoot(
        contract_sha256=sha256_file(contract_path),
        exports_sha256=exports_sha256(names),
        version=version,
        archive_prefix=archive_prefix,
        platforms=normalized_platforms,
    )


def copy_to_release(
    src: pathlib.Path,
    source_base: pathlib.Path,
    release_root: pathlib.Path,
    rel: str,
) -> dict[str, Any]:
    rel = require_relative_safe(rel, "release artifact path")
    require_no_symlink_components(src, source_base, "release artifact source")
    require(src.is_file(), f"release artifact source missing: {src}")
    dst = release_root / pathlib.Path(rel)
    require_no_symlink_components(dst, release_root, "release artifact output")
    protect_private_directory(release_root, "release artifact root")
    ensure_private_directory(dst.parent, release_root)
    output_directory_fd = _open_private_directory(dst.parent, "release artifact")
    output_descriptor = -1
    destination_created = False
    source_snapshot: FileDigestSnapshot | None = None
    try:
        output_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        output_descriptor = os.open(
            dst.name,
            output_flags,
            0o600,
            dir_fd=output_directory_fd,
        )
        destination_created = True
        os.fchmod(output_descriptor, 0o600)

        def write_chunk(chunk: bytes) -> None:
            view = memoryview(chunk)
            while view:
                written = os.write(output_descriptor, view)
                require(
                    written > 0,
                    f"short write while copying release artifact: {dst}",
                )
                view = view[written:]

        source_snapshot = consume_regular_snapshot(
            src,
            maximum=MAX_INDEXED_FILE_BYTES,
            label="release artifact source",
            consume=write_chunk,
        )
        output_metadata = os.fstat(output_descriptor)
        require(
            stat.S_ISREG(output_metadata.st_mode)
            and output_metadata.st_uid == os.geteuid()
            and output_metadata.st_nlink == 1
            and stat.S_IMODE(output_metadata.st_mode) == 0o600
            and output_metadata.st_size == source_snapshot.size,
            f"release artifact output identity is invalid: {dst}",
        )
        os.fsync(output_descriptor)
        os.close(output_descriptor)
        output_descriptor = -1
        os.fsync(output_directory_fd)
    except BaseException as exc:
        if output_descriptor >= 0:
            try:
                os.close(output_descriptor)
            except OSError as cleanup_error:
                exc.add_note(
                    f"cannot close incomplete release copy {dst}: {cleanup_error}"
                )
        if destination_created:
            try:
                os.unlink(dst.name, dir_fd=output_directory_fd)
            except OSError as cleanup_error:
                exc.add_note(
                    f"cannot remove incomplete release copy {dst}: {cleanup_error}"
                )
        if isinstance(exc, SystemExit):
            raise
        if isinstance(exc, EvidenceIOError):
            fail(f"cannot copy release artifact {src} to {dst}: {exc}")
        if isinstance(exc, OSError):
            fail(f"cannot copy release artifact {src} to {dst}: {exc}")
        raise
    finally:
        os.close(output_directory_fd)
    require(
        source_snapshot is not None, "release artifact copy lacked a source snapshot"
    )
    return {
        "path": rel,
        "sha256": source_snapshot.sha256,
        "bytes": source_snapshot.size,
    }


def parse_sha256s(base: pathlib.Path) -> dict[str, str]:
    sums = base / "SHA256SUMS"
    require_no_symlink_components(sums, base, "SHA256SUMS")
    require(sums.is_file(), f"missing SHA256SUMS: {sums}")
    parsed: dict[str, str] = {}
    for line_no, line in enumerate(read_text(sums).splitlines(), start=1):
        require(
            line_no <= MAX_SHA256SUMS_ENTRIES,
            f"SHA256SUMS has more than {MAX_SHA256SUMS_ENTRIES} lines: {sums}",
        )
        if not line.strip():
            continue
        parts = line.split()
        require(len(parts) == 2, f"malformed SHA256SUMS line {line_no}: {line}")
        expected, raw_rel = parts
        require(
            HEX_SHA256.fullmatch(expected) is not None,
            f"malformed sha256 at {sums}:{line_no}",
        )
        rel = require_relative_safe(raw_rel, f"SHA256SUMS path at {sums}:{line_no}")
        require(
            rel not in parsed, f"duplicate SHA256SUMS path at {sums}:{line_no}: {rel}"
        )
        parsed[rel] = expected
    require(parsed, f"SHA256SUMS is empty: {sums}")
    return parsed


def bounded_release_files(base: pathlib.Path) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    entry_count = 0
    for path in base.rglob("*"):
        entry_count += 1
        require(
            entry_count <= MAX_RELEASE_TREE_ENTRIES,
            f"release tree has more than {MAX_RELEASE_TREE_ENTRIES} entries: {base}",
        )
        require(not path.is_symlink(), f"release tree contains a symlink: {path}")
        if path.is_file():
            files.append(path)
        else:
            require(path.is_dir(), f"release tree contains a special file: {path}")
    return files


def verify_sha256s(
    base: pathlib.Path,
    *,
    expected_file_set: set[str] | None = None,
    pinned_digests: dict[str, str] | None = None,
) -> None:
    parsed = parse_sha256s(base)
    if expected_file_set is not None:
        require(
            set(parsed) == expected_file_set,
            "release SHA256SUMS declared file set mismatch "
            f"extra={sorted(set(parsed) - expected_file_set)} "
            f"missing={sorted(expected_file_set - set(parsed))}",
        )
        actual = {
            path.relative_to(base).as_posix()
            for path in bounded_release_files(base)
            if path != base / "SHA256SUMS"
        }
        require(
            actual == expected_file_set,
            "release tree declared file set mismatch "
            f"extra={sorted(actual - expected_file_set)} "
            f"missing={sorted(expected_file_set - actual)}",
        )
    for rel, expected in parsed.items():
        if pinned_digests is not None and rel in pinned_digests:
            require(
                expected == pinned_digests[rel],
                f"release SHA256SUMS does not bind the verified snapshot: {rel}",
            )
        target = base / pathlib.Path(rel)
        require_no_symlink_components(target, base, "SHA256SUMS target")
        require(target.is_file(), f"SHA256SUMS target missing: {target}")
        require(
            sha256_file(target) == expected, f"SHA256SUMS hash mismatch for {target}"
        )


def package_dirty(manifest: dict[str, Any]) -> bool:
    dirty = manifest.get("git_dirty")
    require(type(dirty) is bool, "package manifest git_dirty must be boolean")
    return dirty


def validate_runtime_identity(value: Any, label: str) -> None:
    require(isinstance(value, dict) and value, f"{label} must be a non-empty object")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    require(len(encoded.encode("utf-8")) <= 16 * 1024, f"{label} is too large")
    for key in value:
        require(isinstance(key, str) and key, f"{label} contains a malformed key")


def normalized_package_semantics(manifest: dict[str, Any]) -> dict[str, Any]:
    abi = manifest["abi"]
    return {
        "name": manifest["package"],
        "version": manifest["version"],
        "abi": {
            "major": abi["major"],
            "contract_path": abi["contract_path"],
            "contract_sha256": abi["contract_sha256"],
            "exports_sha256": abi["exports_sha256"],
            "export_count": abi["export_count"],
            "platform": abi["platform"],
            "runtime_identity": abi["runtime_identity"],
            "shared_filename": abi["shared_filename"],
            "static_filename": abi["static_filename"],
        },
    }


def validate_package_manifest(
    manifest_path: pathlib.Path,
    expected_commit: str,
    expected_version: str,
    channel: str,
    face: str,
    trust: AbiTrustRoot,
) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    require(face in EXPECTED_FACES, f"unsupported package face: {face}")
    contract = PACKAGE_MANIFEST_CONTRACTS[face]
    require_exact_object(manifest, contract.manifest_fields, f"{face} manifest")
    require_exact_int(
        manifest.get("schema_version"),
        contract.schema_version,
        f"{face} manifest schema_version",
    )
    expected_kind = contract.kind
    if expected_kind is None:
        require("kind" not in manifest, f"{face} manifest kind must be absent")
    else:
        require_exact_json(manifest.get("kind"), expected_kind, f"{face} manifest kind")
    package = manifest.get("package")
    require(isinstance(package, str) and package, f"{face} manifest package is missing")
    require(
        manifest.get("version") == expected_version,
        f"{face} manifest version mismatch: {manifest.get('version')} != {expected_version}",
    )
    commit = manifest.get("git_commit")
    require(
        commit == expected_commit,
        f"{face} manifest commit mismatch: {commit} != {expected_commit}",
    )
    dirty = package_dirty(manifest)
    if face in {"c-abi", "android"}:
        require(
            manifest.get("diagnostic_only") is dirty,
            f"{face} manifest diagnostic_only must equal git_dirty",
        )
        require_source_timestamp(manifest, f"{face} manifest")
    if channel == "release":
        require(dirty is False, f"{face} release manifest was generated dirty")

    abi = require_exact_object(
        manifest.get("abi"), contract.abi_fields, f"{face} manifest ABI"
    )
    require_exact_int(abi.get("major"), ABI_MAJOR, f"{face} ABI major")
    require(
        abi.get("contract_path") == CONTRACT_RELATIVE_PATH.as_posix(),
        f"{face} ABI contract_path mismatch",
    )
    require(
        abi.get("contract_sha256") == trust.contract_sha256,
        f"{face} ABI contract hash mismatch",
    )
    require(
        abi.get("exports_sha256") == trust.exports_sha256,
        f"{face} ABI exports hash mismatch",
    )
    require_exact_int(abi.get("export_count"), EXPORT_COUNT, f"{face} ABI export_count")
    platform = abi.get("platform")
    require(
        isinstance(platform, str) and SAFE_PLATFORM.fullmatch(platform) is not None,
        f"{face} ABI platform is malformed: {platform}",
    )
    shared_filename = require_safe_basename(
        abi.get("shared_filename"), f"{face} ABI shared_filename"
    )
    static_filename = require_safe_basename(
        abi.get("static_filename"), f"{face} ABI static_filename"
    )
    validate_runtime_identity(
        abi.get("runtime_identity"), f"{face} ABI runtime_identity"
    )

    if face == "c-abi":
        host = manifest.get("host")
        require(
            isinstance(host, str) and SAFE_PLATFORM.fullmatch(host) is not None,
            f"C ABI host is malformed: {host}",
        )
        expected_platform = C_HOST_PLATFORMS.get(host)
        require(expected_platform is not None, f"C ABI host is unsupported: {host}")
        require_exact_json(platform, expected_platform, "C ABI platform for host")
        require(
            package == f"{trust.archive_prefix}-{expected_version}-{host}",
            f"C ABI package name differs from version/host identity: {package}",
        )
        compatibility = manifest.get("platform_compatibility")
        require(
            isinstance(compatibility, dict),
            "C ABI platform_compatibility must be an object",
        )
        require_exact_json(
            compatibility.get("target"), host, "C ABI compatibility target"
        )
        require_exact_json(
            manifest.get("rustc"), EXPECTED_RUSTC_VERSION, "C ABI rustc version"
        )
        require_exact_json(
            manifest.get("cargo"), EXPECTED_CARGO_VERSION, "C ABI Cargo version"
        )
        require_exact_json(
            abi.get("embedded_contract_path"),
            "share/q-periapt/abi/q-periapt-c-abi-v2.json",
            "C ABI embedded contract path",
        )
        expected_identity = trust.platforms.get(platform)
        require(
            expected_identity is not None,
            f"C ABI platform is not in contract: {platform}",
        )
        require(
            abi.get("runtime_identity") == expected_identity,
            f"C ABI runtime identity differs from contract for {platform}",
        )
        require(
            shared_filename == expected_identity.get("shared_filename"),
            f"C ABI shared filename differs from contract for {platform}",
        )
        require(
            static_filename == expected_identity.get("static_filename"),
            f"C ABI static filename differs from contract for {platform}",
        )
    elif face == "swift":
        require(
            package == "q-periapt-swift", f"Swift package name is invalid: {package}"
        )
        require_exact_json(
            manifest.get("type"), SWIFT_PACKAGE_TYPE, "Swift manifest type"
        )
        targets = require_safe_string_list(
            manifest.get("targets"), SWIFT_TARGETS, "Swift manifest targets"
        )
        release_identity = {
            "product_version": expected_version,
            "revision": "r1",
            "tag": f"v{expected_version}",
            "url": (
                "https://github.com/billlza/q-periapt/releases/tag/"
                f"v{expected_version}"
            ),
        }
        require_exact_json(
            manifest.get("release_identity"),
            release_identity,
            "Swift manifest release_identity",
        )
        require_exact_json(
            manifest.get("toolchain"),
            {
                "cargo": EXPECTED_CARGO_VERSION,
                "rust_host": EXPECTED_SWIFT_RUST_HOST,
                "rustc": EXPECTED_RUSTC_VERSION,
                "swift": EXPECTED_SWIFT_VERSION,
                "xcode": list(EXPECTED_XCODE_VERSION),
            },
            "Swift manifest toolchain",
        )
        require_exact_json(
            manifest.get("public_release_boundary"),
            {
                "consumer_distribution_responsibilities": {
                    "ios": {
                        "requires_final_app_signing_and_provisioning": True,
                        "sdk_notarization_applicable": False,
                    },
                    "macos": {
                        "requires_final_app_notarization": True,
                        "requires_final_app_signing": True,
                    },
                },
                "contains_device_udid": False,
                "contains_mobileprovision": False,
                "contains_raw_device_proof": False,
                "distribution_signed": False,
                "notarization_applicability": "not_applicable_static_sdk_payload",
                "notarized": False,
                "requires_clean_tree_for_release": True,
                "stapled": False,
            },
            "Swift manifest public_release_boundary",
        )
        require_exact_json(platform, "apple-xcframework", "Swift ABI platform")
        require_exact_json(
            abi.get("runtime_identity"),
            {
                "container": "CQPeriapt.xcframework",
                "linkage": "static",
                "slice_library": "libq_periapt_ffi_abi2.a",
                "targets": targets,
            },
            "Swift ABI runtime_identity",
        )
        require_exact_json(
            shared_filename, "CQPeriapt.xcframework", "Swift ABI shared filename"
        )
        require_exact_json(
            static_filename, "libq_periapt_ffi_abi2.a", "Swift ABI static filename"
        )
    elif face == "android":
        require(
            package == f"q-periapt-android-{expected_version}.aar",
            f"Android package name is invalid: {package}",
        )
        require_exact_json(
            manifest.get("package_only"), True, "Android manifest package_only"
        )
        require_exact_json(
            manifest.get("device_runtime_proof"),
            False,
            "Android manifest device_runtime_proof",
        )
        require_exact_json(
            manifest.get("boundary"),
            ANDROID_PACKAGE_BOUNDARY,
            "Android manifest boundary",
        )
        require_exact_json(
            manifest.get("toolchain"),
            {"cargo": EXPECTED_CARGO_VERSION, "rustc": EXPECTED_RUSTC_VERSION},
            "Android manifest toolchain",
        )
        android = require_exact_object(
            manifest.get("android"),
            frozenset(
                {
                    "abis",
                    "build_tools",
                    "min_sdk",
                    "native_page_alignment",
                    "native_stripped",
                    "ndk",
                    "platform",
                    "sdk",
                }
            ),
            "Android manifest android",
        )
        abis = require_safe_string_list(
            android.get("abis"), ANDROID_ABIS, "Android manifest ABIs"
        )
        require_exact_json(
            android,
            {
                "abis": abis,
                "build_tools": "36.0.0",
                "min_sdk": 23,
                "native_page_alignment": 16384,
                "native_stripped": True,
                "ndk": "29.0.14206865",
                "platform": "android-35",
                "sdk": "local-android-sdk",
            },
            "Android manifest android",
        )
        require_exact_json(platform, "android-aar", "Android ABI platform")
        require_exact_json(
            abi.get("runtime_identity"),
            {
                "abis": abis,
                "jni_library": "libqperiapt_jni_abi2.so",
                "loader_order": ["q_periapt_ffi_abi2", "qperiapt_jni_abi2"],
                "runtime_library": "libq_periapt_ffi_abi2.so",
            },
            "Android ABI runtime_identity",
        )
        require_exact_json(
            shared_filename,
            "libq_periapt_ffi_abi2.so",
            "Android ABI shared filename",
        )
        require_exact_json(
            static_filename, "not-shipped-abi2", "Android ABI static filename"
        )

    return manifest


def manifest_targets(face: str, manifest: dict[str, Any]) -> list[str]:
    if face == "c-abi":
        return [manifest["host"]]
    if face == "swift":
        return list(manifest["targets"])
    if face == "android":
        return list(manifest["android"]["abis"])
    fail(f"unsupported package face: {face}")


def indexed_artifact_contract(face: str, manifest: dict[str, Any]) -> dict[str, Any]:
    dirty = package_dirty(manifest)
    if face == "c-abi":
        return {
            "id": f"c-abi/{manifest['host']}",
            "type": "tar.gz",
            "boundary": {
                "package_only": False,
                "host_archive_only": True,
                "multi_target_release_pending": True,
                "git_dirty": dirty,
                "leaf_gate_receipt_embedded": False,
                "unprojected_manifest_claims_verified": False,
                "local_artifact_store_trusted": True,
            },
            "required_leaf_gate": "artifact/c-package.sh",
            "targets": manifest_targets(face, manifest),
        }
    if face == "swift":
        return {
            "id": "swift/xcframework",
            "type": "xcframework.zip",
            "boundary": {
                "package_only": True,
                "public_url_uploaded": False,
                "contains_raw_device_proof": False,
                "git_dirty": dirty,
                "leaf_gate_receipt_embedded": False,
                "unprojected_manifest_claims_verified": False,
                "local_artifact_store_trusted": True,
            },
            "required_leaf_gate": "artifact/swift-xcframework.sh",
            "targets": manifest_targets(face, manifest),
        }
    if face == "android":
        return {
            "id": "android/aar",
            "type": "aar",
            "boundary": {
                "package_only": True,
                "device_runtime_proof": False,
                "runtime_proof_is_separate": True,
                "git_dirty": dirty,
                "leaf_gate_receipt_embedded": False,
                "unprojected_manifest_claims_verified": False,
                "local_artifact_store_trusted": True,
            },
            "required_leaf_gate": "artifact/android-aar.sh",
            "targets": manifest_targets(face, manifest),
        }
    fail(f"unsupported package face: {face}")


def validate_indexed_artifact_contract(
    face: str, artifact: dict[str, Any], manifest: dict[str, Any]
) -> None:
    expected = indexed_artifact_contract(face, manifest)
    for field, expected_value in expected.items():
        require_exact_json(
            artifact.get(field), expected_value, f"{face} indexed artifact {field}"
        )


def validate_cross_face_semantics(semantics: dict[str, dict[str, Any]]) -> None:
    require(
        set(semantics) == EXPECTED_FACES,
        "release index must contain C, Swift, and Android faces",
    )
    reference = semantics["c-abi"]
    for face, current in semantics.items():
        require(
            current["version"] == reference["version"],
            f"{face} package version differs across faces",
        )
        for key in ("major", "contract_sha256", "exports_sha256", "export_count"):
            require(
                current["abi"][key] == reference["abi"][key],
                f"{face} ABI {key} differs across faces",
            )


def artifact_entry(
    artifact_id: str,
    face: str,
    kind: str,
    files: list[dict[str, Any]],
    manifest_file: dict[str, Any],
    sha256s_file: dict[str, Any],
    boundary: dict[str, Any],
    required_leaf_gate: str,
    targets: list[str],
    package_semantics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": artifact_id,
        "face": face,
        "type": kind,
        "files": files,
        "manifest": manifest_file,
        "sha256s": sha256s_file,
        "package_semantics": package_semantics,
        "boundary": boundary,
        "required_leaf_gate": required_leaf_gate,
        "targets": targets,
    }


def proof_summary_snapshot(
    snapshot: JsonObjectSnapshot,
    proof_kind: str,
    *,
    expected_commit: str | None = None,
) -> dict[str, Any]:
    proof = snapshot.value
    if expected_commit is not None:
        require(
            proof.get("git_commit") == expected_commit,
            f"{proof_kind} proof commit differs from this index",
        )
        if proof_kind == "apple_matrix":
            require(
                proof.get("schema_version") == APPLE_MATRIX_PROOF_SCHEMA_VERSION,
                "Apple matrix proof schema is not current",
            )
            require(
                proof.get("status") == "pass",
                "Apple matrix proof is not passing",
            )
        elif proof_kind == "android_runtime":
            result = proof.get("result")
            require(
                isinstance(result, dict) and result.get("status") == "pass",
                "Android runtime proof is not passing",
            )
        else:
            fail(f"unsupported proof summary kind: {proof_kind}")
    dirty = proof.get("source_tree_dirty")
    require(type(dirty) is bool, f"{proof_kind} proof lacks explicit dirty provenance")
    summary: dict[str, Any] = {
        "kind": proof_kind,
        "sha256": snapshot.file.sha256,
        "generated_at": proof.get("generated_at"),
        "source_tree_dirty": dirty,
        "copied_raw_proof": False,
        "diagnostic_only": dirty,
    }
    if proof_kind == "apple_matrix":
        devices = []
        entries = proof.get("devices")
        require(isinstance(entries, list), "Apple matrix devices are malformed")
        for item in entries:
            require(isinstance(item, dict), "Apple matrix device entry is malformed")
            devices.append(
                {
                    "label": item.get("label"),
                    "device_type": item.get("device_type"),
                    "product_type": item.get("product_type"),
                    "os_version": item.get("os_version"),
                    "os_build": item.get("os_build"),
                    "device_id_sha256_prefix": str(item.get("device_id_sha256", ""))[
                        :12
                    ],
                    "run_id": item.get("run_id"),
                }
            )
        summary["devices"] = devices
    elif proof_kind == "android_runtime":
        device = proof.get("device")
        result = proof.get("result")
        require(
            isinstance(device, dict)
            and isinstance(result, dict),
            "Android proof is malformed",
        )
        summary["proof_schema"] = proof.get("schema")
        summary["release_candidate_mode"] = proof.get("release_candidate_mode")
        summary["device"] = {
            "kind": device.get("kind"),
            "model": device.get("model"),
            "sdk": device.get("sdk"),
            "abi": device.get("abi"),
            "page_size": device.get("page_size"),
            "serial_sha256_prefix": device.get("serial_sha256_prefix"),
            "raw_serial_recorded": device.get("raw_serial_recorded"),
        }
        summary["result"] = {
            "run_id": proof.get("run_id"),
            "status": result.get("status"),
            "test_count": result.get("test_count"),
            "passed_tests": result.get("passed_tests"),
        }
        if device.get("kind") == "emulator":
            emulator_control = proof.get("emulator_control")
            require(
                isinstance(emulator_control, dict),
                "Android emulator proof lacks control evidence",
            )
            external_adb = emulator_control.get("external_adb")
            private_adb = emulator_control.get("private_adb")
            native_notifier = emulator_control.get("native_notifier")
            require(
                isinstance(external_adb, dict)
                and isinstance(private_adb, dict)
                and isinstance(native_notifier, dict),
                "Android proof lacks adb isolation control",
            )
            summary["adb_isolation"] = {
                "mode": ANDROID_EMULATOR_ROUTING_MODE,
                "external_adb": dict(external_adb),
                "private_adb": dict(private_adb),
                "native_notifier": dict(native_notifier),
            }
        else:
            summary["adb_isolation"] = None
    validate_sanitized_proof_summary(proof_kind, summary)
    return summary


def proof_summary(path: pathlib.Path, proof_kind: str) -> dict[str, Any]:
    try:
        snapshot = load_json_object_snapshot(
            path,
            label=f"{proof_kind} proof",
        )
    except EvidenceIOError as exc:
        fail(str(exc))
    return proof_summary_snapshot(snapshot, proof_kind)


def validate_sanitized_proof_summary(proof_name: str, proof: dict[str, Any]) -> None:
    common_fields = {
        "kind",
        "sha256",
        "generated_at",
        "source_tree_dirty",
        "copied_raw_proof",
        "diagnostic_only",
    }
    extra_fields = {
        "apple_matrix": {"devices"},
        "android_runtime": {
            "proof_schema",
            "release_candidate_mode",
            "device",
            "result",
            "adb_isolation",
        },
    }
    require(proof_name in extra_fields, f"unsupported proof summary: {proof_name}")
    proof = require_exact_object(
        proof,
        frozenset(common_fields | extra_fields[proof_name]),
        f"{proof_name} proof summary",
    )
    require_exact_json(proof.get("kind"), proof_name, f"{proof_name} proof kind")
    require(
        isinstance(proof.get("sha256"), str)
        and HEX_SHA256.fullmatch(proof["sha256"]) is not None,
        f"{proof_name} proof SHA-256 is malformed",
    )
    require_utc_timestamp(proof.get("generated_at"), f"{proof_name} generated_at")
    dirty = proof.get("source_tree_dirty")
    require(type(dirty) is bool, f"{proof_name} source_tree_dirty must be boolean")
    require_exact_json(
        proof.get("copied_raw_proof"), False, f"{proof_name} copied_raw_proof"
    )
    require_exact_json(
        proof.get("diagnostic_only"), dirty, f"{proof_name} diagnostic_only"
    )

    if proof_name == "apple_matrix":
        devices = proof.get("devices")
        require(
            isinstance(devices, list), "Apple matrix summary devices must be a list"
        )
        require(len(devices) == 2, "Apple matrix summary must contain two devices")
        labels: list[str] = []
        for index, device in enumerate(devices):
            device = require_exact_object(
                device,
                frozenset(
                    {
                        "label",
                        "device_type",
                        "product_type",
                        "os_version",
                        "os_build",
                        "device_id_sha256_prefix",
                        "run_id",
                    }
                ),
                f"Apple matrix summary device {index}",
            )
            label = require_bounded_text(device.get("label"), "Apple device label")
            labels.append(label)
            require_bounded_text(device.get("device_type"), "Apple device type")
            require_bounded_text(device.get("product_type"), "Apple product type")
            require_bounded_text(device.get("os_version"), "Apple OS version")
            require_bounded_text(device.get("os_build"), "Apple OS build")
            require(
                isinstance(device.get("device_id_sha256_prefix"), str)
                and re.fullmatch(r"[0-9a-f]{12}", device["device_id_sha256_prefix"])
                is not None,
                "Apple device hash prefix is malformed",
            )
            require(
                isinstance(device.get("run_id"), str)
                and re.fullmatch(r"[0-9a-f]{32}", device["run_id"]) is not None,
                "Apple device run_id is malformed",
            )
        require(labels == ["ipad", "iphone"], "Apple matrix labels must be ipad,iphone")
        return

    device = require_exact_object(
        proof.get("device"),
        frozenset(
            {
                "kind",
                "model",
                "sdk",
                "abi",
                "page_size",
                "serial_sha256_prefix",
                "raw_serial_recorded",
            }
        ),
        "Android proof summary device",
    )
    require_exact_int(
        proof.get("proof_schema"),
        ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "Android proof summary schema",
    )
    require(
        type(proof.get("release_candidate_mode")) is bool,
        "Android release_candidate_mode must be boolean",
    )
    require(
        device.get("kind") in {"physical", "emulator"}, "Android device kind is invalid"
    )
    require_bounded_text(device.get("model"), "Android device model")
    require(
        type(device.get("sdk")) is int and device["sdk"] > 0,
        "Android device SDK must be a positive integer",
    )
    require(device.get("abi") in ANDROID_ABIS, "Android device ABI is invalid")
    require(
        type(device.get("page_size")) is int and device["page_size"] in {4096, 16_384},
        "Android device page size is invalid",
    )
    require(
        isinstance(device.get("serial_sha256_prefix"), str)
        and re.fullmatch(r"[0-9a-f]{12}", device["serial_sha256_prefix"]) is not None,
        "Android serial hash prefix is malformed",
    )
    require_exact_json(
        device.get("raw_serial_recorded"), False, "Android raw_serial_recorded"
    )
    result = require_exact_object(
        proof.get("result"),
        frozenset({"run_id", "status", "test_count", "passed_tests"}),
        "Android proof summary result",
    )
    require(
        isinstance(result.get("run_id"), str)
        and re.fullmatch(r"[0-9a-f]{32}", result["run_id"]) is not None,
        "Android result run_id is malformed",
    )
    require_exact_json(result.get("status"), "pass", "Android result status")
    test_count = result.get("test_count")
    passed_tests = result.get("passed_tests")
    require(type(test_count) is int and test_count > 0, "Android test_count is invalid")
    require(isinstance(passed_tests, list), "Android passed_tests must be a list")
    require(len(passed_tests) == test_count, "Android passed_tests count differs")
    require(
        all(isinstance(name, str) and name for name in passed_tests),
        "Android passed_tests contains a malformed name",
    )
    require(
        len(passed_tests) == len(set(passed_tests)),
        "Android passed_tests contains duplicates",
    )
    adb_isolation = proof.get("adb_isolation")
    if device.get("kind") == "physical":
        require_exact_json(
            adb_isolation, None, "physical Android adb isolation summary"
        )
        return
    isolation = require_exact_object(
        adb_isolation,
        frozenset({"mode", "external_adb", "private_adb", "native_notifier"}),
        "Android adb isolation summary",
    )
    require_exact_json(
        isolation.get("mode"),
        ANDROID_EMULATOR_ROUTING_MODE,
        "Android adb isolation mode",
    )
    external_adb = require_exact_object(
        isolation.get("external_adb"),
        frozenset(
            {
                "snapshot_sha256",
                "routing_environment_sha256",
                "routing_receipt_sha256",
                "transport_binding_sha256",
            }
        ),
        "Android external adb summary",
    )
    for field in external_adb:
        require(
            isinstance(external_adb[field], str)
            and HEX_SHA256.fullmatch(external_adb[field]) is not None,
            f"Android external adb {field} is malformed",
        )
    private_adb = require_exact_object(
        isolation.get("private_adb"),
        EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
        "Android private adb summary",
    )
    for field in private_adb:
        if field == "adb_profile":
            require(
                type(private_adb[field]) is str
                and private_adb[field] in OWNED_ADB_PROFILE_DIALECTS,
                "Android private adb profile is malformed",
            )
            continue
        require(
            isinstance(private_adb[field], str)
            and HEX_SHA256.fullmatch(private_adb[field]) is not None,
            f"Android private adb {field} is malformed",
        )
    expected_transport_binding = emulator_routing_transport_binding_sha256(
        external_adb["snapshot_sha256"],
        external_adb["routing_environment_sha256"],
        private_adb,
    )
    require_exact_json(
        external_adb.get("transport_binding_sha256"),
        expected_transport_binding,
        "Android external adb transport binding",
    )
    native_notifier = require_exact_object(
        isolation.get("native_notifier"),
        frozenset(
            {"mode", "port", "admission_checkpoints", "continuous_absence_claimed"}
        ),
        "Android native adb notifier summary",
    )
    require_exact_json(
        native_notifier.get("mode"),
        ANDROID_NATIVE_NOTIFIER_MODE,
        "Android native adb notifier mode",
    )
    require_exact_int(
        native_notifier.get("port"),
        NATIVE_ADB_NOTIFIER_PORT,
        "Android native adb notifier port",
    )
    require_exact_json(
        native_notifier.get("continuous_absence_claimed"),
        False,
        "Android native adb continuous absence claim",
    )
    checkpoints = native_notifier.get("admission_checkpoints")
    require(
        isinstance(checkpoints, list)
        and len(checkpoints) == len(AdbIsolationCheckpoint),
        "Android native adb notifier checkpoints differ",
    )
    for item, checkpoint in zip(checkpoints, AdbIsolationCheckpoint):
        item = require_exact_object(
            item,
            frozenset({"name", "receipt_sha256"}),
            "Android native adb notifier checkpoint",
        )
        require_exact_json(
            item.get("name"), checkpoint.value, "Android notifier checkpoint name"
        )
        require(
            isinstance(item.get("receipt_sha256"), str)
            and HEX_SHA256.fullmatch(item["receipt_sha256"]) is not None,
            "Android notifier checkpoint receipt hash is malformed",
        )


def validate_android_release_summary_contract(proof: dict[str, Any]) -> None:
    """Require the canonical Android AVD lane in an offline release index."""

    device = proof["device"]
    result = proof["result"]
    isolation = proof.get("adb_isolation")
    require_exact_int(
        proof.get("proof_schema"),
        ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "Android release summary proof schema",
    )
    require_exact_json(
        proof.get("release_candidate_mode"),
        True,
        "Android release summary release_candidate_mode",
    )
    require_exact_json(
        device.get("kind"),
        ANDROID_RELEASE_DEVICE_KIND,
        "Android release summary device kind",
    )
    require_exact_json(
        device.get("abi"),
        ANDROID_RELEASE_DEVICE_ABI,
        "Android release summary device ABI",
    )
    require_exact_int(
        device.get("sdk"),
        ANDROID_RELEASE_DEVICE_SDK,
        "Android release summary device SDK",
    )
    require_exact_int(
        device.get("page_size"),
        ANDROID_RELEASE_PAGE_SIZE,
        "Android release summary device page size",
    )
    require_exact_json(
        result.get("status"),
        "pass",
        "Android release summary result status",
    )
    require(
        isinstance(isolation, dict),
        "Android release summary requires adb isolation evidence",
    )
    require_exact_json(
        isolation.get("mode"),
        ANDROID_EMULATOR_ROUTING_MODE,
        "Android release summary adb isolation mode",
    )
    native_notifier = isolation.get("native_notifier")
    require(isinstance(native_notifier, dict), "Android notifier summary is missing")
    require_exact_json(
        native_notifier.get("mode"),
        ANDROID_NATIVE_NOTIFIER_MODE,
        "Android release summary native notifier mode",
    )
    require_exact_int(
        native_notifier.get("port"),
        NATIVE_ADB_NOTIFIER_PORT,
        "Android release summary native notifier port",
    )


def validate_index_bytes(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"cannot decode release index as UTF-8: {exc}")
    for forbidden in FORBIDDEN_INDEX_TEXT:
        require(
            forbidden not in text,
            f"release index contains private/local token: {forbidden}",
        )


def write_release_sums(release_root: pathlib.Path) -> None:
    files = sorted(
        path
        for path in bounded_release_files(release_root)
        if path != release_root / "SHA256SUMS"
    )
    lines = []
    for path in files:
        require_no_symlink_components(path, release_root, "release checksum input")
        rel = path.relative_to(release_root).as_posix()
        rel = require_relative_safe(rel, "release SHA256SUMS path")
        lines.append(f"{sha256_file(path)}  {rel}")
    sums = release_root / "SHA256SUMS"
    require(not sums.is_symlink(), f"release SHA256SUMS must not be a symlink: {sums}")
    write_private_bytes(sums, ("\n".join(lines) + "\n").encode("utf-8"))


def verify_index_file(release_root: pathlib.Path, item: Any) -> pathlib.Path:
    item = require_exact_object(
        item, frozenset({"path", "sha256", "bytes"}), "indexed file entry"
    )
    rel = item.get("path")
    expected = item.get("sha256")
    size = item.get("bytes")
    require(
        isinstance(expected, str) and HEX_SHA256.fullmatch(expected) is not None,
        f"indexed file hash is malformed: {rel}",
    )
    require(
        type(size) is int and 0 <= size <= MAX_INDEXED_FILE_BYTES,
        f"indexed file byte count is malformed or too large: {rel}",
    )
    rel = require_relative_safe(rel, "indexed file path")
    path = release_root / pathlib.Path(rel)
    require_no_symlink_components(path, release_root, "indexed file")
    observed = digest_regular_file(path, label="indexed file")
    require(observed.size == size, f"indexed file byte count mismatch: {rel}")
    require(observed.sha256 == expected, f"indexed file hash mismatch: {rel}")
    return path


def decompress_single_gzip_member(
    source: Any,
    output: Any,
    *,
    expected_compressed_size: int,
    label: str,
) -> int:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    compressed_size = 0
    decompressed_size = 0
    while chunk := source.read(1024 * 1024):
        compressed_size += len(chunk)
        require(
            compressed_size <= MAX_TAR_ARCHIVE_BYTES,
            f"{label} compressed stream exceeds {MAX_TAR_ARCHIVE_BYTES} bytes",
        )
        require(not decompressor.eof, f"{label} contains trailing compressed data")
        remaining = MAX_TAR_UNCOMPRESSED_BYTES - decompressed_size
        value = decompressor.decompress(chunk, remaining + 1)
        decompressed_size += len(value)
        require(
            decompressed_size <= MAX_TAR_UNCOMPRESSED_BYTES,
            f"{label} decompressed stream exceeds {MAX_TAR_UNCOMPRESSED_BYTES} bytes",
        )
        require(
            not decompressor.unconsumed_tail,
            f"{label} decompressed stream exceeds {MAX_TAR_UNCOMPRESSED_BYTES} bytes",
        )
        require(
            not decompressor.unused_data,
            f"{label} contains more than one gzip member or trailing data",
        )
        written = output.write(value)
        require(written == len(value), f"short write while buffering {label}")

    remaining = MAX_TAR_UNCOMPRESSED_BYTES - decompressed_size
    flushed = decompressor.flush(remaining + 1)
    decompressed_size += len(flushed)
    require(
        decompressed_size <= MAX_TAR_UNCOMPRESSED_BYTES,
        f"{label} decompressed stream exceeds {MAX_TAR_UNCOMPRESSED_BYTES} bytes",
    )
    written = output.write(flushed)
    require(written == len(flushed), f"short write while finalizing {label}")
    require(decompressor.eof, f"{label} gzip member is truncated")
    require(
        compressed_size == expected_compressed_size,
        f"{label} compressed size changed while reading",
    )
    output.flush()
    output.seek(0)
    return decompressed_size


def tar_metadata_bytes(archive: pathlib.Path, suffix: str) -> bytes:
    require(
        archive.name.endswith(".tar.gz"), f"C archive filename is invalid: {archive}"
    )
    require(
        suffix in {"/MANIFEST.json", "/SHA256SUMS"},
        f"unsupported C archive metadata path: {suffix}",
    )
    expected_root = archive.name.removesuffix(".tar.gz")
    expected_member = f"{expected_root}{suffix}"
    try:
        with (
            tempfile.SpooledTemporaryFile(
                max_size=8 * 1024 * 1024, mode="w+b"
            ) as compressed,
            tempfile.SpooledTemporaryFile(
                max_size=8 * 1024 * 1024, mode="w+b"
            ) as decompressed,
        ):

            def write_compressed(chunk: bytes) -> None:
                written = compressed.write(chunk)
                require(written == len(chunk), "short write while buffering C archive")

            archive_snapshot = consume_regular_snapshot(
                archive,
                maximum=MAX_TAR_ARCHIVE_BYTES,
                label="C archive",
                consume=write_compressed,
            )
            compressed.flush()
            compressed.seek(0)
            decompressed_size = decompress_single_gzip_member(
                compressed,
                decompressed,
                expected_compressed_size=archive_snapshot.size,
                label="C archive",
            )
            with tarfile.open(fileobj=decompressed, mode="r|") as bundle:
                seen: set[str] = set()
                match: bytes | None = None
                member_count = 0
                uncompressed_bytes = 0
                for member in bundle:
                    member_count += 1
                    require(
                        member_count <= MAX_TAR_MEMBERS,
                        f"C archive has more than {MAX_TAR_MEMBERS} members: {archive}",
                    )
                    pure = pathlib.PurePosixPath(member.name)
                    require(pure.parts, f"unsafe empty C archive path: {member.name}")
                    require(
                        member.name and not pure.is_absolute(),
                        f"unsafe C archive path: {member.name}",
                    )
                    canonical = pure.as_posix()
                    accepted_name = (
                        member.name[:-1]
                        if member.isdir() and member.name.endswith("/")
                        else member.name
                    )
                    require(
                        accepted_name == canonical,
                        f"non-canonical C archive path: {member.name}",
                    )
                    canonical = require_relative_safe(canonical, "C archive member")
                    require(
                        pure.parts[0] == expected_root,
                        f"C archive member is outside {expected_root}: {member.name}",
                    )
                    require(
                        ":" not in pure.parts[0],
                        f"unsafe C archive drive-like path: {member.name}",
                    )
                    require(
                        canonical not in seen, f"duplicate C archive path: {canonical}"
                    )
                    seen.add(canonical)
                    require(
                        member.isfile() or member.isdir(),
                        f"unsupported C archive member: {member.name}",
                    )
                    if not member.isfile():
                        require(
                            member.size == 0,
                            f"C archive directory has data: {member.name}",
                        )
                        continue
                    require(
                        member.size >= 0,
                        f"C archive member has negative size: {member.name}",
                    )
                    require(
                        member.size <= MAX_TAR_MEMBER_BYTES,
                        f"C archive member exceeds {MAX_TAR_MEMBER_BYTES} bytes: {member.name}",
                    )
                    uncompressed_bytes += member.size
                    require(
                        uncompressed_bytes <= MAX_TAR_UNCOMPRESSED_BYTES,
                        "C archive uncompressed size exceeds "
                        f"{MAX_TAR_UNCOMPRESSED_BYTES} bytes: {archive}",
                    )
                    if canonical != expected_member:
                        continue
                    require(match is None, f"C archive contains more than one {suffix}")
                    require(
                        member.size <= MAX_TAR_METADATA_BYTES,
                        f"C archive {suffix} is too large",
                    )
                    stream = bundle.extractfile(member)
                    require(stream is not None, f"cannot read C archive {suffix}")
                    value = stream.read(MAX_TAR_METADATA_BYTES + 1)
                    require(
                        len(value) == member.size, f"short read for C archive {suffix}"
                    )
                    match = value
                tar_end = bundle.offset
                require(
                    match is not None, f"C archive must contain exactly one {suffix}"
                )
            require(
                type(tar_end) is int and 0 <= tar_end <= decompressed_size,
                f"C archive tar end offset is invalid: {archive}",
            )
            trailer_size = decompressed_size - tar_end
            require(
                trailer_size >= 1024 and trailer_size % 512 == 0,
                f"C archive has a malformed tar trailer: {archive}",
            )
            decompressed.seek(tar_end)
            observed_trailer = 0
            while tar_trailer := decompressed.read(1024 * 1024):
                observed_trailer += len(tar_trailer)
                require(
                    not any(tar_trailer),
                    f"C archive has a non-zero tar trailer: {archive}",
                )
            require(
                observed_trailer == trailer_size,
                f"C archive tar trailer changed while reading: {archive}",
            )
            return match
    except (EOFError, EvidenceIOError, OSError, tarfile.TarError, zlib.error) as exc:
        fail(f"cannot inspect C archive {archive}: {exc}")


def validate_artifact_binding(
    face: str,
    manifest: dict[str, Any],
    manifest_path: pathlib.Path,
    sha256s_path: pathlib.Path,
    package_files: list[pathlib.Path],
) -> None:
    require(
        len(package_files) == 1,
        f"{face} release entry must contain exactly one package file",
    )
    package_file = package_files[0]
    if face == "c-abi":
        require(package_file.name.endswith(".tar.gz"), "C ABI package must be a tar.gz")
        require(
            package_file.name == f"{manifest['package']}.tar.gz",
            "C ABI archive filename differs from copied manifest",
        )
        require(
            sha256_bytes(tar_metadata_bytes(package_file, "/MANIFEST.json"))
            == sha256_file(manifest_path),
            "C archive MANIFEST.json differs from indexed manifest",
        )
        require(
            sha256_bytes(tar_metadata_bytes(package_file, "/SHA256SUMS"))
            == sha256_file(sha256s_path),
            "C archive SHA256SUMS differs from indexed checksum file",
        )
    elif face == "swift":
        artifacts = require_exact_object(
            manifest.get("artifacts"),
            frozenset({"xcframework_zip", "xcframework_info_plist_sha256"}),
            "Swift manifest artifacts",
        )
        zip_entry = artifacts.get("xcframework_zip")
        zip_entry = require_exact_object(
            zip_entry,
            frozenset({"path", "sha256", "swiftpm_checksum"}),
            "Swift manifest xcframework_zip",
        )
        package_sha256 = sha256_file(package_file)
        require_exact_json(
            zip_entry.get("path"),
            "CQPeriapt.xcframework.zip",
            "Swift manifest XCFramework zip path",
        )
        require(
            zip_entry.get("sha256") == package_sha256,
            "Swift manifest does not bind the indexed XCFramework zip",
        )
        require(
            zip_entry.get("swiftpm_checksum") == package_sha256,
            "Swift manifest SwiftPM checksum does not bind the indexed XCFramework zip",
        )
    elif face == "android":
        artifacts = manifest.get("artifacts")
        require(isinstance(artifacts, dict), "Android manifest artifacts are malformed")
        require(
            package_file.name == manifest["package"],
            "Android AAR filename differs from copied manifest",
        )
        require(
            artifacts.get("aar_sha256") == sha256_file(package_file),
            "Android manifest does not bind the indexed AAR",
        )
    else:
        fail(f"unsupported artifact face: {face}")


def validate_index_location(index_path: pathlib.Path, root: pathlib.Path) -> None:
    target = root / "target"
    release_base = target / "qperiapt-local-release"
    require_strictly_under(index_path, release_base, "release index")
    require_no_symlink_components(index_path, target, "release index")
    require(
        index_path.name == "index.json",
        f"release index filename must be index.json: {index_path}",
    )
    require(index_path.is_file(), f"release index missing: {index_path}")


def verify_release_index_snapshot(
    index_path: pathlib.Path,
    root: pathlib.Path,
    *,
    allow_diagnostic: bool,
    expected_index_sha256: str | None = None,
    expected_generated_at: str | None = None,
    identity_index_path: pathlib.Path | None = None,
) -> VerifiedReleaseIndex:
    root = root.resolve()
    index_path = normalized_absolute(index_path)
    identity_index_path = normalized_absolute(identity_index_path or index_path)
    validate_index_location(index_path, root)
    try:
        snapshot = load_json_object_snapshot(
            index_path,
            label=f"release index {index_path}",
        )
    except EvidenceIOError as exc:
        fail(str(exc))
    if expected_index_sha256 is not None:
        require(
            HEX_SHA256.fullmatch(expected_index_sha256) is not None,
            "expected release index digest is malformed",
        )
        require(
            snapshot.file.sha256 == expected_index_sha256,
            "release pointer index hash mismatch",
        )
    index = snapshot.value
    require_exact_object(
        index,
        frozenset(
            {
                "schema_version",
                "kind",
                "version",
                "channel",
                "diagnostic_only",
                "generated_at",
                "abi",
                "git",
                "release_boundary",
                "artifacts",
                "proof_summaries",
            }
        ),
        "release index",
    )
    require_exact_int(
        index.get("schema_version"), SCHEMA_VERSION, "release index schema_version"
    )
    require(index.get("kind") == KIND, "release index kind mismatch")
    index_generated_at = require_utc_timestamp(
        index.get("generated_at"),
        "release index generated_at",
    )
    if expected_generated_at is not None:
        canonical_expected_generated_at = require_utc_timestamp(
            expected_generated_at,
            "expected release index generated_at",
        )
        require(
            index_generated_at == canonical_expected_generated_at,
            "release pointer generated_at differs from the verified index snapshot",
        )
    validate_index_bytes(snapshot.file.data)
    channel = require_release_channel(index.get("channel"))
    diagnostic_only = index.get("diagnostic_only")
    require(
        type(diagnostic_only) is bool, "release index diagnostic_only must be boolean"
    )
    require(
        diagnostic_only is (channel == "diagnostic"),
        "release index channel/diagnostic_only boundary mismatch",
    )
    if channel == "diagnostic":
        require(
            allow_diagnostic,
            "diagnostic release index requires explicit allow_diagnostic",
        )
    channel_base = root / "target" / "qperiapt-local-release" / channel
    require_strictly_under(
        identity_index_path,
        channel_base,
        "release index channel path",
    )

    trust = load_abi_trust_root(root)
    index_version = require_safe_basename(
        index.get("version"), "release index package version"
    )
    require(
        index_version == trust.version,
        "release index package version differs from ABI contract",
    )
    abi = require_exact_object(
        index.get("abi"),
        frozenset(
            {
                "major",
                "contract_path",
                "contract_sha256",
                "exports_sha256",
                "export_count",
            }
        ),
        "release index ABI",
    )
    require_exact_int(abi.get("major"), ABI_MAJOR, "release index ABI major")
    require(
        abi.get("contract_path") == CONTRACT_RELATIVE_PATH.as_posix(),
        "release index contract_path mismatch",
    )
    require(
        abi.get("contract_sha256") == trust.contract_sha256,
        "release index contract hash mismatch",
    )
    require(
        abi.get("exports_sha256") == trust.exports_sha256,
        "release index exports hash mismatch",
    )
    require_exact_int(
        abi.get("export_count"), EXPORT_COUNT, "release index export_count"
    )

    git = require_exact_object(
        index.get("git"),
        frozenset({"commit", "source_tree_dirty"}),
        "release index git provenance",
    )
    commit = require_safe_basename(git.get("commit"), "release index commit")
    dirty = git.get("source_tree_dirty")
    require(
        isinstance(commit, str) and GIT_COMMIT.fullmatch(commit) is not None,
        "release index commit is malformed",
    )
    require(type(dirty) is bool, "release index source_tree_dirty must be boolean")
    try:
        require_commit_or_evidence_successor(root, commit)
        current_dirty = provenance_source_tree_dirty(root)
    except GitProvenanceError as exc:
        fail(f"release index Git provenance is not current: {exc}")
    require(
        current_dirty is dirty,
        "release index source_tree_dirty differs from the current worktree",
    )
    if channel == "release":
        require(dirty is False, "release channel index has dirty source provenance")
    expected_index_path = normalized_absolute(
        root
        / "target"
        / "qperiapt-local-release"
        / channel
        / index_version
        / commit
        / "index.json"
    )
    require(
        identity_index_path == expected_index_path,
        "release index path differs from its channel/version/commit identity",
    )

    require_exact_json(
        index.get("release_boundary"),
        {
            "public_release": False,
            "registry_uploaded": False,
            "raw_device_proofs_copied": False,
            "requires_clean_tree_for_release": True,
            "cryptographic_attestation": False,
            "leaf_gate_receipts_embedded": False,
            "local_artifact_store_trusted": True,
        },
        "release index boundary",
    )

    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list), "release index artifacts are malformed")
    require(
        len(artifacts) == len(EXPECTED_FACES),
        "release index must have exactly three package faces",
    )
    release_root = index_path.parent
    seen_faces: set[str] = set()
    declared_files = {index_path.relative_to(release_root).as_posix()}
    semantics: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        artifact = require_exact_object(
            artifact,
            frozenset(
                {
                    "id",
                    "face",
                    "type",
                    "files",
                    "manifest",
                    "sha256s",
                    "package_semantics",
                    "boundary",
                    "required_leaf_gate",
                    "targets",
                }
            ),
            "release artifact entry",
        )
        face = artifact.get("face")
        require(
            isinstance(face, str) and face in EXPECTED_FACES,
            f"unsupported artifact face: {face}",
        )
        require(face not in seen_faces, f"duplicate artifact face: {face}")
        seen_faces.add(face)
        files = artifact.get("files")
        require(
            isinstance(files, list) and len(files) == 1,
            f"artifact {face} must declare exactly one package file",
        )
        package_files = [verify_index_file(release_root, files[0])]
        manifest_path = verify_index_file(release_root, artifact.get("manifest"))
        sha256s_path = verify_index_file(release_root, artifact.get("sha256s"))
        for declared_path in (*package_files, manifest_path, sha256s_path):
            relative = declared_path.relative_to(release_root).as_posix()
            require(
                relative not in declared_files,
                f"release index declares one file more than once: {relative}",
            )
            declared_files.add(relative)
        manifest = validate_package_manifest(
            manifest_path,
            commit,
            trust.version,
            channel,
            face,
            trust,
        )
        validate_indexed_artifact_contract(face, artifact, manifest)
        semantic = normalized_package_semantics(manifest)
        require(
            artifact.get("package_semantics") == semantic,
            f"{face} indexed package semantics differ from copied manifest",
        )
        semantics[face] = semantic
        validate_artifact_binding(
            face, manifest, manifest_path, sha256s_path, package_files
        )
    require(seen_faces == EXPECTED_FACES, "release index package faces are incomplete")
    validate_cross_face_semantics(semantics)

    proofs = index.get("proof_summaries")
    require(isinstance(proofs, dict), "release index proof_summaries must be an object")
    for proof_name, proof in proofs.items():
        require(isinstance(proof, dict), f"proof summary is malformed: {proof_name}")
        validate_sanitized_proof_summary(proof_name, proof)
        proof_dirty = proof["source_tree_dirty"]
        if channel == "release":
            require(
                not proof_dirty,
                f"release index includes diagnostic proof summary: {proof_name}",
            )
            if proof_name == "android_runtime":
                validate_android_release_summary_contract(proof)

    verify_sha256s(
        release_root,
        expected_file_set=declared_files,
        pinned_digests={"index.json": snapshot.file.sha256},
    )
    return VerifiedReleaseIndex(
        path=index_path,
        sha256=snapshot.file.sha256,
        value=index,
    )


def verify_release_index(
    index_path: pathlib.Path,
    root: pathlib.Path,
    *,
    allow_diagnostic: bool,
    expected_index_sha256: str | None = None,
    expected_generated_at: str | None = None,
) -> dict[str, Any]:
    return verify_release_index_snapshot(
        index_path,
        root,
        allow_diagnostic=allow_diagnostic,
        expected_index_sha256=expected_index_sha256,
        expected_generated_at=expected_generated_at,
    ).value


def requested_proof_summaries(
    args: argparse.Namespace,
    *,
    root: pathlib.Path,
    target: pathlib.Path,
    channel: str,
    commit: str,
) -> dict[str, Any]:
    """Load exactly the proof summaries selected by one emit invocation."""

    proofs: dict[str, Any] = {}
    if args.apple_matrix_run:
        run_leaf = require_safe_basename(
            args.apple_matrix_run, "Apple matrix run selector"
        )
        apple_path = (
            root
            / "artifact"
            / "device-runs"
            / run_leaf
            / "apple-device-matrix-proof.json"
        )
        require_no_symlink_components(
            apple_path,
            root / "artifact" / "device-runs",
            "Apple matrix proof",
        )
        try:
            apple_snapshot = load_json_object_snapshot(
                apple_path,
                label="apple_matrix proof",
            )
        except EvidenceIOError as exc:
            fail(str(exc))
        proofs["apple_matrix"] = proof_summary_snapshot(
            apple_snapshot,
            "apple_matrix",
            expected_commit=commit,
        )
    if args.android_runtime_run:
        android_run = require_safe_basename(
            args.android_runtime_run, "Android runtime run selector"
        )
        require(
            re.fullmatch(r"[0-9a-f]{32}", android_run) is not None,
            "Android runtime run selector must be 32 lowercase hex characters",
        )
        android_path = (
            target
            / "qperiapt-android-device-smoke-runs"
            / android_run
            / "proof"
            / "qperiapt-android-device-proof.json"
        )
        require_no_symlink_components(
            android_path,
            target,
            "Android runtime proof",
        )
        try:
            android_snapshot = load_json_object_snapshot(
                android_path,
                label="android_runtime proof",
            )
        except EvidenceIOError as exc:
            fail(str(exc))
        require(
            android_snapshot.value.get("run_id") == android_run,
            "Android runtime proof run id differs from its selected run directory",
        )
        if channel == "release":
            # Import lazily so release-index-only consumers do not gain a
            # second Android implementation.  The complete runtime verifier,
            # not a hand-written summary check, owns release-mode semantics.
            import android_device_proof

            android_device_proof.verify_proof_freshness(android_snapshot.value, 86_400)
            android_paths = android_device_proof.proof_paths(
                root, android_snapshot.value
            )
            android_device_proof.validate_selected_run_layout(
                root,
                android_path,
                android_snapshot.value,
                android_paths,
                require_unique_run=True,
            )
            android_device_proof.verify_proof_contents(
                root,
                android_snapshot.value,
                android_paths,
                expected_device_kind=ANDROID_RELEASE_DEVICE_KIND,
                expected_device_abi=ANDROID_RELEASE_DEVICE_ABI,
                expected_page_size=ANDROID_RELEASE_PAGE_SIZE,
                expected_device_sdk=ANDROID_RELEASE_DEVICE_SDK,
                require_release_mode=True,
                allow_dirty_proof=False,
            )
        proofs["android_runtime"] = proof_summary_snapshot(
            android_snapshot,
            "android_runtime",
            expected_commit=commit,
        )
    if channel == "release":
        for proof_name, proof in proofs.items():
            require(
                proof["source_tree_dirty"] is False,
                f"release index cannot include dirty {proof_name} proof summary",
            )
    return proofs


def release_pointer_value(
    *,
    target: pathlib.Path,
    index_path: pathlib.Path,
    index_sha256: str,
    version: str,
    channel: str,
    generated_at: str,
) -> dict[str, Any]:
    canonical_channel = require_release_channel(channel)
    canonical_version = require_safe_basename(version, "release pointer version")
    canonical_generated_at = require_utc_timestamp(
        generated_at,
        "release pointer generated_at",
    )
    require(
        HEX_SHA256.fullmatch(index_sha256) is not None,
        "release pointer index digest is malformed",
    )
    require_strictly_under(
        index_path,
        target / "qperiapt-local-release" / canonical_channel,
        "release pointer index",
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": POINTER_KIND,
        "version": canonical_version,
        "channel": canonical_channel,
        "diagnostic_only": canonical_channel == "diagnostic",
        "index_path": str(index_path.relative_to(target)),
        "index_sha256": index_sha256,
        "generated_at": canonical_generated_at,
    }


def _pointer_already_matches(
    pointer_path: pathlib.Path,
    pointer: dict[str, Any],
) -> bool:
    try:
        metadata = pointer_path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        fail(f"cannot inspect existing release pointer {pointer_path}: {exc}")
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_nlink == 1,
        f"existing release pointer is not one current-user regular file: {pointer_path}",
    )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        return False
    expected = (json.dumps(pointer, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        snapshot = read_regular_snapshot(
            pointer_path,
            maximum=MAX_TEXT_BYTES,
            label="release pointer",
        )
    except EvidenceIOError as exc:
        fail(str(exc))
    return snapshot.data == expected


def cleanup_stale_release_pointer_files(pointer_path: pathlib.Path) -> None:
    """Remove exact private-writer remnants and durably sync the pointer parent."""

    prefix = f".{pointer_path.name}.private-"
    directory_fd = _open_private_directory(
        pointer_path.parent,
        "release pointer parent",
    )
    primary: BaseException | None = None
    try:
        try:
            entries = os.scandir(directory_fd)
        except OSError as exc:
            fail(
                f"cannot enumerate release pointer parent {pointer_path.parent}: {exc}"
            )
        with entries:
            parent_entry_count = 0
            stale_entries: list[tuple[str, tuple[int, int]]] = []
            for entry in entries:
                parent_entry_count += 1
                require(
                    parent_entry_count <= MAX_RELEASE_STAGING_PARENT_ENTRIES,
                    "release pointer parent exceeds its entry limit",
                )
                name = entry.name
                if not name.startswith(prefix):
                    continue
                require(
                    len(stale_entries) < MAX_STALE_RELEASE_POINTER_FILES,
                    "release pointer parent has too many stale private files",
                )
                suffix = name[len(prefix) :]
                require(
                    len(suffix) == 32
                    and all(character in "0123456789abcdef" for character in suffix),
                    f"release pointer remnant has an invalid owned name: {name}",
                )
                try:
                    metadata = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    fail(f"cannot inspect stale release pointer file {name}: {exc}")
                require(
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_uid == os.geteuid()
                    and metadata.st_nlink == 1
                    and stat.S_IMODE(metadata.st_mode) == 0o600,
                    f"stale release pointer entry is not one owned private file: {name}",
                )
                stale_entries.append((name, (metadata.st_dev, metadata.st_ino)))
        for name, expected_identity in stale_entries:
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                fail(f"cannot recheck stale release pointer file {name}: {exc}")
            require(
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == os.geteuid()
                and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and (metadata.st_dev, metadata.st_ino) == expected_identity,
                f"stale release pointer entry changed before cleanup: {name}",
            )
        for name, _identity in stale_entries:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError as exc:
                fail(f"cannot remove stale release pointer file {name}: {exc}")
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            fail(
                "cannot synchronize release pointer parent "
                f"{pointer_path.parent}: {exc}"
            )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(directory_fd)
        except BaseException as cleanup_error:
            if primary is not None:
                primary.add_note(
                    f"closing the release pointer parent also failed: {cleanup_error}"
                )
            elif isinstance(cleanup_error, Exception):
                fail(
                    "cannot close release pointer parent "
                    f"{pointer_path.parent}: {cleanup_error}"
                )
            else:
                raise


def recover_verified_release_pointer(
    *,
    root: pathlib.Path,
    target: pathlib.Path,
    release_root: pathlib.Path,
    channel: str,
    requested_proofs: dict[str, Any],
) -> bool:
    """Select a fully verified final tree left before its pointer commit."""

    try:
        metadata = release_root.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        fail(f"cannot inspect recoverable release tree {release_root}: {exc}")
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        f"recoverable release tree is not one owned private directory: {release_root}",
    )
    verified = verify_release_index_snapshot(
        release_root / "index.json",
        root,
        allow_diagnostic=channel == "diagnostic",
    )
    require_exact_json(
        verified.value.get("proof_summaries"),
        requested_proofs,
        "recoverable release proof selectors",
    )
    pointer = release_pointer_value(
        target=target,
        index_path=verified.path,
        index_sha256=verified.sha256,
        version=verified.value["version"],
        channel=verified.value["channel"],
        generated_at=verified.value["generated_at"],
    )
    pointer_path = target / "qperiapt-local-release" / f"latest-{channel}.json"
    with _release_pointer_lock(pointer_path):
        cleanup_stale_release_pointer_files(pointer_path)
        previous = _existing_release_pointer(pointer_path)
        _validate_pointer_replacement(
            root=root,
            pointer_path=pointer_path,
            previous=previous,
            current=pointer,
        )
        if _pointer_already_matches(pointer_path, pointer):
            return True
        write_json(pointer_path, pointer)
        _verify_published_pointer(pointer_path, pointer)
    selection = release_pointer_selection(root, channel)
    require_exact_json(selection.path, verified.path, "recovered release pointer path")
    verify_release_index_snapshot(
        selection.path,
        root,
        allow_diagnostic=channel == "diagnostic",
        expected_index_sha256=selection.expected_sha256,
        expected_generated_at=selection.expected_generated_at,
    )
    return True


def build_release_tree(
    *,
    root: pathlib.Path,
    target: pathlib.Path,
    release_root: pathlib.Path,
    identity_index_path: pathlib.Path,
    channel: str,
    trust: AbiTrustRoot,
    version: str,
    commit: str,
    current_dirty: bool,
    c_dir: pathlib.Path,
    c_manifest_path: pathlib.Path,
    c_archive: pathlib.Path,
    swift_dir: pathlib.Path,
    swift_manifest_path: pathlib.Path,
    swift_zip: pathlib.Path,
    android_dir: pathlib.Path,
    android_manifest_path: pathlib.Path,
    android_aar: pathlib.Path,
    source_semantics: dict[str, dict[str, Any]],
    artifact_contracts: dict[str, dict[str, Any]],
    proofs: dict[str, Any],
) -> BuiltReleaseTree:
    artifacts = [
        artifact_entry(
            artifact_contracts["c-abi"]["id"],
            "c-abi",
            artifact_contracts["c-abi"]["type"],
            [
                copy_to_release(
                    c_archive, target, release_root, f"packages/c/{c_archive.name}"
                )
            ],
            copy_to_release(
                c_manifest_path, target, release_root, "manifests/c/MANIFEST.json"
            ),
            copy_to_release(
                c_dir / "SHA256SUMS", target, release_root, "manifests/c/SHA256SUMS"
            ),
            artifact_contracts["c-abi"]["boundary"],
            artifact_contracts["c-abi"]["required_leaf_gate"],
            artifact_contracts["c-abi"]["targets"],
            source_semantics["c-abi"],
        ),
        artifact_entry(
            artifact_contracts["swift"]["id"],
            "swift",
            artifact_contracts["swift"]["type"],
            [
                copy_to_release(
                    swift_zip,
                    target,
                    release_root,
                    "packages/swift/CQPeriapt.xcframework.zip",
                )
            ],
            copy_to_release(
                swift_manifest_path,
                target,
                release_root,
                "manifests/swift/MANIFEST.json",
            ),
            copy_to_release(
                swift_dir / "SHA256SUMS",
                target,
                release_root,
                "manifests/swift/SHA256SUMS",
            ),
            artifact_contracts["swift"]["boundary"],
            artifact_contracts["swift"]["required_leaf_gate"],
            artifact_contracts["swift"]["targets"],
            source_semantics["swift"],
        ),
        artifact_entry(
            artifact_contracts["android"]["id"],
            "android",
            artifact_contracts["android"]["type"],
            [
                copy_to_release(
                    android_aar,
                    target,
                    release_root,
                    f"packages/android/{android_aar.name}",
                )
            ],
            copy_to_release(
                android_manifest_path,
                target,
                release_root,
                "manifests/android/MANIFEST.json",
            ),
            copy_to_release(
                android_dir / "SHA256SUMS",
                target,
                release_root,
                "manifests/android/SHA256SUMS",
            ),
            artifact_contracts["android"]["boundary"],
            artifact_contracts["android"]["required_leaf_gate"],
            artifact_contracts["android"]["targets"],
            source_semantics["android"],
        ),
    ]

    index = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "version": version,
        "channel": channel,
        "diagnostic_only": channel == "diagnostic",
        "generated_at": utc_now(),
        "abi": {
            "major": ABI_MAJOR,
            "contract_path": CONTRACT_RELATIVE_PATH.as_posix(),
            "contract_sha256": trust.contract_sha256,
            "exports_sha256": trust.exports_sha256,
            "export_count": EXPORT_COUNT,
        },
        "git": {"commit": commit, "source_tree_dirty": current_dirty},
        "release_boundary": {
            "public_release": False,
            "registry_uploaded": False,
            "raw_device_proofs_copied": False,
            "requires_clean_tree_for_release": True,
            "cryptographic_attestation": False,
            "leaf_gate_receipts_embedded": False,
            "local_artifact_store_trusted": True,
        },
        "artifacts": artifacts,
        "proof_summaries": proofs,
    }
    index_path = release_root / "index.json"
    write_json(index_path, index)
    write_release_sums(release_root)
    verified_index = verify_release_index_snapshot(
        index_path,
        root,
        allow_diagnostic=True,
        identity_index_path=identity_index_path,
    )
    return BuiltReleaseTree(
        index_path=index_path,
        index_sha256=verified_index.sha256,
        generated_at=index["generated_at"],
    )


def _build_index_locked(args: argparse.Namespace) -> pathlib.Path:
    root = REPOSITORY_ROOT
    channel = require_release_channel(args.channel)
    trust = load_abi_trust_root(root)
    version = require_safe_basename(cargo_version(root), "Cargo package version")
    require(
        version == trust.version,
        f"Cargo version {version} differs from ABI contract {trust.version}",
    )
    commit = require_safe_basename(git_commit(root), "Git commit")
    require(GIT_COMMIT.fullmatch(commit) is not None, "Git commit is malformed")
    current_dirty = git_dirty(root)
    if channel == "release":
        require(not current_dirty, "release index requires a clean source tree")

    target = root / "target"
    release_root = release_output_identity(
        root,
        channel=channel,
        version=version,
        commit=commit,
    )
    requested_proofs = requested_proof_summaries(
        args,
        root=root,
        target=target,
        channel=channel,
        commit=commit,
    )
    if recover_verified_release_pointer(
        root=root,
        target=target,
        release_root=release_root,
        channel=channel,
        requested_proofs=requested_proofs,
    ):
        final_index_path = release_root / "index.json"
        print(f"QPERIAPT_LOCAL_RELEASE_INDEX={final_index_path}")
        return final_index_path
    release_root = resolve_release_output(
        root,
        channel=channel,
        version=version,
        commit=commit,
    )

    host = require_safe_basename(rust_host(), "Rust host")
    require(host in C_HOST_PLATFORMS, f"Rust host is unsupported: {host}")

    c_package = f"{trust.archive_prefix}-{version}-{host}"
    c_dir = target / "qperiapt-c-abi2" / c_package
    c_manifest_path = c_dir / "MANIFEST.json"
    c_archive = target / "qperiapt-c-abi2" / f"{c_package}.tar.gz"
    swift_dir = target / "qperiapt-swift-xcframework" / f"q-periapt-swift-{version}"
    swift_manifest_path = swift_dir / "MANIFEST.json"
    swift_zip = swift_dir / "CQPeriapt.xcframework.zip"
    android_dir = target / "qperiapt-android-aar" / f"q-periapt-android-{version}"
    android_manifest_path = android_dir / "MANIFEST.json"
    android_aar = android_dir / f"q-periapt-android-{version}.aar"
    input_paths = [c_dir, c_archive, swift_dir, swift_zip, android_dir, android_aar]
    require_disjoint_output(release_root, input_paths)

    for package_dir in (c_dir, swift_dir, android_dir):
        require_no_symlink_components(package_dir, target, "release package directory")
        require(
            package_dir.is_dir(), f"release package directory missing: {package_dir}"
        )
    for package_file in (c_archive, swift_zip, android_aar):
        require_no_symlink_components(package_file, target, "release package file")
        require(package_file.is_file(), f"release package file missing: {package_file}")

    verify_sha256s(c_dir)
    c_manifest = validate_package_manifest(
        c_manifest_path, commit, version, channel, "c-abi", trust
    )
    verify_sha256s(swift_dir)
    swift_manifest = validate_package_manifest(
        swift_manifest_path, commit, version, channel, "swift", trust
    )
    verify_sha256s(android_dir)
    android_manifest = validate_package_manifest(
        android_manifest_path, commit, version, channel, "android", trust
    )
    source_semantics = {
        "c-abi": normalized_package_semantics(c_manifest),
        "swift": normalized_package_semantics(swift_manifest),
        "android": normalized_package_semantics(android_manifest),
    }
    validate_cross_face_semantics(source_semantics)
    artifact_contracts = {
        "c-abi": indexed_artifact_contract("c-abi", c_manifest),
        "swift": indexed_artifact_contract("swift", swift_manifest),
        "android": indexed_artifact_contract("android", android_manifest),
    }
    cleanup_stale_release_staging_trees(release_root, target)

    staging_root: pathlib.Path | None = None
    staging_identity: tuple[int, int] | None = None
    publication_started = False
    final_index_path = release_root / "index.json"

    try:
        staging_root, staging_identity = create_release_staging_tree(
            release_root,
            target,
        )

        built = build_release_tree(
            root=root,
            target=target,
            release_root=staging_root,
            identity_index_path=final_index_path,
            channel=channel,
            trust=trust,
            version=version,
            commit=commit,
            current_dirty=current_dirty,
            c_dir=c_dir,
            c_manifest_path=c_manifest_path,
            c_archive=c_archive,
            swift_dir=swift_dir,
            swift_manifest_path=swift_manifest_path,
            swift_zip=swift_zip,
            android_dir=android_dir,
            android_manifest_path=android_manifest_path,
            android_aar=android_aar,
            source_semantics=source_semantics,
            artifact_contracts=artifact_contracts,
            proofs=requested_proofs,
        )
        pointer = release_pointer_value(
            target=target,
            index_path=final_index_path,
            index_sha256=built.index_sha256,
            version=version,
            channel=channel,
            generated_at=built.generated_at,
        )
        release_base = target / "qperiapt-local-release"
        protect_private_directory(release_base, "release pointer")
        pointer_path = release_base / f"latest-{channel}.json"
        publication_started = True
        publish_release_transaction(
            staging_root=staging_root,
            release_root=release_root,
            staging_identity=staging_identity,
            target=target,
            pointer_path=pointer_path,
            pointer=pointer,
        )
    except BaseException as primary:
        if staging_identity is not None and not publication_started:
            try:
                remove_unpublished_release_tree(
                    staging_root,
                    target,
                    expected_identity=staging_identity,
                )
            except BaseException as cleanup_error:
                primary.add_note(
                    "unpublished release staging cleanup also failed for "
                    f"{staging_root}: {cleanup_error}"
                )
        raise

    print(f"QPERIAPT_LOCAL_RELEASE_INDEX={final_index_path}")
    return final_index_path


def build_index(args: argparse.Namespace) -> pathlib.Path:
    target = REPOSITORY_ROOT / "target"
    with release_emit_lock(target):
        return _build_index_locked(args)


def verify_index_command(args: argparse.Namespace) -> None:
    root = REPOSITORY_ROOT
    channel = require_release_channel(args.channel)
    selection = release_pointer_selection(root, channel)
    require(
        channel == "release" or args.allow_diagnostic,
        "diagnostic release verification requires --allow-diagnostic",
    )
    verify_release_index(
        selection.path,
        root,
        allow_diagnostic=args.allow_diagnostic,
        expected_index_sha256=selection.expected_sha256,
        expected_generated_at=selection.expected_generated_at,
    )
    print("QPERIAPT_LOCAL_RELEASE_INDEX_VERIFY_PASS")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    emit = sub.add_parser("emit")
    emit.add_argument("--channel", choices=["release", "diagnostic"], default="release")
    emit.add_argument("--apple-matrix-run", default="")
    emit.add_argument("--android-runtime-run", default="")
    emit.set_defaults(func=build_index)

    verify = sub.add_parser("verify")
    verify.add_argument(
        "--channel", choices=["release", "diagnostic"], default="release"
    )
    verify.add_argument("--allow-diagnostic", action="store_true")
    verify.set_defaults(func=verify_index_command)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
