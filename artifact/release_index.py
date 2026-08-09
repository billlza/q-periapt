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
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from typing import Any, NoReturn

from evidence_io import (
    EvidenceIOError,
    load_json_object_snapshot,
    parse_strict_json_bytes,
)
from git_provenance import (
    GitProvenanceError,
    git_commit as provenance_git_commit,
    require_commit_or_evidence_successor,
    source_tree_dirty as provenance_source_tree_dirty,
)


@dataclass(frozen=True)
class PackageManifestContract:
    schema_version: int
    kind: str | None
    manifest_fields: frozenset[str]
    abi_fields: frozenset[str]


SCHEMA_VERSION = 3
KIND = "qperiapt.local_release_index"
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


@dataclass(frozen=True)
class RegularFileDigest:
    size: int
    sha256: str


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


def require_safe_string_list(value: Any, expected: tuple[str, ...], label: str) -> list[str]:
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
    require(not path.is_symlink(), f"file must not be a symlink: {path}")
    require(path.is_file(), f"file is missing or not regular: {path}")
    try:
        with path.open("rb") as handle:
            value = handle.read(maximum + 1)
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")
    require(len(value) <= maximum, f"file exceeds {maximum} bytes: {path}")
    return value


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


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    require(not path.is_symlink(), f"JSON output must not be a symlink: {path}")
    try:
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        fail(f"cannot write {path}: {exc}")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def open_bounded_regular_descriptor(
    path: pathlib.Path, *, maximum: int, label: str
) -> tuple[int, os.stat_result]:
    require(type(maximum) is int and maximum > 0, f"{label} maximum must be positive")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot safely open {label} {path}: {exc}")
    try:
        observed = os.fstat(descriptor)
        require(stat.S_ISREG(observed.st_mode), f"{label} is not regular: {path}")
        require(observed.st_size <= maximum, f"{label} exceeds {maximum} bytes: {path}")
        return descriptor, observed
    except BaseException:
        os.close(descriptor)
        raise


def stable_file_identity(observed: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def digest_regular_file(
    path: pathlib.Path,
    *,
    maximum: int = MAX_INDEXED_FILE_BYTES,
    label: str = "hash input",
) -> RegularFileDigest:
    descriptor, before = open_bounded_regular_descriptor(
        path, maximum=maximum, label=label
    )
    hasher = hashlib.sha256()
    total = 0
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            require(total <= maximum, f"{label} exceeds {maximum} bytes: {path}")
            hasher.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        fail(f"cannot hash {path}: {exc}")
    finally:
        os.close(descriptor)
    require(
        stable_file_identity(before) == stable_file_identity(after)
        and total == before.st_size,
        f"file changed while hashing: {path}",
    )
    return RegularFileDigest(size=total, sha256=hasher.hexdigest())


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
    require(candidate != parent, f"{label} must be a dedicated subdirectory of {parent}")


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
        require(not current.is_symlink(), f"{label} must not traverse a symlink: {current}")


def require_relative_safe(path: str, label: str) -> None:
    require(path and not path.startswith(("/", "\\")), f"{label} must be relative: {path}")
    require("\\" not in path, f"{label} must use POSIX separators: {path}")
    require(
        all(ord(character) >= 32 and ord(character) != 127 for character in path),
        f"{label} contains a control character",
    )
    pure = pathlib.PurePosixPath(path)
    require(
        all(part not in {"", ".", ".."} for part in pure.parts),
        f"{label} contains an unsafe component: {path}",
    )


def require_safe_basename(value: Any, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    require("/" not in value and "\\" not in value, f"{label} must be a basename")
    require(value not in {".", ".."}, f"{label} must be a safe basename")
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", value) is not None,
        f"{label} contains unsupported characters",
    )
    return value


def resolve_release_output(
    root: pathlib.Path,
    raw_output: str,
    *,
    channel: str,
    version: str,
    commit: str,
) -> pathlib.Path:
    target = normalized_absolute(root / "target")
    release_base = target / "qperiapt-local-release"
    channel_base = release_base / channel
    raw_path = pathlib.Path(raw_output) if raw_output else channel_base / version / commit
    if not raw_path.is_absolute():
        raw_path = root / raw_path
    output = normalized_absolute(raw_path)
    require_strictly_under(output, channel_base, "release index output")
    require_no_symlink_components(output, target, "release index output")
    if output.exists():
        require(output.is_dir(), f"release index output exists but is not a directory: {output}")
    return output


def require_disjoint_output(
    output: pathlib.Path, inputs: list[pathlib.Path]
) -> None:
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
        require(not overlap, f"release index output overlaps input package path: {source_abs}")


def load_abi_trust_root(root: pathlib.Path) -> AbiTrustRoot:
    contract_path = root / pathlib.Path(CONTRACT_RELATIVE_PATH)
    require_no_symlink_components(contract_path, root, "ABI contract")
    contract = load_json(contract_path)
    require_exact_int(contract.get("schema"), 1, "ABI contract schema")
    require(contract.get("kind") == "qperiapt.c_abi_contract", "ABI contract kind mismatch")
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
    require(names == EXPECTED_EXPORT_NAMES, "ABI contract exact 9-export allowlist mismatch")
    package = contract.get("package")
    require(isinstance(package, dict), "ABI contract package object is missing")
    version = package.get("semver")
    archive_prefix = package.get("archive_prefix")
    platforms = package.get("platforms")
    require(isinstance(version, str) and version, "ABI contract package semver is malformed")
    require(
        isinstance(archive_prefix, str) and archive_prefix,
        "ABI contract archive prefix is malformed",
    )
    require(isinstance(platforms, dict) and platforms, "ABI contract platforms are malformed")
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
    require_relative_safe(rel, "release artifact path")
    require_no_symlink_components(src, source_base, "release artifact source")
    require(src.is_file(), f"release artifact source missing: {src}")
    dst = release_root / pathlib.Path(rel)
    require_no_symlink_components(dst, release_root, "release artifact output")
    destination_created = False
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        source_descriptor, before = open_bounded_regular_descriptor(
            src,
            maximum=MAX_INDEXED_FILE_BYTES,
            label="release artifact source",
        )
        try:
            total = 0
            source_hasher = hashlib.sha256()
            with dst.open("xb") as output:
                destination_created = True
                while chunk := os.read(source_descriptor, 1024 * 1024):
                    total += len(chunk)
                    require(
                        total <= MAX_INDEXED_FILE_BYTES,
                        f"release artifact source grew beyond {MAX_INDEXED_FILE_BYTES} bytes: {src}",
                    )
                    written = output.write(chunk)
                    require(
                        written == len(chunk),
                        f"short write while copying release artifact: {dst}",
                    )
                    source_hasher.update(chunk)
            after = os.fstat(source_descriptor)
            require(
                stable_file_identity(before) == stable_file_identity(after)
                and total == before.st_size,
                f"release artifact source changed while copying: {src}",
            )
        finally:
            os.close(source_descriptor)
        os.chmod(dst, 0o644)
    except BaseException as exc:
        if destination_created:
            try:
                dst.unlink(missing_ok=True)
            except OSError as cleanup_error:
                exc.add_note(f"cannot remove incomplete release copy {dst}: {cleanup_error}")
        if isinstance(exc, SystemExit):
            raise
        if isinstance(exc, OSError):
            fail(f"cannot copy release artifact {src} to {dst}: {exc}")
        raise
    return {"path": rel, "sha256": source_hasher.hexdigest(), "bytes": total}


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
        expected, rel = parts
        require(
            HEX_SHA256.fullmatch(expected) is not None,
            f"malformed sha256 at {sums}:{line_no}",
        )
        require_relative_safe(rel, f"SHA256SUMS path at {sums}:{line_no}")
        require(rel not in parsed, f"duplicate SHA256SUMS path at {sums}:{line_no}: {rel}")
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
    base: pathlib.Path, *, expected_file_set: set[str] | None = None
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
        target = base / pathlib.Path(rel)
        require_no_symlink_components(target, base, "SHA256SUMS target")
        require(target.is_file(), f"SHA256SUMS target missing: {target}")
        require(sha256_file(target) == expected, f"SHA256SUMS hash mismatch for {target}")


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
    require_exact_object(
        manifest, contract.manifest_fields, f"{face} manifest"
    )
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
    require(commit == expected_commit, f"{face} manifest commit mismatch: {commit} != {expected_commit}")
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
    validate_runtime_identity(abi.get("runtime_identity"), f"{face} ABI runtime_identity")

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
        require(expected_identity is not None, f"C ABI platform is not in contract: {platform}")
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
        require(package == "q-periapt-swift", f"Swift package name is invalid: {package}")
        require_exact_json(
            manifest.get("type"), SWIFT_PACKAGE_TYPE, "Swift manifest type"
        )
        targets = require_safe_string_list(
            manifest.get("targets"), SWIFT_TARGETS, "Swift manifest targets"
        )
        release_identity = {
            "product_version": expected_version,
            "revision": "r1",
            "tag": f"v{expected_version}-r1",
            "url": (
                "https://github.com/billlza/q-periapt/releases/tag/"
                f"v{expected_version}-r1"
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
    require(set(semantics) == EXPECTED_FACES, "release index must contain C, Swift, and Android faces")
    reference = semantics["c-abi"]
    for face, current in semantics.items():
        require(current["version"] == reference["version"], f"{face} package version differs across faces")
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


def proof_summary(path: pathlib.Path, proof_kind: str) -> dict[str, Any]:
    try:
        snapshot = load_json_object_snapshot(
            path,
            label=f"{proof_kind} proof",
        )
    except EvidenceIOError as exc:
        fail(str(exc))
    proof = snapshot.value
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
                    "device_id_sha256_prefix": str(item.get("device_id_sha256", ""))[:12],
                    "run_id": item.get("run_id"),
                }
            )
        summary["devices"] = devices
    elif proof_kind == "android_runtime":
        device = proof.get("device")
        result = proof.get("result")
        require(isinstance(device, dict) and isinstance(result, dict), "Android proof is malformed")
        summary["device"] = {
            "kind": device.get("kind"),
            "model": device.get("model"),
            "sdk": device.get("sdk"),
            "abi": device.get("abi"),
            "serial_sha256_prefix": device.get("serial_sha256_prefix"),
            "raw_serial_recorded": device.get("raw_serial_recorded"),
        }
        summary["result"] = {
            "run_id": proof.get("run_id"),
            "test_count": result.get("test_count"),
            "passed_tests": result.get("passed_tests"),
        }
    validate_sanitized_proof_summary(proof_kind, summary)
    return summary


def validate_sanitized_proof_summary(
    proof_name: str, proof: dict[str, Any]
) -> None:
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
        "android_runtime": {"device", "result"},
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
        require(isinstance(devices, list), "Apple matrix summary devices must be a list")
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
            {"kind", "model", "sdk", "abi", "serial_sha256_prefix", "raw_serial_recorded"}
        ),
        "Android proof summary device",
    )
    require(device.get("kind") in {"physical", "emulator"}, "Android device kind is invalid")
    require_bounded_text(device.get("model"), "Android device model")
    require(
        type(device.get("sdk")) is int and device["sdk"] > 0,
        "Android device SDK must be a positive integer",
    )
    require(device.get("abi") in ANDROID_ABIS, "Android device ABI is invalid")
    require(
        isinstance(device.get("serial_sha256_prefix"), str)
        and re.fullmatch(r"[0-9a-f]{12}", device["serial_sha256_prefix"])
        is not None,
        "Android serial hash prefix is malformed",
    )
    require_exact_json(
        device.get("raw_serial_recorded"), False, "Android raw_serial_recorded"
    )
    result = require_exact_object(
        proof.get("result"),
        frozenset({"run_id", "test_count", "passed_tests"}),
        "Android proof summary result",
    )
    require(
        isinstance(result.get("run_id"), str)
        and re.fullmatch(r"[0-9a-f]{32}", result["run_id"]) is not None,
        "Android result run_id is malformed",
    )
    test_count = result.get("test_count")
    passed_tests = result.get("passed_tests")
    require(type(test_count) is int and test_count > 0, "Android test_count is invalid")
    require(isinstance(passed_tests, list), "Android passed_tests must be a list")
    require(len(passed_tests) == test_count, "Android passed_tests count differs")
    require(
        all(isinstance(name, str) and name for name in passed_tests),
        "Android passed_tests contains a malformed name",
    )
    require(len(passed_tests) == len(set(passed_tests)), "Android passed_tests contains duplicates")


def validate_index_text(index_path: pathlib.Path) -> None:
    text = read_text(index_path)
    for forbidden in FORBIDDEN_INDEX_TEXT:
        require(forbidden not in text, f"release index contains private/local token: {forbidden}")


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
        require_relative_safe(rel, "release SHA256SUMS path")
        lines.append(f"{sha256_file(path)}  {rel}")
    sums = release_root / "SHA256SUMS"
    require(not sums.is_symlink(), f"release SHA256SUMS must not be a symlink: {sums}")
    try:
        sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        fail(f"cannot write release SHA256SUMS {sums}: {exc}")


def verify_index_file(release_root: pathlib.Path, item: Any) -> pathlib.Path:
    item = require_exact_object(
        item, frozenset({"path", "sha256", "bytes"}), "indexed file entry"
    )
    rel = item.get("path")
    expected = item.get("sha256")
    size = item.get("bytes")
    require(isinstance(rel, str), "indexed file path is missing")
    require(
        isinstance(expected, str) and HEX_SHA256.fullmatch(expected) is not None,
        f"indexed file hash is malformed: {rel}",
    )
    require(
        type(size) is int and 0 <= size <= MAX_INDEXED_FILE_BYTES,
        f"indexed file byte count is malformed or too large: {rel}",
    )
    require_relative_safe(rel, "indexed file path")
    path = release_root / pathlib.Path(rel)
    require_no_symlink_components(path, release_root, "indexed file")
    observed = digest_regular_file(path, label="indexed file")
    require(observed.size == size, f"indexed file byte count mismatch: {rel}")
    require(observed.sha256 == expected, f"indexed file hash mismatch: {rel}")
    return path


def decompress_single_gzip_member(
    descriptor: int,
    output: Any,
    *,
    expected_compressed_size: int,
    label: str,
) -> int:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    compressed_size = 0
    decompressed_size = 0
    while chunk := os.read(descriptor, 1024 * 1024):
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
    require(archive.name.endswith(".tar.gz"), f"C archive filename is invalid: {archive}")
    require(
        suffix in {"/MANIFEST.json", "/SHA256SUMS"},
        f"unsupported C archive metadata path: {suffix}",
    )
    expected_root = archive.name.removesuffix(".tar.gz")
    expected_member = f"{expected_root}{suffix}"
    descriptor, before = open_bounded_regular_descriptor(
        archive,
        maximum=MAX_TAR_ARCHIVE_BYTES,
        label="C archive",
    )
    try:
        with tempfile.SpooledTemporaryFile(
            max_size=8 * 1024 * 1024, mode="w+b"
        ) as decompressed:
            decompressed_size = decompress_single_gzip_member(
                descriptor,
                decompressed,
                expected_compressed_size=before.st_size,
                label="C archive",
            )
            after = os.fstat(descriptor)
            require(
                stable_file_identity(before) == stable_file_identity(after),
                f"C archive changed while inspecting: {archive}",
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
                    accepted_name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                    require(
                        accepted_name == canonical,
                        f"non-canonical C archive path: {member.name}",
                    )
                    require_relative_safe(canonical, "C archive member")
                    require(
                        pure.parts[0] == expected_root,
                        f"C archive member is outside {expected_root}: {member.name}",
                    )
                    require(
                        ":" not in pure.parts[0],
                        f"unsafe C archive drive-like path: {member.name}",
                    )
                    require(canonical not in seen, f"duplicate C archive path: {canonical}")
                    seen.add(canonical)
                    require(member.isfile() or member.isdir(), f"unsupported C archive member: {member.name}")
                    if not member.isfile():
                        require(member.size == 0, f"C archive directory has data: {member.name}")
                        continue
                    require(member.size >= 0, f"C archive member has negative size: {member.name}")
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
                    require(len(value) == member.size, f"short read for C archive {suffix}")
                    match = value
                tar_end = bundle.offset
                require(match is not None, f"C archive must contain exactly one {suffix}")
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
    except (EOFError, OSError, tarfile.TarError, zlib.error) as exc:
        fail(f"cannot inspect C archive {archive}: {exc}")
    finally:
        os.close(descriptor)


def validate_artifact_binding(
    face: str,
    manifest: dict[str, Any],
    manifest_path: pathlib.Path,
    sha256s_path: pathlib.Path,
    package_files: list[pathlib.Path],
) -> None:
    require(len(package_files) == 1, f"{face} release entry must contain exactly one package file")
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
    require(index_path.name == "index.json", f"release index filename must be index.json: {index_path}")
    require(index_path.is_file(), f"release index missing: {index_path}")


def verify_release_index(
    index_path: pathlib.Path,
    root: pathlib.Path,
    *,
    allow_diagnostic: bool,
) -> dict[str, Any]:
    root = root.resolve()
    index_path = normalized_absolute(index_path)
    validate_index_location(index_path, root)
    index = load_json(index_path)
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
    require_exact_int(index.get("schema_version"), SCHEMA_VERSION, "release index schema_version")
    require(index.get("kind") == KIND, "release index kind mismatch")
    require_utc_timestamp(index.get("generated_at"), "release index generated_at")
    validate_index_text(index_path)
    channel = index.get("channel")
    require(
        isinstance(channel, str) and channel in {"release", "diagnostic"},
        f"release index channel is invalid: {channel}",
    )
    diagnostic_only = index.get("diagnostic_only")
    require(type(diagnostic_only) is bool, "release index diagnostic_only must be boolean")
    require(
        diagnostic_only is (channel == "diagnostic"),
        "release index channel/diagnostic_only boundary mismatch",
    )
    if channel == "diagnostic":
        require(allow_diagnostic, "diagnostic release index requires explicit allow_diagnostic")
    channel_base = root / "target" / "qperiapt-local-release" / channel
    require_strictly_under(index_path, channel_base, "release index channel path")

    trust = load_abi_trust_root(root)
    require(index.get("version") == trust.version, "release index package version differs from ABI contract")
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
    require(abi.get("contract_sha256") == trust.contract_sha256, "release index contract hash mismatch")
    require(abi.get("exports_sha256") == trust.exports_sha256, "release index exports hash mismatch")
    require_exact_int(abi.get("export_count"), EXPORT_COUNT, "release index export_count")

    git = require_exact_object(
        index.get("git"),
        frozenset({"commit", "source_tree_dirty"}),
        "release index git provenance",
    )
    commit = git.get("commit")
    dirty = git.get("source_tree_dirty")
    require(isinstance(commit, str) and GIT_COMMIT.fullmatch(commit) is not None, "release index commit is malformed")
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
    require(len(artifacts) == len(EXPECTED_FACES), "release index must have exactly three package faces")
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
            require(not proof_dirty, f"release index includes diagnostic proof summary: {proof_name}")

    verify_sha256s(release_root, expected_file_set=declared_files)
    return index


def build_index(args: argparse.Namespace) -> pathlib.Path:
    root = pathlib.Path(args.root).resolve()
    channel = args.channel
    trust = load_abi_trust_root(root)
    version = cargo_version(root)
    require(version == trust.version, f"Cargo version {version} differs from ABI contract {trust.version}")
    commit = git_commit(root)
    current_dirty = git_dirty(root)
    if channel == "release":
        require(not current_dirty, "release index requires a clean source tree")

    host = rust_host()
    target = root / "target"
    release_root = resolve_release_output(
        root,
        args.output_dir,
        channel=channel,
        version=version,
        commit=commit,
    )

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
        require(package_dir.is_dir(), f"release package directory missing: {package_dir}")
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

    try:
        if release_root.exists():
            require_no_symlink_components(release_root, target, "release index output")
            shutil.rmtree(release_root)
        release_root.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        fail(f"cannot recreate release index output {release_root}: {exc}")
    require_no_symlink_components(release_root, target, "release index output")

    artifacts = [
        artifact_entry(
            artifact_contracts["c-abi"]["id"],
            "c-abi",
            artifact_contracts["c-abi"]["type"],
            [copy_to_release(c_archive, target, release_root, f"packages/c/{c_archive.name}")],
            copy_to_release(c_manifest_path, target, release_root, "manifests/c/MANIFEST.json"),
            copy_to_release(c_dir / "SHA256SUMS", target, release_root, "manifests/c/SHA256SUMS"),
            artifact_contracts["c-abi"]["boundary"],
            artifact_contracts["c-abi"]["required_leaf_gate"],
            artifact_contracts["c-abi"]["targets"],
            source_semantics["c-abi"],
        ),
        artifact_entry(
            artifact_contracts["swift"]["id"],
            "swift",
            artifact_contracts["swift"]["type"],
            [copy_to_release(swift_zip, target, release_root, "packages/swift/CQPeriapt.xcframework.zip")],
            copy_to_release(swift_manifest_path, target, release_root, "manifests/swift/MANIFEST.json"),
            copy_to_release(swift_dir / "SHA256SUMS", target, release_root, "manifests/swift/SHA256SUMS"),
            artifact_contracts["swift"]["boundary"],
            artifact_contracts["swift"]["required_leaf_gate"],
            artifact_contracts["swift"]["targets"],
            source_semantics["swift"],
        ),
        artifact_entry(
            artifact_contracts["android"]["id"],
            "android",
            artifact_contracts["android"]["type"],
            [copy_to_release(android_aar, target, release_root, f"packages/android/{android_aar.name}")],
            copy_to_release(android_manifest_path, target, release_root, "manifests/android/MANIFEST.json"),
            copy_to_release(android_dir / "SHA256SUMS", target, release_root, "manifests/android/SHA256SUMS"),
            artifact_contracts["android"]["boundary"],
            artifact_contracts["android"]["required_leaf_gate"],
            artifact_contracts["android"]["targets"],
            source_semantics["android"],
        ),
    ]

    proofs: dict[str, Any] = {}
    if args.apple_matrix_proof:
        apple_path = pathlib.Path(args.apple_matrix_proof)
        if not apple_path.is_absolute():
            apple_path = root / apple_path
        apple_path = normalized_absolute(apple_path)
        require_no_symlink_components(apple_path, root / "artifact" / "device-runs", "Apple matrix proof")
        proofs["apple_matrix"] = proof_summary(apple_path, "apple_matrix")
    if args.android_proof:
        android_path = pathlib.Path(args.android_proof)
        if not android_path.is_absolute():
            android_path = root / android_path
        android_path = normalized_absolute(android_path)
        require_no_symlink_components(android_path, target, "Android runtime proof")
        proofs["android_runtime"] = proof_summary(android_path, "android_runtime")
    if channel == "release":
        for proof_name, proof in proofs.items():
            require(
                proof["source_tree_dirty"] is False,
                f"release index cannot include dirty {proof_name} proof summary",
            )

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
    validate_index_text(index_path)
    write_release_sums(release_root)
    verify_release_index(index_path, root, allow_diagnostic=True)

    pointer = {
        "schema_version": SCHEMA_VERSION,
        "kind": "qperiapt.local_release_index.pointer",
        "version": version,
        "channel": channel,
        "diagnostic_only": channel == "diagnostic",
        "index_path": str(index_path.relative_to(target)),
        "index_sha256": sha256_file(index_path),
        "generated_at": index["generated_at"],
    }
    release_base = target / "qperiapt-local-release"
    try:
        release_base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail(f"cannot create release pointer directory {release_base}: {exc}")
    pointer_path = release_base / f"latest-{channel}.json"
    write_json(pointer_path, pointer)
    if channel == "release":
        write_json(release_base / "latest.json", pointer)
    print(f"QPERIAPT_LOCAL_RELEASE_INDEX={index_path}")
    return index_path


def verify_index_command(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.root).resolve()
    index_path = pathlib.Path(args.index)
    if not index_path.is_absolute():
        index_path = root / index_path
    verify_release_index(index_path, root, allow_diagnostic=args.allow_diagnostic)
    print("QPERIAPT_LOCAL_RELEASE_INDEX_VERIFY_PASS")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    emit = sub.add_parser("emit")
    emit.add_argument("--root", default=".")
    emit.add_argument("--channel", choices=["release", "diagnostic"], default="release")
    emit.add_argument("--output-dir", default="")
    emit.add_argument("--apple-matrix-proof", default="")
    emit.add_argument("--android-proof", default="")
    emit.set_defaults(func=build_index)

    verify = sub.add_parser("verify")
    verify.add_argument("--root", default=".")
    verify.add_argument("--index", required=True)
    verify.add_argument("--allow-diagnostic", action="store_true")
    verify.set_defaults(func=verify_index_command)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
