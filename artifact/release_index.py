#!/usr/bin/env python3
"""Build and verify a local, ABI-contract-bound Q-Periapt release index.

The index is a packaging manifest, not a public release claim.  Package hashes
are necessary but insufficient: every verification pass also revalidates the
ABI 2 package semantics against the frozen repository contract.
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
import subprocess
import tarfile
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
    source_tree_dirty as provenance_source_tree_dirty,
)


SCHEMA_VERSION = 2
PACKAGE_MANIFEST_SCHEMA_VERSION = 2
KIND = "qperiapt.local_release_index"
ABI_MAJOR = 2
EXPORT_COUNT = 9
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
EXPECTED_FACES = frozenset({"c-abi", "swift", "android"})
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40,64}")
SAFE_PLATFORM = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}")
MAX_TAR_MEMBERS = 8192
MAX_TAR_METADATA_BYTES = 16 * 1024 * 1024
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


def fail(message: str) -> NoReturn:
    raise SystemExit(f"error: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_exact_int(value: Any, expected: int, label: str) -> None:
    require(type(value) is int, f"{label} must be an integer")
    require(value == expected, f"{label} must be {expected}, got {value}")


def normalized_absolute(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def read_bytes(path: pathlib.Path) -> bytes:
    require(not path.is_symlink(), f"file must not be a symlink: {path}")
    require(path.is_file(), f"file is missing or not regular: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def read_text(path: pathlib.Path) -> str:
    try:
        return read_bytes(path).decode("utf-8")
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


def sha256_file(path: pathlib.Path) -> str:
    require(not path.is_symlink(), f"file must not be a symlink: {path}")
    require(path.is_file(), f"file is missing or not regular: {path}")
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError as exc:
        fail(f"cannot hash {path}: {exc}")
    return hasher.hexdigest()


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
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst, follow_symlinks=False)
    except OSError as exc:
        fail(f"cannot copy release artifact {src} to {dst}: {exc}")
    return {"path": rel, "sha256": sha256_file(dst), "bytes": dst.stat().st_size}


def parse_sha256s(base: pathlib.Path) -> dict[str, str]:
    sums = base / "SHA256SUMS"
    require_no_symlink_components(sums, base, "SHA256SUMS")
    require(sums.is_file(), f"missing SHA256SUMS: {sums}")
    parsed: dict[str, str] = {}
    for line_no, line in enumerate(read_text(sums).splitlines(), start=1):
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


def verify_sha256s(base: pathlib.Path, *, exact_file_set: bool = False) -> None:
    parsed = parse_sha256s(base)
    for rel, expected in parsed.items():
        target = base / pathlib.Path(rel)
        require_no_symlink_components(target, base, "SHA256SUMS target")
        require(target.is_file(), f"SHA256SUMS target missing: {target}")
        require(sha256_file(target) == expected, f"SHA256SUMS hash mismatch for {target}")
    if exact_file_set:
        actual = {
            path.relative_to(base).as_posix()
            for path in base.rglob("*")
            if path.is_file() and path.name != "SHA256SUMS"
        }
        require(
            set(parsed) == actual,
            "release SHA256SUMS file set mismatch "
            f"extra={sorted(set(parsed) - actual)} missing={sorted(actual - set(parsed))}",
        )


def package_dirty(manifest: dict[str, Any]) -> bool | None:
    if type(manifest.get("git_dirty")) is bool:
        return manifest["git_dirty"]
    if type(manifest.get("source_tree_dirty")) is bool:
        return manifest["source_tree_dirty"]
    return None


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
    require_exact_int(
        manifest.get("schema_version"),
        PACKAGE_MANIFEST_SCHEMA_VERSION,
        f"{face} manifest schema_version",
    )
    package = manifest.get("package")
    require(isinstance(package, str) and package, f"{face} manifest package is missing")
    require(
        manifest.get("version") == expected_version,
        f"{face} manifest version mismatch: {manifest.get('version')} != {expected_version}",
    )
    commit = manifest.get("git_commit")
    require(commit == expected_commit, f"{face} manifest commit mismatch: {commit} != {expected_commit}")
    dirty = package_dirty(manifest)
    require(dirty is not None, f"{face} manifest lacks explicit dirty provenance")
    if channel == "release":
        require(dirty is False, f"{face} release manifest was generated dirty")

    abi = manifest.get("abi")
    require(isinstance(abi, dict), f"{face} manifest abi object is missing")
    required_abi_fields = {
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
    missing = required_abi_fields - set(abi)
    require(not missing, f"{face} manifest ABI fields missing: {sorted(missing)}")
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
        require(
            package.startswith(f"{trust.archive_prefix}-{expected_version}-"),
            f"C ABI package name does not carry ABI2/version identity: {package}",
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
        require(
            any(marker in platform for marker in ("apple", "ios", "macos", "xcframework")),
            f"Swift ABI platform is not Apple/XCFramework-specific: {platform}",
        )
        require(
            "abi2" in static_filename,
            f"Swift static filename lacks ABI-major identity: {static_filename}",
        )
    elif face == "android":
        require(
            package == f"q-periapt-android-{expected_version}.aar",
            f"Android package name is invalid: {package}",
        )
        require("android" in platform, f"Android ABI platform is not Android-specific: {platform}")
        require(
            "abi2" in shared_filename,
            f"Android shared filename lacks ABI-major identity: {shared_filename}",
        )
    else:
        fail(f"unsupported package face: {face}")

    return manifest


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
    verified_by: str,
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
        "verified_by": verified_by,
        "targets": targets,
    }


def proof_summary(path: pathlib.Path, proof_kind: str) -> dict[str, Any]:
    proof = load_json(path)
    dirty = proof.get("source_tree_dirty")
    require(type(dirty) is bool, f"{proof_kind} proof lacks explicit dirty provenance")
    summary: dict[str, Any] = {
        "kind": proof_kind,
        "sha256": sha256_file(path),
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
    return summary


def validate_index_text(index_path: pathlib.Path) -> None:
    text = read_text(index_path)
    for forbidden in FORBIDDEN_INDEX_TEXT:
        require(forbidden not in text, f"release index contains private/local token: {forbidden}")


def write_release_sums(release_root: pathlib.Path) -> None:
    files = sorted(
        path
        for path in release_root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
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
    require(isinstance(item, dict), "indexed file entry is not an object")
    rel = item.get("path")
    expected = item.get("sha256")
    size = item.get("bytes")
    require(isinstance(rel, str), "indexed file path is missing")
    require(
        isinstance(expected, str) and HEX_SHA256.fullmatch(expected) is not None,
        f"indexed file hash is malformed: {rel}",
    )
    require(type(size) is int and size >= 0, f"indexed file byte count is malformed: {rel}")
    require_relative_safe(rel, "indexed file path")
    path = release_root / pathlib.Path(rel)
    require_no_symlink_components(path, release_root, "indexed file")
    require(path.is_file(), f"indexed file missing: {path}")
    require(path.stat().st_size == size, f"indexed file byte count mismatch: {rel}")
    require(sha256_file(path) == expected, f"indexed file hash mismatch: {rel}")
    return path


def tar_metadata_bytes(archive: pathlib.Path, suffix: str) -> bytes:
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            require(len(members) <= MAX_TAR_MEMBERS, f"C archive has too many members: {archive}")
            seen: set[str] = set()
            matches: list[tarfile.TarInfo] = []
            for member in members:
                pure = pathlib.PurePosixPath(member.name)
                require(member.name and not pure.is_absolute(), f"unsafe C archive path: {member.name}")
                require("\\" not in member.name, f"unsafe C archive path: {member.name}")
                require(
                    ":" not in pure.parts[0],
                    f"unsafe C archive drive-like path: {member.name}",
                )
                require(
                    all(part not in {"", ".", ".."} for part in pure.parts),
                    f"unsafe C archive path: {member.name}",
                )
                require(member.name not in seen, f"duplicate C archive path: {member.name}")
                seen.add(member.name)
                require(member.isfile() or member.isdir(), f"unsupported C archive member: {member.name}")
                if member.isfile() and member.name.endswith(suffix):
                    matches.append(member)
            require(len(matches) == 1, f"C archive must contain exactly one {suffix}")
            member = matches[0]
            require(member.size <= MAX_TAR_METADATA_BYTES, f"C archive {suffix} is too large")
            stream = bundle.extractfile(member)
            require(stream is not None, f"cannot read C archive {suffix}")
            value = stream.read(MAX_TAR_METADATA_BYTES + 1)
            require(len(value) == member.size, f"short read for C archive {suffix}")
            return value
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot inspect C archive {archive}: {exc}")


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
        artifacts = manifest.get("artifacts")
        require(isinstance(artifacts, dict), "Swift manifest artifacts are malformed")
        zip_entry = artifacts.get("xcframework_zip")
        require(isinstance(zip_entry, dict), "Swift manifest xcframework_zip is malformed")
        require(
            zip_entry.get("sha256") == sha256_file(package_file),
            "Swift manifest does not bind the indexed XCFramework zip",
        )
    elif face == "android":
        artifacts = manifest.get("artifacts")
        require(isinstance(artifacts, dict), "Android manifest artifacts are malformed")
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
    require_exact_int(index.get("schema_version"), SCHEMA_VERSION, "release index schema_version")
    require(index.get("kind") == KIND, "release index kind mismatch")
    validate_index_text(index_path)
    channel = index.get("channel")
    require(channel in {"release", "diagnostic"}, f"release index channel is invalid: {channel}")
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
    abi = index.get("abi")
    require(isinstance(abi, dict), "release index abi object is missing")
    require_exact_int(abi.get("major"), ABI_MAJOR, "release index ABI major")
    require(
        abi.get("contract_path") == CONTRACT_RELATIVE_PATH.as_posix(),
        "release index contract_path mismatch",
    )
    require(abi.get("contract_sha256") == trust.contract_sha256, "release index contract hash mismatch")
    require(abi.get("exports_sha256") == trust.exports_sha256, "release index exports hash mismatch")
    require_exact_int(abi.get("export_count"), EXPORT_COUNT, "release index export_count")

    git = index.get("git")
    require(isinstance(git, dict), "release index git provenance is missing")
    commit = git.get("commit")
    dirty = git.get("source_tree_dirty")
    require(isinstance(commit, str) and GIT_COMMIT.fullmatch(commit) is not None, "release index commit is malformed")
    require(type(dirty) is bool, "release index source_tree_dirty must be boolean")
    if channel == "release":
        require(dirty is False, "release channel index has dirty source provenance")

    boundary = index.get("release_boundary")
    require(isinstance(boundary, dict), "release index boundary is missing")
    require(boundary.get("public_release") is False, "local index must not claim public release")
    require(boundary.get("registry_uploaded") is False, "local index must not claim registry upload")
    require(boundary.get("raw_device_proofs_copied") is False, "release index must not copy raw device proofs")
    require(boundary.get("requires_clean_tree_for_release") is True, "release clean-tree boundary missing")

    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list), "release index artifacts are malformed")
    require(len(artifacts) == len(EXPECTED_FACES), "release index must have exactly three package faces")
    release_root = index_path.parent
    seen_faces: set[str] = set()
    semantics: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        require(isinstance(artifact, dict), "artifact entry is malformed")
        face = artifact.get("face")
        require(face in EXPECTED_FACES, f"unsupported artifact face: {face}")
        require(face not in seen_faces, f"duplicate artifact face: {face}")
        seen_faces.add(face)
        expected_type = {
            "c-abi": "tar.gz",
            "swift": "xcframework.zip",
            "android": "aar",
        }[face]
        require(
            artifact.get("type") == expected_type,
            f"{face} artifact type must be {expected_type}",
        )
        artifact_id = artifact.get("id")
        if face == "c-abi":
            require(
                isinstance(artifact_id, str) and artifact_id.startswith("c-abi/"),
                "C ABI artifact id is malformed",
            )
        else:
            expected_id = {"swift": "swift/xcframework", "android": "android/aar"}[
                face
            ]
            require(artifact_id == expected_id, f"{face} artifact id is malformed")
        require(isinstance(artifact.get("boundary"), dict), f"{face} boundary is malformed")
        require(
            isinstance(artifact.get("verified_by"), str)
            and artifact.get("verified_by"),
            f"{face} verified_by is malformed",
        )
        require(isinstance(artifact.get("targets"), list), f"{face} targets are malformed")
        files = artifact.get("files")
        require(isinstance(files, list) and files, f"artifact {face} lacks files")
        package_files = [verify_index_file(release_root, item) for item in files]
        manifest_path = verify_index_file(release_root, artifact.get("manifest"))
        sha256s_path = verify_index_file(release_root, artifact.get("sha256s"))
        manifest = validate_package_manifest(
            manifest_path,
            commit,
            trust.version,
            channel,
            face,
            trust,
        )
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
        proof_dirty = proof.get("source_tree_dirty")
        proof_diagnostic = proof.get("diagnostic_only")
        require(type(proof_dirty) is bool, f"proof summary dirty provenance is malformed: {proof_name}")
        require(type(proof_diagnostic) is bool, f"proof summary diagnostic flag is malformed: {proof_name}")
        require(proof_diagnostic is proof_dirty, f"proof summary boundary mismatch: {proof_name}")
        if channel == "release":
            require(not proof_dirty, f"release index includes diagnostic proof summary: {proof_name}")
        require(proof.get("copied_raw_proof") is False, f"raw proof copy boundary violated: {proof_name}")

    verify_sha256s(release_root, exact_file_set=True)
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
            f"c-abi/{host}",
            "c-abi",
            "tar.gz",
            [copy_to_release(c_archive, target, release_root, f"packages/c/{c_archive.name}")],
            copy_to_release(c_manifest_path, target, release_root, "manifests/c/MANIFEST.json"),
            copy_to_release(c_dir / "SHA256SUMS", target, release_root, "manifests/c/SHA256SUMS"),
            {
                "package_only": False,
                "host_archive_only": True,
                "multi_target_release_pending": True,
                "git_dirty": package_dirty(c_manifest),
            },
            "artifact/c-package.sh",
            [host],
            source_semantics["c-abi"],
        ),
        artifact_entry(
            "swift/xcframework",
            "swift",
            "xcframework.zip",
            [copy_to_release(swift_zip, target, release_root, "packages/swift/CQPeriapt.xcframework.zip")],
            copy_to_release(swift_manifest_path, target, release_root, "manifests/swift/MANIFEST.json"),
            copy_to_release(swift_dir / "SHA256SUMS", target, release_root, "manifests/swift/SHA256SUMS"),
            {
                "package_only": True,
                "public_url_uploaded": False,
                "contains_raw_device_proof": False,
                "git_dirty": package_dirty(swift_manifest),
            },
            "artifact/swift-xcframework.sh",
            list(swift_manifest.get("targets", [])),
            source_semantics["swift"],
        ),
        artifact_entry(
            "android/aar",
            "android",
            "aar",
            [copy_to_release(android_aar, target, release_root, f"packages/android/{android_aar.name}")],
            copy_to_release(android_manifest_path, target, release_root, "manifests/android/MANIFEST.json"),
            copy_to_release(android_dir / "SHA256SUMS", target, release_root, "manifests/android/SHA256SUMS"),
            {
                "package_only": True,
                "device_runtime_proof": False,
                "runtime_proof_is_separate": True,
                "git_dirty": package_dirty(android_manifest),
            },
            "artifact/android-aar.sh",
            list(android_manifest.get("android", {}).get("abis", [])),
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
