#!/usr/bin/env python3
"""Create and verify the strict manifest inside the Windows x64 ABI2 SDK ZIP."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import stat
from typing import Any, Iterable

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


SCHEMA_VERSION = 2
KIND = "qperiapt.windows_c_package_manifest"
TARGET = "x86_64-pc-windows-msvc"
ABI_PLATFORM = "windows"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_DEPENDENCY_RE = re.compile(r"^[A-Za-z0-9._-]+\.dll$", re.IGNORECASE)
TREE_RE = re.compile(r"^[0-9a-f]{40,64}$")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_FILE_BYTES = 512 * 1024 * 1024

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
ALLOWED_DEPENDENCY_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ADVAPI32\.dll",
        r"bcrypt\.dll",
        r"KERNEL32\.dll",
        r"ntdll\.dll",
        r"USERENV\.dll",
        r"WS2_32\.dll",
        r"VCRUNTIME140(?:_1)?\.dll",
        r"ucrtbase\.dll",
        r"api-ms-win-crt-[A-Za-z0-9._-]+\.dll",
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
            any(pattern.fullmatch(raw) is not None for pattern in ALLOWED_DEPENDENCY_PATTERNS),
            f"unexpected Windows DLL dependency: {raw}",
        )
        _require(
            re.fullmatch(r"q_periapt_ffi(?:_abi1)?\.dll", raw, re.IGNORECASE) is None,
            f"legacy or recursive Q-Periapt DLL dependency: {raw}",
        )
        key = raw.casefold()
        _require(key not in normalized, f"duplicate Windows DLL dependency: {raw}")
        normalized[key] = raw
    _require(normalized, "Windows DLL dependency set must not be empty")
    return [normalized[key] for key in sorted(normalized)]


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
    create.add_argument("--dependency", action="append", default=[])
    verify = subparsers.add_parser("verify")
    verify.add_argument("--package-root", required=True, type=pathlib.Path)
    verify.add_argument("--repository-root", type=pathlib.Path)
    verify.add_argument("--expected-dependency", action="append")
    verify.add_argument("--expected-git-commit")
    verify.add_argument("--expected-git-tree")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
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
                dependencies=args.dependency,
            )
        else:
            result = verify_package(
                args.package_root,
                repository_root=args.repository_root,
                expected_dependencies=args.expected_dependency,
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
