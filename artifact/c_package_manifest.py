#!/usr/bin/env python3
"""Cross-platform structural verifier for extracted ABI2 C SDK packages."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import stat
import sys
from typing import Any, NoReturn

from c_abi_contract import ABI_MAJOR, PACKAGE_SEMVER, load_contract
from evidence_io import EvidenceIOError, load_json_object_snapshot, read_regular_snapshot
from package_bom import PackageBomError, verify as verify_package_boms
from release_binary_scan import ReleaseBinaryScanError, scan_release_file
from third_party_licenses import (
    INVENTORY_RELATIVE as THIRD_PARTY_INVENTORY_RELATIVE,
    ThirdPartyLicenseError,
    verify as verify_third_party_licenses,
)


SCHEMA_VERSION = 2
SUPPORTED_TARGETS = {
    "x86_64-unknown-linux-gnu": {
        "elf_machine": "Advanced Micro Devices X86-64",
        "loader": "ld-linux-x86-64.so.2",
    },
    "aarch64-unknown-linux-gnu": {
        "elf_machine": "AArch64",
        "loader": "ld-linux-aarch64.so.1",
    },
}
MANIFEST_KEYS = frozenset(
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
)
ABI_KEYS = frozenset(
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
)
SOURCE_INPUT_PATHS = {
    "cargo_lock": "Cargo.lock",
    "c_package_script": "artifact/c-package.sh",
    "c_abi_contract_script": "artifact/c_abi_contract.py",
    "deterministic_archive_script": "artifact/deterministic_archive.py",
    "release_binary_scan_script": "artifact/release_binary_scan.py",
    "third_party_licenses_script": "artifact/third_party_licenses.py",
    "c_abi_contract": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    "c_smoke": "bindings/c/smoke.c",
    "c_signed_policy_fixture": "bindings/c/signed_policy_fixture.h",
    "ffi_header": "crates/q-periapt-ffi/include/q_periapt.h",
    "license": "LICENSE",
    "license_apache": "LICENSES/Apache-2.0.txt",
    "license_mit": "LICENSES/MIT.txt",
    "mlkem_native_license": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE.mlkem-native",
    "mlkem_native_license_inventory": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE-INVENTORY.md",
    "mlkem_native_provenance": "crates/q-periapt-mlkem-native-sys/vendor/PROVENANCE.md",
    "mlkem_native_inventory": "crates/q-periapt-mlkem-native-sys/vendor/INVENTORY.sha256",
    "qperiapt_cli_cargo": "crates/q-periapt-cli/Cargo.toml",
    "qperiapt_cli_lib": "crates/q-periapt-cli/src/lib.rs",
    "qperiapt_cli_main": "crates/q-periapt-cli/src/main.rs",
}
RUST_WORKSPACE_INPUTS = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")


class CPackageManifestError(ValueError):
    """An extracted C SDK is structurally invalid or inconsistent."""


def fail(message: str) -> NoReturn:
    raise CPackageManifestError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _snapshot(path: pathlib.Path, label: str):
    try:
        return read_regular_snapshot(path, maximum=MAX_FILE_BYTES, label=label)
    except EvidenceIOError as exc:
        fail(str(exc))


def _json(path: pathlib.Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        snapshot = load_json_object_snapshot(path, maximum=MAX_JSON_BYTES, label=label)
    except EvidenceIOError as exc:
        fail(str(exc))
    require(snapshot.file.data == canonical_json(snapshot.value), f"{label} is not canonical JSON")
    return snapshot.value, snapshot.file.data


def _root(path: pathlib.Path) -> pathlib.Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot inspect C package root {path}: {exc}")
    require(stat.S_ISDIR(metadata.st_mode) and not path.is_symlink(), "C package root must be a non-symlink directory")
    return resolved


def _inventory(root: pathlib.Path) -> dict[str, pathlib.Path]:
    files: dict[str, pathlib.Path] = {}
    try:
        paths = sorted(root.rglob("*"), key=lambda path: path.as_posix())
        for path in paths:
            metadata = path.lstat()
            require(not path.is_symlink(), f"C package contains symlink: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            require(stat.S_ISREG(metadata.st_mode), f"C package contains unsupported entry: {path}")
            relative = path.relative_to(root).as_posix()
            require(relative not in files, f"duplicate C package path: {relative}")
            files[relative] = path
    except OSError as exc:
        fail(f"cannot enumerate C package: {exc}")
    return files


def _source_tree_hash(repository: pathlib.Path) -> str:
    candidates: dict[str, pathlib.Path] = {}
    for relative in RUST_WORKSPACE_INPUTS:
        source = repository / relative
        require(source.exists() and not source.is_symlink(), f"source-tree input is missing or unsafe: {relative}")
        if source.is_file():
            candidates[relative] = source
        else:
            for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
                metadata = path.lstat()
                require(not path.is_symlink(), f"source-tree input contains symlink: {path}")
                require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode), f"source-tree input has unsupported entry: {path}")
                if stat.S_ISREG(metadata.st_mode):
                    candidates[path.relative_to(repository).as_posix()] = path
    require(bool(candidates), "Rust workspace build-input closure is empty")
    digest = hashlib.sha256()
    for relative, path in sorted(candidates.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_snapshot(path, f"source input {relative}").sha256))
        digest.update(b"\0")
    return digest.hexdigest()


def _version_tuple(value: str) -> tuple[int, ...]:
    require(VERSION_RE.fullmatch(value) is not None, f"malformed GLIBC version: {value!r}")
    return tuple(int(part) for part in value.split("."))


def _third_party_files(root: pathlib.Path, target: str) -> frozenset[str]:
    try:
        inventory = verify_third_party_licenses(root, expected_target=target)
    except ThirdPartyLicenseError as exc:
        fail(f"third-party Rust licenses are invalid: {exc}")
    paths = {THIRD_PARTY_INVENTORY_RELATIVE.as_posix()}
    for package in inventory["packages"]:
        for license_file in package["license_files"]:
            paths.add(license_file["path"])
    return frozenset(paths)


def _expected_files(target: str, runtime_identity: dict[str, Any], third_party: frozenset[str]) -> frozenset[str]:
    shared = runtime_identity["shared_filename"]
    static = runtime_identity["static_filename"]
    return frozenset(
        {
            "LICENSE",
            "LICENSES/Apache-2.0.txt",
            "LICENSES/MIT.txt",
            "LICENSES/mlkem-native/INVENTORY.sha256",
            "LICENSES/mlkem-native/LICENSE-INVENTORY.md",
            "LICENSES/mlkem-native/LICENSE.mlkem-native",
            "LICENSES/mlkem-native/PROVENANCE.md",
            "README.md",
            "include/qperiapt/abi2/q_periapt.h",
            "include/qperiapt/abi2/signed_policy_fixture.h",
            f"lib/{shared}",
            f"lib/{static}",
            "lib/pkgconfig/qperiapt-abi2.pc",
            "lib/pkgconfig/qperiapt-abi2-static.pc",
            "lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake",
            "lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake",
            "share/q-periapt/abi/q-periapt-c-abi-v2.json",
            "share/q-periapt/bom/cbom.cdx.json",
            "share/q-periapt/bom/sbom.cdx.json",
            "share/q-periapt/smoke.c",
        }
    ) | third_party


def _validate_licenses(root: pathlib.Path, repository: pathlib.Path) -> None:
    pairs = {
        "LICENSE": "LICENSE",
        "LICENSES/Apache-2.0.txt": "LICENSES/Apache-2.0.txt",
        "LICENSES/MIT.txt": "LICENSES/MIT.txt",
        "LICENSES/mlkem-native/INVENTORY.sha256": "crates/q-periapt-mlkem-native-sys/vendor/INVENTORY.sha256",
        "LICENSES/mlkem-native/LICENSE-INVENTORY.md": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE-INVENTORY.md",
        "LICENSES/mlkem-native/LICENSE.mlkem-native": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE.mlkem-native",
        "LICENSES/mlkem-native/PROVENANCE.md": "crates/q-periapt-mlkem-native-sys/vendor/PROVENANCE.md",
    }
    for packaged, source in pairs.items():
        require(
            _snapshot(root / packaged, f"packaged license {packaged}").sha256
            == _snapshot(repository / source, f"source license {source}").sha256,
            f"packaged license differs from source: {packaged}",
        )


def verify_package(
    package_root: pathlib.Path,
    repository_root: pathlib.Path,
    *,
    expected_target: str,
    expected_commit: str | None = None,
    expected_source_date_epoch: int | None = None,
) -> dict[str, Any]:
    """Verify all portable package invariants before native ELF consumer gates."""

    require(expected_target in SUPPORTED_TARGETS, f"unsupported Linux target: {expected_target}")
    root = _root(package_root)
    repository = _root(repository_root)
    inventory = _inventory(root)
    manifest, manifest_bytes = _json(root / "MANIFEST.json", "C package MANIFEST.json")
    require(set(manifest) == MANIFEST_KEYS, "C package manifest fields differ")
    require(manifest["schema_version"] == SCHEMA_VERSION, "C package manifest schema differs")
    require(manifest["package"] == f"q-periapt-c-abi2-{PACKAGE_SEMVER}-{expected_target}", "C package name differs")
    require(manifest["version"] == PACKAGE_SEMVER, "C package version differs")
    require(manifest["host"] == expected_target, "C package host differs")
    epoch = manifest["source_date_epoch"]
    require(type(epoch) is int and 0 <= epoch <= 0xFFFFFFFF, "C package source epoch is malformed")
    if expected_source_date_epoch is not None:
        require(epoch == expected_source_date_epoch, "C package source epoch differs from release source")
    generated_at = dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z")
    require(manifest["generated_at"] == generated_at, "C package generated_at differs from source epoch")
    require(COMMIT_RE.fullmatch(manifest.get("git_commit", "")) is not None, "C package commit is malformed")
    if expected_commit is not None:
        require(manifest["git_commit"] == expected_commit, "C package commit differs from release source")
    require(manifest["git_dirty"] is False and manifest["diagnostic_only"] is False, "C package is not clean release evidence")
    for key in ("rustc", "cargo"):
        value = manifest[key]
        require(isinstance(value, str) and value and "\n" not in value and "\r" not in value, f"C package {key} version is malformed")

    abi = manifest["abi"]
    require(isinstance(abi, dict) and set(abi) == ABI_KEYS, "C package ABI fields differ")
    require(abi["major"] == ABI_MAJOR and abi["platform"] == "linux", "C package ABI platform differs")
    require(abi["export_count"] == 9, "C package ABI export count differs")
    require(abi["contract_path"] == "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json", "C package source contract path differs")
    require(abi["embedded_contract_path"] == "share/q-periapt/abi/q-periapt-c-abi-v2.json", "C package embedded contract path differs")
    try:
        source_contract = load_contract(repository / abi["contract_path"])
        embedded_contract = load_contract(root / abi["embedded_contract_path"])
    except ValueError as exc:
        fail(f"C package ABI contract is invalid: {exc}")
    require(source_contract.sha256 == embedded_contract.sha256 == abi["contract_sha256"], "C package ABI contract digest differs")
    exports = sorted(item["name"] for item in embedded_contract.document["abi"]["exports"])
    require(len(exports) == 9 and len(set(exports)) == 9, "C package ABI export set differs")
    exports_sha256 = hashlib.sha256(("\n".join(exports) + "\n").encode()).hexdigest()
    require(exports_sha256 == abi["exports_sha256"], "C package ABI export digest differs")
    runtime_identity = embedded_contract.document["package"]["platforms"]["linux"]
    require(abi["runtime_identity"] == runtime_identity, "C package runtime identity differs")
    require(abi["shared_filename"] == runtime_identity["shared_filename"], "C package shared filename differs")
    require(abi["static_filename"] == runtime_identity["static_filename"], "C package static filename differs")

    compatibility = manifest["platform_compatibility"]
    expected_machine = SUPPORTED_TARGETS[expected_target]["elf_machine"]
    loader = SUPPORTED_TARGETS[expected_target]["loader"]
    require(
        isinstance(compatibility, dict)
        and set(compatibility)
        == {"target", "elf_class", "elf_machine", "needed_libraries", "max_glibc_version", "glibc_policy_max", "hardening"},
        "C package Linux compatibility fields differ",
    )
    require(compatibility["target"] == expected_target, "C package compatibility target differs")
    require(compatibility["elf_class"] == "ELF64" and compatibility["elf_machine"] == expected_machine, "C package ELF identity differs")
    needed = compatibility["needed_libraries"]
    require(isinstance(needed, list) and needed == sorted(needed) and len(needed) == len(set(needed)), "C package DT_NEEDED list is malformed")
    allowed = {"libc.so.6", "libdl.so.2", "libgcc_s.so.1", "libm.so.6", "libpthread.so.0", "libresolv.so.2", "librt.so.1", "libutil.so.1", loader}
    require("libc.so.6" in needed and set(needed) <= allowed, "C package DT_NEEDED allowlist differs")
    require(compatibility["glibc_policy_max"] == "2.35", "C package GLIBC policy maximum differs")
    require(_version_tuple(compatibility["max_glibc_version"]) <= _version_tuple("2.35"), "C package GLIBC requirement exceeds policy")
    require(
        compatibility["hardening"]
        == {"bind_now": True, "debug_sections_absent": True, "gnu_relro": True, "nx_stack": True, "rpath_runpath_absent": True, "textrel_absent": True},
        "C package ELF hardening evidence differs",
    )

    third_party = _third_party_files(root, expected_target)
    expected_payload = _expected_files(expected_target, runtime_identity, third_party)
    expected_all = expected_payload | {"MANIFEST.json", "SHA256SUMS"}
    require(set(inventory) == expected_all, f"C package file set differs: missing={sorted(expected_all - set(inventory))} extra={sorted(set(inventory) - expected_all)}")

    entries = manifest["files"]
    require(isinstance(entries, list) and entries, "C package manifest files are missing")
    manifest_hashes: dict[str, str] = {}
    manifest_paths: list[str] = []
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "type", "mode", "sha256", "bytes"}, "C package file entry fields differ")
        relative = entry["path"]
        require(relative in expected_payload and relative not in manifest_hashes, f"invalid or duplicate C package manifest path: {relative}")
        require(entry["type"] == "file" and entry["mode"] == "0o644", f"C package manifest metadata differs: {relative}")
        require(type(entry["bytes"]) is int and entry["bytes"] >= 0, f"C package manifest byte count differs: {relative}")
        require(isinstance(entry["sha256"], str) and SHA256_RE.fullmatch(entry["sha256"]) is not None, f"C package manifest digest is malformed: {relative}")
        snapshot = _snapshot(inventory[relative], f"C package file {relative}")
        require(snapshot.size == entry["bytes"] and snapshot.sha256 == entry["sha256"], f"C package file bytes differ: {relative}")
        require(stat.S_IMODE(inventory[relative].stat().st_mode) == 0o644, f"C package file mode differs: {relative}")
        manifest_hashes[relative] = snapshot.sha256
        manifest_paths.append(relative)
    require(set(manifest_hashes) == expected_payload, "C package manifest file set differs")
    require(manifest_paths == sorted(manifest_paths), "C package manifest files are not canonically sorted")

    sums_snapshot = _snapshot(root / "SHA256SUMS", "C package SHA256SUMS")
    try:
        sums_text = sums_snapshot.data.decode("ascii")
    except UnicodeDecodeError as exc:
        fail(f"C package SHA256SUMS is not ASCII: {exc}")
    require(sums_text.endswith("\n"), "C package SHA256SUMS must end with a newline")
    sums: dict[str, str] = {}
    for line in sums_text.splitlines():
        require(bool(line), "C package SHA256SUMS contains a blank line")
        parts = line.split("  ", 1)
        require(len(parts) == 2, f"malformed C package checksum line: {line!r}")
        digest, relative = parts
        require(SHA256_RE.fullmatch(digest) is not None, f"malformed C package checksum: {relative}")
        require(relative not in sums, f"duplicate C package checksum path: {relative}")
        sums[relative] = digest
    require(list(sums) == sorted(sums), "C package SHA256SUMS is not canonically sorted")
    require(sums == {**manifest_hashes, "MANIFEST.json": hashlib.sha256(manifest_bytes).hexdigest()}, "C package SHA256SUMS differs from package bytes")

    source_inputs = manifest["source_inputs_sha256"]
    expected_source_keys = set(SOURCE_INPUT_PATHS) | {"rust_workspace_build_inputs", "third_party_rust_license_inventory"}
    require(isinstance(source_inputs, dict) and set(source_inputs) == expected_source_keys, "C package source-input fields differ")
    for key, digest in source_inputs.items():
        require(isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None, f"C package source-input digest is malformed: {key}")
    for key, relative in SOURCE_INPUT_PATHS.items():
        require(source_inputs[key] == _snapshot(repository / relative, f"source input {relative}").sha256, f"C package source-input digest differs: {relative}")
    require(source_inputs["rust_workspace_build_inputs"] == _source_tree_hash(repository), "C package Rust workspace source digest differs")
    require(source_inputs["third_party_rust_license_inventory"] == _snapshot(root.joinpath(*THIRD_PARTY_INVENTORY_RELATIVE.parts), "third-party Rust inventory").sha256, "C package third-party inventory source digest differs")

    _validate_licenses(root, repository)
    try:
        verify_package_boms(root, cargo_lock=repository / "Cargo.lock")
    except PackageBomError as exc:
        fail(f"C package BOM is invalid: {exc}")
    forbidden = [str(repository), repository.as_posix()]
    for path in inventory.values():
        try:
            scan_release_file(path, forbidden_text=forbidden)
        except ReleaseBinaryScanError as exc:
            fail(str(exc))
    return manifest


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", required=True, type=pathlib.Path)
    parser.add_argument("--repository-root", required=True, type=pathlib.Path)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-source-date-epoch", type=int)
    args = parser.parse_args(argv)
    try:
        manifest = verify_package(
            args.package_root,
            args.repository_root,
            expected_target=args.expected_target,
            expected_commit=args.expected_commit,
            expected_source_date_epoch=args.expected_source_date_epoch,
        )
    except (CPackageManifestError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"C_PACKAGE_MANIFEST_VERIFY_PASS target={manifest['host']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
