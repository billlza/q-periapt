#!/usr/bin/env python3
"""Assemble and verify the one-off ABI2 Android/Linux/Windows distribution."""

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
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, NoReturn

from android_device_proof import (
    BUNDLE_MANIFEST_PATH,
    BUNDLE_ROOT_NAME,
    verify_bundle_manifest,
    verify_proof_freshness,
    verify_runtime_bundle,
)
from c_package_manifest import (
    CPackageManifestError,
    verify_package as verify_c_package,
)
from c_abi_contract import ABI_MAJOR, PACKAGE_SEMVER, load_contract
from claim_ledger import canonical_tree_digest, repository_paths
from deterministic_archive import (
    ArchiveLimits,
    DeterministicArchiveError,
    extract_tar_gz,
    extract_zip,
)
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    load_json_object_snapshot,
    read_regular_snapshot,
)
from git_provenance import GitProvenanceError, inspect_worktree, run_git_text
from windows_package import (
    WindowsPackageError,
    verify_package as verify_windows_package,
)


SCHEMA_VERSION = 1
KIND = "qperiapt.abi2_platform_distribution"
PRODUCT_VERSION = PACKAGE_SEMVER
DISTRIBUTION_REVISION = "r1"
RELEASE_TAG = "abi2-platforms-v0.1.0-alpha.2-r1"
RELEASE_MANIFEST = "PLATFORM_DISTRIBUTION.json"
RELEASE_SUMS = "SHA256SUMS"
ANDROID_AAR = "q-periapt-android-0.1.0-alpha.2.aar"
ANDROID_MANIFEST = "q-periapt-android-0.1.0-alpha.2-MANIFEST.json"
ANDROID_RUNTIME_BUNDLE = (
    "q-periapt-android-0.1.0-alpha.2-16k-runtime-evidence.zip"
)
LINUX_X86_64 = (
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz"
)
LINUX_AARCH64 = (
    "q-periapt-c-abi2-0.1.0-alpha.2-aarch64-unknown-linux-gnu.tar.gz"
)
WINDOWS_X86_64 = (
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip"
)
INPUT_ASSETS = frozenset(
    {
        ANDROID_AAR,
        ANDROID_MANIFEST,
        ANDROID_RUNTIME_BUNDLE,
        LINUX_X86_64,
        LINUX_AARCH64,
        WINDOWS_X86_64,
    }
)
RELEASE_FILES = INPUT_ASSETS | {RELEASE_MANIFEST, RELEASE_SUMS}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_ASSET_BYTES = 512 * 1024 * 1024
ANDROID_DISTRIBUTION_MAX_PROOF_AGE_SECONDS = 86_400
ARCHIVE_LIMITS = ArchiveLimits(
    maximum_archive_bytes=MAX_ASSET_BYTES,
    maximum_member_count=16_384,
    maximum_member_bytes=MAX_ASSET_BYTES,
    maximum_total_bytes=1024 * 1024 * 1024,
)


class PlatformDistributionError(ValueError):
    """The platform release set is incomplete, inconsistent, or untrusted."""


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    commit: str
    tree: str
    canonical_source_tree_sha256: str
    source_date_epoch: int


@dataclass(frozen=True, slots=True)
class AndroidVerificationTools:
    llvm_nm: pathlib.Path
    llvm_readelf: pathlib.Path
    apksigner: pathlib.Path
    zipalign: pathlib.Path


def fail(message: str) -> NoReturn:
    raise PlatformDistributionError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _regular_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot inspect {label} {path}: {exc}")
    require(
        stat.S_ISDIR(metadata.st_mode) and not path.is_symlink(),
        f"{label} must be a non-symlink directory: {path}",
    )
    return resolved


def _inventory_files(root: pathlib.Path) -> dict[str, pathlib.Path]:
    files: dict[str, pathlib.Path] = {}
    try:
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            metadata = path.lstat()
            require(not path.is_symlink(), f"distribution tree contains symlink: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            require(
                stat.S_ISREG(metadata.st_mode),
                f"distribution tree contains unsupported file type: {path}",
            )
            relative = path.relative_to(root).as_posix()
            require(relative not in files, f"duplicate distribution path: {relative}")
            files[relative] = path
    except OSError as exc:
        fail(f"cannot enumerate distribution tree {root}: {exc}")
    return files


def _snapshot(path: pathlib.Path, label: str) -> FileSnapshot:
    try:
        return read_regular_snapshot(path, maximum=MAX_ASSET_BYTES, label=label)
    except EvidenceIOError as exc:
        fail(str(exc))


def _json(path: pathlib.Path, label: str, *, canonical: bool = True) -> tuple[dict[str, Any], FileSnapshot]:
    try:
        snapshot = load_json_object_snapshot(
            path,
            maximum=16 * 1024 * 1024,
            label=label,
        )
    except EvidenceIOError as exc:
        fail(str(exc))
    if canonical:
        require(snapshot.file.data == canonical_json(snapshot.value), f"{label} is not canonical JSON")
    return snapshot.value, snapshot.file


def _source_identity(root: pathlib.Path, *, require_head: bool) -> SourceIdentity:
    repository = _regular_directory(root, "repository root")
    try:
        tag_type = run_git_text(repository, ["cat-file", "-t", f"refs/tags/{RELEASE_TAG}"])
        tag_commit = run_git_text(
            repository, ["rev-parse", "--verify", f"refs/tags/{RELEASE_TAG}^{{commit}}"]
        )
        tag_tree = run_git_text(
            repository, ["rev-parse", "--verify", f"refs/tags/{RELEASE_TAG}^{{tree}}"]
        )
        epoch_text = run_git_text(repository, ["show", "-s", "--format=%ct", tag_commit])
        inspection = inspect_worktree(repository) if require_head else None
    except GitProvenanceError as exc:
        fail(f"cannot establish platform release provenance: {exc}")
    require(tag_type == "tag", f"release tag must be annotated: {RELEASE_TAG}")
    require(COMMIT_RE.fullmatch(tag_commit) is not None, "release tag commit is malformed")
    require(COMMIT_RE.fullmatch(tag_tree) is not None, "release tag tree is malformed")
    require(epoch_text.isascii() and epoch_text.isdigit(), "release source epoch is malformed")
    epoch = int(epoch_text)
    require(315_532_800 <= epoch <= 0xFFFFFFFF, "release source epoch is out of range")
    if require_head:
        assert inspection is not None
        require(not inspection.dirty, "platform distribution assembly requires a clean worktree")
        require(inspection.commit == tag_commit, "release tag does not point to current HEAD")
        try:
            source_digest = canonical_tree_digest(
                repository,
                repository_paths(repository),
            )
        except ValueError as exc:
            fail(f"cannot compute canonical release source digest: {exc}")
    else:
        source_digest = ""
    return SourceIdentity(
        commit=tag_commit,
        tree=tag_tree,
        canonical_source_tree_sha256=source_digest,
        source_date_epoch=epoch,
    )


def _abi_identity(root: pathlib.Path) -> dict[str, Any]:
    try:
        contract = load_contract(
            root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
        )
    except ValueError as exc:
        fail(f"cannot load ABI2 trust root: {exc}")
    exports = sorted(item["name"] for item in contract.document["abi"]["exports"])
    require(
        contract.document["package"]["semver"] == PRODUCT_VERSION,
        "ABI contract product version differs",
    )
    require(
        contract.document["abi"]["major"] == ABI_MAJOR
        and len(exports) == 9
        and len(set(exports)) == 9,
        "ABI contract is not the frozen nine-symbol ABI2 surface",
    )
    exports_sha256 = hashlib.sha256(
        ("\n".join(exports) + "\n").encode("utf-8")
    ).hexdigest()
    return {
        "major": ABI_MAJOR,
        "contract_sha256": contract.sha256,
        "exports_sha256": exports_sha256,
        "export_count": len(exports),
    }


def _validate_common_manifest(
    manifest: dict[str, Any],
    *,
    source: SourceIdentity,
    abi: dict[str, Any],
    label: str,
) -> None:
    require(manifest.get("version") == PRODUCT_VERSION, f"{label} product version differs")
    require(manifest.get("git_commit") == source.commit, f"{label} source commit differs")
    require(manifest.get("git_dirty") is False, f"{label} is not clean-source bound")
    manifest_abi = manifest.get("abi")
    require(isinstance(manifest_abi, dict), f"{label} ABI evidence is missing")
    require(manifest_abi.get("major") == ABI_MAJOR, f"{label} ABI major differs")
    require(
        manifest_abi.get("contract_sha256") == abi["contract_sha256"],
        f"{label} ABI contract digest differs",
    )
    require(
        manifest_abi.get("exports_sha256") == abi["exports_sha256"]
        and manifest_abi.get("export_count") == abi["export_count"],
        f"{label} ABI export-set evidence differs",
    )


def _linux_asset(
    archive: pathlib.Path,
    snapshot: FileSnapshot,
    *,
    repository: pathlib.Path,
    target: str,
    source: SourceIdentity,
    abi: dict[str, Any],
    scratch: pathlib.Path,
) -> dict[str, Any]:
    package = f"q-periapt-c-abi2-{PRODUCT_VERSION}-{target}"
    destination = scratch / f"extract-{target}"
    try:
        audit = extract_tar_gz(
            archive,
            destination,
            root_name=package,
            expected_sha256=snapshot.sha256,
            limits=ARCHIVE_LIMITS,
        )
    except DeterministicArchiveError as exc:
        fail(f"Linux {target} archive is invalid: {exc}")
    manifest, manifest_snapshot = _json(
        destination / package / "MANIFEST.json",
        f"Linux {target} MANIFEST.json",
    )
    try:
        verified_manifest = verify_c_package(
            destination / package,
            repository,
            expected_target=target,
            expected_commit=source.commit,
            expected_source_date_epoch=source.source_date_epoch,
        )
    except CPackageManifestError as exc:
        fail(f"Linux {target} package verification failed: {exc}")
    require(
        verified_manifest == manifest,
        f"Linux {target} package verifier observed different manifest bytes",
    )
    require(manifest.get("schema_version") == 2, f"Linux {target} manifest schema differs")
    _validate_common_manifest(
        manifest,
        source=source,
        abi=abi,
        label=f"Linux {target} manifest",
    )
    require(manifest.get("host") == target, f"Linux {target} manifest host differs")
    require(manifest.get("diagnostic_only") is False, f"Linux {target} manifest is diagnostic-only")
    require(manifest.get("source_date_epoch") == source.source_date_epoch, f"Linux {target} source epoch differs")
    require(audit.mtime == source.source_date_epoch, f"Linux {target} archive mtime differs")
    compatibility = manifest.get("platform_compatibility")
    require(
        isinstance(compatibility, dict) and compatibility.get("target") == target,
        f"Linux {target} compatibility target differs",
    )
    return {
        "bytes": snapshot.size,
        "media_type": "application/gzip",
        "name": archive.name,
        "package_manifest_sha256": manifest_snapshot.sha256,
        "platform": "linux",
        "role": "native-sdk",
        "sha256": snapshot.sha256,
        "target": target,
    }


def _windows_asset(
    archive: pathlib.Path,
    snapshot: FileSnapshot,
    *,
    repository: pathlib.Path,
    source: SourceIdentity,
    abi: dict[str, Any],
    scratch: pathlib.Path,
) -> dict[str, Any]:
    target = "x86_64-pc-windows-msvc"
    package = f"q-periapt-c-abi2-{PRODUCT_VERSION}-{target}"
    destination = scratch / "extract-windows"
    try:
        audit = extract_zip(
            archive,
            destination,
            root_name=package,
            expected_sha256=snapshot.sha256,
            limits=ARCHIVE_LIMITS,
        )
    except DeterministicArchiveError as exc:
        fail(f"Windows archive is invalid: {exc}")
    manifest, manifest_snapshot = _json(
        destination / package / "MANIFEST.json",
        "Windows MANIFEST.json",
    )
    try:
        verified_manifest = verify_windows_package(
            destination / package,
            repository_root=repository,
            expected_git_commit=source.commit,
            expected_git_tree=source.tree,
        )
    except WindowsPackageError as exc:
        fail(f"Windows package verification failed: {exc}")
    require(
        verified_manifest == manifest,
        "Windows package verifier observed different manifest bytes",
    )
    require(manifest.get("schema_version") == 2, "Windows manifest schema differs")
    _validate_common_manifest(
        manifest,
        source=source,
        abi=abi,
        label="Windows manifest",
    )
    require(manifest.get("target") == target, "Windows manifest target differs")
    require(manifest.get("source_date_epoch") == source.source_date_epoch, "Windows source epoch differs")
    require(audit.mtime == source.source_date_epoch - source.source_date_epoch % 2, "Windows archive mtime differs")
    require(
        manifest.get("release_class") == "unsigned_experimental_prerelease"
        and isinstance(manifest.get("authenticode"), dict)
        and manifest["authenticode"].get("signed") is False,
        "Windows unsigned experimental boundary differs",
    )
    return {
        "authenticode_signed": False,
        "bytes": snapshot.size,
        "media_type": "application/zip",
        "name": archive.name,
        "package_manifest_sha256": manifest_snapshot.sha256,
        "platform": "windows",
        "release_class": "unsigned_experimental_prerelease",
        "role": "native-sdk",
        "sha256": snapshot.sha256,
        "target": target,
    }


def _android_assets(
    files: dict[str, pathlib.Path],
    snapshots: dict[str, FileSnapshot],
    *,
    repository: pathlib.Path,
    source: SourceIdentity,
    abi: dict[str, Any],
    scratch: pathlib.Path,
    tools: AndroidVerificationTools,
    require_fresh_proof: bool,
) -> list[dict[str, Any]]:
    aar_manifest, manifest_snapshot = _json(
        files[ANDROID_MANIFEST],
        "Android AAR MANIFEST.json",
    )
    require(aar_manifest.get("schema_version") == 3, "Android AAR manifest schema differs")
    _validate_common_manifest(
        aar_manifest,
        source=source,
        abi=abi,
        label="Android AAR manifest",
    )
    require(aar_manifest.get("package") == ANDROID_AAR, "Android AAR manifest package differs")
    require(aar_manifest.get("package_only") is True, "Android AAR manifest package boundary differs")
    require(aar_manifest.get("device_runtime_proof") is False, "Android AAR manifest falsely claims runtime proof")
    require(
        aar_manifest.get("source_date_epoch") == source.source_date_epoch,
        "Android AAR source epoch differs",
    )
    android = aar_manifest.get("android")
    require(
        isinstance(android, dict)
        and android.get("native_page_alignment") == 16_384
        and android.get("ndk") == "29.0.14206865",
        "Android AAR toolchain or 16 KiB alignment evidence differs",
    )
    artifacts = aar_manifest.get("artifacts")
    require(
        isinstance(artifacts, dict)
        and artifacts.get("aar_sha256") == snapshots[ANDROID_AAR].sha256,
        "Android AAR manifest digest differs from release asset",
    )

    bundle = files[ANDROID_RUNTIME_BUNDLE]
    try:
        verified_bundle_sha256 = verify_runtime_bundle(
            root=repository,
            bundle=bundle,
            expected_bundle_sha256=snapshots[ANDROID_RUNTIME_BUNDLE].sha256,
            llvm_nm=tools.llvm_nm,
            llvm_readelf=tools.llvm_readelf,
            apksigner=tools.apksigner,
            zipalign=tools.zipalign,
            expected_device_kind="emulator",
            expected_device_abi="arm64-v8a",
            expected_page_size=16_384,
            expected_device_sdk=35,
            require_release_mode=True,
            allow_dirty_proof=False,
            forbidden_text=[str(repository), repository.as_posix()],
        )
    except SystemExit as exc:
        fail(f"Android runtime evidence bundle verification failed: {exc}")
    require(
        verified_bundle_sha256 == snapshots[ANDROID_RUNTIME_BUNDLE].sha256,
        "Android runtime verifier observed different bundle bytes",
    )
    destination = scratch / "extract-android-runtime"
    try:
        audit = extract_zip(
            bundle,
            destination,
            root_name=BUNDLE_ROOT_NAME,
            expected_sha256=snapshots[ANDROID_RUNTIME_BUNDLE].sha256,
            limits=ARCHIVE_LIMITS,
        )
    except DeterministicArchiveError as exc:
        fail(f"Android runtime evidence bundle is invalid: {exc}")
    bundle_root = destination / BUNDLE_ROOT_NAME
    bundle_manifest, bundle_manifest_snapshot = _json(
        bundle_root / BUNDLE_MANIFEST_PATH,
        "Android runtime bundle MANIFEST.json",
    )
    try:
        selected, proof = verify_bundle_manifest(
            bundle_root,
            bundle_manifest,
            archive_mtime=audit.mtime,
        )
    except SystemExit as exc:
        fail(f"Android runtime bundle manifest is invalid: {exc}")
    require(bundle_manifest.get("git_commit") == source.commit, "Android runtime bundle source commit differs")
    require(bundle_manifest.get("source_date_epoch") == source.source_date_epoch, "Android runtime bundle source epoch differs")
    require(bundle_manifest.get("release_candidate_mode") is True, "Android runtime bundle is not release-candidate evidence")
    require(
        bundle_manifest.get("device")
        == {
            "kind": "emulator",
            "abi": "arm64-v8a",
            "page_size": 16_384,
            "sdk": 35,
        },
        "Android runtime bundle did not run on the required API 35 arm64 16 KiB emulator",
    )
    require(proof.get("device_runtime_proof") is True and proof.get("package_only") is False, "Android runtime proof boundary differs")
    require(proof.get("git_commit") == source.commit, "Android runtime proof source commit differs")
    if require_fresh_proof:
        try:
            verify_proof_freshness(
                proof,
                ANDROID_DISTRIBUTION_MAX_PROOF_AGE_SECONDS,
            )
        except SystemExit as exc:
            fail(f"Android runtime proof freshness gate failed: {exc}")
    require(
        _snapshot(selected["aar"], "bundled Android AAR").sha256
        == snapshots[ANDROID_AAR].sha256,
        "Android runtime bundle did not exercise the public AAR bytes",
    )
    require(
        _snapshot(selected["aar_manifest"], "bundled Android AAR manifest").sha256
        == manifest_snapshot.sha256,
        "Android runtime bundle AAR manifest differs from the public manifest",
    )
    proof_snapshot = _snapshot(selected["proof"], "bundled Android runtime proof")
    return [
        {
            "bytes": snapshots[ANDROID_AAR].size,
            "media_type": "application/vnd.android.aar",
            "name": ANDROID_AAR,
            "package_manifest_sha256": manifest_snapshot.sha256,
            "platform": "android",
            "role": "runtime-library",
            "sha256": snapshots[ANDROID_AAR].sha256,
            "target": "arm64-v8a,armeabi-v7a,x86,x86_64",
        },
        {
            "bytes": manifest_snapshot.size,
            "media_type": "application/json",
            "name": ANDROID_MANIFEST,
            "platform": "android",
            "role": "package-manifest",
            "sha256": manifest_snapshot.sha256,
            "target": "arm64-v8a,armeabi-v7a,x86,x86_64",
        },
        {
            "bundle_manifest_sha256": bundle_manifest_snapshot.sha256,
            "bytes": snapshots[ANDROID_RUNTIME_BUNDLE].size,
            "device": {
                "kind": "emulator",
                "abi": "arm64-v8a",
                "page_size": 16_384,
                "sdk": 35,
            },
            "media_type": "application/zip",
            "name": ANDROID_RUNTIME_BUNDLE,
            "platform": "android",
            "proof_sha256": proof_snapshot.sha256,
            "role": "runtime-evidence",
            "sha256": snapshots[ANDROID_RUNTIME_BUNDLE].sha256,
            "tested_aar_sha256": snapshots[ANDROID_AAR].sha256,
            "target": "arm64-v8a",
        },
    ]


def _build_manifest(
    root: pathlib.Path,
    release_dir: pathlib.Path,
    *,
    source: SourceIdentity,
    android_tools: AndroidVerificationTools,
    require_fresh_android_proof: bool,
) -> dict[str, Any]:
    files = _inventory_files(release_dir)
    require(
        frozenset(files) in {INPUT_ASSETS, RELEASE_FILES},
        "distribution input asset set differs",
    )
    snapshots = {
        name: _snapshot(path, f"platform distribution asset {name}")
        for name, path in files.items()
    }
    abi = _abi_identity(root)
    scratch_parent = release_dir.parent
    with tempfile.TemporaryDirectory(
        prefix="qperiapt-platform-distribution-",
        dir=scratch_parent,
    ) as temporary:
        scratch = pathlib.Path(temporary)
        assets = _android_assets(
            files,
            snapshots,
            repository=root,
            source=source,
            abi=abi,
            scratch=scratch,
            tools=android_tools,
            require_fresh_proof=require_fresh_android_proof,
        )
        assets.append(
            _linux_asset(
                files[LINUX_X86_64],
                snapshots[LINUX_X86_64],
                repository=root,
                target="x86_64-unknown-linux-gnu",
                source=source,
                abi=abi,
                scratch=scratch,
            )
        )
        assets.append(
            _linux_asset(
                files[LINUX_AARCH64],
                snapshots[LINUX_AARCH64],
                repository=root,
                target="aarch64-unknown-linux-gnu",
                source=source,
                abi=abi,
                scratch=scratch,
            )
        )
        assets.append(
            _windows_asset(
                files[WINDOWS_X86_64],
                snapshots[WINDOWS_X86_64],
                repository=root,
                source=source,
                abi=abi,
                scratch=scratch,
            )
        )
    assets.sort(key=lambda item: item["name"])
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "product_version": PRODUCT_VERSION,
        "distribution_revision": DISTRIBUTION_REVISION,
        "release_tag": RELEASE_TAG,
        "release_channel": "github-immutable-prerelease",
        "generated_at": dt.datetime.fromtimestamp(
            source.source_date_epoch,
            tz=dt.timezone.utc,
        ).isoformat().replace("+00:00", "Z"),
        "source": {
            "git_commit": source.commit,
            "git_tree": source.tree,
            "canonical_source_tree_sha256": source.canonical_source_tree_sha256,
            "source_date_epoch": source.source_date_epoch,
            "git_dirty": False,
        },
        "abi": abi,
        "assets": assets,
        "security_boundaries": {
            "android_runtime": "arm64-v8a API 35 emulator with 16 KiB pages; other packaged ABIs are statically audited but not runtime-executed in this evidence bundle",
            "linux": "native GNU/Linux x86_64 and aarch64 packages with exact GLIBC, ELF hardening, ABI, pkg-config, and CMake consumer gates",
            "windows": "unsigned experimental prerelease; no Authenticode credential was available, so integrity is SHA-256 plus GitHub release/build attestations",
        },
        "convergence": {
            "temporary_distribution_revision": True,
            "next_release": "return to one unified SemVer release line across Apple, Android, Linux, and Windows",
        },
        "immutability_required": True,
    }


def assemble(
    root: pathlib.Path,
    assets_dir: pathlib.Path,
    output_dir: pathlib.Path,
    *,
    android_tools: AndroidVerificationTools,
) -> dict[str, Any]:
    repository = _regular_directory(root, "repository root")
    inputs = _regular_directory(assets_dir, "platform input asset directory")
    input_files = _inventory_files(inputs)
    require(set(input_files) == INPUT_ASSETS, "platform input asset set differs")
    output = pathlib.Path(output_dir)
    require(not output.exists() and not output.is_symlink(), f"platform output directory already exists: {output}")
    _regular_directory(output.parent, "platform output parent")
    source = _source_identity(repository, require_head=True)
    output.mkdir(mode=0o755)
    try:
        for name in sorted(INPUT_ASSETS):
            snapshot = _snapshot(input_files[name], f"platform input asset {name}")
            destination = output / name
            destination.write_bytes(snapshot.data)
            os.chmod(destination, 0o644)
        manifest = _build_manifest(
            repository,
            output,
            source=source,
            android_tools=android_tools,
            require_fresh_android_proof=True,
        )
        manifest_path = output / RELEASE_MANIFEST
        manifest_path.write_bytes(canonical_json(manifest))
        os.chmod(manifest_path, 0o644)
        sums: list[tuple[str, str]] = []
        for name in sorted(INPUT_ASSETS | {RELEASE_MANIFEST}):
            sums.append((_snapshot(output / name, f"release file {name}").sha256, name))
        sums_path = output / RELEASE_SUMS
        sums_path.write_text(
            "".join(f"{digest}  {name}\n" for digest, name in sums),
            encoding="ascii",
        )
        os.chmod(sums_path, 0o644)
        verify_distribution(repository, output, android_tools=android_tools)
    except Exception:
        if output.exists() and not output.is_symlink():
            shutil.rmtree(output)
        raise
    return manifest


def _parse_sums(path: pathlib.Path) -> dict[str, str]:
    snapshot = _snapshot(path, "platform SHA256SUMS")
    try:
        text = snapshot.data.decode("ascii")
    except UnicodeDecodeError as exc:
        fail(f"platform SHA256SUMS is not ASCII: {exc}")
    require(text.endswith("\n"), "platform SHA256SUMS must end with a newline")
    entries: dict[str, str] = {}
    for line in text.splitlines():
        require(bool(line), "platform SHA256SUMS contains a blank line")
        parts = line.split("  ", 1)
        require(len(parts) == 2, f"malformed platform SHA256SUMS line: {line!r}")
        digest, name = parts
        require(SHA256_RE.fullmatch(digest) is not None, f"invalid platform checksum: {name}")
        require(name in INPUT_ASSETS | {RELEASE_MANIFEST}, f"unexpected platform checksum path: {name}")
        require(name not in entries, f"duplicate platform checksum path: {name}")
        entries[name] = digest
    require(list(entries) == sorted(entries), "platform SHA256SUMS is not canonically sorted")
    return entries


def verify_distribution(
    root: pathlib.Path,
    release_dir: pathlib.Path,
    *,
    android_tools: AndroidVerificationTools,
) -> dict[str, Any]:
    repository = _regular_directory(root, "repository root")
    release = _regular_directory(release_dir, "platform release directory")
    files = _inventory_files(release)
    require(set(files) == RELEASE_FILES, "platform release file set differs")
    manifest, manifest_snapshot = _json(
        files[RELEASE_MANIFEST],
        "platform distribution manifest",
    )
    require(
        set(manifest)
        == {
            "schema_version",
            "kind",
            "product_version",
            "distribution_revision",
            "release_tag",
            "release_channel",
            "generated_at",
            "source",
            "abi",
            "assets",
            "security_boundaries",
            "convergence",
            "immutability_required",
        },
        "platform distribution manifest fields differ",
    )
    require(
        manifest.get("schema_version") == SCHEMA_VERSION
        and manifest.get("kind") == KIND
        and manifest.get("product_version") == PRODUCT_VERSION
        and manifest.get("distribution_revision") == DISTRIBUTION_REVISION
        and manifest.get("release_tag") == RELEASE_TAG,
        "platform distribution identity differs",
    )
    require(
        manifest.get("release_channel") == "github-immutable-prerelease"
        and manifest.get("immutability_required") is True,
        "platform distribution release channel differs",
    )
    actual_source = _source_identity(repository, require_head=True)
    source = manifest.get("source")
    require(isinstance(source, dict), "platform distribution source identity is missing")
    require(source.get("git_commit") == actual_source.commit, "platform distribution tag commit differs")
    require(source.get("git_tree") == actual_source.tree, "platform distribution tag tree differs")
    require(source.get("source_date_epoch") == actual_source.source_date_epoch, "platform distribution source epoch differs")
    require(source.get("git_dirty") is False, "platform distribution is not clean-source bound")
    require(
        isinstance(source.get("canonical_source_tree_sha256"), str)
        and SHA256_RE.fullmatch(source["canonical_source_tree_sha256"]) is not None,
        "platform distribution canonical source digest is malformed",
    )
    require(
        source["canonical_source_tree_sha256"]
        == actual_source.canonical_source_tree_sha256,
        "platform distribution canonical source digest differs from the tagged source",
    )
    expected_generated = dt.datetime.fromtimestamp(
        actual_source.source_date_epoch,
        tz=dt.timezone.utc,
    ).isoformat().replace("+00:00", "Z")
    require(manifest.get("generated_at") == expected_generated, "platform distribution generated_at differs")
    require(manifest.get("abi") == _abi_identity(repository), "platform distribution ABI trust root differs")
    rebuilt = _build_manifest(
        repository,
        release,
        source=actual_source,
        android_tools=android_tools,
        require_fresh_android_proof=False,
    )
    require(manifest == rebuilt, "platform distribution manifest differs from release asset bytes")
    sums = _parse_sums(files[RELEASE_SUMS])
    expected_sums = {
        name: _snapshot(files[name], f"platform release file {name}").sha256
        for name in INPUT_ASSETS
    }
    expected_sums[RELEASE_MANIFEST] = manifest_snapshot.sha256
    require(sums == dict(sorted(expected_sums.items())), "platform SHA256SUMS differs from release bytes")
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_android_tools(command: argparse.ArgumentParser) -> None:
        command.add_argument("--android-llvm-nm", required=True, type=pathlib.Path)
        command.add_argument("--android-llvm-readelf", required=True, type=pathlib.Path)
        command.add_argument("--android-apksigner", required=True, type=pathlib.Path)
        command.add_argument("--android-zipalign", required=True, type=pathlib.Path)

    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--root", required=True, type=pathlib.Path)
    assemble_parser.add_argument("--assets-dir", required=True, type=pathlib.Path)
    assemble_parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    add_android_tools(assemble_parser)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", required=True, type=pathlib.Path)
    verify_parser.add_argument("--release-dir", required=True, type=pathlib.Path)
    add_android_tools(verify_parser)
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    android_tools = AndroidVerificationTools(
        llvm_nm=args.android_llvm_nm,
        llvm_readelf=args.android_llvm_readelf,
        apksigner=args.android_apksigner,
        zipalign=args.android_zipalign,
    )
    try:
        if args.command == "assemble":
            manifest = assemble(
                args.root,
                args.assets_dir,
                args.output_dir,
                android_tools=android_tools,
            )
            print(
                "ABI2_PLATFORM_DISTRIBUTION_ASSEMBLE_PASS "
                f"commit={manifest['source']['git_commit']} assets={len(manifest['assets'])}"
            )
        else:
            manifest = verify_distribution(
                args.root,
                args.release_dir,
                android_tools=android_tools,
            )
            print(
                "ABI2_PLATFORM_DISTRIBUTION_VERIFY_PASS "
                f"commit={manifest['source']['git_commit']} assets={len(manifest['assets'])}"
            )
    except (OSError, PlatformDistributionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
