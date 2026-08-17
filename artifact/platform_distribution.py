#!/usr/bin/env python3
"""Assemble and verify the ABI2 stable Android/Linux distribution."""

from __future__ import annotations

import argparse
import contextlib
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
from collections.abc import Iterator, Mapping
from typing import Any, NoReturn

from android_device_proof import (
    BUNDLE_MANIFEST_PATH,
    BUNDLE_ROOT_NAME,
    BUNDLE_SCHEMA_VERSION,
    PROOF_SCHEMA_VERSION,
    verify_bundle_manifest,
    verify_proof_freshness,
    verify_runtime_bundle,
)
from android_elf import (
    EXPECTED_CARGO_VERSION as ANDROID_EXPECTED_CARGO_VERSION,
)
from android_elf import (
    EXPECTED_RUSTC_VERSION as ANDROID_EXPECTED_RUSTC_VERSION,
)
from android_elf import (
    MANIFEST_SCHEMA_VERSION as ANDROID_MANIFEST_SCHEMA_VERSION,
)
from c_abi_contract import ABI_MAJOR, load_contract
from c_package_manifest import (
    CPackageManifestError,
)
from c_package_manifest import (
    verify_package as verify_c_package,
)
from claim_ledger import canonical_tree_digest, repository_paths
from deterministic_archive import (
    ArchiveLimits,
    DeterministicArchiveError,
    extract_tar_gz,
    extract_zip,
)
from evidence_io import (
    EvidenceIOError,
    FileDigestSnapshot,
    FileSnapshot,
    consume_regular_snapshot_at,
    load_json_object_snapshot,
    load_json_object_snapshot_at,
    read_regular_snapshot,
)
from git_provenance import GitProvenanceError, inspect_worktree, run_git_text
from platform_distribution_contract import (
    ANDROID_AAR,
    ANDROID_MANIFEST,
    ANDROID_RUNTIME_BUNDLE,
    DISTRIBUTION_REVISION,
    LINUX_AARCH64,
    LINUX_X86_64,
    MAX_PLATFORM_ASSET_BYTES,
    PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
    PLATFORM_CANDIDATE_ASSETS,
    PLATFORM_RELEASE_CANDIDATE_KIND,
    PLATFORM_RELEASE_CANDIDATE_SCHEMA_VERSION,
    PlatformDistributionContractError,
    PUBLIC_ASSET_CONTENT_TYPES,
    PUBLIC_ASSET_NAMES,
    PRODUCT_VERSION,
    RELEASE_MANIFEST,
    RELEASE_SUMS,
    RELEASE_TAG,
    validate_release_candidate_receipt,
)
from platform_distribution_contract import (
    PLATFORM_DISTRIBUTION_KIND as KIND,
)
from platform_distribution_contract import (
    PLATFORM_DISTRIBUTION_SCHEMA_VERSION as SCHEMA_VERSION,
)
from platform_distribution_contract import (
    PLATFORM_INPUT_ASSETS as INPUT_ASSETS,
)
from platform_distribution_contract import (
    PLATFORM_RELEASE_FILES as RELEASE_FILES,
)
from publication_receipt_io import (
    PRIVATE_FILE_MODE,
    PrivateDirectoryHandle,
    PublicationReceiptCommittedError,
    PublicationReceiptIOError,
    create_private_direct_child_handle,
    ensure_private_safe_root,
    normalize_safe_root,
    open_private_direct_child_handle,
    open_private_directory,
    open_private_directory_at,
    prepare_private_json_noreplace_at,
    stage_private_file_from_fd_noreplace_at,
    verify_exact_directory_inventory_at,
    verify_private_directory_handle_identity,
)

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

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
PLATFORM_RELEASE_CANDIDATE_ROOT = (
    REPOSITORY_ROOT / "target" / "abi2-platform-release-candidates"
)
PLATFORM_RELEASE_DIRECTORY_NAME = "release"
PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME = (
    "platform-release-candidate-receipt.json"
)
PLATFORM_RELEASE_TRANSACTION_NAME = re.compile(
    r"^transaction\.[0-9A-Za-z][0-9A-Za-z_-]{0,63}$"
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
    """Fixed local tools used to reverify the current Android release bundle."""

    llvm_nm: pathlib.Path
    llvm_readelf: pathlib.Path
    apksigner: pathlib.Path
    zipalign: pathlib.Path


@dataclass(frozen=True, slots=True)
class ReleaseCandidateBundle:
    """One descriptor-resampled completion receipt and its exact seven bytes."""

    receipt: dict[str, Any]
    receipt_sha256: str
    assets: tuple[FileDigestSnapshot, ...]
    transaction_device: int
    transaction_inode: int
    release_device: int
    release_inode: int

    def asset_by_name(self) -> dict[str, FileDigestSnapshot]:
        return {
            name: snapshot
            for name, snapshot in zip(PUBLIC_ASSET_NAMES, self.assets, strict=True)
        }


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
        if inspection is None:
            fail("platform worktree inspection is unavailable")
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
    require(
        aar_manifest.get("schema_version") == ANDROID_MANIFEST_SCHEMA_VERSION,
        "Android AAR manifest schema differs",
    )
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
    require(
        aar_manifest.get("toolchain")
        == {
            "cargo": ANDROID_EXPECTED_CARGO_VERSION,
            "rustc": ANDROID_EXPECTED_RUSTC_VERSION,
        },
        "Android AAR Rust toolchain evidence differs",
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
    require(
        bundle_manifest.get("schema_version") == BUNDLE_SCHEMA_VERSION,
        "Android runtime bundle is not the current bundle schema",
    )
    require(
        proof.get("schema") == PROOF_SCHEMA_VERSION,
        "Android runtime proof is not the current proof schema",
    )
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
    assets.sort(key=lambda item: item["name"])
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "product_version": PRODUCT_VERSION,
        "distribution_revision": DISTRIBUTION_REVISION,
        "release_tag": RELEASE_TAG,
        "release_channel": "github-immutable-release",
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
            "windows": "excluded from this formal stable asset set; the separate unsigned diagnostic package is unsupported until an Authenticode producer, verifier, certificate, and timestamp-authority gate exist",
        },
        "convergence": {
            "temporary_distribution_revision": True,
            "next_release": "add Windows only after its signed publication boundary is implemented and verified",
        },
        "immutability_required": True,
    }


def assemble(
    root: pathlib.Path,
    assets_dir: pathlib.Path,
    output_dir: pathlib.Path,
    *,
    android_tools: AndroidVerificationTools,
    runtime_bundle: pathlib.Path | None = None,
    preserve_failed_output: bool = False,
) -> dict[str, Any]:
    repository = _regular_directory(root, "repository root")
    inputs = _regular_directory(assets_dir, "platform input asset directory")
    inventoried_inputs = _inventory_files(inputs)
    if runtime_bundle is None:
        require(
            set(inventoried_inputs) == INPUT_ASSETS,
            "platform input asset set differs",
        )
        input_files = inventoried_inputs
    else:
        require(
            set(inventoried_inputs)
            == set(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS),
            "verified platform candidate input set differs",
        )
        input_files = {
            name: inventoried_inputs[name] for name in PLATFORM_CANDIDATE_ASSETS
        }
        input_files[ANDROID_RUNTIME_BUNDLE] = pathlib.Path(runtime_bundle)
    output = pathlib.Path(output_dir)
    require(not output.exists() and not output.is_symlink(), f"platform output directory already exists: {output}")
    _regular_directory(output.parent, "platform output parent")
    source = _source_identity(repository, require_head=True)
    output.mkdir(mode=0o755)
    os.chmod(output, 0o755)
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
        if (
            not preserve_failed_output
            and output.exists()
            and not output.is_symlink()
        ):
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
        manifest.get("release_channel") == "github-immutable-release"
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


def _public_release_asset_metadata(metadata: os.stat_result) -> None:
    require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o644
        and metadata.st_nlink == 1,
        "platform release candidate asset metadata differs",
    )


def _snapshot_release_assets(
    release_directory: PrivateDirectoryHandle,
    *,
    sync_files: bool,
) -> list[dict[str, object]]:
    descriptor = release_directory.descriptor
    path = release_directory.path
    try:
        verify_exact_directory_inventory_at(
            descriptor,
            frozenset(PUBLIC_ASSET_NAMES),
            label="platform release candidate directory",
        )
        records: list[dict[str, object]] = []
        for name in PUBLIC_ASSET_NAMES:
            if sync_files:
                file_descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=descriptor,
                )
                primary_error: BaseException | None = None
                try:
                    opened = os.fstat(file_descriptor)
                    named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    _public_release_asset_metadata(opened)
                    require(
                        named.st_dev == opened.st_dev
                        and named.st_ino == opened.st_ino,
                        f"platform release candidate asset identity changed for {name}",
                    )
                    os.fsync(file_descriptor)
                except BaseException as exc:
                    primary_error = exc
                    raise
                finally:
                    try:
                        os.close(file_descriptor)
                    except OSError as exc:
                        if primary_error is not None:
                            primary_error.add_note(
                                f"cannot close platform release candidate asset {name}"
                            )
                        else:
                            raise PlatformDistributionError(
                                f"cannot close platform release candidate asset {name}"
                            ) from exc
            snapshot = consume_regular_snapshot_at(
                descriptor,
                name,
                display_path=path / name,
                maximum=MAX_PLATFORM_ASSET_BYTES,
                label=f"platform release candidate asset {name}",
                validate_metadata=_public_release_asset_metadata,
            )
            require(snapshot.size > 0, f"platform release candidate asset is empty: {name}")
            records.append(
                {
                    "bytes": snapshot.size,
                    "content_type": PUBLIC_ASSET_CONTENT_TYPES[name],
                    "name": name,
                    "sha256": snapshot.sha256,
                }
            )
        if sync_files:
            os.fsync(descriptor)
        verify_exact_directory_inventory_at(
            descriptor,
            frozenset(PUBLIC_ASSET_NAMES),
            label="platform release candidate directory after snapshot",
        )
        verify_private_directory_handle_identity(
            release_directory,
            label="platform release candidate directory",
        )
        return records
    except (EvidenceIOError, PublicationReceiptIOError) as exc:
        raise PlatformDistributionError(str(exc)) from exc
    except OSError as exc:
        raise PlatformDistributionError(
            "cannot durably snapshot platform release candidate assets"
        ) from exc


def _snapshot_release_asset_files(
    release_directory: PrivateDirectoryHandle,
) -> tuple[FileDigestSnapshot, ...]:
    """Read the seven candidate assets through the already-pinned directory."""

    try:
        verify_exact_directory_inventory_at(
            release_directory.descriptor,
            frozenset(PUBLIC_ASSET_NAMES),
            label="platform release candidate file snapshot directory",
        )
        snapshots = tuple(
            consume_regular_snapshot_at(
                release_directory.descriptor,
                name,
                display_path=release_directory.path / name,
                maximum=MAX_PLATFORM_ASSET_BYTES,
                label=f"platform release candidate file snapshot {name}",
                validate_metadata=_public_release_asset_metadata,
            )
            for name in PUBLIC_ASSET_NAMES
        )
        require(
            all(snapshot.size > 0 for snapshot in snapshots),
            "platform release candidate file snapshot is empty",
        )
        verify_exact_directory_inventory_at(
            release_directory.descriptor,
            frozenset(PUBLIC_ASSET_NAMES),
            label="platform release candidate file snapshot directory after read",
        )
        verify_private_directory_handle_identity(
            release_directory,
            label="platform release candidate file snapshot directory",
        )
        return snapshots
    except (EvidenceIOError, PublicationReceiptIOError) as exc:
        raise PlatformDistributionError(str(exc)) from exc


def _candidate_runtime_projection(
    manifest: dict[str, Any],
    assets: dict[str, dict[str, object]],
) -> dict[str, object]:
    values = manifest.get("assets")
    require(isinstance(values, list), "platform manifest assets are missing")
    records: dict[str, dict[str, Any]] = {}
    for value in values:
        require(
            isinstance(value, dict)
            and all(isinstance(key, str) for key in value),
            "platform manifest asset is malformed",
        )
        name = value.get("name")
        require(
            isinstance(name, str) and name not in records,
            "platform manifest asset names differ",
        )
        records[name] = value
    require(
        ANDROID_RUNTIME_BUNDLE in records,
        "platform manifest lacks Android runtime evidence",
    )
    runtime = records[ANDROID_RUNTIME_BUNDLE]
    device = runtime.get("device")
    require(isinstance(device, dict), "platform manifest Android device is missing")
    return {
        "bundle_manifest_sha256": runtime.get("bundle_manifest_sha256"),
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "bundle_sha256": assets[ANDROID_RUNTIME_BUNDLE]["sha256"],
        "device_abi": device.get("abi"),
        "device_kind": device.get("kind"),
        "device_sdk": device.get("sdk"),
        "page_size": device.get("page_size"),
        "proof_schema": PROOF_SCHEMA_VERSION,
        "proof_sha256": runtime.get("proof_sha256"),
        "release_mode": True,
        "tested_aar_manifest_sha256": assets[ANDROID_MANIFEST]["sha256"],
        "tested_aar_sha256": runtime.get("tested_aar_sha256"),
    }


def _release_candidate_receipt(
    manifest: dict[str, Any],
    asset_records: list[dict[str, object]],
) -> dict[str, object]:
    assets = {record["name"]: record for record in asset_records}
    receipt: dict[str, object] = {
        "android_runtime_evidence": _candidate_runtime_projection(
            manifest,
            assets,
        ),
        "assets": asset_records,
        "checksums_sha256": assets[RELEASE_SUMS]["sha256"],
        "kind": PLATFORM_RELEASE_CANDIDATE_KIND,
        "platform_distribution_sha256": assets[RELEASE_MANIFEST]["sha256"],
        "schema_version": PLATFORM_RELEASE_CANDIDATE_SCHEMA_VERSION,
        "source": manifest["source"],
    }
    try:
        validate_release_candidate_receipt(receipt)
    except PlatformDistributionContractError as exc:
        raise PlatformDistributionError(
            f"platform release candidate receipt is invalid: {exc}"
        ) from exc
    return receipt


def _release_transaction_name(value: object) -> str:
    require(
        isinstance(value, str)
        and PLATFORM_RELEASE_TRANSACTION_NAME.fullmatch(value) is not None,
        "platform release transaction name must use transaction.<bounded-id>",
    )
    return value


def assemble_candidate_transaction(
    root: pathlib.Path,
    candidate_dir: pathlib.Path,
    runtime_bundle: pathlib.Path,
    transaction_name: str,
    *,
    android_tools: AndroidVerificationTools,
) -> tuple[pathlib.Path, str, pathlib.Path, dict[str, object]]:
    """Assemble seven public files and commit one manifest-last private receipt."""

    repository = _regular_directory(root, "repository root")
    require(
        repository == REPOSITORY_ROOT.resolve(strict=True),
        "platform release candidate assembly requires the fixed repository root",
    )
    transaction_name = _release_transaction_name(transaction_name)
    committed_digest: str | None = None
    committed_path: pathlib.Path | None = None
    try:
        ensure_private_safe_root(
            PLATFORM_RELEASE_CANDIDATE_ROOT,
            label="platform release candidate root",
        )
        with create_private_direct_child_handle(
            safe_root=PLATFORM_RELEASE_CANDIDATE_ROOT,
            direct_child_name=transaction_name,
            label="platform release candidate transaction",
        ) as transaction:
            verify_exact_directory_inventory_at(
                transaction.descriptor,
                frozenset(),
                label="new platform release candidate transaction",
            )
            release_path = transaction.path / PLATFORM_RELEASE_DIRECTORY_NAME
            manifest = assemble(
                repository,
                candidate_dir,
                release_path,
                android_tools=android_tools,
                runtime_bundle=runtime_bundle,
                preserve_failed_output=True,
            )
            verify_private_directory_handle_identity(
                transaction,
                label="platform release candidate transaction after assembly",
            )
            verify_exact_directory_inventory_at(
                transaction.descriptor,
                frozenset({PLATFORM_RELEASE_DIRECTORY_NAME}),
                label="assembled platform release candidate transaction",
            )
            with open_private_directory_at(
                parent=transaction,
                direct_child_name=PLATFORM_RELEASE_DIRECTORY_NAME,
                label="platform release candidate directory",
                required_mode=0o755,
            ) as release:
                first_assets = _snapshot_release_assets(release, sync_files=True)
                verify_private_directory_handle_identity(
                    transaction,
                    label="platform release candidate transaction before final deep verify",
                )
                verify_private_directory_handle_identity(
                    release,
                    label="platform release candidate directory before final deep verify",
                )
                final_manifest = verify_distribution(
                    repository,
                    release.path,
                    android_tools=android_tools,
                )
                require(
                    final_manifest == manifest,
                    "platform release candidate manifest changed after assembly",
                )
                verify_private_directory_handle_identity(
                    transaction,
                    label="platform release candidate transaction after final deep verify",
                )
                verify_private_directory_handle_identity(
                    release,
                    label="platform release candidate directory after final deep verify",
                )
                verified_assets = _snapshot_release_assets(
                    release,
                    sync_files=False,
                )
                require(
                    verified_assets == first_assets,
                    "platform release candidate assets changed during final deep verify",
                )
                receipt = _release_candidate_receipt(manifest, first_assets)
                with prepare_private_json_noreplace_at(
                    transaction,
                    PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
                    receipt,
                    label="platform release candidate completion receipt",
                ) as prepared:
                    current_source = _source_identity(repository, require_head=True)
                    require(
                        manifest["source"]
                        == {
                            "git_commit": current_source.commit,
                            "git_tree": current_source.tree,
                            "canonical_source_tree_sha256": (
                                current_source.canonical_source_tree_sha256
                            ),
                            "source_date_epoch": current_source.source_date_epoch,
                            "git_dirty": False,
                        },
                        "platform release candidate source changed before receipt commit",
                    )
                    second_assets = _snapshot_release_assets(
                        release,
                        sync_files=False,
                    )
                    require(
                        second_assets == first_assets,
                        "platform release candidate assets changed before receipt commit",
                    )
                    digest = prepared.commit_after_revalidation()
                    committed_digest = digest
                    committed_path = (
                        transaction.path
                        / PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
                    )
                try:
                    verify_exact_directory_inventory_at(
                        transaction.descriptor,
                        frozenset(
                            {
                                PLATFORM_RELEASE_DIRECTORY_NAME,
                                PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
                            }
                        ),
                        label="completed platform release candidate transaction",
                    )
                    verify_private_directory_handle_identity(
                        transaction,
                        label="completed platform release candidate transaction",
                    )
                except (PublicationReceiptIOError, PlatformDistributionError) as exc:
                    raise PublicationReceiptCommittedError(
                        "platform release candidate receipt committed but the "
                        "completed transaction could not be revalidated",
                        leaf=PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
                        digest=digest,
                        path=(
                            transaction.path
                            / PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
                        ),
                    ) from exc
                receipt_path = transaction.path / PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
                return receipt_path, digest, release.path, receipt
    except PublicationReceiptCommittedError:
        raise
    except PublicationReceiptIOError as exc:
        if committed_digest is not None:
            raise PublicationReceiptCommittedError(
                "platform release candidate receipt committed but transaction "
                "resource cleanup or revalidation failed",
                leaf=PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
                digest=committed_digest,
                path=committed_path,
            ) from exc
        raise PlatformDistributionError(str(exc)) from exc


def _private_candidate_receipt_metadata(metadata: os.stat_result) -> None:
    require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE
        and metadata.st_nlink == 1,
        "platform release candidate receipt metadata differs",
    )


def _load_release_candidate_bundle_from_handle(
    transaction: PrivateDirectoryHandle,
    *,
    candidate_path: pathlib.Path,
) -> ReleaseCandidateBundle:
    """Load one candidate through a caller-owned pinned transaction handle."""

    expected_inventory = frozenset(
        {
            PLATFORM_RELEASE_DIRECTORY_NAME,
            PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
        }
    )
    verify_exact_directory_inventory_at(
        transaction.descriptor,
        expected_inventory,
        label="platform release candidate transaction before load",
    )
    with open_private_directory_at(
        parent=transaction,
        direct_child_name=PLATFORM_RELEASE_DIRECTORY_NAME,
        label="platform release candidate directory",
        required_mode=0o755,
    ) as release:
        transaction_metadata = os.fstat(transaction.descriptor)
        release_metadata = os.fstat(release.descriptor)
        assets_before = _snapshot_release_assets(release, sync_files=False)
        files_before = _snapshot_release_asset_files(release)
        first = load_json_object_snapshot_at(
            transaction.descriptor,
            PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
            display_path=candidate_path,
            maximum=16 * 1024 * 1024,
            label="platform release candidate completion receipt",
            validate_metadata=_private_candidate_receipt_metadata,
        )
        require(
            first.file.data == canonical_json(first.value),
            "platform release candidate receipt is not canonical JSON",
        )
        receipt = validate_release_candidate_receipt(first.value)
        require(
            receipt["assets"] == assets_before,
            "platform release candidate receipt assets differ from release files",
        )
        assets_after = _snapshot_release_assets(release, sync_files=False)
        files_after = _snapshot_release_asset_files(release)
        second = load_json_object_snapshot_at(
            transaction.descriptor,
            PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
            display_path=candidate_path,
            maximum=16 * 1024 * 1024,
            label="platform release candidate completion receipt resample",
            validate_metadata=_private_candidate_receipt_metadata,
        )
        require(
            assets_after == assets_before
            and files_after == files_before
            and second.file.data == first.file.data
            and second.value == first.value,
            "platform release candidate transaction changed while loading",
        )
    verify_exact_directory_inventory_at(
        transaction.descriptor,
        expected_inventory,
        label="platform release candidate transaction after load",
    )
    verify_private_directory_handle_identity(
        transaction,
        label="platform release candidate transaction after load",
    )
    return ReleaseCandidateBundle(
        receipt=receipt,
        receipt_sha256=first.file.sha256,
        assets=files_before,
        transaction_device=transaction_metadata.st_dev,
        transaction_inode=transaction_metadata.st_ino,
        release_device=release_metadata.st_dev,
        release_inode=release_metadata.st_ino,
    )


def load_release_candidate_bundle(path: pathlib.Path) -> ReleaseCandidateBundle:
    """Resample one fixed receipt and all seven sibling release files twice."""

    candidate_path = pathlib.Path(path)
    try:
        root = normalize_safe_root(
            PLATFORM_RELEASE_CANDIDATE_ROOT,
            label="platform release candidate root",
        )
        require(candidate_path.is_absolute(), "platform release candidate receipt must be absolute")
        require(
            os.path.realpath(os.fspath(candidate_path))
            == os.path.abspath(os.fspath(candidate_path)),
            "platform release candidate receipt path must be canonical and symlink-free",
        )
        require(
            candidate_path.name == PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
            and candidate_path.parent.parent == root,
            "platform release candidate receipt is outside its fixed transaction root",
        )
        transaction_name = _release_transaction_name(candidate_path.parent.name)
        with open_private_direct_child_handle(
            safe_root=root,
            direct_child_name=transaction_name,
            label="platform release candidate transaction",
        ) as transaction:
            require(
                transaction.path == candidate_path.parent,
                "platform release candidate transaction path differs",
            )
            return _load_release_candidate_bundle_from_handle(
                transaction,
                candidate_path=candidate_path,
            )
    except PlatformDistributionError:
        raise
    except (
        EvidenceIOError,
        PublicationReceiptIOError,
        PlatformDistributionContractError,
        OSError,
    ) as exc:
        raise PlatformDistributionError(
            "cannot verify platform release candidate transaction"
        ) from exc


def load_release_candidate_receipt(path: pathlib.Path) -> dict[str, Any]:
    """Return the receipt projection from the descriptor-resampled bundle."""

    return load_release_candidate_bundle(path).receipt


@contextlib.contextmanager
def _open_candidate_transaction_from_root(
    root: pathlib.Path,
    root_descriptor: int,
    transaction_name: str,
) -> Iterator[PrivateDirectoryHandle]:
    descriptor = -1
    primary_error: BaseException | None = None
    try:
        root_opened = os.fstat(root_descriptor)
        root_named = root.lstat()
        require(
            stat.S_ISDIR(root_opened.st_mode)
            and root_opened.st_uid == os.geteuid()
            and stat.S_IMODE(root_opened.st_mode) == 0o700
            and root_opened.st_dev == root_named.st_dev
            and root_opened.st_ino == root_named.st_ino,
            "platform release candidate root identity differs",
        )
        descriptor = os.open(
            transaction_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_descriptor,
        )
        opened = os.fstat(descriptor)
        named = os.stat(
            transaction_name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        require(
            stat.S_ISDIR(opened.st_mode)
            and opened.st_uid == os.geteuid()
            and stat.S_IMODE(opened.st_mode) == 0o700
            and opened.st_dev == named.st_dev
            and opened.st_ino == named.st_ino,
            "platform release candidate transaction metadata differs",
        )
        handle = PrivateDirectoryHandle(
            path=root / transaction_name,
            descriptor=descriptor,
            parent_descriptor=root_descriptor,
            name=transaction_name,
            device=opened.st_dev,
            inode=opened.st_ino,
            mode=0o700,
        )
        yield handle
        verify_private_directory_handle_identity(
            handle,
            label="platform release candidate transaction",
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                if primary_error is not None:
                    primary_error.add_note(
                        "cannot close platform release candidate transaction"
                    )
                else:
                    raise PlatformDistributionError(
                        "cannot close platform release candidate transaction"
                    ) from exc


def _candidate_transaction_has_receipt(
    transaction: PrivateDirectoryHandle,
) -> bool:
    """Classify a bounded safe pre-receipt residue without deleting it."""

    entries = os.listdir(transaction.descriptor)
    require(
        len(entries) <= 2
        and set(entries)
        <= {
            PLATFORM_RELEASE_DIRECTORY_NAME,
            PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
        },
        "platform release candidate residue inventory is unsafe",
    )
    if PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME in entries:
        require(
            set(entries)
            == {
                PLATFORM_RELEASE_DIRECTORY_NAME,
                PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
            },
            "platform release candidate receipt transaction is incomplete",
        )
        return True
    if PLATFORM_RELEASE_DIRECTORY_NAME in entries:
        with open_private_directory_at(
            parent=transaction,
            direct_child_name=PLATFORM_RELEASE_DIRECTORY_NAME,
            label="failed platform release candidate residue",
            required_mode=0o755,
        ) as release:
            residue_entries = os.listdir(release.descriptor)
            require(
                len(residue_entries) <= len(PUBLIC_ASSET_NAMES)
                and all(
                    isinstance(name, str)
                    and name in PUBLIC_ASSET_NAMES
                    for name in residue_entries
                ),
                "failed platform release candidate residue files differ",
            )
            for name in residue_entries:
                metadata = os.stat(
                    name,
                    dir_fd=release.descriptor,
                    follow_symlinks=False,
                )
                _public_release_asset_metadata(metadata)
    verify_private_directory_handle_identity(
        transaction,
        label="failed platform release candidate residue transaction",
    )
    return False


def find_selected_release_candidate_bundle(
    expected_release_candidate: Mapping[str, object],
    expected_source: Mapping[str, object],
    *,
    staging_directory_fd: int | None = None,
    staging_leaves: Mapping[str, str] | None = None,
    expected_receipt_sha256: str | None = None,
    allow_existing_staging: bool = False,
) -> ReleaseCandidateBundle:
    """Find a deterministic fixed-root cache selected by pending results.

    The caller supplies only the two already-validated projections from P.  No
    caller-selected receipt or asset path participates in authority selection.
    Multiple byte-identical caches are harmless: P's exact seven-byte projection
    is the sole authority, and the lexical first matching transaction is pinned.
    """

    require(
        expected_receipt_sha256 is None
        or (
            isinstance(expected_receipt_sha256, str)
            and SHA256_RE.fullmatch(expected_receipt_sha256) is not None
        ),
        "selected platform candidate receipt digest is malformed",
    )

    try:
        root = normalize_safe_root(
            PLATFORM_RELEASE_CANDIDATE_ROOT,
            label="platform release candidate root",
        )
        root_descriptor = open_private_directory(
            root,
            label="platform release candidate root",
        )
    except PublicationReceiptIOError as exc:
        raise PlatformDistributionError(str(exc)) from exc
    primary_error: BaseException | None = None
    try:
        root_opened = os.fstat(root_descriptor)
        root_named = root.lstat()
        require(
            stat.S_ISDIR(root_opened.st_mode)
            and root_opened.st_uid == os.geteuid()
            and stat.S_IMODE(root_opened.st_mode) == 0o700
            and root_opened.st_dev == root_named.st_dev
            and root_opened.st_ino == root_named.st_ino,
            "platform release candidate root identity differs",
        )
        expected_candidate_source = {
            "canonical_source_tree_sha256": expected_source.get(
                "canonical_source_tree_sha256"
            ),
            "git_commit": expected_source.get("tag_commit"),
            "git_dirty": False,
            "git_tree": expected_source.get("tag_tree"),
            "source_date_epoch": expected_source.get("source_date_epoch"),
        }
        entries = os.listdir(root_descriptor)
        require(
            len(entries) <= 256,
            "platform release candidate root exceeds the bounded inventory",
        )
        names = sorted(entries)
        require(
            all(PLATFORM_RELEASE_TRANSACTION_NAME.fullmatch(name) for name in names),
            "platform release candidate root contains an unexpected entry",
        )
        matches: list[tuple[str, ReleaseCandidateBundle]] = []
        for name in names:
            receipt_path = root / name / PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
            with _open_candidate_transaction_from_root(
                root,
                root_descriptor,
                name,
            ) as transaction:
                if not _candidate_transaction_has_receipt(transaction):
                    continue
                bundle = _load_release_candidate_bundle_from_handle(
                    transaction,
                    candidate_path=receipt_path,
                )
            receipt = bundle.receipt
            projection = {
                "android_runtime_evidence": receipt["android_runtime_evidence"],
                "assets": receipt["assets"],
                "checksums_sha256": receipt["checksums_sha256"],
                "platform_distribution_sha256": receipt[
                    "platform_distribution_sha256"
                ],
            }
            if projection != dict(expected_release_candidate):
                continue
            if receipt["source"] != expected_candidate_source:
                continue
            if (
                expected_receipt_sha256 is not None
                and bundle.receipt_sha256 != expected_receipt_sha256
            ):
                continue
            matches.append((name, bundle))
        entries_after = os.listdir(root_descriptor)
        root_after_opened = os.fstat(root_descriptor)
        root_after_named = root.lstat()
        require(
            sorted(entries_after) == names
            and root_after_opened.st_dev == root_opened.st_dev
            and root_after_opened.st_ino == root_opened.st_ino
            and root_after_named.st_dev == root_opened.st_dev
            and root_after_named.st_ino == root_opened.st_ino
            and stat.S_IMODE(root_after_opened.st_mode) == 0o700
            and root_after_opened.st_uid == os.geteuid(),
            "platform release candidate root changed during selection",
        )
        require(
            bool(matches),
            "pending results do not select a completed platform candidate cache",
        )
        selected_name, selected_bundle = matches[0]
        require(
            (staging_directory_fd is None and staging_leaves is None)
            or (
                type(staging_directory_fd) is int
                and staging_directory_fd >= 0
                and isinstance(staging_leaves, Mapping)
                and frozenset(staging_leaves) == frozenset(PUBLIC_ASSET_NAMES)
            ),
            "platform candidate staging policy is incomplete",
        )
        if staging_directory_fd is not None:
            _require_staging_leaves = staging_leaves
            require(
                isinstance(_require_staging_leaves, Mapping),
                "platform candidate staging leaves are missing",
            )
            selected_assets = selected_bundle.asset_by_name()
            with _open_candidate_transaction_from_root(
                root,
                root_descriptor,
                selected_name,
            ) as transaction:
                with open_private_directory_at(
                    parent=transaction,
                    direct_child_name=PLATFORM_RELEASE_DIRECTORY_NAME,
                    label="selected platform release candidate directory",
                    required_mode=0o755,
                ) as release:
                    for asset_name in PUBLIC_ASSET_NAMES:
                        source_fd = -1
                        source_error: BaseException | None = None
                        try:
                            source_fd = os.open(
                                asset_name,
                                os.O_RDONLY
                                | getattr(os, "O_NONBLOCK", 0)
                                | getattr(os, "O_NOFOLLOW", 0)
                                | getattr(os, "O_CLOEXEC", 0),
                                dir_fd=release.descriptor,
                            )
                            source_metadata = os.fstat(source_fd)
                            _public_release_asset_metadata(source_metadata)
                            expected = selected_assets[asset_name]
                            stage_private_file_from_fd_noreplace_at(
                                source_fd,
                                staging_directory_fd,
                                _require_staging_leaves[asset_name],
                                expected_size=expected.size,
                                expected_sha256=expected.sha256,
                                maximum=MAX_PLATFORM_ASSET_BYTES,
                                label=f"platform publication staging {asset_name}",
                                allow_existing_exact=allow_existing_staging,
                            )
                        except BaseException as exc:
                            source_error = exc
                            raise
                        finally:
                            if source_fd >= 0:
                                try:
                                    os.close(source_fd)
                                except OSError as exc:
                                    if source_error is not None:
                                        source_error.add_note(
                                            "cannot close selected platform asset"
                                        )
                                    else:
                                        raise PlatformDistributionError(
                                            "cannot close selected platform asset"
                                        ) from exc
                staged_bundle = _load_release_candidate_bundle_from_handle(
                    transaction,
                    candidate_path=(
                        root
                        / selected_name
                        / PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
                    ),
                )
            require(
                staged_bundle == selected_bundle,
                "selected platform candidate changed during staging",
            )
        final_entries = sorted(os.listdir(root_descriptor))
        final_opened = os.fstat(root_descriptor)
        final_named = root.lstat()
        require(
            final_entries == names
            and final_opened.st_dev == root_opened.st_dev
            and final_opened.st_ino == root_opened.st_ino
            and final_named.st_dev == root_opened.st_dev
            and final_named.st_ino == root_opened.st_ino,
            "platform release candidate root changed during staging",
        )
        return selected_bundle
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(root_descriptor)
        except OSError as exc:
            if primary_error is not None:
                primary_error.add_note(
                    "cannot close platform release candidate root"
                )
            else:
                raise PlatformDistributionError(
                    "cannot close platform release candidate root"
                ) from exc


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
    assemble_parser.add_argument("--candidate-dir", required=True, type=pathlib.Path)
    assemble_parser.add_argument("--runtime-bundle", required=True, type=pathlib.Path)
    assemble_parser.add_argument("--transaction-name", required=True)
    add_android_tools(assemble_parser)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", required=True, type=pathlib.Path)
    verify_parser.add_argument("--release-dir", required=True, type=pathlib.Path)
    add_android_tools(verify_parser)
    return parser


def _relative_release_output(path: pathlib.Path) -> str:
    try:
        return path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError as exc:
        raise PlatformDistributionError(
            "platform release candidate output escaped the repository"
        ) from exc


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
            receipt_path, digest, release_path, receipt = assemble_candidate_transaction(
                args.root,
                args.candidate_dir,
                args.runtime_bundle,
                args.transaction_name,
                android_tools=android_tools,
            )
            print(
                "ABI2_PLATFORM_DISTRIBUTION_ASSEMBLE_PASS "
                f"commit={receipt['source']['git_commit']} "
                f"assets={len(receipt['assets'])} receipt_sha256={digest} "
                f"receipt={_relative_release_output(receipt_path)} "
                f"release_dir={_relative_release_output(release_path)}"
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
    except PublicationReceiptCommittedError as exc:
        if exc.leaf is not None and exc.digest is not None:
            print(
                "PLATFORM_RELEASE_CANDIDATE_COMMITTED_ERROR "
                f"visibility={exc.visibility} leaf={exc.leaf} "
                f"sha256={exc.digest}",
                file=sys.stderr,
            )
        else:
            print(
                "error: platform release candidate receipt committed with "
                "incomplete durability",
                file=sys.stderr,
            )
        return 125
    except (OSError, PlatformDistributionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
