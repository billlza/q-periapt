#!/usr/bin/env python3
"""The r2 public evidence envelope around canonical runtime and AGP consumers.

The unchanged v2 bundle remains a complete nested artifact. Version 3 adds the
two closed AGP evidence directories; their owning verifier interprets every
consumer file. This module only binds the archive inventory and crosslinks.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import tempfile
from dataclasses import dataclass
from typing import Never

import android_device_proof as runtime
import android_agp_consumer as agp
import android_elf
import android_runtime_state as runtime_state
from deterministic_archive import (
    ArchiveLimits,
    DeterministicArchiveError,
    create_zip,
    extract_zip,
)
from evidence_io import EvidenceIOError, read_regular_snapshot, parse_strict_json_bytes
from platform_distribution_contract import (
    PlatformDistributionContractError,
    validate_agp_consumers,
)


SCHEMA_VERSION = 3
ROOT_NAME = "qperiapt-android-runtime-evidence-v3"
RUNTIME_PATH = "canonical/runtime-evidence-v2.zip"
PROFILES = ("agp_full_release", "agp_minimal_release")
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_FILES = 256
BUNDLE_LIMITS = ArchiveLimits(
    maximum_archive_bytes=MAX_FILE_BYTES,
    maximum_member_count=MAX_FILES * 5 + 2,
    maximum_member_bytes=MAX_FILE_BYTES,
    maximum_total_bytes=MAX_FILE_BYTES + MAX_MANIFEST_BYTES,
)


class AndroidMaintenanceBundleError(ValueError):
    """A maintenance evidence archive is incomplete, inconsistent or unsafe."""


def _fail(message: str) -> Never:
    raise AndroidMaintenanceBundleError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be a JSON object")
    return value


def _relative(value: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    _require(
        bool(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and path.as_posix() == value
        and "\\" not in value,
        "maintenance bundle file path is not canonical",
    )
    _require(
        value == RUNTIME_PATH
        or any(value.startswith(f"consumers/{profile}/") for profile in PROFILES),
        "maintenance bundle file is outside its declared evidence directories",
    )
    return path


@dataclass(frozen=True, slots=True)
class VerifiedMaintenanceBundle:
    archive_sha256: str
    manifest_sha256: str
    runtime_bundle: pathlib.Path
    runtime_bundle_sha256: str
    consumers: dict[str, object]


def android_sdk_for_tools(
    apksigner: pathlib.Path, zipalign: pathlib.Path
) -> pathlib.Path:
    """Derive one explicit SDK from the existing canonical verification tools."""

    try:
        signer = apksigner.resolve(strict=True)
        alignment = zipalign.resolve(strict=True)
    except OSError as exc:
        raise AndroidMaintenanceBundleError(
            "cannot resolve Android verification tools"
        ) from exc
    directory = signer.parent
    _require(
        signer.name == "apksigner"
        and alignment.name == "zipalign"
        and alignment.parent == directory
        and directory.name == "36.0.0"
        and directory.parent.name == "build-tools",
        "maintenance verification requires one explicit Build Tools 36.0.0 directory",
    )
    return directory.parent.parent


def registered_bundle_tools(
    llvm_nm: pathlib.Path,
    llvm_readelf: pathlib.Path,
    apksigner: pathlib.Path,
    zipalign: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    """Admit CLI assertions against one registered SDK and its installed NDK r29."""

    sdk = runtime_state.registered_sdk_root(apksigner.parent.parent.parent)
    build_tools = sdk / "build-tools" / "36.0.0"
    signer = build_tools / "apksigner"
    alignment = build_tools / "zipalign"
    _require(
        apksigner == signer and zipalign == alignment,
        "maintenance CLI tools must use one registered Build Tools 36.0.0 directory",
    )
    selected: list[tuple[pathlib.Path, pathlib.Path]] = []
    for ndk in (sdk / "ndk").iterdir():
        if re.fullmatch(r"29\.[0-9]+\.[0-9]+", ndk.name) is None:
            continue
        if not llvm_nm.is_relative_to(ndk) or not llvm_readelf.is_relative_to(ndk):
            continue
        _require(
            ndk.is_dir() and not ndk.is_symlink(),
            "registered NDK r29 directory is unsafe",
        )
        toolchain = android_elf.find_ndk_toolchain(ndk)
        nm = toolchain / "bin" / "llvm-nm"
        readelf = toolchain / "bin" / "llvm-readelf"
        if llvm_nm == nm and llvm_readelf == readelf:
            selected.append((nm, readelf))
    _require(
        len(selected) == 1,
        "maintenance CLI LLVM tools must select one installed registered NDK r29",
    )
    nm, readelf, _revision = runtime.verified_ndk_tools(*selected[0])
    return nm, readelf, signer, alignment


def verify_and_extract(
    *,
    root: pathlib.Path,
    bundle: pathlib.Path,
    destination: pathlib.Path,
    expected_bundle_sha256: str,
    expected_aar_sha256: str,
    expected_aar_manifest_sha256: str,
    expected_source_commit: str,
    expected_source_tree_sha256: str,
    expected_source_epoch: int,
    sdk: pathlib.Path | None = None,
) -> VerifiedMaintenanceBundle:
    """Verify the envelope and consumers, returning v2 for its separate verifier.

    The distribution caller must run the existing canonical runtime verifier on
    the returned ZIP; a valid v3 envelope cannot replace that gate.
    """

    try:
        audit = extract_zip(
            bundle,
            destination,
            root_name=ROOT_NAME,
            expected_sha256=expected_bundle_sha256,
            limits=BUNDLE_LIMITS,
        )
        extracted = destination / ROOT_NAME
        snapshot = read_regular_snapshot(
            extracted / "MANIFEST.json",
            maximum=MAX_MANIFEST_BYTES,
            label="maintenance bundle manifest",
        )
        manifest = _object(
            parse_strict_json_bytes(snapshot.data, label="maintenance bundle manifest"),
            "manifest",
        )
        _require(
            set(manifest)
            == {
                "schema_version",
                "kind",
                "profile",
                "git_commit",
                "source_date_epoch",
                "source_tree_sha256",
                "aar_sha256",
                "aar_manifest_sha256",
                "files",
                "agp_consumers",
            }
            and type(manifest["schema_version"]) is int
            and manifest["schema_version"] == SCHEMA_VERSION
            and manifest["kind"] == runtime.BUNDLE_KIND
            and manifest["profile"] == "maintenance-r2",
            "maintenance bundle discriminant or fields differ",
        )
        _require(
            manifest["git_commit"] == expected_source_commit
            and manifest["source_tree_sha256"] == expected_source_tree_sha256
            and type(manifest["source_date_epoch"]) is int
            and manifest["source_date_epoch"] == expected_source_epoch
            and audit.mtime == expected_source_epoch - expected_source_epoch % 2
            and manifest["aar_sha256"] == expected_aar_sha256
            and manifest["aar_manifest_sha256"] == expected_aar_manifest_sha256,
            "maintenance bundle source or exact AAR identity differs",
        )
        files = _object(manifest["files"], "maintenance bundle files")
        _require(
            RUNTIME_PATH in files and 1 < len(files) <= MAX_FILES,
            "maintenance bundle file inventory is incomplete or unbounded",
        )
        entries = {ROOT_NAME: "directory", f"{ROOT_NAME}/MANIFEST.json": "file"}
        total_bytes = 0
        for relative, value in files.items():
            path = _relative(relative)
            record = _object(value, "maintenance file record")
            _require(
                set(record) == {"bytes", "sha256"},
                "maintenance file record fields differ",
            )
            file = read_regular_snapshot(
                extracted.joinpath(*path.parts),
                maximum=MAX_FILE_BYTES,
                label=f"maintenance evidence {relative}",
            )
            _require(
                type(record["bytes"]) is int
                and record["bytes"] == file.size
                and record["sha256"] == file.sha256,
                f"maintenance evidence bytes differ: {relative}",
            )
            total_bytes += file.size
            _require(
                total_bytes <= MAX_FILE_BYTES,
                "maintenance evidence exceeds its aggregate size bound",
            )
            entries[f"{ROOT_NAME}/{relative}"] = "file"
            for parent in path.parents:
                if parent.as_posix() != ".":
                    entries[f"{ROOT_NAME}/{parent.as_posix()}"] = "directory"
        _require(
            {entry.path: entry.kind for entry in audit.entries} == entries,
            "maintenance ZIP file inventory differs from its manifest",
        )
        consumers = _object(manifest["agp_consumers"], "maintenance AGP consumers")
        validate_agp_consumers(
            consumers,
            expected_aar_sha256=expected_aar_sha256,
            expected_aar_manifest_sha256=expected_aar_manifest_sha256,
            expected_source_commit=expected_source_commit,
            expected_source_tree_sha256=expected_source_tree_sha256,
        )
        projections = {}
        for profile in PROFILES:
            projection = agp.verify_exported_profile(
                root,
                extracted / "consumers" / profile,
                expected_profile=profile,
                expected_aar_sha256=expected_aar_sha256,
                expected_aar_manifest_sha256=expected_aar_manifest_sha256,
                expected_source_commit=expected_source_commit,
                sdk=sdk,
            )
            _require(
                consumers[profile]["projection"] == projection,
                "bundled AGP consumer projection differs",
            )
            projections[profile] = projection
        _require(
            projections[PROFILES[0]]["run_id"] != projections[PROFILES[1]]["run_id"],
            "AGP consumers reused one runtime run",
        )
        _require(
            projections[PROFILES[0]]["source_tree_sha256"]
            == projections[PROFILES[1]]["source_tree_sha256"],
            "AGP consumers used different source trees",
        )
        nested = _object(files[RUNTIME_PATH], "canonical runtime file")
        return VerifiedMaintenanceBundle(
            audit.archive_sha256,
            snapshot.sha256,
            extracted / RUNTIME_PATH,
            nested["sha256"],
            consumers,
        )
    except (
        DeterministicArchiveError,
        EvidenceIOError,
        agp.AndroidAgpConsumerError,
        PlatformDistributionContractError,
    ) as exc:
        raise AndroidMaintenanceBundleError(str(exc)) from exc


def create_bundle(args: argparse.Namespace) -> str:
    """Package already completed runtime proofs, then independently verify the ZIP."""

    root = runtime_state.collector_repository_root(args.root)
    full_proof = agp.collector_proof_path(args.full_proof)
    minimal_proof = agp.collector_proof_path(args.minimal_proof)
    llvm_nm, llvm_readelf, apksigner, zipalign = registered_bundle_tools(
        args.llvm_nm, args.llvm_readelf, args.apksigner, args.zipalign
    )
    output = args.output.absolute()
    runtime.require_under(output, root / "target", "maintenance bundle output")
    _require(
        not output.exists() and not output.is_symlink(),
        "maintenance bundle output already exists",
    )
    _require(
        output.parent.is_dir() and not output.parent.is_symlink(),
        "maintenance output parent is unsafe",
    )
    canonical = read_regular_snapshot(
        args.runtime_bundle, maximum=MAX_FILE_BYTES, label="canonical runtime bundle"
    )
    sdk = android_sdk_for_tools(apksigner, zipalign)
    try:
        with tempfile.TemporaryDirectory(
            prefix="android-maintenance-bundle-", dir=output.parent
        ) as temporary:
            work = pathlib.Path(temporary)
            runtime.verify_runtime_bundle(
                root=root,
                bundle=args.runtime_bundle,
                expected_bundle_sha256=canonical.sha256,
                llvm_nm=llvm_nm,
                llvm_readelf=llvm_readelf,
                apksigner=apksigner,
                zipalign=zipalign,
                expected_device_kind="emulator",
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
                allow_dirty_proof=False,
                forbidden_text=[str(root)],
            )
            audit = extract_zip(
                args.runtime_bundle,
                work / "canonical",
                root_name=runtime.BUNDLE_ROOT_NAME,
                expected_sha256=canonical.sha256,
            )
            canonical_root = work / "canonical" / runtime.BUNDLE_ROOT_NAME
            original = runtime.load_json(canonical_root / runtime.BUNDLE_MANIFEST_PATH)
            _selected, proof = runtime.verify_bundle_manifest(
                canonical_root, original, archive_mtime=audit.mtime
            )
            artifact = _object(proof["artifacts"], "canonical runtime artifacts")
            source_commit = proof["git_commit"]
            stage = work / "stage"
            stage.mkdir(mode=0o700)
            runtime.write_private_bundle_stage_file(
                stage / RUNTIME_PATH, canonical.data
            )
            files = {
                RUNTIME_PATH: {"bytes": canonical.size, "sha256": canonical.sha256}
            }
            consumers = {}
            for profile, proof_path in zip(
                PROFILES, (full_proof, minimal_proof), strict=True
            ):
                projection = agp.validate_completed_profile(
                    root,
                    proof_path,
                    expected_profile=profile,
                    expected_aar_sha256=artifact["aar_sha256"],
                    expected_aar_manifest_sha256=artifact["aar_manifest_sha256"],
                    expected_source_commit=source_commit,
                    sdk=sdk,
                )
                consumers[profile] = {
                    "proof_path": f"consumers/{profile}/proof.json",
                    "projection": projection,
                }
                evidence_files = agp.profile_evidence_files(root, proof_path, sdk=sdk)
                _require(
                    len(files) + len(evidence_files) <= MAX_FILES,
                    "maintenance evidence file count exceeds its bound",
                )
                for relative, source in evidence_files.items():
                    target = f"consumers/{profile}/{relative}"
                    _relative(target)
                    _require(target not in files, "duplicate maintenance evidence path")
                    snapshot = read_regular_snapshot(
                        source, maximum=MAX_FILE_BYTES, label=f"AGP {profile} evidence"
                    )
                    _require(
                        sum(record["bytes"] for record in files.values())
                        + snapshot.size
                        <= MAX_FILE_BYTES,
                        "maintenance evidence exceeds its aggregate size bound",
                    )
                    runtime.write_private_bundle_stage_file(
                        stage / target, snapshot.data
                    )
                    files[target] = {"bytes": snapshot.size, "sha256": snapshot.sha256}
            manifest = {
                "schema_version": SCHEMA_VERSION,
                "kind": runtime.BUNDLE_KIND,
                "profile": "maintenance-r2",
                "git_commit": source_commit,
                "source_date_epoch": original["source_date_epoch"],
                "source_tree_sha256": proof["proof_source_tree_sha256"],
                "aar_sha256": artifact["aar_sha256"],
                "aar_manifest_sha256": artifact["aar_manifest_sha256"],
                "files": files,
                "agp_consumers": consumers,
            }
            runtime.write_private_bundle_stage_file(
                stage / "MANIFEST.json", runtime.canonical_json(manifest)
            )
            runtime.scan_release_paths(
                [stage / "MANIFEST.json", *(stage / path for path in files)],
                forbidden_text=[str(root)],
            )
            result = create_zip(
                stage,
                output,
                root_name=ROOT_NAME,
                mtime=original["source_date_epoch"],
                limits=BUNDLE_LIMITS,
            )
            verified = verify_and_extract(
                root=root,
                bundle=output,
                destination=work / "verified",
                expected_bundle_sha256=result.archive_sha256,
                expected_aar_sha256=artifact["aar_sha256"],
                expected_aar_manifest_sha256=artifact["aar_manifest_sha256"],
                expected_source_commit=source_commit,
                expected_source_epoch=original["source_date_epoch"],
                expected_source_tree_sha256=proof["proof_source_tree_sha256"],
                sdk=sdk,
            )
            return verified.archive_sha256
    except (
        DeterministicArchiveError,
        EvidenceIOError,
        agp.AndroidAgpConsumerError,
    ) as exc:
        raise AndroidMaintenanceBundleError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in (
        "root",
        "runtime-bundle",
        "full-proof",
        "minimal-proof",
        "output",
        "llvm-nm",
        "llvm-readelf",
        "apksigner",
        "zipalign",
    ):
        parser.add_argument(f"--{name}", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        digest = create_bundle(args)
    except (
        OSError,
        AndroidMaintenanceBundleError,
        runtime_state.AndroidRuntimeStateError,
        android_elf.AndroidVerificationError,
        agp.AndroidAgpConsumerError,
    ) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(f"ANDROID_MAINTENANCE_BUNDLE_CREATE_PASS sha256={digest} path={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
