#!/usr/bin/env python3
"""Verify Q-Periapt Android runtime proof metadata."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from typing import Any

from android_elf import (
    AndroidVerificationError,
    audit_aar,
    verify_aar,
    verify_ndk_r29,
)
from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from deterministic_archive import (
    DeterministicArchiveError,
    create_zip,
    extract_zip,
)
from evidence_io import (
    EvidenceIOError,
    load_json_object_snapshot,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    git_commit as provenance_git_commit,
    require_commit_or_evidence_successor,
    run_git_text,
    source_tree_dirty as provenance_source_tree_dirty,
)
from proof_manifest import (
    ProofManifestError,
    load_results_manifest_snapshot,
    select_bound_json_snapshot,
)
from platform_release_contract import ANDROID_DEVICE_PROOF_SCHEMA_VERSION
from release_binary_scan import ReleaseBinaryScanError, scan_release_file


PROOF_SCHEMA_VERSION = ANDROID_DEVICE_PROOF_SCHEMA_VERSION
RESULT_SCHEMA_VERSION = 1
PASS_MARKER = "QPERIAPT_ANDROID_DEVICE_PASS"
FAIL_MARKER = "QPERIAPT_ANDROID_DEVICE_FAIL"
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ANDROID_PROOF_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_EVIDENCE_FILE_BYTES = 512 * 1024 * 1024
MAX_ANDROID_SDK = 999
ANDROID_RELEASE_SDK = 35
BUNDLE_SCHEMA_VERSION = 1
BUNDLE_KIND = "qperiapt.android_runtime_evidence_bundle"
BUNDLE_ROOT_NAME = "qperiapt-android-runtime-evidence-v1"

PROOF_PATH_KEYS = (
    "aar",
    "aar_manifest",
    "smoke_apk",
    "apksigner_verify",
    "zipalign_verify",
    "result_txt",
    "result_json",
    "logcat",
)
BUNDLE_FILE_PATHS = {
    "proof": "qperiapt-android-device-proof.json",
    "aar": "artifacts/q-periapt-android-0.1.0-alpha.2.aar",
    "aar_manifest": "artifacts/q-periapt-android-0.1.0-alpha.2.MANIFEST.json",
    "smoke_apk": "artifacts/qperiapt-android-smoke.apk",
    "apksigner_verify": "evidence/apksigner-verify.txt",
    "zipalign_verify": "evidence/zipalign-verify.txt",
    "result_txt": "evidence/qperiapt-android-device-result.txt",
    "result_json": "evidence/qperiapt-android-device-result.json",
    "logcat": "evidence/logcat.txt",
}
BUNDLE_MANIFEST_PATH = "MANIFEST.json"

EXPECTED_TESTS = [
    "runtimeMetadataMatches",
    "signedPolicyDecisionIsExactAndFailClosed",
    "osRandomPolicyRoundtripAndWipes",
]

SOURCE_INPUTS = {
    "android_device_smoke_script": "artifact/android-device-smoke.sh",
    "android_device_proof": "artifact/android_device_proof.py",
    "proof_to_byte": "artifact/proof-to-byte.sh",
    "android_aar_script": "artifact/android-aar.sh",
    "android_elf_verifier": "artifact/android_elf.py",
    "release_binary_scan": "artifact/release_binary_scan.py",
    "third_party_license_collector": "artifact/third_party_licenses.py",
    "deterministic_archive": "artifact/deterministic_archive.py",
    "android_facade": "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
    "android_jni_adapter": "bindings/android/jni/qperiapt_jni.c",
    "c_abi_contract": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    "signed_policy_vectors": "bindings/signed-policy-vectors.json",
}

REQUIRED_NATIVE_ABIS = ("arm64-v8a", "x86_64", "armeabi-v7a", "x86")

PROOF_FIELDS = frozenset(
    {
        "schema",
        "generated_at",
        "git_commit",
        "source_tree_dirty",
        "proof_source_tree_sha256",
        "device_runtime_proof",
        "package_only",
        "release_candidate_mode",
        "run_id",
        "package",
        "paths",
        "device",
        "android",
        "abi",
        "result",
        "artifacts",
        "source_hashes",
    }
)
PROOF_DEVICE_FIELDS = frozenset(
    {
        "kind",
        "serial_sha256_prefix",
        "raw_serial_recorded",
        "manufacturer",
        "model",
        "abi",
        "page_size",
        "sdk",
        "release",
        "fingerprint_sha256_prefix",
    }
)
PROOF_ANDROID_FIELDS = frozenset(
    {
        "platform",
        "build_tools",
        "ndk",
        "native_page_alignment",
        "min_sdk",
        "target_sdk",
        "adb_version",
        "apksigner_sha256",
        "zipalign_sha256",
    }
)
PROOF_ABI_FIELDS = frozenset(
    {
        "major",
        "contract_path",
        "contract_sha256",
        "runtime_library",
        "jni_library",
        "legacy_library_names_present",
    }
)
PROOF_RESULT_FIELDS = frozenset(
    {"marker_sha256", "json_sha256", "status", "test_count", "passed_tests"}
)
PROOF_ARTIFACT_FIELDS = frozenset(
    {
        "aar_sha256",
        "aar_manifest_sha256",
        "smoke_apk_sha256",
        "apksigner_verify_sha256",
        "zipalign_verify_sha256",
        "logcat_sha256",
        "native",
    }
)
PROOF_NATIVE_HASH_FIELDS = frozenset({"ffi_so_sha256", "jni_so_sha256"})
RESULT_FIELDS = frozenset({"schema", "status", "run_id", "test_count", "passed_tests"})

LOG_FATAL_PATTERNS = (
    "QPERIAPT_ANDROID_DEVICE_FAIL",
    "FATAL EXCEPTION",
    "JNI DETECTED ERROR",
    "UnsatisfiedLinkError",
    "NoSuchMethodError",
    "NoClassDefFoundError",
    "SIGSEGV",
    "signal 11",
)
LOGCAT_APP_LINE = re.compile(r"^[VDIWEF]/QPeriaptSmoke(?:\(\s*[0-9]+\))?:")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")


def exact_object(
    value: Any,
    expected_fields: frozenset[str] | set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(expected_fields):
        raise SystemExit(f"error: {label} fields differ")
    return value


def canonical_private_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    """Bind a caller-owned private directory to its canonical physical path."""

    raw = pathlib.Path(path)
    require(raw.is_absolute(), f"{label} must be an absolute path")
    try:
        before = raw.lstat()
        resolved = raw.resolve(strict=True)
        after = resolved.lstat()
    except OSError as exc:
        raise SystemExit(f"error: cannot inspect {label} {raw}: {exc}") from exc
    require(
        not stat.S_ISLNK(before.st_mode) and stat.S_ISDIR(before.st_mode),
        f"{label} must be a non-symlink directory: {raw}",
    )
    require(
        not stat.S_ISLNK(after.st_mode) and stat.S_ISDIR(after.st_mode),
        f"resolved {label} must be a non-symlink directory: {resolved}",
    )
    require(
        (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
        f"{label} changed while its canonical path was resolved",
    )
    if os.name == "posix":
        require(
            before.st_uid == os.geteuid(),
            f"{label} must be owned by the current user",
        )
        require(
            stat.S_IMODE(before.st_mode) & 0o077 == 0,
            f"{label} must not be accessible by group or other users",
        )
    return resolved


def read_text(path: pathlib.Path) -> str:
    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="Android text evidence",
        )
        return snapshot.data.decode("utf-8")
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def read_bytes(path: pathlib.Path) -> bytes:
    try:
        return read_regular_snapshot(
            path,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="Android binary evidence",
        ).data
    except EvidenceIOError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(read_bytes(path))


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return load_json_object_snapshot(path, label=f"Android JSON {path}").value
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        raise SystemExit(f"error: {label} must be under {base}: {path}") from None


def git_commit(root: pathlib.Path) -> str:
    try:
        return provenance_git_commit(root)
    except GitProvenanceError as exc:
        raise SystemExit(f"error: cannot inspect git commit: {exc}") from exc


def source_tree_dirty(root: pathlib.Path) -> bool:
    try:
        return provenance_source_tree_dirty(root)
    except GitProvenanceError as exc:
        raise SystemExit(f"error: cannot inspect git worktree: {exc}") from exc


def verify_proof_schema(proof: dict[str, Any]) -> None:
    require(
        proof.get("schema") == PROOF_SCHEMA_VERSION,
        f"Android proof schema must be {PROOF_SCHEMA_VERSION}",
    )
    exact_object(proof, PROOF_FIELDS, "Android proof")
    exact_object(proof.get("paths"), set(PROOF_PATH_KEYS), "Android proof path")
    exact_object(proof.get("device"), PROOF_DEVICE_FIELDS, "Android proof device")
    exact_object(proof.get("android"), PROOF_ANDROID_FIELDS, "Android proof toolchain")
    exact_object(proof.get("abi"), PROOF_ABI_FIELDS, "Android proof ABI")
    exact_object(proof.get("result"), PROOF_RESULT_FIELDS, "Android proof result")
    artifacts = exact_object(
        proof.get("artifacts"), PROOF_ARTIFACT_FIELDS, "Android proof artifact"
    )
    native = exact_object(
        artifacts.get("native"), set(REQUIRED_NATIVE_ABIS), "Android proof native ABI"
    )
    for abi in REQUIRED_NATIVE_ABIS:
        exact_object(
            native.get(abi),
            PROOF_NATIVE_HASH_FIELDS,
            f"Android proof native hash {abi}",
        )
    exact_object(
        proof.get("source_hashes"),
        {name + "_sha256" for name in SOURCE_INPUTS},
        "Android proof source hash",
    )


def current_source_tree_digest(root: pathlib.Path) -> str:
    """Return the exact canonical digest used by the claim-ledger gate."""

    try:
        return canonical_tree_digest(root, repository_paths(root))
    except (LedgerError, OSError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot compute canonical source-input digest: {exc}") from exc


def verify_source_tree_digest(root: pathlib.Path, proof: dict[str, Any]) -> None:
    expected = proof.get("proof_source_tree_sha256")
    require(
        isinstance(expected, str) and SHA256_RE.fullmatch(expected) is not None,
        "Android proof lacks a valid proof_source_tree_sha256",
    )
    actual = current_source_tree_digest(root)
    require(
        expected == actual,
        f"canonical source-input tree changed since Android proof: got {actual}, expected {expected}",
    )


def verify_git_provenance(root: pathlib.Path, proof: dict[str, Any], allow_dirty_proof: bool) -> None:
    proof_commit = proof.get("git_commit")
    require(
        isinstance(proof_commit, str) and re.fullmatch(r"[0-9a-f]{40,64}", proof_commit) is not None,
        "Android proof lacks a valid git_commit",
    )
    try:
        require_commit_or_evidence_successor(root, proof_commit)
    except GitProvenanceError as exc:
        require(False, f"Android proof commit provenance failed: {exc}")
    proof_dirty = proof.get("source_tree_dirty")
    require(isinstance(proof_dirty, bool), "Android proof lacks source_tree_dirty")
    if not allow_dirty_proof:
        require(proof_dirty is False, "Android proof was generated from a dirty source tree")
        require(not source_tree_dirty(root), "Android proof cannot be release-verified while the current source tree is dirty")


def target_path(root: pathlib.Path, rel: str, label: str) -> pathlib.Path:
    require(isinstance(rel, str) and rel, f"{label} path is missing")
    path = (root / rel).resolve()
    require_under(path, root / "target", label)
    return path


def proof_path_fields(proof: dict[str, Any]) -> dict[str, str]:
    rel_paths = proof.get("paths")
    require(isinstance(rel_paths, dict), "proof lacks artifact paths")
    require(set(rel_paths) == set(PROOF_PATH_KEYS), "proof artifact path fields differ")
    validated: dict[str, str] = {}
    for name in PROOF_PATH_KEYS:
        relative = rel_paths.get(name)
        require(isinstance(relative, str) and relative, f"{name} path is missing")
        pure = pathlib.PurePosixPath(relative)
        require(
            not pure.is_absolute()
            and ".." not in pure.parts
            and pure.as_posix() == relative,
            f"{name} path is not a canonical repository-relative path",
        )
        validated[name] = relative
    return validated


def proof_paths(root: pathlib.Path, proof: dict[str, Any]) -> dict[str, pathlib.Path]:
    return {
        name: target_path(root, relative, name)
        for name, relative in proof_path_fields(proof).items()
    }


def expected_marker(run_id: str) -> str:
    require(bool(RUN_ID_RE.fullmatch(run_id)), f"invalid run id: {run_id}")
    return f"{PASS_MARKER} run-id={run_id} tests={len(EXPECTED_TESTS)}"


def parse_generated_at(value: Any) -> dt.datetime:
    require(isinstance(value, str) and value, "proof generated_at is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"error: invalid proof generated_at: {value}") from exc
    require(parsed.tzinfo is not None, "proof generated_at must be timezone-aware")
    canonical = parsed.astimezone(dt.timezone.utc)
    require(
        value == canonical.isoformat().replace("+00:00", "Z"),
        "proof generated_at must be canonical UTC with a Z suffix",
    )
    return canonical


def verify_proof_freshness(
    proof: dict[str, Any],
    max_age_seconds: int,
    *,
    reference_time: dt.datetime | None = None,
) -> None:
    require(
        type(max_age_seconds) is int
        and 0 < max_age_seconds <= MAX_ANDROID_PROOF_AGE_SECONDS,
        "Android proof freshness limit is invalid",
    )
    generated_at = parse_generated_at(proof.get("generated_at"))
    now = reference_time or dt.datetime.now(dt.timezone.utc)
    require(
        isinstance(now, dt.datetime) and now.tzinfo is not None,
        "Android proof freshness reference must be timezone-aware",
    )
    age_seconds = (now.astimezone(dt.timezone.utc) - generated_at).total_seconds()
    require(age_seconds >= 0, "Android proof generated_at is in the future")
    require(age_seconds <= max_age_seconds, f"Android proof is stale: {int(age_seconds)}s old")


def validate_max_age_seconds(raw_value: str) -> int:
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"must be an integer: {raw_value}") from exc
    if not 0 < value <= MAX_ANDROID_PROOF_AGE_SECONDS:
        raise argparse.ArgumentTypeError(
            f"must be between 1 and {MAX_ANDROID_PROOF_AGE_SECONDS}: {value}"
        )
    return value


def validate_device_sdk(raw_value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,2}", raw_value) is None:
        raise argparse.ArgumentTypeError(
            f"must be a canonical integer between 1 and {MAX_ANDROID_SDK}: {raw_value}"
        )
    return int(raw_value)


def verify_source_hashes(root: pathlib.Path, proof: dict[str, Any]) -> None:
    expected = exact_object(
        proof.get("source_hashes"),
        {name + "_sha256" for name in SOURCE_INPUTS},
        "Android proof source hash",
    )
    for name, rel in SOURCE_INPUTS.items():
        got = sha256_file(root / rel)
        require(expected.get(name + "_sha256") == got, f"source input changed since Android proof: {name}")


def verify_result_files(paths: dict[str, pathlib.Path], run_id: str) -> None:
    marker = expected_marker(run_id)
    marker_text = read_text(paths["result_txt"])
    require(marker_text == marker + "\n", f"Android result marker mismatch in {paths['result_txt']}")

    result = load_json(paths["result_json"])
    exact_object(result, RESULT_FIELDS, "Android result")
    require(result.get("schema") == RESULT_SCHEMA_VERSION, "Android result schema mismatch")
    require(result.get("status") == "pass", "Android result status is not pass")
    require(result.get("run_id") == run_id, "Android result run_id mismatch")
    require(result.get("test_count") == len(EXPECTED_TESTS), "Android result test_count mismatch")
    require(result.get("passed_tests") == EXPECTED_TESTS, "Android result passed_tests mismatch")

    logcat = read_text(paths["logcat"])
    for line in logcat.splitlines():
        if not line:
            continue
        require(
            line.startswith("--------- beginning of ")
            or LOGCAT_APP_LINE.match(line) is not None,
            "Android logcat contains data outside the QPeriaptSmoke tag filter",
        )
    for pattern in LOG_FATAL_PATTERNS:
        require(pattern not in logcat, f"Android logcat contains runtime failure marker: {pattern}")


def verify_artifact_hashes(paths: dict[str, pathlib.Path], proof: dict[str, Any]) -> None:
    artifacts = exact_object(
        proof.get("artifacts"), PROOF_ARTIFACT_FIELDS, "Android proof artifact"
    )
    expected_hashes = {
        "aar_sha256": paths["aar"],
        "aar_manifest_sha256": paths["aar_manifest"],
        "smoke_apk_sha256": paths["smoke_apk"],
        "apksigner_verify_sha256": paths["apksigner_verify"],
        "zipalign_verify_sha256": paths["zipalign_verify"],
        "logcat_sha256": paths["logcat"],
    }
    for key, path in expected_hashes.items():
        require(artifacts.get(key) == sha256_file(path), f"hash mismatch for {key}: {path}")

    result = exact_object(
        proof.get("result"), PROOF_RESULT_FIELDS, "Android proof result"
    )
    require(result.get("marker_sha256") == sha256_file(paths["result_txt"]), "result marker hash mismatch")
    require(result.get("json_sha256") == sha256_file(paths["result_json"]), "result JSON hash mismatch")
    require(result.get("status") == "pass", "proof result status is not pass")
    require(result.get("test_count") == len(EXPECTED_TESTS), "proof result test_count mismatch")
    require(result.get("passed_tests") == EXPECTED_TESTS, "proof result passed_tests mismatch")


def verify_native_hashes(paths: dict[str, pathlib.Path], proof: dict[str, Any]) -> None:
    artifacts = exact_object(
        proof.get("artifacts"), PROOF_ARTIFACT_FIELDS, "Android proof artifact"
    )
    native = exact_object(
        artifacts.get("native"), set(REQUIRED_NATIVE_ABIS), "Android proof native ABI"
    )
    try:
        aar_entries, _ = audit_aar(paths["aar"])
    except AndroidVerificationError as exc:
        require(False, f"Android proof AAR audit failed: {exc}")
    for abi in REQUIRED_NATIVE_ABIS:
        expected = exact_object(
            native.get(abi),
            PROOF_NATIVE_HASH_FIELDS,
            f"Android proof native hash {abi}",
        )
        ffi = sha256_bytes(aar_entries[f"jni/{abi}/libq_periapt_ffi_abi2.so"])
        jni = sha256_bytes(aar_entries[f"jni/{abi}/libqperiapt_jni_abi2.so"])
        require(expected.get("ffi_so_sha256") == ffi, f"AAR ffi hash mismatch for {abi}")
        require(expected.get("jni_so_sha256") == jni, f"AAR JNI hash mismatch for {abi}")


def verify_abi_metadata(root: pathlib.Path, proof: dict[str, Any]) -> None:
    abi = exact_object(proof.get("abi"), PROOF_ABI_FIELDS, "Android proof ABI")
    contract_relative = "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
    require(abi.get("major") == 2, "Android proof ABI major is not 2")
    require(
        abi.get("contract_path") == contract_relative,
        "Android proof ABI contract path differs",
    )
    require(
        abi.get("contract_sha256") == sha256_file(root / contract_relative),
        "Android proof ABI contract hash differs",
    )
    require(
        abi.get("runtime_library") == "libq_periapt_ffi_abi2.so",
        "Android proof runtime library name differs",
    )
    require(
        abi.get("jni_library") == "libqperiapt_jni_abi2.so",
        "Android proof JNI library name differs",
    )
    require(
        abi.get("legacy_library_names_present") is False,
        "Android proof reports legacy library names",
    )


def verify_device_metadata(
    proof: dict[str, Any],
    *,
    expected_device_kind: str = "",
    expected_device_abi: str = "",
    expected_page_size: int | None = None,
    expected_device_sdk: int | None = None,
    require_release_mode: bool = False,
) -> None:
    device = proof.get("device")
    require(isinstance(device, dict), "proof lacks device metadata")
    require(device.get("raw_serial_recorded") is False, "proof must not record raw adb serial")
    for prefix_field in ("serial_sha256_prefix", "fingerprint_sha256_prefix"):
        prefix = device.get(prefix_field)
        require(
            isinstance(prefix, str) and re.fullmatch(r"[0-9a-f]{12}", prefix) is not None,
            f"Android proof has an invalid {prefix_field}",
        )
    for text_field in ("manufacturer", "model", "release"):
        text_value = device.get(text_field)
        require(
            isinstance(text_value, str)
            and 0 < len(text_value) <= 256
            and all(ord(character) >= 0x20 for character in text_value),
            f"Android proof has invalid device {text_field}",
        )
    kind = device.get("kind")
    require(kind in {"emulator", "physical"}, f"invalid Android device kind: {kind}")
    if expected_device_kind:
        require(kind == expected_device_kind, f"expected Android device kind {expected_device_kind}, got {kind}")

    device_abi = device.get("abi")
    require(device_abi in REQUIRED_NATIVE_ABIS, f"invalid Android device ABI: {device_abi}")
    if expected_device_abi:
        require(device_abi == expected_device_abi, f"expected Android device ABI {expected_device_abi}, got {device_abi}")
    page_size = device.get("page_size")
    require(type(page_size) is int and page_size in {4096, 16384}, f"invalid Android device page size: {page_size}")
    if expected_page_size is not None:
        require(page_size == expected_page_size, f"expected Android page size {expected_page_size}, got {page_size}")
    device_sdk = device.get("sdk")
    require(
        type(device_sdk) is int and 1 <= device_sdk <= MAX_ANDROID_SDK,
        f"invalid Android device SDK: {device_sdk!r}",
    )
    release_mode = proof.get("release_candidate_mode")
    require(type(release_mode) is bool, "proof lacks release_candidate_mode")
    if require_release_mode:
        require(
            expected_device_sdk == ANDROID_RELEASE_SDK,
            f"release verification requires expected Android device SDK {ANDROID_RELEASE_SDK}",
        )
    if expected_device_sdk is not None:
        require(
            device_sdk == expected_device_sdk,
            f"expected Android device SDK {expected_device_sdk}, got {device_sdk}",
        )

    if require_release_mode:
        require(release_mode is True, "proof was not generated in Android release-candidate mode")
        require(expected_device_abi != "", "release verification requires an explicit expected Android device ABI")
        require(expected_page_size == 16384, "release verification requires expected Android page size 16384")
        require(page_size == 16384, "Android release proof did not run on a 16 KiB page-size device")
        require(
            device_sdk == ANDROID_RELEASE_SDK,
            f"Android release proof did not run on device SDK {ANDROID_RELEASE_SDK}",
        )

    android = proof.get("android")
    require(isinstance(android, dict), "proof lacks Android toolchain metadata")
    ndk = android.get("ndk")
    require(
        isinstance(ndk, str) and re.fullmatch(r"29\.[0-9]+\.[0-9]+", ndk) is not None,
        f"Android runtime proof must use NDK r29, got {ndk!r}",
    )
    require(android.get("native_page_alignment") == 16384, "Android runtime proof lacks 16 KiB native alignment metadata")
    require(android.get("min_sdk") == 23, "Android runtime proof minimum SDK differs")
    build_tools = android.get("build_tools")
    require(
        isinstance(build_tools, str)
        and re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+(?:-rc[1-9][0-9]*)?", build_tools)
        is not None,
        f"Android runtime proof has invalid build-tools metadata: {build_tools!r}",
    )
    adb_version = android.get("adb_version")
    require(
        isinstance(adb_version, str)
        and re.fullmatch(
            r"Android Debug Bridge version [1-9][0-9]*\.[0-9]+\.[0-9]+",
            adb_version,
        )
        is not None,
        f"Android runtime proof has invalid adb version metadata: {adb_version!r}",
    )
    target_sdk = android.get("target_sdk")
    require(
        type(target_sdk) is int and 1 <= target_sdk <= MAX_ANDROID_SDK,
        f"Android runtime proof has invalid target SDK: {target_sdk!r}",
    )
    require(
        android.get("platform") == f"android-{target_sdk}",
        "Android runtime proof platform and target SDK differ",
    )
    if require_release_mode:
        require(
            ndk == "29.0.14206865",
            "Android release proof must use NDK 29.0.14206865",
        )
        require(
            target_sdk == ANDROID_RELEASE_SDK,
            f"Android release proof was not built against SDK {ANDROID_RELEASE_SDK}",
        )
    for tool_name in ("apksigner", "zipalign"):
        digest = android.get(tool_name + "_sha256")
        require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            f"Android runtime proof lacks a valid {tool_name} SHA-256",
        )


def verify_proof_contents(
    root: pathlib.Path,
    proof: dict[str, Any],
    paths: dict[str, pathlib.Path],
    *,
    expected_device_kind: str = "",
    expected_device_abi: str = "",
    expected_page_size: int | None = None,
    expected_device_sdk: int | None = None,
    require_release_mode: bool = False,
    allow_dirty_proof: bool = False,
) -> None:
    verify_proof_schema(proof)
    require(set(paths) == set(PROOF_PATH_KEYS), "selected Android evidence path fields differ")
    proof_path_fields(proof)
    require(proof.get("device_runtime_proof") is True, "proof is not an Android runtime proof")
    require(proof.get("package_only") is False, "runtime proof must not be package_only")
    require(proof.get("package") == "dev.qperiapt.androidsmoke", "unexpected Android proof package")
    run_id = proof.get("run_id")
    require(isinstance(run_id, str), "proof run_id is missing")
    expected_marker(run_id)

    parse_generated_at(proof.get("generated_at"))
    verify_git_provenance(root, proof, allow_dirty_proof)
    verify_source_tree_digest(root, proof)

    verify_device_metadata(
        proof,
        expected_device_kind=expected_device_kind,
        expected_device_abi=expected_device_abi,
        expected_page_size=expected_page_size,
        expected_device_sdk=expected_device_sdk,
        require_release_mode=require_release_mode,
    )
    verify_source_hashes(root, proof)
    verify_abi_metadata(root, proof)
    verify_result_files(paths, run_id)
    verify_artifact_hashes(paths, proof)
    verify_native_hashes(paths, proof)


def verify(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    proof_path = args.proof.resolve()
    require_under(proof_path, root / "target", "Android proof")
    require(
        args.results_manifest is not None or args.expected_results_manifest_sha256 is None,
        "expected results manifest SHA-256 requires --results-manifest",
    )
    if args.results_manifest is not None:
        require(
            args.expected_results_manifest_sha256 is not None,
            "manifest-bound Android verification requires the expected results manifest SHA-256",
        )
        try:
            manifest = load_results_manifest_snapshot(
                args.results_manifest.resolve(),
                expected_sha256=args.expected_results_manifest_sha256,
            )
            proof_snapshot = select_bound_json_snapshot(
                root,
                manifest,
                binding="android_runtime",
                selected_path=proof_path,
                label="Android runtime proof",
            )
        except ProofManifestError as exc:
            raise SystemExit(f"error: {exc}") from exc
        proof = proof_snapshot.value
    else:
        proof_snapshot = None
        proof = load_json(proof_path)

    verify_proof_schema(proof)
    verify_proof_freshness(proof, args.max_age_seconds)
    verify_proof_contents(
        root,
        proof,
        proof_paths(root, proof),
        expected_device_kind=args.expected_device_kind,
        expected_device_abi=args.expected_device_abi,
        expected_page_size=args.expected_page_size,
        expected_device_sdk=args.expected_device_sdk,
        require_release_mode=args.require_release_mode,
        allow_dirty_proof=args.allow_dirty_proof,
    )
    print("ANDROID_DEVICE_PROOF_VERIFY_PASS")
    if proof_snapshot is not None:
        print(
            "PROOF_TO_BYTE_SELECTED_PROOF_MANIFEST_PASS "
            f"section=android_runtime sha256={proof_snapshot.file.sha256}"
        )


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def write_bundle_file(path: pathlib.Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, 0o644)
    except OSError as exc:
        raise SystemExit(f"error: cannot stage Android evidence bundle file {path}: {exc}") from exc


def bundle_file_record(path: pathlib.Path, relative: str) -> dict[str, Any]:
    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label=f"Android bundle file {relative}",
        )
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc
    return {"bytes": snapshot.size, "path": relative, "sha256": snapshot.sha256}


def source_commit_epoch(root: pathlib.Path, proof: dict[str, Any]) -> int:
    source_commit = proof.get("git_commit")
    require(
        isinstance(source_commit, str)
        and re.fullmatch(r"[0-9a-f]{40,64}", source_commit) is not None,
        "Android proof lacks a valid git_commit",
    )
    try:
        raw_epoch = run_git_text(root, ["show", "-s", "--format=%ct", source_commit])
    except GitProvenanceError as exc:
        raise SystemExit(f"error: cannot read Android proof commit epoch: {exc}") from exc
    require(raw_epoch.isascii() and raw_epoch.isdigit(), "Android proof commit epoch is malformed")
    epoch = int(raw_epoch)
    require(315532800 <= epoch <= 0xFFFFFFFF, "Android proof commit epoch cannot be represented by deterministic ZIP")
    return epoch


def scan_release_paths(
    paths: list[pathlib.Path],
    *,
    forbidden_text: list[str],
) -> None:
    for path in paths:
        try:
            scan_release_file(path, forbidden_text=forbidden_text)
        except ReleaseBinaryScanError as exc:
            raise SystemExit(f"error: {exc}") from exc


def scan_apk_contents(apk: pathlib.Path, *, forbidden_text: list[str]) -> None:
    try:
        snapshot = read_regular_snapshot(
            apk,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="Android smoke APK",
        )
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc
    names: set[str] = set()
    folded_names: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(snapshot.data), "r", allowZip64=False) as archive:
            infos = archive.infolist()
            require(0 < len(infos) <= 4096, "Android smoke APK entry count is invalid")
            with tempfile.TemporaryDirectory(prefix="qperiapt-apk-scan-") as temp:
                scan_root = pathlib.Path(temp)
                materialized: list[pathlib.Path] = []
                for index, info in enumerate(infos):
                    name = info.filename
                    canonical_name = name.rstrip("/")
                    pure = pathlib.PurePosixPath(canonical_name)
                    require(
                        name
                        and "\\" not in name
                        and "\x00" not in name
                        and not pure.is_absolute()
                        and ".." not in pure.parts,
                        f"Android smoke APK contains an unsafe path: {name!r}",
                    )
                    require(
                        canonical_name not in {"", "."}
                        and pure.as_posix() == canonical_name,
                        f"Android smoke APK contains a noncanonical path: {name!r}",
                    )
                    require(name not in names, f"Android smoke APK contains duplicate entry: {name}")
                    require(
                        canonical_name.casefold() not in folded_names,
                        f"Android smoke APK contains a case-conflicting entry: {name}",
                    )
                    names.add(name)
                    folded_names.add(canonical_name.casefold())
                    require(info.flag_bits & 0x1 == 0, f"Android smoke APK contains encrypted entry: {name}")
                    require(
                        info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                        f"Android smoke APK contains unsupported compression: {name}",
                    )
                    file_type = (info.external_attr >> 16) & 0o170000
                    expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
                    require(
                        file_type in {0, expected_type},
                        f"Android smoke APK contains a symlink or special entry: {name}",
                    )
                    require(
                        info.file_size <= 128 * 1024 * 1024,
                        f"Android smoke APK entry is too large: {name}",
                    )
                    total += info.file_size
                    require(total <= 256 * 1024 * 1024, "Android smoke APK uncompressed size exceeds limit")
                    if info.is_dir():
                        continue
                    data = archive.read(info)
                    require(len(data) == info.file_size, f"Android smoke APK entry size differs: {name}")
                    materialized_path = scan_root / f"entry-{index:04d}.bin"
                    materialized_path.write_bytes(data)
                    materialized.append(materialized_path)
                scan_release_paths(materialized, forbidden_text=forbidden_text)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"error: cannot audit Android smoke APK {apk}: {exc}") from exc


def require_executable_file(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise SystemExit(f"error: cannot inspect {label} {path}: {exc}") from exc
    require(stat.S_ISREG(metadata.st_mode), f"{label} must resolve to a regular file: {path}")
    require(os.access(resolved, os.X_OK), f"{label} is not executable: {path}")
    return resolved


def verified_ndk_tools(
    llvm_nm: pathlib.Path,
    llvm_readelf: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, str]:
    requested_nm = pathlib.Path(llvm_nm)
    requested_readelf = pathlib.Path(llvm_readelf)
    require(requested_nm.name == "llvm-nm", "Android llvm-nm filename differs")
    require(
        requested_readelf.name == "llvm-readelf",
        "Android llvm-readelf filename differs",
    )
    resolved_nm = require_executable_file(llvm_nm, "Android llvm-nm")
    resolved_readelf = require_executable_file(
        llvm_readelf, "Android llvm-readelf"
    )
    require(
        resolved_nm.name == "llvm-nm"
        and resolved_readelf.name in {"llvm-readelf", "llvm-readobj"},
        "Android LLVM tool targets differ from the NDK layout",
    )
    bin_directory = resolved_nm.parent
    require(
        resolved_readelf.parent == bin_directory
        and requested_nm.parent.resolve(strict=True) == bin_directory
        and requested_readelf.parent.resolve(strict=True) == bin_directory
        and bin_directory.name == "bin"
        and bin_directory.parent.parent.name == "prebuilt"
        and bin_directory.parent.parent.parent.name == "llvm"
        and bin_directory.parent.parent.parent.parent.name == "toolchains",
        "Android LLVM tools are not from one canonical NDK toolchain",
    )
    ndk_root = bin_directory.parent.parent.parent.parent.parent
    try:
        revision = verify_ndk_r29(ndk_root)
    except AndroidVerificationError as exc:
        raise SystemExit(f"error: Android NDK toolchain verification failed: {exc}") from exc
    canonical_nm = bin_directory / "llvm-nm"
    canonical_readelf = bin_directory / "llvm-readelf"
    require(
        canonical_nm.resolve(strict=True) == resolved_nm
        and canonical_readelf.resolve(strict=True) == resolved_readelf,
        "Android LLVM tool aliases differ from the canonical NDK entries",
    )
    return canonical_nm, canonical_readelf, revision


def run_evidence_tool(
    tool: pathlib.Path,
    arguments: list[str],
    *,
    cwd: pathlib.Path,
    label: str,
) -> bytes:
    executable = require_executable_file(tool, label)
    try:
        process = subprocess.run(
            [str(executable), *arguments],
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise SystemExit(f"error: cannot execute {label}: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        suffix = f": {detail}" if detail else ""
        raise SystemExit(
            f"error: {label} failed with exit status {process.returncode}{suffix}"
        )
    require(not process.stderr, f"{label} emitted unexpected diagnostics")
    return process.stdout


def expected_bundle_entries() -> dict[str, str]:
    expected = {
        BUNDLE_ROOT_NAME: "directory",
        f"{BUNDLE_ROOT_NAME}/artifacts": "directory",
        f"{BUNDLE_ROOT_NAME}/evidence": "directory",
        f"{BUNDLE_ROOT_NAME}/{BUNDLE_MANIFEST_PATH}": "file",
    }
    expected.update(
        {
            f"{BUNDLE_ROOT_NAME}/{relative}": "file"
            for relative in BUNDLE_FILE_PATHS.values()
        }
    )
    return expected


def verify_bundle_manifest(
    bundle_root: pathlib.Path,
    manifest: dict[str, Any],
    *,
    archive_mtime: int,
) -> tuple[dict[str, pathlib.Path], dict[str, Any]]:
    require(
        set(manifest)
        == {
            "schema_version",
            "kind",
            "source_date_epoch",
            "git_commit",
            "run_id",
            "release_candidate_mode",
            "device",
            "raw_serial_recorded",
            "files",
        },
        "Android evidence bundle manifest fields differ",
    )
    require(
        manifest.get("schema_version") == BUNDLE_SCHEMA_VERSION
        and manifest.get("kind") == BUNDLE_KIND,
        "Android evidence bundle manifest schema differs",
    )
    source_epoch = manifest.get("source_date_epoch")
    require(
        type(source_epoch) is int and 315532800 <= source_epoch <= 0xFFFFFFFF,
        "Android evidence bundle source_date_epoch is invalid",
    )
    require(
        archive_mtime == source_epoch - source_epoch % 2,
        "Android evidence bundle ZIP timestamp differs from source_date_epoch",
    )
    require(manifest.get("raw_serial_recorded") is False, "Android evidence bundle records a raw serial")
    require(
        type(manifest.get("release_candidate_mode")) is bool,
        "Android evidence bundle release_candidate_mode must be a boolean",
    )
    files = manifest.get("files")
    require(isinstance(files, dict) and set(files) == set(BUNDLE_FILE_PATHS), "Android evidence bundle file fields differ")
    selected: dict[str, pathlib.Path] = {}
    for key, expected_relative in BUNDLE_FILE_PATHS.items():
        record = files.get(key)
        require(
            isinstance(record, dict) and set(record) == {"bytes", "path", "sha256"},
            f"Android evidence bundle file record differs: {key}",
        )
        require(record.get("path") == expected_relative, f"Android evidence bundle path differs: {key}")
        size = record.get("bytes")
        digest = record.get("sha256")
        require(type(size) is int and 0 < size <= MAX_EVIDENCE_FILE_BYTES, f"Android evidence bundle size is invalid: {key}")
        require(isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None, f"Android evidence bundle digest is invalid: {key}")
        path = bundle_root.joinpath(*pathlib.PurePosixPath(expected_relative).parts)
        try:
            snapshot = read_regular_snapshot(
                path,
                maximum=MAX_EVIDENCE_FILE_BYTES,
                label=f"Android bundled evidence {key}",
            )
        except EvidenceIOError as exc:
            raise SystemExit(f"error: {exc}") from exc
        require(snapshot.size == size and snapshot.sha256 == digest, f"Android bundled evidence bytes differ: {key}")
        selected[key] = path
    proof = load_json(selected["proof"])
    verify_proof_schema(proof)
    require(manifest.get("git_commit") == proof.get("git_commit"), "Android bundle git_commit differs from proof")
    require(manifest.get("run_id") == proof.get("run_id"), "Android bundle run_id differs from proof")
    require(
        manifest.get("release_candidate_mode") is proof.get("release_candidate_mode"),
        "Android bundle release mode differs from proof",
    )
    device = manifest.get("device")
    proof_device = proof.get("device")
    require(
        isinstance(device, dict)
        and set(device) == {"kind", "abi", "page_size", "sdk"}
        and isinstance(proof_device, dict),
        "Android bundle device fields differ",
    )
    require(
        device.get("kind") in {"emulator", "physical"}
        and device.get("abi") in REQUIRED_NATIVE_ABIS
        and type(device.get("page_size")) is int
        and device.get("page_size") in {4096, 16384}
        and type(device.get("sdk")) is int
        and 1 <= device.get("sdk") <= MAX_ANDROID_SDK,
        "Android bundle device metadata is invalid",
    )
    require(
        device
        == {
            "kind": proof_device.get("kind"),
            "abi": proof_device.get("abi"),
            "page_size": proof_device.get("page_size"),
            "sdk": proof_device.get("sdk"),
        },
        "Android bundle device metadata differs from proof",
    )
    if manifest.get("release_candidate_mode") is True:
        require(
            device.get("page_size") == 16384
            and device.get("sdk") == ANDROID_RELEASE_SDK,
            "Android release bundle device metadata is not API 35 / 16 KiB",
        )
    return selected, proof


def verify_runtime_bundle(
    *,
    root: pathlib.Path,
    bundle: pathlib.Path,
    expected_bundle_sha256: str | None,
    llvm_nm: pathlib.Path,
    llvm_readelf: pathlib.Path,
    apksigner: pathlib.Path,
    zipalign: pathlib.Path,
    expected_device_kind: str,
    expected_device_abi: str,
    expected_page_size: int | None,
    expected_device_sdk: int | None,
    require_release_mode: bool,
    allow_dirty_proof: bool,
    forbidden_text: list[str],
) -> str:
    try:
        with tempfile.TemporaryDirectory(prefix="qperiapt-android-bundle-") as temp:
            temporary_root = canonical_private_directory(
                pathlib.Path(temp), "Android evidence verification temporary directory"
            )
            destination = temporary_root / "extracted"
            audit = extract_zip(
                bundle,
                destination,
                root_name=BUNDLE_ROOT_NAME,
                expected_sha256=expected_bundle_sha256,
            )
            actual_entries = {entry.path: entry.kind for entry in audit.entries}
            require(actual_entries == expected_bundle_entries(), "Android evidence bundle archive file set differs")
            extracted_root = destination / BUNDLE_ROOT_NAME
            manifest = load_json(extracted_root / BUNDLE_MANIFEST_PATH)
            selected, proof = verify_bundle_manifest(
                extracted_root,
                manifest,
                archive_mtime=audit.mtime,
            )
            require(
                manifest["source_date_epoch"] == source_commit_epoch(root, proof),
                "Android evidence bundle source_date_epoch differs from its proof commit",
            )
            proof_selected = {key: selected[key] for key in PROOF_PATH_KEYS}
            verify_proof_contents(
                root,
                proof,
                proof_selected,
                expected_device_kind=expected_device_kind,
                expected_device_abi=expected_device_abi,
                expected_page_size=expected_page_size,
                expected_device_sdk=expected_device_sdk,
                require_release_mode=require_release_mode,
                allow_dirty_proof=allow_dirty_proof,
            )
            scan_paths = [extracted_root / BUNDLE_MANIFEST_PATH, *selected.values()]
            scan_release_paths(scan_paths, forbidden_text=forbidden_text)
            scan_apk_contents(selected["smoke_apk"], forbidden_text=forbidden_text)

            android = proof["android"]
            resolved_llvm_nm, resolved_llvm_readelf, ndk_revision = verified_ndk_tools(
                llvm_nm, llvm_readelf
            )
            require(
                ndk_revision == android.get("ndk"),
                "Android NDK toolchain revision differs from runtime proof",
            )
            resolved_apksigner = require_executable_file(apksigner, "Android apksigner")
            resolved_zipalign = require_executable_file(zipalign, "Android zipalign")
            require(
                resolved_apksigner.name == "apksigner"
                and resolved_zipalign.name == "zipalign"
                and resolved_apksigner.parent == resolved_zipalign.parent
                and resolved_apksigner.parent.name == android.get("build_tools"),
                "Android build-tools paths differ from runtime proof",
            )
            require(
                sha256_file(resolved_apksigner) == android.get("apksigner_sha256"),
                "Android apksigner bytes differ from runtime proof",
            )
            require(
                sha256_file(resolved_zipalign) == android.get("zipalign_sha256"),
                "Android zipalign bytes differ from runtime proof",
            )
            apk_name = selected["smoke_apk"].name
            apksigner_stdout = run_evidence_tool(
                resolved_apksigner,
                ["verify", "--min-sdk-version", "23", "--print-certs", apk_name],
                cwd=selected["smoke_apk"].parent,
                label="Android apksigner verification",
            )
            require(
                apksigner_stdout == read_bytes(selected["apksigner_verify"]),
                "independent apksigner output differs from bundled evidence",
            )
            zipalign_stdout = run_evidence_tool(
                resolved_zipalign,
                ["-c", "-P", "16", "-v", "4", apk_name],
                cwd=selected["smoke_apk"].parent,
                label="Android zipalign verification",
            )
            require(
                zipalign_stdout == read_bytes(selected["zipalign_verify"]),
                "independent zipalign output differs from bundled evidence",
            )
            artifacts = proof["artifacts"]
            try:
                verify_aar(
                    selected["aar"],
                    llvm_nm=resolved_llvm_nm,
                    llvm_readelf=resolved_llvm_readelf,
                    manifest=selected["aar_manifest"],
                    expected_aar_sha256=artifacts["aar_sha256"],
                    expected_manifest_sha256=artifacts["aar_manifest_sha256"],
                    require_release_manifest=require_release_mode,
                    forbidden_text=forbidden_text,
                    source_root=root,
                )
            except AndroidVerificationError as exc:
                raise SystemExit(f"error: bundled Android AAR verification failed: {exc}") from exc
            return audit.archive_sha256
    except DeterministicArchiveError as exc:
        raise SystemExit(f"error: Android evidence bundle archive verification failed: {exc}") from exc


def create_bundle(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    proof_path = args.proof.resolve()
    output = args.output.resolve()
    require_under(proof_path, root / "target", "Android proof")
    require_under(output, root / "target", "Android evidence bundle output")
    require(output.suffix == ".zip", "Android evidence bundle output must use .zip")
    require(not output.exists() and not output.is_symlink(), f"Android evidence bundle output already exists: {output}")
    require(
        output.parent.is_dir() and not output.parent.is_symlink(),
        f"Android evidence bundle output parent is unsafe or missing: {output.parent}",
    )
    proof = load_json(proof_path)
    verify_proof_schema(proof)
    verify_proof_freshness(proof, args.max_age_seconds)
    selected_paths = proof_paths(root, proof)
    verify_proof_contents(
        root,
        proof,
        selected_paths,
        expected_device_kind=args.expected_device_kind,
        expected_device_abi=args.expected_device_abi,
        expected_page_size=args.expected_page_size,
        expected_device_sdk=args.expected_device_sdk,
        require_release_mode=args.require_release_mode,
        allow_dirty_proof=args.allow_dirty_proof,
    )
    source_epoch = source_commit_epoch(root, proof)
    forbidden_text = [str(root), *args.forbid_text]
    try:
        with tempfile.TemporaryDirectory(prefix="qperiapt-android-bundle-stage-", dir=output.parent) as temp:
            stage = pathlib.Path(temp) / "stage"
            stage.mkdir()
            sources = {"proof": proof_path, **selected_paths}
            for key, relative in BUNDLE_FILE_PATHS.items():
                write_bundle_file(stage / relative, read_bytes(sources[key]))
            file_records = {
                key: bundle_file_record(stage / relative, relative)
                for key, relative in BUNDLE_FILE_PATHS.items()
            }
            device = proof["device"]
            bundle_manifest = {
                "schema_version": BUNDLE_SCHEMA_VERSION,
                "kind": BUNDLE_KIND,
                "source_date_epoch": source_epoch,
                "git_commit": proof["git_commit"],
                "run_id": proof["run_id"],
                "release_candidate_mode": proof["release_candidate_mode"],
                "device": {
                    "kind": device["kind"],
                    "abi": device["abi"],
                    "page_size": device["page_size"],
                    "sdk": device["sdk"],
                },
                "raw_serial_recorded": False,
                "files": file_records,
            }
            write_bundle_file(stage / BUNDLE_MANIFEST_PATH, canonical_json(bundle_manifest))
            staged_paths = [stage / BUNDLE_MANIFEST_PATH]
            staged_paths.extend(stage / relative for relative in BUNDLE_FILE_PATHS.values())
            scan_release_paths(staged_paths, forbidden_text=forbidden_text)
            scan_apk_contents(stage / BUNDLE_FILE_PATHS["smoke_apk"], forbidden_text=forbidden_text)
            audit = create_zip(
                stage,
                output,
                root_name=BUNDLE_ROOT_NAME,
                mtime=source_epoch,
            )
    except DeterministicArchiveError as exc:
        raise SystemExit(f"error: cannot create Android evidence bundle: {exc}") from exc

    verified_sha256 = verify_runtime_bundle(
        root=root,
        bundle=output,
        expected_bundle_sha256=audit.archive_sha256,
        llvm_nm=args.llvm_nm,
        llvm_readelf=args.llvm_readelf,
        apksigner=args.apksigner,
        zipalign=args.zipalign,
        expected_device_kind=args.expected_device_kind,
        expected_device_abi=args.expected_device_abi,
        expected_page_size=args.expected_page_size,
        expected_device_sdk=args.expected_device_sdk,
        require_release_mode=args.require_release_mode,
        allow_dirty_proof=args.allow_dirty_proof,
        forbidden_text=forbidden_text,
    )
    require(verified_sha256 == audit.archive_sha256, "created Android evidence bundle digest changed during verification")
    print(
        "ANDROID_DEVICE_EVIDENCE_BUNDLE_CREATE_PASS "
        f"sha256={audit.archive_sha256} path={output}"
    )


def verify_bundle(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    forbidden_text = [str(root), *args.forbid_text]
    digest = verify_runtime_bundle(
        root=root,
        bundle=args.bundle.resolve(),
        expected_bundle_sha256=args.expected_bundle_sha256,
        llvm_nm=args.llvm_nm,
        llvm_readelf=args.llvm_readelf,
        apksigner=args.apksigner,
        zipalign=args.zipalign,
        expected_device_kind=args.expected_device_kind,
        expected_device_abi=args.expected_device_abi,
        expected_page_size=args.expected_page_size,
        expected_device_sdk=args.expected_device_sdk,
        require_release_mode=args.require_release_mode,
        allow_dirty_proof=args.allow_dirty_proof,
        forbidden_text=forbidden_text,
    )
    print(f"ANDROID_DEVICE_EVIDENCE_BUNDLE_VERIFY_PASS sha256={digest}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_runtime_constraints(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--expected-device-kind",
            choices=["emulator", "physical"],
            default="",
        )
        command.add_argument(
            "--expected-device-abi",
            choices=list(REQUIRED_NATIVE_ABIS),
            default="",
        )
        command.add_argument("--expected-page-size", type=int, choices=[4096, 16384])
        command.add_argument("--expected-device-sdk", type=validate_device_sdk)
        command.add_argument("--require-release-mode", action="store_true")
        command.add_argument("--allow-dirty-proof", action="store_true")

    def add_freshness_gate(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--max-age-seconds",
            type=validate_max_age_seconds,
            default=86400,
        )

    def add_bundle_tools(command: argparse.ArgumentParser) -> None:
        command.add_argument("--llvm-nm", required=True, type=pathlib.Path)
        command.add_argument("--llvm-readelf", required=True, type=pathlib.Path)
        command.add_argument("--apksigner", required=True, type=pathlib.Path)
        command.add_argument("--zipalign", required=True, type=pathlib.Path)
        command.add_argument("--forbid-text", action="append", default=[])

    verify_parser = sub.add_parser("verify", help="verify an Android runtime proof JSON")
    verify_parser.add_argument("--root", required=True, type=pathlib.Path)
    verify_parser.add_argument("--proof", required=True, type=pathlib.Path)
    add_runtime_constraints(verify_parser)
    add_freshness_gate(verify_parser)
    verify_parser.add_argument("--results-manifest", type=pathlib.Path)
    verify_parser.add_argument("--expected-results-manifest-sha256")
    verify_parser.set_defaults(func=verify)

    create_bundle_parser = sub.add_parser(
        "create-bundle",
        help="create and independently verify a deterministic Android runtime evidence ZIP",
    )
    create_bundle_parser.add_argument("--root", required=True, type=pathlib.Path)
    create_bundle_parser.add_argument("--proof", required=True, type=pathlib.Path)
    create_bundle_parser.add_argument("--output", required=True, type=pathlib.Path)
    add_runtime_constraints(create_bundle_parser)
    add_freshness_gate(create_bundle_parser)
    add_bundle_tools(create_bundle_parser)
    create_bundle_parser.set_defaults(func=create_bundle)

    verify_bundle_parser = sub.add_parser(
        "verify-bundle",
        help="independently verify a deterministic Android runtime evidence ZIP",
    )
    verify_bundle_parser.add_argument("--root", required=True, type=pathlib.Path)
    verify_bundle_parser.add_argument("--bundle", required=True, type=pathlib.Path)
    verify_bundle_parser.add_argument("--expected-bundle-sha256")
    add_runtime_constraints(verify_bundle_parser)
    add_bundle_tools(verify_bundle_parser)
    verify_bundle_parser.set_defaults(func=verify_bundle)
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
