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
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from typing import Any

from android_elf import (
    AndroidVerificationError,
    audit_aar,
    verify_aar,
    verify_ndk_r29,
)
from android_emulator_control import (
    ADB_ISOLATION_CHECKPOINT_LEAVES,
    ADB_ISOLATION_RECEIPT_KIND,
    ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
    DEFAULT_ADB_SERVER_PORT,
    EMULATOR_ROUTING_MODE,
    EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
    EMULATOR_ROUTING_RECEIPT_KIND,
    EMULATOR_ROUTING_RECEIPT_LEAF,
    EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION,
    NATIVE_ADB_NOTIFIER_MODE,
    NATIVE_ADB_NOTIFIER_PORT,
    AdbIsolationCheckpoint,
    AndroidEmulatorControlError,
    emulator_routing_transport_binding_sha256,
    fixed_headless_backend_path,
    parse_owned_adb_server_status,
    parse_owned_lsof_listeners,
    parse_owned_single_listener,
    probe_adb_loopback_absence,
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
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    require_commit_or_evidence_successor,
    run_git_text,
)
from git_provenance import (
    git_commit as provenance_git_commit,
)
from git_provenance import (
    source_tree_dirty as provenance_source_tree_dirty,
)
from platform_release_contract import (
    ANDROID_BUNDLE_MANIFEST_SHA256,
    ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
    ANDROID_PROOF_SHA256,
    ANDROID_RUNTIME_BUNDLE,
    ASSET_BY_NAME,
    CANONICAL_SOURCE_TREE_SHA256,
    PUBLISHED_ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
    TAG_COMMIT,
)
from process_identity import (
    ProcessExecutionSnapshot,
    ProcessIdentityError,
)
from process_identity import execution_snapshot as process_execution_snapshot
from process_identity import (
    parse_token as parse_process_identity_token,
)
from process_identity import (
    snapshot as process_snapshot,
)
from proof_manifest import (
    ProofManifestError,
    load_results_manifest_snapshot,
    select_bound_json_snapshot,
)
from release_binary_scan import ReleaseBinaryScanError, scan_release_file

PROOF_SCHEMA_VERSION = ANDROID_DEVICE_PROOF_SCHEMA_VERSION
RESULT_SCHEMA_VERSION = 1
PASS_MARKER = "QPERIAPT_ANDROID_DEVICE_PASS"
FAIL_MARKER = "QPERIAPT_ANDROID_DEVICE_FAIL"
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ANDROID_PROOF_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_EVIDENCE_FILE_BYTES = 512 * 1024 * 1024
MAX_APKSIGNER_OUTPUT_BYTES = 1024 * 1024
MAX_ADB_SERVER_STATUS_BYTES = 64 * 1024
MAX_ADB_LISTENER_OUTPUT_BYTES = 64 * 1024
MAX_ANDROID_SDK = 999
ANDROID_RELEASE_SDK = 35
ANDROID_RELEASE_BUILD_TOOLS = "36.0.0"
BUNDLE_SCHEMA_VERSION = 2
BUNDLE_KIND = "qperiapt.android_runtime_evidence_bundle"
BUNDLE_ROOT_NAME = "qperiapt-android-runtime-evidence-v2"
ANDROID_RUNS_ROOT_LEAF = "qperiapt-android-device-smoke-runs"
ANDROID_PROOF_LEAF = "qperiapt-android-device-proof.json"
PRIVATE_ADB_STATUS_REGISTERED_LEAF = "adb-server-status-registered.txt"
PRIVATE_ADB_LISTENER_REGISTERED_LEAF = "adb-listener-registered.txt"
NATIVE_NOTIFIER_MODE = NATIVE_ADB_NOTIFIER_MODE

BASE_PROOF_PATH_KEYS = (
    "aar",
    "aar_manifest",
    "smoke_apk",
    "apksigner_verify",
    "zipalign_verify",
    "result_txt",
    "result_json",
    "logcat",
)
EMULATOR_CONTROL_PATH_KEYS = (
    "adb_isolation_emulator_pre_exec",
    "adb_isolation_emulator_post_registration",
    "adb_isolation_runtime_pre_cleanup",
    "adb_isolation_runtime_post_cleanup",
    "emulator_routing",
)
PROOF_PATH_KEYS = BASE_PROOF_PATH_KEYS + EMULATOR_CONTROL_PATH_KEYS
BASE_BUNDLE_FILE_PATHS = {
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
EMULATOR_BUNDLE_FILE_PATHS = {
    "adb_isolation_emulator_pre_exec": (
        "evidence/adb-isolation-emulator-pre-exec.json"
    ),
    "adb_isolation_emulator_post_registration": (
        "evidence/adb-isolation-emulator-post-registration.json"
    ),
    "adb_isolation_runtime_pre_cleanup": (
        "evidence/adb-isolation-runtime-pre-cleanup.json"
    ),
    "adb_isolation_runtime_post_cleanup": (
        "evidence/adb-isolation-runtime-post-cleanup.json"
    ),
    "emulator_routing": "evidence/emulator-routing.json",
}
BUNDLE_FILE_PATHS = {**BASE_BUNDLE_FILE_PATHS, **EMULATOR_BUNDLE_FILE_PATHS}
BUNDLE_MANIFEST_PATH = "MANIFEST.json"

# Immutable platform-r2 history.  Every schema-v1/schema-3 shape below is an
# explicit literal so future current-schema evolution cannot silently alter the
# verifier for already-published bytes.
PUBLISHED_BUNDLE_SCHEMA_VERSION = 1
PUBLISHED_BUNDLE_ROOT_NAME = "qperiapt-android-runtime-evidence-v1"
PUBLISHED_BUNDLE_MANIFEST_PATH = "MANIFEST.json"
PUBLISHED_BUNDLE_KIND = "qperiapt.android_runtime_evidence_bundle"
PUBLISHED_BUNDLE_FILE_PATHS = {
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
PUBLISHED_BUNDLE_ARCHIVE_ENTRIES = {
    "qperiapt-android-runtime-evidence-v1": "directory",
    "qperiapt-android-runtime-evidence-v1/artifacts": "directory",
    "qperiapt-android-runtime-evidence-v1/evidence": "directory",
    "qperiapt-android-runtime-evidence-v1/MANIFEST.json": "file",
    "qperiapt-android-runtime-evidence-v1/qperiapt-android-device-proof.json": "file",
    "qperiapt-android-runtime-evidence-v1/artifacts/q-periapt-android-0.1.0-alpha.2.aar": "file",
    "qperiapt-android-runtime-evidence-v1/artifacts/q-periapt-android-0.1.0-alpha.2.MANIFEST.json": "file",
    "qperiapt-android-runtime-evidence-v1/artifacts/qperiapt-android-smoke.apk": "file",
    "qperiapt-android-runtime-evidence-v1/evidence/apksigner-verify.txt": "file",
    "qperiapt-android-runtime-evidence-v1/evidence/zipalign-verify.txt": "file",
    "qperiapt-android-runtime-evidence-v1/evidence/qperiapt-android-device-result.txt": "file",
    "qperiapt-android-runtime-evidence-v1/evidence/qperiapt-android-device-result.json": "file",
    "qperiapt-android-runtime-evidence-v1/evidence/logcat.txt": "file",
}
PUBLISHED_BUNDLE_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "source_date_epoch",
        "git_commit",
        "run_id",
        "release_candidate_mode",
        "device",
        "raw_serial_recorded",
        "files",
    }
)
PUBLISHED_BUNDLE_FILE_RECORD_FIELDS = frozenset({"bytes", "path", "sha256"})
PUBLISHED_PROOF_FIELDS = frozenset(
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
PUBLISHED_PROOF_RESULT_FIELDS = frozenset(
    {"marker_sha256", "json_sha256", "status", "test_count", "passed_tests"}
)
PUBLISHED_PROOF_ARTIFACT_FIELDS = frozenset(
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
PUBLISHED_EXPECTED_TESTS = (
    "runtimeMetadataMatches",
    "signedPolicyDecisionIsExactAndFailClosed",
    "osRandomPolicyRoundtripAndWipes",
)
PUBLISHED_PROOF_ARTIFACT_LINKS = (
    ("aar_sha256", "aar"),
    ("aar_manifest_sha256", "aar_manifest"),
    ("smoke_apk_sha256", "smoke_apk"),
    ("apksigner_verify_sha256", "apksigner_verify"),
    ("zipalign_verify_sha256", "zipalign_verify"),
    ("logcat_sha256", "logcat"),
)
PUBLISHED_BUNDLE_DEVICE = {
    "kind": "emulator",
    "abi": "arm64-v8a",
    "page_size": 16_384,
    "sdk": 35,
}
PUBLISHED_PROOF_DEVICE = {
    "kind": "emulator",
    "serial_sha256_prefix": "04ab3fc382bf",
    "raw_serial_recorded": False,
    "manufacturer": "Google",
    "model": "sdk_gphone16k_arm64",
    "abi": "arm64-v8a",
    "page_size": 16_384,
    "sdk": 35,
    "release": "15",
    "fingerprint_sha256_prefix": "d4cb1bb60eae",
}
PUBLISHED_PROOF_PATHS = {
    "aar": "target/abi2-platform-release-29555221955/candidate/q-periapt-android-0.1.0-alpha.2.aar",
    "aar_manifest": "target/abi2-platform-release-29555221955/candidate/q-periapt-android-0.1.0-alpha.2-MANIFEST.json",
    "smoke_apk": "target/abi2-platform-release-29555221955/android-runtime/proof/qperiapt-android-smoke.apk",
    "apksigner_verify": "target/abi2-platform-release-29555221955/android-runtime/proof/apksigner-verify.txt",
    "zipalign_verify": "target/abi2-platform-release-29555221955/android-runtime/proof/zipalign-verify.txt",
    "result_txt": "target/abi2-platform-release-29555221955/android-runtime/proof/qperiapt-android-device-result.txt",
    "result_json": "target/abi2-platform-release-29555221955/android-runtime/proof/qperiapt-android-device-result.json",
    "logcat": "target/abi2-platform-release-29555221955/android-runtime/proof/logcat.txt",
}
PUBLISHED_ANDROID_RUNTIME_RUN_ID = "ba666ecf3aa279cb83a4218f4951a3e6"
PUBLISHED_ANDROID_RUNTIME_SOURCE_DATE_EPOCH = 1_784_262_215

EXPECTED_TESTS = [
    "runtimeMetadataMatches",
    "signedPolicyDecisionIsExactAndFailClosed",
    "osRandomPolicyRoundtripAndWipes",
]

SOURCE_INPUTS = {
    "bounded_process": "artifact/bounded_process.py",
    "process_identity": "artifact/process_identity.py",
    "android_emulator_control": "artifact/android_emulator_control.py",
    "android_runtime_state": "artifact/android_runtime_state.py",
    "android_runtime_state_tests": "artifact/test_android_runtime_state.py",
    "android_bounded_command": "artifact/android_bounded_command.py",
    "android_bounded_command_tests": "artifact/test_android_bounded_command.py",
    "android_device_smoke_script": "artifact/android-device-smoke.sh",
    "android_device_proof": "artifact/android_device_proof.py",
    "proof_to_byte": "artifact/proof-to-byte.sh",
    "android_aar_script": "artifact/android-aar.sh",
    "android_elf_verifier": "artifact/android_elf.py",
    "release_binary_scan": "artifact/release_binary_scan.py",
    "third_party_license_collector": "artifact/third_party_licenses.py",
    "deterministic_archive": "artifact/deterministic_archive.py",
    "platform_release_contract": "artifact/platform_release_contract.py",
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
        "emulator_control",
        "android",
        "abi",
        "result",
        "artifacts",
        "source_hashes",
    }
)
EMULATOR_CONTROL_FIELDS = frozenset(
    {
        "backend",
        "external_adb",
        "ports",
        "process_identity_sha256",
        "listener_process_identity_sha256",
        "listener_endpoints",
        "listener_snapshot_sha256",
        "native_notifier",
        "registration",
        "private_adb",
    }
)
EMULATOR_BACKEND_FIELDS = frozenset({"identity", "sha256"})
EMULATOR_PORT_FIELDS = frozenset({"console", "adb"})
EMULATOR_REGISTRATION_FIELDS = frozenset({"accepted_response", "response_sha256"})
PRIVATE_ADB_CONTROL_FIELDS = EMULATOR_ROUTING_PRIVATE_ADB_FIELDS
EXTERNAL_ADB_CONTROL_FIELDS = frozenset(
    {
        "transport_binding_sha256",
        "routing_environment_sha256",
        "routing_receipt_sha256",
        "snapshot_sha256",
    }
)
NATIVE_NOTIFIER_CONTROL_FIELDS = frozenset(
    {
        "admission_checkpoints",
        "continuous_absence_claimed",
        "mode",
        "port",
    }
)
NATIVE_NOTIFIER_CHECKPOINT_FIELDS = frozenset({"name", "receipt_sha256"})
ADB_ISOLATION_CHECKPOINTS = tuple(AdbIsolationCheckpoint)
ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT = {
    AdbIsolationCheckpoint.EMULATOR_PRE_EXEC: "adb_isolation_emulator_pre_exec",
    AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION: (
        "adb_isolation_emulator_post_registration"
    ),
    AdbIsolationCheckpoint.RUNTIME_PRE_CLEANUP: "adb_isolation_runtime_pre_cleanup",
    AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP: (
        "adb_isolation_runtime_post_cleanup"
    ),
}
EMULATOR_REGISTRATION_RESPONSES = frozenset({"connected", "already_registered"})
EMULATOR_BACKEND_IDENTITY_BY_ABI = {
    "arm64-v8a": "qemu-system-aarch64-headless",
    "x86_64": "qemu-system-x86_64-headless",
}
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
APKSIGNER_CERT_SHA256_LINE = re.compile(
    r"^Signer #([1-9][0-9]*) certificate SHA-256 digest: ([0-9a-f]{64})$"
)


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


def parse_single_signer_sha256(text: str) -> str:
    """Extract one exact APK signer certificate digest from apksigner output."""

    digests: list[tuple[int, str]] = []
    for line in text.splitlines():
        match = APKSIGNER_CERT_SHA256_LINE.fullmatch(line)
        if match is not None:
            digests.append((int(match.group(1)), match.group(2)))
    require(
        len(digests) == 1 and digests[0][0] == 1,
        "apksigner output must contain exactly one signer #1 SHA-256 certificate digest",
    )
    return digests[0][1]


def signer_sha256(args: argparse.Namespace) -> None:
    try:
        snapshot = read_regular_snapshot(
            args.apksigner_output,
            maximum=MAX_APKSIGNER_OUTPUT_BYTES,
            label="apksigner certificate output",
        )
        text = snapshot.data.decode("utf-8")
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise SystemExit(
            f"error: cannot read apksigner certificate output: {exc}"
        ) from exc
    print(parse_single_signer_sha256(text))


def _reject_macos_allow_acl(file_descriptor: int, label: str) -> None:
    if sys.platform == "linux":
        return
    if sys.platform != "darwin":
        raise SystemExit(
            f"error: adb identity ACL semantics are unsupported on {sys.platform}: {label}"
        )

    import ctypes
    import errno

    acl_type_extended = 0x00000100
    acl_first_entry = 0
    acl_next_entry = -1
    acl_extended_allow = 1
    acl_extended_deny = 2
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_uint]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry = libc.acl_get_entry
    acl_get_entry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    acl_get_entry.restype = ctypes.c_int
    acl_get_tag_type = libc.acl_get_tag_type
    acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    acl_get_tag_type.restype = ctypes.c_int
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = acl_get_fd_np(file_descriptor, acl_type_extended)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return
        detail = (
            os.strerror(error_number) if error_number else "unknown ACL query error"
        )
        raise SystemExit(f"error: cannot inspect macOS ACL for {label}: {detail}")

    allow_entry = False
    acl_error: str | None = None
    selector = acl_first_entry
    while acl_error is None:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = acl_get_entry(acl, selector, ctypes.byref(entry))
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EINVAL and selector == acl_next_entry:
                break
            detail = (
                os.strerror(error_number) if error_number else "unknown ACL entry error"
            )
            acl_error = f"cannot enumerate macOS ACL for {label}: {detail}"
            break
        tag_type = ctypes.c_int()
        ctypes.set_errno(0)
        if acl_get_tag_type(entry, ctypes.byref(tag_type)) != 0:
            error_number = ctypes.get_errno()
            detail = (
                os.strerror(error_number) if error_number else "unknown ACL tag error"
            )
            acl_error = f"cannot inspect macOS ACL tag for {label}: {detail}"
            break
        if tag_type.value == acl_extended_allow:
            allow_entry = True
        elif tag_type.value != acl_extended_deny:
            acl_error = f"macOS ACL for {label} contains an unsupported tag"
            break
        selector = acl_next_entry

    ctypes.set_errno(0)
    if acl_free(acl) != 0:
        error_number = ctypes.get_errno()
        detail = os.strerror(error_number) if error_number else "unknown ACL free error"
        acl_error = acl_error or f"cannot release macOS ACL for {label}: {detail}"
    if acl_error is not None:
        raise SystemExit(f"error: {acl_error}")
    if allow_entry:
        raise SystemExit(f"error: macOS allow ACL is forbidden for {label}")


def _open_verified_adb_identity_entry(
    path: str | pathlib.Path,
    *,
    display_path: pathlib.Path,
    label: str,
    directory: bool,
    forbidden_mode: int,
    parent_descriptor: int | None = None,
) -> int:
    import errno

    required_flags = ("O_CLOEXEC", "O_NOFOLLOW")
    if directory:
        required_flags += ("O_DIRECTORY",)
    if any(not hasattr(os, flag) for flag in required_flags):
        raise SystemExit("error: host lacks descriptor-relative adb identity checks")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    else:
        flags |= os.O_NONBLOCK
    try:
        if parent_descriptor is None:
            descriptor = os.open(path, flags)
        else:
            descriptor = os.open(path, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            kind = "non-symlink directory" if directory else "regular non-symlink file"
            raise SystemExit(
                f"error: {label} must be a {kind}: {display_path}"
            ) from exc
        raise SystemExit(
            f"error: existing {label} is required before device proof: {exc}"
        ) from exc

    try:
        metadata = os.fstat(descriptor)
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected_type(metadata.st_mode):
            kind = "non-symlink directory" if directory else "regular non-symlink file"
            raise SystemExit(f"error: {label} must be a {kind}: {display_path}")
        if metadata.st_uid != os.geteuid():
            raise SystemExit(
                f"error: {label} must be owned by the current user: {display_path}"
            )
        if not directory and metadata.st_size == 0:
            raise SystemExit(f"error: {label} must not be empty: {display_path}")
        if stat.S_IMODE(metadata.st_mode) & forbidden_mode:
            access = (
                "accessible by group or other users"
                if label == "adb private key"
                else "writable by group or other users"
            )
            raise SystemExit(f"error: {label} must not be {access}: {display_path}")
        _reject_macos_allow_acl(descriptor, str(display_path))
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _validate_adb_key_entries(
    directory_descriptor: int, directory: pathlib.Path
) -> None:
    for leaf, label, forbidden_mode in (
        ("adbkey", "adb private key", 0o077),
        ("adbkey.pub", "adb public key", 0o022),
    ):
        descriptor = _open_verified_adb_identity_entry(
            leaf,
            display_path=directory / leaf,
            label=label,
            directory=False,
            forbidden_mode=forbidden_mode,
            parent_descriptor=directory_descriptor,
        )
        os.close(descriptor)


def validate_adb_identity_directory(directory: pathlib.Path) -> None:
    """Require adb keys beneath an owner-controlled directory."""

    descriptor = _open_verified_adb_identity_entry(
        directory,
        display_path=directory,
        label="adb identity directory",
        directory=True,
        forbidden_mode=0o022,
    )
    try:
        _validate_adb_key_entries(descriptor, directory)
    finally:
        os.close(descriptor)


def validate_account_adb_identity(
    home_directory: pathlib.Path, *, account_home: pathlib.Path
) -> None:
    if not home_directory.is_absolute() or home_directory != account_home:
        raise SystemExit(
            "error: HOME must match the current account home directory for device proof: "
            f"{home_directory}"
        )
    home_descriptor = _open_verified_adb_identity_entry(
        home_directory,
        display_path=home_directory,
        label="current account home",
        directory=True,
        forbidden_mode=0o022,
    )
    identity_directory = home_directory / ".android"
    try:
        identity_descriptor = _open_verified_adb_identity_entry(
            ".android",
            display_path=identity_directory,
            label="adb identity directory",
            directory=True,
            forbidden_mode=0o022,
            parent_descriptor=home_descriptor,
        )
        try:
            _validate_adb_key_entries(identity_descriptor, identity_directory)
        finally:
            os.close(identity_descriptor)
    finally:
        os.close(home_descriptor)


def verify_adb_identity(args: argparse.Namespace) -> None:
    account_home = current_account_home()
    validate_account_adb_identity(args.home_directory, account_home=account_home)
    print("ANDROID_ADB_IDENTITY_VERIFY_PASS")


def current_account_home() -> pathlib.Path:
    try:
        import pwd

        return pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (ImportError, KeyError, OSError) as exc:
        raise SystemExit(
            f"error: cannot resolve the current account home directory: {exc}"
        ) from exc


def parse_adb_server_status(text: str) -> dict[str, object]:
    """Parse server-status at the proof CLI error boundary."""

    try:
        return dict(parse_owned_adb_server_status(text))
    except AndroidEmulatorControlError as exc:
        raise SystemExit(f"error: {exc}") from exc


def verify_adb_server_status(args: argparse.Namespace) -> None:
    try:
        snapshot = read_regular_snapshot(
            args.status,
            maximum=MAX_ADB_SERVER_STATUS_BYTES,
            label="adb server-status output",
        )
        fields = parse_adb_server_status(snapshot.data.decode("utf-8"))
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot read adb server-status output: {exc}") from exc

    validate_adb_server_status_fields(
        fields,
        selected_adb=args.adb,
        home_directory=args.home_directory,
        account_home=current_account_home(),
    )
    print("ANDROID_ADB_SERVER_STATUS_VERIFY_PASS")


def validate_adb_server_status_fields(
    fields: dict[str, object],
    *,
    selected_adb: pathlib.Path,
    home_directory: pathlib.Path,
    account_home: pathlib.Path,
) -> None:
    if home_directory != account_home:
        raise SystemExit(
            "error: HOME must match the current account home directory for adb server verification"
        )
    executable = fields["executable_absolute_path"]
    keystore = fields["keystore_path"]
    mdns_enabled = fields["mdns_enabled"]
    if not isinstance(executable, str) or not isinstance(keystore, str):
        raise SystemExit("error: adb server-status path fields must be strings")
    if mdns_enabled is not False:
        raise SystemExit("error: active adb server did not disable mDNS discovery")
    try:
        expected_executable = selected_adb.resolve(strict=True)
        actual_executable = pathlib.Path(executable).resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"error: cannot resolve adb server executable: {exc}") from exc
    if actual_executable != expected_executable:
        raise SystemExit(
            "error: active adb server executable differs from the selected adb: "
            f"{actual_executable}"
        )
    expected_keystore = account_home / ".android" / "adbkey"
    if pathlib.Path(keystore) != expected_keystore:
        raise SystemExit(
            "error: active adb server keystore differs from the verified identity: "
            f"{keystore}"
        )


def assert_default_adb_server_absent(_: argparse.Namespace) -> None:
    try:
        probe_adb_loopback_absence()
    except AndroidEmulatorControlError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(
        "ANDROID_ADB_LOOPBACK_ABSENCE_PASS "
        f"ports={DEFAULT_ADB_SERVER_PORT},{NATIVE_ADB_NOTIFIER_PORT}"
    )


def parse_lsof_adb_listener(text: str, *, expected_endpoint: str) -> tuple[int, int]:
    lines = text.splitlines()
    pid_lines = [line[1:] for line in lines if line.startswith("p")]
    uid_lines = [line[1:] for line in lines if line.startswith("u")]
    if len(pid_lines) != 1 or len(uid_lines) != 1:
        raise SystemExit("error: adb listener lacks one exact pid/uid identity")
    try:
        pid = int(pid_lines[0])
        uid = int(uid_lines[0])
        parse_owned_single_listener(
            text,
            expected_pid=pid,
            expected_uid=uid,
            expected_endpoint=expected_endpoint,
        )
    except (ValueError, AndroidEmulatorControlError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    return pid, uid


def parse_lsof_owned_emulator_listeners(
    text: str,
    *,
    expected_pid: int,
    console_port: int,
    adb_port: int,
) -> int:
    try:
        return parse_owned_lsof_listeners(
            text,
            expected_pid=expected_pid,
            expected_uid=os.geteuid(),
            console_port=console_port,
            adb_port=adb_port,
        )
    except AndroidEmulatorControlError as exc:
        raise SystemExit(f"error: {exc}") from exc


def verify_owned_emulator_listeners(args: argparse.Namespace) -> None:
    try:
        snapshot = read_regular_snapshot(
            args.lsof_output,
            maximum=MAX_ADB_LISTENER_OUTPUT_BYTES,
            label="owned emulator listener inspection",
        )
        text = snapshot.data.decode("utf-8")
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise SystemExit(
            f"error: cannot read owned emulator listener inspection: {exc}"
        ) from exc
    parse_lsof_owned_emulator_listeners(
        text,
        expected_pid=args.expected_pid,
        console_port=args.console_port,
        adb_port=args.adb_port,
    )
    print("ANDROID_OWNED_EMULATOR_LISTENERS_PASS")


def _owned_process_snapshot(pid: int) -> tuple[pathlib.Path, str]:
    require(type(pid) is int and pid > 1, "owned process pid is invalid")
    try:
        identity = process_snapshot(pid)
    except ProcessIdentityError as exc:
        raise SystemExit(f"error: cannot inspect owned process {pid}: {exc}") from exc
    require(
        identity.uid == os.geteuid(),
        "owned process uid differs from the current account",
    )
    return identity.executable, identity.token


def _expected_owned_executable(path: pathlib.Path, label: str) -> pathlib.Path:
    require(not path.is_symlink(), f"{label} must not be a symlink")
    return require_executable_file(path, label)


def verify_owned_process(args: argparse.Namespace) -> None:
    executable, identity = _owned_process_snapshot(args.expected_pid)
    expected_executable = _expected_owned_executable(
        args.expected_executable, "expected owned executable"
    )
    require(executable == expected_executable, "owned process executable differs")
    executable_metadata = expected_executable.lstat()
    require(
        executable_metadata.st_dev == args.expected_executable_device
        and executable_metadata.st_ino == args.expected_executable_inode,
        "owned process executable file identity changed",
    )
    if args.expected_identity is not None:
        require(identity == args.expected_identity, "owned process identity changed")
    print(identity)


def emulator_backend_path(
    launcher_path: pathlib.Path,
    device_abi: str,
) -> pathlib.Path:
    """Derive the one headless QEMU backend selected by the fixed launcher."""

    try:
        return fixed_headless_backend_path(
            launcher_path,
            device_abi,
            host_platform=sys.platform,
            host_machine=platform.machine(),
        )
    except AndroidEmulatorControlError as exc:
        raise SystemExit(f"error: {exc}") from exc


def resolve_emulator_backend(args: argparse.Namespace) -> None:
    print(emulator_backend_path(args.emulator, args.device_abi))


def wait_owned_process_exec(args: argparse.Namespace) -> None:
    initial = _expected_owned_executable(
        args.initial_executable, "owned emulator initial executable"
    )
    launcher = _expected_owned_executable(args.launcher, "Android emulator launcher")
    backend = emulator_backend_path(args.launcher, args.device_abi)
    stages = (initial, launcher, backend)
    require(
        len(set(stages)) == len(stages),
        "owned emulator initial executable, launcher, and backend must differ",
    )
    require(
        type(args.timeout_seconds) is int and 1 <= args.timeout_seconds <= 30,
        "owned process exec timeout is invalid",
    )
    deadline = time.monotonic() + args.timeout_seconds
    expected_identity: str | None = None
    observed_stage = -1
    while True:
        now = time.monotonic()
        require(
            now < deadline,
            "Android emulator launcher did not become its fixed headless backend",
        )
        executable, identity = _owned_process_snapshot(args.expected_pid)
        if expected_identity is None:
            expected_identity = identity
        require(
            identity == expected_identity, "owned process identity changed during exec"
        )
        try:
            current_stage = stages.index(executable)
        except ValueError as exc:
            raise SystemExit(
                "error: owned process executable differs during launcher transition"
            ) from exc
        require(
            current_stage >= observed_stage,
            "owned process executable regressed during launcher transition",
        )
        observed_stage = current_stage
        if current_stage == len(stages) - 1:
            require(
                time.monotonic() <= deadline,
                "Android emulator launcher did not become its fixed headless backend",
            )
            print(identity)
            return
        remaining = deadline - time.monotonic()
        require(
            remaining > 0,
            "Android emulator launcher did not become its fixed headless backend",
        )
        time.sleep(min(0.05, remaining))


def verify_adb_listener(args: argparse.Namespace) -> None:
    try:
        snapshot = read_regular_snapshot(
            args.lsof_output,
            maximum=MAX_ADB_LISTENER_OUTPUT_BYTES,
            label="adb listener inspection",
        )
        pid, reported_uid = parse_lsof_adb_listener(
            snapshot.data.decode("utf-8"), expected_endpoint=args.expected_endpoint
        )
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot read adb listener inspection: {exc}") from exc
    try:
        execution: ProcessExecutionSnapshot = process_execution_snapshot(pid)
    except ProcessIdentityError as exc:
        raise SystemExit(
            f"error: cannot inspect adb listener process {pid}: {exc}"
        ) from exc
    identity_fields = execution.identity
    if args.expected_pid is not None and pid != args.expected_pid:
        raise SystemExit(
            f"error: adb listener pid differs from the owned server: {pid}"
        )
    expected_environment: dict[str, str] = {}
    forbidden_environment = [
        "ANDROID_ADB_SERVER_ADDRESS",
        "ANDROID_ADB_SERVER_PORT",
        "ADB_MDNS_OPENSCREEN",
        "ADB_REJECT_KILL_SERVER",
        "ADB_OSX_USB_CLEAR_ENDPOINTS",
        "ANDROID_ADB_LOG_PATH",
        "ADB_TRACE",
        "ADB_INSTALL_DEFAULT_INCREMENTAL",
        "ADB_LIBUSB",
        "ADB_LIBUSB_START_DETACHED",
    ]
    private_arguments = (
        args.expected_server_socket,
        args.expected_vendor_keys,
        args.expected_mdns,
        args.expected_transport_kind,
    )
    if all(value is None for value in private_arguments):
        forbidden_environment.extend(
            (
                "ADB_VENDOR_KEYS",
                "ADB_SERVER_SOCKET",
                "ADB_MDNS",
                "ADB_MDNS_AUTO_CONNECT",
                "ADB_USB",
                "ADB_EMU",
                "ADB_LOCAL_TRANSPORT_MAX_PORT",
            )
        )
    elif any(value is None for value in private_arguments):
        raise SystemExit(
            "error: expected adb socket, vendor keys, mDNS mode, and transport kind must be supplied together"
        )
    else:
        if args.expected_pid is None:
            raise SystemExit(
                "error: private adb listener verification requires its owned pid"
            )
        expected_socket = f"localfilesystem:{args.expected_endpoint}"
        if args.expected_server_socket != expected_socket:
            raise SystemExit(
                "error: expected adb server socket does not name the inspected endpoint"
            )
        expected_environment = {
            "ADB_SERVER_SOCKET": args.expected_server_socket,
            "ADB_VENDOR_KEYS": args.expected_vendor_keys,
            "ADB_MDNS": args.expected_mdns,
            "ADB_MDNS_AUTO_CONNECT": args.expected_mdns,
            "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        }
        if args.expected_transport_kind == "physical":
            expected_environment["ADB_USB"] = "1"
            expected_environment["ADB_EMU"] = "0"
        elif args.expected_transport_kind == "emulator":
            expected_environment["ADB_USB"] = "0"
            expected_environment["ADB_EMU"] = "0"
        else:
            raise SystemExit("error: invalid private adb transport kind")
    identity = validate_adb_listener_identity(
        pid=pid,
        reported_uid=reported_uid,
        process_uid=identity_fields.uid,
        started_at=identity_fields.started_at,
        started_subsecond=identity_fields.started_subsecond,
        executable=identity_fields.executable,
        environment=dict(execution.environment),
        selected_adb=args.adb,
        account_home=current_account_home(),
        expected_identity=args.expected_identity,
        expected_environment=expected_environment,
        forbidden_environment=tuple(forbidden_environment),
    )
    print(identity)


def publish_staged_proof(args: argparse.Namespace) -> None:
    staging = args.staging
    destination = args.destination
    try:
        metadata = staging.lstat()
    except OSError as exc:
        raise SystemExit(f"error: cannot inspect staged Android proof: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(
            f"error: staged Android proof is not a regular file: {staging}"
        )
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit(
            f"error: staged Android proof ownership or mode changed: {staging}"
        )
    if metadata.st_nlink != 1:
        raise SystemExit(
            f"error: staged Android proof has unexpected hard links: {staging}"
        )
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SystemExit(
            f"error: cannot inspect Android proof destination: {exc}"
        ) from exc
    else:
        raise SystemExit(
            f"error: Android proof destination already exists: {destination}"
        )
    try:
        os.link(staging, destination, follow_symlinks=False)
    except OSError as exc:
        raise SystemExit(
            f"error: cannot atomically publish Android proof: {exc}"
        ) from exc
    try:
        staging.unlink()
    except OSError as exc:
        raise SystemExit(
            f"error: cannot remove staged Android proof after publication: {exc}"
        ) from exc
    print("ANDROID_DEVICE_PROOF_PUBLISH_PASS")


def verify_private_adb_socket(args: argparse.Namespace) -> None:
    directory = args.directory
    if (
        directory.parent != pathlib.Path("/tmp")
        or re.fullmatch(r"qperiapt-adb\.[A-Za-z0-9]{8}", directory.name) is None
    ):
        raise SystemExit(
            "error: private adb server directory must be one fixed-shape child of /tmp"
        )
    socket_path = directory / "adb.sock"
    if len(os.fsencode(socket_path)) >= 104:
        raise SystemExit("error: private adb server socket exceeds the Unix path limit")
    descriptor = _open_verified_adb_identity_entry(
        directory,
        display_path=directory,
        label="private adb server directory",
        directory=True,
        forbidden_mode=0o022,
    )
    try:
        metadata = os.fstat(descriptor)
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise SystemExit(
                f"error: private adb server directory must have mode 0700: {directory}"
            )
        try:
            socket_metadata = os.stat(
                "adb.sock", dir_fd=descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            if args.state != "absent":
                raise SystemExit(
                    f"error: private adb server socket is missing: {socket_path}"
                )
        except OSError as exc:
            raise SystemExit(
                f"error: cannot inspect private adb server socket: {exc}"
            ) from exc
        else:
            if args.state != "present":
                raise SystemExit(
                    f"error: private adb server socket already exists: {socket_path}"
                )
            if not stat.S_ISSOCK(socket_metadata.st_mode):
                raise SystemExit(
                    f"error: private adb server endpoint is not a socket: {socket_path}"
                )
            if socket_metadata.st_uid != os.geteuid():
                raise SystemExit(
                    f"error: private adb server socket has the wrong owner: {socket_path}"
                )
    finally:
        os.close(descriptor)
    print(f"ANDROID_PRIVATE_ADB_SOCKET_{args.state.upper()}_PASS")


def validate_adb_listener_identity(
    *,
    pid: int,
    reported_uid: int,
    process_uid: int,
    started_at: int,
    started_subsecond: int,
    executable: pathlib.Path,
    environment: dict[str, str],
    selected_adb: pathlib.Path,
    account_home: pathlib.Path,
    expected_identity: str | None,
    expected_environment: dict[str, str] | None = None,
    forbidden_environment: tuple[str, ...] = (
        "ADB_VENDOR_KEYS",
        "ADB_SERVER_SOCKET",
        "ANDROID_ADB_SERVER_ADDRESS",
        "ANDROID_ADB_SERVER_PORT",
    ),
) -> str:
    if process_uid != reported_uid or process_uid != os.geteuid():
        raise SystemExit(
            "error: adb listener uid is not the current user: "
            f"lsof={reported_uid}, process={process_uid}"
        )
    try:
        expected_executable = selected_adb.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(
            f"error: cannot resolve selected adb executable: {exc}"
        ) from exc
    if executable != expected_executable:
        raise SystemExit(
            f"error: adb listener executable differs from selected adb: {executable}"
        )
    present = [name for name in forbidden_environment if name in environment]
    if present:
        raise SystemExit(
            "error: adb listener inherited forbidden routing or identity variables: "
            + ", ".join(present)
        )
    for name, expected_value in (expected_environment or {}).items():
        if environment.get(name) != expected_value:
            raise SystemExit(
                f"error: adb listener environment differs for required variable {name}"
            )
    if environment.get("HOME") != str(account_home):
        raise SystemExit(
            "error: adb listener HOME differs from the current account home"
        )
    identity = f"{pid}:{process_uid}:{started_at}:{started_subsecond}"
    if expected_identity is not None and expected_identity != identity:
        raise SystemExit(
            "error: adb listener process identity changed during device proof: "
            f"expected {expected_identity}, got {identity}"
        )
    return identity


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_sha256(value: object, label: str) -> str:
    require(
        isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
        f"{label} lacks a valid SHA-256",
    )
    return value


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
    exact_object(proof.get("device"), PROOF_DEVICE_FIELDS, "Android proof device")
    exact_object(
        proof.get("paths"), expected_proof_path_keys(proof), "Android proof path"
    )
    verify_emulator_control(proof)
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


def emulator_registration_response_bytes(
    accepted_response: str,
    *,
    console_port: int,
    adb_port: int,
) -> bytes:
    """Return the one accepted ADB registration response for a port pair."""

    require(
        isinstance(accepted_response, str)
        and accepted_response in EMULATOR_REGISTRATION_RESPONSES,
        "Android emulator registration response is unsupported",
    )
    require(
        type(console_port) is int
        and 5554 <= console_port <= 5584
        and console_port % 2 == 0
        and type(adb_port) is int
        and adb_port == console_port + 1,
        "Android emulator registration ports are invalid",
    )
    if accepted_response == "connected":
        text = f"Connected to emulator on ports {console_port},{adb_port}\n"
    else:
        text = f"Emulator already registered on port {adb_port}\n"
    return text.encode("ascii")


def classify_emulator_registration_response(
    response: bytes,
    *,
    console_port: int,
    adb_port: int,
) -> str:
    """Classify one exact response without retaining its raw text in the proof."""

    require(
        isinstance(response, bytes),
        "Android emulator registration response is not bytes",
    )
    for accepted_response in sorted(EMULATOR_REGISTRATION_RESPONSES):
        if response == emulator_registration_response_bytes(
            accepted_response,
            console_port=console_port,
            adb_port=adb_port,
        ):
            return accepted_response
    raise SystemExit(
        "error: emulator registration response is not an accepted exact value"
    )


def parse_process_identity(value: str, label: str) -> tuple[int, int, int, int]:
    """Parse the canonical PID/UID/start tuple emitted by the live verifier."""

    try:
        parsed = parse_process_identity_token(value)
    except ProcessIdentityError as exc:
        raise SystemExit(f"error: {label} is invalid: {exc}") from exc
    return (
        parsed.pid,
        parsed.uid,
        parsed.started_at,
        parsed.started_subsecond,
    )


def process_identity_sha256(value: str, label: str) -> str:
    """Hash the canonical PID/UID/start tuple for raw-value-omitting correlation."""

    parse_process_identity(value, label)
    return sha256_bytes(value.encode("ascii"))


def private_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError(
            "Android private evidence must be one current-user-owned mode-0600 regular file"
        )


def _load_private_json_receipt(
    path: pathlib.Path,
    *,
    label: str,
    maximum: int = 64 * 1024,
    bundled: bool = False,
) -> tuple[dict[str, Any], str]:
    def bundled_metadata(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o644
        ):
            raise EvidenceIOError(
                "bundled Android evidence must be one mode-0644 regular file"
            )

    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=maximum,
            label=label,
            validate_metadata=bundled_metadata if bundled else private_file_metadata,
        )
        value = parse_strict_json_bytes(snapshot.data, label=label)
    except EvidenceIOError as exc:
        raise SystemExit(f"error: cannot read {label}: {exc}") from exc
    require(isinstance(value, dict), f"{label} must be an object")
    require(
        canonical_json_bytes(value) == snapshot.data,
        f"{label} is not canonical JSON",
    )
    return value, snapshot.sha256


def _parse_adb_isolation_receipt(
    path: pathlib.Path,
    *,
    run_id: str,
    checkpoint: AdbIsolationCheckpoint,
    bundled: bool = False,
) -> str:
    receipt, receipt_sha256 = _load_private_json_receipt(
        path,
        label=f"Android adb isolation {checkpoint.value} receipt",
        bundled=bundled,
    )
    exact_object(
        receipt,
        {"schema", "kind", "run_id", "checkpoint", "ports"},
        "Android adb isolation receipt",
    )
    require(
        type(receipt.get("schema")) is int
        and receipt["schema"] == ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
        "Android adb isolation receipt schema differs",
    )
    require(
        receipt.get("kind") == ADB_ISOLATION_RECEIPT_KIND,
        "Android adb isolation receipt kind differs",
    )
    require(receipt.get("run_id") == run_id, "Android adb isolation run id differs")
    require(
        receipt.get("checkpoint") == checkpoint.value,
        "Android adb isolation checkpoint differs",
    )
    ports = exact_object(
        receipt.get("ports"),
        {str(DEFAULT_ADB_SERVER_PORT), str(NATIVE_ADB_NOTIFIER_PORT)},
        "Android adb isolation ports",
    )
    for port in (DEFAULT_ADB_SERVER_PORT, NATIVE_ADB_NOTIFIER_PORT):
        families = exact_object(
            ports.get(str(port)),
            {"ipv4", "ipv6"},
            f"Android adb isolation port {port}",
        )
        require(
            families == {
                "ipv4": "connection_refused",
                "ipv6": "connection_refused",
            },
            f"Android adb isolation port {port} was not closed on both loopback families",
        )
    return receipt_sha256


def _parse_emulator_routing_receipt(
    path: pathlib.Path,
    *,
    run_id: str,
    expected_private_adb: dict[str, str],
    bundled: bool = False,
) -> dict[str, str]:
    receipt, receipt_sha256 = _load_private_json_receipt(
        path, label="Android emulator routing receipt", bundled=bundled
    )
    exact_object(
        receipt,
        {
            "schema",
            "kind",
            "run_id",
            "mode",
            "adb_snapshot_sha256",
            "routing_environment_sha256",
            "transport_binding_sha256",
            "private_adb",
            "native_notifier_port",
            "private_socket_kind",
            "raw_paths_recorded",
        },
        "Android emulator routing receipt",
    )
    require(
        type(receipt.get("schema")) is int
        and receipt["schema"] == EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION,
        "Android emulator routing receipt schema differs",
    )
    require(
        receipt.get("kind") == EMULATOR_ROUTING_RECEIPT_KIND
        and receipt.get("run_id") == run_id
        and receipt.get("mode") == EMULATOR_ROUTING_MODE
        and type(receipt.get("native_notifier_port")) is int
        and receipt["native_notifier_port"] == NATIVE_ADB_NOTIFIER_PORT
        and receipt.get("private_socket_kind") == "localfilesystem"
        and receipt.get("raw_paths_recorded") is False,
        "Android emulator routing receipt contract differs",
    )
    environment_sha256 = require_sha256(
        receipt.get("routing_environment_sha256"),
        "Android emulator routing environment projection",
    )
    adb_snapshot_sha256 = require_sha256(
        receipt.get("adb_snapshot_sha256"), "run-owned external adb snapshot"
    )
    receipt_private_adb = exact_object(
        receipt.get("private_adb"),
        PRIVATE_ADB_CONTROL_FIELDS,
        "Android emulator routing private adb evidence",
    )
    require(
        receipt_private_adb == expected_private_adb,
        "Android emulator routing private adb evidence differs",
    )
    transport_commitment = require_sha256(
        receipt.get("transport_binding_sha256"),
        "external adb private transport commitment",
    )
    require(
        transport_commitment
        == emulator_routing_transport_binding_sha256(
            adb_snapshot_sha256,
            environment_sha256,
            expected_private_adb,
        ),
        "external adb private transport binding differs",
    )
    return {
        "snapshot_sha256": adb_snapshot_sha256,
        "routing_environment_sha256": environment_sha256,
        "routing_receipt_sha256": receipt_sha256,
        "transport_binding_sha256": transport_commitment,
    }


def _registered_private_adb_paths(
    routing_receipt_path: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    require(
        routing_receipt_path.name == EMULATOR_ROUTING_RECEIPT_LEAF,
        "Android emulator routing receipt path differs from its fixed leaf",
    )
    proof_root = routing_receipt_path.parent
    return (
        proof_root / PRIVATE_ADB_STATUS_REGISTERED_LEAF,
        proof_root / PRIVATE_ADB_LISTENER_REGISTERED_LEAF,
    )


def _read_registered_private_adb_evidence(
    *,
    routing_receipt_path: pathlib.Path,
    run_id: str,
    private_adb_identity: str | None,
    private_adb_status_path: pathlib.Path | None = None,
    private_adb_listener_path: pathlib.Path | None = None,
) -> dict[str, str]:
    expected_status_path, expected_listener_path = _registered_private_adb_paths(
        routing_receipt_path
    )
    if private_adb_status_path is not None:
        require(
            private_adb_status_path == expected_status_path,
            "registered private adb status path differs from its fixed run leaf",
        )
    if private_adb_listener_path is not None:
        require(
            private_adb_listener_path == expected_listener_path,
            "registered private adb listener path differs from its fixed run leaf",
        )
    try:
        status_snapshot = read_regular_snapshot(
            expected_status_path,
            maximum=MAX_ADB_SERVER_STATUS_BYTES,
            label="registered private adb server status",
            validate_metadata=private_file_metadata,
        )
        listener_snapshot = read_regular_snapshot(
            expected_listener_path,
            maximum=MAX_ADB_LISTENER_OUTPUT_BYTES,
            label="registered private adb listener snapshot",
            validate_metadata=private_file_metadata,
        )
        status_fields = parse_adb_server_status(status_snapshot.data.decode("utf-8"))
        listener_text = listener_snapshot.data.decode("utf-8")
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise SystemExit(
            f"error: cannot read registered private adb evidence: {exc}"
        ) from exc

    proof_root = routing_receipt_path.parent
    run_root = proof_root.parent
    require(
        proof_root.name == "proof"
        and run_root.name == run_id
        and run_root.parent.name == ANDROID_RUNS_ROOT_LEAF,
        "registered private adb evidence is outside its immutable run layout",
    )
    expected_adb = run_root / "work" / f"adb-{run_id}"
    expected_keystore = current_account_home() / ".android" / "adbkey"
    require(
        status_fields.get("executable_absolute_path") == str(expected_adb)
        and status_fields.get("keystore_path") == str(expected_keystore)
        and status_fields.get("mdns_enabled") is False,
        "registered private adb status differs from its fixed run binding",
    )

    listener_endpoints = [
        line[1:] for line in listener_text.splitlines() if line.startswith("n")
    ]
    require(
        len(listener_endpoints) == 1
        and re.fullmatch(
            r"/tmp/qperiapt-adb\.[A-Za-z0-9]{8}/adb\.sock",
            listener_endpoints[0],
        )
        is not None,
        "registered private adb listener endpoint is non-canonical",
    )
    pid_lines = [
        line[1:] for line in listener_text.splitlines() if line.startswith("p")
    ]
    uid_lines = [
        line[1:] for line in listener_text.splitlines() if line.startswith("u")
    ]
    require(
        len(pid_lines) == 1 and len(uid_lines) == 1,
        "registered private adb listener lacks one exact process identity",
    )
    try:
        listener_pid = int(pid_lines[0])
        listener_uid = int(uid_lines[0])
        parse_owned_single_listener(
            listener_text,
            expected_pid=listener_pid,
            expected_uid=listener_uid,
            expected_endpoint=listener_endpoints[0],
        )
    except (ValueError, AndroidEmulatorControlError) as exc:
        raise SystemExit(
            f"error: registered private adb listener is invalid: {exc}"
        ) from exc

    identity_sha256: str
    if private_adb_identity is None:
        identity_sha256 = ""
    else:
        private_pid, private_uid, _started_at, _started_subsecond = (
            parse_process_identity(
                private_adb_identity, "private adb process identity"
            )
        )
        require(
            (listener_pid, listener_uid) == (private_pid, private_uid),
            "registered private adb listener differs from its process identity",
        )
        identity_sha256 = process_identity_sha256(
            private_adb_identity, "private adb process identity"
        )
    return {
        "identity_sha256": identity_sha256,
        "server_status_sha256": status_snapshot.sha256,
        "listener_snapshot_sha256": listener_snapshot.sha256,
    }


def build_emulator_control_receipt(
    *,
    backend_path: pathlib.Path,
    backend_device: int,
    backend_inode: int,
    backend_sha256: str,
    device_abi: str,
    console_port: int,
    process_identity: str,
    listener_snapshot_path: pathlib.Path,
    registration_response_path: pathlib.Path,
    private_adb_identity: str,
    private_adb_status_path: pathlib.Path,
    private_adb_listener_path: pathlib.Path,
    routing_receipt_path: pathlib.Path,
    adb_isolation_receipt_paths: dict[AdbIsolationCheckpoint, pathlib.Path],
    run_id: str,
) -> dict[str, Any]:
    """Build a raw-value-omitting receipt from verified live control files."""

    expected_backend_identity = EMULATOR_BACKEND_IDENTITY_BY_ABI.get(device_abi)
    require(
        expected_backend_identity is not None,
        "script-owned Android emulator ABI is unsupported",
    )
    backend = _expected_owned_executable(
        backend_path, "Android emulator control receipt backend"
    )
    require(
        backend.name == expected_backend_identity,
        "Android emulator backend identity differs from its device ABI",
    )
    backend_metadata = backend.lstat()
    require(
        type(backend_device) is int
        and type(backend_inode) is int
        and backend_device >= 0
        and backend_inode > 0
        and (backend_metadata.st_dev, backend_metadata.st_ino)
        == (backend_device, backend_inode),
        "Android emulator backend file identity changed before proof creation",
    )
    require_sha256(backend_sha256, "Android emulator backend pre-exec identity")
    require(
        sha256_file(backend) == backend_sha256,
        "Android emulator backend bytes changed before proof creation",
    )
    adb_port = console_port + 1
    # The registration formatter is also the canonical port-pair validator.
    emulator_registration_response_bytes(
        "connected", console_port=console_port, adb_port=adb_port
    )
    try:
        listener_snapshot = read_regular_snapshot(
            listener_snapshot_path,
            maximum=MAX_ADB_LISTENER_OUTPUT_BYTES,
            label="owned emulator listener snapshot",
        )
        registration_snapshot = read_regular_snapshot(
            registration_response_path,
            maximum=512,
            label="accepted emulator registration response",
        )
    except EvidenceIOError as exc:
        raise SystemExit(
            f"error: cannot read Android emulator control evidence: {exc}"
        ) from exc
    accepted_response = classify_emulator_registration_response(
        registration_snapshot.data,
        console_port=console_port,
        adb_port=adb_port,
    )
    emulator_pid, emulator_uid, _started_at, _started_subsecond = (
        parse_process_identity(process_identity, "emulator process identity")
    )
    try:
        listener_text = listener_snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(
            f"error: owned emulator listener snapshot is not UTF-8: {exc}"
        ) from exc
    listener_uid = parse_lsof_owned_emulator_listeners(
        listener_text,
        expected_pid=emulator_pid,
        console_port=console_port,
        adb_port=adb_port,
    )
    require(
        listener_uid == emulator_uid,
        "owned emulator listener uid differs from its process identity",
    )
    emulator_identity_digest = process_identity_sha256(
        process_identity, "emulator process identity"
    )
    require(
        isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None,
        "Android emulator control run id is invalid",
    )
    private_adb = _read_registered_private_adb_evidence(
        routing_receipt_path=routing_receipt_path,
        run_id=run_id,
        private_adb_identity=private_adb_identity,
        private_adb_status_path=private_adb_status_path,
        private_adb_listener_path=private_adb_listener_path,
    )
    require(
        set(adb_isolation_receipt_paths) == set(ADB_ISOLATION_CHECKPOINTS),
        "Android adb isolation receipt set differs",
    )
    proof_root = routing_receipt_path.parent
    for checkpoint in ADB_ISOLATION_CHECKPOINTS:
        require(
            adb_isolation_receipt_paths[checkpoint]
            == proof_root / ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint],
            f"Android adb isolation {checkpoint.value} path differs from its fixed leaf",
        )
    admission_checkpoints = [
        {
            "name": checkpoint.value,
            "receipt_sha256": _parse_adb_isolation_receipt(
                adb_isolation_receipt_paths[checkpoint],
                run_id=run_id,
                checkpoint=checkpoint,
            ),
        }
        for checkpoint in ADB_ISOLATION_CHECKPOINTS
    ]
    external_adb = _parse_emulator_routing_receipt(
        routing_receipt_path,
        run_id=run_id,
        expected_private_adb=private_adb,
    )
    return {
        "backend": {
            "identity": backend.name,
            "sha256": backend_sha256,
        },
        "ports": {"console": console_port, "adb": adb_port},
        "process_identity_sha256": emulator_identity_digest,
        "listener_process_identity_sha256": emulator_identity_digest,
        "listener_endpoints": [
            f"127.0.0.1:{console_port}",
            f"127.0.0.1:{adb_port}",
        ],
        "listener_snapshot_sha256": listener_snapshot.sha256,
        "external_adb": external_adb,
        "native_notifier": {
            "mode": NATIVE_NOTIFIER_MODE,
            "port": NATIVE_ADB_NOTIFIER_PORT,
            "admission_checkpoints": admission_checkpoints,
            "continuous_absence_claimed": False,
        },
        "registration": {
            "accepted_response": accepted_response,
            "response_sha256": registration_snapshot.sha256,
        },
        "private_adb": private_adb,
    }


def verify_emulator_control(
    proof: dict[str, Any], *, require_release_mode: bool = False
) -> None:
    """Validate the raw-value-omitting emulator control-plane commitment."""

    device = proof.get("device")
    require(isinstance(device, dict), "proof lacks Android device metadata")
    device_kind = device.get("kind")
    control = proof.get("emulator_control")
    if device_kind == "physical":
        require(
            control is None,
            "physical Android proof must set emulator_control to null",
        )
        return
    require(device_kind == "emulator", "unsupported Android device kind")
    control = exact_object(control, EMULATOR_CONTROL_FIELDS, "Android emulator control")
    backend = exact_object(
        control.get("backend"),
        EMULATOR_BACKEND_FIELDS,
        "Android emulator backend control",
    )
    expected_backend_identity = EMULATOR_BACKEND_IDENTITY_BY_ABI.get(device.get("abi"))
    require(
        expected_backend_identity is not None,
        "script-owned Android emulator ABI is unsupported",
    )
    require(
        backend.get("identity") == expected_backend_identity,
        "Android emulator backend identity differs from its device ABI",
    )
    require_sha256(backend.get("sha256"), "Android emulator backend")

    ports = exact_object(
        control.get("ports"), EMULATOR_PORT_FIELDS, "Android emulator port control"
    )
    console_port = ports.get("console")
    adb_port = ports.get("adb")
    require(
        type(console_port) is int
        and 5554 <= console_port <= 5584
        and console_port % 2 == 0
        and type(adb_port) is int
        and adb_port == console_port + 1,
        "Android emulator control ports are invalid",
    )
    if require_release_mode:
        require(
            (console_port, adb_port) == (5584, 5585),
            "Android release proof must bind emulator ports 5584/5585",
        )
    process_identity_sha256 = control.get("process_identity_sha256")
    listener_process_identity_sha256 = control.get("listener_process_identity_sha256")
    require_sha256(
        process_identity_sha256,
        "Android emulator process identity",
    )
    require_sha256(
        listener_process_identity_sha256,
        "Android emulator listener process identity",
    )
    require(
        listener_process_identity_sha256 == process_identity_sha256,
        "Android emulator listener process identity differs from the owned backend",
    )
    require(
        control.get("listener_endpoints")
        == [f"127.0.0.1:{console_port}", f"127.0.0.1:{adb_port}"],
        "Android emulator listener endpoints differ from its fixed ports",
    )
    require_sha256(
        control.get("listener_snapshot_sha256"),
        "Android emulator listener snapshot",
    )

    registration = exact_object(
        control.get("registration"),
        EMULATOR_REGISTRATION_FIELDS,
        "Android emulator registration control",
    )
    accepted_response = registration.get("accepted_response")
    require(
        isinstance(accepted_response, str),
        "Android emulator registration response is missing",
    )
    expected_response_digest = sha256_bytes(
        emulator_registration_response_bytes(
            accepted_response,
            console_port=console_port,
            adb_port=adb_port,
        )
    )
    require(
        registration.get("response_sha256") == expected_response_digest,
        "Android emulator registration response digest differs",
    )

    private_adb = exact_object(
        control.get("private_adb"),
        PRIVATE_ADB_CONTROL_FIELDS,
        "Android private adb control",
    )
    require_sha256(
        private_adb.get("identity_sha256"),
        "registered private adb process identity",
    )
    require_sha256(
        private_adb.get("server_status_sha256"),
        "registered private adb server status",
    )
    require_sha256(
        private_adb.get("listener_snapshot_sha256"),
        "registered private adb listener snapshot",
    )
    external_adb = exact_object(
        control.get("external_adb"),
        EXTERNAL_ADB_CONTROL_FIELDS,
        "Android external adb control",
    )
    require_sha256(external_adb.get("snapshot_sha256"), "external adb snapshot")
    require_sha256(
        external_adb.get("routing_environment_sha256"),
        "external adb routing environment projection",
    )
    require_sha256(
        external_adb.get("routing_receipt_sha256"), "external adb routing receipt"
    )
    require_sha256(
        external_adb.get("transport_binding_sha256"),
        "external adb private transport commitment",
    )
    require(
        external_adb["transport_binding_sha256"]
        == emulator_routing_transport_binding_sha256(
            external_adb["snapshot_sha256"],
            external_adb["routing_environment_sha256"],
            private_adb,
        ),
        "external adb private transport binding differs",
    )
    native_notifier = exact_object(
        control.get("native_notifier"),
        NATIVE_NOTIFIER_CONTROL_FIELDS,
        "Android native adb notifier control",
    )
    require(
        native_notifier.get("mode") == NATIVE_NOTIFIER_MODE
        and type(native_notifier.get("port")) is int
        and native_notifier["port"] == NATIVE_ADB_NOTIFIER_PORT
        and native_notifier.get("continuous_absence_claimed") is False,
        "Android native adb notifier contract differs",
    )
    checkpoints = native_notifier.get("admission_checkpoints")
    require(
        isinstance(checkpoints, list)
        and len(checkpoints) == len(ADB_ISOLATION_CHECKPOINTS),
        "Android native adb notifier checkpoints differ",
    )
    for item, expected_checkpoint in zip(checkpoints, ADB_ISOLATION_CHECKPOINTS):
        item = exact_object(
            item,
            NATIVE_NOTIFIER_CHECKPOINT_FIELDS,
            "Android native adb notifier checkpoint",
        )
        require(
            item.get("name") == expected_checkpoint.value,
            "Android native adb notifier checkpoint order differs",
        )
        require_sha256(
            item.get("receipt_sha256"),
            f"Android native adb notifier {expected_checkpoint.value} receipt",
        )


def verify_emulator_control_evidence(
    proof: dict[str, Any], paths: dict[str, pathlib.Path], *, bundled: bool = False
) -> None:
    device = proof.get("device")
    require(isinstance(device, dict), "proof lacks device metadata")
    if device.get("kind") == "physical":
        require(
            not (set(paths) & set(EMULATOR_CONTROL_PATH_KEYS)),
            "physical Android proof includes emulator control evidence",
        )
        return
    control = proof.get("emulator_control")
    require(isinstance(control, dict), "emulator proof lacks control evidence")
    notifier = control.get("native_notifier")
    external_adb = control.get("external_adb")
    require(
        isinstance(notifier, dict) and isinstance(external_adb, dict),
        "emulator proof lacks adb isolation evidence",
    )
    checkpoints = notifier.get("admission_checkpoints")
    require(isinstance(checkpoints, list), "emulator proof checkpoints are malformed")
    for item, checkpoint in zip(checkpoints, ADB_ISOLATION_CHECKPOINTS):
        path_key = ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT[checkpoint]
        actual_sha256 = _parse_adb_isolation_receipt(
            paths[path_key],
            run_id=proof["run_id"],
            checkpoint=checkpoint,
            bundled=bundled,
        )
        require(
            isinstance(item, dict) and item.get("receipt_sha256") == actual_sha256,
            f"Android adb isolation {checkpoint.value} receipt hash differs",
        )
    private_adb = control.get("private_adb")
    require(isinstance(private_adb, dict), "emulator proof private adb is malformed")
    if not bundled:
        observed_private_adb = _read_registered_private_adb_evidence(
            routing_receipt_path=paths["emulator_routing"],
            run_id=proof["run_id"],
            private_adb_identity=None,
        )
        require(
            observed_private_adb["server_status_sha256"]
            == private_adb.get("server_status_sha256")
            and observed_private_adb["listener_snapshot_sha256"]
            == private_adb.get("listener_snapshot_sha256"),
            "registered private adb evidence differs from its proof projection",
        )
    reparsed_external_adb = _parse_emulator_routing_receipt(
        paths["emulator_routing"],
        run_id=proof["run_id"],
        expected_private_adb=private_adb,
        bundled=bundled,
    )
    require(
        external_adb == reparsed_external_adb,
        "Android emulator routing evidence differs from its proof projection",
    )


def current_source_tree_digest(root: pathlib.Path) -> str:
    """Return the exact canonical digest used by the claim-ledger gate."""

    try:
        return canonical_tree_digest(root, repository_paths(root))
    except (LedgerError, OSError, UnicodeDecodeError) as exc:
        raise SystemExit(
            f"error: cannot compute canonical source-input digest: {exc}"
        ) from exc


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


def verify_git_provenance(
    root: pathlib.Path, proof: dict[str, Any], allow_dirty_proof: bool
) -> None:
    proof_commit = proof.get("git_commit")
    require(
        isinstance(proof_commit, str)
        and re.fullmatch(r"[0-9a-f]{40,64}", proof_commit) is not None,
        "Android proof lacks a valid git_commit",
    )
    try:
        require_commit_or_evidence_successor(root, proof_commit)
    except GitProvenanceError as exc:
        require(False, f"Android proof commit provenance failed: {exc}")
    proof_dirty = proof.get("source_tree_dirty")
    require(isinstance(proof_dirty, bool), "Android proof lacks source_tree_dirty")
    if not allow_dirty_proof:
        require(
            proof_dirty is False, "Android proof was generated from a dirty source tree"
        )
        require(
            not source_tree_dirty(root),
            "Android proof cannot be release-verified while the current source tree is dirty",
        )


def target_path(root: pathlib.Path, rel: str, label: str) -> pathlib.Path:
    require(isinstance(rel, str) and rel, f"{label} path is missing")
    path = (root / rel).resolve()
    require_under(path, root / "target", label)
    return path


def expected_proof_path_keys(proof: dict[str, Any]) -> frozenset[str]:
    device = proof.get("device")
    require(isinstance(device, dict), "proof lacks device metadata")
    kind = device.get("kind")
    require(kind in {"physical", "emulator"}, "proof device kind is invalid")
    keys = set(BASE_PROOF_PATH_KEYS)
    if kind == "emulator":
        keys.update(EMULATOR_CONTROL_PATH_KEYS)
    return frozenset(keys)


def proof_path_fields(proof: dict[str, Any]) -> dict[str, str]:
    rel_paths = proof.get("paths")
    require(isinstance(rel_paths, dict), "proof lacks artifact paths")
    expected_keys = expected_proof_path_keys(proof)
    require(set(rel_paths) == expected_keys, "proof artifact path fields differ")
    validated: dict[str, str] = {}
    for name in sorted(expected_keys):
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


def validate_selected_run_layout(
    root: pathlib.Path,
    proof_path: pathlib.Path,
    proof: dict[str, Any],
    paths: dict[str, pathlib.Path],
    *,
    require_unique_run: bool,
) -> None:
    runs_root = (root / "target" / ANDROID_RUNS_ROOT_LEAF).resolve()
    selected = proof_path.resolve()
    try:
        relative = selected.relative_to(runs_root)
    except ValueError:
        require(
            not require_unique_run,
            "release Android proof must use one immutable selected run directory",
        )
        return
    require(
        len(relative.parts) == 3
        and RUN_ID_RE.fullmatch(relative.parts[0]) is not None
        and relative.parts[1:] == ("proof", ANDROID_PROOF_LEAF),
        "selected Android proof path does not match the immutable run layout",
    )
    run_id = relative.parts[0]
    require(
        proof.get("run_id") == run_id,
        "selected Android proof run id differs from its run directory",
    )
    proof_root = runs_root / run_id / "proof"
    for directory, label in (
        (runs_root, "Android runs"),
        (runs_root / run_id, "selected Android run"),
        (proof_root, "selected Android proof"),
    ):
        canonical_private_directory(directory, label)
    try:
        proof_metadata = selected.lstat()
    except OSError as exc:
        raise SystemExit(
            f"error: cannot inspect selected Android proof: {exc}"
        ) from exc
    require(
        stat.S_ISREG(proof_metadata.st_mode)
        and not stat.S_ISLNK(proof_metadata.st_mode)
        and proof_metadata.st_uid == os.geteuid()
        and proof_metadata.st_nlink == 1
        and stat.S_IMODE(proof_metadata.st_mode) == 0o600,
        "selected Android proof must be one current-user-owned mode-0600 regular file",
    )
    fixed_runtime_paths = {
        "smoke_apk": proof_root / "qperiapt-android-smoke.apk",
        "apksigner_verify": proof_root / "apksigner-verify.txt",
        "zipalign_verify": proof_root / "zipalign-verify.txt",
        "result_txt": proof_root / "qperiapt-android-device-result.txt",
        "result_json": proof_root / "qperiapt-android-device-result.json",
        "logcat": proof_root / "logcat.txt",
    }
    if proof.get("device", {}).get("kind") == "emulator":
        fixed_runtime_paths.update(
            {
                ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT[checkpoint]: (
                    proof_root / ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint]
                )
                for checkpoint in ADB_ISOLATION_CHECKPOINTS
            }
        )
        fixed_runtime_paths["emulator_routing"] = (
            proof_root / EMULATOR_ROUTING_RECEIPT_LEAF
        )
    for name, expected in fixed_runtime_paths.items():
        require(
            paths.get(name) == expected,
            f"selected Android {name} crosses or differs from its run directory",
        )
        try:
            metadata = expected.lstat()
        except OSError as exc:
            raise SystemExit(
                f"error: cannot inspect selected Android {name}: {exc}"
            ) from exc
        require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            f"selected Android {name} must be one current-user-owned mode-0600 regular file",
        )


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
    require(
        age_seconds <= max_age_seconds,
        f"Android proof is stale: {int(age_seconds)}s old",
    )


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


def validate_run_id(value: str) -> str:
    if RUN_ID_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "must be exactly 32 lowercase hexadecimal characters"
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
        require(
            expected.get(name + "_sha256") == got,
            f"source input changed since Android proof: {name}",
        )


def verify_result_files(paths: dict[str, pathlib.Path], run_id: str) -> None:
    marker = expected_marker(run_id)
    marker_text = read_text(paths["result_txt"])
    require(
        marker_text == marker + "\n",
        f"Android result marker mismatch in {paths['result_txt']}",
    )

    result = load_json(paths["result_json"])
    exact_object(result, RESULT_FIELDS, "Android result")
    require(
        result.get("schema") == RESULT_SCHEMA_VERSION, "Android result schema mismatch"
    )
    require(result.get("status") == "pass", "Android result status is not pass")
    require(result.get("run_id") == run_id, "Android result run_id mismatch")
    require(
        result.get("test_count") == len(EXPECTED_TESTS),
        "Android result test_count mismatch",
    )
    require(
        result.get("passed_tests") == EXPECTED_TESTS,
        "Android result passed_tests mismatch",
    )

    logcat = read_text(paths["logcat"])
    expected_log_marker = marker
    pass_marker_count = 0
    for line in logcat.splitlines():
        if not line:
            continue
        if line.startswith("--------- beginning of "):
            continue
        require(
            LOGCAT_APP_LINE.match(line) is not None,
            "Android logcat contains data outside the QPeriaptSmoke tag filter",
        )
        require(
            f"run-id={run_id}" in line,
            "Android logcat contains a QPeriaptSmoke line from another run",
        )
        if expected_log_marker in line:
            pass_marker_count += 1
    require(
        pass_marker_count == 1,
        "Android logcat must contain exactly one run-bound PASS marker",
    )
    for pattern in LOG_FATAL_PATTERNS:
        require(
            pattern not in logcat,
            f"Android logcat contains runtime failure marker: {pattern}",
        )


def verify_artifact_hashes(
    paths: dict[str, pathlib.Path], proof: dict[str, Any]
) -> None:
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
        require(
            artifacts.get(key) == sha256_file(path), f"hash mismatch for {key}: {path}"
        )

    result = exact_object(
        proof.get("result"), PROOF_RESULT_FIELDS, "Android proof result"
    )
    require(
        result.get("marker_sha256") == sha256_file(paths["result_txt"]),
        "result marker hash mismatch",
    )
    require(
        result.get("json_sha256") == sha256_file(paths["result_json"]),
        "result JSON hash mismatch",
    )
    require(result.get("status") == "pass", "proof result status is not pass")
    require(
        result.get("test_count") == len(EXPECTED_TESTS),
        "proof result test_count mismatch",
    )
    require(
        result.get("passed_tests") == EXPECTED_TESTS,
        "proof result passed_tests mismatch",
    )


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
        require(
            expected.get("ffi_so_sha256") == ffi, f"AAR ffi hash mismatch for {abi}"
        )
        require(
            expected.get("jni_so_sha256") == jni, f"AAR JNI hash mismatch for {abi}"
        )


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
    require(
        device.get("raw_serial_recorded") is False,
        "proof must not record raw adb serial",
    )
    for prefix_field in ("serial_sha256_prefix", "fingerprint_sha256_prefix"):
        prefix = device.get(prefix_field)
        require(
            isinstance(prefix, str)
            and re.fullmatch(r"[0-9a-f]{12}", prefix) is not None,
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
        require(
            kind == expected_device_kind,
            f"expected Android device kind {expected_device_kind}, got {kind}",
        )

    device_abi = device.get("abi")
    require(
        device_abi in REQUIRED_NATIVE_ABIS, f"invalid Android device ABI: {device_abi}"
    )
    if expected_device_abi:
        require(
            device_abi == expected_device_abi,
            f"expected Android device ABI {expected_device_abi}, got {device_abi}",
        )
    page_size = device.get("page_size")
    require(
        type(page_size) is int and page_size in {4096, 16384},
        f"invalid Android device page size: {page_size}",
    )
    if expected_page_size is not None:
        require(
            page_size == expected_page_size,
            f"expected Android page size {expected_page_size}, got {page_size}",
        )
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
        require(
            release_mode is True,
            "proof was not generated in Android release-candidate mode",
        )
        require(
            expected_device_abi != "",
            "release verification requires an explicit expected Android device ABI",
        )
        require(
            expected_page_size == 16384,
            "release verification requires expected Android page size 16384",
        )
        require(
            page_size == 16384,
            "Android release proof did not run on a 16 KiB page-size device",
        )
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
    require(
        android.get("native_page_alignment") == 16384,
        "Android runtime proof lacks 16 KiB native alignment metadata",
    )
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
            build_tools == ANDROID_RELEASE_BUILD_TOOLS,
            f"Android release proof must use build-tools {ANDROID_RELEASE_BUILD_TOOLS}",
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
    bundled: bool = False,
) -> None:
    verify_proof_schema(proof)
    require(
        set(paths) == expected_proof_path_keys(proof),
        "selected Android evidence path fields differ",
    )
    proof_path_fields(proof)
    require(
        proof.get("device_runtime_proof") is True,
        "proof is not an Android runtime proof",
    )
    require(
        proof.get("package_only") is False, "runtime proof must not be package_only"
    )
    require(
        proof.get("package") == "dev.qperiapt.androidsmoke",
        "unexpected Android proof package",
    )
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
    verify_emulator_control(proof, require_release_mode=require_release_mode)
    verify_emulator_control_evidence(proof, paths, bundled=bundled)
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
        args.results_manifest is not None
        or args.expected_results_manifest_sha256 is None,
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
    selected_paths = proof_paths(root, proof)
    validate_selected_run_layout(
        root,
        proof_path,
        proof,
        selected_paths,
        require_unique_run=args.require_release_mode,
    )
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
    print("ANDROID_DEVICE_PROOF_VERIFY_PASS")
    if proof_snapshot is not None:
        print(
            "PROOF_TO_BYTE_SELECTED_PROOF_MANIFEST_PASS "
            f"section=android_runtime sha256={proof_snapshot.file.sha256}"
        )


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def canonical_json(value: Any) -> bytes:
    return canonical_json_bytes(value)


def write_bundle_file(path: pathlib.Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, 0o644)
    except OSError as exc:
        raise SystemExit(
            f"error: cannot stage Android evidence bundle file {path}: {exc}"
        ) from exc


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
        raise SystemExit(
            f"error: cannot read Android proof commit epoch: {exc}"
        ) from exc
    require(
        raw_epoch.isascii() and raw_epoch.isdigit(),
        "Android proof commit epoch is malformed",
    )
    epoch = int(raw_epoch)
    require(
        315532800 <= epoch <= 0xFFFFFFFF,
        "Android proof commit epoch cannot be represented by deterministic ZIP",
    )
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
        with zipfile.ZipFile(
            io.BytesIO(snapshot.data), "r", allowZip64=False
        ) as archive:
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
                    require(
                        name not in names,
                        f"Android smoke APK contains duplicate entry: {name}",
                    )
                    require(
                        canonical_name.casefold() not in folded_names,
                        f"Android smoke APK contains a case-conflicting entry: {name}",
                    )
                    names.add(name)
                    folded_names.add(canonical_name.casefold())
                    require(
                        info.flag_bits & 0x1 == 0,
                        f"Android smoke APK contains encrypted entry: {name}",
                    )
                    require(
                        info.compress_type
                        in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
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
                    require(
                        total <= 256 * 1024 * 1024,
                        "Android smoke APK uncompressed size exceeds limit",
                    )
                    if info.is_dir():
                        continue
                    data = archive.read(info)
                    require(
                        len(data) == info.file_size,
                        f"Android smoke APK entry size differs: {name}",
                    )
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
    require(
        stat.S_ISREG(metadata.st_mode),
        f"{label} must resolve to a regular file: {path}",
    )
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
    resolved_readelf = require_executable_file(llvm_readelf, "Android llvm-readelf")
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
        raise SystemExit(
            f"error: Android NDK toolchain verification failed: {exc}"
        ) from exc
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


def bundle_file_paths(proof: dict[str, Any]) -> dict[str, str]:
    device = proof.get("device")
    require(isinstance(device, dict), "Android bundle proof device is malformed")
    if device.get("kind") == "emulator":
        return dict(BUNDLE_FILE_PATHS)
    require(device.get("kind") == "physical", "Android bundle device kind is invalid")
    return dict(BASE_BUNDLE_FILE_PATHS)


def expected_bundle_entries(
    file_paths: dict[str, str], *, root_name: str = BUNDLE_ROOT_NAME
) -> dict[str, str]:
    expected = {
        root_name: "directory",
        f"{root_name}/artifacts": "directory",
        f"{root_name}/evidence": "directory",
        f"{root_name}/{BUNDLE_MANIFEST_PATH}": "file",
    }
    expected.update(
        {
            f"{root_name}/{relative}": "file"
            for relative in file_paths.values()
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
    require(
        manifest.get("raw_serial_recorded") is False,
        "Android evidence bundle records a raw serial",
    )
    require(
        type(manifest.get("release_candidate_mode")) is bool,
        "Android evidence bundle release_candidate_mode must be a boolean",
    )
    files = manifest.get("files")
    require(isinstance(files, dict), "Android evidence bundle files are malformed")
    proof_record = files.get("proof")
    require(
        isinstance(proof_record, dict)
        and proof_record.get("path") == BASE_BUNDLE_FILE_PATHS["proof"],
        "Android evidence bundle proof record differs",
    )
    proof_path = bundle_root / BASE_BUNDLE_FILE_PATHS["proof"]
    proof = load_json(proof_path)
    verify_proof_schema(proof)
    expected_file_paths = bundle_file_paths(proof)
    require(
        set(files) == set(expected_file_paths),
        "Android evidence bundle file fields differ",
    )
    selected: dict[str, pathlib.Path] = {}
    for key, expected_relative in expected_file_paths.items():
        record = files.get(key)
        require(
            isinstance(record, dict) and set(record) == {"bytes", "path", "sha256"},
            f"Android evidence bundle file record differs: {key}",
        )
        require(
            record.get("path") == expected_relative,
            f"Android evidence bundle path differs: {key}",
        )
        size = record.get("bytes")
        digest = record.get("sha256")
        require(
            type(size) is int and 0 < size <= MAX_EVIDENCE_FILE_BYTES,
            f"Android evidence bundle size is invalid: {key}",
        )
        require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            f"Android evidence bundle digest is invalid: {key}",
        )
        path = bundle_root.joinpath(*pathlib.PurePosixPath(expected_relative).parts)
        try:
            snapshot = read_regular_snapshot(
                path,
                maximum=MAX_EVIDENCE_FILE_BYTES,
                label=f"Android bundled evidence {key}",
            )
        except EvidenceIOError as exc:
            raise SystemExit(f"error: {exc}") from exc
        require(
            snapshot.size == size and snapshot.sha256 == digest,
            f"Android bundled evidence bytes differ: {key}",
        )
        selected[key] = path
    require(selected["proof"] == proof_path, "Android bundled proof path differs")
    require(
        manifest.get("git_commit") == proof.get("git_commit"),
        "Android bundle git_commit differs from proof",
    )
    require(
        manifest.get("run_id") == proof.get("run_id"),
        "Android bundle run_id differs from proof",
    )
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


def _verify_published_runtime_bundle_v1_with_digests(
    bundle: pathlib.Path,
    *,
    expected_bundle_sha256: str,
    expected_manifest_sha256: str,
    expected_proof_sha256: str,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Verify the one immutable platform-r2 schema-3 Android bundle receipt.

    This verifier is intentionally identity-specific. It is not a compatibility
    dispatcher and must never accept a current or future prepublication bundle.
    """

    try:
        with tempfile.TemporaryDirectory(prefix="qperiapt-published-android-v1-") as temp:
            temporary_root = canonical_private_directory(
                pathlib.Path(temp),
                "published Android evidence verification temporary directory",
            )
            destination = temporary_root / "extracted"
            audit = extract_zip(
                bundle,
                destination,
                root_name=PUBLISHED_BUNDLE_ROOT_NAME,
                expected_sha256=expected_bundle_sha256,
            )
            require(
                audit.mtime
                == PUBLISHED_ANDROID_RUNTIME_SOURCE_DATE_EPOCH
                - PUBLISHED_ANDROID_RUNTIME_SOURCE_DATE_EPOCH % 2,
                "published Android bundle timestamp differs from immutable r2",
            )
            actual_entries = {entry.path: entry.kind for entry in audit.entries}
            require(
                actual_entries == PUBLISHED_BUNDLE_ARCHIVE_ENTRIES,
                "published Android bundle archive file set differs",
            )
            extracted_root = destination / PUBLISHED_BUNDLE_ROOT_NAME
            manifest_path = extracted_root / PUBLISHED_BUNDLE_MANIFEST_PATH
            try:
                manifest_snapshot = load_json_object_snapshot(
                    manifest_path,
                    label="published Android bundle manifest",
                )
            except EvidenceIOError as exc:
                raise SystemExit(
                    f"error: cannot read published Android bundle manifest: {exc}"
                ) from exc
            require(
                manifest_snapshot.file.sha256 == expected_manifest_sha256,
                "published Android bundle manifest digest differs from immutable r2",
            )
            require(
                canonical_json_bytes(manifest_snapshot.value)
                == manifest_snapshot.file.data,
                "published Android bundle manifest is not canonical JSON",
            )
            manifest = exact_object(
                manifest_snapshot.value,
                PUBLISHED_BUNDLE_MANIFEST_FIELDS,
                "published Android bundle manifest",
            )
            require(
                type(manifest.get("schema_version")) is int
                and manifest["schema_version"] == PUBLISHED_BUNDLE_SCHEMA_VERSION
                and manifest.get("kind") == PUBLISHED_BUNDLE_KIND
                and manifest.get("source_date_epoch")
                == PUBLISHED_ANDROID_RUNTIME_SOURCE_DATE_EPOCH
                and manifest.get("git_commit") == TAG_COMMIT
                and manifest.get("run_id") == PUBLISHED_ANDROID_RUNTIME_RUN_ID
                and manifest.get("release_candidate_mode") is True
                and manifest.get("raw_serial_recorded") is False
                and manifest.get("device") == PUBLISHED_BUNDLE_DEVICE,
                "published Android bundle identity differs from immutable r2",
            )
            files = exact_object(
                manifest.get("files"),
                set(PUBLISHED_BUNDLE_FILE_PATHS),
                "published Android bundle files",
            )
            selected: dict[str, pathlib.Path] = {}
            for key, relative in PUBLISHED_BUNDLE_FILE_PATHS.items():
                record = exact_object(
                    files.get(key),
                    PUBLISHED_BUNDLE_FILE_RECORD_FIELDS,
                    f"published Android bundle file record {key}",
                )
                require(
                    record.get("path") == relative
                    and type(record.get("bytes")) is int
                    and 0 < record["bytes"] <= MAX_EVIDENCE_FILE_BYTES
                    and isinstance(record.get("sha256"), str)
                    and SHA256_RE.fullmatch(record["sha256"]) is not None,
                    f"published Android bundle file record differs: {key}",
                )
                path = extracted_root.joinpath(*pathlib.PurePosixPath(relative).parts)
                try:
                    snapshot = read_regular_snapshot(
                        path,
                        maximum=MAX_EVIDENCE_FILE_BYTES,
                        label=f"published Android bundled evidence {key}",
                    )
                except EvidenceIOError as exc:
                    raise SystemExit(f"error: {exc}") from exc
                require(
                    snapshot.size == record["bytes"]
                    and snapshot.sha256 == record["sha256"],
                    f"published Android bundled evidence bytes differ: {key}",
                )
                selected[key] = path

            proof_snapshot = read_regular_snapshot(
                selected["proof"],
                maximum=64 * 1024,
                label="published Android runtime proof",
            )
            require(
                proof_snapshot.sha256 == expected_proof_sha256,
                "published Android proof digest differs from immutable r2",
            )
            try:
                proof_value = parse_strict_json_bytes(
                    proof_snapshot.data, label="published Android runtime proof"
                )
            except EvidenceIOError as exc:
                raise SystemExit(
                    f"error: cannot parse published Android runtime proof: {exc}"
                ) from exc
            proof = exact_object(
                proof_value,
                PUBLISHED_PROOF_FIELDS,
                "published Android runtime proof",
            )
            require(
                canonical_json_bytes(proof) == proof_snapshot.data,
                "published Android runtime proof is not canonical JSON",
            )
            require(
                type(proof.get("schema")) is int
                and proof["schema"] == PUBLISHED_ANDROID_DEVICE_PROOF_SCHEMA_VERSION
                and proof.get("git_commit") == TAG_COMMIT
                and proof.get("proof_source_tree_sha256")
                == CANONICAL_SOURCE_TREE_SHA256
                and proof.get("run_id") == PUBLISHED_ANDROID_RUNTIME_RUN_ID
                and proof.get("source_tree_dirty") is False
                and proof.get("device_runtime_proof") is True
                and proof.get("package_only") is False
                and proof.get("release_candidate_mode") is True
                and proof.get("package") == "dev.qperiapt.androidsmoke",
                "published Android proof identity differs from immutable r2",
            )
            require(
                proof.get("device") == PUBLISHED_PROOF_DEVICE,
                "published Android proof device differs from immutable r2",
            )
            result = exact_object(
                proof.get("result"),
                PUBLISHED_PROOF_RESULT_FIELDS,
                "published Android result",
            )
            require(
                result
                == {
                    "marker_sha256": files["result_txt"]["sha256"],
                    "json_sha256": files["result_json"]["sha256"],
                    "status": "pass",
                    "test_count": len(PUBLISHED_EXPECTED_TESTS),
                    "passed_tests": list(PUBLISHED_EXPECTED_TESTS),
                },
                "published Android proof result differs from immutable r2",
            )
            artifacts = exact_object(
                proof.get("artifacts"),
                PUBLISHED_PROOF_ARTIFACT_FIELDS,
                "published Android proof artifacts",
            )
            for proof_field, file_key in PUBLISHED_PROOF_ARTIFACT_LINKS:
                require(
                    artifacts.get(proof_field) == files[file_key]["sha256"],
                    f"published Android proof {proof_field} differs from its bundle",
                )
            require(
                proof.get("paths") == PUBLISHED_PROOF_PATHS,
                "published Android proof paths differ from immutable r2",
            )
            return audit.archive_sha256, manifest, proof
    except DeterministicArchiveError as exc:
        raise SystemExit(
            f"error: published Android evidence bundle is invalid: {exc}"
        ) from exc


def verify_published_runtime_bundle_v1(
    bundle: pathlib.Path,
    *,
    expected_bundle_sha256: str,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Verify only the immutable platform-r2 schema-3 Android bundle."""

    expected_public_digest = ASSET_BY_NAME[ANDROID_RUNTIME_BUNDLE].sha256
    require(
        expected_bundle_sha256 == expected_public_digest,
        "published Android bundle selector differs from the immutable r2 digest",
    )
    return _verify_published_runtime_bundle_v1_with_digests(
        bundle,
        expected_bundle_sha256=expected_public_digest,
        expected_manifest_sha256=ANDROID_BUNDLE_MANIFEST_SHA256,
        expected_proof_sha256=ANDROID_PROOF_SHA256,
    )


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
            extracted_root = destination / BUNDLE_ROOT_NAME
            manifest = load_json(extracted_root / BUNDLE_MANIFEST_PATH)
            selected, proof = verify_bundle_manifest(
                extracted_root,
                manifest,
                archive_mtime=audit.mtime,
            )
            require(
                actual_entries == expected_bundle_entries(bundle_file_paths(proof)),
                "Android evidence bundle archive file set differs",
            )
            require(
                manifest["source_date_epoch"] == source_commit_epoch(root, proof),
                "Android evidence bundle source_date_epoch differs from its proof commit",
            )
            proof_selected = {
                key: selected[key] for key in expected_proof_path_keys(proof)
            }
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
                bundled=True,
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
                raise SystemExit(
                    f"error: bundled Android AAR verification failed: {exc}"
                ) from exc
            return audit.archive_sha256
    except DeterministicArchiveError as exc:
        raise SystemExit(
            f"error: Android evidence bundle archive verification failed: {exc}"
        ) from exc


def create_bundle(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    proof_path = args.proof.resolve()
    output = args.output.resolve()
    require_under(proof_path, root / "target", "Android proof")
    require_under(output, root / "target", "Android evidence bundle output")
    require(output.suffix == ".zip", "Android evidence bundle output must use .zip")
    require(
        not output.exists() and not output.is_symlink(),
        f"Android evidence bundle output already exists: {output}",
    )
    require(
        output.parent.is_dir() and not output.parent.is_symlink(),
        f"Android evidence bundle output parent is unsafe or missing: {output.parent}",
    )
    proof = load_json(proof_path)
    verify_proof_schema(proof)
    verify_proof_freshness(proof, args.max_age_seconds)
    selected_paths = proof_paths(root, proof)
    validate_selected_run_layout(
        root,
        proof_path,
        proof,
        selected_paths,
        require_unique_run=args.require_release_mode,
    )
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
        with tempfile.TemporaryDirectory(
            prefix="qperiapt-android-bundle-stage-", dir=output.parent
        ) as temp:
            stage = pathlib.Path(temp) / "stage"
            stage.mkdir()
            sources = {"proof": proof_path, **selected_paths}
            selected_bundle_paths = bundle_file_paths(proof)
            for key, relative in selected_bundle_paths.items():
                write_bundle_file(stage / relative, read_bytes(sources[key]))
            file_records = {
                key: bundle_file_record(stage / relative, relative)
                for key, relative in selected_bundle_paths.items()
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
            write_bundle_file(
                stage / BUNDLE_MANIFEST_PATH, canonical_json(bundle_manifest)
            )
            staged_paths = [stage / BUNDLE_MANIFEST_PATH]
            staged_paths.extend(
                stage / relative for relative in selected_bundle_paths.values()
            )
            scan_release_paths(staged_paths, forbidden_text=forbidden_text)
            scan_apk_contents(
                stage / selected_bundle_paths["smoke_apk"], forbidden_text=forbidden_text
            )
            audit = create_zip(
                stage,
                output,
                root_name=BUNDLE_ROOT_NAME,
                mtime=source_epoch,
            )
    except DeterministicArchiveError as exc:
        raise SystemExit(
            f"error: cannot create Android evidence bundle: {exc}"
        ) from exc

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
    require(
        verified_sha256 == audit.archive_sha256,
        "created Android evidence bundle digest changed during verification",
    )
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

    verify_parser = sub.add_parser(
        "verify", help="verify an Android runtime proof JSON"
    )
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

    signer_parser = sub.add_parser(
        "signer-sha256",
        help="extract one exact signer certificate SHA-256 digest from apksigner output",
    )
    signer_parser.add_argument("--apksigner-output", required=True, type=pathlib.Path)
    signer_parser.set_defaults(func=signer_sha256)

    adb_identity_parser = sub.add_parser(
        "verify-adb-identity",
        help="verify the current account adb identity and key permissions",
    )
    adb_identity_parser.add_argument(
        "--home-directory", required=True, type=pathlib.Path
    )
    adb_identity_parser.set_defaults(func=verify_adb_identity)

    default_adb_parser = sub.add_parser(
        "assert-default-adb-server-absent",
        help="fail unless the standard IPv4 and IPv6 adb endpoints refuse connections",
    )
    default_adb_parser.set_defaults(func=assert_default_adb_server_absent)

    adb_server_parser = sub.add_parser(
        "verify-adb-server-status",
        help="verify the active adb server executable and keystore paths",
    )
    adb_server_parser.add_argument("--status", required=True, type=pathlib.Path)
    adb_server_parser.add_argument("--adb", required=True, type=pathlib.Path)
    adb_server_parser.add_argument("--home-directory", required=True, type=pathlib.Path)
    adb_server_parser.set_defaults(func=verify_adb_server_status)

    adb_listener_parser = sub.add_parser(
        "verify-adb-listener",
        help="bind one exact adb endpoint to the expected owned server process",
    )
    adb_listener_parser.add_argument("--lsof-output", required=True, type=pathlib.Path)
    adb_listener_parser.add_argument("--adb", required=True, type=pathlib.Path)
    adb_listener_parser.add_argument("--expected-endpoint", required=True)
    adb_listener_parser.add_argument("--expected-pid", type=int)
    adb_listener_parser.add_argument("--expected-identity")
    adb_listener_parser.add_argument("--expected-server-socket")
    adb_listener_parser.add_argument("--expected-vendor-keys")
    adb_listener_parser.add_argument("--expected-mdns", choices=["0"])
    adb_listener_parser.add_argument(
        "--expected-transport-kind", choices=["physical", "emulator"]
    )
    adb_listener_parser.set_defaults(func=verify_adb_listener)

    emulator_listener_parser = sub.add_parser(
        "verify-owned-emulator-listeners",
        help="bind the fixed console and adb ports to the script-owned emulator child",
    )
    emulator_listener_parser.add_argument(
        "--lsof-output", required=True, type=pathlib.Path
    )
    emulator_listener_parser.add_argument("--expected-pid", required=True, type=int)
    emulator_listener_parser.add_argument("--console-port", required=True, type=int)
    emulator_listener_parser.add_argument("--adb-port", required=True, type=int)
    emulator_listener_parser.set_defaults(func=verify_owned_emulator_listeners)

    owned_process_parser = sub.add_parser(
        "verify-owned-process",
        help="bind one direct child pid to its executable and start identity",
    )
    owned_process_parser.add_argument("--expected-pid", required=True, type=int)
    owned_process_parser.add_argument(
        "--expected-executable", required=True, type=pathlib.Path
    )
    owned_process_parser.add_argument(
        "--expected-executable-device", required=True, type=int
    )
    owned_process_parser.add_argument(
        "--expected-executable-inode", required=True, type=int
    )
    owned_process_parser.add_argument("--expected-identity")
    owned_process_parser.set_defaults(func=verify_owned_process)

    emulator_backend_parser = sub.add_parser(
        "emulator-backend-path",
        help="derive the fixed headless QEMU backend selected by an emulator launcher",
    )
    emulator_backend_parser.add_argument("--emulator", required=True, type=pathlib.Path)
    emulator_backend_parser.add_argument(
        "--device-abi", required=True, choices=["arm64-v8a", "x86_64"]
    )
    emulator_backend_parser.set_defaults(func=resolve_emulator_backend)

    wait_exec_parser = sub.add_parser(
        "wait-owned-process-exec",
        help="wait for an owned emulator launcher to exec its fixed backend",
    )
    wait_exec_parser.add_argument("--expected-pid", required=True, type=int)
    wait_exec_parser.add_argument(
        "--initial-executable", required=True, type=pathlib.Path
    )
    wait_exec_parser.add_argument("--launcher", required=True, type=pathlib.Path)
    wait_exec_parser.add_argument(
        "--device-abi", required=True, choices=["arm64-v8a", "x86_64"]
    )
    wait_exec_parser.add_argument(
        "--timeout-seconds", required=True, type=int, choices=range(1, 31)
    )
    wait_exec_parser.set_defaults(func=wait_owned_process_exec)

    publish_parser = sub.add_parser(
        "publish-staged-proof",
        help="atomically publish one private staged Android proof without replacement",
    )
    publish_parser.add_argument("--staging", required=True, type=pathlib.Path)
    publish_parser.add_argument("--destination", required=True, type=pathlib.Path)
    publish_parser.set_defaults(func=publish_staged_proof)

    private_socket_parser = sub.add_parser(
        "verify-private-adb-socket",
        help="verify the private adb server directory and fixed socket leaf",
    )
    private_socket_parser.add_argument("--directory", required=True, type=pathlib.Path)
    private_socket_parser.add_argument(
        "--state", required=True, choices=["absent", "present"]
    )
    private_socket_parser.set_defaults(func=verify_private_adb_socket)
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
